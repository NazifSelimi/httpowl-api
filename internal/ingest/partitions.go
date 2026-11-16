package ingest

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Retention is how long request rows are kept.
const Retention = 30 * 24 * time.Hour

// MaintainPartitions creates day partitions for [today-30d, today+2d]
// and drops the ones older than the retention window.
func MaintainPartitions(ctx context.Context, pool *pgxpool.Pool) error {
	today := time.Now().UTC().Truncate(24 * time.Hour)
	for d := today.Add(-Retention); !d.After(today.Add(48 * time.Hour)); d = d.Add(24 * time.Hour) {
		sql := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s PARTITION OF requests FOR VALUES FROM ('%s') TO ('%s')`,
			partName(d), d.Format(time.RFC3339), d.Add(24*time.Hour).Format(time.RFC3339))
		if _, err := pool.Exec(ctx, sql); err != nil {
			return fmt.Errorf("create partition %s: %w", partName(d), err)
		}
	}
	rows, err := pool.Query(ctx, `SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
		JOIN pg_class p ON p.oid = i.inhparent WHERE p.relname = 'requests'`)
	if err != nil {
		return err
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return err
		}
		names = append(names, n)
	}
	rows.Close()
	oldest := partName(today.Add(-Retention))
	for _, n := range names {
		if strings.HasPrefix(n, "requests_") && len(n) == len("requests_20060102") && n < oldest {
			if _, err := pool.Exec(ctx, "DROP TABLE "+n); err != nil {
				return fmt.Errorf("drop %s: %w", n, err)
			}
			slog.Info("dropped old partition", "name", n)
		}
	}
	return nil
}

func partName(d time.Time) string { return "requests_" + d.Format("20060102") }

// InWindow reports whether ts can be stored (a partition exists for it).
func InWindow(ts time.Time) bool {
	now := time.Now().UTC()
	return ts.After(now.Truncate(24*time.Hour).Add(-Retention)) && ts.Before(now.Add(24*time.Hour))
}
