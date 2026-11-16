-- name: UpsertNote :exec
INSERT INTO daily_notes (site_id, day, body, stats) VALUES ($1, $2, $3, $4)
ON CONFLICT (site_id, day) DO UPDATE SET body = EXCLUDED.body, stats = EXCLUDED.stats, created_at = now();

-- name: ListNotes :many
SELECT day, body, stats, created_at FROM daily_notes
WHERE site_id = $1 ORDER BY day DESC LIMIT 30;

-- name: SitesMissingNote :many
SELECT s.id FROM sites s
WHERE NOT EXISTS (SELECT 1 FROM daily_notes n WHERE n.site_id = s.id AND n.day = $1);

-- name: NewRulesBetween :one
SELECT count(*) FROM rules WHERE site_id = $1 AND created_at >= $2 AND created_at < $3;

-- name: SlowPaths :many
SELECT path, avg(duration_ms)::float8 AS avg_ms, count(*)::bigint AS requests
FROM requests
WHERE site_id = @site_id AND ts >= @from_ts AND ts < @to_ts AND duration_ms > 0
GROUP BY path HAVING count(*) >= 5
ORDER BY 2 DESC LIMIT 3;

-- name: ErrorPaths :many
SELECT path, status, count(*)::bigint AS requests
FROM requests
WHERE site_id = @site_id AND ts >= @from_ts AND ts < @to_ts AND status >= 500
GROUP BY path, status ORDER BY 3 DESC LIMIT 3;
