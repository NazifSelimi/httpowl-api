// Package audit records every user/agent action and lists it back.
package audit

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/NazifSelimi/httpowl-api/internal/store"
)

// Log writes one audit entry. Failures are logged, never fatal to the request.
func Log(ctx context.Context, q *store.Queries, siteID, userID *int64, action string, detail map[string]any, ip string) {
	if detail == nil {
		detail = map[string]any{}
	}
	b, _ := json.Marshal(detail)
	if err := q.InsertAudit(ctx, store.InsertAuditParams{SiteID: siteID, UserID: userID, Action: action, Detail: b, Ip: ip}); err != nil {
		slog.Error("audit write failed", "action", action, "err", err)
	}
}

// P returns a pointer to v (for optional ids).
func P(v int64) *int64 { return &v }
