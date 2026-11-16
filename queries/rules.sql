-- name: ListRules :many
SELECT r.*, cu.email AS created_by_email, ru.email AS removed_by_email
FROM rules r
LEFT JOIN users cu ON cu.id = r.created_by
LEFT JOIN users ru ON ru.id = r.removed_by
WHERE r.site_id = $1 AND (r.removed_at IS NULL OR r.removed_at > now() - interval '30 days')
ORDER BY r.removed_at IS NOT NULL, r.created_at DESC
LIMIT 1000;

-- name: ActiveRules :many
SELECT * FROM rules
WHERE site_id = $1 AND removed_at IS NULL AND (expires_at IS NULL OR expires_at > now())
ORDER BY id;

-- name: CountActiveRules :one
SELECT count(*) FROM rules WHERE site_id = $1 AND removed_at IS NULL;

-- name: CreateRule :one
INSERT INTO rules (site_id, kind, value, note, created_by, expires_at)
VALUES ($1, $2, $3, $4, $5, $6) RETURNING *;

-- name: GetRule :one
SELECT * FROM rules WHERE id = $1 AND site_id = $2;

-- name: RemoveRule :execrows
UPDATE rules SET removed_at = now(), removed_by = $3
WHERE id = $1 AND site_id = $2 AND removed_at IS NULL;

-- name: ExpireRules :exec
UPDATE rules SET removed_at = now() WHERE removed_at IS NULL AND expires_at IS NOT NULL AND expires_at <= now();

-- name: MemberSessionIPs :many
-- IPs the site's team logged in from recently: never blockable.
SELECT DISTINCT s.ip FROM sessions s
JOIN site_members m ON m.user_id = s.user_id
WHERE m.site_id = $1 AND s.last_seen_at > now() - interval '30 days' AND s.ip <> '';

-- name: ActiveRulesForAgent :many
-- Active rules of the agent's site and every site it serves: one firewall per server.
SELECT * FROM rules
WHERE site_id IN (SELECT st.id FROM sites st WHERE st.id = $1 OR st.served_by = $1)
  AND removed_at IS NULL AND (expires_at IS NULL OR expires_at > now())
ORDER BY id;

-- name: MemberSessionIPsForAgent :many
SELECT DISTINCT s.ip FROM sessions s
JOIN site_members m ON m.user_id = s.user_id
WHERE m.site_id IN (SELECT st.id FROM sites st WHERE st.id = $1 OR st.served_by = $1)
  AND s.last_seen_at > now() - interval '30 days' AND s.ip <> '';
