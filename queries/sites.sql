-- name: CreateSite :one
INSERT INTO sites (name, domain) VALUES ($1, $2) RETURNING *;

-- name: AddMember :exec
INSERT INTO site_members (site_id, user_id, role) VALUES ($1, $2, $3)
ON CONFLICT (site_id, user_id) DO UPDATE SET role = EXCLUDED.role;

-- name: ListSitesForUser :many
SELECT s.id, s.name, s.domain, s.created_at, s.agent_last_seen_at, m.role
FROM sites s JOIN site_members m ON m.site_id = s.id
WHERE m.user_id = $1 ORDER BY s.name;

-- name: GetSiteForUser :one
SELECT s.*, m.role
FROM sites s JOIN site_members m ON m.site_id = s.id
WHERE s.id = $1 AND m.user_id = $2;

-- name: UpdateSite :exec
UPDATE sites SET name = $2, domain = $3 WHERE id = $1;

-- name: DeleteSite :exec
DELETE FROM sites WHERE id = $1;

-- name: ListAllSiteIDs :many
SELECT id FROM sites ORDER BY id;

-- name: GetSite :one
SELECT * FROM sites WHERE id = $1;

-- name: RevokeAgentTokens :exec
UPDATE agent_tokens SET revoked_at = now() WHERE site_id = $1 AND revoked_at IS NULL;

-- name: CreateAgentToken :exec
INSERT INTO agent_tokens (site_id, token_hash, prefix, created_by) VALUES ($1, $2, $3, $4);

-- name: ActiveTokenPrefix :one
SELECT prefix, created_at FROM agent_tokens
WHERE site_id = $1 AND revoked_at IS NULL ORDER BY id DESC LIMIT 1;

-- name: SiteByAgentToken :one
SELECT s.id, s.protected_ips FROM agent_tokens t JOIN sites s ON s.id = t.site_id
WHERE t.token_hash = $1 AND t.revoked_at IS NULL;

-- name: AgentHeartbeat :exec
UPDATE sites SET agent_last_seen_at = now(), agent_info = $2, protected_ips = $3 WHERE id = $1;
