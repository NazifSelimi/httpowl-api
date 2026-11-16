-- name: ListMembers :many
SELECT u.id, u.email, u.name, m.role, m.created_at
FROM site_members m JOIN users u ON u.id = m.user_id
WHERE m.site_id = $1 ORDER BY m.created_at;

-- name: ListInvites :many
SELECT email, role, created_at FROM site_invites WHERE site_id = $1 ORDER BY created_at;

-- name: GetMemberRole :one
SELECT role FROM site_members WHERE site_id = $1 AND user_id = $2;

-- name: CountOwners :one
SELECT count(*) FROM site_members WHERE site_id = $1 AND role = 'owner';

-- name: SetMemberRole :execrows
UPDATE site_members SET role = $3 WHERE site_id = $1 AND user_id = $2;

-- name: RemoveMember :execrows
DELETE FROM site_members WHERE site_id = $1 AND user_id = $2;

-- name: UpsertInvite :exec
INSERT INTO site_invites (site_id, email, role, invited_by) VALUES ($1, $2, $3, $4)
ON CONFLICT (site_id, lower(email)) DO UPDATE SET role = EXCLUDED.role, invited_by = EXCLUDED.invited_by, created_at = now();

-- name: DeleteInvite :execrows
DELETE FROM site_invites WHERE site_id = $1 AND lower(email) = lower($2);

-- name: TakeInvites :many
DELETE FROM site_invites WHERE lower(email) = lower($1) RETURNING site_id, role;

-- name: ListSiteAudit :many
SELECT a.id, a.action, a.detail, a.ip, a.created_at, u.email AS user_email
FROM audit_log a LEFT JOIN users u ON u.id = a.user_id
WHERE a.site_id = $1 AND (sqlc.narg(before_id)::bigint IS NULL OR a.id < sqlc.narg(before_id))
ORDER BY a.id DESC LIMIT $2;

-- name: ListUserAudit :many
SELECT id, site_id, action, detail, ip, created_at
FROM audit_log WHERE user_id = $1 AND (sqlc.narg(before_id)::bigint IS NULL OR id < sqlc.narg(before_id))
ORDER BY id DESC LIMIT $2;
