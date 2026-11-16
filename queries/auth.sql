-- name: CreateUser :one
INSERT INTO users (email, name, password_hash) VALUES ($1, $2, $3)
RETURNING *;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE lower(email) = lower($1);

-- name: GetUser :one
SELECT * FROM users WHERE id = $1;

-- name: CreateSession :exec
INSERT INTO sessions (token_hash, user_id, ip, user_agent, expires_at)
VALUES ($1, $2, $3, $4, $5);

-- name: GetSessionUser :one
SELECT u.id, u.email, u.name, s.last_seen_at
FROM sessions s JOIN users u ON u.id = s.user_id
WHERE s.token_hash = $1 AND s.expires_at > now();

-- name: TouchSession :exec
UPDATE sessions SET last_seen_at = now(), ip = $2 WHERE token_hash = $1;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE token_hash = $1;

-- name: DeleteExpiredSessions :exec
DELETE FROM sessions WHERE expires_at < now();

-- name: InsertAudit :exec
INSERT INTO audit_log (site_id, user_id, action, detail, ip)
VALUES ($1, $2, $3, $4, $5);
