-- name: InsertRequests :copyfrom
INSERT INTO requests (site_id, ts, ip, method, host, path, query, proto, status, bytes, duration_ms, ua, referer, country, tag, reason)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16);
