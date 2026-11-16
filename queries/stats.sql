-- name: StatsTotals :one
SELECT
    count(*)::bigint                                   AS requests,
    count(*) FILTER (WHERE tag = 'human')::bigint      AS humans,
    count(*) FILTER (WHERE tag = 'bot')::bigint        AS bots,
    count(*) FILTER (WHERE tag = 'attack')::bigint     AS attacks,
    count(DISTINCT ip)::bigint                         AS unique_ips,
    coalesce(sum(bytes), 0)::bigint                    AS bytes,
    count(*) FILTER (WHERE status >= 500)::bigint      AS errors_5xx,
    count(*) FILTER (WHERE status BETWEEN 400 AND 499)::bigint AS errors_4xx,
    coalesce(avg(duration_ms) FILTER (WHERE duration_ms > 0), 0)::float8 AS avg_ms
FROM requests
WHERE site_id = @site_id AND ts >= @from_ts AND ts < @to_ts;

-- name: StatsSeries :many
SELECT date_bin(make_interval(secs => @bucket_secs::int), ts, '2000-01-01'::timestamptz)::timestamptz AS bucket,
       count(*) FILTER (WHERE tag = 'human')::bigint  AS humans,
       count(*) FILTER (WHERE tag = 'bot')::bigint    AS bots,
       count(*) FILTER (WHERE tag = 'attack')::bigint AS attacks,
       count(*) FILTER (WHERE status >= 500)::bigint  AS errors_5xx
FROM requests
WHERE site_id = @site_id AND ts >= @from_ts AND ts < @to_ts
GROUP BY 1 ORDER BY 1;

-- name: TopCountries :many
SELECT country, count(*)::bigint AS requests,
       count(*) FILTER (WHERE tag = 'attack')::bigint AS attacks
FROM requests
WHERE site_id = @site_id AND ts >= @from_ts AND ts < @to_ts
GROUP BY country ORDER BY 2 DESC LIMIT @lim;

-- name: TopIPs :many
SELECT ip, max(country)::text AS country, count(*)::bigint AS requests,
       count(*) FILTER (WHERE tag = 'attack')::bigint AS attacks,
       max(ua)::text AS sample_ua
FROM requests
WHERE site_id = @site_id AND ts >= @from_ts AND ts < @to_ts
GROUP BY ip ORDER BY 3 DESC LIMIT @lim;

-- name: TopPaths :many
SELECT path, count(*)::bigint AS requests,
       count(*) FILTER (WHERE status >= 400)::bigint AS errors,
       coalesce(avg(duration_ms) FILTER (WHERE duration_ms > 0), 0)::float8 AS avg_ms
FROM requests
WHERE site_id = @site_id AND ts >= @from_ts AND ts < @to_ts
GROUP BY path ORDER BY 2 DESC LIMIT @lim;

-- name: TopReasons :many
SELECT tag, reason, count(*)::bigint AS requests, count(DISTINCT ip)::bigint AS ips
FROM requests
WHERE site_id = @site_id AND ts >= @from_ts AND ts < @to_ts AND tag <> 'human'
GROUP BY tag, reason ORDER BY 3 DESC LIMIT @lim;

-- name: ListRequests :many
SELECT ts, ip, method, host, path, query, status, bytes, duration_ms, ua, referer, country, tag, reason
FROM requests
WHERE site_id = @site_id
  AND ts >= @from_ts AND ts < @to_ts
  AND (sqlc.narg(tag)::text IS NULL OR tag = sqlc.narg(tag))
  AND (sqlc.narg(ip)::inet IS NULL OR ip = sqlc.narg(ip))
  AND (sqlc.narg(country)::text IS NULL OR country = sqlc.narg(country))
  AND (sqlc.narg(status_min)::int IS NULL OR status >= sqlc.narg(status_min))
  AND (sqlc.narg(status_max)::int IS NULL OR status <= sqlc.narg(status_max))
  AND (sqlc.narg(path_prefix)::text IS NULL OR path LIKE sqlc.narg(path_prefix) || '%')
  AND (sqlc.narg(method)::text IS NULL OR method = sqlc.narg(method))
ORDER BY ts DESC
LIMIT @lim;
