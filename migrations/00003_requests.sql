-- +goose Up
-- One row per HTTP request, partitioned by day (requests_YYYYMMDD), kept 30 days.
CREATE TABLE requests (
    site_id     bigint NOT NULL,
    ts          timestamptz NOT NULL,
    ip          inet NOT NULL,
    method      text NOT NULL,
    host        text NOT NULL DEFAULT '',
    path        text NOT NULL,
    query       text NOT NULL DEFAULT '',
    proto       text NOT NULL DEFAULT '',
    status      smallint NOT NULL,
    bytes       bigint NOT NULL DEFAULT 0,
    duration_ms real NOT NULL DEFAULT 0,
    ua          text NOT NULL DEFAULT '',
    referer     text NOT NULL DEFAULT '',
    country     text NOT NULL DEFAULT '',
    tag         text NOT NULL DEFAULT 'human', -- human | bot | attack
    reason      text NOT NULL DEFAULT ''
) PARTITION BY RANGE (ts);
CREATE INDEX requests_site_ts ON requests (site_id, ts DESC);
CREATE INDEX requests_site_ip ON requests (site_id, ip, ts DESC);

-- +goose Down
DROP TABLE requests;
