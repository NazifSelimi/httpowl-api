-- +goose Up
-- Block rules. Removing a rule sets removed_at (so it can be restored = undo).
CREATE TABLE rules (
    id         bigserial PRIMARY KEY,
    site_id    bigint NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    kind       text NOT NULL CHECK (kind IN ('ip','cidr','country','bot')),
    value      text NOT NULL,
    note       text NOT NULL DEFAULT '',
    created_by bigint REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    removed_by bigint REFERENCES users(id) ON DELETE SET NULL,
    removed_at timestamptz
);
CREATE UNIQUE INDEX rules_active_unique ON rules (site_id, kind, value) WHERE removed_at IS NULL;
CREATE INDEX rules_site ON rules (site_id, created_at DESC);

-- +goose Down
DROP TABLE rules;
