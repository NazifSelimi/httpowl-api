-- +goose Up
CREATE TABLE users (
    id            bigserial PRIMARY KEY,
    email         text NOT NULL,
    name          text NOT NULL DEFAULT '',
    password_hash text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email_lower ON users (lower(email));

-- The cookie holds a random token; only its SHA-256 is stored.
CREATE TABLE sessions (
    token_hash   bytea PRIMARY KEY,
    user_id      bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip           text NOT NULL DEFAULT '',
    user_agent   text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL
);
CREATE INDEX sessions_user ON sessions (user_id);

-- Every action is recorded here (site_id is set once sites exist).
CREATE TABLE audit_log (
    id         bigserial PRIMARY KEY,
    site_id    bigint,
    user_id    bigint REFERENCES users(id) ON DELETE SET NULL,
    action     text NOT NULL,
    detail     jsonb NOT NULL DEFAULT '{}',
    ip         text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_site_time ON audit_log (site_id, created_at DESC);
CREATE INDEX audit_user_time ON audit_log (user_id, created_at DESC);

-- +goose Down
DROP TABLE audit_log;
DROP TABLE sessions;
DROP TABLE users;
