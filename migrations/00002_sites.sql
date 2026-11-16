-- +goose Up
CREATE TABLE sites (
    id                 bigserial PRIMARY KEY,
    name               text NOT NULL,
    domain             text NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    agent_last_seen_at timestamptz,
    agent_info         jsonb NOT NULL DEFAULT '{}',
    -- IPs that rules must never block (server's own IPs, SSH peers), reported by the agent.
    protected_ips      text[] NOT NULL DEFAULT '{}'
);

CREATE TABLE site_members (
    site_id    bigint NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    user_id    bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       text NOT NULL CHECK (role IN ('owner','admin','viewer','client')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (site_id, user_id)
);
CREATE INDEX site_members_user ON site_members (user_id);

CREATE TABLE agent_tokens (
    id         bigserial PRIMARY KEY,
    site_id    bigint NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,
    prefix     text NOT NULL,
    created_by bigint REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);
CREATE INDEX agent_tokens_site ON agent_tokens (site_id);

-- +goose Down
DROP TABLE agent_tokens;
DROP TABLE site_members;
DROP TABLE sites;
