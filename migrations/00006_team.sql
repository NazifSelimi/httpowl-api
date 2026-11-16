-- +goose Up
-- Invites for people who don't have an account yet; accepted on sign-up.
CREATE TABLE site_invites (
    site_id    bigint NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    email      text NOT NULL,
    role       text NOT NULL CHECK (role IN ('owner','admin','viewer','client')),
    invited_by bigint REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX site_invites_unique ON site_invites (site_id, lower(email));
CREATE INDEX site_invites_email ON site_invites (lower(email));

-- +goose Down
DROP TABLE site_invites;
