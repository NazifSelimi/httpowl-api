-- +goose Up
CREATE TABLE daily_notes (
    site_id    bigint NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    day        date NOT NULL,
    body       text NOT NULL,
    stats      jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (site_id, day)
);

-- +goose Down
DROP TABLE daily_notes;
