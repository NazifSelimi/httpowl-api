-- +goose Up
-- One agent per server: visits whose domain matches another site of the same
-- owner are stored on that site, which is then "served by" the agent's site.
-- Blocks of all those sites apply on that server (the firewall is per server).
ALTER TABLE sites ADD COLUMN served_by bigint REFERENCES sites(id) ON DELETE SET NULL;
CREATE INDEX sites_served_by ON sites (served_by);

-- +goose Down
ALTER TABLE sites DROP COLUMN served_by;
