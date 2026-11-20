-- NetScope schema v2: richer route profiles, network context per measurement.
-- All statements are SQLite-compatible (ADD COLUMN with defaults).

ALTER TABLE routes ADD COLUMN dns_servers_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE routes ADD COLUMN egress_json TEXT;
ALTER TABLE routes ADD COLUMN vpn_status TEXT;

ALTER TABLE probe_results ADD COLUMN network_context_id TEXT;

ALTER TABLE network_contexts ADD COLUMN interfaces_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE network_contexts ADD COLUMN routes_json TEXT NOT NULL DEFAULT '[]';

CREATE INDEX IF NOT EXISTS idx_probe_results_context
    ON probe_results (network_context_id);
