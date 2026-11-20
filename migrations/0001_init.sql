-- NetScope schema v1
-- Local-first storage: measurements stay on this machine.

CREATE TABLE IF NOT EXISTS agent_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS targets (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    category TEXT NOT NULL,
    check_url TEXT NOT NULL,
    endpoints_json TEXT NOT NULL DEFAULT '[]',
    favorite INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL DEFAULT 5,
    notes TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS network_contexts (
    id TEXT PRIMARY KEY,
    snapshot_fingerprint TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    active_interface TEXT,
    gateway TEXT,
    dns_servers_json TEXT NOT NULL DEFAULT '[]',
    system_proxy_enabled INTEGER NOT NULL DEFAULT 0,
    tunnel_detected INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS routes (
    id TEXT PRIMARY KEY,
    mode TEXT NOT NULL,
    name TEXT NOT NULL,
    interface_name TEXT,
    proxy_type TEXT,
    vpn_kind TEXT,
    vpn_endpoint TEXT,
    verification TEXT NOT NULL,
    confidence TEXT NOT NULL,
    verification_reason TEXT,
    external_ip TEXT,
    external_ipv6 TEXT,
    verified_at TEXT
);

CREATE TABLE IF NOT EXISTS probe_results (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    target_label TEXT NOT NULL,
    route_id TEXT NOT NULL,
    route_mode TEXT NOT NULL,
    correctness TEXT NOT NULL,
    status TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    duration_ms REAL NOT NULL DEFAULT 0,
    ip_family TEXT,
    network_fingerprint TEXT NOT NULL DEFAULT '',
    network_changed INTEGER NOT NULL DEFAULT 0,
    dns_json TEXT,
    tcp_json TEXT,
    tls_json TEXT,
    http_json TEXT,
    perf_json TEXT,
    error TEXT
);

CREATE INDEX IF NOT EXISTS idx_probe_results_target
    ON probe_results (target_id, route_mode, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_probe_results_ts
    ON probe_results (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_probe_results_route
    ON probe_results (route_id, timestamp DESC);

CREATE TABLE IF NOT EXISTS diagnoses (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    route_mode TEXT,
    category TEXT NOT NULL,
    confidence TEXT NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '[]',
    alternative_json TEXT NOT NULL DEFAULT '[]',
    backed_by_control INTEGER NOT NULL DEFAULT 0,
    detected_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_diagnoses_target
    ON diagnoses (target_id, detected_at DESC);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    target_id TEXT,
    route_mode TEXT,
    message TEXT NOT NULL,
    details TEXT,
    started_at TEXT NOT NULL,
    resolved_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_incidents_started
    ON incidents (started_at DESC);

CREATE TABLE IF NOT EXISTS external_observations (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    target_id TEXT,
    observed_at TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    credibility TEXT NOT NULL DEFAULT 'low'
);
