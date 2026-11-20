//! All user-tunable settings for the monitoring pipeline.
//! Storage layer persists these as a JSON blob plus a key-value view.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MonitoringMode {
    DirectOnly,
    VpnOnly,
    #[default]
    Auto,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SpeedTestMode {
    Off,
    ManualOnly,
    Scheduled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
/// How DIRECT route correctness is enforced.
pub enum DirectStrictness {
    #[default]
    /// Never report DIRECT data unless the egress route is verified
    /// independent from the VPN tunnel. Safest default.
    Strict,
    /// Report DIRECT data when no TUN/proxy is detected on the system.
    Auto,
    Off,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AppSettings {
    pub monitoring_mode: MonitoringMode,
    pub direct_strictness: DirectStrictness,
    /// Light connectivity check interval (seconds).
    pub connectivity_check_secs: u64,
    /// Service monitoring interval (seconds).
    pub service_check_secs: u64,
    /// Deep diagnostics: true = run automatically after anomaly, false = manual.
    pub deep_diagnostics_on_anomaly: bool,
    pub max_parallel_probes: usize,
    pub probe_timeout_ms: u64,
    pub dns_timeout_ms: u64,
    pub http_timeout_ms: u64,
    pub probe_retries: u32,
    pub download_body_limit_bytes: u64,
    /// Max HTTP redirects that a probe will follow.
    pub max_redirects: u32,
    pub speed_tests: SpeedTestMode,
    /// Interval for scheduled speed tests (minutes), when enabled.
    pub speed_test_interval_min: u64,
    /// Bytes downloaded during a speed test (default 10 MiB).
    pub speed_test_bytes: u64,
    /// User-defined egress verification endpoints. Empty => defaults.
    pub egress_endpoints: Vec<String>,
    /// Known-good DoH endpoint used as control resolver.
    pub control_doh_url: String,
    /// Query RIPEstat for ASN of external IP (external request, default off).
    pub lookup_asn: bool,
    pub notifications_enabled: bool,
    /// Urls/domains that always must NOT be probed as DIRECT (policy).
    pub direct_exclude_patterns: Vec<String>,
    /// Body fragments (lowercase) that mark a response as a local block page.
    pub block_page_patterns: Vec<String>,
    /// Allow probing hostnames that resolve to private/loopback/link-local
    /// addresses. Off by default (SSRF guard).
    pub allow_private_targets: bool,
    /// User-configured proxy to use as an additional VPN route.
    pub custom_proxy: Option<crate::models::ProxyEndpoint>,
    /// Days of probe history kept before purge.
    pub history_retention_days: u32,
    /// Delete stored external IPs when app closes (privacy).
    pub hide_external_ips: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            monitoring_mode: MonitoringMode::Auto,
            direct_strictness: DirectStrictness::Strict,
            connectivity_check_secs: 20,
            service_check_secs: 120,
            deep_diagnostics_on_anomaly: true,
            max_parallel_probes: 4,
            probe_timeout_ms: 6000,
            dns_timeout_ms: 4000,
            http_timeout_ms: 12000,
            probe_retries: 2,
            download_body_limit_bytes: 1024 * 512,
            max_redirects: 5,
            speed_tests: SpeedTestMode::ManualOnly,
            speed_test_interval_min: 240,
            speed_test_bytes: 10 * 1024 * 1024,
            egress_endpoints: vec![
                "https://1.1.1.1/cdn-cgi/trace".to_string(),
                "https://1.0.0.1/cdn-cgi/trace".to_string(),
                "https://ipv4.icanhazip.com".to_string(),
                "https://[2606:4700:4700::1111]/cdn-cgi/trace".to_string(),
            ],
            control_doh_url: "https://1.1.1.1/dns-query".to_string(),
            lookup_asn: false,
            notifications_enabled: true,
            direct_exclude_patterns: vec![],
            block_page_patterns: vec![
                "доступ ограничен".into(),
                "доступ запрещён".into(),
                "заблокировано".into(),
                "blocked by isp".into(),
                "proxy denied".into(),
                "access denied".into(),
                "access restricted".into(),
                " dieser inhalt ist".into(),
            ],
            allow_private_targets: false,
            custom_proxy: None,
            history_retention_days: 30,
            hide_external_ips: false,
        }
    }
}

impl AppSettings {
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.connectivity_check_secs < 5 {
            return Err("connectivity_check_secs must be >= 5".into());
        }
        if self.service_check_secs < 15 {
            return Err("service_check_secs must be >= 15".into());
        }
        if !(1..=32).contains(&self.max_parallel_probes) {
            return Err("max_parallel_probes must be 1..=32".into());
        }
        if self.probe_timeout_ms < 500 || self.probe_timeout_ms > 60_000 {
            return Err("probe_timeout_ms must be in 500..60000".into());
        }
        if self.probe_retries > 5 {
            return Err("probe_retries must be <= 5".into());
        }
        if self.download_body_limit_bytes == 0 || self.download_body_limit_bytes > 16 * 1024 * 1024 {
            return Err("download_body_limit_bytes must be in 1..16777216".into());
        }
        if self.max_redirects > 10 {
            return Err("max_redirects must be <= 10".into());
        }
        Ok(())
    }
}
