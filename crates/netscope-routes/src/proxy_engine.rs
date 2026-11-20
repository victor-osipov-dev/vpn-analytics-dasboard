//! Proxy-based route engine: HTTP/HTTPS/SOCKS5 proxy verification.
//! Ensures the proxy is reachable and reports the actual exit identity.

use netscope_core::models::EgressIdentity;
use netscope_probes::http::HttpClientRecipe;

use crate::verify::{egress_probe, EgressProbeTarget};
use crate::EngineSettings;

/// Probe egress through an explicitly configured proxy client.
pub async fn probe_proxy_egress(proxy_url: &str, settings: EngineSettings) -> EgressIdentity {
    let targets: Vec<EgressProbeTarget> = settings
        .egress_endpoints
        .iter()
        .filter_map(|u| EgressProbeTarget::from_url(u))
        .collect();

    let recipe = HttpClientRecipe {
        proxy_url: proxy_url.to_string(),
        no_proxy_env: true,
        local_address: None,
        resolve_overrides: vec![],
        body_limit_bytes: 64 * 1024,
        max_redirects: 3,
        timeout_ms: settings.http_timeout_ms,
        user_agent: "NetScope/0.1 (egress-proxy)".into(),
        ..Default::default()
    };
    egress_probe(
        targets,
        recipe,
        format!("via proxy {proxy_url}"),
        settings.lookup_asn,
    )
    .await
}
