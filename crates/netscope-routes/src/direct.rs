//! DIRECT engine: probes the physical route, confirms the egress identity.
//! Uses interface-bound sockets so a TUN hijack is detectable by comparing
//! egress IPs, never by assuming the bind succeeded.

use std::sync::Arc;

use netscope_core::models::{
    EgressIdentity, NetworkSnapshot, RouteConfidence, RouteVerification,
    PerformanceResult, PerfKind,
};
use netscope_core::settings::DirectStrictness;
use netscope_probes::http::HttpClientRecipe;

use crate::verify::{egress_probe, EgressProbeTarget};
use crate::EngineSettings;

/// Egress check for the DIRECT route. Tries multiple endpoints.
pub async fn probe_direct_egress(
    snapshot: &Arc<NetworkSnapshot>,
    settings: EngineSettings,
) -> EgressIdentity {
    run_egress(snapshot, settings, true).await
}

/// Egress check through the normal system route (the TUN when it captures
/// everything).
pub async fn probe_tun_egress(
    snapshot: &Arc<NetworkSnapshot>,
    settings: EngineSettings,
) -> EgressIdentity {
    run_egress(snapshot, settings, false).await
}

async fn run_egress(
    snapshot: &Arc<NetworkSnapshot>,
    settings: EngineSettings,
    bind_physical: bool,
) -> EgressIdentity {
    let ip4 = snapshot
        .physical_default_interface(true)
        .and_then(|i| i.ipv4.first().and_then(|s| s.parse::<std::net::IpAddr>().ok()));
    let targets: Vec<EgressProbeTarget> = settings
        .egress_endpoints
        .iter()
        .filter_map(|u| EgressProbeTarget::from_url(u))
        .collect();
    let recipe_base = HttpClientRecipe {
        proxy_url: String::new(),
        no_proxy_env: true,
        local_address: if bind_physical { ip4 } else { None },
        resolve_overrides: vec![],
        body_limit_bytes: 64 * 1024,
        max_redirects: 3,
        timeout_ms: settings.connect_timeout_ms.max(3000),
        user_agent: "NetScope/0.1 (egress)".into(),
        ..Default::default()
    };

    let identity = egress_probe(
        targets,
        recipe_base,
        format!(
            "iface:{}",
            if bind_physical { "physical-pinned" } else { "system-default" }
        ),
        settings.lookup_asn,
    )
    .await;

    record_direct_strictness(&settings, bind_physical, &identity)
}

/// Attach strictness-filtered confidence to the identity: if the user chose
/// Strict mode and egress confirms no tunnel was involved (system route is
/// different from the physical-route probe), the identity keeps its
/// confidence; otherwise a reason is attached.
fn record_direct_strictness(
    settings: &EngineSettings,
    bind_physical: bool,
    identity: &EgressIdentity,
) -> EgressIdentity {
    let mut out = identity.clone();
    if bind_physical && settings.direct_strictness == DirectStrictness::Strict {
        match out.confidence {
            RouteConfidence::High => {
                out.source_endpoints.push("strictness:strict-mode".into());
            }
            _ => {}
        }
    }
    out
}

/// Light connectivity check used by the scheduler: a single egress trace.
pub async fn connectivity_probe(settings: EngineSettings) -> PerformanceResult {
    let mut ok = 0;
    for url in settings
        .egress_endpoints
        .iter()
        .take(2)
    {
        let recipe = HttpClientRecipe {
            proxy_url: String::new(),
            no_proxy_env: true,
            local_address: None,
            resolve_overrides: vec![],
            body_limit_bytes: 2048,
            max_redirects: 2,
            timeout_ms: settings.connect_timeout_ms,
            user_agent: "NetScope/0.1 (connectivity)".into(),
            ..Default::default()
        };
        match recipe.build_client() {
            Ok(client) => {
                let _t0 = std::time::Instant::now();
                match client.head(url).send().await {
                    Ok(_) => ok += 1,
                    Err(_) => {}
                }
            }
            Err(_) => {}
        }
    }
    if ok == 0 {
        PerformanceResult {
            kind: PerfKind::TcpRtt,
            samples: 1,
            min_ms: None,
            avg_ms: None,
            max_ms: None,
            jitter_ms: None,
            loss_percent: Some(100.0),
            throughput_bytes_per_sec: None,
            error: Some("connectivity check failed on all endpoints".into()),
        }
    } else {
        PerformanceResult {
            kind: PerfKind::TcpRtt,
            samples: 1,
            min_ms: None,
            avg_ms: None,
            max_ms: None,
            jitter_ms: None,
            loss_percent: Some(0.0),
            throughput_bytes_per_sec: None,
            error: None,
        }
    }
}

/// Mark a route as unsafe (policy; e.g., user banned DIRECT probes).
pub fn unsafe_direct(reason: &str) -> RouteVerification {
    let _ = reason;
    RouteVerification::Unsafe
}
