//! One full measurement pipeline for a (target, route) pair:
//! DNS -> TCP -> TLS -> HTTP, bound to a concrete route recipe, with
//! retry/backoff and honest route-error attribution.

use std::net::IpAddr;
use std::time::Instant;

use netscope_core::models::{
    AvailabilityStatus, ProbeResult, RouteProfile, RouteVerificationKind as VerificationKind,
    Target, TargetEndpoint,
};
use netscope_core::settings::AppSettings;
use netscope_probes::dns::{DnsProbe, DnsProbeOptions, ServerSpec};
use netscope_probes::http::{HttpClientRecipe, HttpOptions, HttpProbe};
use netscope_probes::perf::{PerfOptions, PerformanceProbe};
use netscope_probes::tcp::{TcpOptions, TcpProbe, TcpTarget};
use netscope_probes::tls::{TlsProbe, TlsTarget};
use netscope_routes::EngineSettings;

use crate::Scheduler;

/// Default block-page markers; the active list comes from user settings.
pub const DEFAULT_BLOCK_PAGE_PATTERNS: &[&str] = &[
    "доступ ограничен",
    "доступ запрещён",
    "заблокировано",
    "blocked by isp",
    "proxy denied",
];

/// Full pipeline with retries. Each failed attempt gets a linear backoff;
/// successful or route-level-fatal attempts stop the loop immediately.
pub async fn probe_target_once(
    sched: &Scheduler,
    target: &Target,
    route: &RouteProfile,
    fingerprint_at_start: &str,
    engine: EngineSettings,
) -> ProbeResult {
    let settings = sched.load_settings().await;
    let attempts = (1 + settings.probe_retries).clamp(1, 6);
    let started = Instant::now();
    let mut result = ProbeResult::new(&target.id, &target.label, route);
    result.network_fingerprint = fingerprint_at_start.to_string();
    result.correctness = correctness_of(route);

    let snapshot = sched.route_manager.snapshot().await;
    let endpoint: TargetEndpoint = target
        .endpoints
        .first()
        .cloned()
        .unwrap_or_else(|| TargetEndpoint {
            hostname: endpoint_hostname(&target.check_url),
            port: url_port(&target.check_url).unwrap_or(443),
            ip_family: netscope_core::models::IpFamily::Any,
            pinned_ip: None,
        });

    for attempt in 0..attempts {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(250 * attempt as u64)).await;
        }
        result = attempt_once(sched, target, route, &endpoint, &engine, snapshot.as_deref(), fingerprint_at_start)
            .await;
        // Stop on healthy or route-fatal outcomes; plain failures retry.
        let stop = matches!(
            result.status,
            AvailabilityStatus::Available
                | AvailabilityStatus::Partial
                | AvailabilityStatus::SuspectedFiltering
        ) || result.route_error();
        if stop {
            break;
        }
    }
    result.duration_ms = started.elapsed().as_secs_f64() * 1000.0;
    result
}

fn correctness_of(route: &RouteProfile) -> VerificationKind {
    use netscope_core::models::RouteVerification as V;
    match route.verification {
        V::Verified => VerificationKind::Verified,
        V::Unverified => VerificationKind::Unverified,
        V::Unavailable => VerificationKind::Unavailable,
        V::Unsafe => VerificationKind::Unsafe,
    }
}

async fn attempt_once(
    sched: &Scheduler,
    target: &Target,
    route: &RouteProfile,
    endpoint: &TargetEndpoint,
    engine: &EngineSettings,
    snapshot: Option<&netscope_core::models::NetworkSnapshot>,
    fingerprint_at_start: &str,
) -> ProbeResult {
    let settings = sched.load_settings().await;
    let mut result = ProbeResult::new(&target.id, &target.label, route);
    result.network_fingerprint = fingerprint_at_start.to_string();
    if let Ok(Some(ctx_id)) = sched.store.context_id_for(fingerprint_at_start).await {
        result.network_context_id = Some(ctx_id);
    }
    result.correctness = correctness_of(route);
    result.ip_family_used = Some(endpoint.ip_family);

    // ---- Route binding ----
    let bind_local: Option<IpAddr> = if route.mode == netscope_core::models::RouteMode::Direct {
        snapshot
            .and_then(|s| s.physical_default_interface(true))
            .and_then(|i| i.ipv4.first().cloned())
            .and_then(|ip| ip.parse().ok())
    } else {
        None
    };

    // ---- DNS stage ----
    let mut resolved_ip: Option<IpAddr> = None;
    if let Some(pinned) = endpoint.pinned_ip.as_deref() {
        match pinned.parse::<IpAddr>() {
            Ok(ip) => resolved_ip = Some(ip),
            Err(e) => {
                result.error = Some(format!("pinned ip недопустим: {e}"));
                return result;
            }
        }
    } else {
        let is_v6 = matches!(endpoint.ip_family, netscope_core::models::IpFamily::V6);
        let is_direct = route.mode == netscope_core::models::RouteMode::Direct;
        // DIRECT must resolve through the physical interface's own resolvers,
        // otherwise a full-tunnel DNS hijack would silently "prove" DIRECT
        // with answers that actually came through the VPN.
        let mut servers: Vec<ServerSpec> = if is_direct {
            snapshot
                .and_then(|s| s.physical_default_interface(true))
                .map(|iface| {
                    iface
                        .dns_servers
                        .iter()
                        .filter_map(|s| parse_server(s))
                        .collect()
                })
                .unwrap_or_default()
        } else {
            let mut list: Vec<ServerSpec> = route
                .dns_servers
                .iter()
                .filter_map(|s| parse_server(s))
                .collect();
            if list.is_empty() {
                if let Some(snap) = snapshot {
                    list = snap
                        .dns_servers
                        .iter()
                        .filter_map(|s| parse_server(s))
                        .collect();
                }
            }
            list
        };
        if servers.is_empty() && is_direct {
            result.error = Some(
                "DIRECT: у физического интерфейса нет DNS-серверов — DNS-проверка невозможна".into(),
            );
            return result;
        }
        if servers.is_empty() {
            servers = vec![ServerSpec { ip: "1.1.1.1".parse().unwrap(), port: 53 }];
        }
        let dns = DnsProbe::probe(DnsProbeOptions {
            servers: &servers,
            name: &endpoint.hostname,
            query_v6: is_v6,
            dns_timeout_ms: settings.dns_timeout_ms,
            bind_local,
            control_doh_url: &engine.control_doh_url,
            use_system_stack: !is_direct,
        })
        .await;
        if dns.status == netscope_core::models::DnsStatus::Ok {
            let answers = if is_v6 && !dns.answers_v6.is_empty() {
                &dns.answers_v6
            } else if !dns.answers_v4.is_empty() {
                &dns.answers_v4
            } else {
                &dns.answers_v6
            };
            if let Some(a) = answers.first() {
                resolved_ip = a.ip.parse().ok();
            }
        } else if dns.mismatch {
            // Resolver returned something contradicting the clean control
            // check: a strong filtering signal, do not retry this route.
            result.dns = Some(dns);
            result.error = Some("DNS-ответ противоречит контрольному DoH (подозрение на DNS-фильтрацию)".into());
            return result;
        }
        result.dns = Some(dns);
        if resolved_ip.is_none() && result.error.is_none() {
            result.error = Some("DNS не вернул A/AAAA-ответ".into());
        }
        if resolved_ip.is_none() {
            return result;
        }
    }

    let ip = resolved_ip.expect("resolved");

    // SSRF guard: a hostname must not silently resolve into a private,
    // loopback, link-local or multicast address.
    if !settings.allow_private_targets && netscope_probes::http::forbidden_ip(&ip) {
        result.error = Some(format!(
            "разрешённый адрес {ip} является приватным/loopback — проверка заблокирована"
        ));
        return result;
    }

    // ---- TCP stage ----
    let tcp = TcpProbe::connect(
        TcpTarget {
            hostname: endpoint.hostname.clone(),
            ip,
            port: endpoint.port,
        },
        TcpOptions {
            connect_timeout_ms: settings.probe_timeout_ms,
            bind_local,
        },
    )
    .await;
    let tcp_ok = tcp.status == netscope_core::models::TcpStatus::Connected;
    result.tcp = Some(tcp);
    if !tcp_ok {
        if result.error.is_none() {
            result.error = Some("TCP connect failed".into());
        }
        return result;
    }

    // ---- TLS stage ----
    let use_tls = endpoint.port == 443
        || endpoint.port == 8443
        || target.check_url.starts_with("https://");
    if use_tls {
        let tls = TlsProbe::handshake(TlsTarget {
            host: &endpoint.hostname,
            port: endpoint.port,
            ip,
            fixture_tcp: None,
            timeout_ms: settings.probe_timeout_ms,
        })
        .await;
        let tls_ok = tls.status == netscope_core::models::TlsStatus::HandshakeOk;
        let tls_err = tls.error.clone();
        result.tls = Some(tls);
        if !tls_ok {
            if result.error.is_none() {
                result.error = Some(tls_err.unwrap_or_else(|| "TLS handshake failed".into()));
            }
            return result;
        }
    }

    // ---- HTTP stage ----
    let recipe =
        build_recipe(route, endpoint, ip, bind_local, &settings, engine);
    let http = HttpProbe::probe(HttpOptions {
        url: &target.check_url,
        recipe,
        block_page_patterns: &settings.block_page_patterns,
    })
    .await;
    let http_ok = matches!(
        http.status,
        netscope_core::models::HttpStatus::Ok | netscope_core::models::HttpStatus::Redirected
    );
    let http_err = http.error.clone();
    result.http = Some(http);
    if !http_ok && result.error.is_none() {
        result.error = http_err;
    }

    // ---- Performance micro-probe (only after a healthy connect) ----
    result.performance = Some(
        PerformanceProbe::tcp_rtt(
            ip,
            endpoint.port,
            PerfOptions {
                samples: 3,
                connect_timeout_ms: settings.probe_timeout_ms.min(4000),
                spacing_ms: 120,
            },
        )
        .await,
    );
    result
}

fn endpoint_hostname(url: &str) -> String {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let host = rest.split('/').next().unwrap_or(rest);
    host.split('@').last().unwrap_or(host).to_string()
}

fn url_port(url: &str) -> Option<u16> {
    let scheme_port = if url.starts_with("https://") {
        443
    } else if url.starts_with("http://") {
        80
    } else {
        return None;
    };
    let rest = url.split("://").nth(1)?;
    let hostport = rest.split('/').next()?;
    let after = hostport.rsplit_once(':')?.1;
    after.parse().ok().or(Some(scheme_port))
}

fn parse_server(s: &str) -> Option<ServerSpec> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest.find(']')?;
        let ip: IpAddr = rest[..end].parse().ok()?;
        let after = &rest[end + 1..];
        let port = after
            .strip_prefix(':')
            .and_then(|p| p.split('/').next())
            .and_then(|p| p.parse().ok())
            .unwrap_or(53);
        return Some(ServerSpec { ip, port });
    }
    if let Some((host, port)) = s.rsplit_once(':') {
        if let (Ok(ip), Ok(port)) = (host.parse::<IpAddr>(), port.parse::<u16>()) {
            return Some(ServerSpec {
                ip,
                port: if port == 0 { 53 } else { port },
            });
        }
    }
    s.parse::<IpAddr>().ok().map(|ip| ServerSpec { ip, port: 53 })
}

/// Route-aware HTTP client recipe.
fn build_recipe(
    route: &RouteProfile,
    endpoint: &TargetEndpoint,
    ip: IpAddr,
    bind_local: Option<IpAddr>,
    settings: &AppSettings,
    engine: &EngineSettings,
) -> HttpClientRecipe {
    use netscope_core::models::RouteMode;
    let mut recipe = HttpClientRecipe {
        proxy_url: String::new(),
        no_proxy_env: false,
        local_address: None,
        resolve_overrides: vec![],
        body_limit_bytes: settings.download_body_limit_bytes,
        max_redirects: settings.max_redirects,
        timeout_ms: settings.http_timeout_ms,
        user_agent: "NetScope/1.0 (availability probe)".into(),
        ..Default::default()
    };
    match route.mode {
        RouteMode::Direct => {
            recipe.no_proxy_env = true;
            recipe.local_address = bind_local;
            recipe.resolve_overrides = vec![(endpoint.hostname.clone(), ip.to_string())];
        }
        RouteMode::Vpn => {
            // System default path through the tunnel; pin the resolved IP so
            // a second DNS round-trip cannot change the measured destination.
            recipe.no_proxy_env = true;
            recipe.resolve_overrides = vec![(endpoint.hostname.clone(), ip.to_string())];
        }
        RouteMode::System | RouteMode::CustomProxy => {
            if let Some(endpoint_str) = &route.vpn_endpoint {
                let kind = route.proxy_type.as_deref().unwrap_or("http");
                let scheme = match kind {
                    "socks5" | "socks5remotedns" => "socks5",
                    "https" => "https",
                    _ => "http",
                };
                recipe.proxy_url = format!("{scheme}://{}{endpoint_str}", proxy_auth(route, settings));
            }
        }
    }
    let _ = engine;
    recipe
}

/// `user:pass@` fragment. The password comes exclusively from the OS secret
/// store; credentials are never persisted with the settings blob.
fn proxy_auth(route: &RouteProfile, settings: &AppSettings) -> String {
    let Some(endpoint_str) = route.vpn_endpoint.as_deref() else {
        return String::new();
    };
    let Some(user) = settings
        .custom_proxy
        .as_ref()
        .filter(|p| format!("{}:{}", p.host, p.port) == endpoint_str)
        .and_then(|p| p.username.clone())
        .filter(|u| !u.is_empty())
    else {
        return String::new();
    };
    let Some(password) = secret_password(endpoint_str) else {
        return String::new();
    };
    // Only emit auth when the password is URL-safe (no encoding dep).
    if password.is_empty()
        || password.chars().any(|c| {
            matches!(c, ':' | '@' | '/' | ' ' | '#' | '%' | '?')
        })
    {
        return String::new();
    }
    format!("{user}:{password}@")
}

#[cfg(feature = "keyring-secure")]
fn secret_password(endpoint: &str) -> Option<String> {
    let entry = keyring::Entry::new("NetScope", &format!("proxy:{endpoint}")).ok()?;
    entry.get_password().ok()
}

#[cfg(not(feature = "keyring-secure"))]
fn secret_password(_endpoint: &str) -> Option<String> {
    None
}
