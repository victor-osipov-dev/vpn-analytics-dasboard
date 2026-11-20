//! Deep diagnostic pipeline: localises an interruption to a concrete stage
//! by combining DNS, TCP, TLS/SNI, HTTP versions, PMTU and path checks with
//! independent control measurements. Mirrors the diagnostic methodology in
//! the product plan (tests 1-6).

use std::net::IpAddr;
use std::time::{Duration, Instant};

use netscope_core::models::{
    DeepCheck, DeepCheckStatus, DeepDiagnosticReport, DiagnosisCategory, DiagnosisConfidence,
    DnsStatus, RouteMode, TcpStatus,
};

use crate::dns::{DnsProbe, DnsProbeOptions, ServerSpec};
use crate::perf::PerformanceProbe;
use crate::tcp::{TcpOptions, TcpProbe, TcpTarget};
use crate::tls;

const CONTROL_SNI: &str = "example.com";
const CONTROL_IP: &str = "1.1.1.1";
const SMALL_URL: &str = "https://speed.cloudflare.com/__down?bytes=1024";
const LARGE_URL: &str = "https://speed.cloudflare.com/__down?bytes=262144";

pub struct DeepOptions<'a> {
    pub url: &'a str,
    pub route_mode: RouteMode,
    pub timeout_ms: u64,
    pub control_doh_url: &'a str,
    pub dns_servers: Vec<ServerSpec>,
    pub bind_local: Option<IpAddr>,
    /// Run traceroute when available (Windows + IPv4).
    pub traceroute: bool,
    /// Explicit proxy URL for proxy-based routes; empty for DIRECT/VPN/TUN.
    pub proxy_url: String,
}

fn check(
    name: &str,
    status: DeepCheckStatus,
    summary: impl Into<String>,
    details: Vec<String>,
    started: Instant,
) -> DeepCheck {
    DeepCheck {
        name: name.into(),
        status,
        summary: summary.into(),
        details,
        duration_ms: Some(started.elapsed().as_secs_f64() * 1000.0),
    }
}

fn client_builder(opts: &DeepOptions<'_>) -> reqwest::ClientBuilder {
    let mut b = reqwest::Client::builder()
        .timeout(Duration::from_millis(opts.timeout_ms))
        .danger_accept_invalid_certs(false);
    if !opts.proxy_url.is_empty() {
        if let Ok(p) = reqwest::Proxy::all(&opts.proxy_url) {
            b = b.proxy(p);
        }
    } else {
        b = b.no_proxy();
    }
    if let Some(ip) = opts.bind_local {
        b = b.local_address(ip);
    }
    b
}

async fn http_version_probe(
    opts: &DeepOptions<'_>,
    version: &str,
) -> (bool, String, Vec<String>) {
    let builder = client_builder(opts);
    let builder = match version {
        "http1" => builder.http1_only(),
        "http2" => builder.http2_prior_knowledge(),
        "http3" => builder.http3_prior_knowledge(),
        _ => builder,
    };
    let Ok(client) = builder.build() else {
        return (false, "client build failed".into(), vec![]);
    };
    let started = Instant::now();
    match client.get(opts.url).send().await {
        Ok(resp) => {
            let code = resp.status().as_u16();
            let actual = format!("{:?}", resp.version());
            let ms = started.elapsed().as_secs_f64() * 1000.0;
            (
                resp.status().is_success(),
                format!("HTTP {code} via {actual} ({ms:.0} ms)"),
                vec![format!("requested={version} actual={actual}")],
            )
        }
        Err(e) => {
            let ms = started.elapsed().as_secs_f64() * 1000.0;
            (false, format!("error after {ms:.0} ms"), vec![e.to_string()])
        }
    }
}

/// Run the full deep diagnostic for one URL and route.
pub async fn run(opts: DeepOptions<'_>) -> DeepDiagnosticReport {
    let started = Instant::now();
    let mut report = DeepDiagnosticReport {
        url: opts.url.to_string(),
        route_mode: opts.route_mode,
        ..Default::default()
    };
    let mut suspected = Vec::new();
    let mut control_available = false;

    let parsed = match reqwest::Url::parse(opts.url) {
        Ok(u) => u,
        Err(e) => {
            report.checks.push(check(
                "url",
                DeepCheckStatus::Fail,
                "не удалось разобрать URL",
                vec![e.to_string()],
                started,
            ));
            report.conclusion = "Некорректный URL".into();
            report.duration_ms = started.elapsed().as_secs_f64() * 1000.0;
            return report;
        }
    };
    let host = parsed.host_str().unwrap_or("").to_string();
    let port = parsed.port_or_known_default().unwrap_or(443);

    // --- 1. DNS by name vs independent control -----------------------------
    let dns_start = Instant::now();
    let mut servers = opts.dns_servers.clone();
    if servers.is_empty() {
        if let Ok(ip) = CONTROL_IP.parse() {
            servers.push(ServerSpec { ip, port: 53 });
        }
    }
    let dns = DnsProbe::probe(DnsProbeOptions {
        servers: &servers,
        name: &host,
        query_v6: false,
        dns_timeout_ms: opts.timeout_ms,
        bind_local: opts.bind_local,
        control_doh_url: opts.control_doh_url,
        use_system_stack: false,
    })
    .await;
    let mismatch = dns.mismatch;
    let control_ok = dns.control.as_ref().map(|c| c.status == DnsStatus::Ok).unwrap_or(false);
    control_available |= control_ok;
    let dns_ok = dns.status == DnsStatus::Ok;
    report.checks.push(check(
        "dns",
        if !dns_ok {
            DeepCheckStatus::Fail
        } else if mismatch {
            DeepCheckStatus::Fail
        } else {
            DeepCheckStatus::Pass
        },
        if !dns_ok {
            format!("DNS: {:?}", dns.status)
        } else if mismatch {
            "ответы резолвера противоречат контрольному DoH".into()
        } else {
            format!("разрешено {} адресов", dns.answers_v4.len())
        },
        vec![
            format!("resolver={:?}", dns.resolver_addr),
            format!("rcode={:?}", dns.rcode),
            format!("control={:?}", dns.control.as_ref().map(|c| c.status)),
        ],
        dns_start,
    ));
    if mismatch {
        suspected.push(DiagnosisCategory::DnsFiltering);
    }
    let target_ip = dns
        .answers_v4
        .first()
        .and_then(|a| a.ip.parse::<IpAddr>().ok());
    let Some(ip) = target_ip else {
        report.conclusion = "DNS не вернул A-адрес — дальнейшие проверки по IP невозможны".into();
        report.duration_ms = started.elapsed().as_secs_f64() * 1000.0;
        return report;
    };

    // --- 2. TCP connect + control ------------------------------------------
    let tcp_start = Instant::now();
    let target_tcp = TcpProbe::connect(
        TcpTarget {
            hostname: host.clone(),
            ip,
            port,
        },
        TcpOptions {
            connect_timeout_ms: opts.timeout_ms,
            bind_local: opts.bind_local,
        },
    )
    .await;
    let control_ip: IpAddr = CONTROL_IP.parse().unwrap();
    let control_tcp = TcpProbe::connect(
        TcpTarget {
            hostname: CONTROL_IP.into(),
            ip: control_ip,
            port: 443,
        },
        TcpOptions {
            connect_timeout_ms: opts.timeout_ms,
            bind_local: None,
        },
    )
    .await;
    let control_tcp_ok = control_tcp.status == TcpStatus::Connected;
    control_available |= control_tcp_ok;
    let target_tcp_ok = target_tcp.status == TcpStatus::Connected;
    let tcp_status = if target_tcp_ok {
        DeepCheckStatus::Pass
    } else if control_tcp_ok {
        DeepCheckStatus::Fail
    } else {
        DeepCheckStatus::Inconclusive
    };
    report.checks.push(check(
        "tcp",
        tcp_status,
        format!("цель: {:?}, контроль: {:?}", target_tcp.status, control_tcp.status),
        vec![
            format!("target_ms={:?}", target_tcp.connect_ms),
            format!("control_ms={:?}", control_tcp.connect_ms),
            format!("error={:?}", target_tcp.error),
        ],
        tcp_start,
    ));
    if !target_tcp_ok && control_tcp_ok {
        if target_tcp.status == TcpStatus::Reset {
            suspected.push(DiagnosisCategory::TcpReset);
        } else {
            suspected.push(DiagnosisCategory::IpBlocked);
        }
    }

    // --- 3. TLS with target SNI vs control SNI on the same IP --------------
    let sni_start = Instant::now();
    let target_tls = tls::sni_handshake(ip, port, &host, opts.timeout_ms).await;
    let control_tls = tls::sni_handshake(ip, port, CONTROL_SNI, opts.timeout_ms).await;
    let target_tls_ok = target_tls.status == netscope_core::models::TlsStatus::HandshakeOk;
    let control_tls_ok = control_tls.status == netscope_core::models::TlsStatus::HandshakeOk;
    let sni_status = if target_tls_ok && control_tls_ok {
        DeepCheckStatus::Pass
    } else if !target_tls_ok && control_tls_ok {
        DeepCheckStatus::Fail
    } else {
        DeepCheckStatus::Inconclusive
    };
    report.checks.push(check(
        "tls_sni",
        sni_status,
        format!(
            "SNI '{host}': {:?}, SNI '{CONTROL_SNI}': {:?}",
            target_tls.status, control_tls.status
        ),
        vec![
            format!("target_stage={:?}", target_tls.failure_stage),
            format!("control_stage={:?}", control_tls.failure_stage),
            format!("target_alert={:?}", target_tls.alert),
        ],
        sni_start,
    ));
    if !target_tls_ok && control_tls_ok {
        suspected.push(DiagnosisCategory::TlsSniFiltering);
        control_available = true;
    }

    // --- 4. HTTP versions (TCP vs UDP/QUIC) --------------------------------
    let http_start = Instant::now();
    let mut version_details = vec![];
    let mut h1_ok = false;
    let mut h2_ok = false;
    let mut h3_ok = false;
    for version in ["http1", "http2", "http3"] {
        let (ok, summary, details) = http_version_probe(&opts, version).await;
        version_details.push(format!("{version}: {summary}"));
        version_details.extend(details);
        match version {
            "http1" => h1_ok = ok,
            "http2" => h2_ok = ok,
            "http3" => h3_ok = ok,
            _ => {}
        }
    }
    let tcp_http_ok = h1_ok || h2_ok;
    let http_status = if tcp_http_ok && h3_ok {
        DeepCheckStatus::Pass
    } else if tcp_http_ok && !h3_ok {
        DeepCheckStatus::Fail
    } else {
        DeepCheckStatus::Inconclusive
    };
    report.checks.push(check(
        "http_versions",
        http_status,
        format!("HTTP/1.1={h1_ok} HTTP/2={h2_ok} HTTP/3={h3_ok}"),
        version_details,
        http_start,
    ));
    if tcp_http_ok && !h3_ok {
        suspected.push(DiagnosisCategory::QuicRestriction);
    }

    // --- 5. PMTU: small vs large response ----------------------------------
    let pmtu_start = Instant::now();
    let small = http_body_probe(&opts, SMALL_URL, 4 * 1024).await;
    let large = http_body_probe(&opts, LARGE_URL, 512 * 1024).await;
    let pmtu_status = if small.0 && large.0 {
        DeepCheckStatus::Pass
    } else if small.0 && !large.0 {
        DeepCheckStatus::Fail
    } else {
        DeepCheckStatus::Inconclusive
    };
    report.checks.push(check(
        "pmtu",
        pmtu_status,
        format!("маленький ответ: {}, большой ответ: {}", small.0, large.0),
        vec![format!("small={}", small.1), format!("large={}", large.1)],
        pmtu_start,
    ));
    if small.0 && !large.0 {
        suspected.push(DiagnosisCategory::MtuBlackhole);
    }

    // --- 6. Path (traceroute) ----------------------------------------------
    if opts.traceroute && ip.is_ipv4() && cfg!(windows) {
        let route_start = Instant::now();
        let trace = PerformanceProbe::traceroute(ip, 20, 1000).await;
        let status = if trace.reached {
            DeepCheckStatus::Pass
        } else if trace.hops.is_empty() {
            DeepCheckStatus::Inconclusive
        } else {
            DeepCheckStatus::Fail
        };
        report.checks.push(check(
            "traceroute",
            status,
            format!("{} хопов, цель {}", trace.hops.len(), if trace.reached { "достигнута" } else { "не достигнута" }),
            trace
                .hops
                .iter()
                .take(12)
                .map(|h| format!("{}: {} {:?}", h.ttl, h.address.clone().unwrap_or_else(|| "*".into()), h.rtt_ms))
                .collect(),
            route_start,
        ));
    } else {
        report.checks.push(check(
            "traceroute",
            DeepCheckStatus::Skipped,
            "недоступно на этой платформе или для IPv6",
            vec![],
            started,
        ));
    }

    // --- Conclusion --------------------------------------------------------
    report.suspected_categories = suspected.clone();
    report.confidence = if control_available {
        DiagnosisConfidence::Medium
    } else {
        DiagnosisConfidence::Low
    };
    report.conclusion = if suspected.is_empty() {
        "Все доступные проверки прошли: признаков фильтрации или деградации на этом маршруте не найдено".into()
    } else {
        let names: Vec<&str> = suspected
            .iter()
            .map(|c| match c {
                DiagnosisCategory::DnsFiltering => "DNS-фильтрация",
                DiagnosisCategory::IpBlocked => "IP-блокировка",
                DiagnosisCategory::TcpReset => "TCP RST",
                DiagnosisCategory::TlsSniFiltering => "фильтрация по SNI",
                DiagnosisCategory::QuicRestriction => "ограничение QUIC/UDP",
                DiagnosisCategory::MtuBlackhole => "PMTU black hole",
                _ => "другое",
            })
            .collect();
        format!(
            "Обнаружены признаки: {}. Вывод требует повторной проверки и сравнения с другим маршрутом.",
            names.join(", ")
        )
    };
    report.duration_ms = started.elapsed().as_secs_f64() * 1000.0;
    report
}

async fn http_body_probe(
    opts: &DeepOptions<'_>,
    url: &str,
    limit: u64,
) -> (bool, String) {
    let Ok(client) = client_builder(opts).build() else {
        return (false, "client build failed".into());
    };
    let started = Instant::now();
    match client.get(url).send().await {
        Ok(resp) => {
            let code = resp.status().as_u16();
            let mut total = 0u64;
            let mut stream = resp;
            while total < limit {
                match stream.chunk().await {
                    Ok(Some(bytes)) => total += bytes.len() as u64,
                    Ok(None) => break,
                    Err(e) => return (false, format!("read error after {total} bytes: {e}")),
                }
            }
            let ms = started.elapsed().as_secs_f64() * 1000.0;
            (total > 0, format!("HTTP {code}, {total} bytes, {ms:.0} ms"))
        }
        Err(e) => {
            let ms = started.elapsed().as_secs_f64() * 1000.0;
            (false, format!("error after {ms:.0} ms: {e}"))
        }
    }
}
