//! DNS hygiene diagnostics: verifies that DNS traffic actually leaves through
//! the VPN tunnel (v2rayN/sing-box TUN) and that the resolver stack answers.
//!
//! Method: every resolver is queried over raw UDP/53 (bypassing the OS cache)
//! — `whoami.akamai.net` returns the resolver's own egress IP, which is
//! compared with the encrypted (DoH) resolver's egress. Physical-interface
//! resolvers are additionally probed while the socket is bound to the physical
//! adapter address: if those answer with a *different* egress than the tunnel
//! resolver, DNS has a path around the tunnel.

use std::net::IpAddr;
use std::time::Instant;

use netscope_core::models::NetworkSnapshot;
use netscope_core::settings::AppSettings;
use netscope_probes::dns::DnsWireClient;
use serde::{Deserialize, Serialize};

const WHOAMI: &str = "whoami.akamai.net";
const RELIABILITY: &str = "example.com";
const PUBLIC_DNS: &str = "8.8.8.8";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsResolverCheck {
    pub server: String,
    /// tunnel | physical | public
    pub source: String,
    pub adapter: Option<String>,
    /// Local address the UDP socket was bound to (a physical IP = bypass probe).
    pub bound_to: Option<String>,
    pub reachable: bool,
    pub status: String,
    pub duration_ms: Option<f64>,
    pub answers: Vec<String>,
    pub resolver_egress: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsDiagnostics {
    pub system_resolvers: Vec<String>,
    pub tunnel_resolvers: Vec<String>,
    pub physical_resolvers: Vec<String>,
    pub physical_interface: Option<String>,
    pub checks: Vec<DnsResolverCheck>,
    pub doh_url: String,
    pub doh_ok: bool,
    pub doh_egress: Option<String>,
    /// True when DNS answers were obtained through the tunnel path.
    pub tunneled: bool,
    pub leak_suspected: bool,
    pub verdict: String,
    pub notes: Vec<String>,
}

struct PendingCheck {
    server: IpAddr,
    source: &'static str,
    adapter: Option<String>,
    bind: Option<IpAddr>,
}

fn parse_ip(value: &str) -> Option<IpAddr> {
    let raw = value.trim();
    if raw.is_empty() {
        return None;
    }
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Some(ip);
    }
    // Legacy snapshot format: "10.0.0.1:0" / "[fe80::1%12]:0".
    if let Some((host, port)) = raw.rsplit_once(':') {
        if port.parse::<u16>().is_ok() {
            let host = host.trim_start_matches('[').trim_end_matches(']');
            let host = host.split('%').next().unwrap_or(host);
            if let Ok(ip) = host.parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }
    None
}

fn dedup_push(list: &mut Vec<String>, value: &str) {
    let v = value.trim().to_string();
    if !v.is_empty() && !list.iter().any(|x| x == &v) {
        list.push(v);
    }
}

pub async fn diagnose(snapshot: Option<&NetworkSnapshot>, settings: &AppSettings) -> DnsDiagnostics {
    let snapshot = snapshot.cloned();
    let timeout_ms = settings.dns_timeout_ms.clamp(800, 5000);
    let doh_url = settings.control_doh_url.clone();

    let mut system_resolvers = vec![];
    let mut tunnel_resolvers = vec![];
    let mut physical_resolvers = vec![];
    let mut physical_interface = None;
    let mut physical_ip: Option<IpAddr> = None;
    let mut tunnel_adapters: Vec<String> = vec![];

    if let Some(snap) = &snapshot {
        for s in &snap.dns_servers {
            dedup_push(&mut system_resolvers, s);
        }
        for iface in &snap.interfaces {
            let is_tunnel = snap.tunnel_interfaces.iter().any(|n| n == &iface.name);
            if is_tunnel {
                for s in &iface.dns_servers {
                    dedup_push(&mut tunnel_resolvers, s);
                }
                if !tunnel_adapters.contains(&iface.name) {
                    tunnel_adapters.push(iface.name.clone());
                }
            }
        }
        if let Some(iface) = snap.physical_default_interface(true) {
            physical_interface = Some(iface.name.clone());
            physical_ip = iface.ipv4.first().and_then(|s| parse_ip(s));
            for s in &iface.dns_servers {
                dedup_push(&mut physical_resolvers, s);
            }
        }
    }

    let mut pending: Vec<PendingCheck> = vec![];
    for s in &tunnel_resolvers {
        if let Some(ip) = parse_ip(s) {
            pending.push(PendingCheck {
                server: ip,
                source: "tunnel",
                adapter: tunnel_adapters.first().cloned(),
                bind: None,
            });
        }
    }
    for s in &physical_resolvers {
        if let Some(ip) = parse_ip(s) {
            pending.push(PendingCheck {
                server: ip,
                source: "physical",
                adapter: physical_interface.clone(),
                bind: physical_ip,
            });
        }
    }
    if let Some(ip) = parse_ip(PUBLIC_DNS) {
        pending.push(PendingCheck {
            server: ip,
            source: "public",
            adapter: None,
            bind: None,
        });
        if physical_ip.is_some() {
            pending.push(PendingCheck {
                server: ip,
                source: "public",
                adapter: physical_interface.clone(),
                bind: physical_ip,
            });
        }
    }

    let mut handles = vec![];
    for item in pending {
        let server = item.server;
        handles.push(tokio::spawn(async move {
            run_check(server, item.source, item.adapter, item.bind, timeout_ms).await
        }));
    }
    let doh_handle = tokio::spawn({
        let url = doh_url.clone();
        async move { doh_lookup(&url, timeout_ms).await }
    });

    let mut checks = vec![];
    for handle in handles {
        if let Ok(check) = handle.await {
            checks.push(check);
        }
    }
    let (doh_ok, doh_egress) = doh_handle.await.unwrap_or((false, None));

    checks.sort_by(|a, b| {
        source_rank(&a.source)
            .cmp(&source_rank(&b.source))
            .then_with(|| a.server.cmp(&b.server))
    });

    let (tunneled, leak_suspected, verdict, mut notes) = classify(
        &checks,
        doh_egress.as_deref(),
        &tunnel_resolvers,
        &physical_resolvers,
    );

    if !tunnel_resolvers.is_empty() {
        notes.push(format!("DNS туннеля: {}", tunnel_resolvers.join(", ")));
    }
    if let Some(iface) = &physical_interface {
        if !physical_resolvers.is_empty() {
            notes.push(format!(
                "{iface}: резолверы {} (проверены с привязкой к физическому адресу)",
                physical_resolvers.join(", ")
            ));
        }
    }
    if doh_ok {
        notes.push(format!("Контрольный DoH через туннель доступен: {doh_url}"));
    } else {
        notes.push(format!("Контрольный DoH недоступен: {doh_url}"));
    }

    DnsDiagnostics {
        system_resolvers,
        tunnel_resolvers,
        physical_resolvers,
        physical_interface,
        checks,
        doh_url,
        doh_ok,
        doh_egress,
        tunneled,
        leak_suspected,
        verdict,
        notes,
    }
}

fn source_rank(source: &str) -> u8 {
    match source {
        "tunnel" => 0,
        "physical" => 1,
        _ => 2,
    }
}

async fn run_check(
    server: IpAddr,
    source: &'static str,
    adapter: Option<String>,
    bind: Option<IpAddr>,
    timeout_ms: u64,
) -> DnsResolverCheck {
    let started = Instant::now();
    let egress = udp_query(server, WHOAMI, bind, timeout_ms).await;
    let reliability = udp_query(server, RELIABILITY, bind, timeout_ms).await;
    let duration_ms = Some(started.elapsed().as_secs_f64() * 1000.0);

    let mut answers = vec![];
    let mut status = "error".to_string();
    let mut error = None;
    let mut reachable = false;
    let mut resolver_egress = None;

    match egress {
        Ok(reply) => {
            reachable = true;
            status = reply.0;
            answers = reply.1.clone();
            resolver_egress = reply.1.into_iter().next();
        }
        Err(e) => error = Some(e),
    }
    match reliability {
        Ok(reply) => {
            reachable = true;
            if status == "error" {
                status = reply.0;
            }
        }
        Err(e) => {
            if error.is_none() {
                error = Some(e);
            }
        }
    }

    DnsResolverCheck {
        server: server.to_string(),
        source: source.to_string(),
        adapter,
        bound_to: bind.map(|ip| ip.to_string()),
        reachable,
        status,
        duration_ms,
        answers,
        resolver_egress,
        error,
    }
}

async fn udp_query(
    server: IpAddr,
    name: &str,
    bind: Option<IpAddr>,
    timeout_ms: u64,
) -> Result<(String, Vec<String>), String> {
    let name = name.to_string();
    let reply = tokio::task::spawn_blocking(move || {
        DnsWireClient::query(server, 53, &name, 1, timeout_ms, bind)
    })
    .await
    .map_err(|e| format!("join: {e}"))?;
    match reply {
        Ok(rep) => {
            let status = match rep.rcode {
                0 => "NOERROR",
                2 => "SERVFAIL",
                3 => "NXDOMAIN",
                5 => "REFUSED",
                _ => "OTHER",
            };
            Ok((
                status.to_string(),
                rep.answers.into_iter().map(|a| a.ip).collect(),
            ))
        }
        Err(e) => {
            let text = e.to_string();
            Err(if text.contains("timed out") {
                "timeout".to_string()
            } else {
                text
            })
        }
    }
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct DohReply {
    Status: i32,
    Answer: Option<Vec<DohAnswer>>,
}

#[derive(Deserialize)]
struct DohAnswer {
    data: String,
    #[serde(rename = "type")]
    record_type: u16,
}

async fn doh_lookup(url: &str, timeout_ms: u64) -> (bool, Option<String>) {
    if url.trim().is_empty() {
        return (false, None);
    }
    let endpoint = format!("{}?name={WHOAMI}&type=A", url.trim_end_matches('/'));
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(timeout_ms.max(8000)))
        .build()
    {
        Ok(c) => c,
        Err(_) => return (false, None),
    };
    let response = client
        .get(endpoint)
        .header("accept", "application/dns-json")
        .send()
        .await;
    let Ok(response) = response else {
        return (false, None);
    };
    let Ok(body) = response.json::<DohReply>().await else {
        return (false, None);
    };
    if body.Status != 0 {
        return (false, None);
    }
    let egress = body
        .Answer
        .unwrap_or_default()
        .into_iter()
        .find(|a| a.record_type == 1)
        .map(|a| a.data);
    (egress.is_some(), egress)
}

/// Classify the collected observations. Kept pure so it is unit-testable.
fn classify(
    checks: &[DnsResolverCheck],
    doh_egress: Option<&str>,
    tunnel_resolvers: &[String],
    physical_resolvers: &[String],
) -> (bool, bool, String, Vec<String>) {
    let tunnel_ok = checks
        .iter()
        .any(|c| c.source == "tunnel" && c.reachable);
    let public_ok = checks
        .iter()
        .any(|c| c.source == "public" && c.reachable && c.bound_to.is_none());
    let tunneled = tunnel_ok || public_ok;

    let mut notes = vec![];

    let bypass_checks: Vec<&DnsResolverCheck> = checks
        .iter()
        .filter(|c| c.reachable && c.bound_to.is_some())
        .collect();
    let mut leak_suspected = false;
    for check in &bypass_checks {
        let distinct = match (check.resolver_egress.as_deref(), doh_egress) {
            (Some(local), Some(doh)) => local != doh,
            _ => false,
        };
        if distinct {
            leak_suspected = true;
            notes.push(format!(
                "{} отвечает в обход туннеля (egress {})",
                check.server,
                check.resolver_egress.clone().unwrap_or_default()
            ));
        }
    }

    if public_ok {
        notes.push(
            "Запросы к публичным резолверам (8.8.8.8) перехватываются TUN и уходят через прокси"
                .to_string(),
        );
    }
    if !physical_resolvers.is_empty() && bypass_checks.is_empty() {
        notes.push(
            "Резолверы физического интерфейса напрямую недоступны (ожидаемо для strict TUN)"
                .to_string(),
        );
    }
    if tunnel_resolvers.is_empty() {
        notes.push("В снимке сети не найдены DNS-серверы туннельного адаптера".to_string());
    }

    let verdict = if leak_suspected {
        "Обнаружен DNS-канал в обход туннеля — возможна утечка DNS".to_string()
    } else if tunneled {
        let identical = match (
            checks
                .iter()
                .find(|c| c.source == "tunnel" && c.reachable)
                .and_then(|c| c.resolver_egress.as_deref()),
            doh_egress,
        ) {
            (Some(t), Some(d)) => t == d,
            _ => false,
        };
        if identical {
            "DNS идёт через VPN-туннель; system и DoH используют один и тот же резолвер"
                .to_string()
        } else {
            "Утечек DNS не обнаружено: запросы уходят через VPN-туннель".to_string()
        }
    } else {
        "DNS через туннель не отвечает — проверьте настройки v2rayN/sing-box".to_string()
    };

    (tunneled, leak_suspected, verdict, notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(
        server: &str,
        source: &str,
        bound: bool,
        reachable: bool,
        egress: Option<&str>,
    ) -> DnsResolverCheck {
        DnsResolverCheck {
            server: server.into(),
            source: source.into(),
            adapter: None,
            bound_to: if bound {
                Some("192.168.1.10".into())
            } else {
                None
            },
            reachable,
            status: if reachable { "NOERROR".into() } else { "timeout".into() },
            duration_ms: None,
            answers: vec![],
            resolver_egress: egress.map(|s| s.to_string()),
            error: None,
        }
    }

    #[test]
    fn tunnel_only_no_leak() {
        let checks = vec![
            check("172.18.0.2", "tunnel", false, true, Some("1.2.3.4")),
            check("10.0.0.1", "physical", true, false, None),
            check("8.8.8.8", "public", false, true, Some("1.2.3.4")),
        ];
        let (tunneled, leak, verdict, _) = classify(
            &checks,
            Some("1.2.3.4"),
            &["172.18.0.2".to_string()],
            &["10.0.0.1".to_string()],
        );
        assert!(tunneled);
        assert!(!leak);
        assert!(verdict.contains("VPN-туннель"));
    }

    #[test]
    fn physical_bypass_is_a_leak() {
        let checks = vec![
            check("172.18.0.2", "tunnel", false, true, Some("5.6.7.8")),
            check("10.0.0.1", "physical", true, true, Some("203.0.113.5")),
        ];
        let (_, leak, verdict, _) = classify(
            &checks,
            Some("5.6.7.8"),
            &["172.18.0.2".to_string()],
            &["10.0.0.1".to_string()],
        );
        assert!(leak);
        assert!(verdict.contains("утечка"));
    }

    #[test]
    fn no_dns_at_all() {
        let checks = vec![check("172.18.0.2", "tunnel", false, false, None)];
        let (tunneled, leak, verdict, _) =
            classify(&checks, None, &["172.18.0.2".to_string()], &[]);
        assert!(!tunneled);
        assert!(!leak);
        assert!(verdict.contains("не отвечает"));
    }
}
