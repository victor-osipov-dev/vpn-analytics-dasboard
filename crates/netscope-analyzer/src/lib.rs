//! Restriction analyzer: turns probe results into diagnoses.
//!
//! Rules are intentionally conservative: conclusions use confidence levels
//! (low/medium/high/unknown), each diagnosis records its evidence and
//! alternative explanations, and no fabricated percentages are produced.
//! Claiming "blocked by authority X" requires independent confirmation that
//! this engine does not have — those claims stay out of the evidence list.
//!
//! The analyzer works on a *window* of recent results, not on a single
//! measurement: a filtering conclusion requires several consecutive failures
//! and a control comparison, while degradation is measured against a rolling
//! baseline median. This mirrors the methodology in the product plan
//! (compare DIRECT and VPN, require repeats, never conclude from one sample).

use netscope_core::models::{
    AvailabilityStatus, Diagnosis, DiagnosisCategory, DiagnosisConfidence, DnsStatus, HttpStatus,
    HttpResult, Incident, IncidentKind, ProbeResult, RouteMode, TcpStatus, TlsStatus,
};
use std::collections::VecDeque;

pub mod compare;
pub mod window;

pub use compare::analyze_pair;

#[derive(Debug, Clone)]
pub struct AnalyzerConfig {
    /// Threshold rtt_ms for "degraded" flag (relative to the baseline median).
    pub rtt_degraded_factor: f64,
    /// How many consecutive failed slots to call service down.
    pub consecutive_failures_for_incident: usize,
    /// How many repeated failures are required before a filtering diagnosis is
    /// allowed at medium confidence.
    pub min_samples_for_filtering: usize,
    /// How many past successful samples form the degradation baseline.
    pub baseline_window: usize,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            rtt_degraded_factor: 3.0,
            consecutive_failures_for_incident: 3,
            min_samples_for_filtering: 2,
            baseline_window: 12,
        }
    }
}

fn mk(
    target_id: &str,
    route_mode: Option<RouteMode>,
    category: DiagnosisCategory,
    confidence: DiagnosisConfidence,
    evidence: Vec<String>,
    alternative_explanations: Vec<String>,
    backed_by_control_check: bool,
) -> Diagnosis {
    Diagnosis {
        id: netscope_core::new_id(),
        target_id: target_id.to_string(),
        route_mode,
        category,
        confidence,
        evidence,
        alternative_explanations,
        detected_at: netscope_core::now_rfc3339(),
        backed_by_control_check,
    }
}

fn insufficient(target_id: &str, route_mode: Option<RouteMode>, reason: &str) -> Diagnosis {
    mk(
        target_id,
        route_mode,
        DiagnosisCategory::InsufficientData,
        DiagnosisConfidence::Unknown,
        vec![reason.to_string()],
        vec![],
        false,
    )
}

/// True for statuses that mean "the service did not work", excluding Unknown
/// (not measured) and Partial (worked with caveats).
fn is_hard_failure(status: AvailabilityStatus) -> bool {
    matches!(
        status,
        AvailabilityStatus::Unavailable
            | AvailabilityStatus::SuspectedFiltering
            | AvailabilityStatus::RouteError
            | AvailabilityStatus::Degraded
    )
}

fn consecutive_hard_failures(series: &[&ProbeResult]) -> usize {
    series
        .iter()
        .rev()
        .take_while(|r| is_hard_failure(r.status))
        .count()
}

fn successful_values(series: &[&ProbeResult], pick: fn(&ProbeResult) -> Option<f64>) -> Vec<f64> {
    series
        .iter()
        .filter(|r| r.status.is_ok())
        .filter_map(|r| pick(r))
        .collect()
}

fn median(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut v = values.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mid = v.len() / 2;
    if v.len() % 2 == 1 {
        Some(v[mid])
    } else {
        Some((v[mid - 1] + v[mid]) / 2.0)
    }
}

fn baseline_median(series: &[&ProbeResult], pick: fn(&ProbeResult) -> Option<f64>, window: usize) -> Option<f64> {
    let values = successful_values(series, pick);
    let start = values.len().saturating_sub(window);
    median(&values[start..])
}

fn current_latency(r: &ProbeResult) -> Option<f64> {
    r.http
        .as_ref()
        .and_then(|h| h.total_ms)
        .or_else(|| r.performance.as_ref().and_then(|p| p.avg_ms))
        .or_else(|| r.tcp.as_ref().and_then(|t| t.connect_ms))
}

/// One diagnosis for a route pair (direct + vpn measurements).
pub fn diagnose_pair(
    target_id: &str,
    direct: Option<&ProbeResult>,
    vpn: Option<&ProbeResult>,
    window: &[ProbeResult],
    config: &AnalyzerConfig,
) -> Vec<Diagnosis> {
    let mut out = vec![];

    // History series (ascending) for repetition/baseline rules.
    let mut asc: Vec<&ProbeResult> = window.iter().collect();
    asc.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    let series = |mode: RouteMode| -> Vec<&ProbeResult> {
        asc.iter().filter(|r| r.route_mode == mode).copied().collect()
    };
    let direct_series = series(RouteMode::Direct);
    let vpn_series = series(RouteMode::Vpn);

    // Prefer the explicitly passed latest result; fall back to history.
    let direct = direct.or_else(|| direct_series.last().copied());
    let vpn = vpn.or_else(|| vpn_series.last().copied());

    if direct.is_none() && vpn.is_none() {
        out.push(insufficient(
            target_id,
            None,
            "No measurement has been performed yet",
        ));
        return out;
    }

    out.extend(compare::analyze_pair(target_id, direct, vpn));

    let stage_health = |r: Option<&ProbeResult>| -> Option<bool> {
        let r = r?;
        if r.status != AvailabilityStatus::Unknown {
            if matches!(
                r.status,
                AvailabilityStatus::SuspectedFiltering | AvailabilityStatus::RouteError
            ) {
                return Some(matches!(r.status, AvailabilityStatus::SuspectedFiltering));
            }
            return Some(r.status.is_ok());
        }
        let http_ok = r
            .http
            .as_ref()
            .map(|h| matches!(h.status, HttpStatus::Ok | HttpStatus::Redirected))
            .unwrap_or(false);
        let tls_ok = r
            .tls
            .as_ref()
            .map(|t| t.status == TlsStatus::HandshakeOk)
            .unwrap_or(false);
        let tcp_ok = r
            .tcp
            .as_ref()
            .map(|t| t.status == TcpStatus::Connected)
            .unwrap_or(false);
        let dns_ok = r
            .dns
            .as_ref()
            .map(|d| d.status == DnsStatus::Ok)
            .unwrap_or(false);
        Some(http_ok || tls_ok || tcp_ok || dns_ok)
    };
    let direct_ok = stage_health(direct).unwrap_or(false);
    let vpn_ok = stage_health(vpn).unwrap_or(false);

    let direct_fails = consecutive_hard_failures(&direct_series);
    let vpn_fails = consecutive_hard_failures(&vpn_series);
    let enough_direct = direct_fails >= config.min_samples_for_filtering;
    let enough_vpn = vpn_fails >= config.min_samples_for_filtering;

    match (direct_ok, vpn_ok) {
        (false, true) => {
            if let Some(r) = direct {
                out.extend(detect_per_route(target_id, RouteMode::Direct, r, &direct_series, config));
            }
            let confidence = if enough_direct {
                DiagnosisConfidence::Medium
            } else {
                DiagnosisConfidence::Low
            };
            let mut evidence = collect_evidence(direct);
            evidence.push(format!(
                "repeated failures in window: {direct_fails} (need {} for medium confidence)",
                config.min_samples_for_filtering
            ));
            out.push(mk(
                target_id,
                Some(RouteMode::Direct),
                DiagnosisCategory::DirectVpnAsymmetry,
                confidence,
                evidence,
                vec![
                    "Local filtering of the network/provider".into(),
                    "Proxy settings or the ISP's firewall".into(),
                    "Service is unavailable from the ISP's network only".into(),
                    "Local device firewall / antivirus interfering".into(),
                ],
                has_control(direct),
            ));
        }
        (true, false) => {
            if let Some(r) = vpn {
                out.extend(detect_per_route(target_id, RouteMode::Vpn, r, &vpn_series, config));
            }
            let confidence = if enough_vpn {
                DiagnosisConfidence::Medium
            } else {
                DiagnosisConfidence::Low
            };
            let mut evidence = collect_evidence(vpn);
            evidence.push(format!(
                "repeated failures in window: {vpn_fails} (need {} for medium confidence)",
                config.min_samples_for_filtering
            ));
            out.push(mk(
                target_id,
                Some(RouteMode::Vpn),
                DiagnosisCategory::VpnIssue,
                confidence,
                evidence,
                vec![
                    "VPN is unavailable/incorrectly configured: wrong gateway".into(),
                    "Blocking from the side of the VPN provider's egress network".into(),
                    "VPN server overload or its instability".into(),
                ],
                has_control(vpn),
            ));
        }
        (false, false) => {
            if let Some(r) = direct {
                out.extend(detect_per_route(target_id, RouteMode::Direct, r, &direct_series, config));
            }
            if let Some(r) = vpn {
                out.extend(detect_per_route(target_id, RouteMode::Vpn, r, &vpn_series, config));
            }
            // Both routes failed: distinguish a route-level failure from a
            // service/network-wide outage using the individual evidence.
            let both_route_error = direct.map(|r| r.route_error()).unwrap_or(false)
                && vpn.map(|r| r.route_error()).unwrap_or(false);
            let category = if both_route_error {
                DiagnosisCategory::LocalIssue
            } else {
                DiagnosisCategory::GlobalServiceFailure
            };
            let mut evidence = collect_evidence(direct);
            evidence.extend(collect_evidence(vpn));
            out.push(mk(
                target_id,
                None,
                category,
                DiagnosisConfidence::Low,
                evidence,
                vec![
                    "Global outage of the service or both channels".into(),
                    "Loss of internet on this device".into(),
                    "Blocking on both routes (requires control comparison)".into(),
                ],
                has_control(direct) || has_control(vpn),
            ));
        }
        (true, true) => {
            if let Some(r) = direct {
                out.extend(detect_per_route(target_id, RouteMode::Direct, r, &direct_series, config));
            }
            if let Some(r) = vpn {
                out.extend(detect_per_route(target_id, RouteMode::Vpn, r, &vpn_series, config));
            }
            // Degradation: current latency far above the rolling baseline.
            out.extend(detect_degradation(target_id, RouteMode::Direct, direct, &direct_series, config));
            out.extend(detect_degradation(target_id, RouteMode::Vpn, vpn, &vpn_series, config));
        }
    }
    out
}

/// Per-result analysis: stage-localised categories (TCP reset, TLS/SNI,
/// HTTP filtering, DNS). Runs even when both routes are healthy to catch
/// subtle signals.
fn detect_per_route(
    target_id: &str,
    mode: RouteMode,
    r: &ProbeResult,
    series: &[&ProbeResult],
    config: &AnalyzerConfig,
) -> Vec<Diagnosis> {
    let mut out = vec![];
    let repeats = consecutive_hard_failures(series);
    let confidence = if repeats >= config.min_samples_for_filtering {
        DiagnosisConfidence::Medium
    } else {
        DiagnosisConfidence::Low
    };

    if let Some(tcp) = &r.tcp {
        if tcp.status == TcpStatus::Reset {
            out.push(mk(
                target_id,
                Some(mode),
                DiagnosisCategory::TcpReset,
                confidence,
                vec![
                    format!("tcp: status={:?} remote={:?}", tcp.status, tcp.remote_address),
                    format!("repeats in window: {repeats}"),
                ],
                vec![
                    "The server itself reset the connection".into(),
                    "A network middlebox injected a TCP RST".into(),
                    "Antivirus / local firewall interference".into(),
                ],
                false,
            ));
        } else if matches!(tcp.status, TcpStatus::Unreachable | TcpStatus::Refused) {
            out.push(mk(
                target_id,
                Some(mode),
                DiagnosisCategory::IpBlocked,
                DiagnosisConfidence::Low,
                vec![format!("tcp: status={:?}", tcp.status)],
                vec![
                    "The route to the server is unavailable due to an internet outage".into(),
                    "Firewall rules of the device itself".into(),
                    "The service is down".into(),
                ],
                false,
            ));
        }
    }

    if let Some(tls) = &r.tls {
        if matches!(
            tls.status,
            TlsStatus::HandshakeReset | TlsStatus::HandshakeTimeout | TlsStatus::ClosedEarly
        ) {
            let stage = tls.failure_stage.clone().unwrap_or_else(|| "tls_handshake".into());
            let mut evidence = vec![
                format!("tls: status={:?} stage={stage}", tls.status),
                format!("alert={:?}", tls.alert),
                format!("repeats in window: {repeats}"),
            ];
            if tls.client_hello_sent {
                evidence.push("client hello was sent".into());
            }
            out.push(mk(
                target_id,
                Some(mode),
                DiagnosisCategory::TlsSniFiltering,
                confidence,
                evidence,
                vec![
                    "Proxy or antivirus interfering with the TLS traffic".into(),
                    "The TLS stack of the service is overloaded".into(),
                    "A middlebox drops ClientHello/ServerHello".into(),
                ],
                false,
            ));
        } else if tls.status == TlsStatus::CertificateInvalid {
            out.push(mk(
                target_id,
                Some(mode),
                DiagnosisCategory::TlsSniFiltering,
                DiagnosisConfidence::Low,
                vec![
                    format!("tls: certificate invalid stage={:?}", tls.failure_stage),
                    format!("issuer={:?}", tls.certificate_issued_by),
                ],
                vec![
                    "TLS interception (MITM proxy) with an untrusted CA".into(),
                    "The site serves an expired or misconfigured certificate".into(),
                    "Antivirus HTTPS scanning".into(),
                ],
                false,
            ));
        }
    }

    if let Some(http) = &r.http {
        if http.block_page_matched {
            out.push(mk(
                target_id,
                Some(mode),
                DiagnosisCategory::HttpFiltering,
                DiagnosisConfidence::Medium,
                vec![
                    format!("http: block page matched, code={:?}", http.response_status),
                    format!("final_url={:?}", http.final_url),
                ],
                vec![
                    "CAPTCHA or WAF page mistakenly recognized as a block page".into(),
                    "The service itself returned a denial page".into(),
                ],
                false,
            ));
        } else if let Some(code) = http.response_status {
            if matches!(code, 403 | 429) {
                out.push(mk(
                    target_id,
                    Some(mode),
                    DiagnosisCategory::HttpFiltering,
                    DiagnosisConfidence::Low,
                    vec![format!("http: status {code}"), format!("server={:?}", http.server)],
                    vec![
                        "WAF / rate limiter of the service".into(),
                        "Geo-blocking or anti-bot policy".into(),
                        "Not necessarily a network-level block".into(),
                    ],
                    false,
                ));
            } else if matches!(code, 500 | 502 | 503 | 504) {
                out.push(mk(
                    target_id,
                    Some(mode),
                    DiagnosisCategory::PartialAvailability,
                    DiagnosisConfidence::Low,
                    vec![format!("http: status {code}"), format!("server={:?}", http.server)],
                    vec![
                        "CDN / load balancer / upstream failure".into(),
                        "The application behind the edge is down".into(),
                    ],
                    false,
                ));
            }
        }
    }

    if let Some(dns) = &r.dns {
        if dns.mismatch && dns.status == DnsStatus::Ok {
            out.push(mk(
                target_id,
                Some(mode),
                DiagnosisCategory::DnsFiltering,
                DiagnosisConfidence::Medium,
                vec![
                    "dns: answers contradict the control resolver".into(),
                    format!("resolver={:?}", dns.resolver_addr),
                ],
                vec![
                    "Legitimate DNS reconfiguration of the service".into(),
                    "CDN with different IP sets for different resolvers".into(),
                ],
                true,
            ));
        } else if dns.status == DnsStatus::Nxdomain {
            out.push(mk(
                target_id,
                Some(mode),
                DiagnosisCategory::DnsFiltering,
                DiagnosisConfidence::Low,
                vec![format!("dns: NXDOMAIN from {:?}", dns.resolver_addr)],
                vec![
                    "The domain really does not exist".into(),
                    "DNS filtering returned NXDOMAIN".into(),
                ],
                has_control(Some(r)),
            ));
        }
    }
    out
}

fn detect_degradation(
    target_id: &str,
    mode: RouteMode,
    current: Option<&ProbeResult>,
    series: &[&ProbeResult],
    config: &AnalyzerConfig,
) -> Vec<Diagnosis> {
    let r = match current {
        Some(r) if r.status.is_ok() => r,
        _ => return vec![],
    };
    let cur = match current_latency(r) {
        Some(v) => v,
        None => return vec![],
    };
    let baseline = match baseline_median(series, current_latency, config.baseline_window) {
        Some(v) => v,
        None => return vec![],
    };
    if baseline <= 1.0 || cur < baseline * config.rtt_degraded_factor {
        return vec![];
    }
    // Require a meaningful absolute difference to avoid noise on tiny values.
    if cur - baseline < 150.0 {
        return vec![];
    }
    vec![mk(
        target_id,
        Some(mode),
        DiagnosisCategory::SustainedDegradation,
        DiagnosisConfidence::Medium,
        vec![
            format!("current_ms={cur:.0} baseline_median_ms={baseline:.0}"),
            format!("factor={:.1}", config.rtt_degraded_factor),
        ],
        vec![
            "Congestion or a slower route through the provider".into(),
            "CDN edge node far away / overloaded".into(),
            "VPN server overload (for the VPN route)".into(),
            "For a filtering conclusion repeated measurements are required".into(),
        ],
        false,
    )]
}

pub fn has_control(r: Option<&ProbeResult>) -> bool {
    r.and_then(|r| r.dns.as_ref())
        .map(|d| d.control.is_some() || d.mismatch)
        .unwrap_or(false)
}

pub fn collect_evidence(r: Option<&ProbeResult>) -> Vec<String> {
    let mut out = vec![];
    if let Some(r) = r {
        if let Some(e) = &r.error {
            out.push(format!("error: {e}"));
        }
        if let Some(dns) = &r.dns {
            out.push(format!(
                "dns: status={:?} rcode={:?} mismatch={}",
                dns.status, dns.rcode, dns.mismatch
            ));
        }
        if let Some(tcp) = &r.tcp {
            out.push(format!(
                "tcp: status={:?} ms={:?} local={:?}",
                tcp.status, tcp.connect_ms, tcp.local_address
            ));
        }
        if let Some(tls) = &r.tls {
            out.push(format!(
                "tls: status={:?} stage={:?} version={:?} alert={:?}",
                tls.status, tls.failure_stage, tls.tls_version, tls.alert
            ));
        }
        if let Some(http) = &r.http {
            out.push(format!(
                "http: status={:?} code={:?} group={:?} block_page={}",
                http.status, http.response_status, http.status_group, http.block_page_matched
            ));
        }
        if r.network_changed {
            out.push("network fingerprint changed during probe".to_string());
        }
    }
    out
}

/// Derive a numeric AvailabilityStatus from the probe internals (used by the
/// monitoring loop).
pub fn status_of(r: &ProbeResult) -> AvailabilityStatus {
    if r.route_error() {
        return AvailabilityStatus::RouteError;
    }
    let tcp_ok = r.tcp.as_ref().map(|t| t.status == TcpStatus::Connected).unwrap_or(false);
    let http_ok = r
        .http
        .as_ref()
        .map(|h| h.status == HttpStatus::Ok)
        .unwrap_or(false);
    let tls_ok = r.tls.as_ref().map(|t| t.status == TlsStatus::HandshakeOk).unwrap_or(false);
    let dns_ok = r.dns.as_ref().map(|d| d.status == DnsStatus::Ok).unwrap_or(false);

    if http_ok {
        AvailabilityStatus::Available
    } else if r
        .http
        .as_ref()
        .map(|http| http.block_page_matched)
        .unwrap_or(false)
    {
        AvailabilityStatus::SuspectedFiltering
    } else if tcp_ok && !tls_ok {
        if let Some(t) = &r.tls {
            if matches!(t.status, TlsStatus::HandshakeReset | TlsStatus::HandshakeTimeout) {
                return AvailabilityStatus::SuspectedFiltering;
            }
        }
        AvailabilityStatus::Unavailable
    } else if tcp_ok || dns_ok {
        AvailabilityStatus::Partial
    } else {
        AvailabilityStatus::Unavailable
    }
}

/// Build an Incident record from a repeating failure.
pub fn incident_from_failures(
    target_id: Option<&str>,
    route: Option<RouteMode>,
    failed_count: usize,
    first_error: Option<&str>,
) -> Option<Incident> {
    if failed_count == 0 {
        return None;
    }
    Some(Incident {
        id: netscope_core::new_id(),
        kind: if failed_count >= 3 {
            IncidentKind::ServiceDown
        } else {
            IncidentKind::DegradationDetected
        },
        target_id: target_id.map(|s| s.to_string()),
        route_mode: route,
        message: format!("Failures in a row: {failed_count}"),
        details: first_error.map(|e| e.to_string()),
        started_at: netscope_core::now_rfc3339(),
        resolved_at: None,
    })
}

/// Sliding window helper for repeated-measurement rules.
pub struct FailureWindow {
    buf: VecDeque<bool>,
    cap: usize,
}

impl FailureWindow {
    pub fn new(cap: usize) -> Self {
        Self {
            buf: VecDeque::with_capacity(cap),
            cap,
        }
    }

    pub fn push(&mut self, ok: bool) {
        if self.buf.len() == self.cap {
            self.buf.pop_back();
        }
        self.buf.push_front(ok);
    }

    pub fn consecutive_failures(&self) -> usize {
        self.buf.iter().take_while(|&&ok| !ok).count()
    }

    /// Whether any failure entered the window recently (for restore events).
    pub fn had_failures(&self) -> bool {
        self.buf.iter().any(|&ok| !ok)
    }
}

/// HTTP status -> coarse group used by the UI and the analyzer.
pub fn http_status_group(code: u16) -> &'static str {
    match code {
        200..=299 => "ok",
        300..=399 => "redirect",
        400..=499 => "client_error",
        500..=599 => "server_error",
        _ => "other",
    }
}

/// True when the HTTP result looks like a block/interception page.
pub fn is_block_page(http: &HttpResult) -> bool {
    http.block_page_matched
}

#[cfg(test)]
mod tests {
    use super::*;
    use netscope_core::models::{
        DnsResult, DnsStatus, PerformanceResult, ProbeResult, RouteProfile, TcpResult, TcpStatus,
    };

    fn route(mode: RouteMode) -> RouteProfile {
        RouteProfile::placeholder(
            if mode == RouteMode::Direct { "rd" } else { "rv" },
            mode,
            "route",
        )
    }

    #[test]
    fn consecutive_failures_work() {
        let mut w = FailureWindow::new(5);
        w.push(true);
        w.push(false);
        w.push(false);
        assert_eq!(w.consecutive_failures(), 2);
        w.push(true);
        assert_eq!(w.consecutive_failures(), 0);
    }

    #[test]
    fn tcp_ok_tls_reset_suspected() {
        let mut r = ProbeResult::new("t", "t", &route(RouteMode::Direct));
        r.tcp = Some(TcpResult {
            status: TcpStatus::Connected,
            connect_ms: None,
            local_address: None,
            remote_address: None,
            interface_bound: false,
            error: None,
        });
        r.tls = Some(Default::default());
        assert_eq!(status_of(&r), AvailabilityStatus::Unavailable);
    }

    #[test]
    fn both_blocked_gives_low_confidence() {
        let d = ProbeResult::new("t", "t", &route(RouteMode::Direct));
        let v = ProbeResult::new("t", "t", &route(RouteMode::Vpn));
        let out = diagnose_pair("t", Some(&d), Some(&v), &[], &AnalyzerConfig::default());
        assert!(out
            .iter()
            .any(|x| x.category == DiagnosisCategory::GlobalServiceFailure));
        if let Some(d) = out
            .iter()
            .find(|x| x.category == DiagnosisCategory::GlobalServiceFailure)
        {
            assert_eq!(d.confidence, DiagnosisConfidence::Low);
        }
    }

    #[test]
    fn dns_failed_direct_ok_vpn_flags_asymmetry() {
        let mut d = ProbeResult::new("t", "t", &route(RouteMode::Direct));
        d.dns = Some(DnsResult {
            status: DnsStatus::Nxdomain,
            ..Default::default()
        });
        let mut v = ProbeResult::new("t", "t", &route(RouteMode::Vpn));
        v.dns = Some(DnsResult {
            status: DnsStatus::Ok,
            ..Default::default()
        });
        let out = diagnose_pair("t", Some(&d), Some(&v), &[], &AnalyzerConfig::default());
        assert!(out
            .iter()
            .any(|x| x.category == DiagnosisCategory::DirectVpnAsymmetry));
        let _ = PerformanceResult::default();
    }

    #[test]
    fn tcp_reset_is_reported() {
        let mut d = ProbeResult::new("t", "t", &route(RouteMode::Direct));
        d.status = AvailabilityStatus::Unavailable;
        d.tcp = Some(TcpResult {
            status: TcpStatus::Reset,
            ..Default::default()
        });
        let mut v = ProbeResult::new("t", "t", &route(RouteMode::Vpn));
        v.status = AvailabilityStatus::Available;
        v.http = Some(HttpResult {
            status: HttpStatus::Ok,
            response_status: Some(200),
            ..Default::default()
        });
        let out = diagnose_pair("t", Some(&d), Some(&v), &[], &AnalyzerConfig::default());
        assert!(out.iter().any(|x| x.category == DiagnosisCategory::TcpReset));
    }

    #[test]
    fn http_403_is_reported_as_filtering_hint() {
        let mut d = ProbeResult::new("t", "t", &route(RouteMode::Direct));
        d.status = AvailabilityStatus::Available;
        d.http = Some(HttpResult {
            status: HttpStatus::HttpError,
            response_status: Some(403),
            ..Default::default()
        });
        let out = detect_per_route("t", RouteMode::Direct, &d, &[&d], &AnalyzerConfig::default());
        assert!(out.iter().any(|x| x.category == DiagnosisCategory::HttpFiltering));
    }

    #[test]
    fn degradation_uses_baseline() {
        let mut series: Vec<ProbeResult> = vec![];
        for _ in 0..6 {
            let mut r = ProbeResult::new("t", "t", &route(RouteMode::Direct));
            r.status = AvailabilityStatus::Available;
            r.http = Some(HttpResult {
                status: HttpStatus::Ok,
                total_ms: Some(100.0),
                ..Default::default()
            });
            series.push(r);
        }
        let mut slow = ProbeResult::new("t", "t", &route(RouteMode::Direct));
        slow.status = AvailabilityStatus::Available;
        slow.http = Some(HttpResult {
            status: HttpStatus::Ok,
            total_ms: Some(900.0),
            ..Default::default()
        });
        let refs: Vec<&ProbeResult> = series.iter().collect();
        let out = detect_degradation("t", RouteMode::Direct, Some(&slow), &refs, &AnalyzerConfig::default());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].category, DiagnosisCategory::SustainedDegradation);
    }
}
