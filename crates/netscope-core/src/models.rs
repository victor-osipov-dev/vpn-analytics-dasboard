use serde::{Deserialize, Serialize};

use crate::{new_id, now_rfc3339};

// ---------------------------------------------------------------------------
// Route & network identity models
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum RouteMode {
    Direct,
    Vpn,
    System,
    CustomProxy,
}

impl RouteMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            RouteMode::Direct => "direct",
            RouteMode::Vpn => "vpn",
            RouteMode::System => "system",
            RouteMode::CustomProxy => "custom_proxy",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "vpn" => RouteMode::Vpn,
            "system" => RouteMode::System,
            "custom_proxy" => RouteMode::CustomProxy,
            _ => RouteMode::Direct,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteVerification {
    /// The route was measurably confirmed (independent egress check passed).
    Verified,
    /// The route exists but could not be confirmed as distinct (e.g. TUN may
    /// capture all traffic, egress IP matches the VPN egress).
    Unverified,
    /// The route cannot be used at all right now (no interface, proxy down).
    Unavailable,
    /// Using the route would violate user policy (kill switch active etc.).
    Unsafe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteConfidence {
    High,
    Medium,
    Low,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceKind {
    Physical,
    Virtual,
    Loopback,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceState {
    Up,
    Down,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct InterfaceInfo {
    pub index: u32,
    pub name: String,
    pub description: String,
    pub kind: InterfaceKind,
    pub state: InterfaceState,
    pub mac: Option<String>,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub default_v4: bool,
    pub default_v6: bool,
    pub dns_servers: Vec<String>,
    pub gateway: Option<String>,
    pub kind_guess_reason: String,
}

impl InterfaceInfo {
    pub fn loopback() -> Self {
        Self {
            index: 1,
            name: "lo".to_string(),
            description: "Loopback Pseudo-Interface".to_string(),
            kind: InterfaceKind::Loopback,
            state: InterfaceState::Up,
            mac: None,
            ipv4: vec!["127.0.0.1".into()],
            ipv6: vec!["::1".into()],
            default_v4: false,
            default_v6: false,
            dns_servers: vec![],
            gateway: None,
            kind_guess_reason: "IANA type 24".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RouteEntry {
    pub destination: String,
    pub prefix_len: u8,
    pub next_hop: String,
    pub interface_index: u32,
    pub metric: u32,
    pub persistent: bool,
    pub is_default: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyKind {
    Http,
    Https,
    Socks5,
    Socks5RemoteDns,
    Pac,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ProxyEndpoint {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    /// username for proxy authentication (password kept in the secret store)
    pub username: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SystemProxyConfig {
    pub enabled: bool,
    pub http_proxy: Option<ProxyEndpoint>,
    pub https_proxy: Option<ProxyEndpoint>,
    pub socks: Option<ProxyEndpoint>,
    pub bypass_list: Vec<String>,
    pub pac_url: Option<String>,
    /// PAC/WPAD is only partially supported: rules are not evaluated.
    pub pac_supported: bool,
}

impl Default for SystemProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            http_proxy: None,
            https_proxy: None,
            socks: None,
            bypass_list: vec![],
            pac_url: None,
            pac_supported: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VpnKind {
    Tunnel,
    ProxyBased,
    Mixed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VpnStatus {
    /// A virtual interface or proxy exists on the system.
    Detected,
    /// The tunnel/proxy is up and answering, but egress not confirmed.
    Connected,
    /// Egress confirmed distinct from DIRECT.
    Verified,
    /// Nothing VPN-like is present.
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct NetworkSnapshot {
    pub captured_at: String,
    pub fingerprint: String,
    pub interfaces: Vec<InterfaceInfo>,
    pub routes_v4: Vec<RouteEntry>,
    pub routes_v6: Vec<RouteEntry>,
    pub system_proxy: SystemProxyConfig,
    pub default_gateway_v4: Option<String>,
    pub default_gateway_v6: Option<String>,
    pub dns_servers: Vec<String>,
    pub tunnel_interfaces: Vec<String>,
}

impl NetworkSnapshot {
    pub fn physical_default_interface(&self, v4: bool) -> Option<&InterfaceInfo> {
        self.interfaces.iter().find(|i| {
            i.kind == InterfaceKind::Physical
                && i.state == InterfaceState::Up
                && (if v4 { i.default_v4 } else { i.default_v6 })
        })
    }
}

/// Verified identity of the egress path for one probe run.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EgressIdentity {
    pub external_ip: Option<String>,
    pub external_ipv6: Option<String>,
    pub interface_name: Option<String>,
    pub dns_resolver: Option<String>,
    pub asn: Option<String>,
    pub asn_source: Option<String>,
    pub confidence: RouteConfidence,
    pub reason: Option<String>,
    pub checked_at: String,
    pub source_endpoints: Vec<String>,
}

impl Default for EgressIdentity {
    fn default() -> Self {
        Self {
            external_ip: None,
            external_ipv6: None,
            interface_name: None,
            dns_resolver: None,
            asn: None,
            asn_source: None,
            confidence: RouteConfidence::None,
            reason: None,
            checked_at: now_rfc3339(),
            source_endpoints: vec![],
        }
    }
}

/// Full profile of one monitoring route (DIRECT / VPN / proxy variants).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RouteProfile {
    pub id: String,
    pub mode: RouteMode,
    pub name: String,
    pub interface_name: Option<String>,
    pub proxy_type: Option<String>,
    pub external_ip: Option<String>,
    pub external_ipv6: Option<String>,
    pub dns_servers: Vec<String>,
    pub verification: RouteVerification,
    pub confidence: RouteConfidence,
    pub verification_reason: Option<String>,
    pub vpn_kind: Option<VpnKind>,
    pub vpn_status: Option<VpnStatus>,
    pub vpn_endpoint: Option<String>,
    pub egress: Option<EgressIdentity>,
    pub last_checked: String,
}

impl RouteProfile {
    pub fn placeholder(id: &str, mode: RouteMode, name: &str) -> Self {
        Self {
            id: id.to_string(),
            mode,
            name: name.to_string(),
            interface_name: None,
            proxy_type: None,
            external_ip: None,
            external_ipv6: None,
            dns_servers: vec![],
            verification: RouteVerification::Unverified,
            confidence: RouteConfidence::None,
            verification_reason: None,
            vpn_kind: None,
            vpn_status: None,
            vpn_endpoint: None,
            egress: None,
            last_checked: now_rfc3339(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct NetworkContext {
    pub id: String,
    pub snapshot_fingerprint: String,
    pub captured_at: String,
    pub active_interface: Option<String>,
    pub gateway: Option<String>,
    pub dns_servers: Vec<String>,
    pub system_proxy_enabled: bool,
    pub tunnel_detected: bool,
}

// ---------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum TargetCategory {
    Web,
    Api,
    Messenger,
    Gaming,
    Video,
    Ai,
    Search,
    Social,
    Streaming,
    Custom,
}

impl TargetCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::Api => "api",
            Self::Messenger => "messenger",
            Self::Gaming => "gaming",
            Self::Video => "video",
            Self::Ai => "ai",
            Self::Search => "search",
            Self::Social => "social",
            Self::Streaming => "streaming",
            Self::Custom => "custom",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "web" => Self::Web,
            "api" => Self::Api,
            "messenger" => Self::Messenger,
            "gaming" => Self::Gaming,
            "video" => Self::Video,
            "ai" => Self::Ai,
            "search" => Self::Search,
            "social" => Self::Social,
            "streaming" => Self::Streaming,
            _ => Self::Custom,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IpFamily {
    V4,
    V6,
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    Tcp,
    Quic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TargetEndpoint {
    /// Fully qualified hostname of the endpoint.
    pub hostname: String,
    pub port: u16,
    pub ip_family: IpFamily,
    /// Explicit IP address: skip DNS when provided.
    pub pinned_ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Target {
    pub id: String,
    pub label: String,
    pub category: TargetCategory,
    /// Primary URL used for the HTTP probe.
    pub check_url: String,
    pub endpoints: Vec<TargetEndpoint>,
    pub favorite: bool,
    pub enabled: bool,
    /// Priorities for the scheduler: 0 = highest.
    pub priority: u8,
    pub notes: Option<String>,
}

impl Target {
    pub fn single(
        label: &str,
        category: TargetCategory,
        check_url: &str,
        hostname: &str,
        port: u16,
        priority: u8,
    ) -> Self {
        Self {
            id: new_id(),
            label: label.to_string(),
            category,
            check_url: check_url.to_string(),
            endpoints: vec![TargetEndpoint {
                hostname: hostname.to_string(),
                port,
                ip_family: IpFamily::Any,
                pinned_ip: None,
            }],
            favorite: false,
            enabled: true,
            priority,
            notes: None,
        }
    }
}

/// Sensitive hash of content used to detect blocking pages reliably.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ContentFingerprint {
    /// Sha-256 over the first 64 KiB of the response body.
    pub body_sha256: Option<String>,
    pub title: Option<String>,
    pub server_header: Option<String>,
    pub true_asn_hint: Option<String>,
    /// Preview of the body (<= 64 KiB) for trace parsing and diagnosis.
    pub body_preview: Option<String>,
}

// ---------------------------------------------------------------------------
// Probe result models
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityStatus {
    Available,
    Partial,
    Degraded,
    Unavailable,
    SuspectedFiltering,
    RouteError,
    Unknown,
    /// Route exists but could not be verified -> never shown green.
    Unverified,
}

impl AvailabilityStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Partial => "partial",
            Self::Degraded => "degraded",
            Self::Unavailable => "unavailable",
            Self::SuspectedFiltering => "suspected_filtering",
            Self::RouteError => "route_error",
            Self::Unknown => "unknown",
            Self::Unverified => "unverified",
        }
    }

    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Available)
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "available" => Self::Available,
            "partial" => Self::Partial,
            "degraded" => Self::Degraded,
            "unavailable" => Self::Unavailable,
            "suspected_filtering" => Self::SuspectedFiltering,
            "route_error" => Self::RouteError,
            "unverified" => Self::Unverified,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsStatus {
    Ok,
    /// NOERROR with no answers of the requested type.
    NoData,
    Nxdomain,
    Servfail,
    Timeout,
    Blocked,
    Misconfigured,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DnsAnswer {
    pub name: String,
    pub ip: String,
    pub ttl: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DnsResult {
    pub status: DnsStatus,
    /// Which resolver stack produced the primary answers: system / control / doh.
    pub resolver_kind: String,
    pub resolver_addr: Option<String>,
    pub duration_ms: Option<f64>,
    pub answers_v4: Vec<DnsAnswer>,
    pub answers_v6: Vec<DnsAnswer>,
    /// Explicit rcode from the server, e.g. NOERROR / NXDOMAIN.
    pub rcode: Option<String>,
    /// TC flag was set: the UDP answer was truncated, retry over TCP/53.
    pub truncated: bool,
    /// Control (DoH) result when the control check ran.
    pub control: Option<Box<DnsResult>>,
    pub mismatch: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TcpStatus {
    Connected,
    Refused,
    Reset,
    Timeout,
    Unreachable,
    Blocked,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TcpResult {
    pub status: TcpStatus,
    pub connect_ms: Option<f64>,
    pub local_address: Option<String>,
    pub remote_address: Option<String>,
    /// True when the socket was bound to a concrete local interface address.
    pub interface_bound: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsStatus {
    HandshakeOk,
    HandshakeReset,
    HandshakeTimeout,
    CertificateInvalid,
    ProtocolError,
    ClosedEarly,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TlsResult {
    pub status: TlsStatus,
    pub handshake_ms: Option<f64>,
    pub tls_version: Option<String>,
    pub cipher: Option<String>,
    pub sni: Option<String>,
    /// Stage where the handshake failed, when it failed.
    pub failure_stage: Option<String>,
    /// TLS alert description received from the peer, e.g. `handshake_failure`,
    /// `unknown_ca`, `protocol_version`, `unexpected_message`, `close_notify`.
    pub alert: Option<String>,
    /// True when the ClientHello was actually written to the socket. False when
    /// the failure happened before TLS (TCP connect/timeout).
    pub client_hello_sent: bool,
    pub certificate_subject: Option<String>,
    pub certificate_issued_by: Option<String>,
    pub certificate_valid_from: Option<String>,
    pub certificate_valid_to: Option<String>,
    pub certificate_sans: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HttpStatus {
    Ok,
    /// Got a response, but the status code is not 2xx.
    HttpError,
    /// A redirect that did not resolve to a 2xx.
    Redirected,
    /// Response body looks like a local block page.
    BlockPage,
    ConnectionError,
    TlsError,
    Timeout,
    Error,
}

impl HttpStatus {
    /// Only a real 2xx response counts as success for egress probes.
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct HttpResult {
    pub status: HttpStatus,
    pub final_url: Option<String>,
    pub response_status: Option<u16>,
    /// Coarse class of the response: ok / redirect / client_error /
    /// server_error / block_page. Lets the UI distinguish 403/429/502/504
    /// without pattern-matching the raw status.
    pub status_group: Option<String>,
    pub ttfb_ms: Option<f64>,
    pub total_ms: Option<f64>,
    pub body_bytes: Option<u64>,
    pub http_version: Option<String>,
    pub redirect_chain: Vec<String>,
    /// Selected response headers useful for CDN/WAF attribution.
    pub server: Option<String>,
    pub content_type: Option<String>,
    pub date: Option<String>,
    pub cf_ray: Option<String>,
    /// Address the response actually came from (reveals the edge node).
    pub remote_addr: Option<String>,
    pub fingerprint: Option<ContentFingerprint>,
    pub block_page_matched: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TracerouteHop {
    pub ttl: u8,
    pub address: Option<String>,
    pub rtt_ms: Option<f64>,
}

impl Default for TracerouteHop {
    fn default() -> Self {
        Self {
            ttl: 0,
            address: None,
            rtt_ms: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TracerouteResult {
    pub target: String,
    pub hops: Vec<TracerouteHop>,
    pub reached: bool,
    pub error: Option<String>,
}

impl Default for TracerouteResult {
    fn default() -> Self {
        Self {
            target: String::new(),
            hops: vec![],
            reached: false,
            error: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PerfKind {
    TcpRtt,
    IcmpPing,
    Download,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PerformanceResult {
    pub kind: PerfKind,
    pub samples: u32,
    pub min_ms: Option<f64>,
    pub avg_ms: Option<f64>,
    pub max_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub loss_percent: Option<f64>,
    pub throughput_bytes_per_sec: Option<f64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind {
    Dns,
    Tcp,
    Tls,
    Http,
    Performance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteVerificationKind {
    Verified,
    Unverified,
    Unavailable,
    Unsafe,
}

/// One executed measurement, bound to a concrete route + network context.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ProbeResult {
    pub id: String,
    pub target_id: String,
    pub target_label: String,
    pub route_id: String,
    pub route_mode: RouteMode,
    /// Fingerprint of the network snapshot this probe ran in; if it changed
    /// mid-run, the result is flagged unreliable.
    pub network_fingerprint: String,
    /// Stored network context row (interfaces/gateway/DNS/proxy) for this run.
    pub network_context_id: Option<String>,
    pub network_changed: bool,
    pub timestamp: String,
    pub duration_ms: f64,
    pub correctness: RouteVerificationKind,
    pub status: AvailabilityStatus,
    pub ip_family_used: Option<IpFamily>,
    pub dns: Option<DnsResult>,
    pub tcp: Option<TcpResult>,
    pub tls: Option<TlsResult>,
    pub http: Option<HttpResult>,
    pub performance: Option<PerformanceResult>,
    pub error: Option<String>,
}

impl ProbeResult {
    pub fn new(target_id: &str, target_label: &str, route: &RouteProfile) -> Self {
        Self {
            id: new_id(),
            target_id: target_id.to_string(),
            target_label: target_label.to_string(),
            route_id: route.id.clone(),
            route_mode: route.mode,
            network_fingerprint: String::new(),
            network_context_id: None,
            network_changed: false,
            timestamp: now_rfc3339(),
            duration_ms: 0.0,
            correctness: RouteVerificationKind::Unverified,
            status: AvailabilityStatus::Unknown,
            ip_family_used: None,
            dns: None,
            tcp: None,
            tls: None,
            http: None,
            performance: None,
            error: None,
        }
    }

    /// True when the probe ran on a route whose state is so broken / unsafe
    /// that the result cannot be interpreted as service availability.
    pub fn route_error(&self) -> bool {
        matches!(
            self.correctness,
            RouteVerificationKind::Unavailable | RouteVerificationKind::Unsafe
        ) || self.network_changed
    }
}

// ---------------------------------------------------------------------------
// Diagnoses
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosisConfidence {
    Low,
    Medium,
    High,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosisCategory {
    DnsFiltering,
    IpBlocked,
    TcpReset,
    TlsSniFiltering,
    HttpFiltering,
    PartialAvailability,
    QuicRestriction,
    MtuBlackhole,
    SustainedDegradation,
    LocalIssue,
    GlobalServiceFailure,
    InsufficientData,
    NoRestriction,
    DirectVpnAsymmetry,
    VpnIssue,
}

impl DiagnosisCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DnsFiltering => "dns_filtering",
            Self::IpBlocked => "ip_blocked",
            Self::TcpReset => "tcp_reset",
            Self::TlsSniFiltering => "tls_sni_filtering",
            Self::HttpFiltering => "http_filtering",
            Self::PartialAvailability => "partial_availability",
            Self::QuicRestriction => "quic_restriction",
            Self::MtuBlackhole => "mtu_blackhole",
            Self::SustainedDegradation => "sustained_degradation",
            Self::LocalIssue => "local_issue",
            Self::GlobalServiceFailure => "global_service_failure",
            Self::InsufficientData => "insufficient_data",
            Self::NoRestriction => "no_restriction",
            Self::DirectVpnAsymmetry => "direct_vpn_asymmetry",
            Self::VpnIssue => "vpn_issue",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "dns_filtering" => Self::DnsFiltering,
            "ip_blocked" => Self::IpBlocked,
            "tcp_reset" => Self::TcpReset,
            "tls_sni_filtering" => Self::TlsSniFiltering,
            "http_filtering" => Self::HttpFiltering,
            "partial_availability" => Self::PartialAvailability,
            "quic_restriction" => Self::QuicRestriction,
            "mtu_blackhole" => Self::MtuBlackhole,
            "sustained_degradation" => Self::SustainedDegradation,
            "local_issue" => Self::LocalIssue,
            "global_service_failure" => Self::GlobalServiceFailure,
            "no_restriction" => Self::NoRestriction,
            "direct_vpn_asymmetry" => Self::DirectVpnAsymmetry,
            "vpn_issue" => Self::VpnIssue,
            _ => Self::InsufficientData,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Diagnosis {
    pub id: String,
    pub target_id: String,
    pub route_mode: Option<RouteMode>,
    pub category: DiagnosisCategory,
    pub confidence: DiagnosisConfidence,
    pub evidence: Vec<String>,
    pub alternative_explanations: Vec<String>,
    pub detected_at: String,
    /// Whether a control measurement (clean DNS / different resolver / other
    /// route) backs this diagnosis.
    pub backed_by_control_check: bool,
}

// ---------------------------------------------------------------------------
// Deep diagnostics
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeepCheckStatus {
    /// The check completed and the parameter looks normal.
    Pass,
    /// The check completed and deviated from the expected behaviour.
    Fail,
    /// The check could not be interpreted (control unavailable, etc.).
    Inconclusive,
    /// The check was not run (unsupported platform/missing endpoint).
    Skipped,
}

impl Default for DeepCheckStatus {
    fn default() -> Self {
        Self::Inconclusive
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DeepCheck {
    pub name: String,
    pub status: DeepCheckStatus,
    pub summary: String,
    pub details: Vec<String>,
    pub duration_ms: Option<f64>,
}

impl Default for DeepCheck {
    fn default() -> Self {
        Self {
            name: String::new(),
            status: DeepCheckStatus::Inconclusive,
            summary: String::new(),
            details: vec![],
            duration_ms: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DeepDiagnosticReport {
    pub id: String,
    pub url: String,
    pub route_mode: RouteMode,
    pub started_at: String,
    pub duration_ms: f64,
    pub checks: Vec<DeepCheck>,
    pub conclusion: String,
    pub suspected_categories: Vec<DiagnosisCategory>,
    pub confidence: DiagnosisConfidence,
}

impl Default for DeepDiagnosticReport {
    fn default() -> Self {
        Self {
            id: new_id(),
            url: String::new(),
            route_mode: RouteMode::Direct,
            started_at: now_rfc3339(),
            duration_ms: 0.0,
            checks: vec![],
            conclusion: String::new(),
            suspected_categories: vec![],
            confidence: DiagnosisConfidence::Unknown,
        }
    }
}

// ---------------------------------------------------------------------------
// Incidents
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IncidentKind {
    BlockedSuspected,
    ServiceDown,
    Restored,
    NetworkChanged,
    VpnConnected,
    VpnDisconnected,
    RouteUnverified,
    InternetDown,
    InternetRecovered,
    DnsAnomaly,
    DegradationDetected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Incident {
    pub id: String,
    pub kind: IncidentKind,
    pub target_id: Option<String>,
    pub route_mode: Option<RouteMode>,
    pub message: String,
    pub details: Option<String>,
    pub started_at: String,
    pub resolved_at: Option<String>,
}

// ---------------------------------------------------------------------------
// Default impls (serde container-level `default` requires them; the neutral
// values never look "green": statuses default to their Error / Unknown form)
// ---------------------------------------------------------------------------

impl Default for InterfaceInfo {
    fn default() -> Self {
        Self {
            index: 0,
            name: String::new(),
            description: String::new(),
            kind: InterfaceKind::Unknown,
            state: InterfaceState::Unknown,
            mac: None,
            ipv4: vec![],
            ipv6: vec![],
            default_v4: false,
            default_v6: false,
            dns_servers: vec![],
            gateway: None,
            kind_guess_reason: String::new(),
        }
    }
}

impl Default for RouteEntry {
    fn default() -> Self {
        Self {
            destination: String::new(),
            prefix_len: 0,
            next_hop: String::new(),
            interface_index: 0,
            metric: 0,
            persistent: false,
            is_default: false,
        }
    }
}

impl Default for ProxyEndpoint {
    fn default() -> Self {
        Self {
            kind: ProxyKind::Http,
            host: String::new(),
            port: 0,
            username: None,
        }
    }
}

impl Default for NetworkSnapshot {
    fn default() -> Self {
        Self {
            captured_at: now_rfc3339(),
            fingerprint: String::new(),
            interfaces: vec![],
            routes_v4: vec![],
            routes_v6: vec![],
            system_proxy: SystemProxyConfig::default(),
            default_gateway_v4: None,
            default_gateway_v6: None,
            dns_servers: vec![],
            tunnel_interfaces: vec![],
        }
    }
}

impl Default for RouteProfile {
    fn default() -> Self {
        Self {
            id: String::new(),
            mode: RouteMode::Direct,
            name: String::new(),
            interface_name: None,
            proxy_type: None,
            external_ip: None,
            external_ipv6: None,
            dns_servers: vec![],
            verification: RouteVerification::Unverified,
            confidence: RouteConfidence::None,
            verification_reason: None,
            vpn_kind: None,
            vpn_status: None,
            vpn_endpoint: None,
            egress: None,
            last_checked: now_rfc3339(),
        }
    }
}

impl Default for NetworkContext {
    fn default() -> Self {
        Self {
            id: new_id(),
            snapshot_fingerprint: String::new(),
            captured_at: now_rfc3339(),
            active_interface: None,
            gateway: None,
            dns_servers: vec![],
            system_proxy_enabled: false,
            tunnel_detected: false,
        }
    }
}

impl Default for TargetEndpoint {
    fn default() -> Self {
        Self {
            hostname: String::new(),
            port: 443,
            ip_family: IpFamily::Any,
            pinned_ip: None,
        }
    }
}

impl Default for Target {
    fn default() -> Self {
        Self {
            id: new_id(),
            label: String::new(),
            category: TargetCategory::Custom,
            check_url: String::new(),
            endpoints: vec![],
            favorite: false,
            enabled: true,
            priority: 5,
            notes: None,
        }
    }
}

impl Default for DnsAnswer {
    fn default() -> Self {
        Self {
            name: String::new(),
            ip: String::new(),
            ttl: 0,
        }
    }
}

impl Default for DnsResult {
    fn default() -> Self {
        Self {
            status: DnsStatus::Error,
            resolver_kind: String::new(),
            resolver_addr: None,
            duration_ms: None,
            answers_v4: vec![],
            answers_v6: vec![],
            rcode: None,
            truncated: false,
            control: None,
            mismatch: false,
            error: None,
        }
    }
}

impl Default for TcpResult {
    fn default() -> Self {
        Self {
            status: TcpStatus::Error,
            connect_ms: None,
            local_address: None,
            remote_address: None,
            interface_bound: false,
            error: None,
        }
    }
}

impl Default for TlsResult {
    fn default() -> Self {
        Self {
            status: TlsStatus::Error,
            handshake_ms: None,
            tls_version: None,
            cipher: None,
            sni: None,
            failure_stage: None,
            alert: None,
            client_hello_sent: false,
            certificate_subject: None,
            certificate_issued_by: None,
            certificate_valid_from: None,
            certificate_valid_to: None,
            certificate_sans: vec![],
            error: None,
        }
    }
}

impl Default for HttpResult {
    fn default() -> Self {
        Self {
            status: HttpStatus::Error,
            final_url: None,
            response_status: None,
            status_group: None,
            ttfb_ms: None,
            total_ms: None,
            body_bytes: None,
            http_version: None,
            redirect_chain: vec![],
            server: None,
            content_type: None,
            date: None,
            cf_ray: None,
            remote_addr: None,
            fingerprint: None,
            block_page_matched: false,
            error: None,
        }
    }
}

impl Default for ContentFingerprint {
    fn default() -> Self {
        Self {
            body_sha256: None,
            title: None,
            server_header: None,
            true_asn_hint: None,
            body_preview: None,
        }
    }
}

impl Default for PerformanceResult {
    fn default() -> Self {
        Self {
            kind: PerfKind::TcpRtt,
            samples: 0,
            min_ms: None,
            avg_ms: None,
            max_ms: None,
            jitter_ms: None,
            loss_percent: None,
            throughput_bytes_per_sec: None,
            error: None,
        }
    }
}

impl Default for ProbeResult {
    fn default() -> Self {
        Self {
            id: new_id(),
            target_id: String::new(),
            target_label: String::new(),
            route_id: String::new(),
            route_mode: RouteMode::Direct,
            network_fingerprint: String::new(),
            network_context_id: None,
            network_changed: false,
            timestamp: now_rfc3339(),
            duration_ms: 0.0,
            correctness: RouteVerificationKind::Unverified,
            status: AvailabilityStatus::Unknown,
            ip_family_used: None,
            dns: None,
            tcp: None,
            tls: None,
            http: None,
            performance: None,
            error: None,
        }
    }
}

impl Default for Diagnosis {
    fn default() -> Self {
        Self {
            id: new_id(),
            target_id: String::new(),
            route_mode: None,
            category: DiagnosisCategory::InsufficientData,
            confidence: DiagnosisConfidence::Unknown,
            evidence: vec![],
            alternative_explanations: vec![],
            detected_at: now_rfc3339(),
            backed_by_control_check: false,
        }
    }
}

impl Default for Incident {
    fn default() -> Self {
        Self {
            id: new_id(),
            kind: IncidentKind::NetworkChanged,
            target_id: None,
            route_mode: None,
            message: String::new(),
            details: None,
            started_at: now_rfc3339(),
            resolved_at: None,
        }
    }
}
