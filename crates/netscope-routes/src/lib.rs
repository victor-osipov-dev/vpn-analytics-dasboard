//! DIRECT / VPN route engines with egress verification.
//!
//! Key rule (from the product plan): a measurement may only be called DIRECT
//! when the egress route is confirmed to be independent from the VPN. When a
//! TUN VPN captures all traffic, the DIRECT route is reported as unverified.

use std::sync::Arc;

use netscope_network::{tunnel_presence, Discovery};
use netscope_core::models::{
    EgressIdentity, NetworkSnapshot, ProxyEndpoint, RouteConfidence, RouteMode,
    RouteProfile, RouteVerification, VpnKind, VpnStatus,
};
use tokio::sync::RwLock;
use tracing::warn;

pub mod direct;
pub mod proxy_engine;
pub mod verify;

pub const DIRECT_ROUTE_ID: &str = "route:direct";
pub const VPN_ROUTE_ID: &str = "route:vpn";
pub const SYSTEM_ROUTE_ID: &str = "route:system";
pub const CUSTOM_PROXY_ROUTE_ID: &str = "route:custom-proxy";

/// Everything the engines need to operate.
#[derive(Debug, Clone, Default)]
pub struct EngineSettings {
    pub control_doh_url: String,
    pub egress_endpoints: Vec<String>,
    pub connect_timeout_ms: u64,
    pub http_timeout_ms: u64,
    pub lookup_asn: bool,
    pub direct_strictness: netscope_core::settings::DirectStrictness,
}

/// Owns the network snapshot and the concrete route profiles.
pub struct NetworkRouteManager {
    snapshot: RwLock<Option<Arc<NetworkSnapshot>>>,
    settings: RwLock<EngineSettings>,
    custom_proxy: RwLock<Option<ProxyEndpoint>>,
}

impl NetworkRouteManager {
    pub fn new() -> Self {
        Self {
            snapshot: RwLock::new(None),
            settings: RwLock::new(EngineSettings {
                control_doh_url: "https://1.1.1.1/dns-query".into(),
                egress_endpoints: netscope_core::settings::AppSettings::default().egress_endpoints,
                connect_timeout_ms: 6000,
                http_timeout_ms: 12_000,
                lookup_asn: false,
                direct_strictness: netscope_core::settings::DirectStrictness::Strict,
            }),
            custom_proxy: RwLock::new(None),
        }
    }

    /// Refresh the live snapshot.
    pub async fn refresh(&self) -> netscope_core::Result<Arc<NetworkSnapshot>> {
        let snap = Discovery::snapshot()?;
        let arc = Arc::new(snap);
        *self.snapshot.write().await = Some(arc.clone());
        Ok(arc)
    }

    pub async fn snapshot(&self) -> Option<Arc<NetworkSnapshot>> {
        self.snapshot.read().await.clone()
    }

    pub async fn update_settings(&self, s: EngineSettings) {
        *self.settings.write().await = s;
    }

    pub async fn settings(&self) -> EngineSettings {
        self.settings.read().await.clone()
    }

    pub async fn set_custom_proxy(&self, proxy: Option<ProxyEndpoint>) {
        *self.custom_proxy.write().await = proxy;
    }

    pub async fn custom_proxy(&self) -> Option<ProxyEndpoint> {
        self.custom_proxy.read().await.clone()
    }

    /// Which monitoring routes are possible in the current snapshot.
    pub async fn candidate_routes(&self) -> Vec<RouteProfile> {
        let snapshot = match self.snapshot().await {
            Some(s) => s,
            None => return vec![],
        };
        let settings = self.settings().await;
        let has_tunnel = tunnel_presence(&snapshot);
        let proxy_cfg = &snapshot.system_proxy;

        let mut out = vec![];

        // DIRECT candidate (the strictly verified physical route)
        let mut direct = RouteProfile::placeholder(DIRECT_ROUTE_ID, RouteMode::Direct, "DIRECT");
        let physical = snapshot.physical_default_interface(true);
        match physical {
            Some(iface) => {
                direct.interface_name = Some(iface.name.clone());
                direct.dns_servers = iface.dns_servers.clone();
                let strict = settings.direct_strictness;
                let unverified_reason =
                    if has_tunnel {
                        // Cannot be directly confirmed unless the egress check
                        // proves that the route bypasses the TUN.
                        Some("Possible full tunneling: TUN interface captures traffic; egress not yet confirmed".to_string())
                    } else if proxy_cfg.enabled {
                        Some("System proxy enabled; direct egress requires bypass verification".to_string())
                    } else {
                        None
                    };
                match (strict, unverified_reason.clone()) {
                    (netscope_core::settings::DirectStrictness::Off, _) => {
                        direct.verification = RouteVerification::Unverified;
                        direct.verification_reason = unverified_reason;
                        direct.confidence = RouteConfidence::None;
                    }
                    (netscope_core::settings::DirectStrictness::Auto, r) if r.is_none() => {
                        direct.verification =
                            RouteVerification::Unverified; // will be verified by egress check below
                        direct.confidence = RouteConfidence::Medium;
                    }
                    (_, r) => {
                        direct.verification = RouteVerification::Unverified;
                        direct.verification_reason = r;
                        direct.confidence = RouteConfidence::None;
                    }
                }
            }
            None => {
                direct.verification = RouteVerification::Unavailable;
                direct.verification_reason = Some("Physical interface with default route not found".into());
            }
        }
        out.push(direct);

        // VPN tunnel candidate
        if has_tunnel {
            let mut vpn = RouteProfile::placeholder(VPN_ROUTE_ID, RouteMode::Vpn, "VPN (TUN)");
            vpn.vpn_kind = Some(VpnKind::Tunnel);
            vpn.vpn_status = Some(VpnStatus::Detected);
            vpn.verification = RouteVerification::Unverified;
            vpn.verification_reason = Some("Tunnel detected, egress not yet confirmed".into());
            vpn.confidence = RouteConfidence::Medium;
            if let Some(t) = snapshot.tunnel_interfaces.first() {
                vpn.interface_name = Some(t.clone());
                if let Some(iface) = snapshot
                    .interfaces
                    .iter()
                    .find(|i| i.name == *t)
                {
                    vpn.dns_servers = iface.dns_servers.clone();
                }
            }
            out.push(vpn);
        }

        // System proxy candidates (proxy-based VPN works through them)
        if proxy_cfg.enabled {
            if let Some(p) = &proxy_cfg.https_proxy {
                let mut r = RouteProfile::placeholder(SYSTEM_ROUTE_ID, RouteMode::System, "System HTTPS proxy");
                r.proxy_type = Some(proxy_kind_str(p));
                r.vpn_kind = Some(VpnKind::ProxyBased);
                r.vpn_status = Some(VpnStatus::Detected);
                r.vpn_endpoint = Some(format!("{}:{}", p.host, p.port));
                r.verification = RouteVerification::Unverified;
                out.push(r);
            } else if let Some(p) = &proxy_cfg.http_proxy {
                let mut r = RouteProfile::placeholder(SYSTEM_ROUTE_ID, RouteMode::System, "System HTTP proxy");
                r.proxy_type = Some(proxy_kind_str(p));
                r.vpn_kind = Some(VpnKind::ProxyBased);
                r.vpn_status = Some(VpnStatus::Detected);
                r.vpn_endpoint = Some(format!("{}:{}", p.host, p.port));
                r.verification = RouteVerification::Unverified;
                out.push(r);
            }
        }

        // User-configured proxy as an explicit VPN route
        if let Some(custom) = self.custom_proxy().await {
            let mut r =
                RouteProfile::placeholder(CUSTOM_PROXY_ROUTE_ID, RouteMode::CustomProxy, "User proxy (VPN)");
            r.proxy_type = Some(proxy_kind_str(&custom));
            r.vpn_kind = Some(VpnKind::ProxyBased);
            r.vpn_status = Some(VpnStatus::Detected);
            r.vpn_endpoint = Some(format!("{}:{}", custom.host, custom.port));
            r.verification = RouteVerification::Unverified;
            out.push(r);
        }

        if let Some(s) = self.snapshot().await {
            let _ = s.captured_at;
        }
        out
    }

    /// Full verification pass: egress check for every candidate route, which
    /// raises confidence above "unverified" where provable. Never runs
    /// automatically-violating actions — only outbound probes.
    pub async fn verify_all(&self) -> Vec<RouteProfile> {
        let candidates = self.candidate_routes().await;
        let snapshot = match self.snapshot().await {
            Some(s) => s,
            None => return candidates,
        };
        let mut out = Vec::with_capacity(candidates.len());
        let mut egress_direct: Option<EgressIdentity> = None;
        let mut egress_vpn: Option<EgressIdentity> = None;
        let has_tunnel_snapshot = tunnel_presence(&snapshot);

        // System-default egress (unbound) — baseline for tunnel comparisons.
        let egress_system: Option<EgressIdentity> =
            if has_tunnel_snapshot {
                Some(direct::probe_tun_egress(&snapshot, self.settings().await).await)
            } else {
                None
            };

        for cand in candidates {
            let mut profile = cand.clone();
            match profile.mode {
                RouteMode::Direct => {
                    if profile.verification == RouteVerification::Unavailable {
                        out.push(profile);
                        continue;
                    }
                    let eg = direct::probe_direct_egress(&snapshot, self.settings().await).await;
                    profile.egress = Some(eg.clone());
                    profile.external_ip = eg.external_ip.clone();
                    profile.external_ipv6 = e_v6(&eg);

                    // Egress comparison rule:
                    // - no tunnel present and probe OK -> verified;
                    // - tunnel present and bound egress == system egress
                    //   -> TUN captures all traffic, DIRECT not confirmed;
                    // - tunnel present and bound egress differs -> verified.
                    let (ver, conf, reason) = if profile.egress.is_none() {
                        (
                            RouteVerification::Unavailable,
                            RouteConfidence::None,
                            Some("Не удалось измерить исходящий маршрут DIRECT".into()),
                        )
                    } else if !has_tunnel_snapshot {
                        (
                            RouteVerification::Verified,
                            RouteConfidence::High,
                            None,
                        )
                    } else {
                        let same: Option<bool> = match (
                            eg.external_ip.as_ref(),
                            egress_system.as_ref().and_then(|e| e.external_ip.as_ref()),
                        ) {
                            (Some(a), Some(b)) => Some(a == b),
                            (Some(a), None) => Some(!a.is_empty() && false),
                            _ => None,
                        };
                        match same {
                            Some(true) => (
                                RouteVerification::Unverified,
                                RouteConfidence::Low,
                                Some(
                                    "Одинаковый выходной IP в привязанном к физическому интерфейсу и системном маршруте: туннель захватывает весь трафик, DIRECT не подтверждён".to_string(),
                                ),
                            ),
                            Some(false) => (
                                RouteVerification::Verified,
                                RouteConfidence::High,
                                Some("Прямой маршрут подтверждён: выходной IP отличается от туннеля".to_string()),
                            ),
                            None => (
                                RouteVerification::Unverified,
                                RouteConfidence::Low,
                                Some("Есть TUN-интерфейс, но системный egress не удалось измерить; DIRECT строго не подтверждён".to_string()),
                            ),
                        }
                    };
                    profile.verification = ver;
                    profile.confidence = conf;
                    profile.verification_reason = reason;
                    profile.last_checked = netscope_core::now_rfc3339();
                    egress_direct = Some(eg);
                }
                RouteMode::System | RouteMode::CustomProxy => {
                    let proxy_url = proxy_url_for(&profile);
                    match proxy_url {
                        Some(url) => {
                            let eg =
                                proxy_engine::probe_proxy_egress(&url, self.settings().await).await;
                            profile.egress = Some(eg.clone());
                            profile.external_ip = eg.external_ip.clone();
                            profile.external_ipv6 = e_v6(&eg);
                            match eg.external_ip {
                                Some(_) => {
                                    profile.verification = RouteVerification::Verified;
                                    profile.confidence = RouteConfidence::High;
                                    profile.verification_reason = None;
                                    profile.vpn_status = Some(VpnStatus::Verified);
                                }
                                None => {
                                    profile.verification = RouteVerification::Unavailable;
                                    profile.confidence = RouteConfidence::None;
                                    profile.verification_reason =
                                        eg.reason.clone().or_else(|| Some("Proxy does not respond".into()));
                                    profile.vpn_status = Some(VpnStatus::Detected);
                                }
                            }
                            profile.last_checked = netscope_core::now_rfc3339();
                        }
                        None => {
                            profile.verification = RouteVerification::Unavailable;
                            profile.verification_reason =
                                Some("Failed to build proxy URL".into());
                        }
                    }
                }
                RouteMode::Vpn => {
                    // TUN route: normal egress is the tunnel; verify by
                    // comparing to the DIRECT egress.
                    let eg = direct::probe_tun_egress(&snapshot, self.settings().await).await;
                    profile.egress = Some(eg.clone());
                    profile.external_ip = eg.external_ip.clone();
                    profile.external_ipv6 = e_v6(&eg);
                    match (&eg.external_ip, &egress_direct) {
                        (Some(ip), Some(d)) => {
                            profile.vpn_status = Some(VpnStatus::Connected);
                            match &d.external_ip {
                                Some(dip) if dip == ip && !ip.is_empty() => {
                                    // Same egress: not proof that the VPN is dead —
                                    // could be split tunnel / transparent egress.
                                    profile.verification = RouteVerification::Unverified;
                                    profile.confidence = RouteConfidence::Low;
                                    profile.verification_reason = Some(
                                        "The external IP matches DIRECT: possible split-channeling, transparent egress, or a non-working VPN".into(),
                                    );
                                }
                                _ => {
                                    profile.verification = RouteVerification::Verified;
                                    profile.confidence = RouteConfidence::High;
                                    profile.verification_reason = None;
                                    profile.vpn_status = Some(VpnStatus::Verified);
                                }
                            }
                        }
                        (Some(_), None) => {
                            profile.vpn_status = Some(VpnStatus::Connected);
                            profile.verification = RouteVerification::Unverified;
                            profile.verification_reason = Some(
                                "DIRECT egress was not defined for the VPN egress comparison".into(),
                            );
                        }
                        (None, _) => {
                            profile.vpn_status = Some(VpnStatus::Detected);
                            profile.verification = RouteVerification::Unavailable;
                            profile.verification_reason =
                                eg.reason.clone().or_else(|| Some("Tunnel does not respond".into()));
                        }
                    }
                    profile.last_checked = netscope_core::now_rfc3339();
                    egress_vpn = Some(eg);
                }
            }
            out.push(profile);
        }

        if egress_direct.is_none() && egress_vpn.is_none() {
            warn!("verification produced no egress data at all");
        }

        out
    }
}

fn e_v6(eg: &EgressIdentity) -> Option<String> {
    eg.external_ipv6.clone()
}

fn proxy_kind_str(p: &ProxyEndpoint) -> String {
    format!("{:?}", p.kind).to_lowercase()
}

fn proxy_url_for(profile: &RouteProfile) -> Option<String> {
    let endpoint = &profile.vpn_endpoint.as_deref()?;
    let kind = profile.proxy_type.as_deref().unwrap_or("http");
    let scheme = match kind {
        "socks5" | "socks5remotedns" => "socks5h",
        "https" => "https",
        _ => "http",
    };
    Some(format!("{scheme}://{endpoint}"))
}
