//! Network discovery: interfaces, routes, DNS, system proxy, TUN detection.
//! Composes raw platform data into a consistent `NetworkSnapshot`.

use std::collections::HashSet;

use netscope_core::models::{
    InterfaceInfo, InterfaceKind, InterfaceState, NetworkSnapshot, RouteEntry,
};
use sha2::{Digest, Sha256};

pub mod watcher;
pub use watcher::{NetworkChange, NetworkWatcher};

#[cfg(windows)]
use netscope_platform_windows as platform;

/// Discovery entry point.
pub struct Discovery;

impl Discovery {
    pub fn snapshot() -> netscope_core::Result<NetworkSnapshot> {
        #[cfg(windows)]
        {
            DiscoverWindows::new().run()
        }
        #[cfg(not(windows))]
        {
            Err(netscope_core::CoreError::Platform(
                "network discovery currently requires Windows; other platforms are on the roadmap".into(),
            ))
        }
    }
}

pub struct SnapshotError(pub String);

#[cfg(windows)]
struct DiscoverWindows;

#[cfg(windows)]
impl DiscoverWindows {
    fn new() -> Self {
        Self
    }

    fn run(&self) -> netscope_core::Result<NetworkSnapshot> {
        let interfaces = platform::adapters::list_interfaces()?;
        let mut routes = platform::routes::list_routes()?;
        let system_proxy = platform::proxy::system_proxy()?;

        let (idx_v4, gw_v4) = Self::default_route(&routes, true);
        let (_, gw_v6) = Self::default_route(&routes, false);

        // Sort by metric so "best default route" logic is deterministic.
        routes.sort_by_key(|r| (r.metric, r.interface_index));

        let mut interfaces = interfaces;
        // Mark which interfaces carry the default route (v4/v6 separately).
        // Priority: lowest metric wins among default routes of same family.
        if let Some(i) = interfaces
            .iter_mut()
            .find(|i| i.index == idx_v4)
        {
            i.default_v4 = true;
            i.gateway = gw_v4.clone();
        }
        if let Some(i) = interfaces
            .iter_mut()
            .find(|i| i.index == default_index_v6(&routes))
        {
            i.default_v6 = true;
            if i.gateway.is_none() {
                i.gateway = gw_v6.clone();
            }
        }

        let dns_servers = Self::active_dns(&interfaces);
        let tunnel_interfaces: Vec<String> = interfaces
            .iter()
            .filter(|i| i.kind == InterfaceKind::Virtual && i.state == InterfaceState::Up)
            .map(|i| i.name.clone())
            .collect();

        let snapshot = NetworkSnapshot {
            captured_at: netscope_core::now_rfc3339(),
            fingerprint: String::new(),
            interfaces,
            routes_v4: routes.iter().filter(|r| is_v4_route(&r.destination)).cloned().collect(),
            routes_v6: routes.iter().filter(|r| !is_v4_route(&r.destination)).cloned().collect(),
            system_proxy,
            default_gateway_v4: gw_v4,
            default_gateway_v6: gw_v6,
            dns_servers,
            tunnel_interfaces,
        };
        let mut snapshot = snapshot;
        snapshot.fingerprint = fingerprint(&snapshot);
        Ok(snapshot)
    }

    fn default_route(
        routes: &[RouteEntry],
        v4: bool,
    ) -> (u32, Option<String>) {
        let best = routes
            .iter()
            .filter(|r| r.is_default && Self::route_is_v4(r) == v4)
            .min_by_key(|r| (r.metric, r.interface_index));
        (
            best.map(|r| r.interface_index).unwrap_or(0),
            best.map(|r| r.next_hop.clone()).filter(|n| n != "0.0.0.0" && n != "::"),
        )
    }

    fn route_is_v4(r: &RouteEntry) -> bool {
        is_v4_route(&r.destination)
    }

    fn active_dns(interfaces: &[InterfaceInfo]) -> Vec<String> {
        // Prefer DNS from the default (physical) interface, then any up ifaces,
        // then virtual, deduped in order.
        let mut out: Vec<String> = vec![];
        let mut seen = HashSet::new();

        let ordered: Vec<&InterfaceInfo> = {
            let mut v: Vec<&InterfaceInfo> = interfaces.iter().collect();
            v.sort_by_key(|i| {
                (
                    match i.kind {
                        InterfaceKind::Physical => 0,
                        InterfaceKind::Unknown => 1,
                        InterfaceKind::Virtual => 2,
                        InterfaceKind::Loopback => 3,
                    },
                    i.index,
                )
            });
            v.into_iter().filter(|i| i.state == InterfaceState::Up).collect()
        };
        // default interface first
        for i in ordered {
            for d in &i.dns_servers {
                if seen.insert(d.clone()) {
                    out.push(d.clone());
                }
            }
        }
        out
    }
}

#[cfg(windows)]
fn default_index_v6(routes: &[RouteEntry]) -> u32 {
    routes
        .iter()
        .filter(|r| r.is_default && !is_v4_route(&r.destination))
        .min_by_key(|r| (r.metric, r.interface_index))
        .map(|r| r.interface_index)
        .unwrap_or(0)
}

pub fn is_v4_route(destination: &str) -> bool {
    !destination.contains(':')
}

/// Stable fingerprint of the network state: hash of sorted interface/route/
/// proxy signatures. Detects configuration changes (gateway change, VPN up...).
pub fn fingerprint(snapshot: &NetworkSnapshot) -> String {
    let mut hasher = Sha256::new();
    for i in &snapshot.interfaces {
        let line = format!(
            "{}|{}|{}|{:?}|{:?}|{:?}|{}|{}|{}",
            i.index,
            i.name,
            i.description,
            i.kind,
            i.state,
            i.mac,
            i.ipv4.join(","),
            i.default_v4,
            i.default_v6
        );
        hasher.update(line.as_bytes());
        hasher.update([0]);
        hasher.update(i.dns_servers.join(",").as_bytes());
        hasher.update([0]);
    }
    for r in snapshot.routes_v4.iter().chain(snapshot.routes_v6.iter()) {
        hasher.update(format!("{}|{}/{}|->{}|if{}|m{}", r.is_default, r.destination, r.prefix_len, r.next_hop, r.interface_index, r.metric).as_bytes());
        hasher.update([0]);
    }
    hasher.update(
        format!("{:?}", snapshot.system_proxy.enabled).as_bytes(),
    );
    hasher.update(
        format!(
            "{:?}|{:?}|{:?}|{}",
            snapshot.system_proxy.http_proxy,
            snapshot.system_proxy.https_proxy,
            snapshot.system_proxy.socks,
            snapshot.system_proxy.pac_url.is_some()
        )
        .as_bytes(),
    );
    hex(&hasher.finalize())
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Report whether a snapshot suggests a VPN/TUN presence (heuristic view).
pub fn tunnel_presence(snapshot: &NetworkSnapshot) -> bool {
    !snapshot.tunnel_interfaces.is_empty()
        || snapshot.interfaces.iter().any(|i| {
            i.kind == InterfaceKind::Virtual
                && i.state != InterfaceState::Down
                && snapshot
                    .routes_v4
                    .iter()
                    .any(|r| r.interface_index == i.index && r.is_default)
        })
}

pub fn interface_by_index(
    snapshot: &NetworkSnapshot,
    index: u32,
) -> Option<InterfaceInfo> {
    snapshot.interfaces.iter().find(|i| i.index == index).cloned()
}
