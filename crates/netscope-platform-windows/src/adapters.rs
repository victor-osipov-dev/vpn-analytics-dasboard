//! Interface + address discovery via IPHLPAPI.

use netscope_core::models::{InterfaceInfo, InterfaceKind, InterfaceState};

/// All visible IP interfaces (including virtual and loopback).
pub fn list_interfaces() -> netscope_core::Result<Vec<InterfaceInfo>> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_UNICAST_ADDRESS_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET as AF_INET_W, AF_UNSPEC as AF_UNSPEC_W, SOCKADDR};

    // IANA interface types used for classification (kept local so we do not
    // depend on possibly-renamed windows-sys constants).
    const IF_TYPE_ETHERNET_CSMACD: u32 = 6;
    const IF_TYPE_PPP: u32 = 23;
    const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
    const IF_TYPE_PROP_VIRTUAL: u32 = 53;
    const IF_TYPE_TUNNEL: u32 = 131;
    const IF_TYPE_IEEE80211: u32 = 71;

    let mut size: u32 = 16 * 1024;
    let mut buffer;
    // GetAdaptersAddresses may report ERROR_BUFFER_OVERFLOW (122) and the
    // needed size; documented retry loop.
    let rc = loop {
        buffer = vec![0u8; size as usize];
        let rc: u32 = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC_W as u32,
                0,
                std::ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if rc != 122 {
            break rc;
        }
        size += 16 * 1024;
        if size > 64 * 1024 * 1024 {
            return Err(netscope_core::CoreError::Platform(
                "GetAdaptersAddresses needs > 64 MiB; aborting".into(),
            ));
        }
    };
    if rc != 0 {
        return Err(netscope_core::CoreError::Platform(format!(
            "GetAdaptersAddresses failed with code {rc}"
        )));
    }

    let mut out: Vec<InterfaceInfo> = vec![];
    let mut cursor: *mut IP_ADAPTER_ADDRESSES_LH = buffer.as_mut_ptr().cast();
    while !cursor.is_null() {
        // SAFETY: cursor walks the well-formed list written by Win32 above.
        let row: &IP_ADAPTER_ADDRESSES_LH = unsafe { &*cursor };
        cursor = row.Next;

        let if_type = row.IfType;
        let (kind, reason) = match if_type {
            IF_TYPE_SOFTWARE_LOOPBACK => (
                InterfaceKind::Loopback,
                "IANA type 24 (software loopback)".to_string(),
            ),
            IF_TYPE_TUNNEL => (
                InterfaceKind::Virtual,
                "IANA type 131 (tunnel/VPN adapter)".to_string(),
            ),
            IF_TYPE_PROP_VIRTUAL => (
                InterfaceKind::Virtual,
                "IANA type 53 (logical/prop virtual)".to_string(),
            ),
            IF_TYPE_PPP => (
                InterfaceKind::Virtual,
                "IANA type 23 (wan/ppp)".to_string(),
            ),
            IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE80211 => (
                InterfaceKind::Physical,
                format!("IANA type {if_type} (ethernet/wifi)"),
            ),
            // Other types (e.g. 929 wireless WAN, 53x L2 frameworks) are
            // classified by name hints below.
            other => {
                let hay = format!(
                    "{} {}",
                    wide_to_string(row.FriendlyName),
                    wide_to_string(row.Description)
                )
                .to_lowercase();
                const HINTS: [&str; 13] = [
                    "wireguard", "wintun", "tap", "tun", "tailscale", "openvpn", "zerotier",
                    "proton", "mullvad", "clash", "cloudflared", "hyper-v", "tunneling",
                ];
                if HINTS.iter().any(|h| hay.contains(h)) {
                    (
                        InterfaceKind::Virtual,
                        format!("IANA type {other} + vendor name match"),
                    )
                } else {
                    (InterfaceKind::Unknown, format!("IANA type {other}"))
                }
            }
        };

        let mut info = InterfaceInfo {
            index: unsafe { row.Anonymous1.Anonymous.IfIndex },
            name: wide_to_string(row.FriendlyName),
            description: wide_to_string(row.Description),
            kind: kind,
            state: match row.OperStatus {
                1 => InterfaceState::Up,
                2 => InterfaceState::Down,
                _ => InterfaceState::Unknown,
            },
            mac: mac_from_bytes(&row.PhysicalAddress, row.PhysicalAddressLength),            ipv4: Vec::new(),
            ipv6: Vec::new(),
            default_v4: false,
            default_v6: false,
            dns_servers: Vec::new(),
            gateway: None,
            kind_guess_reason: reason,
        };
        if info.name.is_empty() {
            info.name = format!("if{}", info.index);
        }

        // Unicast addresses
        let mut p: *mut IP_ADAPTER_UNICAST_ADDRESS_LH = row.FirstUnicastAddress;
        while !p.is_null() {
            // SAFETY: node written by Win32 above.
            let node = unsafe { &*p };
            p = node.Next;
            let family = unsafe { (*(node.Address.lpSockaddr as *const SOCKADDR)).sa_family };
            let text = crate::adapters::sockaddr_to_string(node.Address.lpSockaddr);
            if let Some(t) = text {
                if family == AF_INET_W as u16 {
                    info.ipv4.push(t);
                } else {
                    info.ipv6.push(t);
                }
            }
        }
        let mut existing = std::collections::HashSet::new();
        info.ipv4.retain(|x| existing.insert(x.clone()));

        // DNS servers
        let mut dns = row.FirstDnsServerAddress;
        while !dns.is_null() {
            // SAFETY: linked-list node written by Win32 above.
            let node = unsafe { &*dns };
            dns = node.Next;
            if let Some(s) = crate::adapters::sockaddr_to_string(node.Address.lpSockaddr) {
                info.dns_servers.push(s);
            }
        }
        info.dns_servers.sort();
        info.dns_servers
            .retain(|x| !x.starts_with("169.254.") && !x.starts_with("fe80:"));

        // Gateway: derive from the route table in routes.rs; store a hint here
        // only when the adapter exposes one.
        info.gateway = None;
        out.push(info);
    }
    Ok(out)
}

/// IPv4 addrs per interface index (for binding checks).
pub fn list_ipv4_addrs_by_iface(
    indices: &[u32],
) -> netscope_core::Result<std::collections::HashMap<u32, Vec<std::net::Ipv4Addr>>> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetIpAddrTable, MIB_IPADDRTABLE};
    let mut size: u32 = 0;
    // SAFETY: null pointer + size 0 -> required buffer size returned.
    unsafe {
        GetIpAddrTable(std::ptr::null_mut(), &mut size, 0);
    }
    let mut buf = vec![0u8; size.max(4) as usize];
    // SAFETY: buf holds exactly the required table bytes.
    let rc = unsafe { GetIpAddrTable(buf.as_mut_ptr().cast::<MIB_IPADDRTABLE>(), &mut size, 0) };
    if rc != 0 {
        return Err(netscope_core::CoreError::Platform(format!(
            "GetIpAddrTable failed: {rc}"
        )));
    }
    // SAFETY: GetIpAddrTable returned success on this buffer.
    let table = unsafe { buf.as_ptr().cast::<MIB_IPADDRTABLE>().as_ref().expect("table") };
    let count = table.dwNumEntries as usize;
    // SAFETY: entries inline in table struct.
    let entries = unsafe { std::slice::from_raw_parts(table.table.as_ptr(), count) };
    let mut map: std::collections::HashMap<u32, Vec<std::net::Ipv4Addr>> = std::collections::HashMap::new();
    for e in entries {
        if indices.contains(&e.dwIndex) {
            let ip = std::net::Ipv4Addr::from(u32::from_be(e.dwAddr));
            map.entry(e.dwIndex).or_default().push(ip);
        }
    }
    Ok(map)
}

/// SOCKADDR pointer -> string. Public so other platform modules reuse it.
pub(crate) fn sockaddr_to_string(sa: *mut windows_sys::Win32::Networking::WinSock::SOCKADDR) -> Option<String> {
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6};
    if sa.is_null() {
        return None;
    }
    // SAFETY: family byte at the same offset for every sockaddr variant.
    let family = unsafe { (*sa.cast::<SOCKADDR>()).sa_family };
    match family {
        AF_INET => {
            // SAFETY: the pointer is a valid sockaddr of length >= 16 for INET.
            let s = unsafe { sa.cast::<SOCKADDR_IN>().as_ref()? };
            let ip = std::net::Ipv4Addr::from(u32::from_be(unsafe { s.sin_addr.S_un.S_addr }));
            Some(ip.to_string())
        }
        AF_INET6 => {
            // SAFETY: sockaddr_in6 layout; union read of the address bytes.
            let s = unsafe { sa.cast::<SOCKADDR_IN6>().as_ref()? };
            let octets: [u8; 16] = unsafe { s.sin6_addr.u.Byte };
            Some(std::net::Ipv6Addr::from(octets).to_string())
        }
        _ => None,
    }
}
fn mac_from_bytes(bytes: &[u8], len: u32) -> Option<String> {
    let l = (len as usize).min(bytes.len());
    if l == 0 || l > 32 {
        return None;
    }
    Some(bytes[..l].iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":"))
}

fn wide_to_string(ptr: *mut u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    // SAFETY: null-terminated UTF-16 string written by Win32.
    unsafe {
        let mut len = 0usize;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
    }
}


