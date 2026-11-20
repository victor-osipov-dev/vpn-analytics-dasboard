//! Route table discovery via GetIpForwardTable2.

use netscope_core::models::RouteEntry;

/// Full IPv4 + IPv6 route table.
pub fn list_routes() -> netscope_core::Result<Vec<RouteEntry>> {
    const AF_INET: u16 = 2;
    const AF_INET6: u16 = 23;
    let mut out = vec![];
    out.extend(table(AF_INET)?);
    out.extend(table(AF_INET6)?);
    Ok(out)
}

fn table(family: u16) -> netscope_core::Result<Vec<RouteEntry>> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIpForwardTable2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
    };
    let mut ptr: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: out pointer only read on success, then freed.
    let rc = unsafe { GetIpForwardTable2(family, &mut ptr) };
    if rc != 0 {
        return Err(netscope_core::CoreError::Platform(format!(
            "GetIpForwardTable2 failed: {rc}"
        )));
    }
    if ptr.is_null() {
        return Err(netscope_core::CoreError::Platform(
            "GetIpForwardTable2 returned null".into(),
        ));
    }
    // SAFETY: table struct from win32 on success.
    let tbl = unsafe { &*ptr };
    let count = tbl.NumEntries as usize;
    // SAFETY: rows are inline in the table allocation.
    let rows: &[MIB_IPFORWARD_ROW2] =
        unsafe { std::slice::from_raw_parts(tbl.Table.as_ptr(), count) };
    let mut out = Vec::with_capacity(count);
    for r in rows {
        let is_default = r.DestinationPrefix.PrefixLength == 0;
        let dest = crate::routes::sockaddr_to_string(&r.DestinationPrefix.Prefix)
            .unwrap_or_else(|| "<unknown>".to_string());
        let next_hop = crate::routes::sockaddr_to_string(&r.NextHop)
            .unwrap_or_else(|| "<unknown>".to_string());
        if dest == "<unknown>" {
            continue;
        }
        out.push(RouteEntry {
            destination: dest,
            prefix_len: r.DestinationPrefix.PrefixLength,
            next_hop,
            interface_index: r.InterfaceIndex,
            metric: r.Metric,
            persistent: false,
            is_default,
        });
    }
    // SAFETY: allocated by GetIpForwardTable2, documented free function.
    unsafe {
        FreeMibTable(ptr.cast());
    }
    Ok(out)
}

pub(crate) fn sockaddr_to_string(sa: &windows_sys::Win32::Networking::WinSock::SOCKADDR_INET) -> Option<String> {
    // SAFETY: union access: si_family shares the first two bytes with sockaddr.
    let family = unsafe { sa.si_family };
    match family {
        2 => {
            // SAFETY: variant Ipv4 of the same-size union.
            let v4 = unsafe { sa.Ipv4 };
            let ip = std::net::Ipv4Addr::from(u32::from_be(unsafe { v4.sin_addr.S_un.S_addr }));
            // route sockaddrs have port 0; show address only
            Some(ip.to_string())
        }
        23 => {
            // SAFETY: variant Ipv6.
            let v6 = unsafe { sa.Ipv6 };
            let octets: [u8; 16] = unsafe { v6.sin6_addr.u.Byte };
            Some(std::net::Ipv6Addr::from(octets).to_string())
        }
        _ => None,
    }
}
