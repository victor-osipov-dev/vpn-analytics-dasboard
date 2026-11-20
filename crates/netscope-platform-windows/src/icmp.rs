//! ICMP echo ping without admin rights via IPHLPAPI (IcmpSendEcho).

use netscope_core::models::{PerformanceResult, PerfKind};

pub fn ping(
    target: std::net::IpAddr,
    count: u32,
    timeout_ms: u32,
) -> netscope_core::Result<PerformanceResult> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{IcmpCloseHandle, IcmpCreateFile, ICMP_ECHO_REPLY, IcmpSendEcho};

    let ip4 = match target {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => {
            return Err(netscope_core::CoreError::Platform(
                "IcmpSendEcho supports IPv4 only; use tcp ping for IPv6".into(),
            ))
        }
    };

    // SAFETY: IcmpCreateFile allocates a valid handle.
    let handle = unsafe { IcmpCreateFile() };
    if handle == 0 {
        return Err(netscope_core::CoreError::Platform("IcmpCreateFile failed".into()));
    }

    const PAYLOAD: usize = 32;
    let payload = [0x4eu8; PAYLOAD]; // 'N' as in NetScope
    let mut reply = [0u8; std::mem::size_of::<ICMP_ECHO_REPLY>() + PAYLOAD + 64];
    let oct = ip4.octets();
    // IPAddr (win32) is an address in network byte order stored in a u32,
    // which on little-endian equals a reversed-octet numeric value.
    let addr = u32::from_le_bytes(oct);

    let mut rtts = Vec::<f64>::new();
    let mut lost = 0u32;
    let mut last_error: Option<String> = None;

    for _ in 0..count {
        // SAFETY: handle + payload + reply buffers sized correctly.
        let n = unsafe {
            IcmpSendEcho(
                handle,
                addr,
                payload.as_ptr().cast(),
                PAYLOAD as u16,
                std::ptr::null_mut(),
                reply.as_mut_ptr().cast(),
                reply.len() as u32,
                timeout_ms,
            )
        };
        if n == 0 {
            lost += 1;
            let err = std::io::Error::last_os_error();
            last_error = Some(err.to_string());
            continue;
        }
        // SAFETY: IcmpSendEcho reports 1 reply; layout guaranteed by win32.
        let r = unsafe { reply.as_ptr().cast::<ICMP_ECHO_REPLY>().as_ref().expect("reply") };
        let status = r.Status;
        if status_ok(status) {
            rtts.push(r.RoundTripTime as f64);
        } else {
            lost += 1;
            last_error = Some(format!("icmp status {status}"));
        }
    }
    // SAFETY: ownership transfers back to the os module here.
    unsafe {
        IcmpCloseHandle(handle);
    }

    if rtts.is_empty() {
        return Ok(PerformanceResult {
            kind: PerfKind::IcmpPing,
            samples: count,
            min_ms: None,
            avg_ms: None,
            max_ms: None,
            jitter_ms: None,
            loss_percent: Some(100.0),
            throughput_bytes_per_sec: None,
            error: last_error.or_else(|| Some("100% packet loss".into())),
        });
    }

    let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
    let lost_pct = lost as f64 / count.max(1) as f64 * 100.0;
    let jitter = if rtts.len() > 1 {
        rtts.windows(2)
            .map(|w| (w[0] - w[1]).abs())
            .sum::<f64>()
            / (rtts.len() - 1) as f64
    } else {
        0.0
    };

    Ok(PerformanceResult {
        kind: PerfKind::IcmpPing,
        samples: count,
        min_ms: Some(rtts.iter().cloned().fold(f64::MAX, f64::min)),
        avg_ms: Some(avg),
        max_ms: Some(rtts.iter().cloned().fold(f64::MIN, f64::max)),
        jitter_ms: Some(jitter),
        loss_percent: Some(lost_pct),
        throughput_bytes_per_sec: None,
        error: if lost_pct > 0.0 { Some(format!("loss {lost_pct:.0}%")) } else { last_error },
    })
}

/// Traceroute via IcmpSendEcho with a growing TTL. No administrative rights
/// are required (IcmpCreateFile is available to ordinary users).
pub fn traceroute(
    target: std::net::IpAddr,
    max_hops: u8,
    timeout_ms: u32,
) -> netscope_core::Result<netscope_core::models::TracerouteResult> {
    use netscope_core::models::{TracerouteHop, TracerouteResult};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, ICMP_ECHO_REPLY, IP_OPTION_INFORMATION,
    };

    let ip4 = match target {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => {
            return Err(netscope_core::CoreError::Platform(
                "IcmpSendEcho supports IPv4 only; traceroute for IPv6 needs Icmp6SendEcho".into(),
            ))
        }
    };
    // SAFETY: IcmpCreateFile allocates a valid handle.
    let handle = unsafe { IcmpCreateFile() };
    if handle == 0 {
        return Err(netscope_core::CoreError::Platform("IcmpCreateFile failed".into()));
    }
    const PAYLOAD: usize = 32;
    let payload = [0x4eu8; PAYLOAD];
    let addr = u32::from_le_bytes(ip4.octets());

    let mut hops = Vec::new();
    let mut reached = false;
    for ttl in 1..=max_hops.max(1) {
        let mut reply = [0u8; std::mem::size_of::<ICMP_ECHO_REPLY>() + PAYLOAD + 64];
        let options = IP_OPTION_INFORMATION {
            Ttl: ttl,
            Tos: 0,
            Flags: 0,
            OptionsSize: 0,
            OptionsData: std::ptr::null_mut(),
        };
        // SAFETY: buffers and option struct are correctly sized; handle valid.
        let n = unsafe {
            IcmpSendEcho(
                handle,
                addr,
                payload.as_ptr().cast(),
                PAYLOAD as u16,
                &options,
                reply.as_mut_ptr().cast(),
                reply.len() as u32,
                timeout_ms,
            )
        };
        let mut hop = TracerouteHop {
            ttl,
            ..Default::default()
        };
        if n > 0 {
            // SAFETY: IcmpSendEcho reports at least one reply in a valid layout.
            let r = unsafe { reply.as_ptr().cast::<ICMP_ECHO_REPLY>().as_ref().expect("reply") };
            let oct = r.Address.to_le_bytes();
            hop.address = Some(std::net::Ipv4Addr::from(oct).to_string());
            if status_ok(r.Status) {
                hop.rtt_ms = Some(r.RoundTripTime as f64);
            }
            if std::net::Ipv4Addr::from(oct) == ip4 {
                reached = true;
            }
        }
        hops.push(hop);
        if reached {
            break;
        }
    }
    // SAFETY: ownership transfers back to the OS.
    unsafe {
        IcmpCloseHandle(handle);
    }
    Ok(TracerouteResult {
        target: target.to_string(),
        hops,
        reached,
        error: None,
    })
}

/// IP_SUCCESS = 0
fn status_ok(status: u32) -> bool {
    status == 0
}
