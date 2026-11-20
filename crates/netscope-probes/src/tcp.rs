//! TCP connect probe with explicit timeout and optional local-bind.
//! Classifies the network-level failure kind from the connection attempt.

use std::net::{IpAddr, SocketAddr};

use netscope_core::models::{TcpResult, TcpStatus};

pub struct TcpProbe;

/// Destination after optional DNS resolution.
#[derive(Debug, Clone)]
pub struct TcpTarget {
    pub hostname: String,
    pub ip: IpAddr,
    pub port: u16,
}

pub struct TcpOptions {
    pub connect_timeout_ms: u64,
    /// Bind the socket to a concrete local address so the outbound interface
    /// is known (physical vs tunnel interface distinction).
    pub bind_local: Option<IpAddr>,
}

impl TcpProbe {
    pub async fn connect(target: TcpTarget, opts: TcpOptions) -> TcpResult {
        let started = std::time::Instant::now();
        let dest = SocketAddr::new(target.ip, target.port);
        let bound = opts.bind_local.is_some();

        let attempt: Result<tokio::net::TcpStream, std::io::Error> =
            match (opts.bind_local, dest) {
                (Some(local), SocketAddr::V4(dest_v4)) if local.is_ipv4() => {
                    tokio::time::timeout(
                        std::time::Duration::from_millis(opts.connect_timeout_ms),
                        try_connect_v4(local, dest_v4),
                    )
                    .await
                    .unwrap_or_else(|_| Err(timeout_err()))
                }
                (Some(local), SocketAddr::V6(dest_v6)) if local.is_ipv6() => {
                    tokio::time::timeout(
                        std::time::Duration::from_millis(opts.connect_timeout_ms),
                        try_connect_v6(local, dest_v6),
                    )
                    .await
                    .unwrap_or_else(|_| Err(timeout_err()))
                }
                (Some(_), _) => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "local bind family does not match target family",
                )),
                (None, d) => {
                    let dur =
                        std::time::Duration::from_millis(opts.connect_timeout_ms);
                    tokio::time::timeout(dur, tokio::net::TcpStream::connect(d))
                        .await
                        .unwrap_or_else(|_| Err(timeout_err()))
                }
            };

        match attempt {
            Ok(stream) => {
                let elapsed = started.elapsed().as_secs_f64() * 1000.0;
                TcpResult {
                    status: TcpStatus::Connected,
                    connect_ms: Some(elapsed),
                    local_address: stream.local_addr().ok().map(|l| l.to_string()),
                    remote_address: Some(dest.to_string()),
                    interface_bound: bound,
                    error: None,
                }
            }
            Err(e) => classify_io_err(e, started, dest, bound),
        }
    }
}

async fn try_connect_v4(
    local: IpAddr,
    dest: std::net::SocketAddrV4,
) -> Result<tokio::net::TcpStream, std::io::Error> {
    let local_v4 = match local {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return Err(family_err()),
    };
    let sock = tokio::net::TcpSocket::new_v4()?;
    sock.bind(SocketAddr::new(IpAddr::V4(local_v4), 0))?;
    sock.connect(SocketAddr::V4(dest)).await
}

async fn try_connect_v6(
    local: IpAddr,
    dest: std::net::SocketAddrV6,
) -> Result<tokio::net::TcpStream, std::io::Error> {
    let local_v6 = match local {
        IpAddr::V6(v6) => v6,
        IpAddr::V4(_) => return Err(family_err()),
    };
    let sock = tokio::net::TcpSocket::new_v6()?;
    sock.bind(SocketAddr::new(IpAddr::V6(local_v6), 0))?;
    sock.connect(SocketAddr::V6(dest)).await
}

fn family_err() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "bind family mismatch",
    )
}

fn timeout_err() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("connect timed out"),
    )
}

fn classify_io_err(
    e: std::io::Error,
    started: std::time::Instant,
    dest: SocketAddr,
    bound: bool,
) -> TcpResult {
    let ms = Some(started.elapsed().as_secs_f64() * 1000.0);
    TcpResult {
        status: code_or_kind(&e),
        connect_ms: ms,
        local_address: None,
        remote_address: Some(dest.to_string()),
        interface_bound: bound,
        error: Some(e.to_string()),
    }
}

fn code_or_kind(e: &std::io::Error) -> TcpStatus {
    if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock {
        return TcpStatus::Timeout;
    }
    match e.raw_os_error().unwrap_or(0) {
        10060 | 110 => TcpStatus::Timeout,
        10061 | 111 => TcpStatus::Refused,
        10054 | 104 => TcpStatus::Reset,
        10051 | 10065 | 101 | 113 => TcpStatus::Unreachable,
        10013 | 13 => TcpStatus::Blocked,
        _ => match e.kind() {
            std::io::ErrorKind::ConnectionRefused => TcpStatus::Refused,
            std::io::ErrorKind::ConnectionReset => TcpStatus::Reset,
            std::io::ErrorKind::ConnectionAborted => TcpStatus::Reset,
            std::io::ErrorKind::PermissionDenied => TcpStatus::Blocked,
            std::io::ErrorKind::TimedOut => TcpStatus::Timeout,
            _ => TcpStatus::Error,
        },
    }
}
