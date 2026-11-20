//! NetScope probe engine: DNS / TCP / TLS / HTTP / performance measurement.
//! Each probe runs with explicit timeout + explicit route binding so the
//! measurement is attributable to a concrete network route.

pub mod deep;
pub mod dns;
pub mod http;
pub mod tcp;
pub mod tls;
pub mod perf;

pub use dns::DnsProbe;
pub use http::HttpProbe;
pub use tcp::TcpProbe;
pub use tls::TlsProbe;
pub use perf::PerformanceProbe;

/// Structure with all timeouts pulled from AppSettings.
#[derive(Debug, Clone, Copy)]
pub struct ProbeTimeouts {
    pub dns_ms: u64,
    pub connect_ms: u64,
    pub http_ms: u64,
}

impl Default for ProbeTimeouts {
    fn default() -> Self {
        Self {
            dns_ms: 4000,
            connect_ms: 6000,
            http_ms: 12_000,
        }
    }
}
