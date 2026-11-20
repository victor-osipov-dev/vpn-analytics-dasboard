//! Performance probe: TCP-based RTT/jitter/loss estimation and a capped
//! throughput test through explicit endpoints only (user- or schedule-driven).

use std::net::IpAddr;
use std::time::Instant;

use netscope_core::models::{PerformanceResult, PerfKind, TracerouteResult};

#[derive(Debug, Clone, Copy)]
pub struct PerfOptions {
    /// Number of TCP connection samples.
    pub samples: u32,
    pub connect_timeout_ms: u64,
    /// Small pause between samples.
    pub spacing_ms: u64,
}

impl Default for PerfOptions {
    fn default() -> Self {
        Self {
            samples: 5,
            connect_timeout_ms: 4000,
            spacing_ms: 120,
        }
    }
}

pub struct PerformanceProbe;

impl PerformanceProbe {
    /// Repeated TCP connects -> RTT distribution, jitter (successive mean
    /// deviation), observed failure rate. Packet loss in the strict sense is
    /// not measurable without ICMP authority; replaced with an honest
    /// "connect failure rate" which is reported as loss_percent.
    pub async fn tcp_rtt(
        ip: IpAddr,
        port: u16,
        opts: PerfOptions,
    ) -> PerformanceResult {
        let mut rtts = vec![];
        let mut failures = 0u32;
        let mut last_error: Option<String> = None;

        for i in 0..opts.samples {
            if i > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(opts.spacing_ms)).await;
            }
            let started = Instant::now();
            let addr = std::net::SocketAddr::new(ip, port);
            let dur = std::time::Duration::from_millis(opts.connect_timeout_ms);
            let res = tokio::time::timeout(dur, tokio::net::TcpStream::connect(addr)).await;
            match res {
                Ok(Ok(_stream)) => {
                    rtts.push(started.elapsed().as_secs_f64() * 1000.0);
                }
                Ok(Err(e)) => {
                    failures += 1;
                    last_error = Some(e.to_string());
                }
                Err(_) => {
                    failures += 1;
                    last_error = Some("timeout".into());
                }
            }
        }

        if rtts.is_empty() {
            return PerformanceResult {
                kind: PerfKind::TcpRtt,
                samples: opts.samples,
                min_ms: None,
                avg_ms: None,
                max_ms: None,
                jitter_ms: None,
                loss_percent: Some(100.0),
                throughput_bytes_per_sec: None,
                error: last_error.or_else(|| Some("all connect attempts failed".into())),
            };
        }

        let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
        let jitter = if rtts.len() > 1 {
            rtts.windows(2)
                .map(|w| (w[0] - w[1]).abs())
                .sum::<f64>()
                / (rtts.len() - 1) as f64
        } else {
            0.0
        };

        let loss = failures as f64 / opts.samples as f64 * 100.0;
        PerformanceResult {
            kind: PerfKind::TcpRtt,
            samples: opts.samples,
            min_ms: Some(rtts.iter().cloned().fold(f64::MAX, f64::min)),
            avg_ms: Some(avg),
            max_ms: Some(rtts.iter().cloned().fold(f64::MIN, f64::max)),
            jitter_ms: Some(jitter),
            loss_percent: Some(loss),
            throughput_bytes_per_sec: None,
            error: if loss > 0.0 || last_error.is_some() {
                last_error
            } else {
                None
            },
        }
    }

    /// ICMP ping through the platform module (Windows, IPHLPAPI, no admin).
    pub async fn icmp(ip: IpAddr, count: u32, timeout_ms: u32) -> PerformanceResult {
        let res = tokio::task::spawn_blocking(move || {
            netscope_platform_windows_probe(ip, count, timeout_ms)
        })
        .await;
        match res {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => PerformanceResult {
                kind: PerfKind::IcmpPing,
                samples: count,
                min_ms: None,
                avg_ms: None,
                max_ms: None,
                jitter_ms: None,
                loss_percent: None,
                throughput_bytes_per_sec: None,
                error: Some(e.to_string()),
            },
            Err(join) => PerformanceResult {
                kind: PerfKind::IcmpPing,
                samples: count,
                min_ms: None,
                avg_ms: None,
                max_ms: None,
                jitter_ms: None,
                loss_percent: None,
                throughput_bytes_per_sec: None,
                error: Some(format!("join: {join}")),
            },
        }
    }

    /// Traceroute through the platform ICMP implementation (Windows only).
    pub async fn traceroute(ip: IpAddr, max_hops: u8, timeout_ms: u32) -> TracerouteResult {
        let res = tokio::task::spawn_blocking(move || platform_traceroute(ip, max_hops, timeout_ms)).await;
        match res {
            Ok(Ok(result)) => result,
            Ok(Err(e)) => TracerouteResult {
                target: ip.to_string(),
                error: Some(e.to_string()),
                ..Default::default()
            },
            Err(join) => TracerouteResult {
                target: ip.to_string(),
                error: Some(format!("join: {join}")),
                ..Default::default()
            },
        }
    }

    /// Throughput via GET of a controlled endpoint with a hard byte cap.
    /// Runs only when the user or the schedule explicitly asks for it.
    pub async fn download(
        client: reqwest::Client,
        url: &str,
        max_bytes: u64,
    ) -> PerformanceResult {
        let started = Instant::now();
        let mut downloaded = 0u64;
        let response = match client.get(url).send().await {
            Ok(r) => r,
            Err(e) => {
                return PerformanceResult {
                    kind: PerfKind::Download,
                    samples: 1,
                    min_ms: None,
                    avg_ms: None,
                    max_ms: None,
                    jitter_ms: None,
                    loss_percent: None,
                    throughput_bytes_per_sec: None,
                    error: Some(e.to_string()),
                }
            }
        };
        let total_dur_ms_response = started.elapsed().as_secs_f64() * 1000.0;
        let _ = total_dur_ms_response;
        let mut bytes_stream = response;
        let mut loop_count = 100_000u64;
        while downloaded < max_bytes {
            loop_count -= 1;
            if loop_count == 0 {
                break;
            }
            let next = bytes_stream.chunk().await;
            match next {
                Ok(Some(chunk)) => {
                    let remaining = max_bytes - downloaded;
                    let take = chunk.len().min(remaining as usize);
                    downloaded += take as u64;
                    if downloaded >= max_bytes {
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    let elapsed = started.elapsed().as_secs_f64();
                    if downloaded > 0 {
                        return PerformanceResult {
                            kind: PerfKind::Download,
                            samples: 1,
                            min_ms: None,
                            avg_ms: None,
                            max_ms: None,
                            jitter_ms: None,
                            loss_percent: None,
                            throughput_bytes_per_sec: Some(downloaded as f64 / elapsed),
                            error: Some(format!("stream end: {e}")),
                        };
                    }
                    return PerformanceResult {
                        kind: PerfKind::Download,
                        samples: 1,
                        min_ms: None,
                        avg_ms: None,
                        max_ms: None,
                        jitter_ms: None,
                        loss_percent: None,
                        throughput_bytes_per_sec: None,
                        error: Some(e.to_string()),
                    };
                }
            }
        }
        let elapsed = started.elapsed().as_secs_f64();
        if downloaded == 0 || elapsed <= 0.001 {
            return PerformanceResult {
                kind: PerfKind::Download,
                samples: 1,
                min_ms: None,
                avg_ms: None,
                max_ms: None,
                jitter_ms: None,
                loss_percent: None,
                throughput_bytes_per_sec: None,
                error: Some("no measurable download".into()),
            };
        }
        PerformanceResult {
            kind: PerfKind::Download,
            samples: 1,
            min_ms: None,
            avg_ms: None,
            max_ms: None,
            jitter_ms: None,
            loss_percent: None,
            throughput_bytes_per_sec: Some(downloaded as f64 / elapsed),
            error: None,
        }
    }
}

#[cfg(windows)]
fn platform_traceroute(
    ip: IpAddr,
    max_hops: u8,
    timeout_ms: u32,
) -> Result<TracerouteResult, netscope_core::CoreError> {
    netscope_platform_windows::icmp::traceroute(ip, max_hops, timeout_ms)
}

#[cfg(not(windows))]
fn platform_traceroute(
    ip: IpAddr,
    _max_hops: u8,
    _timeout_ms: u32,
) -> Result<TracerouteResult, netscope_core::CoreError> {
    Err(netscope_core::CoreError::Platform(format!(
        "traceroute requires Windows (target {ip})"
    )))
}

/// Thin wrapper: platform ICMP is only available on Windows.
fn netscope_platform_windows_probe(
    ip: IpAddr,
    count: u32,
    timeout_ms: u32,
) -> Result<netscope_core::models::PerformanceResult, netscope_core::CoreError> {
    #[cfg(windows)]
    {
        netscope_platform_windows::icmp::ping(ip, count, timeout_ms)
    }
    #[cfg(not(windows))]
    {
        let _ = ip;
        let _ = count;
        let _ = timeout_ms;
        Err(netscope_core::CoreError::Platform(
            "icmp requires Windows".into(),
        ))
    }
}
