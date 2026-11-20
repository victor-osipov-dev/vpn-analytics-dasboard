//! DNS probing:
//! - tiny DNS-over-UDP client measuring a concrete resolver (no OS cache);
//! - DoH-JSON control check (Cloudflare-style endpoints);
//! - hickory-based "system stack" path for comparison.
//! Mismatch between primary and control answers is flagged for the analyzer.

use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use netscope_core::models::{DnsAnswer, DnsResult, DnsStatus};
use serde::Deserialize;

const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;

#[derive(Debug, Clone)]
pub struct DnsRawReply {
    pub rcode: u16,
    pub answers: Vec<DnsAnswer>,
    /// TC flag from the header: the answer was truncated and should be retried
    /// over TCP/53.
    pub truncated: bool,
}

impl DnsRawReply {
    pub fn status(&self) -> DnsStatus {
        match self.rcode {
            0 if self.answers.is_empty() => DnsStatus::NoData,
            0 => DnsStatus::Ok,
            3 => DnsStatus::Nxdomain,
            2 => DnsStatus::Servfail,
            _ => DnsStatus::Error,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DnsWireError {
    #[error("bad query name: {0}")]
    BadQuery(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("short packet")]
    ShortPacket,
    #[error("reply id mismatch")]
    IdMismatch,
}

impl From<DnsWireError> for netscope_core::CoreError {
    fn from(e: DnsWireError) -> Self {
        if let DnsWireError::Io(ref io) = e {
            if io.kind() == std::io::ErrorKind::TimedOut {
                return netscope_core::CoreError::Timeout("dns query timed out".into());
            }
        }
        netscope_core::CoreError::Dns(e.to_string())
    }
}

/// Per-server DNS measurement: encodes one query, waits for a reply with the
/// matching id, parses A/AAAA answers.
pub struct DnsWireClient;

impl DnsWireClient {
    pub fn query(
        server: IpAddr,
        port: u16,
        name: &str,
        qtype: u16,
        timeout_ms: u64,
        bind_local: Option<IpAddr>,
    ) -> Result<DnsRawReply, DnsWireError> {
        if name.len() > 253
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
        {
            return Err(DnsWireError::BadQuery(name.to_string()));
        }
        let id: u16 = {
            use std::collections::hash_map::RandomState;
            use std::hash::{BuildHasher, Hasher};
            RandomState::new().build_hasher().finish() as u16
        };
        let payload = encode_query(id, name, qtype);
        let local: SocketAddr = SocketAddr::new(
            bind_local.unwrap_or_else(|| match server {
                IpAddr::V4(_) => "0.0.0.0".parse().unwrap(),
                IpAddr::V6(_) => "::".parse().unwrap(),
            }),
            0,
        );
        let sock = std::net::UdpSocket::bind(local)?;
        sock.set_read_timeout(Some(std::time::Duration::from_millis(timeout_ms)))?;
        sock.set_write_timeout(Some(std::time::Duration::from_millis(timeout_ms)))?;
        let sent = sock.send_to(&payload, SocketAddr::new(server, port))?;
        if sent < 12 {
            return Err(DnsWireError::ShortPacket);
        }
        let mut buf = [0u8; 8192];
        let (n, _from) = sock.recv_from(&mut buf).map_err(DnsWireError::Io)?;
        decode_reply(&buf[..n], id, qtype)
    }
}

fn encode_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut b = Vec::with_capacity(64);
    b.extend_from_slice(&id.to_be_bytes());
    b.extend([0x01, 0x00]); // RD
    b.extend([0, 1, 0, 0, 0, 0, 0, 0]); // 1 question
    for label in name.split('.').filter(|s| !s.is_empty()) {
        b.push(label.len() as u8);
        b.extend(label.as_bytes());
    }
    b.push(0);
    b.extend(qtype.to_be_bytes());
    b.extend([0, 1]); // IN
    b
}

fn decode_reply(buf: &[u8], expect_id: u16, qtype: u16) -> Result<DnsRawReply, DnsWireError> {
    if buf.len() < 12 {
        return Err(DnsWireError::ShortPacket);
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    if id != expect_id {
        return Err(DnsWireError::IdMismatch);
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let rcode = flags & 0x000f;
    let truncated = flags & 0x0200 != 0;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut answers = Vec::new();
    if an > 0 {
        // skip question section
        let Some((_name, after_q)) = skip_name(buf, 12) else {
            return Err(DnsWireError::ShortPacket);
        };
        let roff = after_q + 4; // QTYPE + QCLASS
        let mut off = roff;
        for _ in 0..an {
            let Some((nm, after_name)) = skip_name(buf, off) else {
                break;
            };
            if after_name + 10 > buf.len() {
                break;
            }
            let rt = u16::from_be_bytes([buf[after_name], buf[after_name + 1]]);
            let ttl = u32::from_be_bytes([
                buf[after_name + 4],
                buf[after_name + 5],
                buf[after_name + 6],
                buf[after_name + 7],
            ]);
            let rdlen = u16::from_be_bytes([buf[after_name + 8], buf[after_name + 9]]) as usize;
            let rd = after_name + 10;
            if rd + rdlen > buf.len() {
                break;
            }
            let rdata = &buf[rd..rd + rdlen];
            if rt == qtype {
                if let Ok(ip) = parse_rdata(rt, rdata) {
                    answers.push(DnsAnswer {
                        name: nm.unwrap_or_default(),
                        ip,
                        ttl,
                    });
                }
            }
            off = rd + rdlen;
        }
    }
    Ok(DnsRawReply {
        rcode,
        answers,
        truncated,
    })
}

fn parse_rdata(rt: u16, rdata: &[u8]) -> Result<String, ()> {
    match rt {
        QTYPE_A if rdata.len() == 4 => Ok(std::net::Ipv4Addr::new(
            rdata[0],
            rdata[1],
            rdata[2],
            rdata[3],
        )
        .to_string()),
        QTYPE_AAAA if rdata.len() == 16 => {
            let o: [u8; 16] = rdata.try_into().map_err(|_| ())?;
            Ok(std::net::Ipv6Addr::from(o).to_string())
        }
        _ => Err(()),
    }
}

/// Skip a (possibly compressed) domain name; returns (extracted name, offset
/// just after the name in the wire format).
fn skip_name(buf: &[u8], mut off: usize) -> Option<(Option<String>, usize)> {
    let mut out = String::new();
    let mut jumped = false;
    let mut end_off = off;
    let mut guard = 0;
    loop {
        guard += 1;
        if guard > 64 || off >= buf.len() {
            return None;
        }
        let len = buf[off];
        if len & 0xC0 == 0xC0 {
            if off + 2 > buf.len() {
                return None;
            }
            let ptr = ((len as usize & 0x3F) << 8) | buf[off + 1] as usize;
            if !jumped {
                end_off = off + 2;
            }
            off = ptr;
            jumped = true;
            continue;
        }
        if len == 0 {
            if !jumped {
                end_off = off + 1;
            }
            break;
        }
        let start = off + 1;
        let stop = (start + len as usize).min(buf.len());
        out.push_str(&String::from_utf8_lossy(&buf[start..stop]));
        out.push('.');
        off += len as usize + 1;
    }
    Some((Some(out.trim_end_matches('.').to_string()), end_off))
}

// ---------------------------------------------------------------------------
// High-level probe
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ServerSpec {
    pub ip: IpAddr,
    pub port: u16,
}

pub struct DnsProbeOptions<'a> {
    /// Servers to try in order; first successful answer is primary.
    pub servers: &'a [ServerSpec],
    pub name: &'a str,
    pub query_v6: bool,
    pub dns_timeout_ms: u64,
    pub bind_local: Option<IpAddr>,
    /// Control DoH JSON endpoint (e.g. `https://1.1.1.1/dns-query`).
    pub control_doh_url: &'a str,
    /// When set, run the hickory system-stack query too (recorded in control).
    pub use_system_stack: bool,
}

pub struct DnsProbe;

impl DnsProbe {
    pub async fn probe(opts: DnsProbeOptions<'_>) -> DnsResult {
        let qtype = if opts.query_v6 { QTYPE_AAAA } else { QTYPE_A };

        let mut result = DnsResult {
            status: DnsStatus::Error,
            resolver_kind: "direct_udp".into(),
            resolver_addr: None,
            duration_ms: None,
            answers_v4: vec![],
            answers_v6: vec![],
            rcode: None,
            truncated: false,
            control: None,
            mismatch: false,
            error: None,
        };

        for spec in opts.servers {
            let name = opts.name.to_string();
            let timeout = opts.dns_timeout_ms;
            let q = qtype;
            let bind = opts.bind_local;
            let ip = spec.ip;
            let port = spec.port;
            let started = Instant::now();
            let reply = tokio::task::spawn_blocking(move || {
                DnsWireClient::query(ip, port, &name, q, timeout, bind)
            })
            .await;
            match reply {
                Ok(Ok(rep)) => {
                    result.duration_ms = Some(started.elapsed().as_secs_f64() * 1000.0);
                    result.resolver_addr = Some(spec.ip.to_string());
                    result.rcode = Some(rcode_str(rep.rcode));
                    result.status = rep.status();
                    result.truncated = rep.truncated;
                    for a in rep.answers {
                        if a.ip.contains(':') {
                            result.answers_v6.push(a);
                        } else {
                            result.answers_v4.push(a);
                        }
                    }
                    break;
                }
                Ok(Err(e)) => {
                    result.status = if is_wire_timeout(&e) {
                        DnsStatus::Timeout
                    } else {
                        DnsStatus::Error
                    };
                    result.error = Some(e.to_string());
                }
                Err(join) => result.error = Some(format!("join: {join}")),
            }
        }

        if opts.use_system_stack {
            if let Some(sys) = system_stack_query(opts.name, qtype, opts.dns_timeout_ms).await {
                result.control = Some(Box::new(sys));
            }
        } else if !opts.control_doh_url.is_empty() {
            result.control = Some(Box::new(control_doh(opts).await));
        }

        // Control comparison: when the system-stack/DoH check succeeded, flag
        // mismatches between primary answers and the independent view.
        let control = result.control.clone();
        if let Some(ref ctrl) = control {
            DnsProbe::compare_and_flag(ctrl, &mut result);
        }
        result
    }

    /// Sets `primary.mismatch` when primary answers differ from control answers
    /// (only when the control check itself succeeded).
    pub fn compare_and_flag(control: &DnsResult, primary: &mut DnsResult) {
        if control.status != DnsStatus::Ok {
            // Control unavailable -> no reliable mismatch conclusion.
            return;
        }
        let collect = |v: &[DnsAnswer]| -> std::collections::BTreeSet<String> {
            v.iter().map(|a| a.ip.clone()).collect()
        };
        if primary.status != DnsStatus::Ok {
            primary.mismatch = true;
            return;
        }
        let mismatch_v4 = !control.answers_v4.is_empty()
            && collect(&control.answers_v4) != collect(&primary.answers_v4);
        let mismatch_v6 = !control.answers_v6.is_empty()
            && collect(&control.answers_v6) != collect(&primary.answers_v6);
        primary.mismatch = mismatch_v4 || mismatch_v6;
    }
}

fn is_wire_timeout(e: &DnsWireError) -> bool {
    matches!(e, DnsWireError::Io(ref io) if io.kind() == std::io::ErrorKind::TimedOut)
}

fn rcode_str(r: u16) -> String {
    match r {
        0 => "NOERROR".into(),
        1 => "FORMERR".into(),
        2 => "SERVFAIL".into(),
        3 => "NXDOMAIN".into(),
        4 => "NOTIMP".into(),
        5 => "REFUSED".into(),
        other => format!("RCODE{other}"),
    }
}

async fn control_doh(opts: DnsProbeOptions<'_>) -> DnsResult {
    let url = format!(
        "{}?name={name}&type={t}",
        opts.control_doh_url.trim_end_matches('/'),
        name = opts.name,
        t = if opts.query_v6 { "AAAA" } else { "A" }
    );
    let mut out = DnsResult {
        status: DnsStatus::Error,
        resolver_kind: "doh".into(),
        resolver_addr: None,
        duration_ms: None,
        answers_v4: vec![],
        answers_v6: vec![],
        rcode: None,
        truncated: false,
        control: None,
        mismatch: false,
        error: None,
    };
    let client = match reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_millis(opts.dns_timeout_ms * 2))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            out.error = Some(e.to_string());
            return out;
        }
    };
    let started = Instant::now();
    let resp = client
        .get(&url)
        .header("accept", "application/dns-json")
        .send()
        .await;
    out.duration_ms = Some(started.elapsed().as_secs_f64() * 1000.0);
    match resp {
        Ok(r) if r.status().is_success() => match r.json::<DohJson>().await {
            Ok(doh) => {
                out.rcode = Some(rcode_str(doh.Status));
                let has_answers = doh
                    .Answer
                    .as_ref()
                    .map(|v| !v.is_empty())
                    .unwrap_or(false);
                out.status = match doh.Status {
                    0 if has_answers => DnsStatus::Ok,
                    0 => DnsStatus::NoData,
                    3 => DnsStatus::Nxdomain,
                    2 => DnsStatus::Servfail,
                    _ => DnsStatus::Error,
                };
                for a in doh.Answer.unwrap_or_default() {
                    let ans = DnsAnswer {
                        name: opts.name.into(),
                        ip: a.data,
                        ttl: a.ttl,
                    };
                    if ans.ip.contains(':') {
                        out.answers_v6.push(ans);
                    } else {
                        out.answers_v4.push(ans);
                    }
                }
            }
            Err(e) => out.error = Some(format!("doh json: {e}")),
        },
        Ok(r) => out.error = Some(format!("doh http status {}", r.status())),
        Err(e) => out.error = Some(format!("doh: {e}")),
    }
    out
}

#[derive(Debug, Deserialize)]
struct DohAnswer {
    #[allow(dead_code)]
    #[serde(rename = "type")]
    r#type: u16,
    #[serde(rename = "TTL")]
    ttl: u32,
    data: String,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct DohJson {
    Status: u16,
    Answer: Option<Vec<DohAnswer>>,
}

/// hickory-driven query using the platform nameserver config. Returned as a
/// secondary view (the wire client against concrete servers stays primary).
async fn system_stack_query(name: &str, qtype: u16, timeout_ms: u64) -> Option<DnsResult> {
    let _ = qtype; // lookup_ip resolves both A and AAAA records
    let started = Instant::now();
    let mut out = DnsResult {
        status: DnsStatus::Error,
        resolver_kind: "system_stack".into(),
        resolver_addr: None,
        duration_ms: None,
        answers_v4: vec![],
        answers_v6: vec![],
        rcode: None,
        truncated: false,
        control: None,
        mismatch: false,
        error: None,
    };

    let dur = std::time::Duration::from_millis(timeout_ms);
    let lookup_opt = if let Ok(mut builder) = hickory_resolver::Resolver::builder_tokio() {
        let mut opts = hickory_resolver::config::ResolverOpts::default();
        opts.timeout = std::time::Duration::from_millis(timeout_ms);
        *builder.options_mut() = opts;
        if let Ok(resolver) = builder.build() {
            Some(tokio::time::timeout(dur, resolver.lookup_ip(name)).await)
        } else {
            None
        }
    } else {
        None
    };
    let lookup = match lookup_opt {
        Some(l) => l,
        None => {
            out.error = Some("hickory system stack unavailable".into());
            return Some(out);
        }
    };

    out.duration_ms = Some(started.elapsed().as_secs_f64() * 1000.0);
    match lookup {
        Ok(Ok(lookup_res)) => {
            out.status = DnsStatus::Ok;
            let mut any = false;
            for ip in lookup_res.iter() {
                any = true;
                let ans = DnsAnswer {
                    name: name.to_string(),
                    ip: ip.to_string(),
                    ttl: 0,
                };
                if ip.is_ipv4() {
                    out.answers_v4.push(ans);
                } else {
                    out.answers_v6.push(ans);
                }
            }
            if !any {
                out.status = DnsStatus::Error;
                out.error = Some("empty answer".into());
            } else {
                out.rcode = Some("NOERROR".into());
            }
        }
        Ok(Err(e)) => {
            let text = e.to_string();
            if text.to_lowercase().contains("timeout") || text.to_lowercase().contains("timed out") {
                out.status = DnsStatus::Timeout;
            } else if text.to_lowercase().contains("does not exist")
                || text.to_lowercase().contains("nxdomain")
                || text.to_lowercase().contains("no records")
                || text.contains("form err")
                || text.contains("no addresses")
            {
                out.status = DnsStatus::Nxdomain;
                out.rcode = Some("NXDOMAIN".into());
            } else {
                out.status = DnsStatus::Error;
                out.rcode = Some("SERVFAIL".into());
            }
            out.error = Some(text);
        }
        Err(join) => {
            out.status = DnsStatus::Timeout;
            out.error = Some(format!("system stack timeout: {join}"));
        }
    }
    Some(out)
}
