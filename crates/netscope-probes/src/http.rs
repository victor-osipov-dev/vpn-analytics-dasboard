//! HTTP probe: status, TTFB, redirects, selected headers, body fingerprint
//! with size cap. Every regular probe goes through reqwest with rustls and
//! validation on. Redirects to private/loopback addresses are refused.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use netscope_core::models::{
    ContentFingerprint, HttpResult, HttpStatus, RouteMode,
};
use sha2::{Digest, Sha256};

pub struct HttpProbe;

/// How to construct the HTTP client for a given route.
#[derive(Clone)]
pub struct HttpClientRecipe {
    /// SOCKS/HTTP proxy url, e.g. `socks5h://user:pass@host:port` or
    /// `http://host:port`. Empty => no explicit proxy.
    pub proxy_url: String,
    /// Disable system environmental proxy discovery (DIRECT).
    pub no_proxy_env: bool,
    /// Local bind (DIRECT engine interface pinning).
    pub local_address: Option<std::net::IpAddr>,
    /// http -> resolve pins: manual IP overrides.
    pub resolve_overrides: Vec<(String, String)>,
    /// Total body download cap.
    pub body_limit_bytes: u64,
    /// Max redirects.
    pub max_redirects: u32,
    /// Total time budget.
    pub timeout_ms: u64,
    /// User-Agent.
    pub user_agent: String,
    /// Refuse redirects to private/loopback/link-local hosts (SSRF guard).
    pub block_private_redirects: bool,
    /// Receives every redirect target in order when present.
    pub redirect_log: Option<Arc<Mutex<Vec<String>>>>,
}

impl Default for HttpClientRecipe {
    fn default() -> Self {
        Self {
            proxy_url: String::new(),
            no_proxy_env: false,
            local_address: None,
            resolve_overrides: vec![],
            body_limit_bytes: 64 * 1024,
            max_redirects: 5,
            timeout_ms: 12_000,
            user_agent: "NetScope/1.0".into(),
            block_private_redirects: true,
            redirect_log: None,
        }
    }
}

impl HttpClientRecipe {
    pub fn build_client(&self) -> Result<reqwest::Client, netscope_core::CoreError> {
        let log = self.redirect_log.clone();
        let block_private = self.block_private_redirects;
        let mut builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(self.timeout_ms))
            .redirect(reqwest::redirect::Policy::custom(policy_redirects(
                self.max_redirects.min(10),
                log,
                block_private,
            )))
            .user_agent(self.user_agent.clone());

        if let Some(ip) = &self.local_address {
            builder = builder.local_address(*ip);
        }

        if self.no_proxy_env || self.proxy_url.is_empty() {
            builder = builder.no_proxy();
        }
        if !self.proxy_url.is_empty() {
            let proxy = parse_proxy(&self.proxy_url, RouteMode::CustomProxy)?;
            builder = builder.proxy(proxy);
        }
        for (host, ip) in &self.resolve_overrides {
            let ip: std::net::IpAddr = ip.parse().map_err(|e| {
                netscope_core::CoreError::Config(format!("bad resolve override ip: {e}"))
            })?;
            builder = builder.resolve(host, std::net::SocketAddr::new(ip, 0));
        }

        builder.build().map_err(|e| netscope_core::CoreError::Http(e.to_string()))
    }
}

fn policy_redirects(
    max_redirects: u32,
    log: Option<Arc<Mutex<Vec<String>>>>,
    block_private: bool,
) -> impl Fn(reqwest::redirect::Attempt) -> reqwest::redirect::Action + Send + Sync {
    move |attempt: reqwest::redirect::Attempt| {
        use reqwest::redirect::Attempt;
        let next = attempt.url().clone();
        if let Some(log) = &log {
            if let Ok(mut list) = log.lock() {
                list.push(next.to_string());
            }
        }
        if block_private && unsafe_redirect_target(&next) {
            return attempt.error("redirect to a private/loopback address is not allowed");
        }
        match attempt.previous().len() as u32 {
            n if n >= max_redirects => Attempt::stop(attempt),
            _ => Attempt::follow(attempt),
        }
    }
}

/// True when a redirect target must be refused: non-http(s) scheme or an
/// address in a private/loopback/link-local range.
pub fn unsafe_redirect_target(url: &reqwest::Url) -> bool {
    if !matches!(url.scheme(), "http" | "https") {
        return true;
    }
    if let Some(host) = url.host_str() {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return forbidden_ip(&ip);
        }
    }
    false
}

pub fn forbidden_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unicast_link_local()
                || v6.is_unique_local()
                || v6.is_multicast()
        }
    }
}

/// Builds a reqwest proxy from a URL string with scheme validation.
pub fn parse_proxy(
    url: &str,
    _mode: RouteMode,
) -> Result<reqwest::Proxy, netscope_core::CoreError> {
    let p = reqwest::Proxy::all(url)
        .map_err(|e| netscope_core::CoreError::Config(format!("proxy url: {e}")))?;
    Ok(p)
}

pub struct HttpOptions<'a> {
    pub url: &'a str,
    pub recipe: HttpClientRecipe,
    /// String fragments (lowercase) that mark a response body as a blocking
    /// page; supplied from settings so the list is user-editable.
    pub block_page_patterns: &'a [String],
}

impl HttpProbe {
    pub async fn probe(opts: HttpOptions<'_>) -> HttpResult {
        let started = Instant::now();
        let mut recipe = opts.recipe;
        let redirect_log = Arc::new(Mutex::new(Vec::<String>::new()));
        recipe.redirect_log = Some(redirect_log.clone());

        let client = match recipe.build_client() {
            Ok(c) => c,
            Err(e) => {
                return HttpResult {
                    status: HttpStatus::Error,
                    total_ms: Some(started.elapsed().as_secs_f64() * 1000.0),
                    error: Some(e.to_string()),
                    ..Default::default()
                };
            }
        };

        // Initial URL is also validated before any request leaves the device.
        if let Ok(parsed) = reqwest::Url::parse(opts.url) {
            if recipe.block_private_redirects && unsafe_redirect_target(&parsed) {
                return HttpResult {
                    status: HttpStatus::Error,
                    total_ms: Some(started.elapsed().as_secs_f64() * 1000.0),
                    error: Some("refusing to probe a private/loopback address".into()),
                    ..Default::default()
                };
            }
        }

        let request_url = opts.url.to_string();
        let ttfb_before = started;

        let response = match client.get(request_url.clone()).send().await {
            Ok(r) => r,
            Err(e) => {
                let elapsed = started.elapsed().as_secs_f64() * 1000.0;
                let status = reqwest_err_status(&e);
                return HttpResult {
                    status,
                    total_ms: Some(elapsed),
                    error: Some(e.to_string()),
                    ..Default::default()
                };
            }
        };
        let ttfb_ms = ttfb_before.elapsed().as_secs_f64() * 1000.0;

        let status_code = response.status();
        let version = format!("{:?}", response.version());
        let final_url = response.url().to_string();
        let remote_addr = response.remote_addr().map(|a| a.to_string());

        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        };
        let server = header("server");
        let content_type = header("content-type");
        let date = header("date");
        let cf_ray = header("cf-ray");

        let mut chain = vec![request_url];
        if let Ok(list) = redirect_log.lock() {
            chain.extend(list.iter().cloned());
        }
        if final_url != chain[chain.len() - 1] {
            chain.push(final_url.clone());
        }

        // Body with hard cap
        let mut body_bytes = 0u64;
        let mut body_hasher = Sha256::new();
        let mut title: Option<String> = None;
        let mut first_chunk = true;
        let mut response = response;
        let mut body_text_preview: Vec<u8> = vec![];

        match response.chunk().await {
            Ok(mut chunk) => {
                loop {
                    match chunk {
                        Some(bytes) => {
                            let remaining = recipe.body_limit_bytes.saturating_sub(body_bytes);
                            let take = remaining.min(bytes.len() as u64) as usize;
                            if take > 0 {
                                body_hasher.update(&bytes[..take]);
                                if first_chunk {
                                    body_text_preview.extend_from_slice(&bytes[..take.min(65536)]);
                                    first_chunk = false;
                                    if title.is_none() {
                                        title = extract_title(&body_text_preview);
                                    }
                                }
                            }
                            body_bytes += bytes.len() as u64;
                            if body_bytes > recipe.body_limit_bytes {
                                break;
                            }
                        }
                        None => break,
                    }
                    chunk = match response.chunk().await {
                        Ok(c) => c,
                        Err(_e) => break,
                    };
                }
            }
            Err(e) => {
                let elapsed = started.elapsed().as_secs_f64() * 1000.0;
                return HttpResult {
                    status: HttpStatus::ConnectionError,
                    final_url: Some(final_url),
                    response_status: Some(status_code.as_u16()),
                    ttfb_ms: Some(ttfb_ms),
                    total_ms: Some(elapsed),
                    body_bytes: Some(body_bytes),
                    http_version: Some(version),
                    redirect_chain: chain,
                    server,
                    content_type,
                    date,
                    cf_ray,
                    remote_addr,
                    error: Some(format!("body read: {e}")),
                    ..Default::default()
                };
            }
        }

        let digest = Some(hex_encode(body_hasher.finalize().as_slice()));
        let preview_text = String::from_utf8_lossy(&body_text_preview).to_lowercase();
        let block_hit = opts
            .block_page_patterns
            .iter()
            .any(|pat| !pat.is_empty() && preview_text.contains(&pat.to_lowercase()));

        let codes = status_code.as_u16();
        let mut status = if codes >= 400 {
            HttpStatus::HttpError
        } else if codes >= 300 {
            HttpStatus::Redirected
        } else {
            HttpStatus::Ok
        };
        if block_hit {
            status = HttpStatus::BlockPage;
        }

        let total = started.elapsed().as_secs_f64() * 1000.0;
        let group = if block_hit {
            "block_page"
        } else {
            status_group(codes)
        };

        HttpResult {
            status,
            final_url: Some(final_url),
            response_status: Some(codes),
            status_group: Some(group.into()),
            ttfb_ms: Some(ttfb_ms),
            total_ms: Some(total),
            body_bytes: Some(body_bytes),
            http_version: Some(version),
            redirect_chain: chain,
            server: server.clone(),
            content_type,
            date,
            cf_ray,
            remote_addr,
            fingerprint: Some(ContentFingerprint {
                body_sha256: digest,
                title,
                server_header: server.clone(),
                true_asn_hint: None,
                body_preview: if body_text_preview.is_empty() {
                    None
                } else {
                    Some(String::from_utf8_lossy(&body_text_preview).to_string())
                },
            }),
            block_page_matched: block_hit,
            error: None,
        }
    }
}

fn status_group(code: u16) -> &'static str {
    match code {
        200..=299 => "ok",
        300..=399 => "redirect",
        400..=499 => "client_error",
        500..=599 => "server_error",
        _ => "other",
    }
}

fn reqwest_err_status(e: &reqwest::Error) -> HttpStatus {
    let text = e.to_string().to_lowercase();
    if text.contains("timed out") || text.contains("timeout") {
        HttpStatus::Timeout
    } else if text.contains("certificate") {
        HttpStatus::TlsError
    } else {
        HttpStatus::ConnectionError
    }
}

fn extract_title(bytes: &[u8]) -> Option<String> {
    let hay = String::from_utf8_lossy(bytes);
    let lower_start = hay.to_ascii_lowercase();
    let start = lower_start.find("<title")?;
    let rest = &hay[start..];
    let close = rest.find('>')?;
    let end = rest[close..].find("</title>")?;
    Some(rest[close + 1..close + end].trim().to_string())
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
