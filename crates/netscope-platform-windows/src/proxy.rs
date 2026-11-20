//! System proxy configuration from the registry.
//!
//! PAC/WPAD: we detect `AutoConfigURL` but do not evaluate PAC rules. The
//! limitation is surfaced to the user in the UI and stored in the model
//! (`pac_supported = false`).

use netscope_core::models::{ProxyEndpoint, ProxyKind, SystemProxyConfig};

const INTERNET_SETTINGS: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

/// Read HKCU `Internet Settings` and build the normalized proxy config.
pub fn system_proxy() -> netscope_core::Result<SystemProxyConfig> {
    Ok(system_proxy_impl())
}

pub(crate) fn system_proxy_impl() -> SystemProxyConfig {
    let mut cfg = SystemProxyConfig::default();

    let key = match winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
        .open_subkey(INTERNET_SETTINGS)
    {
        Ok(k) => k,
        Err(_) => return cfg,
    };

    let enabled: Option<u32> = key.get_value("ProxyEnable").ok();
    let raw: Option<String> = key.get_value("ProxyServer").ok();
    let bypass: Option<String> = key.get_value("ProxyOverride").ok();
    let pac: Option<String> = key.get_value("AutoConfigURL").ok();

    if let Some(url) = pac.as_deref().filter(|s| !s.trim().is_empty()) {
        cfg.pac_url = Some(url.to_string());
        // PAC detected but not evaluated: HTTP client cannot use it yet.
    }

    cfg.enabled = enabled.map(|e| e != 0).unwrap_or(false);
    if cfg.enabled {
        if let Some(raw) = raw.filter(|s| !s.trim().is_empty()) {
            let mut http: Option<String> = None;
            let mut https: Option<String> = None;
            let mut socks: Option<String> = None;
            let mut single: Option<String> = None;
            let mut has_scheme = false;
            for part in raw.split(';') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                let (scheme, value) = match part.split_once('=') {
                    Some((s, v)) => {
                        has_scheme = true;
                        (s.to_ascii_lowercase(), v.to_string())
                    }
                    None => {
                        single = Some(part.to_string());
                        continue;
                    }
                };
                match scheme.as_str() {
                    "http" | "http=" => http = Some(value),
                    "https" | "secure" => https = Some(value),
                    "socks" => socks = Some(value),
                    _ => {}
                }
            }
            if !has_scheme {
                // Single "host:port" applies to all protocols (HTTP default).
                if let Some(v) = single {
                    http = Some(v.clone());
                    https = Some(v.clone());
                }
            }
            cfg.http_proxy = http.and_then(parse_endpoint);
            cfg.https_proxy = https.and_then(parse_endpoint);
            if let Some(v) = socks.and_then(|v| parse_endpoint(v)) {
                cfg.socks = Some(ProxyEndpoint {
                    kind: ProxyKind::Socks5,
                    host: v.host,
                    port: v.port,
                    username: v.username,
                });
            }
        }
    }

    if let Some(b) = bypass.filter(|s| !s.trim().is_empty()) {
        cfg.bypass_list = b
            .split(';')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
    }

    cfg
}

fn parse_endpoint(v: String) -> Option<ProxyEndpoint> {
    let parsed: Option<(String, u16)> = match v.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => Some((h.trim_start_matches('[').trim_end_matches(']').to_string(), port)),
            Err(_) => proxy_default_port(&v).map(|port| (v.clone(), port)),
        },
        None => proxy_default_port(&v).map(|port| (v.clone(), port)),
    };
    let Some((host, port)) = parsed else {
        return None;
    };
    if host.is_empty() {
        return None;
    }
    Some(ProxyEndpoint {
        kind: ProxyKind::Http,
        host,
        port,
        username: None,
    })
}

fn proxy_default_port(_h: &str) -> Option<u16> {
    Some(8080)
}
