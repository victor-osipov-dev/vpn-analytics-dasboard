//! Egress identity probing: HTTPS checks through configured endpoints derive
//! external IP / confidence per route. Multiple independent endpoints are
//! used; literal-IP endpoints skip DNS entirely (no DNS-view confusion).

use std::net::IpAddr;

use netscope_core::models::{EgressIdentity, RouteConfidence};
use netscope_probes::http::{HttpClientRecipe, HttpOptions, HttpProbe};
use tracing::debug;

/// One egress endpoint, e.g. `https://1.1.1.1/cdn-cgi/trace` (literal IP) or
/// `https://ipv4.icanhazip.com` (host resolved via normal DNS).
#[derive(Debug, Clone)]
pub struct EgressProbeTarget {
    pub url: String,
    /// Literal-IP endpoints skip DNS entirely.
    pub literal_ip: bool,
    pub is_v6: bool,
}

impl EgressProbeTarget {
    pub fn from_url(url: &str) -> Option<Self> {
        let (scheme, rest) = url.split_once("://")?;
        if scheme != "https" && scheme != "http" {
            return None;
        }
        let host_part = rest.split('/').next()?;
        let host = if host_part.starts_with('[') {
            // [IPv6] or [IPv6]:port form
            host_part
                .trim_start_matches('[')
                .split(']')
                .next()?
        } else {
            host_part.split(':').next()?
        };
        let ip: Option<IpAddr> = host.parse().ok();
        let is_v6 = matches!(ip, Some(IpAddr::V6(_)));
        Some(Self {
            url: url.to_string(),
            literal_ip: ip.is_some(),
            is_v6,
        })
    }
}

/// Run the trace at all configured endpoints, keep the first works-one-per
/// family. Compiling pattern support: Cloudflare trace (`ip=`) and icanhazip.
pub async fn egress_probe(
    targets: Vec<EgressProbeTarget>,
    recipe: HttpClientRecipe,
    notes: String,
    lookup_asn: bool,
) -> EgressIdentity {
    let mut identity = EgressIdentity {
        confidence: RouteConfidence::None,
        reason: None,
        source_endpoints: vec![],
        ..Default::default()
    };
    identity.reason = Some(notes);

    let mut ip_v4: Option<String> = None;
    let mut ip_v6: Option<String> = None;

    for target in targets.iter().filter(|t| !t.is_v6).take(4) {
        if ip_v4.is_some() {
            break;
        }
        debug!("egress probe v4: {}", target.url);
        let opts = HttpOptions {
            url: &target.url,
            recipe: recipe.clone(),
            block_page_patterns: &[],
        };
        let res = HttpProbe::probe(opts).await;
        if !res.status.is_ok() {
            continue;
        }
        identity.source_endpoints.push(target.url.clone());
        if let Some(fp) = &res.fingerprint {
            if let Some(body) = &fp.body_preview {
                if let Some(extracted) = parse_external_ip(body) {
                    ip_v4 = Some(extracted);
                }
            }
        }
    }

    for target in targets.iter().filter(|t| t.is_v6).take(2) {
        if ip_v6.is_some() {
            break;
        }
        debug!("egress probe v6: {}", target.url);
        let opts = HttpOptions {
            url: &target.url,
            recipe: recipe.clone(),
            block_page_patterns: &[],
        };
        let res = HttpProbe::probe(opts).await;
        if !res.status.is_ok() {
            continue;
        }
        identity.source_endpoints.push(target.url.clone());
        if let Some(fp) = &res.fingerprint {
            if let Some(body) = &fp.body_preview {
                if let Some(extracted) = parse_external_ip(body) {
                    ip_v6 = Some(extracted);
                }
            }
        }
    }

    identity.external_ip = ip_v4.clone();
    identity.external_ipv6 = ip_v6;
    if lookup_asn {
        if let Some(ip) = ip_v4.or_else(|| identity.external_ipv6.clone()) {
            if let Some(asn) = lookup_asn_ripe(&ip).await {
                identity.asn = Some(asn);
                identity.asn_source = Some("RIPEstat".into());
            }
        }
    }
    if identity.external_ip.is_none() && identity.external_ipv6.is_none() {
        identity.reason = Some(
            "egress endpoints did not return a usable answer".into(),
        );
        identity.confidence = RouteConfidence::None;
    } else {
        identity.confidence = if identity.source_endpoints.len() > 1 {
            RouteConfidence::High
        } else {
            RouteConfidence::Medium
        };
        identity.reason = None;
    }
    identity
}

/// Query RIPEstat for the ASN announcing an IP. Strictly opt-in via settings.
#[derive(Debug, serde::Deserialize)]
struct RipeAsn {
    asn: String,
}
#[derive(Debug, serde::Deserialize)]
struct RipeResponse {
    data: RipeData,
}
#[derive(Debug, serde::Deserialize)]
struct RipeData {
    asns: Vec<RipeAsn>,
}

async fn lookup_asn_ripe(ip: &str) -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .ok()?;
    let url = format!("https://stat.ripe.net/data/asns/data.json?resource={ip}");
    let resp = client.get(&url).send().await.ok()?;
    let parsed = resp.json::<RipeResponse>().await.ok()?;
    parsed
        .data
        .asns
        .first()
        .map(|a| a.asn.clone())
        .filter(|s| !s.is_empty())
}

/// Parse `ip=1.2.3.4` style trace fields (Cloudflare) or plain IP bodies.
pub fn parse_external_ip(body: &str) -> Option<String> {
    for line in body.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("ip=") {
            let v = rest.trim();
            if !v.is_empty() && v.parse::<IpAddr>().is_ok() {
                return Some(v.to_string());
            }
        }
    }
    // icanhazip-style plain output
    for line in body.lines() {
        let line = line.trim();
        if line.parse::<IpAddr>().is_ok() {
            return Some(line.to_string());
        }
    }
    None
}
