//! Tauri commands: thin adapters over the Rust core. No network logic here.

use std::net::IpAddr;
use std::path::PathBuf;

use netscope_core::models::{
    DeepDiagnosticReport, Diagnosis, Incident, NetworkSnapshot, PerformanceResult, ProbeResult,
    RouteMode, RouteProfile, Target, TargetCategory, TargetEndpoint,
};
use netscope_probes::dns::ServerSpec;
use netscope_probes::deep::DeepOptions;
use netscope_core::settings::AppSettings;
use serde::Serialize;
use tauri::{Manager, State};

use crate::state::AppState;

type CmdResult<T> = Result<T, String>;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub version: String,
    pub database_path: String,
    pub data_dir: String,
    pub platform: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkContextPayload {
    pub snapshot: Option<NetworkSnapshot>,
    pub routes: Vec<RouteProfile>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardPayload {
    pub targets: Vec<Target>,
    pub routes: Vec<RouteProfile>,
    pub latest: Vec<ProbeResult>,
    pub incidents: Vec<Incident>,
    pub diagnoses: Vec<Diagnosis>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportResult {
    pub path: String,
    pub rows: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportExport {
    pub generated_at: String,
    pub routes: Vec<RouteProfile>,
    pub diagnoses: Vec<Diagnosis>,
    pub incidents: Vec<Incident>,
    pub targets: Vec<Target>,
}

#[tauri::command]
pub async fn app_info(state: State<'_, AppState>) -> CmdResult<AppInfo> {
    Ok(AppInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        database_path: state.db_path.display().to_string(),
        data_dir: state.data_dir.display().to_string(),
        platform: std::env::consts::OS.to_string(),
    })
}

#[tauri::command]
pub async fn get_settings(state: State<'_, AppState>) -> CmdResult<AppSettings> {
    Ok(state.scheduler.load_settings().await)
}

#[tauri::command]
pub async fn save_settings(
    state: State<'_, AppState>,
    settings: AppSettings,
) -> CmdResult<AppSettings> {
    settings.validate()?;
    state
        .store
        .save_settings(&settings)
        .await
        .map_err(|e| e.to_string())?;
    let engine = state.scheduler.engine_settings().await;
    state.manager.update_settings(engine).await;
    state
        .manager
        .set_custom_proxy(settings.custom_proxy.clone())
        .await;
    Ok(settings)
}

/// Proxy password never touches settings/DB: it goes to the OS secret store
/// and is read back by the virtual-interface keyring helper key only.
#[tauri::command]
pub async fn set_proxy_password(host: String, port: u16, password: String) -> CmdResult<()> {
    if host.trim().is_empty() {
        return Err("proxy host is empty".into());
    }
    let entry = keyring::Entry::new("NetScope", &format!("proxy:{host}:{port}"))
        .map_err(|e| e.to_string())?;
    entry.set_password(&password).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn clear_proxy_password(host: String, port: u16) -> CmdResult<()> {
    let entry = keyring::Entry::new("NetScope", &format!("proxy:{host}:{port}"))
        .map_err(|e| e.to_string())?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
pub async fn get_network_context(state: State<'_, AppState>) -> CmdResult<NetworkContextPayload> {
    let snapshot = state.manager.snapshot().await.map(|s| (*s).clone());
    let routes = state.store.list_routes().await.map_err(|e| e.to_string())?;
    Ok(NetworkContextPayload { snapshot, routes })
}

#[tauri::command]
pub async fn refresh_routes(state: State<'_, AppState>) -> CmdResult<Vec<RouteProfile>> {
    manager_refresh(&state).await
}

async fn manager_refresh(state: &State<'_, AppState>) -> CmdResult<Vec<RouteProfile>> {
    if let Err(e) = state.manager.refresh().await {
        return Err(format!("network snapshot: {e}"));
    }
    Ok(state.scheduler.refresh_routes().await)
}

#[tauri::command]
pub async fn list_targets(state: State<'_, AppState>) -> CmdResult<Vec<Target>> {
    state.store.list_targets().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn save_target(state: State<'_, AppState>, target: Target) -> CmdResult<Target> {
    validate_target(&target)?;
    state
        .store
        .upsert_target(&target)
        .await
        .map_err(|e| e.to_string())?;
    Ok(target)
}

#[tauri::command]
pub async fn delete_target(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    state
        .store
        .delete_target(&id)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn restore_default_targets(state: State<'_, AppState>) -> CmdResult<Vec<Target>> {
    let targets = crate::defaults::default_targets();
    for t in &targets {
        state
            .store
            .upsert_target(t)
            .await
            .map_err(|e| e.to_string())?;
    }
    state.store.list_targets().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_dashboard(state: State<'_, AppState>) -> CmdResult<DashboardPayload> {
    let targets = state.store.list_targets().await.map_err(|e| e.to_string())?;
    let routes = state.store.list_routes().await.map_err(|e| e.to_string())?;

    let mut latest = vec![];
    for target in &targets {
        for mode in [
            RouteMode::Direct,
            RouteMode::Vpn,
            RouteMode::System,
            RouteMode::CustomProxy,
        ] {
            if let Ok(mut rows) = state.store.recent_results(&target.id, Some(mode), 1).await {
                if let Some(row) = rows.pop() {
                    latest.push(row);
                }
            }
        }
    }

    let incidents = state
        .store
        .recent_incidents(30)
        .await
        .map_err(|e| e.to_string())?;
    let diagnoses = state
        .store
        .recent_diagnoses(30)
        .await
        .map_err(|e| e.to_string())?;

    Ok(DashboardPayload {
        targets,
        routes,
        latest,
        incidents,
        diagnoses,
    })
}

#[tauri::command]
pub async fn get_history(
    state: State<'_, AppState>,
    target_id: String,
    route_mode: Option<String>,
    limit: Option<usize>,
) -> CmdResult<Vec<ProbeResult>> {
    let mode = route_mode.map(|m| RouteMode::parse(&m));
    state
        .store
        .recent_results(&target_id, mode, limit.unwrap_or(200).clamp(1, 2000))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_incidents(
    state: State<'_, AppState>,
    limit: Option<usize>,
) -> CmdResult<Vec<Incident>> {
    state
        .store
        .recent_incidents(limit.unwrap_or(100).clamp(1, 500))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_diagnoses(
    state: State<'_, AppState>,
    limit: Option<usize>,
) -> CmdResult<Vec<Diagnosis>> {
    state
        .store
        .recent_diagnoses(limit.unwrap_or(100).clamp(1, 500))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn trigger_manual(
    state: State<'_, AppState>,
    target_id: Option<String>,
) -> CmdResult<()> {
    tracing::info!("manual trigger requested: {target_id:?}");
    state.scheduler.trigger_manual(target_id).await;
    Ok(())
}

#[tauri::command]
pub async fn set_paused(state: State<'_, AppState>, paused: bool) -> CmdResult<()> {
    state.scheduler.set_paused(paused);
    Ok(())
}

/// One-off deep diagnostic for an arbitrary URL, not stored as a target.
#[tauri::command]
pub async fn run_domain(
    state: State<'_, AppState>,
    url: String,
    route_mode: Option<String>,
) -> CmdResult<ProbeResult> {
    let parsed = tauri::Url::parse(url.trim()).map_err(|e| format!("invalid url: {e}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("only http/https urls are supported".into());
    }
    let host = parsed.host_str().ok_or("url has no host")?.to_string();
    reject_private_host(&host)?;
    let port = parsed.port_or_known_default().unwrap_or(443);
    let check_url = parsed.to_string();
    let target = Target::single(&host, TargetCategory::Custom, &check_url, &host, port, 0);

    let routes = state.scheduler.routes_cached().await;
    let wanted = route_mode.map(|m| RouteMode::parse(&m));
    let route = match wanted {
        Some(mode) => routes
            .iter()
            .find(|r| r.mode == mode)
            .cloned()
            .ok_or_else(|| format!("route {mode:?} is not available"))?,
        None => routes
            .iter()
            .find(|r| r.mode == RouteMode::Direct)
            .or_else(|| routes.first())
            .cloned()
            .ok_or("no verified route available")?,
    };
    let snapshot_fp = state
        .manager
        .snapshot()
        .await
        .map(|s| s.fingerprint.clone())
        .unwrap_or_default();
    let engine = state.scheduler.engine_settings().await;
    Ok(netscope_scheduler::runner::probe_target_once(
        &state.scheduler,
        &target,
        &route,
        &snapshot_fp,
        engine,
    )
    .await)
}

#[tauri::command]
pub async fn purge_history(state: State<'_, AppState>, keep_days: u32) -> CmdResult<i64> {
    state
        .store
        .purge_history(keep_days.max(1))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn clear_history(state: State<'_, AppState>) -> CmdResult<()> {
    state
        .store
        .clear_all_probe_results()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn export_json(app: tauri::AppHandle, state: State<'_, AppState>) -> CmdResult<ExportResult> {
    let rows = state
        .store
        .export_probe_results()
        .await
        .map_err(|e| e.to_string())?;
    let body = serde_json::to_string_pretty(&rows).map_err(|e| e.to_string())?;
    let path = export_path(&app, "json")?;
    std::fs::write(&path, body).map_err(|e| e.to_string())?;
    Ok(ExportResult {
        path: path.display().to_string(),
        rows: rows.len(),
    })
}

#[tauri::command]
pub async fn export_csv(app: tauri::AppHandle, state: State<'_, AppState>) -> CmdResult<ExportResult> {
    let rows = state
        .store
        .export_probe_results()
        .await
        .map_err(|e| e.to_string())?;
    let mut out = String::from(
        "id,target_id,target_label,route_id,route_mode,timestamp,duration_ms,status,correctness,error\n",
    );
    for r in &rows {
        out.push_str(&format!(
            "{},{},{},{},{},{},{:.2},{:?},{:?},{}\n",
            csv_cell(&r.id),
            csv_cell(&r.target_id),
            csv_cell(&r.target_label),
            csv_cell(&r.route_id),
            r.route_mode.as_str(),
            csv_cell(&r.timestamp),
            r.duration_ms,
            r.status.as_str(),
            format!("{:?}", r.correctness),
            csv_cell(r.error.as_deref().unwrap_or("")),
        ));
    }
    let path = export_path(&app, "csv")?;
    std::fs::write(&path, out).map_err(|e| e.to_string())?;
    Ok(ExportResult {
        path: path.display().to_string(),
        rows: rows.len(),
    })
}

/// Export the analytical layer (routes, diagnoses, incidents, targets) as a
/// single JSON report. Measurements themselves are exported separately.
#[tauri::command]
pub async fn export_report(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> CmdResult<ExportResult> {
    let report = ReportExport {
        generated_at: netscope_core::now_rfc3339(),
        routes: state.store.list_routes().await.map_err(|e| e.to_string())?,
        diagnoses: state.store.recent_diagnoses(10_000).await.map_err(|e| e.to_string())?,
        incidents: state.store.recent_incidents(10_000).await.map_err(|e| e.to_string())?,
        targets: state.store.list_targets().await.map_err(|e| e.to_string())?,
    };
    let rows = report.diagnoses.len() + report.incidents.len();
    let body = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
    let path = export_path(&app, "json")?;
    let path = path.with_file_name(format!(
        "netscope-report-{}.json",
        chrono::Local::now().format("%Y%m%d-%H%M%S")
    ));
    std::fs::write(&path, body).map_err(|e| e.to_string())?;
    Ok(ExportResult {
        path: path.display().to_string(),
        rows,
    })
}

/// Explicit, user-triggered throughput test. Downloads come from Cloudflare's
/// public speed endpoint with a hard byte cap.
#[tauri::command]
pub async fn speed_test(
    state: State<'_, AppState>,
    url: Option<String>,
    bytes: Option<u64>,
) -> CmdResult<PerformanceResult> {
    let limit = bytes.unwrap_or(10 * 1024 * 1024).clamp(256 * 1024, 100 * 1024 * 1024);
    let endpoint = url.unwrap_or_else(|| "https://speed.cloudflare.com/__down".into());
    let full = if endpoint.contains('?') {
        format!("{endpoint}&bytes={limit}")
    } else {
        format!("{endpoint}?bytes={limit}")
    };
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(45))
        .user_agent("NetScope/0.1")
        .build()
        .map_err(|e| e.to_string())?;
    let perf = netscope_probes::PerformanceProbe::download(client, &full, limit).await;
    let _ = state;
    Ok(perf)
}

pub fn event_channel_name() -> &'static str {
    "netscope://scheduler-event"
}

/// Deep diagnostic for one URL: DNS/SNI/TCP/HTTP-version/PMTU/path checks
/// with independent controls, localised to a concrete stage.
#[tauri::command]
pub async fn run_deep_diagnostic(
    state: State<'_, AppState>,
    url: String,
    route_mode: Option<String>,
    traceroute: Option<bool>,
) -> CmdResult<DeepDiagnosticReport> {
    let parsed = tauri::Url::parse(url.trim()).map_err(|e| format!("invalid url: {e}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("only http/https urls are supported".into());
    }
    let host = parsed.host_str().ok_or("url has no host")?.to_string();
    reject_private_host(&host)?;

    let settings = state.scheduler.load_settings().await;
    let routes = state.scheduler.routes_cached().await;
    let mode = route_mode
        .map(|m| RouteMode::parse(&m))
        .unwrap_or(RouteMode::Direct);
    let route = routes
        .iter()
        .find(|r| r.mode == mode)
        .cloned()
        .ok_or_else(|| format!("route {mode:?} is not available"))?;
    let snapshot = state.manager.snapshot().await;

    let mut dns_servers: Vec<ServerSpec> = if mode == RouteMode::Direct {
        snapshot
            .as_ref()
            .and_then(|s| s.physical_default_interface(true))
            .map(|i| {
                i.dns_servers
                    .iter()
                    .filter_map(|s| parse_dns_server(s))
                    .collect()
            })
            .unwrap_or_default()
    } else {
        route
            .dns_servers
            .iter()
            .filter_map(|s| parse_dns_server(s))
            .collect()
    };
    if dns_servers.is_empty() {
        if let Some(snap) = &snapshot {
            dns_servers = snap
                .dns_servers
                .iter()
                .filter_map(|s| parse_dns_server(s))
                .collect();
        }
    }

    let bind_local = if mode == RouteMode::Direct {
        snapshot.as_ref().and_then(|s| {
            s.physical_default_interface(true)
                .and_then(|i| i.ipv4.first().and_then(|ip| ip.parse().ok()))
        })
    } else {
        None
    };

    let mut proxy_url = String::new();
    if matches!(mode, RouteMode::System | RouteMode::CustomProxy) {
        if let Some(endpoint) = &route.vpn_endpoint {
            let kind = route.proxy_type.as_deref().unwrap_or("http");
            let scheme = if matches!(kind, "socks5" | "socks5remotedns") {
                "socks5h"
            } else if kind == "https" {
                "https"
            } else {
                "http"
            };
            proxy_url = format!("{scheme}://{endpoint}");
        }
    }

    let clean_url = parsed.to_string();
    let opts = DeepOptions {
        url: &clean_url,
        route_mode: mode,
        timeout_ms: settings.probe_timeout_ms,
        control_doh_url: &settings.control_doh_url,
        dns_servers,
        bind_local,
        traceroute: traceroute.unwrap_or(true),
        proxy_url,
    };
    Ok(netscope_probes::deep::run(opts).await)
}

fn parse_dns_server(s: &str) -> Option<ServerSpec> {
    let ip: std::net::IpAddr = s.trim().parse().ok()?;
    Some(ServerSpec { ip, port: 53 })
}

/// Verify DNS hygiene: where DNS actually goes (through the tunnel or not)
/// and whether the resolver stack is answering.
#[tauri::command]
pub async fn dns_diagnostics(
    state: State<'_, AppState>,
) -> CmdResult<crate::dns_probe::DnsDiagnostics> {
    if state.manager.snapshot().await.is_none() {
        let _ = state.manager.refresh().await;
    }
    let snapshot = state.manager.snapshot().await.map(|s| (*s).clone());
    let settings = state.scheduler.load_settings().await;
    Ok(crate::dns_probe::diagnose(snapshot.as_ref(), &settings).await)
}

fn export_path(app: &tauri::AppHandle, ext: &str) -> CmdResult<PathBuf> {
    let dir = app
        .path()
        .download_dir()
        .or_else(|_| app.path().app_data_dir())
        .map_err(|e| e.to_string())?;
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    Ok(dir.join(format!("netscope-export-{stamp}.{ext}")))
}

fn csv_cell(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn validate_target(t: &Target) -> CmdResult<()> {
    if t.label.trim().is_empty() {
        return Err("label is required".into());
    }
    if !t.check_url.starts_with("http://") && !t.check_url.starts_with("https://") {
        return Err("checkUrl must start with http:// or https://".into());
    }
    if t.endpoints.is_empty() {
        return Err("at least one endpoint is required".into());
    }
    for TargetEndpoint { hostname, .. } in &t.endpoints {
        if hostname.trim().is_empty() {
            return Err("endpoint hostname is empty".into());
        }
        reject_hostname(hostname)?;
    }
    Ok(())
}

fn reject_hostname(host: &str) -> CmdResult<()> {
    let lower = host.trim().trim_end_matches('.').to_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") {
        return Err("localhost targets are not allowed".into());
    }
    reject_private_host(&lower)
}

fn reject_private_host(host: &str) -> CmdResult<()> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<IpAddr>() {
        let forbidden = match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_unspecified()
                    || v4.is_broadcast()
            }
            IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
        };
        if forbidden {
            return Err("private, loopback and link-local addresses are not allowed".into());
        }
    }
    Ok(())
}
