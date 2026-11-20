//! ProbeScheduler: periodic + manual probes across available routes with
//! concurrency limits, retries with backoff, dedupe, pause and event stream.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use netscope_analyzer::{AnalyzerConfig, FailureWindow};
use netscope_core::models::{
    DiagnosisCategory, DiagnosisConfidence, Incident, IncidentKind, ProbeResult, RouteMode,
    RouteProfile, Target,
};
use netscope_core::settings::{AppSettings, MonitoringMode, SpeedTestMode};
use netscope_probes::http::HttpClientRecipe;
use netscope_routes::{EngineSettings, NetworkRouteManager};
use netscope_storage::Store;
use tokio::sync::{broadcast, mpsc, watch, Mutex, Semaphore};
use tracing::{debug, info, warn};

pub mod events;
pub mod runner;

pub use events::SchedulerEvent;

type RouteCache = Mutex<Option<(Vec<RouteProfile>, Instant)>>;

/// True when an RFC3339 timestamp is within `secs` of now.
fn recent_within(ts: &str, secs: i64) -> bool {
    match chrono::DateTime::parse_from_rfc3339(ts) {
        Ok(t) => chrono::Utc::now().signed_duration_since(t.with_timezone(&chrono::Utc)).num_seconds() <= secs,
        Err(_) => false,
    }
}

fn is_filtering_category(c: DiagnosisCategory) -> bool {
    matches!(
        c,
        DiagnosisCategory::DnsFiltering
            | DiagnosisCategory::IpBlocked
            | DiagnosisCategory::TcpReset
            | DiagnosisCategory::TlsSniFiltering
            | DiagnosisCategory::HttpFiltering
            | DiagnosisCategory::QuicRestriction
    )
}

/// Apply the user's DIRECT exclusion policy to a target.
fn target_allows_mode(target: &Target, mode: RouteMode, settings: &AppSettings) -> bool {
    if mode != RouteMode::Direct || settings.direct_exclude_patterns.is_empty() {
        return true;
    }
    let host = target
        .endpoints
        .first()
        .map(|e| e.hostname.as_str())
        .unwrap_or("");
    let hay = format!("{} {} {}", target.label, target.check_url, host).to_lowercase();
    !settings
        .direct_exclude_patterns
        .iter()
        .any(|p| !p.trim().is_empty() && hay.contains(&p.trim().to_lowercase()))
}

pub struct Scheduler {
    pub store: Arc<Store>,
    pub route_manager: Arc<NetworkRouteManager>,
    pub events_tx: broadcast::Sender<SchedulerEvent>,
    shutdown_tx: watch::Sender<bool>,
    manual_tx: mpsc::Sender<Option<String>>,
    manual_child: Mutex<Option<mpsc::Receiver<Option<String>>>>,
    in_flight: Arc<Mutex<HashSet<String>>>,
    permit_pool: Arc<Semaphore>,
    fail_windows: Arc<Mutex<HashMap<String, FailureWindow>>>,
    due_next: Arc<Mutex<HashMap<String, i64>>>,
    paused: Arc<AtomicBool>,
    last_connectivity_ok: Arc<Mutex<Option<bool>>>,
    last_speed_at: Arc<Mutex<Option<Instant>>>,
    last_deep_at: Arc<Mutex<HashMap<String, Instant>>>,
    route_cache: Arc<RouteCache>,
}

impl Scheduler {
    pub fn new(
        store: Arc<Store>,
        route_manager: Arc<NetworkRouteManager>,
        max_parallel: usize,
    ) -> Arc<Self> {
        let (events_tx, _) = broadcast::channel(256);
        let (shutdown_tx, _) = watch::channel(false);
        let (manual_tx, manual_child) = mpsc::channel(128);
        Arc::new(Self {
            store,
            route_manager,
            events_tx,
            shutdown_tx,
            manual_tx,
            manual_child: Mutex::new(Some(manual_child)),
            in_flight: Arc::new(Mutex::new(HashSet::new())),
            permit_pool: Arc::new(Semaphore::new(max_parallel.clamp(1, 32))),
            fail_windows: Arc::new(Mutex::new(HashMap::new())),
            due_next: Arc::new(Mutex::new(HashMap::new())),
            paused: Arc::new(AtomicBool::new(false)),
            last_connectivity_ok: Arc::new(Mutex::new(None)),
            last_speed_at: Arc::new(Mutex::new(None)),
            last_deep_at: Arc::new(Mutex::new(HashMap::new())),
            route_cache: Arc::new(Mutex::new(None)),
        })
    }

    /// Manual trigger entry point (one target id or None for all).
    pub async fn trigger_manual(&self, target_id: Option<String>) {
        let _ = self.manual_tx.send(target_id).await;
    }

    pub fn subscribe(&self) -> broadcast::Receiver<SchedulerEvent> {
        self.events_tx.subscribe()
    }

    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    pub fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::SeqCst);
        let _ = self
            .events_tx
            .send(if paused { SchedulerEvent::Paused } else { SchedulerEvent::Resumed });
    }

    pub async fn load_settings(&self) -> AppSettings {
        match self.store.load_settings().await {
            Ok(s) => {
                if let Err(e) = s.validate() {
                    warn!("stored settings invalid: {e}; using defaults");
                    return AppSettings::default();
                }
                s
            }
            Err(e) => {
                warn!("settings load failed: {e}; using defaults");
                AppSettings::default()
            }
        }
    }

    pub async fn engine_settings(&self) -> EngineSettings {
        let cfg = self.load_settings().await;
        EngineSettings {
            control_doh_url: cfg.control_doh_url,
            egress_endpoints: cfg.egress_endpoints.clone(),
            connect_timeout_ms: cfg.probe_timeout_ms,
            http_timeout_ms: cfg.http_timeout_ms,
            lookup_asn: cfg.lookup_asn,
            direct_strictness: cfg.direct_strictness,
        }
    }

    /// Refresh snapshot + verified routes, persist them.
    pub async fn refresh_routes(&self) -> Vec<RouteProfile> {
        info!("routes: refresh started");
        // Candidate routes are derived from a network snapshot; make sure one
        // exists even when this is the first call after an app restart.
        if self.route_manager.snapshot().await.is_none() {
            if let Err(e) = self.route_manager.refresh().await {
                warn!("network snapshot refresh failed: {e}");
            }
        }
        // Persist the network context once per fingerprint so every measurement
        // can be tied back to interfaces/gateway/DNS/proxy at that moment.
        if let Some(snap) = self.route_manager.snapshot().await {
            match self.store.context_id_for(&snap.fingerprint).await {
                Ok(None) => {
                    if let Err(e) = self.store.save_network_context(&snap).await {
                        warn!("network context save failed: {e}");
                    }
                }
                Ok(Some(_)) => {}
                Err(e) => warn!("network context lookup failed: {e}"),
            }
        }
        let settings = self.engine_settings().await;
        let _ = self.route_manager.update_settings(settings).await;
        let routes = self.route_manager.verify_all().await;
        info!("routes: verified {}", routes.len());
        for r in &routes {
            if let Err(e) = self.store.save_route(r).await {
                warn!("route save failed: {e}");
            }
            if matches!(
                r.verification,
                netscope_core::models::RouteVerification::Unverified
            ) {
                let _ = self.events_tx.send(SchedulerEvent::RouteUnverified {
                    route_id: r.id.clone(),
                    reason: r.verification_reason.clone().unwrap_or_default(),
                });
            }
        }
        routes
    }

    /// Cached route verification with a 30 s fresh window.
    pub async fn routes_cached(&self) -> Vec<RouteProfile> {
        let cache = self.route_cache.lock().await;
        if let Some((routes, at)) = cache.as_ref() {
            if at.elapsed().as_secs() < 30 {
                return routes.clone();
            }
        }
        drop(cache);
        let routes = self.refresh_routes().await;
        let mut cache = self.route_cache.lock().await;
        *cache = Some((routes.clone(), Instant::now()));
        routes
    }

    /// Mode selection applied on actually-usable routes. In Auto mode DIRECT
    /// participates only when its egress verification passed.
    pub fn wanted_modes(routes: &[RouteProfile], mode: MonitoringMode) -> Vec<RouteMode> {
        let usable = |r: &RouteProfile| {
            !matches!(
                r.verification,
                netscope_core::models::RouteVerification::Unavailable
            ) || matches!(
                r.verification,
                netscope_core::models::RouteVerification::Verified
            )
        };
        let vpn_routes: Vec<RouteMode> = routes
            .iter()
            .filter(|r| r.mode != RouteMode::Direct && usable(r))
            .map(|r| r.mode)
            .collect();
        let direct_ok = routes.iter().find(|r| r.mode == RouteMode::Direct).map(|r| {
            matches!(
                r.verification,
                netscope_core::models::RouteVerification::Verified
            )
        });

        match mode {
            MonitoringMode::DirectOnly => if direct_ok == Some(true) { vec![RouteMode::Direct] } else { vec![] },
            MonitoringMode::VpnOnly => vpn_routes,
            MonitoringMode::Both => {
                let mut v = if direct_ok == Some(true) { vec![RouteMode::Direct] } else { vec![] };
                v.extend(vpn_routes);
                v
            }
            MonitoringMode::Auto => {
                let mut v: Vec<RouteMode> =
                    if direct_ok == Some(true) { vec![RouteMode::Direct] } else { vec![] };
                v.extend(vpn_routes.clone());
                v
            }
        }
    }

    /// Main loop. Spawns work targets; keeps everything cancellable.
    pub async fn run(self: Arc<Self>) {
        info!("scheduler: starting");
        netscope_probes::tls::install_crypto_provider();
        let cfg = self.load_settings().await;

        let mut manual_rx = match self.manual_child.lock().await.take() {
            Some(rx) => rx,
            None => {
                let (_tx, rx) = mpsc::channel(1);
                drop(_tx);
                rx
            }
        };

        let watcher = netscope_network::NetworkWatcher::start(5);
        let mut net_rx = watcher.subscribe();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        let mut connectivity_ticker =
            tokio::time::interval(std::time::Duration::from_secs(cfg.connectivity_check_secs.max(5)));
        let mut service_ticker = tokio::time::interval(std::time::Duration::from_secs(1));
        service_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut speed_ticker = tokio::time::interval(std::time::Duration::from_secs(60));
        speed_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let mut targets_cache = self.store.list_targets().await.unwrap_or_default();
        let mut targets_refreshed_at = Instant::now();

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = connectivity_ticker.tick() => {
                    debug!("tick: connectivity");
                    if !self.paused.load(Ordering::SeqCst) {
                        self.connectivity_cycle().await;
                    }
                }
                _ = speed_ticker.tick() => {
                    if !self.paused.load(Ordering::SeqCst) {
                        self.scheduled_speed_test().await;
                    }
                }
                _ = service_ticker.tick() => {
                    debug!("tick: service pass");
                    if !self.paused.load(Ordering::SeqCst) {
                        if targets_refreshed_at.elapsed().as_secs() > 15 {
                            targets_cache = self.store.list_targets().await.unwrap_or_default();
                            targets_refreshed_at = Instant::now();
                        }
                        self.spawn_due_pass(&targets_cache).await;
                    }
                }
                change = net_rx.recv() => {
                    if let Ok(c) = change {
                        debug!(
                            "network change: {} -> {}",
                            c.previous_fingerprint, c.current_fingerprint
                        );
                        let _ = self.events_tx.send(SchedulerEvent::NetworkChanged {
                            previous: c.previous_fingerprint,
                            current: c.current_fingerprint,
                            at: c.captured_at,
                        });
                        // Invalidate cache, re-verify routes now, clear dues
                        // (all measurements right after a net change restart).
                        {
                            let mut cache = self.route_cache.lock().await;
                            *cache = None;
                        }
                        self.refresh_routes().await;
                        self.due_next.lock().await.clear();
                    }
                }
                manual = manual_rx.recv() => {
                    match manual {
                        Some(Some(target_id)) => {
                            self.spawn_manual_target(&target_id).await;
                        }
                        Some(None) => {
                            self.spawn_full_manual_pass(&targets_cache).await;
                        }
                        None => {
                            debug!("manual channel closed by task exit");
                            manual_rx = {
                                let mut lock = self.manual_child.lock().await;
                                match lock.take() {
                                    Some(rx) => rx,
                                    None => {
                                        let (_tx, rx) = mpsc::channel(1);
                                        drop(_tx);
                                        rx
                                    }
                                }
                            };
                        }
                    }
                }
            }
        }
        watcher.stop();
        info!("scheduler stopped");
    }

    /// Optional scheduled throughput test, bound to a concrete route.
    async fn scheduled_speed_test(&self) {
        let cfg = self.load_settings().await;
        if cfg.speed_tests != SpeedTestMode::Scheduled {
            return;
        }
        {
            let last = self.last_speed_at.lock().await;
            if let Some(at) = *last {
                if at.elapsed().as_secs() < cfg.speed_test_interval_min.saturating_mul(60) {
                    return;
                }
            }
        }
        let routes = self.routes_cached().await;
        let Some(route) = routes
            .iter()
            .find(|r| r.mode == RouteMode::Vpn)
            .or_else(|| routes.iter().find(|r| r.mode == RouteMode::Direct))
        else {
            return;
        };
        let mut recipe = HttpClientRecipe {
            body_limit_bytes: cfg.speed_test_bytes,
            timeout_ms: 45_000,
            ..Default::default()
        };
        match route.mode {
            RouteMode::Direct => {
                recipe.no_proxy_env = true;
                recipe.local_address = self.route_manager.snapshot().await.and_then(|s| {
                    s.physical_default_interface(true)
                        .and_then(|i| i.ipv4.first().and_then(|ip| ip.parse().ok()))
                });
            }
            RouteMode::System | RouteMode::CustomProxy => {
                if let Some(endpoint) = &route.vpn_endpoint {
                    let kind = route.proxy_type.as_deref().unwrap_or("http");
                    let scheme = if matches!(kind, "socks5" | "socks5remotedns") {
                        "socks5h"
                    } else if kind == "https" {
                        "https"
                    } else {
                        "http"
                    };
                    recipe.proxy_url = format!("{scheme}://{endpoint}");
                }
            }
            _ => recipe.no_proxy_env = true,
        }
        let Ok(client) = recipe.build_client() else {
            return;
        };
        let url = format!(
            "https://speed.cloudflare.com/__down?bytes={}",
            cfg.speed_test_bytes
        );
        let perf = netscope_probes::PerformanceProbe::download(client, &url, cfg.speed_test_bytes).await;
        *self.last_speed_at.lock().await = Some(Instant::now());
        let _ = self.events_tx.send(SchedulerEvent::SpeedResult(perf));
    }

    /// Light internet check + down/up incident events.
    async fn connectivity_cycle(&self) {
        let es = self.engine_settings().await;
        let probe = netscope_routes::direct::connectivity_probe(es).await;
        let ok = probe.error.is_none();
        let mut last = self.last_connectivity_ok.lock().await;
        let previous = *last;
        *last = Some(ok);
        drop(last);
        match (previous, ok) {
            (Some(true), false) => {
                let incident = Incident {
                    kind: IncidentKind::InternetDown,
                    route_mode: Some(RouteMode::Direct),
                    message: "Интернет недоступен: контрольные endpoints не отвечают".into(),
                    details: probe.error.clone(),
                    ..Default::default()
                };
                let id = incident.id.clone();
                let _ = self.store.save_incident(&incident).await;
                let _ = self.events_tx.send(SchedulerEvent::IncidentSaved(id));
                let _ = self.events_tx.send(SchedulerEvent::ConnectivityStatus(false));
            }
            (Some(false), true) => {
                let incident = Incident {
                    kind: IncidentKind::InternetRecovered,
                    message: "Интернет восстановлен".into(),
                    ..Default::default()
                };
                let id = incident.id.clone();
                let _ = self.store.save_incident(&incident).await;
                let _ = self.events_tx.send(SchedulerEvent::IncidentSaved(id));
                let _ = self.events_tx.send(SchedulerEvent::ConnectivityStatus(true));
            }
            _ => {
                let _ = self.events_tx.send(SchedulerEvent::ConnectivityStatus(ok));
            }
        }
    }

    /// Spawn one probe per (enabled target x wanted route) whose due time
    /// passed. In-flight set prevents duplicates.
    async fn spawn_due_pass(self: &Arc<Self>, targets: &[Target]) {
        if targets.is_empty() {
            debug!("due pass: no targets");
            return;
        }
        let cfg = self.load_settings().await;
        let routes = self.routes_cached().await;
        let wanted = Self::wanted_modes(&routes, cfg.monitoring_mode);
        debug!(
            "due pass: targets={} routes={} wanted={:?}",
            targets.len(),
            routes.len(),
            wanted
        );
        if wanted.is_empty() {
            return;
        }
        let now_ms = netscope_core::now_utc().timestamp_millis();
        let snapshot_fp = self
            .route_manager
            .snapshot()
            .await
            .map(|s| s.fingerprint.clone())
            .unwrap_or_default();

        let mut due_next = self.due_next.lock().await;
        let mut in_flight = self.in_flight.lock().await;

        let mut jobs: Vec<(String, Target, RouteProfile)> = vec![];
        for (idx, target) in targets.iter().enumerate() {
            if !target.enabled {
                continue;
            }
            let jitter = (target.id.len() % 7) as i64;
            let interval =
                (cfg.service_check_secs as i64).max(15) + (idx as i64 % 5) * (jitter + 1);
            for mode in &wanted {
                if !target_allows_mode(target, *mode, &cfg) {
                    continue;
                }
                let key = format!("{}:{}", target.id, mode.as_str());
                if in_flight.contains(&key) {
                    continue;
                }
                let due = due_next.get(&key).copied().unwrap_or(0);
                if due > now_ms {
                    continue;
                }
                due_next.insert(key.clone(), now_ms + interval);
                if let Some(route) = routes.iter().find(|r| r.mode == *mode) {
                    in_flight.insert(key.clone());
                    jobs.push((key, target.clone(), route.clone()));
                }
            }
        }
        drop(in_flight);
        drop(due_next);

        for (key, target, route) in jobs {
            debug!("due pass: spawn {}", key);
            self.spawn_probe(&key, &target, &route, &snapshot_fp).await;
        }
    }

    async fn spawn_manual_target(self: &Arc<Self>, target_id: &str) {
        debug!("manual: request for {target_id}");
        let targets = self.store.list_targets().await.unwrap_or_default();
        let Some(target) = targets.iter().find(|t| t.id == target_id) else {
            debug!("manual trigger: unknown target {target_id}");
            return;
        };
        let routes = self.routes_cached().await;
        let cfg = self.load_settings().await;
        let wanted = Self::wanted_modes(&routes, cfg.monitoring_mode);
        debug!("manual: wanted={wanted:?}");
        let snapshot_fp = self
            .route_manager
            .snapshot()
            .await
            .map(|s| s.fingerprint.clone())
            .unwrap_or_default();
        for mode in wanted {
            if !target_allows_mode(target, mode, &cfg) {
                continue;
            }
            let Some(route) = routes.iter().find(|r| r.mode == mode) else {
                continue;
            };
            let key = format!("{}:{}", target.id, mode.as_str());
            {
                let mut in_flight = self.in_flight.lock().await;
                if in_flight.contains(&key) {
                    continue;
                }
                in_flight.insert(key.clone());
            }
            self.spawn_probe(&key, target, route, &snapshot_fp).await;
        }
    }

    async fn spawn_full_manual_pass(self: &Arc<Self>, targets: &[Target]) {
        for t in targets {
            self.spawn_manual_target(&t.id).await;
        }
    }

    async fn spawn_probe(self: &Arc<Self>, key: &str, target: &Target, route: &RouteProfile, snapshot_fp: &str) {
        let sched = self.clone();
        let key = key.to_string();
        let target = target.clone();
        let route = route.clone();
        let fp = snapshot_fp.to_string();
        let permit = self.permit_pool.clone();
        tokio::spawn(async move {
            debug!("probe start {key}");
            let guard = match permit.acquire_owned().await {
                Ok(g) => g,
                Err(_) => {
                    sched.release_in_flight(&key).await;
                    return;
                }
            };
            let settings = sched.engine_settings().await;
            let result = runner::probe_target_once(&sched, &target, &route, &fp, settings).await;
            debug!("probe done {key} -> {:?}", result.status);
            sched.finish_probe(&target, &route, result).await;
            sched.release_in_flight(&key).await;
            drop(guard);
        });
    }

    async fn release_in_flight(&self, key: &str) {
        self.in_flight.lock().await.remove(key);
    }

    /// Run a full deep diagnostic once per target/route after a strong
    /// filtering conclusion, when the user enabled automatic deep analysis.
    async fn maybe_deep_diagnose(&self, target: &Target, mode: RouteMode) {
        let cfg = self.load_settings().await;
        if !cfg.deep_diagnostics_on_anomaly {
            return;
        }
        let key = format!("{}:{}", target.id, mode.as_str());
        {
            let last = self.last_deep_at.lock().await;
            if let Some(at) = last.get(&key) {
                if at.elapsed().as_secs() < 300 {
                    return;
                }
            }
        }
        let routes = self.routes_cached().await;
        let Some(route) = routes.iter().find(|r| r.mode == mode).cloned() else {
            return;
        };
        let snapshot = self.route_manager.snapshot().await;
        let dns_servers: Vec<netscope_probes::dns::ServerSpec> = route
            .dns_servers
            .iter()
            .filter_map(|s| s.trim().parse::<std::net::IpAddr>().ok())
            .map(|ip| netscope_probes::dns::ServerSpec { ip, port: 53 })
            .collect();
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
        let cfg_url = cfg.control_doh_url.clone();
        let check_url = target.check_url.clone();
        let opts = netscope_probes::deep::DeepOptions {
            url: &check_url,
            route_mode: mode,
            timeout_ms: cfg.probe_timeout_ms,
            control_doh_url: &cfg_url,
            dns_servers,
            bind_local,
            traceroute: true,
            proxy_url,
        };
        let report = netscope_probes::deep::run(opts).await;
        self.last_deep_at.lock().await.insert(key, Instant::now());
        let _ = self.events_tx.send(SchedulerEvent::DeepDiagnostic(report));
    }

    /// Build and persist diagnoses for the latest DIRECT/VPN pair. Conclusions
    /// are deduplicated per (target, route, category) for 10 minutes so the UI
    /// is not flooded on every probe.
    async fn analyze_and_store(&self, target: &Target) {
        let config = AnalyzerConfig::default();
        let window = self
            .store
            .recent_results(&target.id, None, 40)
            .await
            .unwrap_or_default();
        let direct = window
            .iter()
            .find(|r| r.route_mode == RouteMode::Direct)
            .cloned();
        let vpn = window
            .iter()
            .find(|r| r.route_mode == RouteMode::Vpn)
            .cloned();
        let diagnoses = netscope_analyzer::diagnose_pair(
            &target.id,
            direct.as_ref(),
            vpn.as_ref(),
            &window,
            &config,
        );
        let existing = self
            .store
            .recent_diagnoses_for(&target.id, None, 60)
            .await
            .unwrap_or_default();

        for d in diagnoses {
            let duplicate = existing.iter().any(|e| {
                e.target_id == d.target_id
                    && e.route_mode == d.route_mode
                    && e.category == d.category
                    && recent_within(&e.detected_at, 600)
            });
            if duplicate {
                continue;
            }
            let id = d.id.clone();
            let is_filtering = is_filtering_category(d.category);
            let strong = matches!(
                d.confidence,
                DiagnosisConfidence::Medium | DiagnosisConfidence::High
            );
            if let Err(e) = self.store.save_diagnosis(&d).await {
                warn!("diagnosis save failed: {e}");
                continue;
            }
            let _ = self.events_tx.send(SchedulerEvent::DiagnosisSaved(id));

            if is_filtering && strong {
                let open = self
                    .store
                    .recent_incidents(200)
                    .await
                    .unwrap_or_default()
                    .iter()
                    .any(|i| {
                        i.target_id.as_deref() == Some(&target.id)
                            && i.route_mode == d.route_mode
                            && i.resolved_at.is_none()
                            && i.kind == IncidentKind::BlockedSuspected
                    });
                if !open {
                    let incident = Incident {
                        kind: IncidentKind::BlockedSuspected,
                        target_id: Some(target.id.clone()),
                        route_mode: d.route_mode,
                        message: format!("{}: возможная фильтрация", target.label),
                        details: d.evidence.first().cloned(),
                        ..Default::default()
                    };
                    let inc_id = incident.id.clone();
                    let _ = self.store.save_incident(&incident).await;
                    let _ = self.events_tx.send(SchedulerEvent::IncidentSaved(inc_id));
                }
                if let Some(mode) = d.route_mode {
                    self.maybe_deep_diagnose(target, mode).await;
                }
            }
        }
    }

    /// Persist a result, update failure windows/incidents, emit an event.
    pub async fn finish_probe(
        &self,
        target: &Target,
        route: &RouteProfile,
        mut result: ProbeResult,
    ) {
        result.status = netscope_analyzer::status_of(&result);
        if let Err(e) = self.store.save_probe_result(&result).await {
            warn!("probe result save failed: {e}");
        }
        let ok = result.status.is_ok();
        let key = format!("{}:{}", target.id, route.mode.as_str());
        let fail_count = {
            let mut windows = self.fail_windows.lock().await;
            let win = windows
                .entry(key.clone())
                .or_insert_with(|| FailureWindow::new(6));
            win.push(ok);
            win.consecutive_failures()
        };
        if !ok && fail_count == 3 {
            let incident = Incident {
                kind: IncidentKind::ServiceDown,
                target_id: Some(target.id.clone()),
                route_mode: Some(route.mode),
                message: format!("{}: сервис недоступен (3 неудачи подряд)", target.label),
                details: result.error.clone(),
                ..Default::default()
            };
            let id = incident.id.clone();
            let _ = self.store.save_incident(&incident).await;
            let _ = self.events_tx.send(SchedulerEvent::IncidentSaved(id));
        }
        if ok {
            if let Err(e) = self
                .store
                .resolve_open_incidents(&target.id, Some(route.mode))
                .await
            {
                warn!("incident resolution failed: {e}");
            }
        }
        if ok && fail_count == 0 {
            let was_down = self
                .fail_windows
                .lock()
                .await
                .get(&key)
                .map(|w| w.had_failures())
                .unwrap_or(false);
            if was_down {
                let incident = Incident {
                    kind: IncidentKind::Restored,
                    target_id: Some(target.id.clone()),
                    route_mode: Some(route.mode),
                    message: format!("{}: сервис снова доступен", target.label),
                    ..Default::default()
                };
                let id = incident.id.clone();
                let _ = self.store.save_incident(&incident).await;
                let _ = self.events_tx.send(SchedulerEvent::IncidentSaved(id));
            }
        }
        self.analyze_and_store(target).await;
        let _ = self
            .events_tx
            .send(SchedulerEvent::ProbeFinished { result: Arc::new(result) });
    }
}
