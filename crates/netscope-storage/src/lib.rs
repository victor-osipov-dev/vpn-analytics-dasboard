//! SQLite storage for measurements, routes, diagnoses, incidents, settings.
//! Local-first: a single file, no cloud dependency, easy export/purge.

use std::path::Path;

use netscope_core::models::{
    AvailabilityStatus, Diagnosis, DiagnosisConfidence, DiagnosisCategory, EgressIdentity, Incident,
    IncidentKind, NetworkSnapshot, ProbeResult, RouteMode, RouteProfile,
    RouteVerification, Target, TargetCategory, VpnStatus,
};
use netscope_core::settings::AppSettings;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use sqlx::Row;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("sqlx: {0}")]
    Sql(#[from] sqlx::Error),
    #[error("migrate: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("{0}")]
    Other(String),
}

pub type StoreResult<T> = Result<T, StorageError>;

pub struct Store {
    pool: SqlitePool,
}

impl Store {
    /// Open (and migrate) the app database at `db_path`.
    pub async fn open(db_path: &Path) -> StoreResult<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let url = format!("sqlite://{}?mode=rwc", db_path.display().to_string().replace('\\', "/"));
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await?;
        // sqlx resolves migrate! paths against CARGO_MANIFEST_DIR of the
        // compiling crate.
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await?;
        Ok(Self { pool })
    }

    /// In-memory store for tests.
    pub async fn open_memory() -> StoreResult<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect("sqlite::memory:")
            .await?;
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await?;
        Ok(Self { pool })
    }

    // ------------------------------------------------------------------
    // probe_results
    // ------------------------------------------------------------------

    pub async fn save_probe_result(&self, r: &ProbeResult) -> StoreResult<()> {
        let dns = r.dns.as_ref().map(serde_json::to_string).transpose()?;
        let tcp = r.tcp.as_ref().map(serde_json::to_string).transpose()?;
        let tls = r.tls.as_ref().map(serde_json::to_string).transpose()?;
        let http = r.http.as_ref().map(serde_json::to_string).transpose()?;
        let perf = r.performance.as_ref().map(serde_json::to_string).transpose()?;
        sqlx::query(
            r#"INSERT INTO probe_results
               (id, target_id, target_label, route_id, route_mode, correctness, status,
                timestamp, duration_ms, ip_family, network_fingerprint, network_context_id,
                network_changed, dns_json, tcp_json, tls_json, http_json, perf_json, error)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"#,
        )
        .bind(&r.id)
        .bind(&r.target_id)
        .bind(&r.target_label)
        .bind(&r.route_id)
        .bind(r.route_mode.as_str())
        .bind(serde_json::to_string(&r.correctness)?)
        .bind(r.status.as_str())
        .bind(&r.timestamp)
        .bind(r.duration_ms)
        .bind(r.ip_family_used.map(|f| match f {
            netscope_core::models::IpFamily::V4 => "v4".to_string(),
            netscope_core::models::IpFamily::V6 => "v6".to_string(),
            netscope_core::models::IpFamily::Any => "any".to_string(),
        }))
        .bind(&r.network_fingerprint)
        .bind(r.network_context_id.as_ref())
        .bind(r.network_changed)
        .bind(dns)
        .bind(tcp)
        .bind(tls)
        .bind(http)
        .bind(perf)
        .bind(&r.error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn recent_results(
        &self,
        target_id: &str,
        route_mode: Option<RouteMode>,
        limit: usize,
    ) -> StoreResult<Vec<ProbeResult>> {
        let (rows, mode) = (limit as i64, route_mode.map(|m| m.as_str().to_string()));
        let query = match &mode {
            None => {
                sqlx::query(
                    "SELECT * FROM probe_results WHERE target_id = ? ORDER BY timestamp DESC LIMIT ?",
                )
                .bind(target_id)
                .bind(rows)
            }
            Some(m) => {
                sqlx::query(
                    "SELECT * FROM probe_results WHERE target_id = ? AND route_mode = ? ORDER BY timestamp DESC LIMIT ?",
                )
                .bind(target_id)
                .bind(m)
                .bind(rows)
            }
        };
        let fetched = query.fetch_all(&self.pool).await?;
        let mut out = vec![];
        for row in fetched {
            out.push(row_to_result(&row)?);
        }
        Ok(out)
    }

    pub async fn results_range(
        &self,
        since_rfc3339: &str,
        limit: usize,
    ) -> StoreResult<Vec<ProbeResult>> {
        let rows = sqlx::query(
            "SELECT * FROM probe_results WHERE timestamp >= ? ORDER BY timestamp DESC LIMIT ?",
        )
        .bind(since_rfc3339)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;
        let mut out = vec![];
        for row in rows {
            out.push(row_to_result(&row)?);
        }
        Ok(out)
    }

    pub async fn purge_history(&self, keep_days: u32) -> StoreResult<i64> {
        let cutoff = netscope_core::rfc3339_days_ago(keep_days);
        let res = sqlx::query("DELETE FROM probe_results WHERE timestamp < ?")
            .bind(&cutoff)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() as i64)
    }

    // ------------------------------------------------------------------
    // targets
    // ------------------------------------------------------------------

    pub async fn upsert_target(&self, t: &Target) -> StoreResult<()> {
        let endpoints = serde_json::to_string(&t.endpoints)?;
        sqlx::query(
            r#"INSERT INTO targets (id, label, category, check_url, endpoints_json, favorite, enabled, priority, notes, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET
                 label = excluded.label,
                 category = excluded.category,
                 check_url = excluded.check_url,
                 endpoints_json = excluded.endpoints_json,
                 favorite = excluded.favorite,
                 enabled = excluded.enabled,
                 priority = excluded.priority,
                 notes = excluded.notes"#,
        )
        .bind(&t.id)
        .bind(&t.label)
        .bind(t.category.as_str())
        .bind(&t.check_url)
        .bind(&endpoints)
        .bind(t.favorite)
        .bind(t.enabled)
        .bind(t.priority)
        .bind(t.notes.as_ref())
        .bind(netscope_core::now_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete_target(&self, id: &str) -> StoreResult<()> {
        sqlx::query("DELETE FROM targets WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_targets(&self) -> StoreResult<Vec<Target>> {
        let rows = sqlx::query("SELECT * FROM targets ORDER BY priority ASC, label ASC")
            .fetch_all(&self.pool)
            .await?;
        let mut out = vec![];
        for row in rows {
            let category: String = row.try_get("category")?;
            let endpoints_json: String = row.try_get("endpoints_json")?;
            out.push(Target {
                id: row.try_get("id")?,
                label: row.try_get("label")?,
                category: TargetCategory::parse(&category),
                check_url: row.try_get("check_url")?,
                endpoints: serde_json::from_str(&endpoints_json).unwrap_or_default(),
                favorite: row
                    .try_get::<i64, _>("favorite")
                    .map(|v| v != 0)
                    .unwrap_or(false),
                enabled: row
                    .try_get::<i64, _>("enabled")
                    .map(|v| v != 0)
                    .unwrap_or(true),
                priority: row.try_get::<i64, _>("priority")?.clamp(0, 255) as u8,
                notes: row.try_get("notes")?,
            });
        }
        Ok(out)
    }

    // ------------------------------------------------------------------
    // routes
    // ------------------------------------------------------------------

    pub async fn save_route(&self, r: &RouteProfile) -> StoreResult<()> {
        sqlx::query(
            r#"INSERT INTO routes (id, mode, name, interface_name, proxy_type, vpn_kind, vpn_endpoint,
                   verification, confidence, verification_reason, external_ip, external_ipv6,
                   dns_servers_json, egress_json, vpn_status, verified_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET
                 name = excluded.name,
                 interface_name = excluded.interface_name,
                 proxy_type = excluded.proxy_type,
                 vpn_kind = excluded.vpn_kind,
                 vpn_endpoint = excluded.vpn_endpoint,
                 verification = excluded.verification,
                 confidence = excluded.confidence,
                 verification_reason = excluded.verification_reason,
                 external_ip = excluded.external_ip,
                 external_ipv6 = excluded.external_ipv6,
                 dns_servers_json = excluded.dns_servers_json,
                 egress_json = excluded.egress_json,
                 vpn_status = excluded.vpn_status,
                 verified_at = excluded.verified_at"#,
        )
        .bind(&r.id)
        .bind(r.mode.as_str())
        .bind(&r.name)
        .bind(r.interface_name.as_ref())
        .bind(r.proxy_type.as_ref())
        .bind(r.vpn_kind.map(|k| serde_json::to_string(&k).unwrap_or_default()).as_deref())
        .bind(r.vpn_endpoint.as_ref())
        .bind(serde_json::to_string(&r.verification)?)
        .bind(serde_json::to_string(&r.confidence)?)
        .bind(r.verification_reason.as_ref())
        .bind(r.external_ip.as_ref())
        .bind(r.external_ipv6.as_ref())
        .bind(serde_json::to_string(&r.dns_servers)?)
        .bind(r.egress.as_ref().map(serde_json::to_string).transpose()?)
        .bind(r.vpn_status.map(|s| serde_json::to_string(&s).unwrap_or_default()).as_deref())
        .bind(netscope_core::now_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_routes(&self) -> StoreResult<Vec<RouteProfile>> {
        let rows = sqlx::query("SELECT * FROM routes").fetch_all(&self.pool).await?;
        let mut out = vec![];
        for row in rows {
            let verification: String = row.try_get("verification")?;
            let confidence: String = row.try_get("confidence")?;
            let dns_json: String = row.try_get("dns_servers_json")?;
            let egress_json: Option<String> = row.try_get("egress_json")?;
            let vpn_status_json: Option<String> = row.try_get("vpn_status")?;
            out.push(RouteProfile {
                id: row.try_get("id")?,
                mode: RouteMode::parse(&row.try_get::<String, _>("mode")?),
                name: row.try_get("name")?,
                interface_name: row.try_get("interface_name")?,
                proxy_type: row.try_get("proxy_type")?,
                external_ip: row.try_get("external_ip")?,
                external_ipv6: row.try_get("external_ipv6")?,
                dns_servers: serde_json::from_str(&dns_json).unwrap_or_default(),
                verification: serde_json::from_str(&verification).unwrap_or(RouteVerification::Unverified),
                confidence: serde_json::from_str(&confidence).unwrap_or(netscope_core::models::RouteConfidence::None),
                verification_reason: row.try_get("verification_reason")?,
                vpn_kind: row
                    .try_get::<Option<String>, _>("vpn_kind")?
                    .and_then(|k| serde_json::from_str(&k).ok()),
                vpn_status: vpn_status_json.and_then(|s| serde_json::from_str::<VpnStatus>(&s).ok()),
                vpn_endpoint: row.try_get("vpn_endpoint")?,
                egress: egress_json.and_then(|s| serde_json::from_str::<EgressIdentity>(&s).ok()),
                last_checked: row.try_get("verified_at")?,
            });
        }
        Ok(out)
    }

    // ------------------------------------------------------------------
    // network contexts
    // ------------------------------------------------------------------

    /// Persist a full snapshot as a context row and return its id.
    pub async fn save_network_context(&self, snap: &NetworkSnapshot) -> StoreResult<String> {
        let id = netscope_core::new_id();
        let interfaces = serde_json::to_string(&snap.interfaces)?;
        let routes = serde_json::to_string(
            &snap
                .routes_v4
                .iter()
                .chain(snap.routes_v6.iter())
                .collect::<Vec<_>>(),
        )?;
        let active_interface = snap
            .physical_default_interface(true)
            .map(|i| i.name.clone())
            .or_else(|| snap.default_gateway_v4.clone());
        sqlx::query(
            r#"INSERT INTO network_contexts
               (id, snapshot_fingerprint, captured_at, active_interface, gateway,
                dns_servers_json, system_proxy_enabled, tunnel_detected,
                interfaces_json, routes_json)
               VALUES (?,?,?,?,?,?,?,?,?,?)"#,
        )
        .bind(&id)
        .bind(&snap.fingerprint)
        .bind(&snap.captured_at)
        .bind(active_interface)
        .bind(&snap.default_gateway_v4)
        .bind(serde_json::to_string(&snap.dns_servers)?)
        .bind(snap.system_proxy.enabled)
        .bind(!snap.tunnel_interfaces.is_empty())
        .bind(&interfaces)
        .bind(&routes)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    /// Id of the context row matching a snapshot fingerprint, if it was stored.
    pub async fn context_id_for(&self, fingerprint: &str) -> StoreResult<Option<String>> {
        let row = sqlx::query("SELECT id FROM network_contexts WHERE snapshot_fingerprint = ? LIMIT 1")
            .bind(fingerprint)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.try_get("id")).transpose()?)
    }

    // ------------------------------------------------------------------
    // diagnoses / incidents
    // ------------------------------------------------------------------

    pub async fn save_diagnosis(&self, d: &Diagnosis) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO diagnoses (id, target_id, route_mode, category, confidence, evidence_json, alternative_json, backed_by_control, detected_at)
             VALUES (?,?,?,?,?,?,?,?,?)",
        )
        .bind(&d.id)
        .bind(&d.target_id)
        .bind(d.route_mode.map(|m| m.as_str().to_string()).as_deref())
        .bind(d.category.as_str())
        .bind(serde_json::to_string(&d.confidence)?)
        .bind(serde_json::to_string(&d.evidence)?)
        .bind(serde_json::to_string(&d.alternative_explanations)?)
        .bind(d.backed_by_control_check)
        .bind(&d.detected_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn recent_diagnoses(&self, limit: usize) -> StoreResult<Vec<Diagnosis>> {
        let rows = sqlx::query(
            "SELECT * FROM diagnoses ORDER BY detected_at DESC LIMIT ?",
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;
        let mut out = vec![];
        for row in rows {
            let evidence: String = row.try_get("evidence_json")?;
            let alternatives: String = row.try_get("alternative_json")?;
            let confidence: String = row.try_get("confidence")?;
            let rm: Option<String> = row.try_get("route_mode")?;
            out.push(Diagnosis {
                id: row.try_get("id")?,
                target_id: row.try_get("target_id")?,
                route_mode: rm.map(|m| RouteMode::parse(&m)),
                category: DiagnosisCategory::parse(&row.try_get::<String, _>("category")?),
                confidence: serde_json::from_str(&confidence)
                    .unwrap_or(DiagnosisConfidence::Unknown),
                evidence: serde_json::from_str(&evidence).unwrap_or_default(),
                alternative_explanations: serde_json::from_str(&alternatives).unwrap_or_default(),
                detected_at: row.try_get("detected_at")?,
                backed_by_control_check: row
                    .try_get::<i64, _>("backed_by_control")
                    .map(|v| v != 0)
                    .unwrap_or(false),
            });
        }
        Ok(out)
    }

    /// Diagnoses for one target, newest first, optionally filtered by route.
    /// Used to avoid emitting the same conclusion on every probe.
    pub async fn recent_diagnoses_for(
        &self,
        target_id: &str,
        route_mode: Option<RouteMode>,
        limit: usize,
    ) -> StoreResult<Vec<Diagnosis>> {
        let rows = match route_mode {
            None => {
                sqlx::query(
                    "SELECT * FROM diagnoses WHERE target_id = ? ORDER BY detected_at DESC LIMIT ?",
                )
                .bind(target_id)
                .bind(limit as i64)
                .fetch_all(&self.pool)
                .await?
            }
            Some(mode) => {
                sqlx::query(
                    "SELECT * FROM diagnoses WHERE target_id = ? AND route_mode = ? ORDER BY detected_at DESC LIMIT ?",
                )
                .bind(target_id)
                .bind(mode.as_str())
                .bind(limit as i64)
                .fetch_all(&self.pool)
                .await?
            }
        };
        let mut out = vec![];
        for row in rows {
            let evidence: String = row.try_get("evidence_json")?;
            let alternatives: String = row.try_get("alternative_json")?;
            let confidence: String = row.try_get("confidence")?;
            let rm: Option<String> = row.try_get("route_mode")?;
            out.push(Diagnosis {
                id: row.try_get("id")?,
                target_id: row.try_get("target_id")?,
                route_mode: rm.map(|m| RouteMode::parse(&m)),
                category: DiagnosisCategory::parse(&row.try_get::<String, _>("category")?),
                confidence: serde_json::from_str(&confidence)
                    .unwrap_or(DiagnosisConfidence::Unknown),
                evidence: serde_json::from_str(&evidence).unwrap_or_default(),
                alternative_explanations: serde_json::from_str(&alternatives).unwrap_or_default(),
                detected_at: row.try_get("detected_at")?,
                backed_by_control_check: row
                    .try_get::<i64, _>("backed_by_control")
                    .map(|v| v != 0)
                    .unwrap_or(false),
            });
        }
        Ok(out)
    }

    /// Close every unresolved incident for a target/route (recovery).
    pub async fn resolve_open_incidents(
        &self,
        target_id: &str,
        route_mode: Option<RouteMode>,
    ) -> StoreResult<u64> {
        let res = match route_mode {
            None => {
                sqlx::query(
                    "UPDATE incidents SET resolved_at = ? WHERE target_id = ? AND resolved_at IS NULL",
                )
                .bind(netscope_core::now_rfc3339())
                .bind(target_id)
                .execute(&self.pool)
                .await?
            }
            Some(mode) => {
                sqlx::query(
                    "UPDATE incidents SET resolved_at = ? WHERE target_id = ? AND route_mode = ? AND resolved_at IS NULL",
                )
                .bind(netscope_core::now_rfc3339())
                .bind(target_id)
                .bind(mode.as_str())
                .execute(&self.pool)
                .await?
            }
        };
        Ok(res.rows_affected())
    }

    pub async fn save_incident(&self, i: &Incident) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO incidents (id, kind, target_id, route_mode, message, details, started_at, resolved_at)
             VALUES (?,?,?,?,?,?,?,?)",
        )
        .bind(&i.id)
        .bind(serde_json::to_string(&i.kind)?)
        .bind(i.target_id.as_ref())
        .bind(i.route_mode.map(|m| m.as_str().to_string()).as_deref())
        .bind(&i.message)
        .bind(i.details.as_ref())
        .bind(&i.started_at)
        .bind(i.resolved_at.as_ref())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_incident(&self, id: &str) -> StoreResult<Option<Incident>> {
        let row = sqlx::query("SELECT * FROM incidents WHERE id = ? LIMIT 1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|row| Incident {
            id: row.try_get("id").unwrap_or_default(),
            kind: serde_json::from_str(&row.try_get::<String, _>("kind").unwrap_or_default())
                .unwrap_or(IncidentKind::NetworkChanged),
            target_id: row.try_get("target_id").ok().flatten(),
            route_mode: row
                .try_get::<Option<String>, _>("route_mode")
                .ok()
                .flatten()
                .map(|m| RouteMode::parse(&m)),
            message: row.try_get("message").unwrap_or_default(),
            details: row.try_get("details").ok().flatten(),
            started_at: row.try_get("started_at").unwrap_or_default(),
            resolved_at: row.try_get("resolved_at").ok().flatten(),
        }))
    }

    pub async fn recent_incidents(&self, limit: usize) -> StoreResult<Vec<Incident>> {
        let rows = sqlx::query("SELECT * FROM incidents ORDER BY started_at DESC LIMIT ?")
            .bind(limit as i64)
            .fetch_all(&self.pool)
            .await?;
        let mut out = vec![];
        for row in rows {
            let kind: String = row.try_get("kind")?;
            let rm: Option<String> = row.try_get("route_mode")?;
            out.push(Incident {
                id: row.try_get("id")?,
                kind: serde_json::from_str(&kind).unwrap_or(IncidentKind::NetworkChanged),
                target_id: row.try_get("target_id")?,
                route_mode: rm.map(|m| RouteMode::parse(&m)),
                message: row.try_get("message")?,
                details: row.try_get("details")?,
                started_at: row.try_get("started_at")?,
                resolved_at: row.try_get("resolved_at")?,
            });
        }
        Ok(out)
    }

    // ------------------------------------------------------------------
    // settings
    // ------------------------------------------------------------------

    pub async fn load_settings(&self) -> StoreResult<AppSettings> {
        let row = sqlx::query("SELECT value FROM settings WHERE key = 'app' LIMIT 1")
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => {
                let value: String = r.try_get("value")?;
                Ok(serde_json::from_str(&value).unwrap_or_default())
            }
            None => Ok(AppSettings::default()),
        }
    }

    pub async fn save_settings(&self, s: &AppSettings) -> StoreResult<()> {
        let value = serde_json::to_string(s)?;
        sqlx::query(
            "INSERT INTO settings (key, value) VALUES ('app', ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(&value)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn mark_agent_metadata(&self, key: &str, value: &str) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO agent_metadata (key, value) VALUES (?, ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // export / purge
    // ------------------------------------------------------------------

    pub async fn export_probe_results(&self) -> StoreResult<Vec<ProbeResult>> {
        let rows =
            sqlx::query("SELECT * FROM probe_results ORDER BY timestamp DESC LIMIT 100000")
                .fetch_all(&self.pool)
                .await?;
        let mut out = vec![];
        for row in rows {
            out.push(row_to_result(&row)?);
        }
        Ok(out)
    }

    pub async fn clear_all_probe_results(&self) -> StoreResult<()> {
        sqlx::query("DELETE FROM probe_results")
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM diagnoses").execute(&self.pool).await?;
        Ok(())
    }
}

fn row_to_result(row: &sqlx::sqlite::SqliteRow) -> StoreResult<ProbeResult> {
    let dns_str: Option<String> = row.try_get("dns_json")?;
    let tcp_str: Option<String> = row.try_get("tcp_json")?;
    let tls_str: Option<String> = row.try_get("tls_json")?;
    let http_str: Option<String> = row.try_get("http_json")?;
    let perf_str: Option<String> = row.try_get("perf_json")?;
    let status: String = row.try_get("status")?;
    let correctness: String = row.try_get("correctness")?;
    let rm: String = row.try_get("route_mode")?;
    let ip_family: Option<String> = row.try_get("ip_family")?;
    Ok(ProbeResult {
        id: row.try_get("id")?,
        target_id: row.try_get("target_id")?,
        target_label: row.try_get("target_label")?,
        route_id: row.try_get("route_id")?,
        route_mode: RouteMode::parse(&rm),
        network_fingerprint: row.try_get("network_fingerprint")?,
        network_context_id: row.try_get("network_context_id")?,
        network_changed: row
            .try_get::<i64, _>("network_changed")
            .map(|v| v != 0)
            .unwrap_or(false),
        timestamp: row.try_get("timestamp")?,
        duration_ms: row.try_get("duration_ms")?,
        correctness: serde_json::from_str(&correctness)
            .unwrap_or(netscope_core::models::RouteVerificationKind::Unverified),
        status: AvailabilityStatus::from_str(&status),
        ip_family_used: ip_family.map(|f| match f.as_str() {
            "v4" => netscope_core::models::IpFamily::V4,
            "v6" => netscope_core::models::IpFamily::V6,
            _ => netscope_core::models::IpFamily::Any,
        }),
        dns: dns_str.and_then(|s| serde_json::from_str(&s).ok()),
        tcp: tcp_str.and_then(|s| serde_json::from_str(&s).ok()),
        tls: tls_str.and_then(|s| serde_json::from_str(&s).ok()),
        http: http_str.and_then(|s| serde_json::from_str(&s).ok()),
        performance: perf_str.and_then(|s| serde_json::from_str(&s).ok()),
        error: row.try_get("error")?,
    })
}

/// Serialization view of probe results for export (JSON/CSV).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResultRow {
    pub timestamp: String,
    pub target_id: String,
    pub target_label: String,
    #[serde(rename = "route")]
    pub route_mode: String,
    pub status: String,
    pub duration_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn to_csv(results: &[ProbeResult]) -> String {
    let mut out = String::new();
    out.push_str("timestamp,target_id,target_label,route,status,duration_ms,error\n");
    for r in results {
        out.push_str(&format!(
            "{},\"{}\",\"{}\",{},{},{:.0},\"{}\"\n",
            r.timestamp,
            r.target_id,
            r.target_label.replace('"', "'"),
            r.route_mode.as_str(),
            r.status.as_str(),
            r.duration_ms,
            r.error.as_deref().unwrap_or("").replace('"', "'"),
        ));
    }
    out
}
