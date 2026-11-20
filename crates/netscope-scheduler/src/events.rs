//! Event streams from the scheduler (Tauri app forwards them to the UI).

use std::sync::Arc;

use netscope_core::models::{DeepDiagnosticReport, PerformanceResult, ProbeResult};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(
    tag = "type",
    content = "payload",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum SchedulerEvent {
    ProbeFinished {
        result: Arc<ProbeResult>,
    },
    NetworkChanged {
        previous: String,
        current: String,
        at: String,
    },
    RouteUnverified {
        route_id: String,
        reason: String,
    },
    IncidentSaved(String),
    /// A new analyzer conclusion was persisted; the UI reloads diagnoses.
    DiagnosisSaved(String),
    /// Result of a manual or scheduled throughput test.
    SpeedResult(PerformanceResult),
    /// Result of a deep diagnostic (manual or triggered by an anomaly).
    DeepDiagnostic(DeepDiagnosticReport),
    ConnectivityStatus(bool),
    Paused,
    Resumed,
}
