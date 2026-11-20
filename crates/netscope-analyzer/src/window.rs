//! History-window aggregation used by the scheduler/analyzer: summarizes a
//! set of probe results over time for a target+route combination.

use netscope_core::models::{ProbeResult};

/// Aggregated numbers over a result window.
#[derive(Debug, Clone, Default)]
pub struct WindowSummary {
    pub total: usize,
    pub success: usize,
    pub failures_in_row_at_start: usize,
    pub avg_duration_ms: Option<f64>,
    pub latest_status: Option<String>,
}

impl WindowSummary {
    pub fn success_rate(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        self.success as f64 / self.total as f64
    }
}

pub fn summarize(results: &[ProbeResult]) -> WindowSummary {
    let mut summary = WindowSummary::default();
    summary.total = results.len();
    summary.success = results.iter().filter(|r| r.status.is_ok()).count();
    summary.failures_in_row_at_start = results
        .first()
        .map(|_| results.iter().take_while(|r| !r.status.is_ok()).count())
        .unwrap_or(0);
    let durations: Vec<f64> = results
        .iter()
        .filter(|r| r.duration_ms > 0.0)
        .map(|r| r.duration_ms)
        .collect();
    if !durations.is_empty() {
        summary.avg_duration_ms =
            Some(durations.iter().sum::<f64>() / durations.len() as f64);
    }
    summary.latest_status = results
        .first()
        .map(|r| r.status.as_str().to_string());
    summary
}
