//! Direct comparison of DIRECT vs VPN measurement pairs.

use netscope_core::models::{
    Diagnosis, DiagnosisCategory, DiagnosisConfidence, ProbeResult, RouteMode,
};

/// Compare a direct/vpn measurement pair and produce additional diagnoses
/// beyond the simple asymmetry rules (degradation, filtering hints).
pub fn analyze_pair(
    target_id: &str,
    direct: Option<&ProbeResult>,
    vpn: Option<&ProbeResult>,
) -> Vec<Diagnosis> {
    let mut out = vec![];
    let (Some(d), Some(v)) = (direct, vpn) else {
        return out;
    };

    // Both available, but DIRECT is markedly slower -> degradation.
    if d.status.is_ok() && v.status.is_ok() {
        let dd = d.http.as_ref().and_then(|h| h.total_ms);
        let dv = v.http.as_ref().and_then(|h| h.total_ms);
        if let (Some(dd), Some(dv)) = (dd, dv) {
            if dv > dd * 3.0 && dd > 150.0 {
                out.push(Diagnosis {
                    id: netscope_core::new_id(),
                    target_id: target_id.into(),
                    route_mode: Some(RouteMode::Direct),
                    category: DiagnosisCategory::SustainedDegradation,
                    confidence: DiagnosisConfidence::Low,
                    evidence: vec![
                        format!("direct_total_ms={dd:.0}"),
                        format!("vpn_total_ms={dv:.0}"),
                    ],
                    alternative_explanations: vec![
                        "Замедление канала провайдера".into(),
                        "Нагрузка на CDN от питающего провайдера".into(),
                        "Для вывода о фильтрации нужны повторные измерения".into(),
                    ],
                    detected_at: netscope_core::now_rfc3339(),
                    backed_by_control_check: false,
                });
            }
        }
    }

    // DIRECT has TLS stage errors while VPN is fine -> strong hint of SNI
    // level filtering, but not a proof: keep confidence low and require more
    // measurements (see analyzer::diagnose_pair).
    if !d.status.is_ok() && v.status.is_ok() {
        let tls_stage: Option<String> = d
            .tls
            .as_ref()
            .and_then(|t| t.failure_stage.clone());
        if let Some(stage) = tls_stage {
            if stage.contains("reset") {
                out.push(Diagnosis {
                    id: netscope_core::new_id(),
                    target_id: target_id.into(),
                    route_mode: Some(RouteMode::Direct),
                    category: DiagnosisCategory::TlsSniFiltering,
                    confidence: DiagnosisConfidence::Low,
                    evidence: vec![format!("tls_stage={stage}")],
                    alternative_explanations: vec![
                        "Требуется повторная проверка DNS и IP сравнения".into(),
                        "Антивирус/прокси влияет на TLS".into(),
                    ],
                    detected_at: netscope_core::now_rfc3339(),
                    backed_by_control_check: d
                        .dns
                        .as_ref()
                        .map(|x| x.control.is_some())
                        .unwrap_or(false),
                });
            }
        }
    }
    out
}
