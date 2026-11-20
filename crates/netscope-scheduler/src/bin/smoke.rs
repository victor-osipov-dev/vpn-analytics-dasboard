//! Smoke run: full pipeline on the local machine — route discovery,
//! egress verification, real probes and persistence to a temp SQLite DB.

use std::sync::Arc;
use std::time::Duration;

use netscope_core::models::{Target, TargetCategory};
use netscope_core::settings::AppSettings;
use netscope_routes::NetworkRouteManager;
use netscope_scheduler::{Scheduler, SchedulerEvent};
use netscope_storage::Store;

const EXPECTED_MIN_RESULTS: usize = 3;

#[tokio::main]
async fn main() {
    netscope_probes::tls::install_crypto_provider();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,netscope_scheduler=debug,netscope_routes=info".into()),
        )
        .init();

    let tmp = std::env::temp_dir().join(format!("netscope-smoke-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let store = Arc::new(Store::open(&tmp).await.expect("store open"));

    // Settings so the scheduler doesn't fall back to defaults silently.
    let settings = AppSettings::default();
    store.save_settings(&settings).await.expect("save settings");

    // 1. Route discovery + egress verification (uses real network calls).
    let manager = Arc::new(NetworkRouteManager::new());
    manager.refresh().await.expect("snapshot refresh");

    let scheduler = Scheduler::new(store.clone(), manager, 4);

    // 2. Seed default targets.
    let targets = vec![
        Target::single(
            "YouTube",
            TargetCategory::Video,
            "https://www.youtube.com/generate_204",
            "www.youtube.com",
            443,
            0,
        ),
        Target::single(
            "GitHub",
            TargetCategory::Web,
            "https://github.com/robots.txt",
            "github.com",
            443,
            1,
        ),
        Target::single(
            "ProtonVPN",
            TargetCategory::Custom,
            "https://account.protonvpn.com/api/js/sdk.js",
            "account.protonvpn.com",
            443,
            1,
        ),
    ];
    for t in &targets {
        store.upsert_target(t).await.expect("upsert target");
    }

    // 3. Subscribe before starting so no events are missed.
    let mut rx = scheduler.subscribe();

    let sched = scheduler.clone();
    let run_task = tokio::spawn(async move { sched.run().await });

    println!("=== scheduler started, waiting for {EXPECTED_MIN_RESULTS} probe results ===");

    // 4. Wait for the probes to flow (first service tick runs immediately).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    let mut received = 0usize;
    let mut delivered = vec![];
    while received < EXPECTED_MIN_RESULTS {
        let next = tokio::time::timeout_at(deadline, rx.recv()).await;
        match next {
            Ok(Ok(SchedulerEvent::ProbeFinished { result })) => {
                received += 1;
                println!(
                    "[{}/{}] {} -> {:?} | total_ms={:?} | error={:?}",
                    received,
                    EXPECTED_MIN_RESULTS,
                    result.target_label,
                    result.status,
                    result
                        .performance
                        .as_ref()
                        .and_then(|p| p.min_ms),
                    result.error,
                );
                delivered.push(Arc::clone(&result));
            }
            Ok(Ok(evt)) => println!("event: {evt:?}"),
            Ok(Err(_)) => break,
            Err(_) => {
                eprintln!("TIMEOUT waiting for probe results");
                break;
            }
        }
    }

    scheduler.stop();
    let _ = run_task.await;

    // 5. What landed in the DB?
    let stored = store.export_probe_results().await.expect("export");
    println!("\n=== stored results: {} ===", stored.len());
    for r in &stored {
        println!(
            "{} | {} | {:?} | ttfb={:?} | dns={:?} tls={:?} tcp={:?}",
            r.target_label,
            r.route_mode.as_str(),
            r.status,
            r.http.as_ref().and_then(|h| h.ttfb_ms),
            r.dns.as_ref().map(|d| d.status),
            r.tls.as_ref().map(|t| t.status),
            r.tcp.as_ref().map(|t| t.status),
        );
    }

    let routes = store.list_routes().await.expect("routes");
    println!("\n=== routes ===");
    for r in &routes {
        println!(
            "{} | {:?} | {:?} | external_ip={:?} egress_asn={:?}",
            r.id,
            r.mode,
            r.verification,
            r.external_ip,
            r.egress.as_ref().and_then(|e| e.asn.clone())
        );
    }

    let incidents = store.recent_incidents(10).await.expect("incidents");
    println!("\n=== incidents: {} ===", incidents.len());
    for i in &incidents {
        println!("{:?} | {}", i.kind, i.message);
    }

    let _ = std::fs::remove_file(&tmp);
    if delivered.len() >= 1 {
        println!("\nSMOKE OK ({} live probe results)", delivered.len());
    } else {
        eprintln!("\nSMOKE FAILED");
        std::process::exit(1);
    }
}
