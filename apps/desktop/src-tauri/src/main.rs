#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod defaults;
mod dns_probe;
mod state;

use netscope_scheduler::SchedulerEvent;
use tauri::{Emitter, Manager};
use tauri_plugin_notification::NotificationExt;

fn main() {
    netscope_probes::tls::install_crypto_provider();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "info,netscope_scheduler=debug,netscope_routes=info,netscope_desktop=debug".into()
            }),
        )
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            let handle = app.handle().clone();
            let app_state = tauri::async_runtime::block_on(state::AppState::init(&handle))
                .map_err(|e| format!("init failed: {e}"))?;

            let scheduler = app_state.scheduler.clone();
            let store = app_state.store.clone();
            app.manage(app_state);

            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.set_size(tauri::LogicalSize::new(1250.0, 820.0));
                let _ = window.center();
                let _ = window.show();
                let _ = window.set_focus();
            }

            // Scheduler loop.
            let runner = scheduler.clone();
            tauri::async_runtime::spawn(async move {
                runner.run().await;
            });

            // Initial route verification (network calls, so off the UI thread).
            let verifier = scheduler.clone();
            tauri::async_runtime::spawn(async move {
                let _ = verifier.refresh_routes().await;
            });

            // Forward scheduler events to the WebView.
            let mut rx = scheduler.subscribe();
            let emit_handle = handle.clone();
            let notify_store = store.clone();
            let notify_scheduler = scheduler.clone();
            tauri::async_runtime::spawn(async move {
                while let Ok(event) = rx.recv().await {
                    let _ = emit_handle.emit(commands::event_channel_name(), &event);
                    if let SchedulerEvent::IncidentSaved(id) = &event {
                        let settings = notify_scheduler.load_settings().await;
                        if settings.notifications_enabled {
                            if let Ok(Some(incident)) = notify_store.get_incident(id).await {
                                let _ = emit_handle
                                    .notification()
                                    .builder()
                                    .title("NetScope")
                                    .body(&incident.message)
                                    .show();
                            }
                        }
                    }
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::get_settings,
            commands::save_settings,
            commands::set_proxy_password,
            commands::clear_proxy_password,
            commands::get_network_context,
            commands::refresh_routes,
            commands::list_targets,
            commands::save_target,
            commands::delete_target,
            commands::restore_default_targets,
            commands::get_dashboard,
            commands::get_history,
            commands::list_incidents,
            commands::list_diagnoses,
            commands::trigger_manual,
            commands::run_domain,
            commands::set_paused,
            commands::purge_history,
            commands::clear_history,
            commands::export_json,
            commands::export_csv,
            commands::export_report,
            commands::speed_test,
            commands::dns_diagnostics,
            commands::run_deep_diagnostic,
        ])
        .build(tauri::generate_context!())
        .expect("failed to build NetScope")
        .run(|app, event| {
            if let tauri::RunEvent::ExitRequested { .. } = event {
                if let Some(state) = app.try_state::<state::AppState>() {
                    state.scheduler.stop();
                }
            }
        });
}
