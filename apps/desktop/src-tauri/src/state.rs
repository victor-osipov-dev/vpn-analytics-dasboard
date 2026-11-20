//! Application-wide state shared by Tauri commands.

use std::path::PathBuf;
use std::sync::Arc;

use netscope_core::settings::AppSettings;
use netscope_routes::NetworkRouteManager;
use netscope_scheduler::Scheduler;
use netscope_storage::Store;
use tauri::{AppHandle, Manager};

pub struct AppState {
    pub store: Arc<Store>,
    pub manager: Arc<NetworkRouteManager>,
    pub scheduler: Arc<Scheduler>,
    pub db_path: PathBuf,
    pub data_dir: PathBuf,
}

impl AppState {
    pub async fn init(app: &AppHandle) -> Result<Self, String> {
        let data_dir = app
            .path()
            .app_data_dir()
            .map_err(|e| format!("app data dir: {e}"))?;
        std::fs::create_dir_all(&data_dir).map_err(|e| format!("create data dir: {e}"))?;
        let db_path = data_dir.join("netscope.db");

        let store = Arc::new(Store::open(&db_path).await.map_err(|e| e.to_string())?);

        let settings = match store.load_settings().await {
            Ok(s) if s.validate().is_ok() => s,
            _ => AppSettings::default(),
        };

        let manager = Arc::new(NetworkRouteManager::new());
        if let Err(e) = manager.refresh().await {
            tracing::warn!("initial network snapshot failed: {e}");
        }
        let scheduler = Scheduler::new(
            store.clone(),
            manager.clone(),
            settings.max_parallel_probes.clamp(1, 8),
        );

        let engine = scheduler.engine_settings().await;
        manager.update_settings(engine).await;
        manager.set_custom_proxy(settings.custom_proxy.clone()).await;

        let is_empty = store
            .list_targets()
            .await
            .map(|t| t.is_empty())
            .unwrap_or(true);
        if is_empty {
            for target in crate::defaults::default_targets() {
                if let Err(e) = store.upsert_target(&target).await {
                    tracing::warn!("seed target failed: {e}");
                }
            }
        }

        Ok(Self {
            store,
            manager,
            scheduler,
            db_path,
            data_dir,
        })
    }
}
