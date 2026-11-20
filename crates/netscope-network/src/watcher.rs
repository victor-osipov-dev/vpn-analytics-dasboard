//! Watches the network configuration and raises change events.
//! Poll-based (robust and permission-free); interval is configurable.

use std::sync::Arc;

use tokio::sync::{broadcast, watch};
use tracing::warn;

use crate::Discovery;

#[derive(Debug, Clone)]
pub struct NetworkChange {
    pub previous_fingerprint: String,
    pub current_fingerprint: String,
    pub captured_at: String,
}

/// Emits NetworkChange on every observed configuration difference.
pub struct NetworkWatcher {
    rx: broadcast::Receiver<NetworkChange>,
    shutdown: watch::Sender<bool>,
}

impl NetworkWatcher {
    pub fn start(poll_secs: u64) -> Arc<Self> {
        let (tx_changes, rx) = broadcast::channel(64);
        let (tx_shutdown, mut shutdown) = watch::channel(false);
        let interval = std::time::Duration::from_secs(poll_secs.max(2));

        tokio::spawn(async move {
            let mut last: Option<String> = None;
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {},
                    _ = shutdown.changed() => break,
                }
                let snapshot = match Discovery::snapshot() {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("network watcher discovery failed: {e}");
                        continue;
                    }
                };
                let fp = snapshot.fingerprint;
                match &last {
                    None => last = Some(fp),
                    Some(prev) if *prev != fp => {
                        let change = NetworkChange {
                            previous_fingerprint: prev.clone(),
                            current_fingerprint: fp.clone(),
                            captured_at: snapshot.captured_at,
                        };
                        last = Some(fp);
                        let _ = tx_changes.send(change);
                    }
                    _ => {}
                }
            }
        });

        Arc::new(Self {
            rx,
            shutdown: tx_shutdown,
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<NetworkChange> {
        self.rx.resubscribe()
    }

    pub fn stop(&self) {
        let _ = self.shutdown.send(true);
    }
}
