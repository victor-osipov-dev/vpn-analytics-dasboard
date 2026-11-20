//! CLI: `cargo run -p netscope-desktop --bin netscope-dnscheck`
//! Prints the same DNS hygiene report the UI shows.

#[path = "../dns_probe.rs"]
mod dns_probe;

use netscope_core::settings::AppSettings;

#[tokio::main]
async fn main() {
    netscope_probes::tls::install_crypto_provider();

    let snapshot = match netscope_network::Discovery::snapshot() {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("snapshot failed: {e}");
            None
        }
    };
    let settings = AppSettings::default();
    let diag = dns_probe::diagnose(snapshot.as_ref(), &settings).await;
    println!("{}", serde_json::to_string_pretty(&diag).expect("json"));
}
