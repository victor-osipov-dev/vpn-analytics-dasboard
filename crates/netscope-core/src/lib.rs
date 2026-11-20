pub mod error;
pub mod models;
pub mod settings;

pub use error::CoreError;
pub use settings::AppSettings;

pub type Result<T> = std::result::Result<T, CoreError>;

pub fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub fn now_utc() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}

pub fn now_rfc3339() -> String {
    now_utc().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub fn rfc3339_days_ago(days: u32) -> String {
    let back = chrono::Duration::days(days as i64);
    match now_utc().checked_sub_signed(back) {
        Some(t) => t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        None => String::new(),
    }
}
