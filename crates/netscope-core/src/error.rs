#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("timeout: {0}")]
    Timeout(String),

    #[error("DNS error: {0}")]
    Dns(String),

    #[error("TCP error: {0}")]
    Tcp(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("platform error: {0}")]
    Platform(String),

    #[error("operation cancelled")]
    Cancelled,

    #[error("route not available: {0}")]
    RouteUnavailable(String),

    #[error("{0}")]
    Other(String),
}

pub type CoreResult<T> = std::result::Result<T, CoreError>;

pub fn is_timeout(err: &CoreError) -> bool {
    matches!(err, CoreError::Timeout(_)) || err_msg_contains(err, "timed out")
}

fn err_msg_contains(err: &CoreError, needle: &str) -> bool {
    err.to_string().to_lowercase().contains(needle)
}
