//! TLS handshake probe. Runs over a prepared TCP stream (or opens one).
//! Reports TLS version, cipher, certificate chain details, SNI, TLS alerts
//! and the precise failure stage so an interruption can be localised to
//! ClientHello / ServerHello / certificate validation / alert.
//! Certificate validation is always enabled for regular measurements,
//! so "certificate invalid" is a real diagnostic signal.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use netscope_core::models::{TlsResult, TlsStatus};
use rustls_pki_types::ServerName;
use tokio::net::TcpStream as TokioTcp;
use x509_parser::prelude::FromDer;

pub struct TlsProbe;

/// All inputs the TLS probe needs after the TCP stage.
pub struct TlsTarget<'a> {
    pub host: &'a str,
    pub port: u16,
    pub ip: IpAddr,
    /// Pre-connected stream from the TCP probe (skips a second connect).
    pub fixture_tcp: Option<TokioTcp>,
    pub timeout_ms: u64,
}

impl TlsProbe {
    pub async fn handshake(payload: TlsTarget<'_>) -> TlsResult {
        let started = Instant::now();
        let TlsTarget {
            host,
            port,
            ip,
            fixture_tcp,
            timeout_ms,
        } = payload;

        let mut owned = fixture_tcp;
        let stream = match owned.take() {
            Some(s) => Some(s),
            None => {
                let addr = std::net::SocketAddr::new(ip, port);
                let dur = std::time::Duration::from_millis(timeout_ms);
                match tokio::time::timeout(dur, tokio::net::TcpStream::connect(addr)).await {
                    Ok(Ok(s)) => Some(s),
                    _ => None,
                }
            }
        };

        let Some(stream) = stream else {
            let elapsed = started.elapsed().as_secs_f64() * 1000.0;
            return TlsResult {
                status: TlsStatus::ClosedEarly,
                handshake_ms: Some(elapsed),
                tls_version: None,
                cipher: None,
                sni: Some(host.to_string()),
                failure_stage: Some("tcp_connect_or_timeout_before_tls".into()),
                alert: None,
                client_hello_sent: false,
                certificate_subject: None,
                certificate_issued_by: None,
                certificate_valid_from: None,
                certificate_valid_to: None,
                certificate_sans: vec![],
                error: Some(format!(
                    "TCP stage failed in {:.0} ms (timeout/refused/reset)",
                    elapsed
                )),
            };
        };

        let mut res = handshake_rustls(stream, host, timeout_ms).await;
        res.handshake_ms = Some(started.elapsed().as_secs_f64() * 1000.0);
        res
    }
}

#[allow(clippy::too_many_arguments)]
fn err(
    status: TlsStatus,
    stage: &str,
    host: &str,
    error: String,
    alert: Option<String>,
    client_hello_sent: bool,
) -> TlsResult {
    TlsResult {
        status,
        handshake_ms: None,
        tls_version: None,
        cipher: None,
        sni: Some(host.to_string()),
        failure_stage: Some(stage.into()),
        alert,
        client_hello_sent,
        certificate_subject: None,
        certificate_issued_by: None,
        certificate_valid_from: None,
        certificate_valid_to: None,
        certificate_sans: vec![],
        error: Some(error),
    }
}

async fn handshake_rustls(stream: TokioTcp, host: &str, timeout_ms: u64) -> TlsResult {
    let tls_start = Instant::now();

    let config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store())
            .with_no_client_auth(),
    );

    let sni = match ServerName::try_from(host.to_string()) {
        Ok(s) => s.to_owned(),
        Err(e) => {
            return err(
                TlsStatus::Error,
                "sni_build",
                host,
                format!("sni build: {e}"),
                None,
                false,
            );
        }
    };

    let connector = tokio_rustls::TlsConnector::from(config);
    let dur = std::time::Duration::from_millis(timeout_ms);
    let session = match tokio::time::timeout(dur, connector.connect(sni, stream)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            let (status, stage, alert) = classify_tls_error(&e);
            return err(
                status,
                stage,
                host,
                e.to_string(),
                alert,
                true, // ClientHello is written before a TLS-level error arrives.
            );
        }
        Err(_) => {
            return err(
                TlsStatus::HandshakeTimeout,
                "handshake_timeout_no_server_response",
                host,
                "tls handshake timed out: no usable ServerHello".into(),
                None,
                true,
            );
        }
    };

    let (_tcp, conn) = session.get_ref();
    let tls_version = conn
        .protocol_version()
        .map(|v| format!("{v:?}"))
        .unwrap_or_else(|| "unknown".into());
    let cipher = conn
        .negotiated_cipher_suite()
        .map(|c| format!("{c:?}"))
        .unwrap_or_else(|| "unknown".into());

    let mut certificate_subject = None;
    let mut certificate_issued_by = None;
    let mut certificate_valid_from = None;
    let mut certificate_valid_to = None;
    let mut certificate_sans: Vec<String> = vec![];

    if let Some(certs) = conn.peer_certificates() {
        if let Some(first) = certs.first() {
            if let Ok(parsed) = x509_parser::certificate::X509Certificate::from_der(first.as_ref()) {
                let cert = parsed.1;
                certificate_subject = Some(cert.subject().to_string());
                certificate_issued_by = Some(cert.issuer().to_string());
                certificate_valid_from = validity(cert.validity().not_before);
                certificate_valid_to = validity(cert.validity().not_after);
                if let Some(sans) = cert.subject_alternative_name().ok().flatten() {
                    for name in sans.value.general_names.iter() {
                        match name {
                            x509_parser::extensions::GeneralName::DNSName(d) => {
                                certificate_sans.push(format!("dns:{d}"));
                            }
                            x509_parser::extensions::GeneralName::IPAddress(bytes) => {
                                certificate_sans.push(format!("ip:{}", format_ip(bytes)));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    TlsResult {
        status: TlsStatus::HandshakeOk,
        handshake_ms: Some(tls_start.elapsed().as_secs_f64() * 1000.0),
        tls_version: Some(tls_version),
        cipher: Some(cipher),
        sni: Some(host.to_string()),
        failure_stage: None,
        alert: None,
        client_hello_sent: true,
        certificate_subject,
        certificate_issued_by,
        certificate_valid_from,
        certificate_valid_to,
        certificate_sans,
        error: None,
    }
}

fn validity(t: x509_parser::time::ASN1Time) -> Option<String> {
    Some(t.to_datetime().to_string())
}

fn format_ip(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]),
        16 => {
            let o: [u8; 16] = bytes[0..16].try_into().unwrap_or([0u8; 16]);
            std::net::Ipv6Addr::from(o).to_string()
        }
        _ => format!("<{} bytes>", bytes.len()),
    }
}

/// Classify a failed handshake. We try the concrete rustls error first (it
/// carries the alert description and certificate error); fall back to text
/// heuristics for transports that only provide an io::Error string.
fn classify_tls_error(e: &std::io::Error) -> (TlsStatus, &'static str, Option<String>) {
    if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock {
        return (TlsStatus::HandshakeTimeout, "handshake_timeout_no_server_response", None);
    }
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        return (TlsStatus::ClosedEarly, "connection_closed_during_handshake", None);
    }
    if e.kind() == std::io::ErrorKind::ConnectionReset {
        return (TlsStatus::HandshakeReset, "reset_after_client_hello", None);
    }
    if let Some(inner) = e.get_ref() {
        if let Some(rustls_error) = inner.downcast_ref::<rustls::Error>() {
            return classify_rustls_error(rustls_error);
        }
        let text = inner.to_string().to_lowercase();
        return classify_tls_text(&text);
    }
    classify_tls_text(&e.to_string().to_lowercase())
}

fn classify_rustls_error(e: &rustls::Error) -> (TlsStatus, &'static str, Option<String>) {
    use rustls::AlertDescription as A;
    match e {
        rustls::Error::AlertReceived(alert) => {
            let name = alert_name(*alert);
            let status = match alert {
                A::BadCertificate
                | A::UnsupportedCertificate
                | A::CertificateRevoked
                | A::CertificateExpired
                | A::CertificateUnknown
                | A::CertificateUnobtainable
                | A::NoCertificate
                | A::CertificateRequired => TlsStatus::CertificateInvalid,
                A::CloseNotify | A::UserCanceled => TlsStatus::ClosedEarly,
                _ => TlsStatus::ProtocolError,
            };
            (status, "tls_alert", Some(name))
        }
        rustls::Error::InvalidCertificate(_) => (
            TlsStatus::CertificateInvalid,
            "certificate_validation",
            Some("bad_certificate".into()),
        ),
        rustls::Error::NoCertificatesPresented => (
            TlsStatus::CertificateInvalid,
            "certificate_validation",
            Some("no_certificate".into()),
        ),
        rustls::Error::InvalidMessage(_) => (TlsStatus::ProtocolError, "tls_message", None),
        rustls::Error::DecryptError => (
            TlsStatus::ProtocolError,
            "tls_decrypt",
            Some("decrypt_error".into()),
        ),
        rustls::Error::UnsupportedNameType => (TlsStatus::Error, "sni_build", None),
        _ => (TlsStatus::Error, "handshake", None),
    }
}

fn classify_tls_text(text: &str) -> (TlsStatus, &'static str, Option<String>) {
    if text.contains("alert") {
        let alert = if text.contains("handshakefailure") || text.contains("handshake failure") {
            "handshake_failure"
        } else if text.contains("protocolversion") || text.contains("protocol version") {
            "protocol_version"
        } else if text.contains("unknownca") || text.contains("unknown ca") {
            "unknown_ca"
        } else if text.contains("unexpectedmessage") || text.contains("unexpected message") {
            "unexpected_message"
        } else if text.contains("closenotify") || text.contains("close notify") {
            "close_notify"
        } else if text.contains("badcertificate") || text.contains("bad certificate") {
            "bad_certificate"
        } else {
            "tls_alert"
        };
        return (TlsStatus::ProtocolError, "tls_alert", Some(alert.into()));
    }
    if text.contains("certificate") || text.contains("unknownca") {
        return (
            TlsStatus::CertificateInvalid,
            "certificate_validation",
            Some("bad_certificate".into()),
        );
    }
    if text.contains("eof") || text.contains("closed") {
        return (TlsStatus::ClosedEarly, "connection_closed_during_handshake", None);
    }
    if text.contains("reset") {
        return (TlsStatus::HandshakeReset, "reset_after_client_hello", None);
    }
    if text.contains("timeout") || text.contains("timed out") {
        return (TlsStatus::HandshakeTimeout, "handshake_timeout_no_server_response", None);
    }
    (TlsStatus::Error, "handshake", None)
}

fn alert_name(a: rustls::AlertDescription) -> String {
    use rustls::AlertDescription as A;
    let s = match a {
        A::CloseNotify => "close_notify",
        A::UnexpectedMessage => "unexpected_message",
        A::BadRecordMac => "bad_record_mac",
        A::DecryptionFailed => "decryption_failed",
        A::RecordOverflow => "record_overflow",
        A::DecompressionFailure => "decompression_failure",
        A::HandshakeFailure => "handshake_failure",
        A::NoCertificate => "no_certificate",
        A::BadCertificate => "bad_certificate",
        A::UnsupportedCertificate => "unsupported_certificate",
        A::CertificateRevoked => "certificate_revoked",
        A::CertificateExpired => "certificate_expired",
        A::CertificateUnknown => "certificate_unknown",
        A::IllegalParameter => "illegal_parameter",
        A::UnknownCA => "unknown_ca",
        A::AccessDenied => "access_denied",
        A::DecodeError => "decode_error",
        A::DecryptError => "decrypt_error",
        A::ExportRestriction => "export_restriction",
        A::ProtocolVersion => "protocol_version",
        A::InsufficientSecurity => "insufficient_security",
        A::InternalError => "internal_error",
        A::InappropriateFallback => "inappropriate_fallback",
        A::UserCanceled => "user_canceled",
        A::NoRenegotiation => "no_renegotiation",
        A::MissingExtension => "missing_extension",
        A::UnsupportedExtension => "unsupported_extension",
        A::CertificateUnobtainable => "certificate_unobtainable",
        A::UnrecognisedName => "unrecognised_name",
        A::BadCertificateStatusResponse => "bad_certificate_status_response",
        A::BadCertificateHashValue => "bad_certificate_hash_value",
        A::UnknownPSKIdentity => "unknown_psk_identity",
        A::CertificateRequired => "certificate_required",
        A::NoApplicationProtocol => "no_application_protocol",
        A::EncryptedClientHelloRequired => "encrypted_client_hello_required",
        _ => return format!("{a:?}").to_lowercase(),
    };
    s.to_string()
}

/// A verifier used only for the SNI-filtering control test. Certificate trust
/// is intentionally ignored: the question is whether a TLS server answers to
/// this SNI at all, not whether its certificate is valid.
#[derive(Debug)]
struct NoCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Perform a TLS handshake with an arbitrary SNI against a fixed IP without
/// validating the certificate. Used to detect SNI-based filtering: if the
/// target SNI fails while a control SNI on the same IP succeeds, a middlebox
/// is likely reading SNI.
pub async fn sni_handshake(
    ip: IpAddr,
    port: u16,
    host: &str,
    timeout_ms: u64,
) -> TlsResult {
    let config = Arc::new(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
            .with_no_client_auth(),
    );
    let Ok(sni) = ServerName::try_from(host.to_string()) else {
        return err(TlsStatus::Error, "sni_build", host, "invalid SNI".into(), None, false);
    };
    let addr = std::net::SocketAddr::new(ip, port);
    let dur = std::time::Duration::from_millis(timeout_ms);
    let stream = match tokio::time::timeout(dur, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => {
            return err(
                TlsStatus::ClosedEarly,
                "tcp_connect_before_tls",
                host,
                "tcp connect failed".into(),
                None,
                false,
            )
        }
    };
    match tokio::time::timeout(dur, tokio_rustls::TlsConnector::from(config).connect(sni, stream)).await {
        Ok(Ok(_)) => TlsResult {
            status: TlsStatus::HandshakeOk,
            sni: Some(host.to_string()),
            client_hello_sent: true,
            ..Default::default()
        },
        Ok(Err(e)) => {
            let (status, stage, alert) = classify_tls_error(&e);
            err(status, stage, host, e.to_string(), alert, true)
        }
        Err(_) => err(
            TlsStatus::HandshakeTimeout,
            "handshake_timeout_no_server_response",
            host,
            "no ServerHello after ClientHello".into(),
            None,
            true,
        ),
    }
}

fn root_store() -> rustls::RootCertStore {
    let mut store = rustls::RootCertStore::empty();
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    store
}

/// Install the process-level rustls crypto provider. Must run before any
/// TLS client (probes/reqwest) is used; idempotent, so every entry point can
/// call it unconditionally.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
