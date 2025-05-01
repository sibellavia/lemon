use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::body::Bytes;
use hyper::http::{HeaderName, HeaderValue};
use std::io;

// Type alias for the response body
pub type BoxedBody = BoxBody<Bytes, std::io::Error>;

// Helper function to create an empty body
pub fn empty() -> BoxedBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

// Helper function to create a full body
pub fn full<T: Into<Bytes>>(chunk: T) -> BoxedBody {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

/// Helper function to check for common Hyper errors that can usually be ignored
/// Used to avoid spamming logs during normal operation or client disconnects.
pub fn should_ignore_hyper_error(err: &dyn std::error::Error) -> bool {
    let err_str = err.to_string();
    err_str.contains("connection reset by peer")
        || err_str.contains("unexpected EOF")
        || err_str.contains("connection closed")
        || err_str.contains("broken pipe")
        || err_str.contains("operation canceled")
}

/// Helper function to check for common TLS handshake errors
pub fn should_ignore_tls_error(err: &std::io::Error) -> bool {
    let err_str = err.to_string();
    // Protocol mismatch (HTTP on HTTPS port), client cert issues, or normal disconnects
    err_str.contains("unexpected message")
        || err_str.contains("invalid certificate")
        || err_str.contains("connection reset by peer")
        || err_str.contains("connection closed")
        || err_str.contains("broken pipe")
}

/// Helper function to check for transient TCP accept errors, including FD limits
pub fn is_transient_accept_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    )
    // Add check for file descriptor limits
    || err.raw_os_error().is_some_and(|code| {
        code == libc::EMFILE || code == libc::ENFILE
    })
}

/// Helper function to check specifically for file descriptor exhaustion errors
pub fn is_fd_exhaustion_error(err: &io::Error) -> bool {
    err.raw_os_error()
        .is_some_and(|code| code == libc::EMFILE || code == libc::ENFILE)
}

// --- Security Commons ---

pub const H_XCTO: HeaderName = HeaderName::from_static("x-content-type-options");
pub const H_XFO: HeaderName = HeaderName::from_static("x-frame-options");

pub static V_NOSNIFF: HeaderValue = HeaderValue::from_static("nosniff");
pub static V_DENY: HeaderValue = HeaderValue::from_static("DENY");
pub static V_SAMEORIGIN: HeaderValue = HeaderValue::from_static("SAMEORIGIN");

pub fn build_hsts(cfg: &crate::config::SecurityConfig) -> HeaderValue {
    // Build string once; small, so an alloc here is negligible and happens at startup
    let mut v = format!("max-age={}", cfg.hsts_max_age.unwrap_or(31_536_000));
    if cfg.hsts_include_subdomains.unwrap_or(true) {
        v.push_str("; includeSubDomains");
    }
    if cfg.hsts_preload.unwrap_or(false) {
        v.push_str("; preload");
    }
    HeaderValue::from_str(&v).expect("valid HSTS header")
}
