use self::redirect::RedirectHttpsHandler;
use crate::common::BoxedBody;
use crate::config::{HandlerConfig, ServerConfig};
use anyhow::Result;
use async_trait::async_trait;
use hyper::{Request, Response};
use reverse_proxy::ReverseProxyHandler;
use rustls_acme::ResolvesServerCertAcme;
use std::sync::Arc;
use tracing::info;

// Define the core Handler trait
#[async_trait]
pub trait Handler: Send + Sync + 'static {
    async fn handle(&self, req: Request<hyper::body::Incoming>) -> Result<Response<BoxedBody>>;
}

// Implement Handler for Arc<dyn Handler> to allow wrappers like SecHeaders
// to wrap the trait object directly.
#[async_trait]
impl Handler for Arc<dyn Handler> {
    async fn handle(&self, req: Request<hyper::body::Incoming>) -> Result<Response<BoxedBody>> {
        // Delegate to the handler contained within the Arc
        (**self).handle(req).await
    }
}

// Type alias for convenience
pub type SharedHandler = Arc<dyn Handler>;

pub mod acme;
pub mod health;
pub mod redirect;
pub mod reverse_proxy;
pub mod security_wrappers;
pub mod static_files;

// Re-export handler implementations
pub use self::acme::AcmeRedirectHandler;
pub use self::health::HealthCheckHandler;
pub use self::static_files::StaticFileHandler;

// Default cache sizes
const DEFAULT_CONTENT_CACHE_MAX_FILE_BYTES: u64 = 1_048_576; // 1 MiB
const DEFAULT_CONTENT_CACHE_MAX_TOTAL_BYTES: u64 = 268_435_456; // 256 MiB

/// Creates a concrete `Handler` instance based on the provided configuration
/// and, unless disabled, wraps it with the security-header middleware.
pub fn create_handler(
    config: &HandlerConfig,
    server_cfg: &ServerConfig,
    _acme_resolver: Option<Arc<ResolvesServerCertAcme>>,
    _acme_domains: Option<Arc<Vec<String>>>,
) -> Result<SharedHandler> {
    // ----------------------------------------------------------------
    // 1. Build the concrete handler
    // ----------------------------------------------------------------
    let mut handler: SharedHandler = match config {
        HandlerConfig::Static(static_cfg) => {
            let max_file_bytes = static_cfg
                .content_cache_max_file_bytes
                .unwrap_or(DEFAULT_CONTENT_CACHE_MAX_FILE_BYTES);
            let max_total_bytes = static_cfg
                .content_cache_max_total_bytes
                .unwrap_or(DEFAULT_CONTENT_CACHE_MAX_TOTAL_BYTES);

            info!(
                www_root        = %static_cfg.www_root.display(),
                max_file_cache  = max_file_bytes,
                max_total_cache = max_total_bytes,
                "Creating StaticFileHandler"
            );

            Arc::new(StaticFileHandler::new(
                static_cfg.www_root.clone(),
                max_file_bytes,
                max_total_bytes,
            ))
        }

        HandlerConfig::HealthCheck(_) => Arc::new(HealthCheckHandler::new()),

        HandlerConfig::ReverseProxy(proxy_cfg) => {
            Arc::new(ReverseProxyHandler::new(&proxy_cfg.target_url)?)
        }

        HandlerConfig::RedirectHttps(redirect_cfg) => {
            info!(
                target_base = %redirect_cfg.target_base,
                "Creating RedirectHttpsHandler"
            );
            Arc::new(RedirectHttpsHandler::new(redirect_cfg)?)
        }
    };

    // ----------------------------------------------------------------
    // 2. Conditionally wrap with the SecHeaders, if needed
    // ----------------------------------------------------------------
    if server_cfg.security.add_default_headers.unwrap_or(true) {
        let wrapped = security_wrappers::SecHeaders::new(
            handler.clone(),
            Arc::new(server_cfg.security.clone()),
            server_cfg.tls.is_some(), // HTTPS?
        );
        handler = Arc::new(wrapped);
    }

    // ----------------------------------------------------------------
    // 3. Return the handler
    // ----------------------------------------------------------------
    Ok(handler)
}
