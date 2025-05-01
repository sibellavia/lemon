/// Request handler that runs *during* an incoming HTTP request on port 80
///
/// Checks if the request is an ACME challenge and, if so, use the ACME resolver
/// OR redirect the request to HTTPS.
///
/// It consumes the ACME resolver.
// Internal imports
use crate::common::{BoxedBody, empty, full};
use crate::handlers::Handler;

// Standard library imports
use std::sync::Arc;

// HTTP and body handling
use anyhow::Result;
use async_trait::async_trait;
use hyper::{Request, Response, StatusCode, body::Incoming, header};

// TLS and ACME
use rustls_acme::ResolvesServerCertAcme;

// Logging
use tracing::{error, info};

// Struct to hold ACME resolver and domains
#[derive(Clone)]
pub struct AcmeRedirectHandler {
    pub resolver: Arc<ResolvesServerCertAcme>,
    pub https_domains: Arc<Vec<String>>,
}

#[async_trait]
impl Handler for AcmeRedirectHandler {
    async fn handle(&self, req: Request<hyper::body::Incoming>) -> Result<Response<BoxedBody>> {
        match handle_acme_or_redirect_internal(
            req,
            Arc::clone(&self.resolver),
            Arc::clone(&self.https_domains),
        )
        .await
        {
            Ok(resp) => Ok(resp),
            Err(e) => {
                error!("Error in ACME/Redirect handler: {}", e);
                let body = full("Internal Server Error");
                let resp = Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(body)
                    .unwrap();
                Ok(resp)
            }
        }
    }
}

/// **INTERNAL function**: Handles HTTP requests by either processing ACME challenges or redirecting to HTTPS.
/// Renamed from handle_acme_or_redirect.
///
/// # Arguments
/// * `req` - The incoming HTTP request
/// * `resolver` - ACME certificate resolver
/// * `https_domains` - List of domains configured for HTTPS redirection
///
/// # Returns
/// Returns a Result containing the HTTP response with a BoxedBody, or a hyper::Error.
async fn handle_acme_or_redirect_internal(
    req: Request<Incoming>,
    resolver: Arc<ResolvesServerCertAcme>,
    https_domains: Arc<Vec<String>>,
) -> Result<Response<BoxedBody>, hyper::Error> {
    const ACME_CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";
    let path = req.uri().path();

    // --- Handle ACME HTTP-01 Challenge ---
    if let Some(token) = path.strip_prefix(ACME_CHALLENGE_PREFIX) {
        info!("handling ACME challenge request for token: {}", token);
        let token_trimmed = token.trim_matches('/');

        match resolver.get_http_01_key_auth(token_trimmed) {
            // Pass token
            Some(key_authorization) => {
                info!(
                    "ACME challenge key authorization found for token: {}",
                    token_trimmed
                );
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/plain")
                    .body(full(key_authorization))
                    .unwrap())
            }
            None => {
                // This might happen if the request arrives before the state machine
                // has registered the challenge, or if the token is invalid.
                error!(
                    "ACME challenge token not found in resolver: {}",
                    token_trimmed
                );
                Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .header(header::CONTENT_TYPE, "text/plain")
                    .body(full("ACME challenge token not found"))
                    .unwrap())
            }
        }
    } else {
        // --- Redirect all other HTTP requests to HTTPS ---
        info!("Request is not ACME challenge, redirecting HTTP request to HTTPS.");
        let host = req
            .headers()
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .and_then(|h_str| {
                https_domains
                    .iter()
                    .find(|domain| *domain == h_str)
                    .map(|s| s.as_str())
            })
            .or_else(|| https_domains.first().map(|s| s.as_str()));

        let target_host = match host {
            Some(h) => h,
            None => {
                error!(
                    "Error: Could not determine target host for HTTPS redirect. `https_domains` might be empty."
                );
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(full(
                        "Configuration error: Cannot determine redirect target.",
                    ))
                    .unwrap());
            }
        };

        let uri = req.uri();
        let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
        let https_uri = format!("https://{}{}", target_host, path_and_query);

        info!("Redirecting HTTP request to: {}", https_uri);

        Ok(Response::builder()
            .status(StatusCode::PERMANENT_REDIRECT)
            .header(header::LOCATION, https_uri)
            .body(empty())
            .unwrap())
    }
}
