// Internal imports
use crate::common::{BoxedBody, empty, full};
use crate::handlers::Handler;

// HTTP and body handling
use hyper::{Method, Request, Response, StatusCode, body::Incoming, header};

// Logging & Error Handling
use anyhow::{Context, Result};
use async_trait::async_trait;

#[derive(Debug, Clone)]
pub struct HealthCheckHandler {}

impl Default for HealthCheckHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthCheckHandler {
    pub fn new() -> Self {
        HealthCheckHandler {}
    }
}

#[async_trait]
impl Handler for HealthCheckHandler {
    async fn handle(&self, req: Request<Incoming>) -> Result<Response<BoxedBody>> {
        // Call the internal logic
        match health_service_internal(req).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                // Log the error from the internal function
                tracing::error!("Error in health service handler: {:?}", e);
                // Construct an internal server error response
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

pub async fn health_service_internal(
    req: Request<Incoming>,
) -> anyhow::Result<Response<BoxedBody>> {
    if *req.method() != Method::GET {
        tracing::info!("Health check received non-GET request: {}", req.method());
        let response = Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header(header::ALLOW, "GET")
            .body(empty())
            .context("Failed to build 405 response")?;
        return Ok(response);
    }

    tracing::info!("Health check successful");
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full("lemon is healthy"))
        .context("Failed to build 200 response")?;
    Ok(response)
}
