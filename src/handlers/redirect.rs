use crate::common::BoxedBody;
use crate::common::full; // For response body
use crate::config::HandlerRedirectHttpsConfig; // Import the config struct
use crate::handlers::Handler; // Import the Handler trait
use anyhow::{Context, Result};
use async_trait::async_trait;
use hyper::header::{HeaderValue, LOCATION};
use hyper::{Method, Request, Response, StatusCode};
use url::Url;

#[derive(Debug)]
pub struct RedirectHttpsHandler {
    target_base_url: Url, // Store the parsed base URL
}

impl RedirectHttpsHandler {
    pub fn new(config: &HandlerRedirectHttpsConfig) -> Result<Self> {
        // Parsing and validation already happened in config::validate_config,
        // but we parse again here to store the Url type.
        // This assumes config validation already ensured it's a valid HTTPS base URL.
        let target_base_url = Url::parse(&config.target_base).with_context(|| {
            format!(
                "Invalid target_base URL in RedirectHttpsConfig: {}",
                config.target_base
            )
        })?;

        // Defensive check (already validated, but good practice)
        if target_base_url.scheme() != "https" {
            anyhow::bail!(
                "Internal error: RedirectHttpsHandler created with non-HTTPS target_base: {}",
                config.target_base
            );
        }

        Ok(Self { target_base_url })
    }
}

#[async_trait]
impl Handler for RedirectHttpsHandler {
    async fn handle(&self, req: Request<hyper::body::Incoming>) -> Result<Response<BoxedBody>> {
        // Only redirect GET and HEAD requests typically
        // Other methods might indicate API usage or forms that shouldn't be blindly redirected.
        // Returning Method Not Allowed is a reasonable default.
        if req.method() != Method::GET && req.method() != Method::HEAD {
            return Ok(Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(full("Method Not Allowed"))?);
        }

        // Construct the target URL
        let mut target_url = self.target_base_url.clone();

        // Append the original path and query
        if let Some(path_and_query) = req.uri().path_and_query() {
            target_url.set_path(path_and_query.path());
            target_url.set_query(path_and_query.query());
        }

        // Create the redirect response
        let location_header = HeaderValue::try_from(target_url.to_string())?;

        // Use 301 Moved Permanently for HTTP -> HTTPS redirection
        // 308 Permanent Redirect could also be used if preserving the method is critical,
        // but 301 is widely understood by browsers for this purpose.
        let response = Response::builder()
            .status(StatusCode::MOVED_PERMANENTLY)
            .header(LOCATION, location_header)
            .body(full("Redirecting to HTTPS"))?;

        Ok(response)
    }
}
