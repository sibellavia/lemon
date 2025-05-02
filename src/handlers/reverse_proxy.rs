use crate::common::BoxedBody;
use crate::handlers::Handler;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;

use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Request, Response, Uri, header};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use std::io;

use tracing::{debug, error, instrument};

// --- Client Setup ---
// Define the connector type that supports both HTTP and HTTPS
type HttpsConnector = hyper_rustls::HttpsConnector<HttpConnector>;
// Configure the Hyper client
type HttpClient = Client<HttpsConnector, Incoming>;

#[derive(Debug, Clone)]
pub struct ReverseProxyHandler {
    target_uri: Arc<Uri>, // parsed URI
    client: HttpClient,
}

impl ReverseProxyHandler {
    pub fn new(target_url: &str) -> Result<Self> {
        let target_uri = target_url
            .parse::<Uri>()
            .with_context(|| format!("Invalid target URL for reverse proxy: {}", target_url))?;

        if target_uri.scheme().is_none() || target_uri.authority().is_none() {
            return Err(anyhow!(
                "Target URL must be absolute (include scheme and host): {}",
                target_url
            ));
        }

        // --- Create a TLS-aware connector ---
        // Prepare the rustls client config with root certificates.
        // Use rustls_native_certs to load platform's native root certificates.
        let mut root_cert_store = rustls::RootCertStore::empty();
        // load_native_certs() returns a CertificateResult struct.
        let cert_result = rustls_native_certs::load_native_certs();

        // Log any errors encountered during loading.
        for err in &cert_result.errors {
            error!("Error loading native root certificate: {}", err);
        }

        // Add successfully loaded certificates to the store.
        for cert in cert_result.certs {
            // Errors adding individual certs are logged but not fatal.
            if let Err(e) = root_cert_store.add(cert) {
                error!("Failed to add native root certificate to store: {}", e);
            }
        }

        // Log if no certificates were loaded, which might be unexpected.
        if root_cert_store.is_empty() {
            error!("No native root certificates could be loaded.");
            // Depending on requirements, you might want to return an error here
            // if a root store is essential for the proxy to function.
            // return Err(anyhow!("No native root certificates could be loaded"));
        }

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();

        // Build the HttpsConnector
        let https_connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_http1()
            .build();

        // Build the client
        // The client uses TokioExecutor and accepts Incoming request bodies.
        let client: HttpClient = Client::builder(TokioExecutor::new()).build(https_connector);

        Ok(ReverseProxyHandler {
            target_uri: Arc::new(target_uri),
            client,
        })
    }
}

#[async_trait]
impl Handler for ReverseProxyHandler {
    #[instrument(skip(self, req), fields(uri = %req.uri(), method = %req.method()))]
    async fn handle(&self, mut req: Request<Incoming>) -> Result<Response<BoxedBody>> {
        debug!(target = %self.target_uri, "Proxying request");

        // --- 1. Modify the request URI ---
        let original_uri = req.uri().clone();
        let mut uri_builder = Uri::builder()
            .scheme(self.target_uri.scheme().unwrap().clone())
            .authority(self.target_uri.authority().unwrap().clone());

        // Preserve path and query from the original request
        if let Some(pq) = original_uri.path_and_query() {
            uri_builder = uri_builder.path_and_query(pq.clone());
        }

        let target_req_uri = uri_builder
            .build()
            .context("Failed to build target URI for proxy request")?;

        *req.uri_mut() = target_req_uri;

        // --- 2. Update Headers ---
        let headers = req.headers_mut();
        // Set the Host header to the target authority
        headers.insert(
            header::HOST,
            self.target_uri.authority().unwrap().as_str().parse()?,
        );
        // Remove hyper's connection headers, let the client handle connection management
        headers.remove(header::CONNECTION);
        headers.remove("keep-alive");

        // TODO: Add X-Forwarded-For, X-Forwarded-Proto, etc. (Requires access to original remote addr)

        // --- 3. Send Request to Backend ---
        // Remove the buffering logic. Pass the request with its streaming body directly.
        // The client is configured to handle Incoming bodies.
        debug!("Sending request to backend: {:?}", req);
        let backend_response_result = self.client.request(req).await;

        // --- 4. Process Backend Response ---
        // Revert to using a match block for explicit error handling and propagation.
        match backend_response_result {
            Ok(backend_res) => {
                debug!(status = %backend_res.status(), "Received response from backend");
                // Proxy the response back, keeping the body as a stream.
                Ok(backend_res.map(|b| {
                    b.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
                        .boxed()
                }))
            }
            Err(e) => {
                // Convert hyper::Error to anyhow::Error and propagate it.
                let proxy_error =
                    anyhow!(e).context(format!("Proxy request to {} failed", self.target_uri));
                error!("{:?}", proxy_error);
                // Return Err to signal failure, letting the caller handle the HTTP response.
                Err(proxy_error)
            }
        }
    }
}
