use crate::common::{full, should_ignore_hyper_error, should_ignore_tls_error};
use crate::handlers::SharedHandler;
use anyhow::Result;
use hyper::header;
use hyper::header::HeaderValue;
use hyper::rt::{Read as HyperRead, Write as HyperWrite};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

// --- IO Handling --- //

// Define a marker trait for Boxed I/O
trait ServerIo: HyperRead + HyperWrite + Send + Unpin {}

// Implement the marker trait for anything that satisfies the bounds.
impl<T> ServerIo for T where T: HyperRead + HyperWrite + Send + Unpin {}

// Type alias for the boxed I/O type using the marker trait
type BoxedIo = Box<dyn ServerIo>;

// --- Connection Handling Logic --- //

/// Handles a single accepted TCP connection.
/// Performs TLS handshake if acceptor is provided, sets up Hyper service, and serves the connection.
/// This function is designed to be spawned in its own Tokio task.
#[allow(clippy::too_many_arguments)] // Accept many args for clarity here
pub async fn handle_connection(
    stream: TcpStream,
    remote_addr: SocketAddr,
    handler: SharedHandler, // Handler for business logic
    tls_acceptor: Option<TlsAcceptor>,
    mut conn_shutdown_rx: watch::Receiver<()>, // Receiver for graceful shutdown
    server_name: String,                       // Name of the server instance for logging
) {
    // --- Handle TLS Handshake (if HTTPS) ---
    let io_result: Result<BoxedIo, ()> = if let Some(acceptor) = tls_acceptor {
        match acceptor.accept(stream).await {
            Ok(tls_stream) => Ok(Box::new(TokioIo::new(tls_stream))),
            Err(e) => {
                let mut specific_error_handled = false;
                if let Some(inner_err) = e.get_ref() {
                    if let Some(rustls_err) = inner_err.downcast_ref::<rustls::Error>() {
                        if matches!(
                            rustls_err,
                            rustls::Error::AlertReceived(rustls::AlertDescription::UnknownCA)
                        ) {
                            warn!(server_name = %server_name, remote = %remote_addr, "TLS handshake error (likely staging cert): {:?} (UnknownCA expected)", e);
                            specific_error_handled = true;
                        }
                    }
                }
                if !specific_error_handled && !should_ignore_tls_error(&e) {
                    error!(server_name = %server_name, remote = %remote_addr, "Error during TLS handshake: {:?}", e);
                }
                Err(()) // Indicate handshake failure
            }
        }
    } else {
        // Plain HTTP
        Ok(Box::new(TokioIo::new(stream)))
    };

    // Proceed only if IO setup (including TLS handshake) succeeded
    if let Ok(io) = io_result {
        // --- Create the Hyper Service ---
        let server_name_for_service = server_name.clone();
        let service = service_fn(move |req: Request<hyper::body::Incoming>| {
            let handler_service_clone = Arc::clone(&handler);
            let server_name_for_async_block = server_name_for_service.clone();
            async move {
                let result = handler_service_clone.handle(req).await;
                let mut response = match result {
                    Ok(resp) => resp,
                    Err(e) => {
                        error!(server_name = %server_name_for_async_block, "Handler error: {:?}", e);
                        Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(full("Internal Server Error")) // Use common::full
                            .unwrap()
                    }
                };

                // Add the Server header
                response.headers_mut().insert(
                    header::SERVER,
                    HeaderValue::from_static("Lemon"), // TODO: Maybe include version?
                );

                Ok::<_, hyper::Error>(response)
            }
        });

        // --- Serve the Connection --- //
        let builder = auto::Builder::new(TokioExecutor::new());
        let conn_fut = builder.serve_connection_with_upgrades(io, service);

        // --- Graceful Shutdown for the Connection --- //
        let shutdown_future = async {
            conn_shutdown_rx.changed().await.ok();
        };
        tokio::pin!(shutdown_future);

        let conn_result = tokio::select! {
            biased;
            _ = &mut shutdown_future => {
                info!(server_name = %server_name, remote = %remote_addr, "Graceful shutdown triggered for connection.");
                Ok(())
            },
            res = conn_fut => res,
        };

        // Log connection errors
        if let Err(err) = conn_result {
            if !should_ignore_hyper_error(err.as_ref()) {
                error!(server_name = %server_name, remote = %remote_addr, "Error serving connection: {:?}", err);
            }
        }
    } // else: IO setup/TLS handshake failed, error already logged.
}
