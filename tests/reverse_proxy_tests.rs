use anyhow::{Context, Result};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming as IncomingBody};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use lemon::config::load_and_validate_config;
use lemon::shutdown::setup_shutdown_signal;
use lemon::start_services;
use reqwest;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;
use tempfile::tempdir;
use tokio::fs;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, watch};
use tokio::time::sleep;
use tracing::{error, info};

use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder as ConnectionBuilder;

mod common;

const BACKEND_RESPONSE_BODY: &str = "Hello from backend!";

// --- Backend Server Setup ---

struct BackendServer {
    base_url: String,
    shutdown_tx: oneshot::Sender<()>, // Use oneshot for simple backend shutdown
    _handle: tokio::task::JoinHandle<Result<()>>, // Change error type to Result<()>
}

// Simple backend request handler - Using Full<Bytes> for body
async fn handle_backend_request(
    _req: Request<IncomingBody>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::from(BACKEND_RESPONSE_BODY)))
        .unwrap())
}

// Helper to start the minimal backend server using hyper 1.x patterns
async fn setup_backend_server() -> Result<BackendServer> {
    common::ensure_logging_initialized();
    let port = portpicker::pick_unused_port().expect("Failed to find unused port for backend");
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    let listener = TcpListener::bind(addr).await?;
    info!("Backend listener bound to {}", addr);

    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    let handle = tokio::spawn(async move {
        let service = service_fn(handle_backend_request);
        let connection_builder = ConnectionBuilder::new(TokioExecutor::new());

        loop {
            tokio::select! {
                res = listener.accept() => {
                    match res {
                        Ok((stream, remote_addr)) => {
                            info!("Backend accepted connection from {}", remote_addr);
                            let io = TokioIo::new(stream);
                            let service = service.clone(); // Clone service for the connection
                            let connection_builder = connection_builder.clone(); // Clone builder
                            tokio::task::spawn(async move {
                                if let Err(err) = connection_builder
                                    .serve_connection(io, service)
                                    .await
                                {
                                    error!("Backend error serving connection from {}: {}", remote_addr, err);
                                }
                            });
                        },
                        Err(e) => {
                            error!("Backend failed to accept connection: {}", e);
                            // Optionally break or sleep on certain errors
                            sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    info!("Backend received shutdown signal, stopping accept loop.");
                    break;
                }
            }
        }
        info!("Backend accept loop finished.");
        Ok(())
    });

    Ok(BackendServer {
        base_url: format!("http://{}", addr),
        shutdown_tx,
        _handle: handle,
    })
}

// --- Lemon Proxy Server Setup ---

// Similar structure to TestServer in other tests
struct ProxyServer {
    shutdown_tx: watch::Sender<()>,
    acceptor_handle: std::thread::JoinHandle<Result<()>>,
    base_url: String,
    _temp_dir: tempfile::TempDir,
}

// Helper to write temp config (could be moved to common)
async fn write_temp_config(filename: &str, content: &str) -> Result<()> {
    fs::write(filename, content).await?;
    Ok(())
}

// Helper to set up and start the Lemon proxy server
async fn setup_proxy_server(target_url: &str) -> Result<ProxyServer> {
    common::ensure_logging_initialized();
    let temp_dir = tempdir()?;
    let proxy_port = portpicker::pick_unused_port().expect("Failed to find unused port for proxy");
    let listen_addr = format!("127.0.0.1:{}", proxy_port);

    let config_content = format!(
        r#"
[server.proxy_test]
listen_addr = "{}"
security = {{}} # Assuming no security headers needed for basic test

[server.proxy_test.handler]
type = "reverse_proxy"
target_url = "{}"
"#,
        listen_addr, target_url
    );

    let config_filename = temp_dir
        .path()
        .join(format!("test_proxy_config_{}.toml", proxy_port))
        .to_str()
        .unwrap()
        .to_string();

    write_temp_config(&config_filename, &config_content).await?;

    let config = load_and_validate_config(&config_filename).await?;
    let (shutdown_tx, shutdown_rx, _) = setup_shutdown_signal();

    let (_acme_state, acceptor_handle, _server_handles) =
        start_services(&config, shutdown_rx.clone()).await?;

    sleep(Duration::from_millis(200)).await;

    Ok(ProxyServer {
        shutdown_tx,
        acceptor_handle,
        base_url: format!("http://{}", listen_addr),
        _temp_dir: temp_dir,
    })
}

// Helper to shut down the Lemon proxy server (similar to shutdown_test_server)
async fn shutdown_proxy_server(server: ProxyServer) -> Result<()> {
    common::ensure_logging_initialized();
    info!("Sending shutdown signal for proxy server...");
    let _ = server.shutdown_tx.send(()).map_err(|e| {
        error!("Failed to send proxy shutdown signal: {}", e);
        anyhow::anyhow!("Failed to send proxy shutdown signal")
    });

    let handle = server.acceptor_handle;
    let join_result = tokio::task::spawn_blocking(move || handle.join()).await;

    match join_result {
        Ok(thread_result) => match thread_result {
            Ok(Ok(())) => info!("Proxy server acceptor thread joined successfully."),
            Ok(Err(e)) => {
                error!("Proxy server acceptor thread finished with error: {}", e);
                return Err(e.context("Acceptor thread failed"));
            }
            Err(e) => {
                error!("Proxy server acceptor thread panicked: {:?}", e);
                return Err(anyhow::anyhow!("Acceptor thread panicked"));
            }
        },
        Err(e) => {
            error!("Failed to join acceptor thread task: {}", e);
            return Err(e.into());
        }
    }

    info!("Proxy server shutdown complete.");
    Ok(())
}

// --- Test Case ---

#[tokio::test]
async fn test_reverse_proxy_basic() -> Result<()> {
    common::ensure_logging_initialized();

    // 1. Start the backend server
    let backend = setup_backend_server().await?;
    info!("Backend server started at {}", backend.base_url);

    // 2. Start the Lemon proxy server pointing to the backend
    let proxy = setup_proxy_server(&backend.base_url)
        .await
        .context("Failed to setup proxy server")?;
    info!("Proxy server started at {}", proxy.base_url);

    // Give backend and proxy a bit more time to fully initialize
    sleep(Duration::from_millis(300)).await;

    // 3. Make a request to the proxy
    let client = reqwest::Client::new();
    let proxy_url = format!("{}/", proxy.base_url);

    info!("Sending request to proxy: {}", proxy_url);
    let response = client
        .get(&proxy_url)
        .send()
        .await
        .context("Failed to send request to proxy")?;

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Proxy did not return OK status"
    );
    let body = response
        .text()
        .await
        .context("Failed to read response body from proxy")?;
    assert_eq!(
        body, BACKEND_RESPONSE_BODY,
        "Proxy response body did not match backend response body"
    );
    info!("Received correct response from proxy: {}", body);

    info!("Shutting down proxy server...");
    shutdown_proxy_server(proxy)
        .await
        .context("Failed to shutdown proxy server")?;

    info!("Shutting down backend server...");
    let _ = backend.shutdown_tx.send(());

    Ok(())
}
