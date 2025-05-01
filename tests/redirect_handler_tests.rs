use anyhow::{Context, Result};
use hyper::StatusCode;
use hyper::header::LOCATION;
use lemon::config::load_and_validate_config;
use lemon::shutdown::setup_shutdown_signal;
use lemon::start_services;
use portpicker::pick_unused_port;
use reqwest;
use tempfile::tempdir;
use tokio::fs;
use tokio::time::{Duration, sleep};
use tracing::{error, info};

// Helper struct to manage server state
#[derive(Debug)]
struct TestServer {
    shutdown_tx: tokio::sync::watch::Sender<()>,
    acceptor_handle: std::thread::JoinHandle<Result<()>>,
    _temp_dir: tempfile::TempDir,
}

// Helper function to gracefully shut down the test server
async fn shutdown_test_server(server: TestServer) -> Result<()> {
    info!("Sending shutdown signal for redirect server...");
    let _ = server.shutdown_tx.send(()).map_err(|e| {
        error!("Failed to send shutdown signal: {}", e);
        anyhow::anyhow!("Failed to send shutdown signal")
    });

    // Wait for the acceptor thread to finish
    // Use spawn_blocking because std::thread::JoinHandle::join is blocking
    let handle = server.acceptor_handle;
    tokio::task::spawn_blocking(move || match handle.join() {
        Ok(Ok(())) => info!("Redirect server acceptor thread joined successfully."),
        Ok(Err(e)) => error!("Redirect server acceptor thread finished with error: {}", e),
        Err(e) => error!("Redirect server acceptor thread panicked: {:?}", e),
    })
    .await?;

    info!("Redirect test server shutdown complete.");
    Ok(())
}

#[tokio::test]
async fn test_redirect_handler() -> Result<()> {
    // 1. Setup: Temp dir, config with redirect handler
    let temp_dir = tempdir().context("Failed to create temp dir")?;
    let dir_path = temp_dir.path();

    let port = pick_unused_port().context("Failed to pick unused port")?;
    let listen_addr_str = format!("127.0.0.1:{}", port);
    let target_base = "https://test-target.com"; // Target for redirection

    let config_content = format!(
        r#"
[server.http_redirector]
listen_addr = "{}"
security = {{}}
# No tls block = HTTP

[server.http_redirector.handler]
type = "redirect_https"
target_base = "{}"
"#,
        listen_addr_str, target_base
    );

    let config_path = dir_path.join("lemon.toml");
    let config_path_buf = config_path.to_path_buf();
    fs::write(&config_path, config_content)
        .await
        .context("Failed to write temp config")?;

    // 2. Load config and start server using start_services
    println!(
        "[Redirect Test] Starting server with config: {}",
        config_path_buf.display()
    );
    let config = load_and_validate_config(config_path_buf.to_str().unwrap()).await?;
    let (shutdown_tx, shutdown_rx, _) = setup_shutdown_signal();

    let (_acme_state, acceptor_handle, _server_handles) =
        start_services(&config, shutdown_rx.clone()).await?;

    // Create TestServer instance
    let test_server = TestServer {
        shutdown_tx,
        acceptor_handle,
        _temp_dir: temp_dir,
    };

    // Give the server a moment to start up
    sleep(Duration::from_millis(500)).await;

    // 3. Make HTTP Request (without following redirects)
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none()) // DO NOT follow redirects
        .build()?;

    let request_path = "/some/path?query=value&another=true";
    let url = format!("http://{}{}", listen_addr_str, request_path);
    let expected_redirect_url = format!("{}{}", target_base, request_path);

    println!("[Redirect Test] Making request to: {}", url);
    let response = client
        .get(&url)
        .send()
        .await
        .context("HTTP request failed")?;
    println!(
        "[Redirect Test] Received response status: {:?}",
        response.status()
    );
    println!(
        "[Redirect Test] Received response headers: {:?}",
        response.headers()
    );

    // 4. Assertions
    assert_eq!(
        response.status(),
        StatusCode::MOVED_PERMANENTLY, // Check for 301
        "Expected status code 301 Moved Permanently"
    );

    let location_header = response
        .headers()
        .get(LOCATION)
        .context("Response missing Location header")?
        .to_str()
        .context("Location header is not valid UTF-8")?;

    assert_eq!(
        location_header, expected_redirect_url,
        "Location header did not match expected redirect URL"
    );

    // 5. Cleanup - Replace abort with shutdown call
    println!("[Redirect Test] Shutting down server...");
    shutdown_test_server(test_server).await?; // Call the new function
    println!("[Redirect Test] Server shutdown complete.");

    Ok(())
}
