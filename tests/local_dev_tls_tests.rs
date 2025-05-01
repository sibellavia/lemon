use anyhow::{Context, Result};
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
    info!("Sending shutdown signal for local dev server...");
    let _ = server.shutdown_tx.send(()).map_err(|e| {
        error!("Failed to send shutdown signal: {}", e);
        anyhow::anyhow!("Failed to send shutdown signal")
    });

    // Wait for the acceptor thread to finish
    // Use spawn_blocking because std::thread::JoinHandle::join is blocking
    let handle = server.acceptor_handle;
    tokio::task::spawn_blocking(move || match handle.join() {
        Ok(Ok(())) => info!("Local dev server acceptor thread joined successfully."),
        Ok(Err(e)) => error!(
            "Local dev server acceptor thread finished with error: {}",
            e
        ),
        Err(e) => error!("Local dev server acceptor thread panicked: {:?}", e),
    })
    .await?;

    info!("Local dev test server shutdown complete.");
    Ok(())
}

#[tokio::test]
async fn test_local_dev_tls_serves_request() -> Result<()> {
    // 1. Setup: Temp dir, config with local_dev handler
    let temp_dir = tempdir().context("Failed to create temp dir")?;
    let dir_path = temp_dir.path();

    let port = pick_unused_port().context("Failed to pick unused port")?;
    let listen_addr_str = format!("127.0.0.1:{}", port);

    let config_content = format!(
        r#"
[server.local_dev_server]
listen_addr = "{}"
security = {{}}

[server.local_dev_server.tls]
type = "local_dev" # Use the new type

[server.local_dev_server.handler]
type = "health_check"
"#,
        listen_addr_str
    );

    let config_path = dir_path.join("lemon.toml");
    let config_path_buf = config_path.to_path_buf();
    fs::write(&config_path, config_content)
        .await
        .context("Failed to write temp config")?;

    // 2. Load config and start server using start_services
    println!(
        "[LocalDev Test] Starting server with config: {}",
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

    // 3. Make HTTPS Requests (accepting invalid certs)
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // Allow self-signed cert
        .build()?;

    // Test against 127.0.0.1
    let url_ip = format!("https://{}/", listen_addr_str);
    println!("[LocalDev Test] Making request to: {}", url_ip);
    let response_ip = client
        .get(&url_ip)
        .send()
        .await
        .context("HTTPS request to IP failed")?;
    println!("[LocalDev Test] Received IP response: {:?}", response_ip);
    assert!(
        response_ip.status().is_success(),
        "Request to IP failed with status: {}",
        response_ip.status()
    );
    let body_ip = response_ip
        .text()
        .await
        .context("Failed to read IP response body")?;
    assert!(
        body_ip.contains("lemon is healthy"),
        "IP Response body did not contain 'Healthy'. Got: '{}'",
        body_ip
    );

    // Test against localhost
    let url_host = format!("https://localhost:{}/", port);
    println!("[LocalDev Test] Making request to: {}", url_host);
    let response_host = client
        .get(&url_host)
        .send()
        .await
        .context("HTTPS request to localhost failed")?;
    println!(
        "[LocalDev Test] Received localhost response: {:?}",
        response_host
    );
    assert!(
        response_host.status().is_success(),
        "Request to localhost failed with status: {}",
        response_host.status()
    );
    let body_host = response_host
        .text()
        .await
        .context("Failed to read localhost response body")?;
    assert!(
        body_host.contains("lemon is healthy"),
        "Localhost Response body did not contain 'Healthy'. Got: '{}'",
        body_host
    );

    // 5. Cleanup - Replace abort with shutdown call
    println!("[LocalDev Test] Shutting down server...");
    shutdown_test_server(test_server).await?; // Call the new function
    println!("[LocalDev Test] Server shutdown complete.");

    Ok(())
}
