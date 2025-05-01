use anyhow::{Context, Result};
use lemon::config::load_and_validate_config;
use lemon::shutdown::setup_shutdown_signal;
use lemon::start_services;
use portpicker::pick_unused_port;
use rcgen::{CertificateParams, DistinguishedName, Ia5String, KeyPair, PKCS_RSA_SHA256, SanType};
use reqwest;
use std::net::IpAddr;
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
    // config_path: std::path::PathBuf, // We might not need this if we don't explicitly clean up
}

// Helper function to gracefully shut down the test server
async fn shutdown_test_server(server: TestServer) -> Result<()> {
    info!("Sending shutdown signal for manual TLS server...");
    let _ = server.shutdown_tx.send(()).map_err(|e| {
        error!("Failed to send shutdown signal: {}", e);
        anyhow::anyhow!("Failed to send shutdown signal")
    });

    // Wait for the acceptor thread to finish
    // Use spawn_blocking because std::thread::JoinHandle::join is blocking
    let handle = server.acceptor_handle;
    tokio::task::spawn_blocking(move || match handle.join() {
        Ok(Ok(())) => info!("Manual TLS server acceptor thread joined successfully."),
        Ok(Err(e)) => error!(
            "Manual TLS server acceptor thread finished with error: {}",
            e
        ),
        Err(e) => error!("Manual TLS server acceptor thread panicked: {:?}", e),
    })
    .await?;

    info!("Manual TLS test server shutdown complete.");
    Ok(())
}

#[tokio::test]
async fn test_manual_tls_serves_request() -> Result<()> {
    // 1. Setup: Temp dir, cert/key, config
    let temp_dir = tempdir().context("Failed to create temp dir")?;
    let dir_path = temp_dir.path();

    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.subject_alt_names = vec![
        SanType::DnsName(Ia5String::try_from("localhost".to_string())?),
        SanType::IpAddress(IpAddr::V4("127.0.0.1".parse()?)),
    ];
    let key_pair =
        KeyPair::generate_for(&PKCS_RSA_SHA256).context("Failed to generate key pair")?;
    let cert = params
        .self_signed(&key_pair)
        .context("Failed to self-sign certificate")?;
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    let cert_path = dir_path.join("test.crt");
    let key_path = dir_path.join("test.key");
    fs::write(&cert_path, cert_pem)
        .await
        .context("Failed to write temp cert")?;
    fs::write(&key_path, key_pem)
        .await
        .context("Failed to write temp key")?;

    let port = pick_unused_port().context("Failed to pick unused port")?;
    let listen_addr_str = format!("127.0.0.1:{}", port);
    let config_content = format!(
        r#"
[server.manual_tls_serve_test]
listen_addr = "{}"
security = {{}}

[server.manual_tls_serve_test.tls]
type = "manual"
certificate_file = "{}"
key_file = "{}"

[server.manual_tls_serve_test.handler]
type = "health_check"
"#,
        listen_addr_str,
        cert_path.display(),
        key_path.display()
    );

    let config_path = dir_path.join("lemon.toml");
    let config_path_buf = config_path.to_path_buf();
    fs::write(&config_path, config_content)
        .await
        .context("Failed to write temp config")?;

    // 2. Load config and start server using start_services
    println!(
        "[Manual TLS Test] Starting server with config: {}",
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
        // config_path: config_path_buf, // Not storing path for now
    };

    // Give the server a moment to start up
    // This is a potential source of flakiness, but simplest for now.
    sleep(Duration::from_millis(500)).await;

    // 3. Make HTTPS Request
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // Allow self-signed cert
        .build()?;

    let url = format!("https://{}/", listen_addr_str);
    println!("Making request to: {}", url);

    let response = client
        .get(&url)
        .send()
        .await
        .context("HTTP request failed")?;
    println!("Received response: {:?}", response);

    // 4. Assertions
    assert!(
        response.status().is_success(),
        "Request failed with status: {}",
        response.status()
    );
    let body = response
        .text()
        .await
        .context("Failed to read response body")?;
    assert!(
        body.contains("lemon is healthy"),
        "Response body did not contain 'Healthy'. Got: '{}'",
        body
    );

    // 5. Cleanup - Replace abort with shutdown call
    println!("[Manual TLS Test] Shutting down server...");
    shutdown_test_server(test_server).await?;
    println!("[Manual TLS Test] Server shutdown complete.");

    // temp_dir cleans up automatically

    Ok(())
}
