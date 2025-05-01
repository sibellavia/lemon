use anyhow::Result;
use std::time::Duration;
use tokio::fs;
use tokio::time::sleep;
// Import tracing macros
use tracing::{error, info};
// Import tempdir
use tempfile::tempdir;

// Declare the common module
mod common;

use lemon::config::load_and_validate_config;
// Correct the path for setup_shutdown_signal
use lemon::shutdown::setup_shutdown_signal;
// Correct the path for start_services
use lemon::start_services;
use portpicker::pick_unused_port;
use reqwest::header::{HeaderMap, HeaderName};
use std::collections::HashMap;

// Helper struct to manage server state
#[derive(Debug)]
struct TestServer {
    shutdown_tx: tokio::sync::watch::Sender<()>,
    // Change the type and name to reflect it holds the acceptor thread handle
    acceptor_handle: std::thread::JoinHandle<Result<()>>,
    base_url: String,
    _temp_dir: tempfile::TempDir,
}

// Helper function to set up and start a test server
async fn setup_test_server(
    tls_type: Option<&str>, // e.g., None for HTTP, Some("local_dev") for HTTPS
    security_config_snippet: Option<&str>,
) -> Result<TestServer> {
    common::ensure_logging_initialized();

    let temp_dir = tempdir()?;
    let dir_path = temp_dir.path();

    let port = pick_unused_port().expect("Failed to find unused port");
    let listen_addr = format!("127.0.0.1:{}", port);
    let (_protocol, base_url) = match tls_type {
        Some(_) => ("https", format!("https://{}", listen_addr)),
        None => ("http", format!("http://{}", listen_addr)),
    };

    let tls_config_block = match tls_type {
        Some(ttype) => format!(
            "
[server.test_security.tls]
type = \"{}\"
",
            ttype
        ),
        None => "".to_string(),
    };

    let security_config_block = match security_config_snippet {
        Some(snippet) => format!(
            "
[server.test_security.security]
{}
",
            snippet
        ),
        None => "
[server.test_security.security]
# Using defaults
"
        .to_string(), // Use default config
    };

    let config_content = format!(
        r#"
[server.test_security]
listen_addr = "{}"
{}
{}
[server.test_security.handler]
type = "health_check" # Simple handler is sufficient
"#,
        listen_addr,
        tls_config_block,      // Add TLS block if needed
        security_config_block  // Add security block
    );

    let config_filename = format!("test_security_config_{}.toml", port);
    fs::write(dir_path.join(&config_filename), &config_content).await?;
    let config_path = dir_path.join(&config_filename);

    // --- Start Server using start_services ---
    let config = load_and_validate_config(config_path.to_str().unwrap()).await?;
    // setup_shutdown_signal now returns tx, rx, ctrl_c_future
    // Ignore the ctrl_c_future part
    let (shutdown_tx, shutdown_rx, _) = setup_shutdown_signal();

    // Call start_services directly
    // It returns (AcmeState, acceptor_handle, server_handles)
    // We only need the acceptor_handle and shutdown_tx for the test server struct
    let (_acme_state, acceptor_handle, _server_handles) =
        start_services(&config, shutdown_rx.clone()).await?;

    // Allow some time for the server to start listening
    sleep(Duration::from_millis(200)).await; // Reduced sleep time slightly

    Ok(TestServer {
        shutdown_tx,     // Pass the sender
        acceptor_handle, // Store the handle for the acceptor thread
        base_url,
        _temp_dir: temp_dir,
    })
}

// Helper to shut down the server gracefully
async fn shutdown_test_server(server: TestServer) -> Result<()> {
    info!("Sending shutdown signal...");
    let _ = server.shutdown_tx.send(()).map_err(|e| {
        error!("Failed to send shutdown signal: {}", e);
        anyhow::anyhow!("Failed to send shutdown signal")
    });

    // Wait for the acceptor thread to finish
    // Use spawn_blocking because std::thread::JoinHandle::join is blocking
    let handle = server.acceptor_handle;
    tokio::task::spawn_blocking(move || match handle.join() {
        Ok(Ok(())) => info!("Acceptor thread joined successfully."),
        Ok(Err(e)) => error!("Acceptor thread finished with error: {}", e),
        Err(e) => error!("Acceptor thread panicked: {:?}", e),
    })
    .await?;

    info!("Test server shutdown complete.");
    Ok(())
}

// Helper to check headers
fn check_headers(
    headers: &HeaderMap,
    expected_headers: &HashMap<HeaderName, Option<&str>>, // Use Option<&str> to check for absence or specific value
) {
    for (name, expected_value) in expected_headers {
        let actual_header_value_opt = headers.get(name);

        match expected_value {
            Some(expected) => {
                // Assert header exists
                assert!(
                    actual_header_value_opt.is_some(),
                    "Expected header '{}' to be present with value \"{}\", but it was absent",
                    name,
                    expected
                );
                // Unwrap and compare the string value
                let actual_str = actual_header_value_opt
                    .unwrap()
                    .to_str()
                    .unwrap_or("[Invalid UTF-8]");
                assert_eq!(actual_str, *expected, "Header '{}' value mismatch", name);
            }
            None => {
                // Assert header is absent
                assert!(
                    actual_header_value_opt.is_none(),
                    "Expected header '{}' to be absent, but found value: {:?}",
                    name,
                    actual_header_value_opt.map(|v| v.to_str().unwrap_or("[Invalid UTF-8]"))
                );
            }
        }
    }
}

// --- HTTP Test Cases ---

#[tokio::test]
async fn test_http_default_headers() -> Result<()> {
    let server = setup_test_server(None, None).await?; // HTTP, Default security
    let client = reqwest::Client::new();
    let response = client.get(&server.base_url).send().await?;
    assert!(response.status().is_success());

    let mut expected = HashMap::new();
    expected.insert(
        HeaderName::from_static("x-content-type-options"),
        Some("nosniff"),
    );
    expected.insert(HeaderName::from_static("x-frame-options"), Some("DENY"));
    expected.insert(HeaderName::from_static("strict-transport-security"), None); // Should NOT be present on HTTP

    check_headers(response.headers(), &expected);

    shutdown_test_server(server).await?;
    Ok(())
}

#[tokio::test]
async fn test_http_security_disabled() -> Result<()> {
    let server = setup_test_server(None, Some("add_default_headers = false")).await?; // HTTP, Disabled
    let client = reqwest::Client::new();
    let response = client.get(&server.base_url).send().await?;
    assert!(response.status().is_success());

    let mut expected = HashMap::new();
    expected.insert(HeaderName::from_static("x-content-type-options"), None);
    expected.insert(HeaderName::from_static("x-frame-options"), None);
    expected.insert(HeaderName::from_static("strict-transport-security"), None);

    check_headers(response.headers(), &expected);

    shutdown_test_server(server).await?;
    Ok(())
}

#[tokio::test]
async fn test_http_frame_options_sameorigin() -> Result<()> {
    let server = setup_test_server(None, Some("frame_options = \"SAMEORIGIN\"")).await?; // HTTP
    let client = reqwest::Client::new();
    let response = client.get(&server.base_url).send().await?;
    assert!(response.status().is_success());

    let mut expected = HashMap::new();
    expected.insert(
        HeaderName::from_static("x-content-type-options"),
        Some("nosniff"),
    );
    expected.insert(
        HeaderName::from_static("x-frame-options"),
        Some("SAMEORIGIN"),
    ); // Check override
    expected.insert(HeaderName::from_static("strict-transport-security"), None);

    check_headers(response.headers(), &expected);

    shutdown_test_server(server).await?;
    Ok(())
}

#[tokio::test]
async fn test_http_frame_options_none() -> Result<()> {
    let server = setup_test_server(None, Some("frame_options = \"NONE\"")).await?; // HTTP
    let client = reqwest::Client::new();
    let response = client.get(&server.base_url).send().await?;
    assert!(response.status().is_success());

    let mut expected = HashMap::new();
    expected.insert(
        HeaderName::from_static("x-content-type-options"),
        Some("nosniff"),
    );
    expected.insert(HeaderName::from_static("x-frame-options"), None); // Should be absent
    expected.insert(HeaderName::from_static("strict-transport-security"), None);

    check_headers(response.headers(), &expected);

    shutdown_test_server(server).await?;
    Ok(())
}

// --- HTTPS Test Cases ---

#[tokio::test]
async fn test_https_default_headers() -> Result<()> {
    let server = setup_test_server(Some("local_dev"), None).await?; // HTTPS, Default security
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    let response = client.get(&server.base_url).send().await?;
    assert!(response.status().is_success());

    let mut expected = HashMap::new();
    expected.insert(
        HeaderName::from_static("x-content-type-options"),
        Some("nosniff"),
    );
    expected.insert(HeaderName::from_static("x-frame-options"), Some("DENY"));
    // Default HSTS: max-age=31536000; includeSubDomains (preload=false is default)
    expected.insert(
        HeaderName::from_static("strict-transport-security"),
        Some("max-age=31536000; includeSubDomains"),
    );

    check_headers(response.headers(), &expected);

    shutdown_test_server(server).await?;
    Ok(())
}

#[tokio::test]
async fn test_https_security_disabled() -> Result<()> {
    let server = setup_test_server(Some("local_dev"), Some("add_default_headers = false")).await?; // HTTPS, Disabled
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    let response = client.get(&server.base_url).send().await?;
    assert!(response.status().is_success());

    let mut expected = HashMap::new();
    expected.insert(HeaderName::from_static("x-content-type-options"), None);
    expected.insert(HeaderName::from_static("x-frame-options"), None);
    expected.insert(HeaderName::from_static("strict-transport-security"), None);

    check_headers(response.headers(), &expected);

    shutdown_test_server(server).await?;
    Ok(())
}

#[tokio::test]
async fn test_https_frame_options_sameorigin() -> Result<()> {
    let server =
        setup_test_server(Some("local_dev"), Some("frame_options = \"SAMEORIGIN\"")).await?; // HTTPS
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    let response = client.get(&server.base_url).send().await?;
    assert!(response.status().is_success());

    let mut expected = HashMap::new();
    expected.insert(
        HeaderName::from_static("x-content-type-options"),
        Some("nosniff"),
    );
    expected.insert(
        HeaderName::from_static("x-frame-options"),
        Some("SAMEORIGIN"),
    ); // Check override
    expected.insert(
        HeaderName::from_static("strict-transport-security"),
        Some("max-age=31536000; includeSubDomains"),
    ); // HSTS should still be default

    check_headers(response.headers(), &expected);

    shutdown_test_server(server).await?;
    Ok(())
}

#[tokio::test]
async fn test_https_frame_options_none() -> Result<()> {
    let server = setup_test_server(Some("local_dev"), Some("frame_options = \"NONE\"")).await?; // HTTPS
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    let response = client.get(&server.base_url).send().await?;
    assert!(response.status().is_success());

    let mut expected = HashMap::new();
    expected.insert(
        HeaderName::from_static("x-content-type-options"),
        Some("nosniff"),
    );
    expected.insert(HeaderName::from_static("x-frame-options"), None); // Should be absent
    expected.insert(
        HeaderName::from_static("strict-transport-security"),
        Some("max-age=31536000; includeSubDomains"),
    ); // HSTS should still be default

    check_headers(response.headers(), &expected);

    shutdown_test_server(server).await?;
    Ok(())
}

#[tokio::test]
async fn test_https_hsts_overrides() -> Result<()> {
    let security_snippet = r#"
hsts_max_age = 1000
hsts_include_subdomains = false
hsts_preload = true
# frame_options = "DENY" # Implicit default
# add_default_headers = true # Implicit default
"#;
    let server = setup_test_server(Some("local_dev"), Some(security_snippet)).await?; // HTTPS, HSTS overrides
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    let response = client.get(&server.base_url).send().await?;
    assert!(response.status().is_success());

    let mut expected = HashMap::new();
    expected.insert(
        HeaderName::from_static("x-content-type-options"),
        Some("nosniff"),
    );
    expected.insert(HeaderName::from_static("x-frame-options"), Some("DENY")); // Should be default
    // Check HSTS overrides: max-age=1000; preload (no includeSubDomains)
    expected.insert(
        HeaderName::from_static("strict-transport-security"),
        Some("max-age=1000; preload"),
    );

    check_headers(response.headers(), &expected);

    shutdown_test_server(server).await?;
    Ok(())
}
