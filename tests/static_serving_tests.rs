use anyhow::Result;
use lemon::config::load_and_validate_config;
use lemon::shutdown::setup_shutdown_signal;
use lemon::start_services;
use reqwest;
use std::time::Duration;
use tempfile::tempdir;
use tokio::fs;
use tokio::time::sleep;
use tracing::{error, info, warn};

// Declare the common module
mod common;

// Helper to write temp config
async fn write_temp_config(filename: &str, content: &str) -> Result<()> {
    fs::write(filename, content).await?;
    Ok(())
}

struct TestServer {
    shutdown_tx: tokio::sync::watch::Sender<()>,
    acceptor_handle: std::thread::JoinHandle<Result<()>>,
    base_url: String,
    _temp_dir: tempfile::TempDir,
    config_filename: String,
}

// Updated helper function to set up and start a test server with configurable cache
async fn setup_static_server(
    files_to_create: &[(&str, &[u8])], // List of (relative_path, content_bytes)
    cache_max_file_bytes: Option<u64>,
    cache_max_total_bytes: Option<u64>,
) -> Result<TestServer> {
    // Ensure logging is initialized once for the test suite
    common::ensure_logging_initialized();

    // Create a temporary directory for www_root
    let temp_dir = tempdir()?;
    let www_root = temp_dir.path().to_path_buf();

    // Create the files to be served
    for (relative_path, content_bytes) in files_to_create {
        let full_path = www_root.join(relative_path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::write(&full_path, *content_bytes).await?;
    }

    // Create cache config lines if values are provided
    let cache_config_lines = format!(
        "{}{}",
        cache_max_file_bytes
            .map(|v| format!("content_cache_max_file_bytes = {}\n", v))
            .unwrap_or_default(),
        cache_max_total_bytes
            .map(|v| format!("content_cache_max_total_bytes = {}\n", v))
            .unwrap_or_default()
    );

    // Create config file pointing to the temp www_root
    let port = portpicker::pick_unused_port().expect("Failed to find unused port");
    let listen_addr = format!("127.0.0.1:{}", port);
    let config_content = format!(
        r#"
[server.test_static]
listen_addr = "{}"
security = {{}}

[server.test_static.handler]
type = "static"
www_root = "{}"
{}
"#,
        listen_addr,
        www_root.display(),
        cache_config_lines
    );

    let config_filename = format!("test_static_config_{}.toml", port);
    write_temp_config(&config_filename, &config_content).await?;

    // --- Start Server using start_services ---
    let config = load_and_validate_config(&config_filename).await?;
    let (shutdown_tx, shutdown_rx, _) = setup_shutdown_signal();

    // Call start_services directly
    let (_acme_state, acceptor_handle, _server_handles) =
        start_services(&config, shutdown_rx.clone()).await?;

    // Allow some time for the server to start listening
    sleep(Duration::from_millis(200)).await; // Reduced sleep time

    Ok(TestServer {
        shutdown_tx,     // Pass the sender
        acceptor_handle, // Store the handle for the acceptor thread
        base_url: format!("http://{}", listen_addr),
        _temp_dir: temp_dir,
        config_filename,
    })
}

// Helper function to gracefully shut down the test server
async fn shutdown_test_server(server: TestServer) -> Result<()> {
    common::ensure_logging_initialized(); // Ensure logging for shutdown messages
    info!("Sending shutdown signal for static server...");
    let _ = server.shutdown_tx.send(()).map_err(|e| {
        error!("Failed to send shutdown signal: {}", e);
        anyhow::anyhow!("Failed to send shutdown signal")
    });

    // Wait for the acceptor thread to finish
    // Use spawn_blocking because std::thread::JoinHandle::join is blocking
    let handle = server.acceptor_handle;
    tokio::task::spawn_blocking(move || match handle.join() {
        Ok(Ok(())) => info!("Static server acceptor thread joined successfully."),
        Ok(Err(e)) => error!("Static server acceptor thread finished with error: {}", e),
        Err(e) => error!("Static server acceptor thread panicked: {:?}", e),
    })
    .await?;

    // Clean up the temporary config file
    if let Err(e) = fs::remove_file(&server.config_filename).await {
        warn!(
            "Failed to remove temp config file {}: {}",
            server.config_filename, e
        );
    }

    info!("Static test server shutdown complete.");
    Ok(())
}

// --- Test Cases --- //

#[tokio::test]
async fn test_serve_existing_file() -> Result<()> {
    let file_content = b"Hello from static test!";
    let path = "index.html";
    let server = setup_static_server(&[(path, file_content)], None, None).await?;

    let client = reqwest::Client::new();
    let url = format!("{}/{}", server.base_url, path);

    let response = client.get(&url).send().await?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body = response.text().await?;
    assert_eq!(body, std::str::from_utf8(file_content)?);

    shutdown_test_server(server).await?;
    Ok(())
}

#[tokio::test]
async fn test_serve_non_existent_file() -> Result<()> {
    // Setup server with some dummy file
    let server = setup_static_server(&[("dummy.txt", b"dummy content")], None, None).await?;

    let client = reqwest::Client::new();
    let url = format!("{}/non_existent_file.html", server.base_url);

    let response = client.get(&url).send().await?;

    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);

    shutdown_test_server(server).await?;
    Ok(())
}

#[tokio::test]
async fn test_serve_file_in_subdirectory() -> Result<()> {
    let file_content = b"Content in subdirectory";
    let path = "subdir/file.txt";
    let server = setup_static_server(&[(path, file_content)], None, None).await?;

    let client = reqwest::Client::new();

    let url = format!("{}/{}", server.base_url, path);

    let response = client.get(&url).send().await?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body = response.text().await?;
    assert_eq!(body, std::str::from_utf8(file_content)?);

    shutdown_test_server(server).await?;
    Ok(())
}

#[tokio::test]
async fn test_serve_file_with_content_type() -> Result<()> {
    let file_content = b"body { color: blue; }";
    let path = "style.css";
    let expected_content_type = "text/css";

    let server = setup_static_server(&[(path, file_content)], None, None).await?;

    let client = reqwest::Client::new();
    let url = format!("{}/{}", server.base_url, path);

    let response = client.get(&url).send().await?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    // Check the Content-Type header
    let content_type_header = response.headers().get(reqwest::header::CONTENT_TYPE);
    assert!(content_type_header.is_some(), "Content-Type header missing");
    assert_eq!(
        content_type_header.unwrap().to_str()?,
        expected_content_type
    );

    // Optionally check body as well
    let body = response.text().await?;
    assert_eq!(body, std::str::from_utf8(file_content)?);

    shutdown_test_server(server).await?;
    Ok(())
}

#[tokio::test]
async fn test_serve_file_with_cache_control() -> Result<()> {
    let file_content = b"Cache me!";
    let path = "cacheable.txt";
    let expected_cache_control = "public, max-age=3600";

    let server = setup_static_server(&[(path, file_content)], None, None).await?;

    let client = reqwest::Client::new();
    let url = format!("{}/{}", server.base_url, path);

    let response = client.get(&url).send().await?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    // Check the Cache-Control header
    let cache_control_header = response.headers().get(reqwest::header::CACHE_CONTROL);
    assert!(
        cache_control_header.is_some(),
        "Cache-Control header missing"
    );
    assert_eq!(
        cache_control_header.unwrap().to_str()?,
        expected_cache_control
    );

    // Optionally check body as well
    let body = response.text().await?;
    assert_eq!(body, std::str::from_utf8(file_content)?);

    shutdown_test_server(server).await?;
    Ok(())
}

// --- Cache Test Cases --- //

#[tokio::test]
async fn test_cache_hit_small_file() -> Result<()> {
    // Small file content, well within default cache limits
    let small_content = "This is a small file.".repeat(10);
    let small_path = "small.txt";
    let files = [(small_path, small_content.as_bytes())];

    // Use default cache limits (1MB file, 256MB total) which should cache this file
    let server = setup_static_server(&files, None, None).await?;
    let client = reqwest::Client::new();
    let url = format!("{}/{}", server.base_url, small_path);

    // First request - should populate cache
    let response1 = client.get(&url).send().await?;
    assert_eq!(response1.status(), reqwest::StatusCode::OK);
    let body1 = response1.text().await?;
    assert_eq!(body1, small_content);

    // Second request - should *likely* hit cache (verify correctness)
    let response2 = client.get(&url).send().await?;
    assert_eq!(response2.status(), reqwest::StatusCode::OK);
    let body2 = response2.text().await?;
    assert_eq!(body2, small_content);

    shutdown_test_server(server).await?;
    Ok(())
}

#[tokio::test]
async fn test_cache_miss_large_file() -> Result<()> {
    // Create content larger than the explicit cache limit we set
    let large_content = "A".repeat(1500); // > 1KB limit set below
    let large_path = "large.txt";
    let files = [(large_path, large_content.as_bytes())];

    // Explicitly limit single file cache size to 1KB
    let server = setup_static_server(&files, Some(1024), None).await?;
    let client = reqwest::Client::new();
    let url = format!("{}/{}", server.base_url, large_path);

    // First request - should be streamed (too large for cache)
    let response1 = client.get(&url).send().await?;
    assert_eq!(response1.status(), reqwest::StatusCode::OK);
    let body1 = response1.text().await?;
    assert_eq!(body1, large_content);

    // Second request - should also be streamed
    let response2 = client.get(&url).send().await?;
    assert_eq!(response2.status(), reqwest::StatusCode::OK);
    let body2 = response2.text().await?;
    assert_eq!(body2, large_content);

    shutdown_test_server(server).await?;
    Ok(())
}

#[tokio::test]
async fn test_etag_with_cache() -> Result<()> {
    let file_content = "Check ETag with cache.".repeat(5);
    let path = "etag_cache.txt";
    let files = [(path, file_content.as_bytes())];

    // Configure cache small enough to cache this file
    let server = setup_static_server(&files, Some(1024), Some(2048)).await?;
    let client = reqwest::Client::new();
    let url = format!("{}/{}", server.base_url, path);

    // 1. First request to get ETag
    let response1 = client.get(&url).send().await?;
    assert_eq!(response1.status(), reqwest::StatusCode::OK);
    // Get ETag header *before* consuming the body
    let etag = response1
        .headers()
        .get(reqwest::header::ETAG)
        .expect("ETag header missing")
        .to_str()?
        .to_string(); // Clone the ETag string
    // Now consume the body
    let body1 = response1.text().await?;
    assert_eq!(body1, file_content);

    // 2. Second request with If-None-Match - should be 304
    let response2 = client
        .get(&url)
        .header(reqwest::header::IF_NONE_MATCH, etag)
        .send()
        .await?;

    assert_eq!(response2.status(), reqwest::StatusCode::NOT_MODIFIED);
    let body2 = response2.text().await?;
    assert!(body2.is_empty(), "Body should be empty for 304");

    shutdown_test_server(server).await?;
    Ok(())
}

// --- Compression Test Cases --- //

const COMPRESSIBLE_PATH: &str = "compressible.txt";

fn create_compressible_content() -> String {
    "This is compressible content. Repeat. ".repeat(100) // Make it > 256 bytes
}

#[tokio::test]
async fn test_compression_gzip() -> Result<()> {
    let content = create_compressible_content();
    let files = [(COMPRESSIBLE_PATH, content.as_bytes())];
    // Disable content cache (max_file_bytes = 0) to force the streaming path,
    // ensuring we test the on-the-fly Gzip compression logic.
    let server = setup_static_server(&files, Some(0), None).await?;

    let client = reqwest::Client::new();
    let url = format!("{}/{}", server.base_url, COMPRESSIBLE_PATH);

    let response = client
        .get(&url)
        // Only accept gzip to specifically test the gzip path
        .header(reqwest::header::ACCEPT_ENCODING, "gzip")
        .send()
        .await?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    // Check headers
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .map(|v| v.to_str().unwrap()),
        Some("gzip")
    );
    assert!(
        response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .is_none()
    ); // Should be absent for compressed
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::VARY)
            .map(|v| v.to_str().unwrap()),
        Some("Accept-Encoding")
    );

    // Check body decompressed
    let decompressed_body = response.bytes().await?;
    // Use a Gzip decoder (requires flate2 or similar if testing exact content)
    // For now, just assert it's smaller than original
    assert!(decompressed_body.len() < content.len());

    shutdown_test_server(server).await?;
    Ok(())
}

#[tokio::test]
async fn test_compression_brotli() -> Result<()> {
    let content = create_compressible_content();
    let files = [(COMPRESSIBLE_PATH, content.as_bytes())];
    // Disable content cache (max_file_bytes = 0) to force the streaming path,
    // ensuring we test the on-the-fly Brotli compression logic.
    let server = setup_static_server(&files, Some(0), None).await?;

    let client = reqwest::Client::new();
    let url = format!("{}/{}", server.base_url, COMPRESSIBLE_PATH);

    let response = client
        .get(&url)
        .header(reqwest::header::ACCEPT_ENCODING, "br, gzip") // Brotli preferred
        .send()
        .await?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    // Check headers
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .map(|v| v.to_str().unwrap()),
        Some("br")
    );
    assert!(
        response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .is_none()
    );
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::VARY)
            .map(|v| v.to_str().unwrap()),
        Some("Accept-Encoding")
    );

    // Check body decompressed
    let decompressed_body = response.bytes().await?;
    // Use a Brotli decoder (requires brotli crate if testing exact content)
    // For now, just assert it's smaller than original
    assert!(decompressed_body.len() < content.len());

    shutdown_test_server(server).await?;
    Ok(())
}

#[tokio::test]
async fn test_compression_none_accepted() -> Result<()> {
    let content = create_compressible_content();
    let files = [(COMPRESSIBLE_PATH, content.as_bytes())];
    let server = setup_static_server(&files, None, None).await?;

    let client = reqwest::Client::new();
    let url = format!("{}/{}", server.base_url, COMPRESSIBLE_PATH);

    // No Accept-Encoding header or "identity"
    let response = client.get(&url).send().await?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    // Check headers
    assert!(
        response
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .is_none()
    );
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .map(|v| v.to_str().unwrap()),
        Some(content.len().to_string().as_str())
    );
    // Vary should still be set if the resource *could* be compressed
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::VARY)
            .map(|v| v.to_str().unwrap()),
        Some("Accept-Encoding")
    );

    // Check body
    let body = response.text().await?;
    assert_eq!(body, content);

    shutdown_test_server(server).await?;
    Ok(())
}

#[tokio::test]
async fn test_compression_non_compressible_file() -> Result<()> {
    // Test with a png file, which should not be compressed
    let path_png = "image.png";
    // Use actual PNG data to ensure MIME type is correctly inferred
    let content_png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\0\x01\0\0\0\x01\x08\x06\0\0\0\x1f\x15\xc4\x89\0\0\0\nIDATx\x9cc\xfc\xff?\x03\0\x01\xfc'\x9e\xde\0\0\0\0IEND\xaeB`\x82";
    let path_txt = "compressible.txt";
    let content_txt = create_compressible_content(); // Ensure this exists

    // Disable content cache to test streaming path for txt file
    let server = setup_static_server(
        &[
            (path_png, content_png as &[u8]),
            (path_txt, content_txt.as_bytes()),
        ],
        Some(0), // Disable content cache
        None,
    )
    .await?;

    let client = reqwest::Client::new();

    // --- Check PNG file (should not be compressed) ---
    let url_png = format!("{}/{}", server.base_url, path_png);
    let response_png = client
        .get(&url_png)
        .header(reqwest::header::ACCEPT_ENCODING, "gzip, br, zstd")
        .send()
        .await?;

    assert_eq!(response_png.status(), reqwest::StatusCode::OK);
    assert!(
        response_png
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .is_none(),
        "PNG file should not have Content-Encoding header"
    );
    assert_eq!(
        response_png
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .unwrap()
            .to_str()?,
        "image/png"
    );
    // Check Content-Length matches original size
    assert_eq!(
        response_png
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .unwrap()
            .to_str()?,
        content_png.len().to_string()
    );

    // --- Check TXT file (should be compressed) ---
    let url_txt = format!("{}/{}", server.base_url, path_txt);
    let response_txt = client
        .get(&url_txt)
        .header(reqwest::header::ACCEPT_ENCODING, "gzip") // Request gzip
        .send()
        .await?;

    assert_eq!(response_txt.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response_txt
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .unwrap()
            .to_str()?,
        "gzip"
    );
    // Content-Length should be absent for compressed data
    assert!(
        response_txt
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .is_none()
    );

    shutdown_test_server(server).await?;
    Ok(())
}

// --- NEW TESTS START HERE ---

#[tokio::test]
async fn test_compression_zstd() -> Result<()> {
    let file_content = create_compressible_content();
    let path = "data.txt";
    // Disable content cache to test streaming path
    let server = setup_static_server(&[(path, file_content.as_bytes())], Some(0), None).await?;

    let client = reqwest::Client::new();
    let url = format!("{}/{}", server.base_url, path);

    let response = client
        .get(&url)
        .header(reqwest::header::ACCEPT_ENCODING, "zstd")
        .send()
        .await?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .unwrap()
            .to_str()?,
        "zstd"
    );
    assert!(
        response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .is_none()
    );

    // We should also get the Vary header
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::VARY)
            .unwrap()
            .to_str()?,
        "Accept-Encoding"
    );

    shutdown_test_server(server).await?;
    Ok(())
}

#[tokio::test]
async fn test_compression_priority() -> Result<()> {
    let file_content = create_compressible_content();
    let path = "priority.txt";
    // Disable content cache to test streaming path
    let server = setup_static_server(&[(path, file_content.as_bytes())], Some(0), None).await?;
    let client = reqwest::Client::new();
    let url = format!("{}/{}", server.base_url, path);

    // Test 1: br > zstd > gzip (request all, expect br)
    let response_br = client
        .get(&url)
        .header(reqwest::header::ACCEPT_ENCODING, "gzip, zstd, br")
        .send()
        .await?;
    assert_eq!(response_br.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response_br
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .unwrap()
            .to_str()?,
        "br"
    );
    assert_eq!(
        response_br
            .headers()
            .get(reqwest::header::VARY)
            .unwrap()
            .to_str()?,
        "Accept-Encoding"
    );

    // Test 2: zstd > gzip (request zstd, gzip, expect zstd)
    let response_zstd = client
        .get(&url)
        .header(reqwest::header::ACCEPT_ENCODING, "gzip, zstd")
        .send()
        .await?;
    assert_eq!(response_zstd.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response_zstd
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .unwrap()
            .to_str()?,
        "zstd"
    );
    assert_eq!(
        response_zstd
            .headers()
            .get(reqwest::header::VARY)
            .unwrap()
            .to_str()?,
        "Accept-Encoding"
    );

    // Test 3: gzip only (request gzip, expect gzip)
    let response_gzip = client
        .get(&url)
        .header(reqwest::header::ACCEPT_ENCODING, "gzip")
        .send()
        .await?;
    assert_eq!(response_gzip.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response_gzip
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .unwrap()
            .to_str()?,
        "gzip"
    );
    assert_eq!(
        response_gzip
            .headers()
            .get(reqwest::header::VARY)
            .unwrap()
            .to_str()?,
        "Accept-Encoding"
    );

    // Test 4: Identity (request unknown, expect no encoding)
    let response_identity = client
        .get(&url)
        .header(reqwest::header::ACCEPT_ENCODING, "deflate, unknown")
        .send()
        .await?;
    assert_eq!(response_identity.status(), reqwest::StatusCode::OK);
    assert!(
        response_identity
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .is_none()
    );
    // Correction: Vary *should* be present if type is compressible, even if Identity is chosen
    assert_eq!(
        response_identity
            .headers()
            .get(reqwest::header::VARY)
            .expect("Missing Vary header")
            .to_str()?,
        "Accept-Encoding"
    );

    shutdown_test_server(server).await?;
    Ok(())
}

#[tokio::test]
async fn test_compression_small_file() -> Result<()> {
    // File content less than 256 bytes
    let small_content = "This is a small text file.";
    assert!(
        small_content.len() < 256,
        "Test precondition failed: small_content is too large"
    );
    let path = "small.txt";
    let server = setup_static_server(&[(path, small_content.as_bytes())], None, None).await?;

    let client = reqwest::Client::new();
    let url = format!("{}/{}", server.base_url, path);

    let response = client
        .get(&url)
        .header(reqwest::header::ACCEPT_ENCODING, "gzip, br, zstd") // Request compression
        .send()
        .await?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    // Should NOT be compressed
    assert!(
        response
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .is_none()
    );
    // Content-Length should match original size
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .unwrap()
            .to_str()?,
        small_content.len().to_string()
    );
    // Vary header should not be present as compression was skipped due to size
    // assert!(response.headers().get(reqwest::header::VARY).is_none()); // TODO: Double check if Vary is added even if size prevents compression
    // Correction: The handler adds Vary if the *type* is compressible, even if size prevents it.
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::VARY)
            .unwrap()
            .to_str()?,
        "Accept-Encoding"
    );

    shutdown_test_server(server).await?;
    Ok(())
}

#[tokio::test]
async fn test_etag_suffix() -> Result<()> {
    let file_content = create_compressible_content();
    let path = "etag_test.txt";
    let server = setup_static_server(&[(path, file_content.as_bytes())], None, None).await?;
    let client = reqwest::Client::new();
    let url = format!("{}/{}", server.base_url, path);

    // 1. Get initial ETag (no compression requested)
    let response_identity = client.get(&url).send().await?;
    assert_eq!(response_identity.status(), reqwest::StatusCode::OK);
    let etag_identity = response_identity
        .headers()
        .get(reqwest::header::ETAG)
        .expect("Missing ETag")
        .to_str()?
        .to_string();
    println!("Identity ETag: {}", etag_identity);
    assert!(
        !etag_identity.contains("-gz")
            && !etag_identity.contains("-br")
            && !etag_identity.contains("-zst"),
        "Identity ETag should not have suffix"
    );

    // 2. Get Gzip ETag and test 304
    let response_gzip = client
        .get(&url)
        .header(reqwest::header::ACCEPT_ENCODING, "gzip")
        .send()
        .await?;
    assert_eq!(response_gzip.status(), reqwest::StatusCode::OK);
    let etag_gzip = response_gzip
        .headers()
        .get(reqwest::header::ETAG)
        .expect("Missing ETag for gzip")
        .to_str()?
        .to_string();
    println!("Gzip ETag: {}", etag_gzip);
    assert!(etag_gzip.ends_with("-gz\""), "Gzip ETag incorrect suffix");
    assert_ne!(
        etag_identity, etag_gzip,
        "Identity and Gzip ETags should differ"
    );

    let response_gzip_304 = client
        .get(&url)
        .header(reqwest::header::ACCEPT_ENCODING, "gzip") // Add corresponding Accept-Encoding
        .header(reqwest::header::IF_NONE_MATCH, &etag_gzip)
        .send()
        .await?;
    assert_eq!(
        response_gzip_304.status(),
        reqwest::StatusCode::NOT_MODIFIED
    );

    // 3. Get Brotli ETag and test 304
    let response_br = client
        .get(&url)
        .header(reqwest::header::ACCEPT_ENCODING, "br")
        .send()
        .await?;
    assert_eq!(response_br.status(), reqwest::StatusCode::OK);
    let etag_br = response_br
        .headers()
        .get(reqwest::header::ETAG)
        .expect("Missing ETag for br")
        .to_str()?
        .to_string();
    println!("Brotli ETag: {}", etag_br);
    assert!(etag_br.ends_with("-br\""), "Brotli ETag incorrect suffix");
    assert_ne!(
        etag_identity, etag_br,
        "Identity and Brotli ETags should differ"
    );
    assert_ne!(etag_gzip, etag_br, "Gzip and Brotli ETags should differ");

    let response_br_304 = client
        .get(&url)
        .header(reqwest::header::ACCEPT_ENCODING, "br") // Add corresponding Accept-Encoding
        .header(reqwest::header::IF_NONE_MATCH, &etag_br)
        .send()
        .await?;
    assert_eq!(response_br_304.status(), reqwest::StatusCode::NOT_MODIFIED);

    // 4. Get Zstd ETag and test 304
    let response_zstd = client
        .get(&url)
        .header(reqwest::header::ACCEPT_ENCODING, "zstd")
        .send()
        .await?;
    assert_eq!(response_zstd.status(), reqwest::StatusCode::OK);
    let etag_zstd = response_zstd
        .headers()
        .get(reqwest::header::ETAG)
        .expect("Missing ETag for zstd")
        .to_str()?
        .to_string();
    println!("Zstd ETag: {}", etag_zstd);
    assert!(etag_zstd.ends_with("-zst\""), "Zstd ETag incorrect suffix");
    assert_ne!(
        etag_identity, etag_zstd,
        "Identity and Zstd ETags should differ"
    );
    assert_ne!(etag_br, etag_zstd, "Brotli and Zstd ETags should differ");

    let response_zstd_304 = client
        .get(&url)
        .header(reqwest::header::ACCEPT_ENCODING, "zstd") // Add corresponding Accept-Encoding
        .header(reqwest::header::IF_NONE_MATCH, &etag_zstd)
        .send()
        .await?;
    assert_eq!(
        response_zstd_304.status(),
        reqwest::StatusCode::NOT_MODIFIED
    );

    // 5. Ensure 304 response also includes the correct ETag
    assert_eq!(
        response_zstd_304
            .headers()
            .get(reqwest::header::ETAG)
            .unwrap()
            .to_str()?,
        etag_zstd
    );

    // 6. Test ETag for small file (should be unsuffixed)
    let small_content = b"tiny";
    let small_path = "tiny.txt";
    fs::write(server._temp_dir.path().join(small_path), small_content).await?;
    let url_small = format!("{}/{}", server.base_url, small_path);
    let response_small = client
        .get(&url_small)
        .header(reqwest::header::ACCEPT_ENCODING, "gzip")
        .send()
        .await?;
    assert_eq!(response_small.status(), reqwest::StatusCode::OK);
    let etag_small = response_small
        .headers()
        .get(reqwest::header::ETAG)
        .expect("Missing ETag for small file")
        .to_str()?
        .to_string();
    assert!(
        !etag_small.contains("-gz") && !etag_small.contains("-br") && !etag_small.contains("-zst"),
        "Small file ETag should not have suffix"
    );

    shutdown_test_server(server).await?;
    Ok(())
}

// --- END NEW TESTS ---

#[tokio::test]
async fn test_compression_head_request() -> Result<()> {
    let content = create_compressible_content();
    let files = [(COMPRESSIBLE_PATH, content.as_bytes())];
    let server = setup_static_server(&files, None, None).await?;

    let client = reqwest::Client::new();
    let url = format!("{}/{}", server.base_url, COMPRESSIBLE_PATH);

    // Send HEAD request with Accept-Encoding
    let response = client
        .head(&url)
        .header(reqwest::header::ACCEPT_ENCODING, "gzip")
        .send()
        .await?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    // Check headers
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .map(|v| v.to_str().unwrap()),
        Some("gzip")
    );
    assert!(
        response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .is_none()
    ); // No content-length for compressed HEAD
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::VARY)
            .map(|v| v.to_str().unwrap()),
        Some("Accept-Encoding")
    );

    // Body should be empty
    let body = response.text().await?;
    assert!(body.is_empty());

    shutdown_test_server(server).await?;
    Ok(())
}

#[tokio::test]
async fn test_server_header_present() -> Result<()> {
    let server = setup_static_server(&[("hello.txt", b"world")], None, None).await?;
    let client = reqwest::Client::new();
    let url = format!("{}/hello.txt", server.base_url);
    let response = client.get(&url).send().await?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.headers().get("server").unwrap().to_str()?,
        "Lemon"
    );

    shutdown_test_server(server).await?;
    Ok(())
}

// --- Range Request Tests --- //

// Helper to create a reasonably large file for range tests
fn create_large_test_content(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

#[tokio::test]
async fn test_range_request_specific() -> Result<()> {
    let content = create_large_test_content(2000);
    let path = "largefile.bin";
    let server = setup_static_server(&[(path, &content)], None, None).await?;
    let client = reqwest::Client::new();
    let url = format!("{}/{}", server.base_url, path);

    let range = "bytes=100-199"; // Request 100 bytes (inclusive)
    let response = client.get(&url).header("Range", range).send().await?;

    assert_eq!(response.status(), reqwest::StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CONTENT_RANGE)
            .unwrap().to_str()?,
        "bytes 100-199/2000"
    );
    assert_eq!(
        response.headers().get(reqwest::header::CONTENT_LENGTH).unwrap().to_str()?,
        "100"
    );
    assert_eq!(
        response.headers().get(reqwest::header::ACCEPT_RANGES).unwrap().to_str()?,
        "bytes"
    );
    // Should not be compressed
    assert!(response.headers().get(reqwest::header::CONTENT_ENCODING).is_none());

    let body_bytes = response.bytes().await?;
    assert_eq!(body_bytes.len(), 100);
    assert_eq!(&body_bytes[..], &content[100..=199]);

    shutdown_test_server(server).await?;
    Ok(())
}

#[tokio::test]
async fn test_range_request_open_start() -> Result<()> {
    let content = create_large_test_content(500);
    let path = "midfile.bin";
    let server = setup_static_server(&[(path, &content)], None, None).await?;
    let client = reqwest::Client::new();
    let url = format!("{}/{}", server.base_url, path);

    let range = "bytes=450-"; // Request from byte 450 to end
    let response = client.get(&url).header("Range", range).send().await?;

    assert_eq!(response.status(), reqwest::StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CONTENT_RANGE)
            .unwrap().to_str()?,
        "bytes 450-499/500"
    );
    assert_eq!(
        response.headers().get(reqwest::header::CONTENT_LENGTH).unwrap().to_str()?,
        "50" // 499 - 450 + 1
    );
    assert_eq!(
        response.headers().get(reqwest::header::ACCEPT_RANGES).unwrap().to_str()?,
        "bytes"
    );

    let body_bytes = response.bytes().await?;
    assert_eq!(body_bytes.len(), 50);
    assert_eq!(&body_bytes[..], &content[450..]);

    shutdown_test_server(server).await?;
    Ok(())
}

#[tokio::test]
async fn test_range_request_suffix() -> Result<()> {
    let content = create_large_test_content(1024);
    let path = "suffix.bin";
    let server = setup_static_server(&[(path, &content)], None, None).await?;
    let client = reqwest::Client::new();
    let url = format!("{}/{}", server.base_url, path);

    let range = "bytes=-100"; // Request last 100 bytes
    let response = client.get(&url).header("Range", range).send().await?;

    assert_eq!(response.status(), reqwest::StatusCode::PARTIAL_CONTENT);
    let expected_start = 1024 - 100;
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CONTENT_RANGE)
            .unwrap().to_str()?,
        format!("bytes {}-1023/1024", expected_start)
    );
    assert_eq!(
        response.headers().get(reqwest::header::CONTENT_LENGTH).unwrap().to_str()?,
        "100"
    );
    assert_eq!(
        response.headers().get(reqwest::header::ACCEPT_RANGES).unwrap().to_str()?,
        "bytes"
    );

    let body_bytes = response.bytes().await?;
    assert_eq!(body_bytes.len(), 100);
    assert_eq!(&body_bytes[..], &content[expected_start..]);

    shutdown_test_server(server).await?;
    Ok(())
}

#[tokio::test]
async fn test_range_request_unsatisfiable() -> Result<()> {
    let content = b"short content";
    let path = "short.txt";
    let server = setup_static_server(&[(path, content)], None, None).await?;
    let client = reqwest::Client::new();
    let url = format!("{}/{}", server.base_url, path);

    let range = format!("bytes={}-", content.len()); // Start exactly at end, invalid
    let response = client.get(&url).header("Range", range).send().await?;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::RANGE_NOT_SATISFIABLE
    );
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CONTENT_RANGE)
            .unwrap().to_str()?,
        format!("bytes */{}", content.len())
    );

    shutdown_test_server(server).await?;
    Ok(())
}

#[tokio::test]
async fn test_range_request_invalid_format_fallback() -> Result<()> {
    // Test that an invalid range header is ignored and returns the full content
    let content = b"some data";
    let path = "fallback.txt";
    let server = setup_static_server(&[(path, content)], None, None).await?;
    let client = reqwest::Client::new();
    let url = format!("{}/{}", server.base_url, path);

    // Invalid ranges
    let ranges = [
        "bytes=10-5",
        "bytes=-a",
        "bits=0-10",
        "bytes=10-5, 20-25", // Multi-range currently treated as invalid format
    ];

    for range in ranges {
        let response = client.get(&url).header("Range", range).send().await?;
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert!(response.headers().get(reqwest::header::CONTENT_RANGE).is_none());
        assert_eq!(
            response.headers().get(reqwest::header::CONTENT_LENGTH).unwrap().to_str()?,
            content.len().to_string()
        );
        assert_eq!(response.text().await?, std::str::from_utf8(content)?);
    }

    shutdown_test_server(server).await?;
    Ok(())
}

#[tokio::test]
async fn test_range_request_head() -> Result<()> {
    let content = create_large_test_content(1000);
    let path = "headrange.bin";
    let server = setup_static_server(&[(path, &content)], None, None).await?;
    let client = reqwest::Client::new();
    let url = format!("{}/{}", server.base_url, path);

    let range = "bytes=50-149";
    let response = client.head(&url).header("Range", range).send().await?;

    assert_eq!(response.status(), reqwest::StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CONTENT_RANGE)
            .unwrap().to_str()?,
        "bytes 50-149/1000"
    );
    assert_eq!(
        response.headers().get(reqwest::header::CONTENT_LENGTH).unwrap().to_str()?,
        "100"
    );
    assert_eq!(
        response.headers().get(reqwest::header::ACCEPT_RANGES).unwrap().to_str()?,
        "bytes"
    );
    let body = response.text().await?;
    assert!(body.is_empty());

    shutdown_test_server(server).await?;
    Ok(())
}

#[tokio::test]
async fn test_range_request_from_cache() -> Result<()> {
    // Force caching by making file size <= max file cache bytes
    let content = create_large_test_content(512); // Small enough to cache by default (1MiB)
    let path = "cached_range.bin";
    let server = setup_static_server(&[(path, &content)], Some(1024), Some(10 * 1024)).await?;
    let client = reqwest::Client::new();
    let url = format!("{}/{}", server.base_url, path);

    // 1. Initial request to populate cache (optional but good practice)
    let _ = client.get(&url).send().await?;
    sleep(Duration::from_millis(50)).await; // Give cache time

    // 2. Range request (should be served from cache)
    let range = "bytes=10-29";
    let response = client.get(&url).header("Range", range).send().await?;

    assert_eq!(response.status(), reqwest::StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CONTENT_RANGE)
            .unwrap().to_str()?,
        "bytes 10-29/512"
    );
    assert_eq!(
        response.headers().get(reqwest::header::CONTENT_LENGTH).unwrap().to_str()?,
        "20"
    );

    let body_bytes = response.bytes().await?;
    assert_eq!(body_bytes.len(), 20);
    assert_eq!(&body_bytes[..], &content[10..=29]);

    shutdown_test_server(server).await?;
    Ok(())
}

#[tokio::test]
async fn test_range_request_conditional_304() -> Result<()> {
    let content = b"conditional range content";
    let path = "cond_range.txt";
    let server = setup_static_server(&[(path, content)], None, None).await?;
    let client = reqwest::Client::new();
    let url = format!("{}/{}", server.base_url, path);

    // 1. Get the ETag (must be identity ETag)
    let initial_response = client.get(&url).send().await?;
    assert_eq!(initial_response.status(), reqwest::StatusCode::OK);
    let etag = initial_response
        .headers()
        .get(reqwest::header::ETAG)
        .expect("ETag header missing")
        .clone(); // Clone the HeaderValue

    // 2. Make a range request with If-None-Match using the ETag
    let range = "bytes=5-10";
    let response = client
        .get(&url)
        .header("Range", range)
        .header(reqwest::header::IF_NONE_MATCH, etag)
        .send()
        .await?;

    // Expect 304 Not Modified, ignoring the Range header
    assert_eq!(response.status(), reqwest::StatusCode::NOT_MODIFIED);
    assert!(response.headers().get(reqwest::header::CONTENT_RANGE).is_none());
    assert!(response.headers().get(reqwest::header::CONTENT_LENGTH).is_none());
    // 304 should still advertise range support
    assert_eq!(
        response.headers().get(reqwest::header::ACCEPT_RANGES).unwrap().to_str()?,
        "bytes"
    );
    // The original ETag should be present
    assert!(response.headers().get(reqwest::header::ETAG).is_some());

    shutdown_test_server(server).await?;
    Ok(())
}
