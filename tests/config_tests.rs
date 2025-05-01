use anyhow::{Context, Result};
use lemon::config::load_and_validate_config;
use rcgen::{CertificateParams, DistinguishedName, Ia5String, KeyPair, PKCS_RSA_SHA256, SanType};
use std::net::IpAddr;
use tempfile::tempdir;
use tokio::fs;

// Helper to write temp config
async fn write_temp_config(filename: &str, content: &str) -> Result<()> {
    fs::write(filename, content).await?;
    Ok(())
}

// Helper to clean up temp config
async fn cleanup_temp_config(filename: &str) {
    let _ = fs::remove_file(filename).await;
}

#[tokio::test]
async fn test_load_valid_minimal_config() -> Result<()> {
    let config_content = r#"
[server.main]
listen_addr = "127.0.0.1:8080"
security = {}

[server.main.handler]
type = "health_check"
"#;
    let filename = "test_valid_minimal_config.toml";

    write_temp_config(filename, config_content).await?;

    let result = load_and_validate_config(filename).await;
    cleanup_temp_config(filename).await;

    assert!(
        result.is_ok(),
        "Failed to load valid minimal config: {:?}",
        result.err()
    );

    Ok(())
}

#[tokio::test]
async fn test_load_valid_static_config() -> Result<()> {
    let config_content = r#"
[server.web]
listen_addr = "127.0.0.1:8081"
security = {}

[server.web.handler]
type = "static"
www_root = "/tmp/lemon_test_www" # Needs to be non-empty, existence not checked here
"#;
    let filename = "test_valid_static_config.toml";

    let _ = fs::create_dir_all("/tmp/lemon_test_www").await;

    write_temp_config(filename, config_content).await?;

    let result = load_and_validate_config(filename).await;
    cleanup_temp_config(filename).await;

    assert!(
        result.is_ok(),
        "Failed to load valid static config: {:?}",
        result.err()
    );

    let _ = fs::remove_dir_all("/tmp/lemon_test_www").await;

    Ok(())
}

#[tokio::test]
async fn test_invalid_static_empty_www_root() -> Result<()> {
    let config_content = r#"
[server.web]
listen_addr = "127.0.0.1:8082"
security = {}

[server.web.handler]
type = "static"
www_root = "" # Use empty string instead of missing field
"#;
    let filename = "test_invalid_static_empty_www_root.toml";

    write_temp_config(filename, config_content).await?;

    let result = load_and_validate_config(filename).await;
    cleanup_temp_config(filename).await;

    assert!(
        result.is_err(),
        "Expected loading config with empty www_root to fail, but it succeeded."
    );

    if let Err(e) = result {
        assert!(
            format!("{:?}", e).contains("Handler type 'static' requires a non-empty 'www_root'"),
            "Debug representation of error did not contain expected content. Got: {:?}",
            e
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_invalid_acme_bad_contact() -> Result<()> {
    let config_content = r#"
[server.secure]
listen_addr = "127.0.0.1:8443"
security = {}

[server.secure.tls]
type = "acme"
domains = ["example.com"]
contact = "not-an-email@example.com" # Missing mailto:
cache_dir = "./acme-test-cache"

[server.secure.handler]
type = "health_check"
"#;
    let filename = "test_invalid_acme_bad_contact.toml";

    write_temp_config(filename, config_content).await?;

    let result = load_and_validate_config(filename).await;
    cleanup_temp_config(filename).await;

    assert!(
        result.is_err(),
        "Expected loading config with bad ACME contact to fail, but it succeeded."
    );
    if let Err(e) = result {
        let err_dbg = format!("{:?}", e);
        assert!(
            err_dbg.contains("TLS type 'acme' contact must start with 'mailto:'"),
            "Debug representation of error did not contain expected content for bad contact. Got: {:?}",
            err_dbg
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_invalid_reverse_proxy_bad_url() -> Result<()> {
    let config_content = r#"
[server.proxy]
listen_addr = "127.0.0.1:8090"
security = {}

[server.proxy.handler]
type = "reverse_proxy"
target_url = "this is not a valid url" # Invalid URL
"#;
    let filename = "test_invalid_reverse_proxy_bad_url.toml";

    write_temp_config(filename, config_content).await?;

    let result = load_and_validate_config(filename).await;
    cleanup_temp_config(filename).await;

    assert!(
        result.is_err(),
        "Expected loading config with bad reverse proxy URL to fail, but it succeeded."
    );
    if let Err(e) = result {
        let err_dbg = format!("{:?}", e);
        assert!(
            err_dbg.contains("Invalid 'target_url' for reverse_proxy handler")
                && err_dbg.contains("relative URL without a base"),
            "Debug representation of error did not contain expected content for bad URL. Got: {:?}",
            err_dbg
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_valid_manual_tls_config() -> Result<()> {
    let temp_dir = tempdir().context("Failed to create temp dir")?;
    let dir_path = temp_dir.path();

    // 1. Generate Self-Signed Cert and Key
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new(); // Empty DN
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
    let key_pem = key_pair.serialize_pem(); // Serialize key pair

    // 2. Write Cert and Key to Temp Files
    let cert_path = dir_path.join("test.crt");
    let key_path = dir_path.join("test.key");
    fs::write(&cert_path, cert_pem)
        .await
        .context("Failed to write temp cert")?;
    fs::write(&key_path, key_pem)
        .await
        .context("Failed to write temp key")?;

    // 3. Create lemon.toml content
    let config_content = format!(
        r#"
[server.manual_tls_test]
listen_addr = "127.0.0.1:9443"
security = {{}}

[server.manual_tls_test.tls]
type = "manual"
certificate_file = "{}"
key_file = "{}"

[server.manual_tls_test.handler]
type = "health_check"
"#,
        cert_path.display(),
        key_path.display()
    );

    // 4. Write config to temp file
    let config_path = dir_path.join("lemon.toml");
    fs::write(&config_path, config_content)
        .await
        .context("Failed to write temp config")?;

    // 5. Load and Validate
    let config_path_str = config_path.to_str().expect("Temp path is not valid UTF-8");
    let result = load_and_validate_config(config_path_str).await;

    // Assertion
    assert!(
        result.is_ok(),
        "Failed to load valid manual TLS config: {:?}",
        result.err()
    );

    Ok(())
}
