/// Encapsulates the server launching process, returning
/// the JoinHandle for each server task.
// Standard library imports
use std::{io::BufReader, net::IpAddr, net::SocketAddr, sync::Arc};

// Async runtime and utilities
use tokio::{fs, net::TcpListener};

// HTTP and TLS
use tokio_rustls::TlsAcceptor;

// Added rustls imports
// Use specific types from pki_types
use rustls::ServerConfig as RustlsServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{Item, certs};

use rcgen::{CertificateParams, DistinguishedName, Ia5String, KeyPair, PKCS_RSA_SHA256, SanType};

// Logging and error handling
use anyhow::{Context, Result, bail};
use tracing::{info, warn};

// Internal imports
use crate::{
    config::LemonConfig,
    config::{ServerConfig, TlsConfig, TlsManualConfig},
    handlers::{AcmeRedirectHandler, SharedHandler, create_handler},
    tls::AcmeState,
};

type ShutdownRx = tokio::sync::watch::Receiver<()>;

/// Holds a bound listener and all necessary context to handle its connections.
pub struct ListenerContext {
    pub server_name: String,
    pub listener: TcpListener,
    pub handler: SharedHandler,
    pub tls_acceptor: Option<TlsAcceptor>,
    pub shutdown_rx: ShutdownRx,
}

/// Helper function to load TLS cert and key from files for manual configuration
async fn load_manual_tls(config: &TlsManualConfig) -> Result<TlsAcceptor> {
    // Read certificate chain file
    let cert_data = fs::read(&config.certificate_file)
        .await
        .with_context(|| format!("Reading cert file {}", config.certificate_file.display()))?;
    let mut cert_reader = BufReader::new(cert_data.as_slice());
    // Collect results from the iterator before using ?
    let cert_chain = certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>() // Collect into Result<Vec<_>>
        .with_context(|| format!("Parsing cert file {}", config.certificate_file.display()))?;

    if cert_chain.is_empty() {
        bail!(
            "No valid PEM certificates found in {}",
            config.certificate_file.display()
        );
    }

    // Read private key file
    let key_data = fs::read(&config.key_file)
        .await
        .with_context(|| format!("Reading key file {}", config.key_file.display()))?;
    let mut key_reader = BufReader::new(key_data.as_slice());

    // Find the first valid private key
    // Use PrivateKeyDer enum
    let mut key: Option<PrivateKeyDer<'static>> = None;
    // Use ? directly on read_one within the loop
    while let Some(item_result) = rustls_pemfile::read_one(&mut key_reader)? {
        match item_result {
            Item::Pkcs1Key(k) => {
                key = Some(PrivateKeyDer::Pkcs1(k));
                break;
            }
            Item::Pkcs8Key(k) => {
                key = Some(PrivateKeyDer::Pkcs8(k));
                break;
            }
            Item::Sec1Key(k) => {
                key = Some(PrivateKeyDer::Sec1(k));
                break;
            }
            _ => {} // Ignore other PEM items like certificates in the key file
        }
    }

    let key = key.ok_or_else(|| {
        anyhow::anyhow!(
            "No valid PEM private key (PKCS1, PKCS8, SEC1) found in {}",
            config.key_file.display()
        )
    })?;

    // Create rustls ServerConfig
    // Use the corrected cert_chain and key types
    let mut rustls_config = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key) // expects Vec<CertificateDer> and PrivateKeyDer
        .with_context(|| {
            format!(
                "Creating rustls config from cert {} and key {}",
                config.certificate_file.display(),
                config.key_file.display()
            )
        })?;

    // Configure ALPN for HTTP/2 and HTTP/1.1
    rustls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    info!(
        "Manual TLS ALPN protocols configured: {:?}",
        rustls_config.alpn_protocols
    );

    Ok(TlsAcceptor::from(Arc::new(rustls_config)))
}

/// Generates a self-signed certificate for local development and creates a TlsAcceptor.
/// The certificate is valid for localhost and 127.0.0.1.
fn generate_local_dev_tls() -> Result<TlsAcceptor> {
    info!("Generating self-signed certificate for local development (localhost, 127.0.0.1)");

    // 1. Generate Cert/Key using rcgen
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new(); // Use empty DN
    // Add Subject Alternative Names (SANs) for localhost and 127.0.0.1
    params.subject_alt_names = vec![
        SanType::DnsName(
            Ia5String::try_from("localhost".to_string())
                .with_context(|| "Failed to create Ia5String for localhost SAN")?,
        ),
        SanType::IpAddress(IpAddr::V4("127.0.0.1".parse()?)),
    ];
    // Optional: Set validity period (e.g., 1 year)
    // params.not_before = time::OffsetDateTime::now_utc();
    // params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);

    let key_pair = KeyPair::generate_for(&PKCS_RSA_SHA256)
        .with_context(|| "Failed to generate key pair for local dev cert")?;
    let cert = params
        .self_signed(&key_pair)
        .with_context(|| "Failed to self-sign local dev certificate")?;

    // Get certificate and key in required formats (DER)
    let cert_der: CertificateDer<'static> = CertificateDer::from(cert.der().to_vec());
    let key_der: PrivateKeyDer<'static> =
        PrivateKeyDer::try_from(key_pair.serialize_der()).map_err(anyhow::Error::msg)?;

    // 2. Create rustls ServerConfig
    let mut rustls_config = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der) // Pass DER encoded cert/key
        .with_context(|| "Failed to create rustls config for local dev cert")?;

    // 3. Configure ALPN for HTTP/2 and HTTP/1.1
    rustls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    info!(
        "Local Dev TLS ALPN protocols configured: {:?}",
        rustls_config.alpn_protocols
    );

    // 4. Create and return TlsAcceptor
    Ok(TlsAcceptor::from(Arc::new(rustls_config)))
}

/// Prepares the handler and TLS acceptor for a single server configuration.
async fn prepare_server_components(
    server_name: &str,
    server_config: &ServerConfig, // Use reference
    acme_state: &AcmeState,       // Use immutable reference for now
) -> Result<(SharedHandler, Option<TlsAcceptor>)> {
    // 1. Create the handler (synchronous, needs full server_config)
    let handler = create_handler(
        &server_config.handler,
        server_config, // Pass the whole server config
        None,          // TODO: Revisit ACME state integration
        None,          // TODO: Revisit ACME state integration
    )
    .with_context(|| format!("Failed to create handler for server '{}'", server_name))?;

    // 2. Determine TLS Acceptor
    let tls_acceptor_option = match &server_config.tls {
        None => {
            // HTTP server
            info!(server_name = %server_name, "Configured for HTTP (no TLS).");
            None
        }
        Some(tls_config) => {
            // HTTPS server
            info!(server_name = %server_name, "Configuring for HTTPS...");
            let acceptor = match tls_config {
                TlsConfig::Acme(acme_config) => {
                    info!(server_name = %server_name, domains = ?acme_config.domains, "Using ACME TLS configuration.");
                    if let Some(acceptor) = &acme_state.acceptor {
                        info!(server_name = %server_name, "Using shared ACME TlsAcceptor.");
                        acceptor.clone()
                    } else {
                        bail!(
                            "ACME TLS configured for server '{}', but ACME state acceptor is missing.",
                            server_name
                        );
                    }
                }
                TlsConfig::Manual(manual_config) => {
                    info!(server_name = %server_name, cert = %manual_config.certificate_file.display(), key = %manual_config.key_file.display(), "Using Manual TLS configuration.");
                    // Await the loading directly here
                    load_manual_tls(manual_config).await.with_context(|| {
                        format!("Failed to load manual TLS for server '{}'", server_name)
                    })?
                }
                TlsConfig::LocalDev(_) => {
                    info!(server_name = %server_name, "Using Local Development TLS configuration (self-signed).");
                    // generate_local_dev_tls is sync
                    generate_local_dev_tls().with_context(|| {
                        format!(
                            "Failed to generate local development TLS for server '{}'",
                            server_name
                        )
                    })?
                }
            };
            Some(acceptor) // Wrap the result in Some
        }
    };

    Ok((handler, tls_acceptor_option))
}

/// Prepares listeners and their context based on the configuration.
/// This function binds all TCP listeners but does not start accepting connections yet.
pub async fn prepare_listeners(
    config: &LemonConfig,
    acme_state: &mut AcmeState,
    shutdown_rx: ShutdownRx,
) -> Result<Vec<ListenerContext>> {
    let mut listener_contexts = Vec::new();
    let mut acme_on_443_exists = false; // Track if ACME is configured on default HTTPS port
    let mut explicit_port_80_exists = false; // Track if user configured port 80

    for (server_name, server_config) in &config.server {
        info!(server_name = %server_name, "Preparing server configuration...");

        // Check for explicit port 80 config before binding attempts
        if server_config.listen_addr.port() == 80 {
            explicit_port_80_exists = true;
        }
        // Check if this server uses ACME and is on port 443
        if let Some(TlsConfig::Acme(_)) = server_config.tls {
            if server_config.listen_addr.port() == 443 {
                acme_on_443_exists = true;
            }
        }

        // 1. Prepare Handler and TLS Acceptor
        match prepare_server_components(server_name, server_config, acme_state)
            .await // Await the preparation
        {
            Ok((handler, tls_acceptor)) => {
                // 2. Bind the listener
                let listener = match TcpListener::bind(server_config.listen_addr).await {
                    Ok(l) => l,
                    Err(e) => {
                        warn!(
                            server_name = %server_name,
                            addr = %server_config.listen_addr,
                            error = %e,
                            "Failed to bind listener; skipping server"
                        );
                        continue; // Skip this server
                    }
                };
                let server_addr = listener.local_addr()?;
                let server_protocol = if tls_acceptor.is_some() { "HTTPS" } else { "HTTP" };
                info!(server_name = %server_name, "{} listener bound to {}", server_protocol, server_addr);

                // 3. Create and store context
                listener_contexts.push(ListenerContext {
                    server_name: server_name.clone(),
                    listener,
                    handler,
                    tls_acceptor,
                    shutdown_rx: shutdown_rx.clone(), // Clone Rx for this listener context
                });
            }
            Err(e) => {
                warn!(server_name = %server_name, error = %e, "Skipping server due to component preparation error");
                continue; // Skip this server
            }
        }
    }

    // --- Add implicit ACME HTTP challenge listener if needed ---
    // Check if ACME state was initialized (meaning ACME config exists) AND
    // if an ACME server was configured on port 443 AND
    // if no server was explicitly configured for port 80.
    if acme_state.resolver.is_some() && acme_on_443_exists && !explicit_port_80_exists {
        let acme_resolver = acme_state
            .resolver
            .clone()
            .expect("Resolver checked as Some above");
        let acme_domains = acme_state
            .domains
            .clone()
            .expect("Domains should exist if resolver exists");

        let http_addr_v4: SocketAddr = "0.0.0.0:80".parse().unwrap();
        let http_addr_v6: SocketAddr = "[::]:80".parse().unwrap();
        let server_name = "acme-http-challenge".to_string();

        // Try binding IPv4 first, then IPv6 if IPv4 fails, log appropriately.
        // TODO: This covers most common scenarios. A more complex approach might bind both if possible.
        let listener_result = match TcpListener::bind(http_addr_v4).await {
            Ok(l) => {
                info!(server_name = %server_name, "Bound implicit ACME HTTP challenge listener to {}", http_addr_v4);
                Ok(l)
            }
            Err(e_v4) => {
                warn!(server_name = %server_name, addr = %http_addr_v4, error = %e_v4, "Failed to bind implicit ACME listener to IPv4, trying IPv6...");
                match TcpListener::bind(http_addr_v6).await {
                    Ok(l) => {
                        info!(server_name = %server_name, "Bound implicit ACME HTTP challenge listener to {}", http_addr_v6);
                        Ok(l)
                    }
                    Err(e_v6) => {
                        warn!(server_name = %server_name, addr = %http_addr_v6, error = %e_v6, "Failed to bind implicit ACME listener to IPv6 as well. ACME HTTP-01 challenge may fail.");
                        Err(anyhow::anyhow!(
                            "Failed to bind implicit ACME listener on port 80 (IPv4: {}, IPv6: {})",
                            e_v4,
                            e_v6
                        ))
                    }
                }
            }
        };

        if let Ok(listener) = listener_result {
            let handler = Arc::new(AcmeRedirectHandler {
                resolver: acme_resolver,
                https_domains: acme_domains,
            });
            listener_contexts.push(ListenerContext {
                server_name,
                listener,
                handler,
                tls_acceptor: None, // Plain HTTP
                shutdown_rx: shutdown_rx.clone(),
            });
        }
        // else: binding failed, warning already logged. Continue without implicit listener.
    }

    if listener_contexts.is_empty() && config.server.is_empty() {
        info!("No servers configured.");
    } else if listener_contexts.is_empty() && !config.server.is_empty() {
        bail!("All configured servers failed to prepare. See previous warnings.");
    }

    Ok(listener_contexts)
}
