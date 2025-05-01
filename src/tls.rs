/// Create the ACME configuration (AcmeConfig)
///
/// Initialize the ACME state machine
///
/// Create the ACME resolver (ResolvesServerCertAcme)
///
/// Configure rustls (ServerConfig, TlsAcceptor)
///
/// Spawn the background task that periodically interacts
/// with the Let's Encrypt servers to manage certificates (state.next().await)
///
/// It should produce the TlsAcceptor (for the HTTPS server) and
/// the Arc<ResolvesServerCertAcme>
use anyhow::{Context, Result, bail};
use futures::stream::StreamExt;
use rustls_acme::{AcmeConfig, ResolvesServerCertAcme, caches::DirCache};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{fs, sync::Mutex};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info};

/// Import config types needed for initialize_acme_state
use crate::config::{LemonConfig, TlsAcmeConfig, TlsConfig};

/// Holds the state related to ACME TLS setup.
#[derive(Default)] // Removed Debug derive
pub struct AcmeState {
    pub acceptor: Option<TlsAcceptor>,
    pub resolver: Option<Arc<ResolvesServerCertAcme>>,
    pub domains: Option<Arc<Vec<String>>>,
}

/// Inputs:
///
/// We pass only the specific configuration values needed from lemon_config.
/// We take ownership of https_domains and acme_contact.
///
/// Outputs:
///
/// it returns a Result containing a tuple:
/// - TlsAcceptor: needed by the HTTPS server to accept TLS connections.
/// - Arc<ResolvesServerCertAcme>: the ACME resolver, needed by the
///   HTTP challenge listener (handle_acme_or_redirect). Wrapped in Arc.
///
/// The function needs to be async because creating the cache directory
/// is an async operation.
async fn setup_acme_tls(
    http_domains: Vec<String>,
    acme_contact: String,
    acme_cache_dir: String,
    use_staging: bool,
) -> Result<(TlsAcceptor, Arc<ResolvesServerCertAcme>)> {
    // Ensure cache directory exists
    fs::create_dir_all(&acme_cache_dir).await?;
    let cache = DirCache::new(PathBuf::from(acme_cache_dir));

    // --- ACME/TLS Setup ---

    // Creating State
    let state = AcmeConfig::new(http_domains)
        .contact(vec![acme_contact])
        .cache(cache)
        .directory(if use_staging {
            rustls_acme::acme::LETS_ENCRYPT_STAGING_DIRECTORY
        } else {
            rustls_acme::acme::LETS_ENCRYPT_PRODUCTION_DIRECTORY
        })
        .state();

    // Creating Resolver
    let resolver = state.resolver();

    // Creating State Arc mutex
    let state_arc_mutex = Arc::new(Mutex::new(state));
    let resolver_clone = resolver.clone(); // Clone resolver for the server config

    // Creating rustls::ServerConfig
    let mut rustls_server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver_clone); // Use the cloned resolver here

    rustls_server_config.alpn_protocols =
        vec![b"acme-tls/1".to_vec(), b"h2".to_vec(), b"http/1.1".to_vec()];

    info!(
        "ServerConfig ALPN protocols configured: {:?}",
        rustls_server_config.alpn_protocols
    );

    // Creating acceptor
    let acceptor = TlsAcceptor::from(Arc::new(rustls_server_config));

    // Spawn ACME Background Task
    let acme_runner_state = Arc::clone(&state_arc_mutex);
    tokio::spawn(async move {
        loop {
            info!("ACME background task: Acquiring state lock...");
            let mut guard = acme_runner_state.lock().await;
            info!("ACME background task: Lock acquired. Checking state machine...");

            // Declare and initialize check_interval inside the loop
            let mut check_interval = Duration::from_secs(60 * 60);

            match guard.next().await {
                Some(Ok(event)) => {
                    debug!("ACME background task: Event received: {:?}", event);
                    // Potentially adjust check_interval based on the event if needed
                    // e.g., if a challenge needs immediate attention or renewal is close.
                }
                Some(Err(err)) => {
                    error!("ACME background task: Error processing state: {:?}", err);
                    // Consider shorter sleep on persistent errors
                    check_interval = Duration::from_secs(5 * 60);
                }
                None => {
                    error!("ACME background task: State stream ended unexpectedly. Stopping task.");
                    break;
                }
            }

            info!("ACME background task: Releasing state lock.");
            drop(guard); // Explicit drop for clarity before sleep

            info!("ACME background task: Sleeping for {:?}...", check_interval);
            tokio::time::sleep(check_interval).await; // Sleep *after* processing
        }
        info!("ACME background task: Exited loop.");
    });

    Ok((acceptor, resolver)) // Return the original resolver
}

/// Initializes ACME state if configured in any server block.
/// Only supports one ACME configuration block currently.
///
/// # Arguments
/// * `config` - A reference to the loaded Lemon configuration.
///
/// # Returns
/// A `Result` containing the `AcmeState` (potentially empty if no ACME config found),
/// or an error if multiple ACME configs are found or setup fails.
pub async fn initialize_acme_state(config: &LemonConfig) -> Result<AcmeState> {
    let mut acme_config_found: Option<(&String, &TlsAcmeConfig)> = None;

    // Find the first ACME configuration
    for (name, server_config) in &config.server {
        if let Some(TlsConfig::Acme(acme_conf)) = &server_config.tls {
            if acme_config_found.is_some() {
                bail!(
                    "Multiple servers configured with ACME TLS. Only one is currently supported."
                );
            }
            acme_config_found = Some((name, acme_conf));
            // Don't break here, allow the loop to finish to detect duplicates
        }
    }

    // If an ACME config was found, set it up
    if let Some((server_name, conf)) = acme_config_found {
        info!(server_name = %server_name, "Found ACME configuration. Setting up ACME TLS...");
        let (acceptor, resolver) = setup_acme_tls(
            conf.domains.clone(),
            conf.contact.clone(),
            conf.cache_dir.clone(),
            conf.staging,
        )
        .await
        .with_context(|| format!("Failed to setup ACME TLS for server '{}'", server_name))?;

        info!(server_name = %server_name, "ACME TLS setup complete.");
        Ok(AcmeState {
            acceptor: Some(acceptor),
            resolver: Some(resolver),
            domains: Some(Arc::new(conf.domains.clone())), // Clone domains again for state
        })
    } else {
        info!("No ACME TLS configuration found.");
        Ok(AcmeState::default()) // Return default empty state
    }
}
