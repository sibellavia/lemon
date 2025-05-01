use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::{collections::HashMap, net::SocketAddr, path::PathBuf, str::FromStr};
use tokio::fs;
use tracing::debug;
use tracing_subscriber::filter::LevelFilter;
use url::Url;

// --- Security Configuration ---
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    pub add_default_headers: Option<bool>,     // default true
    pub hsts_max_age: Option<u64>,             // seconds; default 31_536_000 (1 year)
    pub hsts_include_subdomains: Option<bool>, // default true
    pub hsts_preload: Option<bool>,            // default false
    pub frame_options: Option<String>,         // "DENY", "SAMEORIGIN", "NONE"
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            add_default_headers: Some(true),
            hsts_max_age: Some(31_536_000),
            hsts_include_subdomains: Some(true),
            hsts_preload: Some(false),
            frame_options: None,
        }
    }
}

// --- Logging Configuration ---

#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum LoggingFormat {
    #[default]
    Text,
    Json,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LoggingOutput {
    #[default]
    Stdout,
    File {
        path: PathBuf,
    },
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> LoggingFormat {
    LoggingFormat::Text
}

fn default_log_output() -> LoggingOutput {
    LoggingOutput::Stdout
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: LoggingFormat,
    #[serde(default = "default_log_output")]
    pub output: LoggingOutput,
}

// --- Top-Level Configuration ---

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct LemonConfig {
    #[serde(default)]
    pub server: HashMap<String, ServerConfig>,
    #[serde(default)]
    pub logging: Option<LoggingConfig>,
}

// --- Server Block Configuration ---

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub listen_addr: SocketAddr,
    pub tls: Option<TlsConfig>,
    pub handler: HandlerConfig,
    pub security: SecurityConfig,
}

// --- TLS Configuration ---

#[derive(Deserialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum TlsConfig {
    Acme(TlsAcmeConfig),
    Manual(TlsManualConfig),
    LocalDev(TlsLocalDevConfig),
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct TlsAcmeConfig {
    pub domains: Vec<String>,
    pub contact: String, // should validate mailto: prefix
    #[serde(default = "default_acme_cache_dir")]
    pub cache_dir: String, // PathBuf might be better if validated early
    #[serde(default)]
    pub staging: bool,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct TlsManualConfig {
    pub certificate_file: PathBuf,
    pub key_file: PathBuf,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct TlsLocalDevConfig {
    // This struct remains empty as local_dev doesn't require parameters.
}

fn default_acme_cache_dir() -> String {
    "./acme-cache".to_string()
}

// --- Handler Configuration ---

#[derive(Deserialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum HandlerConfig {
    Static(HandlerStaticConfig),
    HealthCheck(HandlerHealthCheckConfig),
    ReverseProxy(HandlerReverseProxyConfig),
    RedirectHttps(HandlerRedirectHttpsConfig),
    // future handlers like ApiGateway, Inference etc. would go here
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct HandlerStaticConfig {
    pub www_root: PathBuf,
    #[serde(default)] // Optional: Max size of a single file to cache in memory (bytes)
    pub content_cache_max_file_bytes: Option<u64>,
    #[serde(default)] // Optional: Max total size of the in-memory content cache (bytes)
    pub content_cache_max_total_bytes: Option<u64>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct HandlerHealthCheckConfig {}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct HandlerReverseProxyConfig {
    pub target_url: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct HandlerRedirectHttpsConfig {
    /// The base HTTPS URL to redirect to (e.g., "<https://example.com>").
    /// The original request path and query will be appended.
    pub target_base: String,
}

// --- Loading and Validation ---

/// Loads and parses the configuration from a TOML file, then validates it.
///
/// # Arguments
///
/// * `path` - Path to the lemon configuration file.
///
/// # Returns
///
/// Returns `Ok(LemonConfig)` if the file was read, parsed, and validated successfully.
/// Returns `Err` if any step fails.
pub async fn load_and_validate_config(path: &str) -> Result<LemonConfig> {
    let config_content = fs::read_to_string(path)
        .await
        .with_context(|| format!("Failed to read configuration file at '{}'", path))?;

    debug!("Read config file content from {}", path);

    let raw_config: LemonConfig = toml::from_str(&config_content)
        .with_context(|| format!("Failed to parse TOML configuration from '{}'", path))?;

    debug!("Parsed TOML configuration successfully.");

    validate_config(&raw_config).context("Configuration validation failed")?;

    debug!("Configuration validation passed.");

    Ok(raw_config)
}

/// Performs validation checks on the parsed LemonConfig.
pub fn validate_config(config: &LemonConfig) -> Result<()> {
    if config.server.is_empty() && config.logging.is_none() {
        bail!("Configuration must define at least one [[server]] block or a [logging] block.");
    }

    // --- Logging Validation ---
    if let Some(log_config) = &config.logging {
        if LevelFilter::from_str(&log_config.level.to_uppercase()).is_err() {
            bail!(
                "Invalid log level '{}' in [logging] configuration. Use one of: trace, debug, info, warn, error.",
                log_config.level
            );
        }
        if let LoggingOutput::File { path } = &log_config.output {
            if path.as_os_str().is_empty() {
                bail!("Logging output type 'file' requires a non-empty 'path'.");
            }
        }
        debug!("Logging config validated.");
    }

    // --- Server Validation ---
    for (name, server_config) in &config.server {
        debug!(server_name = %name, "Validating server config");

        // --- TLS Validation ---
        if let Some(tls_config) = &server_config.tls {
            match tls_config {
                TlsConfig::Acme(acme_config) => {
                    if acme_config.domains.is_empty() {
                        bail!(
                            "Server '{}': TLS type 'acme' requires at least one domain in 'domains'.",
                            name
                        );
                    }
                    if !acme_config.contact.starts_with("mailto:") {
                        bail!(
                            "Server '{}': TLS type 'acme' contact must start with 'mailto:'. Found: {}",
                            name,
                            acme_config.contact
                        );
                    }
                    if acme_config.cache_dir.is_empty() {
                        bail!(
                            "Server '{}': TLS type 'acme' requires a non-empty 'cache_dir'.",
                            name
                        );
                    }
                    debug!(server_name = %name, "ACME TLS config validated.");
                }
                TlsConfig::Manual(manual_config) => {
                    if manual_config.certificate_file.as_os_str().is_empty() {
                        bail!(
                            "Server '{}': TLS type 'manual' requires a non-empty 'certificate_file'.",
                            name
                        );
                    }
                    if manual_config.key_file.as_os_str().is_empty() {
                        bail!(
                            "Server '{}': TLS type 'manual' requires a non-empty 'key_file'.",
                            name
                        );
                    }
                    debug!(server_name = %name, "Manual TLS config paths validated (non-empty check).");
                }
                TlsConfig::LocalDev(_) => {
                    debug!(server_name = %name, "Local Dev TLS config type specified.");
                }
            }
        }

        // --- Handler Validation ---
        match &server_config.handler {
            HandlerConfig::Static(static_config) => {
                if static_config.www_root.as_os_str().is_empty() {
                    bail!(
                        "Server '{}': Handler type 'static' requires a non-empty 'www_root'.",
                        name
                    );
                }
                debug!(server_name = %name, "Static handler config validated.");
            }
            HandlerConfig::HealthCheck(_healthcheck) => {
                // no specific validation needed for health check handler
            }
            HandlerConfig::ReverseProxy(proxy_config) => {
                if proxy_config.target_url.is_empty() {
                    bail!(
                        "Server '{}': Handler type 'reverse_proxy' requires a non-empty 'target_url'.",
                        name
                    );
                }
                match url::Url::parse(&proxy_config.target_url) {
                    Ok(_) => {
                        debug!(server_name = %name, "Reverse proxy handler config validated (basic URL check).")
                    }
                    Err(e) => bail!(
                        "Server '{}': Invalid 'target_url' for reverse_proxy handler: {}",
                        name,
                        e
                    ),
                }
            }
            HandlerConfig::RedirectHttps(redirect_config) => {
                if redirect_config.target_base.is_empty() {
                    bail!(
                        "Server '{}': Handler type 'redirect_https' requires a non-empty 'target_base'.",
                        name
                    );
                }
                match Url::parse(&redirect_config.target_base) {
                    Ok(url) => {
                        if url.scheme() != "https" {
                            bail!(
                                "Server '{}': 'target_base' for redirect_https handler must use the HTTPS scheme. Found: {}",
                                name,
                                url.scheme()
                            );
                        }
                        if url.path() != "/" && url.path() != "" {
                            bail!(
                                "Server '{}': 'target_base' for redirect_https handler should be a base URL (e.g., \"https://example.com\") without a path component. Found path: {}",
                                name,
                                url.path()
                            );
                        }
                        if url.query().is_some() {
                            bail!(
                                "Server '{}': 'target_base' for redirect_https handler should not include a query string. Found: ?{}",
                                name,
                                url.query().unwrap()
                            );
                        }
                        if url.fragment().is_some() {
                            bail!(
                                "Server '{}': 'target_base' for redirect_https handler should not include a fragment. Found: #{}",
                                name,
                                url.fragment().unwrap()
                            );
                        }
                        debug!(server_name = %name, "Redirect HTTPS handler config validated.");
                    }
                    Err(e) => bail!(
                        "Server '{}': Invalid 'target_base' for redirect_https handler: {}",
                        name,
                        e
                    ),
                }
            }
        }

        // --- Security Validation ---
        if let Some(frame_opts) = &server_config.security.frame_options {
            let upper_opts = frame_opts.to_uppercase();
            if upper_opts != "DENY" && upper_opts != "SAMEORIGIN" && upper_opts != "NONE" {
                bail!(
                    "Server '{}': Invalid value for security.frame_options: '{}'. Must be one of 'DENY', 'SAMEORIGIN', or 'NONE'.",
                    name,
                    frame_opts
                );
            }
        }
        // HSTS values (max_age, include_subdomains, preload) don't need explicit validation here
        // as their types (u64, bool) enforce basic constraints.
        // add_default_headers (bool) also doesn't need validation.
        debug!(server_name = %name, "Security config validated.");
    }

    Ok(())
}
