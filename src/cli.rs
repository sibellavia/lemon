use crate::config;
use crate::config::LemonConfig;
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{debug, info};

#[derive(Parser, Debug)]
#[command(author, version, about = "🍋 Lemon: a general-purpose web server")]
pub struct Cli {
    /// Path to the lemon configuration file.
    #[arg(
        short,
        long,
        value_name = "FILE",
        global = true, // allows specifying --config before or after subcommand
        default_value = "lemon.toml"
    )]
    pub config: PathBuf,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Run Lemon (default command)
    Run,

    /// Validate the configuration file and exit.
    Validate,

    /// Create a basic lemon.toml config file in the current directory.
    #[command(name = "create-config")]
    CreateConfig {
        /// Overwrite existing lemon.toml file if present.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    // NOTE: 'help' and 'version' subcommands/flags are automatically handled by clap
    // based on the attributes on the `Cli` struct and Cargo.toml.
}

pub fn parse_args() -> Cli {
    Cli::parse()
}

// --- Command Implementations ---

pub(crate) async fn validate_config_cmd(
    config_path: &Path,
    config: Option<LemonConfig>,
) -> Result<()> {
    if config.is_none() {
        if !config_path.exists() {
            bail!("Configuration file not found: {}", config_path.display());
        }
        let config_path_str = config_path.to_str().ok_or_else(|| {
            anyhow::anyhow!(
                "Configuration path is not valid UTF-8: {}",
                config_path.display()
            )
        })?;

        config::load_and_validate_config(config_path_str)
            .await
            .with_context(|| format!("Validation failed for '{}'", config_path.display()))?;
    } else {
        debug!("Using pre-validated configuration for validation check.");
    }

    info!(
        "✅ Configuration file '{}' is valid.",
        config_path.display()
    );
    Ok(())
}

pub(crate) async fn create_default_config_cmd(config_path: &Path, force: bool) -> Result<PathBuf> {
    if config_path.exists() && !force {
        bail!(
            "Configuration file '{}' already exists. Use --force to overwrite.",
            config_path.display()
        );
    }

    let default_content = r#"# Default Lemon Configuration
# Define at least one server instance below.

# Example HTTP Static Server:
# Serves files from the './public' directory on port 8080.
[server.my_http_site]
listen_addr = "127.0.0.1:8080" # Use 0.0.0.0:8080 to listen on all interfaces

[server.my_http_site.handler]
type = "static"
www_root = "./public" # Path relative to where 'lemon' runs


# Example HTTPS Server using Let's Encrypt (ACME):
# Make sure your domain points to this server's public IP.
# [server.my_secure_site]
# listen_addr = "0.0.0.0:443" # Standard HTTPS port
# tls = { type = "acme", domains = ["yourdomain.com", "www.yourdomain.com"], contact = "mailto:you@yourdomain.com" }
#
# [server.my_secure_site.handler]
# type = "static"
# www_root = "./public_secure" # Serve from a different directory
#
# # Optional security headers configuration:
# [server.my_secure_site.security]
# add_default_headers = true      # Default: true. Adds HSTS (for HTTPS), X-Frame-Options, X-Content-Type-Options
# frame_options = "DENY"          # Default: DENY. Alternatives: "SAMEORIGIN", "NONE"
# # hsts_max_age = 31536000       # Default: 1 year. HSTS max age in seconds.
# # hsts_include_subdomains = true # Default: true. Include subdomains in HSTS.
# # hsts_preload = false          # Default: false. Add HSTS preload directive.


# Example Reverse Proxy:
# Forwards requests from port 9000 to a backend service running on port 5000.
# [server.api_proxy]
# listen_addr = "127.0.0.1:9000"
#
# [server.api_proxy.handler]
# type = "reverse_proxy"
# target_url = "http://localhost:5000"

"#;

    fs::write(config_path, default_content)
        .await
        .with_context(|| {
            format!(
                "Failed to write default config to '{}'",
                config_path.display()
            )
        })?;

    // Return Ok with the path to indicate success
    let created_path = config_path.to_path_buf();
    info!(
        "✅ Successfully created default config file: {}",
        created_path.display()
    );
    Ok(created_path)
}
