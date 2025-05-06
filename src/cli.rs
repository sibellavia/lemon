use crate::config;
use crate::config::LemonConfig;
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{error, debug, info, warn};
use std::process::Command;
use nix::unistd::Uid;
use std::fs as other_fs;

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

    /// (Requires sudo) Sets up Lemon to run as a systemd service.
    /// This will create a 'lemon' system user/group, configure directories,
    /// and install a systemd unit file.
    #[command(name = "setup-systemd")]
    SetupSystemd,

    /// (Requires sudo) Stops, disables, and removes the Lemon systemd service.
    /// It does not remove the 'lemon' user, configuration files, or data directories.
    #[command(name = "uninstall-systemd")]
    UninstallSystemd,
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

// --- Constants for systemd setup ---
const LEMON_USER: &str = "lemon";
const LEMON_GROUP: &str = "lemon";
const DEFAULT_WORKING_DIR: &str = "/opt/lemon"; // Where lemon and its assets might reside
const DEFAULT_CONFIG_FILE_PATH: &str = "/etc/lemon/lemon.toml";
const DEFAULT_ACME_CACHE_DIR: &str = "/var/lib/lemon/acme-cache";
const DEFAULT_LOG_DIR: &str = "/var/log/lemon";
const SYSTEMD_SERVICE_FILE_PATH: &str = "/etc/systemd/system/lemon.service";
const LEMON_SYSTEM_BINARY_PATH: &str = "/usr/local/bin/lemon"; // New location for the binary

// --- Helper function to run system commands ---
fn run_system_command(command_name: &str, args: &[&str]) -> Result<()> {
    info!("Executing: {} {}", command_name, args.join(" "));
    let status = Command::new(command_name).args(args).status()?;

    if !status.success() {
        error!(
            "Command '{}' failed with exit code: {:?}",
            command_name,
            status.code()
        );
        bail!("Failed to execute system command: {}", command_name);
    }
    Ok(())
}

// Placeholder for the systemd setup logic
pub async fn systemd_setup_cmd() -> Result<()> {
    info!("Starting systemd setup for Lemon Web Server...");

    // 1. Check for root privileges
    if !Uid::current().is_root() {
        error!("The 'setup-systemd' command must be run as root (e.g., using sudo).");
        bail!("Permission denied. Please run with sudo.");
    }
    info!("Running with root privileges.");

    // 2. Create lemon user and group (if they don't already exist)
    info!("Ensuring '{}' group exists...", LEMON_GROUP);
    match run_system_command("getent", &["group", LEMON_GROUP]) {
        Ok(_) => info!("Group '{}' already exists.", LEMON_GROUP),
        Err(_) => {
            info!("Group '{}' not found, creating...", LEMON_GROUP);
            run_system_command("groupadd", &["--system", LEMON_GROUP])
                .context(format!("Failed to create group '{}'", LEMON_GROUP))?;
            info!("Group '{}' created successfully.", LEMON_GROUP);
        }
    }

    info!("Ensuring '{}' user exists...", LEMON_USER);
    match run_system_command("getent", &["passwd", LEMON_USER]) {
        Ok(_) => info!("User '{}' already exists.", LEMON_USER),
        Err(_) => {
            info!("User '{}' not found, creating...", LEMON_USER);
            run_system_command(
                "useradd",
                &[
                    "--system",
                    "--gid",
                    LEMON_GROUP,
                    "--home-dir",
                    DEFAULT_ACME_CACHE_DIR, // Or /var/lib/lemon as a general home
                    "--no-create-home", // We'll create the ACME dir specifically if needed
                    "--shell",
                    "/usr/sbin/nologin",
                    LEMON_USER,
                ],
            )
            .context(format!("Failed to create user '{}'", LEMON_USER))?;
            info!("User '{}' created successfully.", LEMON_USER);
        }
    }

    // 3. Create necessary directories and set permissions
    info!("Creating directories...");
    let dirs_to_create = [
        DEFAULT_WORKING_DIR,
        Path::new(DEFAULT_CONFIG_FILE_PATH).parent().unwrap().to_str().unwrap(), // /etc/lemon
        DEFAULT_ACME_CACHE_DIR,
        DEFAULT_LOG_DIR,
    ];

    for dir_path in dirs_to_create.iter() {
        info!("Ensuring directory '{}' exists...", dir_path);
        other_fs::create_dir_all(dir_path).with_context(|| format!("Failed to create directory '{}'", dir_path))?;
        info!("Setting ownership for '{}' to '{}:{}'...", dir_path, LEMON_USER, LEMON_GROUP);
        run_system_command("chown", &["-R", &format!("{}:{}", LEMON_USER, LEMON_GROUP), dir_path])
            .with_context(|| format!("Failed to set ownership for directory '{}'", dir_path))?;
    }
    info!("Directories created and permissions set.");

    // 4. Get current binary path (where `setup-systemd` is being run from)
    info!("Determining path of the currently running lemon executable...");
    let current_exe_path = std::env::current_exe()
        .context("Failed to get current executable path")?;
    info!("Current lemon executable path: {}", current_exe_path.display());

    // 4b. Copy the binary to a system location
    info!("Copying lemon executable from {} to {}...", current_exe_path.display(), LEMON_SYSTEM_BINARY_PATH);
    other_fs::copy(&current_exe_path, LEMON_SYSTEM_BINARY_PATH).with_context(|| 
        format!("Failed to copy lemon binary from {} to {}", current_exe_path.display(), LEMON_SYSTEM_BINARY_PATH)
    )?;
    info!("Setting execute permissions on {}...", LEMON_SYSTEM_BINARY_PATH);
    run_system_command("chmod", &["+x", LEMON_SYSTEM_BINARY_PATH])
        .with_context(|| format!("Failed to set execute permissions on {}", LEMON_SYSTEM_BINARY_PATH))?;
    info!("Lemon executable copied and permissions set at {}.", LEMON_SYSTEM_BINARY_PATH);

    // 5. Generate and write the systemd service file
    info!("Generating systemd service file content...");
    let service_file_content = format!(
        r#"[Unit]
Description=Lemon Web Server
Documentation=https://github.com/sibellavia/lemon
After=network.target network-online.target
Requires=network-online.target

[Service]
User={LEMON_USER}
Group={LEMON_GROUP}
WorkingDirectory={DEFAULT_WORKING_DIR}
ExecStart={LEMON_SYSTEM_BINARY_PATH} run --config {DEFAULT_CONFIG_FILE_PATH}
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
Environment="RUST_LOG=info"

[Install]
WantedBy=multi-user.target
"#
    );

    info!("Writing systemd service file to {}...", SYSTEMD_SERVICE_FILE_PATH);
    other_fs::write(SYSTEMD_SERVICE_FILE_PATH, service_file_content)
        .with_context(|| format!("Failed to write systemd service file to {}", SYSTEMD_SERVICE_FILE_PATH))?;
    info!("Systemd service file written successfully.");

    // 6. Set capabilities on the lemon binary (at its new system location)
    info!(
        "Setting CAP_NET_BIND_SERVICE capability on '{}'...",
        LEMON_SYSTEM_BINARY_PATH
    );
    run_system_command(
        "setcap",
        &["cap_net_bind_service=+ep", LEMON_SYSTEM_BINARY_PATH],
    )
    .with_context(|| format!(
        "Failed to set capabilities on '{}'. Ensure setcap utility is installed.",
        LEMON_SYSTEM_BINARY_PATH
    ))?;
    info!("Capabilities set successfully.");

    // 7. Run systemctl commands
    info!("Reloading systemd daemon...");
    run_system_command("systemctl", &["daemon-reload"])
        .with_context(|| "Failed to reload systemd daemon")?;

    info!("Enabling lemon service to start on boot...");
    run_system_command("systemctl", &["enable", "lemon.service"])
        .with_context(|| "Failed to enable lemon service")?;

    info!("Starting lemon service...");
    run_system_command("systemctl", &["start", "lemon.service"])
        .with_context(|| "Failed to start lemon service")?;

    info!("------------------------------------------------------------");
    info!("🍋 Lemon systemd service setup complete!");
    info!("------------------------------------------------------------");
    info!("Your Lemon server should now be running and enabled on boot.");
    info!("You can check its status with: sudo systemctl status lemon.service");
    info!("Logs can be viewed with: journalctl -u lemon.service -f");
    info!("Default configuration path: {}", DEFAULT_CONFIG_FILE_PATH);
    info!("Default working directory: {}", DEFAULT_WORKING_DIR);
    info!("Ensure your {} is configured correctly.", DEFAULT_CONFIG_FILE_PATH);

    Ok(())
}

// Command implementation for uninstalling systemd service
pub async fn systemd_uninstall_cmd() -> Result<()> {
    info!("Starting systemd uninstall for Lemon Web Server...");

    // 1. Check for root privileges
    if !Uid::current().is_root() {
        error!("The 'uninstall-systemd' command must be run as root (e.g., using sudo).");
        bail!("Permission denied. Please run with sudo.");
    }
    info!("Running with root privileges.");

    // 2. Stop the service
    info!("Stopping lemon.service...");
    // Use a dedicated run_system_command that doesn't bail hard on expected failures (like service not found)
    match run_system_command_allow_failure("systemctl", &["stop", "lemon.service"]) {
        Ok(_) => info!("lemon.service stopped (if it was running)."),
        Err(e) => warn!("Attempt to stop lemon.service encountered an issue (might be okay if not running): {}", e),
    }

    // 3. Disable the service
    info!("Disabling lemon.service...");
    match run_system_command_allow_failure("systemctl", &["disable", "lemon.service"]) {
        Ok(_) => info!("lemon.service disabled (if it was enabled)."),
        Err(e) => warn!("Attempt to disable lemon.service encountered an issue (might be okay if not enabled): {}", e),
    }

    // 4. Remove the systemd service file
    info!("Removing systemd service file: {}...", SYSTEMD_SERVICE_FILE_PATH);
    if Path::new(SYSTEMD_SERVICE_FILE_PATH).exists() {
        other_fs::remove_file(SYSTEMD_SERVICE_FILE_PATH)
            .with_context(|| format!("Failed to remove systemd service file: {}", SYSTEMD_SERVICE_FILE_PATH))?;
        info!("Systemd service file removed successfully.");
    } else {
        info!("Systemd service file {} not found, nothing to remove.", SYSTEMD_SERVICE_FILE_PATH);
    }

    // 5. Reload systemd daemon
    info!("Reloading systemd daemon...");
    run_system_command("systemctl", &["daemon-reload"])
        .context("Failed to reload systemd daemon")?;
    info!("Systemd daemon reloaded.");

    info!("------------------------------------------------------------");
    info!("🍋 Lemon systemd service uninstallation complete!");
    info!("------------------------------------------------------------");
    info!("The lemon.service has been stopped, disabled, and its unit file removed.");
    info!("The following items have NOT been removed and may require manual cleanup if desired:");
    info!("- Lemon binary: {}", LEMON_SYSTEM_BINARY_PATH);
    info!("- 'lemon' user and group");
    info!("- Configuration directory: {}", Path::new(DEFAULT_CONFIG_FILE_PATH).parent().unwrap().display());
    info!("- Working directory: {}", DEFAULT_WORKING_DIR);
    info!("- ACME cache directory: {}", DEFAULT_ACME_CACHE_DIR);
    info!("- Log directory: {}", DEFAULT_LOG_DIR);

    Ok(())
}

// Helper function to run system commands, allowing for non-zero exit codes for certain operations
fn run_system_command_allow_failure(command_name: &str, args: &[&str]) -> Result<()> {
    info!("Executing (allowing failure): {} {}", command_name, args.join(" "));
    let status = Command::new(command_name).args(args).status()?;

    if !status.success() {
        // Log as a warning instead of an error, and don't bail hard
        warn!(
            "Command '{}' completed with a non-success exit code: {:?}. This might be expected.",
            command_name,
            status.code()
        );
        // Still return an error so the caller can decide if it's truly an issue
        bail!("System command '{}' did not succeed as expected, but failure was allowed.", command_name);
    }
    Ok(())
}