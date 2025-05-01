pub mod cli;
pub mod common;
pub mod config;
pub mod connection;
pub mod handlers;
pub mod logging;
pub mod server;
pub mod shutdown;
pub mod tls;

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::config::LemonConfig;
use crate::server::prepare_listeners;
use crate::tls::AcmeState;
use std::thread;

use futures::future::{FutureExt, select_all};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use tokio::net::TcpStream;

/// Initializes ACME state, prepares listeners, starts the acceptor thread,
/// but does not yet spawn individual connection handling tasks.
pub async fn start_services(
    config: &LemonConfig,
    shutdown_rx: watch::Receiver<()>,
) -> Result<(
    AcmeState,
    thread::JoinHandle<Result<()>>,
    Vec<JoinHandle<Result<()>>>,
)> {
    // --- Initialize ACME State ---
    let mut acme_state = tls::initialize_acme_state(config).await?;

    // --- Prepare Listeners ---
    let listener_contexts = prepare_listeners(config, &mut acme_state, shutdown_rx.clone()).await?;

    // --- Get Main Runtime Handle ---
    let main_runtime_handle = tokio::runtime::Handle::current();

    // --- Spawn Acceptor Thread ---
    // Clone shutdown receiver for the acceptor thread itself
    let acceptor_shutdown_rx = shutdown_rx.clone();

    let acceptor_thread_handle = thread::Builder::new()
        .name("lemon-acceptor".into())
        .spawn(move || -> Result<()> { // Move contexts and handle into the thread
            info!("Acceptor thread started.");

            // Create a dedicated Tokio runtime for the acceptor thread
            let acceptor_runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .context("Failed to create acceptor runtime")?;

            // Run the acceptor loop within this dedicated runtime
            acceptor_runtime.block_on(async move {
                info!("Acceptor loop running on dedicated runtime.");

                // We need listener_contexts accessible throughout the loop for re-arming 
                // and getting context for handoff. Do not consume it when creating futures.
                let listener_contexts = listener_contexts; // Take ownership inside the async block

                // Create a vector of futures, each pinned and boxed.
                // Output is just the result of accept(), index comes from select_all.
                let mut accept_futures: Vec<Pin<Box<dyn Future<Output = Result<(TcpStream, SocketAddr), std::io::Error>> + Send>>> =
                    listener_contexts.iter().map(|ctx| {
                        // Get the accept future from the listener
                        ctx.listener.accept().boxed()
                    }).collect();

                let mut acceptor_shutdown_rx = acceptor_shutdown_rx;

                loop {
                    // Combine listener futures and the shutdown future
                    let shutdown_future = acceptor_shutdown_rx.changed().fuse();

                    tokio::select! {
                        biased;

                        // Check for shutdown signal
                        _ = shutdown_future => {
                            info!("Acceptor loop received shutdown signal. Exiting.");
                            break;
                        }

                        // Check if any listener accepted a connection
                        // select_all returns (result, index_of_completed_future, remaining_futures)
                        (result, index, _remaining) = select_all(accept_futures.iter_mut()) => {

                            // Get the context for the listener that completed
                            // Use .get() for safety, though index should always be valid
                            let context = match listener_contexts.get(index) {
                                Some(ctx) => ctx,
                                None => {
                                    error!(listener_index = index, "BUG: Invalid index from select_all. Skipping.");
                                    // Replace future temporarily to avoid immediate re-polling
                                    accept_futures[index] = futures::future::pending().boxed();
                                    continue;
                                }
                            };

                            match result {
                                Ok((stream, remote_addr)) => {
                                    info!(
                                        server_name = %context.server_name,
                                        listener_index = index,
                                        remote_addr = %remote_addr,
                                        "Connection accepted. Handing off to main pool."
                                    );

                                    // --- Phase 4: Handoff ---
                                    // Clone necessary context items for the new task.
                                    // Cloning Arcs is cheap.
                                    let handler = context.handler.clone();
                                    let tls_acceptor = context.tls_acceptor.clone();
                                    let server_name = context.server_name.clone();
                                    // Clone the shutdown receiver for the connection task.
                                    // Each connection needs its own receiver to react to shutdown.
                                    let conn_shutdown_rx = context.shutdown_rx.clone();

                                    // Spawn the connection handling task onto the main runtime pool.
                                    main_runtime_handle.spawn(async move {
                                        // Phase 5: Call the actual connection handler
                                        crate::connection::handle_connection(
                                            stream,
                                            remote_addr,
                                            handler,
                                            tls_acceptor,
                                            conn_shutdown_rx,
                                            server_name,
                                        )
                                        .await;
                                        // We don't need to return a Result from the spawned task itself,
                                        // handle_connection logs its own errors.
                                    });

                                    // --- Re-arm the future ---
                                    // Replace the completed future with a new call to accept()
                                    accept_futures[index] = context.listener.accept().boxed();

                                }
                                Err(e) => {
                                    // Handle accept errors gracefully
                                    error!(
                                        server_name = %context.server_name,
                                        listener_index = index,
                                        error = %e,
                                        "Error accepting connection"
                                    );
                                    // TODO: Consider more robust error handling (e.g., backoff, stop listening?)                     
                                    // --- Re-arm the future even after error ---
                                    // Attempt to accept again immediately. Might need smarter backoff later.
                                    accept_futures[index] = context.listener.accept().boxed();
                                }
                            }
                        }
                    }
                } // end loop

                info!("Acceptor loop finished.");
                Ok::<(), anyhow::Error>(())
            })?; // Propagate errors from the acceptor loop

            info!("Acceptor thread finished.");
            Ok(())
        })
        .context("Spawning acceptor thread failed")?;

    // --- Server Tasks ---
    // The Tokio JoinHandles for server tasks are now empty because tasks
    // are spawned by the acceptor thread onto the main pool later.
    let server_handles: Vec<JoinHandle<Result<()>>> = Vec::new();

    Ok((acme_state, acceptor_thread_handle, server_handles))
}

/// The main entry point for running the Lemon server logic.
pub async fn run(config_path: &Path, config: LemonConfig) -> Result<()> {
    // Config is already loaded and validated, passed as argument

    // --- Core Setup (Shutdown Signal Only) ---
    let (shutdown_tx, shutdown_rx, ctrl_c_signal) = shutdown::setup_shutdown_signal();

    // --- Start Services ---
    let (_acme_state_result, acceptor_handle_result, _server_handles_result) =
        match start_services(&config, shutdown_rx.clone()).await {
            Ok((acme_state, acceptor_handle, server_handles)) => {
                // SUCCESS CASE: start_services finished without error.
                // The acceptor thread is running.
                // We now have the AcmeState and the JoinHandle for the acceptor thread.
                (acme_state, acceptor_handle, server_handles)
            }
            Err(e) => {
                // If start_services returns Err (e.g., ACME init failed, listener bind failed),
                // we jump here. shutdown_tx is dropped when this function returns Err.
                error!("Failed to start services: {}", e);
                // Ensure the specific error is propagated
                return Err(e.context("Service initialization failed"));
            }
        };

    // --- Log Readiness ---
    // Check if the acceptor handle is valid (indicates thread spawned)
    // We don't have listener_contexts here, so we rely on start_services succeeding.
    // If start_services returned Ok, we assume listeners are ready.
    if !acceptor_handle_result.is_finished() {
        // Basic check if thread is still running
        info!("Acceptor thread launched. Ready to accept connections.");
    } else {
        // This case should ideally not be reached if start_services succeeded
        // but the acceptor finished instantly. Log a warning if it happens.
        warn!("Acceptor thread finished unexpectedly soon after starting.");
        // TODO ERR: depending on desired behavior, maybe return an error here too?
        // For now, let it proceed to shutdown.
    }

    // --- Wait for Shutdown ---
    let shutdown_timeout = Duration::from_secs(30);
    info!("Waiting for shutdown signal (Ctrl+C)...");
    shutdown::await_shutdown(
        shutdown_tx,
        ctrl_c_signal,
        acceptor_handle_result, // Pass the handle here
        shutdown_timeout,
    )
    .await;

    info!(
        "lemon server using {} has shut down gracefully.",
        config_path.display()
    );
    Ok(())
}

pub async fn squeeze(cli_args: cli::Cli) -> Result<()> {
    // --- Determine command and config path early ---
    let command_to_run = cli_args.command.unwrap_or(cli::Commands::Run);
    let config_path = Path::new(&cli_args.config); // Create Path object once

    // --- Load config only if needed (Validate/Run) ---
    // Note: create-config doesn't need to load an existing config
    let config: Option<LemonConfig> =
        if matches!(command_to_run, cli::Commands::Run | cli::Commands::Validate) {
            if config_path.exists() {
                // Load config for Run and Validate, if it exists.
                // Validation happens inside load_and_validate_config or validate_config_cmd
                match config::load_and_validate_config(config_path.to_str().unwrap()).await {
                    Ok(cfg) => Some(cfg),
                    Err(e) => {
                        // PROPAGATE THE ORIGINAL ERROR DIRECTLY
                        // The error 'e' already contains context from parsing or validation.
                        // We add top-level context here for clarity.
                        return Err(e.context(format!(
                            "Config load/validation failed for '{}'",
                            config_path.display()
                        )));
                    }
                }
            } else if matches!(command_to_run, cli::Commands::Run) {
                // If running and config doesn't exist, it's an error.
                bail!("Configuration file not found: {}", config_path.display());
            } else {
                // Validate command and config doesn't exist
                // Let validate_config_cmd handle non-existent file message
                None
            }
        } else {
            None // Not Run or Validate command
        };

    // --- Setup logging ---
    // Pass loaded config if available, otherwise defaults will be used
    let _logging_guards = logging::setup_logging(config.as_ref().and_then(|c| c.logging.as_ref()))?;
    // Keep guards in scope until squeeze finishes

    // Dispatch based on the command
    match command_to_run {
        cli::Commands::Run => {
            // We already attempted to load and validate the config above.
            // If we are here, 'config' must contain Some(validated_config).
            let loaded_config = config.expect("Config should be loaded for Run command");
            info!("🍋 Starting Lemon using config: {}", config_path.display());
            run(config_path, loaded_config).await?;
            info!("🍋 Lemon shut down gracefully.");
        }
        cli::Commands::Validate => {
            info!("Validating configuration file: {}", config_path.display());
            // Pass the already loaded config (if any) to avoid reloading
            cli::validate_config_cmd(config_path, config).await?;
        }
        cli::Commands::CreateConfig { force } => {
            info!(
                "Attempting to create default config file: {}",
                config_path.display()
            );
            cli::create_default_config_cmd(config_path, force).await?;
        }
    }
    Ok(())
}
