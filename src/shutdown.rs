use futures::Future;
use std::{pin::Pin, time::Duration};
use tokio::{signal::ctrl_c, sync::watch, time::timeout};
use tracing::{error, info};

// Type alias for the pinned Ctrl+C future for cleaner signatures
type CtrlCFuture = Pin<Box<dyn Future<Output = Result<(), std::io::Error>> + Send>>;

/// Sets up the shutdown signal handling.
///
/// Returns a tuple containing:
/// - `watch::Sender<()>`: Used to signal shutdown to tasks.
/// - `watch::Receiver<()>`: Can be cloned and passed to tasks to listen for the signal.
/// - `CtrlCFuture`: A pinned future that resolves when Ctrl+C is pressed.
pub fn setup_shutdown_signal() -> (watch::Sender<()>, watch::Receiver<()>, CtrlCFuture) {
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let ctrl_c_fut = Box::pin(ctrl_c());
    (shutdown_tx, shutdown_rx, ctrl_c_fut)
}

/// Waits for the shutdown signal (Ctrl+C). Once signaled, it sends the shutdown
/// signal via the watch channel, waits for the acceptor thread to join, and
/// gives connection tasks time to shut down gracefully.
///
/// # Arguments
/// * `shutdown_tx` - The sender half of the watch channel. Used to signal shutdown.
/// * `ctrl_c_signal` - The future that resolves on Ctrl+C.
/// * `acceptor_handle` - The JoinHandle for the dedicated acceptor OS thread.
/// * `shutdown_timeout` - Duration to wait for the acceptor thread and tasks to shut down.
pub async fn await_shutdown(
    shutdown_tx: watch::Sender<()>,
    ctrl_c_signal: CtrlCFuture,
    acceptor_handle: std::thread::JoinHandle<Result<(), anyhow::Error>>,
    shutdown_timeout: Duration,
) {
    // Wait for the Ctrl+C signal.
    info!("Server running. Press Ctrl+C to initiate graceful shutdown.");
    match ctrl_c_signal.await {
        Ok(()) => info!("Ctrl+C received. Initiating graceful shutdown..."),
        Err(e) => error!(
            "Failed listening for Ctrl+C: {}. Initiating shutdown anyway...",
            e
        ),
    }

    // --- Initiate and Wait for Graceful Shutdown ---
    info!("Signaling acceptor thread and connection tasks to shut down...");
    // Send the signal. Clones of the receiver in the acceptor and connection tasks will see this.
    if let Err(e) = shutdown_tx.send(()) {
        error!("Failed to send shutdown signal: {}", e);
        // Proceed with shutdown anyway
    }
    // Keep the tx alive briefly so receivers can react before we potentially block on join
    drop(shutdown_tx);

    info!(
        "Waiting up to {:?} for acceptor thread to join...",
        shutdown_timeout
    );

    // Wait for the acceptor OS thread to complete with a timeout.
    // Use spawn_blocking because std::thread::JoinHandle::join() is blocking.
    let join_acceptor = tokio::task::spawn_blocking(move || match acceptor_handle.join() {
        Ok(Ok(())) => info!("Acceptor thread joined gracefully."),
        Ok(Err(e)) => error!("Acceptor thread exited with error: {:?}", e),
        Err(panic_payload) => error!("Acceptor thread panicked: {:?}", panic_payload),
    });

    match timeout(shutdown_timeout, join_acceptor).await {
        Ok(_) => info!("Acceptor thread join completed within timeout."),
        Err(_) => error!(
            "Shutdown timed out after {:?} waiting for acceptor thread to join. It might be stuck.",
            shutdown_timeout
        ),
    }

    // Note: We no longer explicitly wait for individual connection tasks here.
    // They receive the shutdown signal via their cloned `shutdown_rx` and are expected
    // to terminate within the Hyper grace period handled in `handle_connection`.
    // The overall process might take slightly longer than `shutdown_timeout` if
    // connections take time to close after the acceptor thread finishes.
    info!("Shutdown process complete.");
}
