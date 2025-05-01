use once_cell::sync::Lazy;
use tracing_subscriber::EnvFilter;

// Use Lazy to ensure initialization happens only once across all tests.
static INIT_LOGGING: Lazy<()> = Lazy::new(|| {
    // Setup a basic subscriber that respects RUST_LOG.
    // Use try_init just in case some other part of the test setup
    // might have already initialized logging (though unlikely).
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init()
        .ok(); // Ignore the result, we just care it's attempted.
    println!("Test logging initialized.");
});

/// Call this function at the beginning of tests or test setup functions
/// that require logging to be initialized.
pub fn ensure_logging_initialized() {
    // Accessing the Lazy static ensures the initialization closure runs exactly once.
    Lazy::force(&INIT_LOGGING);
}
