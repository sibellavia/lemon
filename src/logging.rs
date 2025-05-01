use crate::config::{LoggingConfig, LoggingFormat, LoggingOutput};
use anyhow::Result;
use std::str::FromStr;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

pub fn setup_logging(config: Option<&LoggingConfig>) -> Result<Vec<WorkerGuard>> {
    let mut guards = Vec::new();

    // Determine Level Filter
    let env_filter = EnvFilter::try_from_default_env();
    let filter_layer = match env_filter {
        Ok(filter) => filter,
        Err(_) => {
            let level_str = config.map(|c| c.level.as_str()).unwrap_or("info");
            let level = LevelFilter::from_str(level_str).unwrap_or(LevelFilter::INFO);
            EnvFilter::builder()
                .with_default_directive(level.into())
                .from_env_lossy()
        }
    };

    // Get format and output from config
    let log_format = config.map(|c| c.format.clone()).unwrap_or_default();
    let log_output = config.map(|c| c.output.clone()).unwrap_or_default();

    // Build the subscriber
    let registry = tracing_subscriber::registry().with(filter_layer);

    // Conditionally initialize based on output and format
    match log_output {
        LoggingOutput::Stdout => match log_format {
            LoggingFormat::Text => {
                let _ = registry
                    .with(tracing_subscriber::fmt::layer().with_writer(std::io::stdout))
                    .try_init();
            }
            LoggingFormat::Json => {
                let _ = registry
                    .with(
                        tracing_subscriber::fmt::layer()
                            .json()
                            .with_writer(std::io::stdout),
                    )
                    .try_init();
            }
        },
        LoggingOutput::File { path } => {
            let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
            let filename = path
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new("lemon.log"));
            let file_appender = tracing_appender::rolling::never(parent, filename);
            let (non_blocking_writer, guard) = tracing_appender::non_blocking(file_appender);
            guards.push(guard);

            match log_format {
                LoggingFormat::Text => {
                    let _ = registry
                        .with(tracing_subscriber::fmt::layer().with_writer(non_blocking_writer))
                        .try_init();
                }
                LoggingFormat::Json => {
                    let _ = registry
                        .with(
                            tracing_subscriber::fmt::layer()
                                .json()
                                .with_writer(non_blocking_writer),
                        )
                        .try_init();
                }
            }
        }
    }

    Ok(guards)
}
