use anyhow::Result;
use lemon::cli;

#[tokio::main]
async fn main() -> Result<()> {
    let cli_args = cli::parse_args();

    tracing::info!("lemon {} starting...", env!("CARGO_PKG_VERSION"));
    lemon::squeeze(cli_args).await?;

    Ok(())
}
