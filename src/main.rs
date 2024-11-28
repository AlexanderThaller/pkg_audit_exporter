#![forbid(unsafe_code)]
#![warn(clippy::allow_attributes)]
#![warn(clippy::allow_attributes_without_reason)]
#![warn(clippy::dbg_macro)]
#![warn(clippy::pedantic)]
#![warn(clippy::unwrap_used)]
#![warn(rust_2018_idioms, unused_lifetimes, missing_debug_implementations)]

use color_eyre::eyre::{
    Result,
    WrapErr,
};

// mod metrics;
// mod pkg_audit;
mod handler;
mod telemetry;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install().expect("failed to setup color_eyre");

    telemetry::setup(tracing::Level::INFO, None).context("failed to setup telemetry")?;

    let binding = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8683".to_string())
        .parse()
        .context("failed to parse socket address")?;

    handler::start(binding)
        .await
        .context("failed to start webserver")?;

    Ok(())
}
