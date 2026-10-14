#![forbid(unsafe_code)]
#![warn(clippy::allow_attributes)]
#![warn(clippy::allow_attributes_without_reason)]
#![warn(clippy::dbg_macro)]
#![warn(clippy::pedantic)]
#![warn(clippy::unwrap_used)]
#![warn(rust_2018_idioms, unused_lifetimes, missing_debug_implementations)]

use std::time::Duration;

use metrics_exporter_prometheus::PrometheusBuilder;
use metrics_util::MetricKindMask;
use thiserror::Error;
use tracing_subscriber::EnvFilter;

mod metrics;
mod pkg_audit;

use metrics::MetricExporter;

/// How often `pkg audit` is run to refresh the metrics.
const UPDATE_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Error, Debug)]
enum Error {
    #[error("can not parse binding from args: {0}")]
    ParseSocketAddr(std::net::AddrParseError),

    #[error("can not start exporter: {0}")]
    ExporterStart(metrics_exporter_prometheus::BuildError),

    #[error("can not update metrics: {0}")]
    UpdateMetrics(metrics::Error),
}

fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let binding = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8683".to_string())
        .parse::<std::net::SocketAddr>()
        .map_err(Error::ParseSocketAddr)?;

    PrometheusBuilder::new()
        .with_http_listener(binding)
        .idle_timeout(MetricKindMask::GAUGE, Some(UPDATE_INTERVAL * 3))
        .install()
        .map_err(Error::ExporterStart)?;

    let mut metrics = MetricExporter::new();

    loop {
        metrics.update().map_err(Error::UpdateMetrics)?;

        std::thread::sleep(UPDATE_INTERVAL);
    }
}
