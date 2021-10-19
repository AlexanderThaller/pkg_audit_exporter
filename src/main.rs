#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![warn(clippy::unwrap_used)]
#![warn(rust_2018_idioms, unused_lifetimes, missing_debug_implementations)]

use thiserror::Error;

mod metrics;
mod pkg_audit;

use metrics::MetricExporter;

#[derive(Error, Debug)]
enum Error {
    #[error("can not parse binding from args: {0}")]
    ParseSocketAddr(std::net::AddrParseError),

    #[error("can not start exporter: {0}")]
    ExporterStart(prometheus_exporter::Error),

    #[error("can not update metrics: {0}")]
    UpdateMetrics(metrics::Error),
}

fn main() -> Result<(), Error> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "info");
    }
    pretty_env_logger::init();

    let binding = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8683".to_string())
        .parse::<std::net::SocketAddr>()
        .map_err(Error::ParseSocketAddr)?;

    let exporter = prometheus_exporter::start(binding).map_err(Error::ExporterStart)?;

    let mut metrics = MetricExporter::new();

    loop {
        let guard = exporter.wait_request();

        metrics.update().map_err(Error::UpdateMetrics)?;

        drop(guard);
    }
}
