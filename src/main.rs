use thiserror::Error;

mod audit;
mod metrics;
mod parser;

use metrics::Metrics;

#[derive(Error, Debug)]
enum Error {
    #[error("can not parse binding from args: {0}")]
    ParseSocketAddr(std::net::AddrParseError),

    #[error("can not start exporter")]
    ExporterStart(prometheus_exporter::Error),
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

    let mut metrics = Metrics::new();

    loop {
        let guard = exporter.wait_request();

        metrics.update().unwrap();

        drop(guard);
    }
}
