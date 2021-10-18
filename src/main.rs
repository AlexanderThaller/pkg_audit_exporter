mod audit;
mod metrics;
mod parser;

use metrics::Metrics;

fn main() {
    let binding = "127.0.0.1:9185".parse().unwrap();
    let exporter = prometheus_exporter::start(binding).unwrap();
    let metrics = Metrics::new();

    loop {
        let guard = exporter.wait_request();

        metrics.update().unwrap();

        drop(guard);
    }
}
