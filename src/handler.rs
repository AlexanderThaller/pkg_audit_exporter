use std::{
    net::SocketAddr,
    sync::Arc,
};

use axum::{
    body::Body,
    extract::State,
    http::{
        Response,
        StatusCode,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use color_eyre::eyre::{
    Report,
    Result,
    WrapErr,
};
use prometheus_client::registry::Registry;
use tokio::sync::Mutex;
use tracing::{
    error,
    event,
    instrument,
    Level,
};

use crate::metrics::MetricExporter;

#[derive(Debug, Clone)]
struct AppState {
    exporter: Arc<Mutex<MetricExporter>>,
}

#[derive(Debug)]
struct Error(Report);

#[instrument]
pub(crate) async fn start(binding: SocketAddr) -> Result<()> {
    let app_state = AppState {
        exporter: Arc::new(Mutex::new(MetricExporter::default())),
    };

    let router = router(app_state);

    let listener = tokio::net::TcpListener::bind(binding)
        .await
        .context("failed to bind to address")?;

    event!(
        Level::INFO,
        binding = binding.to_string(),
        "Starting pkg_audit_exporter"
    );

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("failed to start server")?;

    Ok(())
}

#[instrument(skip(app_state))]
fn router(app_state: AppState) -> Router {
    Router::new()
        .route("/", get(root))
        .route("/metrics", get(metrics))
        .with_state(app_state)
        .layer(tower_http::compression::CompressionLayer::new())
}

#[instrument]
async fn root() -> Result<impl IntoResponse, Error> {
    Ok(Response::builder()
        .status(StatusCode::MOVED_PERMANENTLY)
        .header("Content-Type", "text/plain; charset=utf-8")
        .header("Location", "/metrics")
        .body(Body::from("find metrics under /metrics"))
        .context("should never fail to build a response")?)
}

#[instrument(skip(app_state))]
async fn metrics(State(app_state): State<AppState>) -> Result<impl IntoResponse, Error> {
    let mut state = app_state.exporter.lock().await;
    state.update().await.context("failed to update metrics")?;

    Ok(encode_prometheus(&state.registry).context("failed to encode prometheus metrics")?)
}

#[instrument]
fn encode_prometheus(registry: &Registry) -> Result<impl IntoResponse, Report> {
    let mut body = String::new();

    prometheus_client::encoding::text::encode(&mut body, registry)
        .context("failed to encode prometheus metrics")?;

    Response::builder()
        .header(
            "Content-Type",
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        )
        .body(Body::from(body))
        .context("should never fail to build a response")
}

impl From<Report> for Error {
    #[instrument]
    fn from(report: Report) -> Self {
        Self(report)
    }
}

impl IntoResponse for Error {
    #[instrument]
    fn into_response(self) -> axum::response::Response {
        error!("{:?}", self.0);

        axum::http::Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header("content-type", "text/plain")
            .body("Internal Server Error".into())
            .expect("failed to create response")
    }
}

#[instrument]
pub(crate) async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    let signal = tokio::select! {
        () = ctrl_c => {
            "SIGINT (CTRL+C)"
        },
        () = terminate => {
            "SIGTERM"
        },
    };

    event!(
        Level::INFO,
        signal = signal,
        "Signal received, shutting down"
    );
}
