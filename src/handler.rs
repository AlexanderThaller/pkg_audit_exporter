use std::net::SocketAddr;

use axum::{
    response::IntoResponse,
    routing::get,
    Router,
};
use color_eyre::eyre::{
    Result,
    WrapErr,
};
use tracing::{
    event,
    instrument,
    Level,
};

#[instrument]
pub(super) async fn start(binding: SocketAddr) -> Result<()> {
    let router = router();

    let listener = tokio::net::TcpListener::bind(binding)
        .await
        .context("failed to bind to address")?;

    event!(
        Level::INFO,
        binding = binding.to_string(),
        "Starting trivy-web"
    );

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("failed to start server")?;

    Ok(())
}

#[instrument]
fn router() -> Router {
    Router::new()
    // handlers
        .route("/", get(root))
        .route("/metrics", get(metrics))
    // state
        .layer(tower_http::compression::CompressionLayer::new())
}

#[instrument]
async fn root() -> impl IntoResponse {
    "todo"
}

#[instrument]
async fn metrics() -> impl IntoResponse {
    "todo"
}

#[instrument]
pub(super) async fn shutdown_signal() {
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
