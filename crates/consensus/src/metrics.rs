use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    body::Body,
    http::{Response, StatusCode, header},
    routing::get,
};
use commonware_runtime::{Handle, Metrics as _, Spawner as _, tokio::Context};
use eyre::WrapErr as _;
use tokio::net::TcpListener;

/// Installs a metrics server so that commonware can publish its metrics.
///
/// This is lifted straight from [`commonware_runtime::tokio::telemetry::init`],
/// because it also wants to install a tracing subscriber, which clashes with
/// reth ethereum cli doing the same thing.
pub fn install(context: Context, listen_addr: SocketAddr) -> Handle<eyre::Result<()>> {
    context.spawn(move |context| async move {
        // Create a tokio listener for the metrics server.
        //
        // We explicitly avoid using a runtime `Listener` because
        // it will track bandwidth used for metrics and apply a policy
        // for read/write timeouts fit for a p2p network.
        let listener = TcpListener::bind(listen_addr)
            .await
            .wrap_err("failed to bind provided address")?;

        // Create a router for the metrics server
        let metrics_context = Arc::new(Mutex::new(context));
        let app = Router::new().route(
            "/metrics",
            get({
                let metrics_context = Arc::clone(&metrics_context);
                move || {
                    let metrics_context = Arc::clone(&metrics_context);
                    async move {
                        let body = metrics_context
                            .lock()
                            .expect("metrics context mutex must not be poisoned")
                            .encode();
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(header::CONTENT_TYPE, "text/plain; version=0.0.4")
                            .body(Body::from(body))
                            .expect("Failed to create response")
                    }
                }
            }),
        );

        // Serve the metrics over HTTP.
        //
        // `serve` will spawn its own tasks using `tokio::spawn` (and there is no way to specify
        // it to do otherwise). These tasks will not be tracked like metrics spawned using `Spawner`.
        axum::serve(listener, app.into_make_service())
            .await
            .map_err(Into::into)
    })
}
