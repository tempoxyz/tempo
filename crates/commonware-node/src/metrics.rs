use std::{net::SocketAddr, time::Duration};

use axum::{
    Extension, Router,
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
        let app = Router::new()
            .route(
                "/metrics",
                get(|Extension(ctx): Extension<Context>| async move {
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "text/plain; version=0.0.4")
                        .body(Body::from(ctx.encode()))
                        .expect("Failed to create response")
                }),
            )
            .layer(Extension(context));

        // Serve the metrics over HTTP.
        //
        // `serve` will spawn its own tasks using `tokio::spawn` (and there is no way to specify
        // it to do otherwise). These tasks will not be tracked like metrics spawned using `Spawner`.
        axum::serve(listener, app.into_make_service())
            .await
            .map_err(Into::into)
    })
}

/// Starts a background task that periodically pushes consensus metrics to a Prometheus-compatible endpoint.
///
/// The metrics are pushed in Prometheus text format to the specified URL using HTTP PUT.
pub fn install_push(
    context: Context,
    push_url: String,
    interval: Duration,
) -> Handle<eyre::Result<()>> {
    context.spawn(move |context| async move {
        let client = reqwest::Client::builder()
            .build()
            .wrap_err("failed to create HTTP client for metrics push")?;

        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;

            let metrics = context.encode();
            if metrics.is_empty() {
                continue;
            }

            match client
                .put(&push_url)
                .header("Content-Type", "text/plain")
                .body(metrics)
                .send()
                .await
            {
                Ok(response) => {
                    if !response.status().is_success() {
                        tracing::warn!(
                            status = %response.status(),
                            url = %push_url,
                            "failed to push consensus metrics"
                        );
                    } else {
                        tracing::trace!(url = %push_url, "pushed consensus metrics");
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        url = %push_url,
                        "failed to push consensus metrics"
                    );
                }
            }
        }
    })
}
