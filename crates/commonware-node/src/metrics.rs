use std::{net::SocketAddr, path::PathBuf, time::Duration};

use axum::{
    Extension, Router,
    body::Body,
    http::{Response, StatusCode, header},
    routing::get,
};
use commonware_runtime::{Handle, Metrics as _, Spawner as _, tokio::Context};
use eyre::WrapErr as _;
use prometheus_client::metrics::gauge::Gauge;
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

/// How often the consensus directory disk size is recalculated.
const DISK_SIZE_REPORT_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Spawns a background task that periodically reports the total disk size of the
/// consensus storage directory as a gauge metric.
pub fn install_disk_size_reporter(context: Context, storage_dir: PathBuf) -> Handle<()> {
    let gauge: Gauge = Gauge::default();
    context.register(
        "disk_size_bytes",
        "total disk size of the consensus storage directory in bytes",
        gauge.clone(),
    );

    context.spawn(move |_context| async move {
        loop {
            match dir_size(&storage_dir) {
                Ok(size) => {
                    gauge.set(size);
                }
                Err(err) => {
                    tracing::warn!(%err, path = %storage_dir.display(), "failed to compute consensus disk size");
                }
            }
            tokio::time::sleep(DISK_SIZE_REPORT_INTERVAL).await;
        }
    })
}

/// Recursively walks a directory and sums the size of all files.
fn dir_size(path: &std::path::Path) -> std::io::Result<i64> {
    let mut total: u64 = 0;
    let mut stack = vec![path.to_path_buf()];

    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            if metadata.is_dir() {
                stack.push(entry.path());
            } else {
                total += metadata.len();
            }
        }
    }

    Ok(total as i64)
}
