//! Early jemalloc pprof debug server.
//!
//! Starts a lightweight HTTP server that serves jemalloc heap profiles at
//! `/debug/pprof/heap` before the main node launch. This makes profiling
//! available during early startup phases like storage healing, which happen
//! before the reth metrics endpoint is ready.

use axum::{Router, http::StatusCode, response::IntoResponse, routing::get};
use std::net::SocketAddr;
use tracing::info;

/// Starts the jemalloc debug server on the given address.
pub(crate) async fn start(addr: SocketAddr) -> eyre::Result<()> {
    let app = Router::new().route("/debug/pprof/heap", get(handle_pprof_heap));

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| eyre::eyre!("failed to bind jemalloc debug server to {addr}: {e}"))?;

    info!(target: "tempo::debug", %addr, "Starting early jemalloc debug server");

    tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, app).await {
            tracing::error!(target: "tempo::debug", %err, "jemalloc debug server failed");
        }
    });

    Ok(())
}

async fn handle_pprof_heap() -> impl IntoResponse {
    let prof_ctl = match jemalloc_pprof::PROF_CTL.as_ref() {
        Some(ctl) => ctl,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "jemalloc profiling not enabled",
            )
                .into_response();
        }
    };

    let mut prof_ctl = prof_ctl.lock().await;

    match prof_ctl.dump_pprof() {
        Ok(pprof) => (
            StatusCode::OK,
            [
                ("content-type", "application/octet-stream"),
                ("content-encoding", "gzip"),
            ],
            pprof,
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to dump pprof: {err}"),
        )
            .into_response(),
    }
}
