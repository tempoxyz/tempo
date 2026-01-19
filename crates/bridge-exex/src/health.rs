//! HTTP health endpoints for Kubernetes liveness and readiness probes.

use axum::{http::StatusCode, response::IntoResponse, routing::get, Extension, Router};
use serde::Serialize;
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tracing::info;

use crate::{persistence::StateManager, tempo_client::TempoClient};

#[derive(Clone)]
pub struct HealthState {
    pub state_manager: Arc<StateManager>,
    pub tempo_client: Option<Arc<TempoClient>>,
    pub start_time: std::time::Instant,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    uptime_secs: u64,
}

#[derive(Serialize)]
struct ReadinessResponse {
    status: &'static str,
    tempo_rpc_connected: bool,
    last_tempo_block: u64,
    signed_deposits: usize,
    processed_burns: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

async fn health_handler(Extension(state): Extension<HealthState>) -> impl IntoResponse {
    let uptime = state.start_time.elapsed().as_secs();
    (
        StatusCode::OK,
        axum::Json(HealthResponse {
            status: "ok",
            uptime_secs: uptime,
        }),
    )
}

async fn ready_handler(Extension(state): Extension<HealthState>) -> impl IntoResponse {
    let stats = state.state_manager.get_stats().await;

    let tempo_rpc_connected = if let Some(client) = &state.tempo_client {
        client.health_check().await.is_ok()
    } else {
        false
    };

    let is_ready = tempo_rpc_connected;

    let response = ReadinessResponse {
        status: if is_ready { "ready" } else { "not_ready" },
        tempo_rpc_connected,
        last_tempo_block: stats.last_tempo_block,
        signed_deposits: stats.signed_deposits,
        processed_burns: stats.processed_burns,
        error: if !tempo_rpc_connected {
            Some("Tempo RPC not connected".to_string())
        } else {
            None
        },
    };

    let status = if is_ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status, axum::Json(response))
}

pub async fn start_health_server(port: u16, health_state: HealthState) -> eyre::Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "Starting health server");

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler))
        .layer(Extension(health_state));

    axum::serve(listener, app.into_make_service())
        .await
        .map_err(Into::into)
}
