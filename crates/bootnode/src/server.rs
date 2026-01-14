//! HTTP server and bootnode lifecycle management.

use crate::{
    parse_peer_id,
    state::{BootnodeState, RegisterRequest},
};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
};
use eyre::Result;
use futures::StreamExt;
use reth_discv4::{Discv4, Discv4Config, NatResolver};
use reth_network_peers::NodeRecord;
use secp256k1::SecretKey;
use std::net::{IpAddr, SocketAddr};
use tracing::{error, info};

/// Configuration for the bootnode server.
#[derive(Debug, Clone)]
pub struct BootnodeConfig {
    /// Address to bind the discovery UDP socket.
    pub discovery_addr: SocketAddr,
    /// Address to bind the HTTP API.
    pub http_addr: SocketAddr,
    /// Node secret key.
    pub secret_key: SecretKey,
    /// External IP for NAT traversal.
    pub external_ip: Option<IpAddr>,
    /// Lookup interval in seconds.
    pub lookup_interval_secs: u64,
}

impl Default for BootnodeConfig {
    fn default() -> Self {
        Self {
            discovery_addr: ([0, 0, 0, 0], 30303).into(),
            http_addr: ([0, 0, 0, 0], 8080).into(),
            secret_key: crate::generate_secret_key(),
            external_ip: None,
            lookup_interval_secs: 30,
        }
    }
}

impl BootnodeConfig {
    /// Create a new config with the given discovery and HTTP addresses.
    pub fn new(discovery_addr: SocketAddr, http_addr: SocketAddr) -> Self {
        Self {
            discovery_addr,
            http_addr,
            ..Default::default()
        }
    }

    /// Set the secret key.
    pub fn with_secret_key(mut self, key: SecretKey) -> Self {
        self.secret_key = key;
        self
    }

    /// Set the external IP.
    pub fn with_external_ip(mut self, ip: IpAddr) -> Self {
        self.external_ip = Some(ip);
        self
    }

    /// Set the lookup interval.
    pub fn with_lookup_interval_secs(mut self, secs: u64) -> Self {
        self.lookup_interval_secs = secs;
        self
    }
}

/// The bootnode server combining discv4 discovery and HTTP API.
pub struct BootnodeServer {
    config: BootnodeConfig,
    local_enr: NodeRecord,
}

impl BootnodeServer {
    /// Create a new bootnode server with the given configuration.
    pub async fn new(config: BootnodeConfig) -> Result<Self> {
        let local_enr = NodeRecord::from_secret_key(config.discovery_addr, &config.secret_key);

        info!("Bootnode created with enode: {}", local_enr);
        info!("Peer ID: {:?}", local_enr.id);

        Ok(Self { config, local_enr })
    }

    /// Get the local ENR.
    pub fn local_enr(&self) -> &NodeRecord {
        &self.local_enr
    }

    /// Build the axum router with the given state.
    fn router(state: BootnodeState) -> axum::Router {
        axum::Router::new()
            .route("/", get(get_info))
            .route("/health", get(health))
            .route("/peers", get(list_peers))
            .route("/peers", post(register_peer))
            .route("/peers/{peer_id}", get(get_peer))
            .route("/peers/{peer_id}", delete(deregister_peer))
            .route("/discovered", get(list_discovered))
            .with_state(state)
    }

    /// Create and bind the discv4 service.
    async fn create_discv4(&self) -> Result<(Discv4, reth_discv4::Discv4Service)> {
        let nat_resolver = self
            .config
            .external_ip
            .map(NatResolver::ExternalIp)
            .unwrap_or(NatResolver::None);

        let discv4_config = Discv4Config::builder()
            .external_ip_resolver(Some(nat_resolver))
            .lookup_interval(std::time::Duration::from_secs(
                self.config.lookup_interval_secs,
            ))
            .build();

        let (discv4, discv4_service) = Discv4::bind(
            self.config.discovery_addr,
            self.local_enr,
            self.config.secret_key,
            discv4_config,
        )
        .await?;

        Ok((discv4, discv4_service))
    }

    /// Run the bootnode server.
    ///
    /// This spawns the discv4 service and HTTP server, then processes
    /// discovery updates until shutdown.
    pub async fn run(self) -> Result<()> {
        let (discv4, mut discv4_service) = self.create_discv4().await?;
        let state = BootnodeState::new(discv4, self.local_enr, self.config.http_addr);

        let mut updates = discv4_service.update_stream();
        discv4_service.spawn();

        let app = Self::router(state.clone());
        let listener = tokio::net::TcpListener::bind(self.config.http_addr).await?;
        info!("HTTP API listening on {}", self.config.http_addr);

        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                error!("HTTP server error: {}", e);
            }
        });

        loop {
            tokio::select! {
                Some(update) = updates.next() => {
                    state.handle_discovery_update(update);
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("Shutting down...");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Run the bootnode server with a shutdown signal.
    pub async fn run_until<F>(self, shutdown: F) -> Result<()>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let (discv4, mut discv4_service) = self.create_discv4().await?;
        let state = BootnodeState::new(discv4, self.local_enr, self.config.http_addr);

        let mut updates = discv4_service.update_stream();
        discv4_service.spawn();

        let app = Self::router(state.clone());
        let listener = tokio::net::TcpListener::bind(self.config.http_addr).await?;
        info!("HTTP API listening on {}", self.config.http_addr);

        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                error!("HTTP server error: {}", e);
            }
        });

        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                Some(update) = updates.next() => {
                    state.handle_discovery_update(update);
                }
                _ = &mut shutdown => {
                    info!("Shutdown signal received");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Start the server in background and return a handle.
    pub async fn start(self) -> Result<BootnodeHandle> {
        let (discv4, mut discv4_service) = self.create_discv4().await?;
        let state = BootnodeState::new(discv4, self.local_enr, self.config.http_addr);

        let mut updates = discv4_service.update_stream();
        discv4_service.spawn();

        let app = Self::router(state.clone());
        let listener = tokio::net::TcpListener::bind(self.config.http_addr).await?;
        let http_addr = listener.local_addr()?;
        info!("HTTP API listening on {}", http_addr);

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                error!("HTTP server error: {}", e);
            }
        });

        let state_clone = state.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(update) = updates.next() => {
                        state_clone.handle_discovery_update(update);
                    }
                    _ = &mut shutdown_rx => {
                        info!("Shutdown signal received");
                        break;
                    }
                }
            }
        });

        Ok(BootnodeHandle {
            state,
            http_addr,
            shutdown_tx: Some(shutdown_tx),
        })
    }
}

/// Handle to a running bootnode server.
pub struct BootnodeHandle {
    state: BootnodeState,
    http_addr: SocketAddr,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl BootnodeHandle {
    /// Get the HTTP API address.
    pub fn http_addr(&self) -> SocketAddr {
        self.http_addr
    }

    /// Get the bootnode state.
    pub fn state(&self) -> &BootnodeState {
        &self.state
    }

    /// Get the base URL for the HTTP API.
    pub fn base_url(&self) -> String {
        format!("http://{}", self.http_addr)
    }

    /// Shutdown the bootnode.
    pub fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for BootnodeHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

// HTTP Handlers

async fn health() -> impl IntoResponse {
    StatusCode::OK
}

async fn get_info(State(state): State<BootnodeState>) -> impl IntoResponse {
    Json(state.info())
}

async fn list_peers(State(state): State<BootnodeState>) -> impl IntoResponse {
    Json(state.list_registered())
}

async fn list_discovered(State(state): State<BootnodeState>) -> impl IntoResponse {
    Json(state.list_discovered())
}

async fn register_peer(
    State(state): State<BootnodeState>,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    let secret_bytes = match const_hex::decode(req.secret_key.trim_start_matches("0x")) {
        Ok(bytes) => bytes,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("Invalid secret key hex: {}", e) })),
            )
                .into_response();
        }
    };

    let secret_key = match SecretKey::from_slice(&secret_bytes) {
        Ok(key) => key,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("Invalid secret key: {}", e) })),
            )
                .into_response();
        }
    };

    let udp_port = req.udp_port.unwrap_or(req.tcp_port);
    let socket_addr = SocketAddr::new(req.ip, udp_port);
    let mut record = NodeRecord::from_secret_key(socket_addr, &secret_key);
    record.tcp_port = req.tcp_port;

    let info = state.register_peer(record);
    (
        StatusCode::CREATED,
        Json(serde_json::to_value(info).unwrap()),
    )
        .into_response()
}

async fn get_peer(
    State(state): State<BootnodeState>,
    Path(peer_id): Path<String>,
) -> impl IntoResponse {
    let peer_id = match parse_peer_id(&peer_id) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response();
        }
    };

    match state.get_peer(&peer_id) {
        Some(info) => Json(serde_json::to_value(info).unwrap()).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Peer not found" })),
        )
            .into_response(),
    }
}

async fn deregister_peer(
    State(state): State<BootnodeState>,
    Path(peer_id): Path<String>,
) -> impl IntoResponse {
    let peer_id = match parse_peer_id(&peer_id) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": e })),
            );
        }
    };

    if state.deregister_peer(peer_id) {
        (StatusCode::OK, Json(serde_json::json!({ "removed": true })))
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Peer not found in registered peers" })),
        )
    }
}
