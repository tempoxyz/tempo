//! Redacted zone RPC server.
//!
//! An axum HTTP server backed by the zone node's EthApi, with
//! authentication and privacy redactions applied per-method.
//!
//! Supports both HTTP POST and WebSocket transports.

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use std::{
    io,
    sync::Arc,
    time::{Duration, Instant},
};
use tempo_contracts::precompiles::account_keychain::IAccountKeychain::{
    KeyInfo, SignatureType as KeyInfoSignatureType,
};
use tempo_primitives::transaction::{
    SignatureType as TempoSignatureType,
    tt_signature::{KeychainSignature, TempoSignature},
};
use tokio::sync::Semaphore;
use tracing::info;

use crate::{
    auth::{self, AuthContext, now_unix_seconds},
    config::RedactedRpcConfig,
    error::{AuthError, AuthenticateError},
    handlers::{self, Simulation, ZoneRpcApi},
    metrics::{RedactedRpcAuthMetrics, RedactedRpcCallMetrics, RedactedRpcSimulationMetrics},
    types::{JsonRpcError, JsonRpcRequest, JsonRpcResponse},
    ws::handle_ws_upgrade,
};

/// Maximum number of requests in a single JSON-RPC batch.
pub(crate) const MAX_BATCH_SIZE: usize = 100;

/// How long the simulations in a request or batch wait for permits before they are rejected with
/// `-32009`.
///
/// Waiters are served in arrival order, so a caller that reissues simulations back to back cannot
/// take every released permit ahead of callers already waiting.
pub(crate) const SIMULATION_PERMIT_WAIT: Duration = Duration::from_secs(2);

/// Shared state for the redacted RPC server.
#[derive(Clone)]
pub struct RpcState {
    /// Server configuration.
    pub config: RedactedRpcConfig,
    /// Type-erased EthApi for handling RPC methods.
    pub api: Arc<dyn ZoneRpcApi>,
    /// Authentication failure metric for the redacted RPC.
    auth_metrics: RedactedRpcAuthMetrics,
    /// Permits for simulation requests, sized by [`RedactedRpcConfig::max_concurrent_simulations`].
    simulation_permits: Arc<Semaphore>,
    /// Rejected simulation metric for the redacted RPC.
    simulation_metrics: RedactedRpcSimulationMetrics,
}

/// Start the redacted zone RPC server.
///
/// The `api` argument provides the underlying EthApi methods (obtained from
/// the zone node's launched handle).
pub async fn start_redacted_rpc(
    config: RedactedRpcConfig,
    api: Arc<dyn ZoneRpcApi>,
) -> eyre::Result<std::net::SocketAddr> {
    let listen_addr = config.listen_addr;
    let state = Arc::new(RpcState {
        simulation_permits: Arc::new(Semaphore::new(config.max_concurrent_simulations.get())),
        config,
        api,
        auth_metrics: RedactedRpcAuthMetrics::default(),
        simulation_metrics: RedactedRpcSimulationMetrics::default(),
    });

    let app = Router::new()
        .route("/", post(handle_rpc))
        .route("/", get(handle_ws_upgrade))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    let local_addr = listener.local_addr()?;

    info!(target: "zone::rpc", %local_addr, "Starting redacted zone RPC server");

    tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, app).await {
            tracing::error!(target: "zone::rpc", %err, "Redacted RPC server failed");
        }
    });

    Ok(local_addr)
}

/// Pre-serialized JSON-RPC response body.
pub(crate) struct RpcResult(String);

impl IntoResponse for RpcResult {
    fn into_response(self) -> axum::response::Response {
        ([(header::CONTENT_TYPE, "application/json")], self.0).into_response()
    }
}

impl RpcResult {
    fn single(response: JsonRpcResponse, max_response_size: usize) -> Self {
        Self(serialize_response_with_limit(response, max_response_size))
    }
}

fn serialize_response(response: JsonRpcResponse) -> String {
    serde_json::to_string(&response).expect("JsonRpcResponse serialization is infallible")
}

pub(crate) fn append_batch_response(
    batch: &mut String,
    response: JsonRpcResponse,
    max_response_size: usize,
) -> Result<(), String> {
    let response = serialize_response_with_limit(response, max_response_size);
    if batch.len().saturating_add(response.len()).saturating_add(1) > max_response_size {
        return Err(serialize_response(JsonRpcResponse::error(
            serde_json::Value::Null,
            JsonRpcError::batch_response_too_large(max_response_size),
        )));
    }
    batch.push_str(&response);
    batch.push(',');
    Ok(())
}

pub(crate) fn serialize_response_with_limit(
    response: JsonRpcResponse,
    max_response_size: usize,
) -> String {
    let id = response.id.clone();
    let mut writer = BoundedWriter::new(max_response_size);
    if serde_json::to_writer(&mut writer, &response).is_ok() {
        String::from_utf8(writer.into_bytes())
            .expect("serde_json only emits valid UTF-8 response bytes")
    } else {
        serialize_response(JsonRpcResponse::error(
            id,
            JsonRpcError::response_too_large(max_response_size),
        ))
    }
}

/// Writer that refuses to buffer more than the configured response size.
struct BoundedWriter {
    max_len: usize,
    bytes: Vec<u8>,
}

impl BoundedWriter {
    fn new(max_len: usize) -> Self {
        Self {
            max_len,
            bytes: Vec::with_capacity(128.min(max_len)),
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl io::Write for &mut BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.bytes.len().saturating_add(bytes.len()) > self.max_len {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "response size limit exceeded",
            ));
        }

        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Parse and dispatch a JSON-RPC text payload, handling both single and batch
/// requests. Shared by HTTP and WebSocket transports.
pub(crate) async fn process_rpc_text(
    text: &str,
    auth: &AuthContext,
    state: &RpcState,
) -> RpcResult {
    let max_response_size = state.config.max_response_size;
    let trimmed = text.trim_start();

    if trimmed.starts_with('[') {
        match serde_json::from_str::<Vec<JsonRpcRequest>>(trimmed) {
            Ok(requests) if requests.is_empty() => RpcResult::single(
                JsonRpcResponse::error(
                    serde_json::Value::Null,
                    JsonRpcError::parse_error("empty batch"),
                ),
                max_response_size,
            ),
            Ok(requests) if requests.len() > MAX_BATCH_SIZE => RpcResult::single(
                JsonRpcResponse::error(
                    serde_json::Value::Null,
                    JsonRpcError::invalid_params(format!(
                        "batch too large ({} > {MAX_BATCH_SIZE})",
                        requests.len()
                    )),
                ),
                max_response_size,
            ),
            Ok(requests) => {
                let permit_deadline = simulation_permit_deadline();
                let mut responses = String::from("[");
                for req in &requests {
                    let response = dispatch_request(req, auth, state, permit_deadline).await;
                    if let Err(error) =
                        append_batch_response(&mut responses, response, max_response_size)
                    {
                        return RpcResult(error);
                    }
                }
                responses.pop();
                responses.push(']');
                RpcResult(responses)
            }
            Err(e) => RpcResult::single(
                JsonRpcResponse::error(
                    serde_json::Value::Null,
                    JsonRpcError::parse_error(format!("parse error: {e}")),
                ),
                max_response_size,
            ),
        }
    } else {
        match serde_json::from_str::<JsonRpcRequest>(trimmed) {
            Ok(request) => RpcResult::single(
                dispatch_request(&request, auth, state, simulation_permit_deadline()).await,
                max_response_size,
            ),
            Err(e) => RpcResult::single(
                JsonRpcResponse::error(
                    serde_json::Value::Null,
                    JsonRpcError::parse_error(format!("parse error: {e}")),
                ),
                max_response_size,
            ),
        }
    }
}

/// Returns the deadline for simulation permits in a request or batch arriving now.
///
/// A batch shares one deadline, so its simulations wait at most [`SIMULATION_PERMIT_WAIT`] in
/// total rather than that long each.
pub(crate) fn simulation_permit_deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + SIMULATION_PERMIT_WAIT
}

/// Dispatches one request. A simulation waits for a permit until `permit_deadline`.
pub(crate) async fn dispatch_request(
    req: &JsonRpcRequest,
    auth: &AuthContext,
    state: &RpcState,
    permit_deadline: tokio::time::Instant,
) -> JsonRpcResponse {
    let metrics = RedactedRpcCallMetrics::new_for(&req.method);
    let started_at = Instant::now();

    metrics.started_total.increment(1);
    // Params are validated before taking a permit, so invalid simulations never wait for one.
    let response = match Simulation::parse(req) {
        None => handlers::dispatch(req, auth, state.api.as_ref()).await,
        Some(Err(response)) => response,
        Some(Ok(simulation)) => {
            simulate(simulation, req.id.clone(), auth, state, permit_deadline).await
        }
    };
    metrics
        .time_seconds
        .record(started_at.elapsed().as_secs_f64());

    if response.error.is_some() {
        metrics.failed_total.increment(1);
    } else {
        metrics.successful_total.increment(1);
    }

    response
}

/// Runs a validated simulation once a permit is free, or rejects it with `-32009` if none frees up
/// by `permit_deadline`. A permit that is free immediately is taken even after the deadline.
async fn simulate(
    simulation: Simulation,
    id: serde_json::Value,
    auth: &AuthContext,
    state: &RpcState,
    permit_deadline: tokio::time::Instant,
) -> JsonRpcResponse {
    let Ok(permit) = tokio::time::timeout_at(
        permit_deadline,
        Arc::clone(&state.simulation_permits).acquire_owned(),
    )
    .await
    else {
        state.simulation_metrics.rejected_total.increment(1);
        return JsonRpcResponse::error(id, JsonRpcError::server_busy());
    };
    let permit = permit.expect("simulation semaphore is never closed");
    let (permits, metrics) = (
        Arc::clone(&state.simulation_permits),
        state.simulation_metrics.clone(),
    );
    let max_permits = state.config.max_concurrent_simulations.get();
    // Read from the semaphore, so the next update corrects a count missed by a panic.
    let record_permits_in_use = move || {
        let in_use = max_permits.saturating_sub(permits.available_permits());
        metrics.permits_in_use.set(in_use as f64);
    };
    record_permits_in_use();
    let (task_id, task_auth, api) = (id.clone(), auth.clone(), Arc::clone(&state.api));
    // Reth keeps executing on a blocking thread when a disconnecting client drops this future,
    // so a detached task holds the permit until the simulation completes.
    let simulation = tokio::spawn(async move {
        let response = simulation.execute(task_id, &task_auth, api.as_ref()).await;
        drop(permit);
        record_permits_in_use();
        response
    });
    match simulation.await {
        Ok(response) => response,
        Err(err) if err.is_panic() => std::panic::resume_unwind(err.into_panic()),
        Err(err) => JsonRpcResponse::error(id, JsonRpcError::internal(err.to_string())),
    }
}

/// Main HTTP RPC handler — authenticates, dispatches, returns response.
async fn handle_rpc(
    State(state): State<Arc<RpcState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let auth = match authenticate(&headers, &state.config, state.api.as_ref()).await {
        Ok(auth) => auth,
        Err(e) => {
            if e.is_invalid() {
                state.auth_metrics.auth_failures_total.increment(1);
            }
            e.log("http");
            return (e.status_code(), "").into_response();
        }
    };

    let body_str = match std::str::from_utf8(&body) {
        Ok(s) => s,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "invalid UTF-8").into_response();
        }
    };

    process_rpc_text(body_str, &auth, &state)
        .await
        .into_response()
}

/// Authenticate the request using the `X-Authorization-Token` header.
async fn authenticate(
    headers: &HeaderMap,
    config: &RedactedRpcConfig,
    api: &dyn ZoneRpcApi,
) -> Result<AuthContext, AuthenticateError> {
    let header_value = headers
        .get(auth::X_AUTHORIZATION_TOKEN)
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthError::Missing)?;

    authenticate_token(header_value, config, api).await
}

/// Authenticate using a raw token string (shared by HTTP and WebSocket paths).
pub(crate) async fn authenticate_token(
    token_value: &str,
    config: &RedactedRpcConfig,
    api: &dyn ZoneRpcApi,
) -> Result<AuthContext, AuthenticateError> {
    let token = auth::parse_auth_header(token_value)?;
    let max_auth_token_validity = config
        .max_auth_token_validity
        .min(auth::DEFAULT_MAX_AUTH_TOKEN_VALIDITY);

    // Validate token fields against server config
    token.validate_with_max_auth_token_validity(
        config.zone_id,
        config.chain_id,
        max_auth_token_validity,
    )?;

    let signature =
        TempoSignature::from_bytes(&token.signature).map_err(|_| AuthError::InvalidSignature)?;
    let caller = signature
        .recover_signer(&token.digest)
        .map_err(|_| AuthError::InvalidSignature)?;

    let keychain_key_id = if let TempoSignature::Keychain(keychain_signature) = &signature {
        Some(validate_keychain_signature(api, caller, keychain_signature, &token.digest).await?)
    } else {
        None
    };

    Ok(AuthContext {
        caller,
        expires_at: token.expires_at,
        keychain_key_id,
    })
}

async fn validate_keychain_signature(
    api: &dyn ZoneRpcApi,
    caller: alloy_primitives::Address,
    keychain_signature: &KeychainSignature,
    digest: &alloy_primitives::B256,
) -> Result<alloy_primitives::Address, AuthenticateError> {
    let key_id = keychain_signature
        .key_id(digest)
        .map_err(|_| AuthError::InvalidSignature)?;
    let key_info = api.get_keychain_key(caller, key_id).await?;

    validate_keychain_key_info(&key_info)?;

    let expected_signature_type = match keychain_signature.signature.signature_type() {
        TempoSignatureType::Secp256k1 => KeyInfoSignatureType::Secp256k1,
        TempoSignatureType::P256 => KeyInfoSignatureType::P256,
        TempoSignatureType::WebAuthn => KeyInfoSignatureType::WebAuthn,
    };

    if key_info.signatureType != expected_signature_type {
        return Err(AuthError::KeychainSignatureTypeMismatch.into());
    }

    Ok(key_id)
}

pub(crate) fn validate_keychain_key_info(key_info: &KeyInfo) -> Result<(), AuthenticateError> {
    if key_info.isRevoked {
        return Err(AuthError::RevokedKeychainKey.into());
    }
    if key_info.keyId.is_zero() {
        return Err(AuthError::UnauthorizedKeychainKey.into());
    }
    if key_info.expiry <= now_unix_seconds() {
        return Err(AuthError::ExpiredKeychainKey.into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        RpcState, SIMULATION_PERMIT_WAIT, append_batch_response, authenticate_token,
        dispatch_request, process_rpc_text, serialize_response, serialize_response_with_limit,
        simulation_permit_deadline,
    };
    use crate::{
        RedactedRpcConfig,
        auth::{AuthContext, build_token_fields},
        error::AuthenticateError,
        handlers::ZoneRpcApi,
        metrics::{RedactedRpcAuthMetrics, RedactedRpcSimulationMetrics},
        types::{BoxEyreFut, BoxFut, JsonRpcError, JsonRpcRequest, JsonRpcResponse, to_raw},
    };
    use alloy_primitives::{Address, Bytes};
    use axum::http::StatusCode;
    use p256::{ecdsa::SigningKey as P256SigningKey, elliptic_curve::rand_core::OsRng};
    use parking_lot::Mutex;
    use std::{collections::HashMap, num::NonZeroUsize, sync::Arc, time::Duration};
    use tempo_contracts::precompiles::account_keychain::IAccountKeychain::{
        KeyInfo, SignatureType as KeyInfoSignatureType,
    };
    use tokio::sync::{Notify, Semaphore};

    #[allow(dead_code)]
    mod auth_tokens {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test-utils/auth_tokens.rs"
        ));
    }

    use auth_tokens::{build_token_with_signature, now_secs, sign_keychain_signature};

    const ZONE_ID: u32 = 7;
    const CHAIN_ID: u64 = 99;
    const PORTAL: Address = Address::repeat_byte(0x22);

    #[derive(Default)]
    struct TestApi {
        key_infos: Mutex<HashMap<(Address, Address), KeyInfo>>,
        /// When set, `eth_call` waits for a notification before returning.
        call_release: Option<Arc<Notify>>,
    }

    impl TestApi {
        fn with_key_info(account: Address, key_id: Address, key_info: KeyInfo) -> Self {
            let mut key_infos = HashMap::new();
            key_infos.insert((account, key_id), key_info);
            Self {
                key_infos: Mutex::new(key_infos),
                ..Default::default()
            }
        }
    }

    macro_rules! stub {
        ($method:ident $(, $arg:ident : $ty:ty)*) => {
            fn $method(&self $(, $arg: $ty)*) -> BoxFut<'_> {
                Box::pin(async { Err(JsonRpcError::internal("not implemented")) })
            }
        };
    }

    impl ZoneRpcApi for TestApi {
        fn get_keychain_key(&self, account: Address, key_id: Address) -> BoxEyreFut<'_, KeyInfo> {
            let key_info = self
                .key_infos
                .lock()
                .get(&(account, key_id))
                .cloned()
                .unwrap_or(KeyInfo {
                    signatureType: KeyInfoSignatureType::Secp256k1,
                    keyId: Address::ZERO,
                    expiry: 0,
                    enforceLimits: false,
                    isRevoked: false,
                });
            Box::pin(async move { Ok(key_info) })
        }

        stub!(block_number);
        stub!(chain_id);
        stub!(net_version);
        stub!(client_version);
        stub!(syncing);
        stub!(coinbase);
        stub!(gas_price);
        stub!(max_priority_fee_per_gas);
        stub!(fee_history, _a: u64, _b: alloy_rpc_types_eth::BlockNumberOrTag, _c: Option<Vec<f64>>);
        stub!(get_balance, _a: Address, _b: Option<alloy_rpc_types_eth::BlockId>, _c: crate::auth::AuthContext);
        stub!(get_transaction_count, _a: Address, _b: Option<alloy_rpc_types_eth::BlockId>, _c: crate::auth::AuthContext);
        stub!(block_by_number, _a: alloy_rpc_types_eth::BlockNumberOrTag, _b: bool, _c: crate::auth::AuthContext);
        stub!(block_by_hash, _a: alloy_primitives::B256, _b: bool, _c: crate::auth::AuthContext);
        stub!(transaction_by_hash, _a: alloy_primitives::B256, _c: crate::auth::AuthContext);
        stub!(transaction_receipt, _a: alloy_primitives::B256, _c: crate::auth::AuthContext);
        fn call(
            &self,
            _a: tempo_alloy::rpc::TempoTransactionRequest,
            _b: Option<alloy_rpc_types_eth::BlockId>,
            _c: Option<alloy_rpc_types_eth::state::StateOverride>,
            _d: crate::auth::AuthContext,
        ) -> BoxFut<'_> {
            let release = self.call_release.clone();
            Box::pin(async move {
                if let Some(release) = release {
                    release.notified().await;
                }
                Err(JsonRpcError::internal("not implemented"))
            })
        }
        stub!(estimate_gas, _a: tempo_alloy::rpc::TempoTransactionRequest, _b: Option<alloy_rpc_types_eth::BlockId>, _c: Option<alloy_rpc_types_eth::state::StateOverride>, _d: crate::auth::AuthContext);
        stub!(send_raw_transaction, _a: Bytes, _c: crate::auth::AuthContext);
        stub!(send_raw_transaction_sync, _a: Bytes, _c: crate::auth::AuthContext);
        stub!(fill_transaction, _a: tempo_alloy::rpc::TempoTransactionRequest, _c: crate::auth::AuthContext);
        stub!(get_logs, _a: alloy_rpc_types_eth::Filter, _c: crate::auth::AuthContext);
        stub!(new_filter, _a: alloy_rpc_types_eth::Filter, _c: crate::auth::AuthContext);
        stub!(get_filter_logs, _a: alloy_rpc_types_eth::FilterId, _c: crate::auth::AuthContext);
        stub!(get_filter_changes, _a: alloy_rpc_types_eth::FilterId, _c: crate::auth::AuthContext);
        stub!(new_block_filter, _c: crate::auth::AuthContext);
        stub!(uninstall_filter, _a: alloy_rpc_types_eth::FilterId, _c: crate::auth::AuthContext);
        stub!(zone_get_authorization_token_info, _c: crate::auth::AuthContext);
        stub!(zone_get_zone_info, _c: crate::auth::AuthContext);
        stub!(zone_get_encryption_key, _c: crate::auth::AuthContext);
    }

    fn test_config() -> RedactedRpcConfig {
        RedactedRpcConfig {
            listen_addr: ([127, 0, 0, 1], 0).into(),
            zone_id: ZONE_ID,
            chain_id: CHAIN_ID,
            max_auth_token_validity: crate::auth::DEFAULT_MAX_AUTH_TOKEN_VALIDITY,
            max_response_size: 160 * 1024 * 1024,
            max_concurrent_simulations: crate::config::DEFAULT_MAX_CONCURRENT_SIMULATIONS,
            zone_portal: PORTAL,
        }
    }

    #[test]
    fn oversized_response_matches_jsonrpsee_error() {
        let response = JsonRpcResponse::success(
            serde_json::json!(7),
            to_raw(&"x".repeat(128)).expect("test response serializes"),
        );

        let response = serialize_response_with_limit(response, 64);
        let response: serde_json::Value =
            serde_json::from_str(&response).expect("response is valid JSON");

        assert_eq!(response["id"], serde_json::json!(7));
        assert_eq!(response["error"]["code"], serde_json::json!(-32008));
        assert_eq!(response["error"]["message"], "Response is too big");
        assert_eq!(response["error"]["data"], "Exceeded max limit of 64");
    }

    #[test]
    fn batch_response_limit_is_aggregate() {
        let response = JsonRpcResponse::success(
            serde_json::json!(1),
            to_raw(&"result").expect("test response serializes"),
        );
        let serialized = serialize_response(response.clone());
        // Exactly enough bytes for `[response]`, but not for a second response.
        let max_response_size = serialized.len() + 2;
        let mut batch = String::from("[");

        append_batch_response(&mut batch, response.clone(), max_response_size)
            .expect("one response fits");
        let error = append_batch_response(&mut batch, response, max_response_size)
            .expect_err("aggregate batch response exceeds the limit");
        let error: serde_json::Value =
            serde_json::from_str(&error).expect("response is valid JSON");

        assert_eq!(error["id"], serde_json::Value::Null);
        assert_eq!(error["error"]["code"], serde_json::json!(-32011));
        assert_eq!(
            error["error"]["message"],
            "The batch response was too large"
        );
        assert_eq!(
            error["error"]["data"],
            format!("Exceeded max limit of {max_response_size}")
        );
    }

    fn simulation_state(api: TestApi) -> RpcState {
        let mut config = test_config();
        config.max_concurrent_simulations = NonZeroUsize::MIN;
        RpcState {
            simulation_permits: Arc::new(Semaphore::new(config.max_concurrent_simulations.get())),
            config,
            api: Arc::new(api),
            auth_metrics: RedactedRpcAuthMetrics::default(),
            simulation_metrics: RedactedRpcSimulationMetrics::default(),
        }
    }

    fn simulation_auth() -> AuthContext {
        AuthContext {
            caller: Address::repeat_byte(0x11),
            expires_at: u64::MAX,
            keychain_key_id: None,
        }
    }

    fn simulation_request(method: &str) -> JsonRpcRequest {
        serde_json::from_value(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": [{"to": format!("{:#x}", Address::repeat_byte(0x22)), "data": "0x"}],
        }))
        .expect("test request deserializes")
    }

    #[tokio::test(start_paused = true)]
    async fn simulations_queue_for_a_permit_until_the_deadline() {
        let state = simulation_state(TestApi::default());
        let auth = simulation_auth();
        let simulations = ["eth_call", "eth_estimateGas", "eth_fillTransaction"];
        // The test API stubs every method with this internal error.
        let stub_error = JsonRpcError::internal("not implemented").code;

        let held = state
            .simulation_permits
            .try_acquire()
            .expect("the only permit is available");
        for method in simulations {
            let error = dispatch_request(
                &simulation_request(method),
                &auth,
                &state,
                simulation_permit_deadline(),
            )
            .await
            .error
            .expect("simulation is rejected");
            assert_eq!(error.code, JsonRpcError::server_busy().code, "{method}");
        }
        // Other methods do not take a simulation permit.
        let error = dispatch_request(
            &simulation_request("eth_chainId"),
            &auth,
            &state,
            simulation_permit_deadline(),
        )
        .await
        .error
        .expect("stub returns an error");
        assert_eq!(error.code, stub_error);
        drop(held);

        for method in simulations {
            let held = state
                .simulation_permits
                .try_acquire()
                .expect("the only permit is available");
            let request = simulation_request(method);
            let (response, ()) = tokio::join!(
                dispatch_request(&request, &auth, &state, simulation_permit_deadline()),
                async {
                    tokio::time::sleep(SIMULATION_PERMIT_WAIT / 2).await;
                    drop(held);
                    assert!(
                        state.simulation_permits.try_acquire().is_err(),
                        "the released permit goes to the queued simulation"
                    );
                }
            );
            let error = response.error.expect("stub returns an error");
            assert_eq!(error.code, stub_error, "{method}");
        }
        assert_eq!(state.simulation_permits.available_permits(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn invalid_simulations_are_rejected_without_waiting_for_a_permit() {
        let state = simulation_state(TestApi::default());
        let auth = simulation_auth();
        let call = serde_json::json!({"to": format!("{:#x}", Address::repeat_byte(0x22))});
        let requests = [
            ("eth_call", serde_json::json!([call, "0x1"])),
            ("eth_estimateGas", serde_json::json!([call, "latest", {}])),
            ("eth_fillTransaction", serde_json::json!([])),
        ];

        let _held = state
            .simulation_permits
            .try_acquire()
            .expect("the only permit is available");
        let started_at = tokio::time::Instant::now();
        for (method, params) in requests {
            let request = serde_json::from_value(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            }))
            .expect("test request deserializes");
            let error = dispatch_request(&request, &auth, &state, simulation_permit_deadline())
                .await
                .error
                .expect("simulation is rejected");
            assert_eq!(
                error.code,
                JsonRpcError::invalid_params("").code,
                "{method}"
            );
        }
        assert_eq!(started_at.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn batch_simulations_share_one_permit_deadline() {
        let state = simulation_state(TestApi::default());
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_call",
            "params": [{"to": format!("{:#x}", Address::repeat_byte(0x22)), "data": "0x"}],
        });
        let batch = serde_json::json!([request, request, request]).to_string();

        let _held = state
            .simulation_permits
            .try_acquire()
            .expect("the only permit is available");
        let started_at = tokio::time::Instant::now();
        let responses = process_rpc_text(&batch, &simulation_auth(), &state).await;
        assert_eq!(started_at.elapsed(), SIMULATION_PERMIT_WAIT);

        let responses: Vec<serde_json::Value> =
            serde_json::from_str(&responses.0).expect("batch response is valid JSON");
        assert_eq!(responses.len(), 3);
        for response in responses {
            assert_eq!(
                response["error"]["code"],
                serde_json::json!(JsonRpcError::server_busy().code)
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn simulation_permit_outlives_a_dropped_request() {
        let release = Arc::new(Notify::new());
        let state = simulation_state(TestApi {
            call_release: Some(Arc::clone(&release)),
            ..Default::default()
        });
        let request = simulation_request("eth_call");

        // Dropping the request future is what a client disconnect does.
        tokio::time::timeout(
            Duration::from_secs(1),
            dispatch_request(
                &request,
                &simulation_auth(),
                &state,
                simulation_permit_deadline(),
            ),
        )
        .await
        .expect_err("the simulation runs until released");
        assert_eq!(state.simulation_permits.available_permits(), 0);

        release.notify_one();
        let permit =
            tokio::time::timeout(Duration::from_secs(1), state.simulation_permits.acquire())
                .await
                .expect("the permit returns once the simulation completes")
                .expect("simulation semaphore is never closed");
        drop(permit);
    }

    #[tokio::test]
    async fn configured_auth_token_validity_limit_is_enforced() {
        let mut config = test_config();
        config.max_auth_token_validity = std::time::Duration::from_secs(60);

        let now = now_secs();
        let (fields, _digest) = build_token_fields(ZONE_ID, CHAIN_ID, now, now + 600);
        let mut blob = vec![0u8; 65];
        blob.extend_from_slice(&fields);
        let token = alloy_primitives::hex::encode(blob);
        let api = TestApi::default();

        let err = authenticate_token(&token, &config, &api)
            .await
            .expect_err("token window should exceed configured maximum");
        assert!(matches!(
            err,
            AuthenticateError::Invalid(crate::auth::AuthError::WindowTooLarge)
        ));
        assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn protocol_max_auth_token_validity_is_enforced_even_if_configured_higher() {
        let mut config = test_config();
        config.max_auth_token_validity =
            crate::auth::DEFAULT_MAX_AUTH_TOKEN_VALIDITY + std::time::Duration::from_secs(60);

        let now = now_secs();
        let (fields, _digest) = build_token_fields(
            ZONE_ID,
            CHAIN_ID,
            now,
            now + crate::auth::DEFAULT_MAX_AUTH_TOKEN_VALIDITY.as_secs() + 1,
        );
        let mut blob = vec![0u8; 65];
        blob.extend_from_slice(&fields);
        let token = alloy_primitives::hex::encode(blob);
        let api = TestApi::default();

        let err = authenticate_token(&token, &config, &api)
            .await
            .expect_err("token window should exceed protocol maximum");
        assert!(matches!(
            err,
            AuthenticateError::Invalid(crate::auth::AuthError::WindowTooLarge)
        ));
        assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn revoked_keychain_key_is_classified_as_revoked() {
        let root_account = Address::repeat_byte(0x55);
        let access_signer = P256SigningKey::random(&mut OsRng);
        let now = now_secs();
        let (fields, digest) = build_token_fields(ZONE_ID, CHAIN_ID, now, now + 600);
        let (signature, key_id) =
            sign_keychain_signature(digest, &access_signer, root_account, 0x04)
                .expect("keychain signing failed");
        let token = build_token_with_signature(signature, &fields);
        let api = TestApi::with_key_info(
            root_account,
            key_id,
            KeyInfo {
                signatureType: KeyInfoSignatureType::P256,
                keyId: Address::ZERO,
                expiry: 0,
                enforceLimits: false,
                isRevoked: true,
            },
        );

        let err = authenticate_token(&token, &test_config(), &api)
            .await
            .expect_err("revoked key should fail authentication");
        assert!(matches!(
            err,
            AuthenticateError::Invalid(crate::auth::AuthError::RevokedKeychainKey)
        ));
        assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn expired_keychain_key_is_classified_as_expired() {
        let root_account = Address::repeat_byte(0x55);
        let access_signer = P256SigningKey::random(&mut OsRng);
        let now = now_secs();
        let (fields, digest) = build_token_fields(ZONE_ID, CHAIN_ID, now, now + 600);
        let (signature, key_id) =
            sign_keychain_signature(digest, &access_signer, root_account, 0x04)
                .expect("keychain signing failed");
        let token = build_token_with_signature(signature, &fields);
        let api = TestApi::with_key_info(
            root_account,
            key_id,
            KeyInfo {
                signatureType: KeyInfoSignatureType::P256,
                keyId: key_id,
                expiry: now,
                enforceLimits: false,
                isRevoked: false,
            },
        );

        let err = authenticate_token(&token, &test_config(), &api)
            .await
            .expect_err("expired key should fail authentication");
        assert!(matches!(
            err,
            AuthenticateError::Invalid(crate::auth::AuthError::ExpiredKeychainKey)
        ));
        assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
    }
}
