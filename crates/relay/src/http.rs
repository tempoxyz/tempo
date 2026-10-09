//! HTTP adapters for the relay engine, including JSON-RPC batches and notifications.

use crate::{Backend, Relay, Request, RpcError};
use async_trait::async_trait;
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use jsonrpsee::{
    core::{
        client::{ClientT, Error as ClientError},
        params::ArrayParams,
    },
    http_client::{HttpClient, HttpClientBuilder},
};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::net::TcpListener;

/// HTTP downstream with bounded request time and no automatic submission retries.
pub struct HttpBackend(HttpClient);

impl HttpBackend {
    /// Connects an HTTP JSON-RPC backend.
    pub fn new(url: &str) -> Result<Self, RpcError> {
        HttpClientBuilder::default()
            .request_timeout(Duration::from_secs(30))
            .max_response_size(16 * 1024 * 1024)
            .build(url)
            .map(Self)
            .map_err(|error| RpcError::new(-32603, error.to_string()))
    }
}

#[async_trait]
impl Backend for HttpBackend {
    async fn request(&self, request: Request) -> Result<Value, RpcError> {
        let mut params = ArrayParams::new();
        for parameter in request.params {
            params
                .insert(parameter)
                .map_err(|error| RpcError::invalid(error.to_string()))?;
        }
        self.0
            .request(&request.method, params)
            .await
            .map_err(|error| match error {
                ClientError::Call(error) => RpcError {
                    code: error.code(),
                    message: error.message().to_owned(),
                    data: error
                        .data()
                        .and_then(|data| serde_json::from_str(data.get()).ok()),
                },
                error => RpcError::new(-32603, error.to_string()),
            })
    }
}

/// Serves a relay on an already-bound listener, stopping on the supplied future.
pub async fn serve(
    listener: TcpListener,
    relay: Relay,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let app = Router::new()
        .route("/", post(handle))
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
        .with_state(relay);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
}

async fn handle(State(relay): State<Relay>, body: Bytes) -> Response {
    let value: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => {
            return axum::Json(failure(Value::Null, RpcError::new(-32700, "Parse error")))
                .into_response();
        }
    };
    let response = match value {
        Value::Array(requests) if requests.is_empty() || requests.len() > 100 => Some(failure(
            Value::Null,
            RpcError::new(-32600, "Expected 1 to 100 batch requests"),
        )),
        Value::Array(requests) => {
            let mut responses = Vec::new();
            for request in requests {
                if let Some(response) = execute(&relay, request).await {
                    responses.push(response);
                }
            }
            (!responses.is_empty()).then_some(Value::Array(responses))
        }
        value => execute(&relay, value).await,
    };
    match response {
        Some(response) => axum::Json(response).into_response(),
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

async fn execute(relay: &Relay, value: Value) -> Option<Value> {
    let id = value.get("id").cloned();
    let method = value.get("method").and_then(Value::as_str);
    let params = value.get("params").cloned().unwrap_or_else(|| json!([]));
    if value.get("jsonrpc") != Some(&json!("2.0"))
        || method.is_none()
        || !params.is_array()
        || id
            .as_ref()
            .is_some_and(|id| !(id.is_null() || id.is_number() || id.is_string()))
    {
        return Some(failure(
            Value::Null,
            RpcError::new(-32600, "Invalid request"),
        ));
    }
    let request = Request::new(
        method.expect("validated method"),
        params.as_array().expect("validated params").clone(),
    );
    let result = tokio::time::timeout(Duration::from_secs(60), relay.handle(request))
        .await
        .unwrap_or_else(|_| {
            Err(RpcError::new(
                -32000,
                "Relay request timed out; submission outcome may be unknown",
            ))
        });
    id.map(|id| match result {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err(error) => failure(id, error),
    })
}

fn failure(id: Value, error: RpcError) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": error})
}
