//! Embeddable JSON-RPC relay. Middleware and transport are independent of custody.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{sync::Arc, time::Duration};

pub mod chains;
pub mod errors;
pub mod external;
#[cfg(feature = "http")]
pub mod http;
pub mod multisig;
pub mod plugins;
pub mod simulation;
pub mod sponsor;
pub mod store;
pub mod wire;

/// A JSON-RPC error, including downstream revert data.
#[derive(Clone, Debug, Deserialize, Serialize, thiserror::Error)]
#[error("{message}")]
pub struct RpcError {
    /// JSON-RPC error code.
    pub code: i32,
    /// Human-readable message.
    pub message: String,
    /// Original error data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl RpcError {
    /// Constructs an error without additional data.
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// Constructs an invalid-parameters error.
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(-32602, message)
    }
}

/// Transport-independent RPC request, without wire-level IDs.
#[derive(Clone, Debug)]
pub struct Request {
    /// RPC method name.
    pub method: String,
    /// Positional RPC parameters.
    pub params: Vec<Value>,
}

impl Request {
    /// Constructs a positional RPC request.
    pub fn new(method: impl Into<String>, params: Vec<Value>) -> Self {
        Self {
            method: method.into(),
            params,
        }
    }

    /// Returns the transaction object from a fill request.
    pub fn transaction(&self) -> Result<&Map<String, Value>, RpcError> {
        self.params
            .first()
            .and_then(Value::as_object)
            .ok_or_else(|| RpcError::invalid("Expected a transaction object"))
    }

    /// Returns the mutable transaction object from a fill request.
    pub fn transaction_mut(&mut self) -> Result<&mut Map<String, Value>, RpcError> {
        self.params
            .first_mut()
            .and_then(Value::as_object_mut)
            .ok_or_else(|| RpcError::invalid("Expected a transaction object"))
    }
}

/// A downstream RPC handler, usable with HTTP or an in-process node.
#[async_trait]
pub trait Backend: Send + Sync {
    /// Executes one request. Implementations must not retry broadcasts automatically.
    async fn request(&self, request: Request) -> Result<Value, RpcError>;
}

/// Ordered request middleware and immutable post-fill enrichment.
#[async_trait]
pub trait Plugin: Send + Sync {
    /// Executes middleware. Consuming `next` prevents duplicate forwarding.
    async fn handle(&self, request: Request, next: Next<'_>) -> Result<Value, RpcError> {
        next.run(request).await
    }

    /// Returns capabilities only; transaction mutation is not allowed at this stage.
    async fn after_fill(
        &self,
        _request: &Request,
        _filled: &Value,
        _backend: &dyn Backend,
    ) -> Result<Map<String, Value>, RpcError> {
        Ok(Map::new())
    }
}

/// The rest of a request middleware chain.
pub struct Next<'a> {
    plugins: &'a [Arc<dyn Plugin>],
    backend: &'a dyn Backend,
}

impl Next<'_> {
    /// Forwards a request exactly once.
    pub async fn run(self, request: Request) -> Result<Value, RpcError> {
        if let Some((plugin, plugins)) = self.plugins.split_first() {
            plugin
                .handle(
                    request,
                    Self {
                        plugins,
                        backend: self.backend,
                    },
                )
                .await
        } else {
            self.backend.request(request).await
        }
    }
}

/// One relay engine shared by embedded services and the standalone sidecar.
#[derive(Clone)]
pub struct Relay {
    backend: Arc<dyn Backend>,
    plugins: Vec<Arc<dyn Plugin>>,
    sponsor: Option<Arc<sponsor::Sponsor>>,
    fill_timeout: Duration,
    coordination: Option<(Arc<dyn store::Store>, u64)>,
}

impl Relay {
    /// Creates a passthrough relay without a signer.
    pub fn new(backend: Arc<dyn Backend>) -> Self {
        Self {
            backend,
            plugins: Vec::new(),
            sponsor: None,
            fill_timeout: Duration::from_secs(10),
            coordination: None,
        }
    }

    /// Appends request middleware in execution order.
    pub fn with_plugin(mut self, plugin: impl Plugin + 'static) -> Self {
        self.plugins.push(Arc::new(plugin));
        self
    }

    /// Installs the sole fee-payer signer. A second signer is rejected.
    pub fn with_sponsor(mut self, sponsor: sponsor::Sponsor) -> Result<Self, RpcError> {
        if self.sponsor.is_some() {
            return Err(RpcError::invalid(
                "Only one relay fee payer may be configured",
            ));
        }
        self.sponsor = Some(Arc::new(sponsor));
        Ok(self)
    }

    /// Executes middleware, enrichment, then signing of the final immutable transaction.
    pub async fn handle(&self, request: Request) -> Result<Value, RpcError> {
        if let Some((_, chain_id)) = &self.coordination
            && let Some(body_chain) = chains::body_chain(&request)?
            && body_chain != *chain_id
        {
            return Err(RpcError::invalid("Conflicting chain IDs"));
        }
        if request.method != "eth_fillTransaction"
            || self.plugins.is_empty() && self.sponsor.is_none()
        {
            return self.handle_inner(request).await;
        }
        let original = request.clone();
        let deadline = tokio::time::Instant::now() + self.fill_timeout;
        let result = tokio::time::timeout_at(deadline, self.handle_inner(request))
            .await
            .map_err(|_| RpcError::new(-32603, "Relay fill deadline exceeded"))?;
        match result {
            Err(error)
                if errors::is_execution(&error)
                    && original
                        .transaction()?
                        .get("capabilities")
                        .and_then(|v| v.get("errors"))
                        == Some(&json!(true)) =>
            {
                let simulator = simulation::Simulate::new(0, None);
                let preview = simulator.error_fill(&original, &error, &*self.backend);
                tokio::time::timeout_at(deadline, preview)
                    .await
                    .map_err(|_| RpcError::new(-32603, "Relay fill deadline exceeded"))
            }
            result => result,
        }
    }

    /// Configures the complete fill deadline, including asynchronous plugin callbacks.
    pub fn with_fill_timeout(mut self, timeout: Duration) -> Self {
        self.fill_timeout = timeout;
        self
    }

    /// Enables outer native multisig coordination with a shared store and the sole fee payer.
    pub fn with_multisig(mut self, store: Arc<dyn store::Store>, chain_id: u64) -> Self {
        self.coordination = Some((store, chain_id));
        self
    }

    async fn handle_inner(&self, mut request: Request) -> Result<Value, RpcError> {
        if self.plugins.is_empty() && self.sponsor.is_none() && self.coordination.is_none() {
            return self.backend.request(request).await;
        }
        if request.method != "eth_fillTransaction"
            && let Some((store, chain_id)) = &self.coordination
        {
            let downstream = Arc::new(MiddlewareBackend {
                plugins: self.plugins.clone(),
                backend: self.backend.clone(),
            });
            let mut coordinator = multisig::Multisig::new(store.clone(), downstream, *chain_id);
            if let Some(sponsor) = &self.sponsor {
                coordinator = coordinator.with_sponsor(sponsor.clone());
            }
            let terminal = FinalBackend {
                backend: &*self.backend,
                sponsor: self.sponsor.as_deref(),
            };
            return coordinator
                .handle(
                    request,
                    Next {
                        plugins: &self.plugins,
                        backend: &terminal,
                    },
                )
                .await;
        }
        let original = request.clone();
        let fill = request.method == "eth_fillTransaction";
        let local_sponsorship = !fill
            || !original
                .transaction()?
                .get("feePayer")
                .is_some_and(Value::is_string);
        if fill {
            normalize_fill_request(&mut request)?;
            if local_sponsorship && let Some(sponsor) = &self.sponsor {
                sponsor.prepare_fill(&mut request)?;
            }
        }
        let prepared = request.clone();
        let backend = FinalBackend {
            backend: &*self.backend,
            sponsor: self.sponsor.as_deref(),
        };
        let mut result = Next {
            plugins: &self.plugins,
            backend: &backend,
        }
        .run(request)
        .await?;
        if !fill || result.pointer("/capabilities/error").is_some() {
            return Ok(result);
        }
        if result.get("tx").and_then(Value::as_object).is_none() {
            return Err(RpcError::new(
                -32603,
                "Downstream fill response is missing tx",
            ));
        }
        normalize_filled_calls(&mut result)?;
        if local_sponsorship && let Some(sponsor) = &self.sponsor {
            sponsor.finalize_fill(&original, &mut result)?;
            if !sponsor.approve_fill(&original, &result).await? {
                let mut unsponsored = original;
                unsponsored
                    .transaction_mut()?
                    .insert("feePayer".into(), json!(false));
                return Box::pin(self.handle_inner(unsponsored)).await;
            }
        }
        let mut patches = Map::new();
        let enrichment = futures::future::try_join_all(
            self.plugins
                .iter()
                .map(|plugin| plugin.after_fill(&prepared, &result, &*self.backend)),
        )
        .await?;
        for patch in enrichment {
            for (key, value) in patch {
                if patches.insert(key.clone(), value).is_some() {
                    return Err(RpcError::invalid(format!(
                        "Conflicting relay capability: {key}"
                    )));
                }
            }
        }
        let capabilities = result
            .as_object_mut()
            .expect("validated fill response")
            .entry("capabilities")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or_else(|| RpcError::new(-32603, "Invalid fill capabilities"))?;
        for (key, value) in patches {
            if capabilities.contains_key(&key) {
                return Err(RpcError::invalid(format!(
                    "Conflicting relay capability: {key}"
                )));
            }
            capabilities.insert(key, value);
        }
        if local_sponsorship && let Some(sponsor) = &self.sponsor {
            sponsor.sign_fill(&original, &mut result).await?;
        }
        result["capabilities"]
            .as_object_mut()
            .expect("validated capabilities")
            .entry("sponsored")
            .or_insert(Value::Bool(false));
        Ok(result)
    }
}

struct FinalBackend<'a> {
    backend: &'a dyn Backend,
    sponsor: Option<&'a sponsor::Sponsor>,
}

#[async_trait]
impl Backend for FinalBackend<'_> {
    async fn request(&self, request: Request) -> Result<Value, RpcError> {
        if request.method == "eth_fillTransaction"
            && request
                .transaction()?
                .get("feePayer")
                .is_some_and(Value::is_string)
        {
            return Err(RpcError::invalid("External fee payer URL is not allowed"));
        }
        if request.method == "eth_fillTransaction" && self.sponsor.is_some() {
            let transaction = request.transaction()?;
            if transaction.get("feePayer") == Some(&json!(true))
                && transaction.contains_key("gas")
                && transaction.contains_key("nonce")
                && (transaction.contains_key("maxFeePerGas")
                    || transaction.contains_key("gasPrice"))
            {
                return Ok(json!({"tx": transaction}));
            }
        }
        if matches!(
            request.method.as_str(),
            "eth_signRawTransaction" | "eth_sendRawTransaction" | "eth_sendRawTransactionSync"
        ) {
            if let Some(sponsor) = self.sponsor {
                return sponsor
                    .handle_raw(
                        request,
                        Next {
                            plugins: &[],
                            backend: self.backend,
                        },
                    )
                    .await;
            }
            if request.method == "eth_signRawTransaction" {
                return Err(RpcError::new(-32601, "No relay fee payer is configured"));
            }
        }
        self.backend.request(request).await
    }
}

struct MiddlewareBackend {
    plugins: Vec<Arc<dyn Plugin>>,
    backend: Arc<dyn Backend>,
}

#[async_trait]
impl Backend for MiddlewareBackend {
    async fn request(&self, request: Request) -> Result<Value, RpcError> {
        Next {
            plugins: &self.plugins,
            backend: &*self.backend,
        }
        .run(request)
        .await
    }
}

fn normalize_fill_request(request: &mut Request) -> Result<(), RpcError> {
    let transaction = request.transaction_mut()?;
    if !transaction.contains_key("calls")
        || (transaction
            .get("calls")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
            && transaction.get("to").is_some_and(|to| !to.is_null()))
    {
        let mut call = Map::new();
        call.insert("to".into(), transaction.remove("to").unwrap_or(Value::Null));
        call.insert(
            "value".into(),
            transaction.remove("value").unwrap_or_else(|| json!("0x0")),
        );
        let input = transaction.remove("input");
        let data = transaction.remove("data");
        if input
            .as_ref()
            .zip(data.as_ref())
            .is_some_and(|(input, data)| input != data)
        {
            return Err(RpcError::invalid("Conflicting input and data"));
        }
        call.insert("data".into(), input.or(data).unwrap_or_else(|| json!("0x")));
        transaction.insert("calls".into(), Value::Array(vec![Value::Object(call)]));
    }
    let calls = transaction
        .get_mut("calls")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| RpcError::invalid("Expected a calls array"))?;
    if calls.is_empty() {
        return Err(RpcError::invalid("Expected at least one call"));
    }
    for call in calls {
        let call = call
            .as_object_mut()
            .ok_or_else(|| RpcError::invalid("Expected a call object"))?;
        let input = call.remove("input").filter(|input| !input.is_null());
        let data = call.remove("data").filter(|data| !data.is_null());
        if input
            .as_ref()
            .zip(data.as_ref())
            .is_some_and(|(input, data)| input != data)
        {
            return Err(RpcError::invalid("Conflicting input and data"));
        }
        call.insert("data".into(), input.or(data).unwrap_or_else(|| json!("0x")));
        let value = call.entry("value").or_insert_with(|| json!("0x0"));
        if value.is_null() {
            *value = json!("0x0");
        }
    }
    Ok(())
}

fn normalize_filled_calls(result: &mut Value) -> Result<(), RpcError> {
    if let Some(calls) = result
        .pointer_mut("/tx/calls")
        .and_then(Value::as_array_mut)
    {
        for call in calls {
            let call = call
                .as_object_mut()
                .ok_or_else(|| RpcError::new(-32603, "Invalid filled call"))?;
            if let Some(input) = call.remove("input").filter(|input| !input.is_null()) {
                if call
                    .get("data")
                    .is_some_and(|data| !data.is_null() && data != &input)
                {
                    return Err(RpcError::new(-32603, "Conflicting filled input and data"));
                }
                call.insert("data".into(), input);
            }
        }
    }
    Ok(())
}
