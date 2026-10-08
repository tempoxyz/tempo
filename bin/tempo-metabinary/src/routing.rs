use std::{collections::HashSet, sync::Arc};

use futures::future::BoxFuture;
use jsonrpsee::{
    core::{
        RpcResult,
        client::{ClientT, Error as ClientError},
        traits::ToRpcParams,
    },
    http_client::HttpClient,
    types::ErrorObjectOwned,
};
use serde_json::{Value, json, value::RawValue};

use crate::{
    catalog::{ChainEras, ReleaseEra},
    handshake::{EXECUTION_INFO_METHOD, WorkerIdentity},
    manifest::Manifest,
};

pub use crate::handshake::ExecutionInfo;

/// JSON-RPC supports both positional and named params. Keep that representation when forwarding.
#[derive(Debug, Clone)]
pub struct RpcParams(pub Value);

impl ToRpcParams for RpcParams {
    fn to_rpc_params(self) -> Result<Option<Box<RawValue>>, serde_json::Error> {
        if self.0.is_null() {
            Ok(None)
        } else {
            serde_json::value::to_raw_value(&self.0).map(Some)
        }
    }
}

impl RpcParams {
    pub(crate) fn parse(params: &jsonrpsee::types::Params<'_>) -> RpcResult<Self> {
        params
            .as_str()
            .map(serde_json::from_str::<Value>)
            .transpose()
            .map(|value| Self(value.unwrap_or(Value::Null)))
            .map_err(|error| invalid(error.to_string()))
    }

    fn get(&self, index: usize, names: &[&str]) -> Option<&Value> {
        match &self.0 {
            Value::Array(a) => a.get(index),
            Value::Object(o) => names.iter().find_map(|n| o.get(*n)),
            _ => None,
        }
        .filter(|v| !v.is_null())
    }

    fn set(&mut self, index: usize, names: &[&str], value: Value) {
        if self.0.is_null() {
            self.0 = json!([]);
        }
        match &mut self.0 {
            Value::Array(a) => {
                a.resize(a.len().max(index + 1), Value::Null);
                a[index] = value;
            }
            Value::Object(o) => {
                let key = names
                    .iter()
                    .find(|n| o.contains_key(**n))
                    .copied()
                    .unwrap_or(names[0]);
                o.insert(key.into(), value);
            }
            _ => {}
        }
    }
}

pub fn upstream_error(error: ClientError) -> ErrorObjectOwned {
    match error {
        ClientError::Call(e) => e,
        other => {
            ErrorObjectOwned::owned(-32000, format!("era RPC unavailable: {other}"), None::<()>)
        }
    }
}

fn invalid(message: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32602, message.into(), None::<()>)
}

fn unsupported(message: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32004, message.into(), None::<()>)
}

pub fn quantity(value: &Value) -> RpcResult<u64> {
    if let Some(n) = value.as_u64() {
        return Ok(n);
    }
    value
        .as_str()
        .and_then(|s| s.strip_prefix("0x"))
        .and_then(|s| u64::from_str_radix(s, 16).ok())
        .ok_or_else(|| invalid("expected a hexadecimal quantity"))
}

#[derive(Debug)]
struct Block {
    number: u64,
    hash: String,
    timestamp: u64,
}

impl Block {
    fn parse(value: Value) -> RpcResult<Self> {
        if value.is_null() {
            return Err(ErrorObjectOwned::owned(-32001, "unknown block", None::<()>));
        }
        Ok(Self {
            number: quantity(&value["number"])?,
            timestamp: quantity(&value["timestamp"])?,
            hash: value["hash"]
                .as_str()
                .ok_or_else(|| invalid("block has no hash"))?
                .into(),
        })
    }

    fn id(&self) -> Value {
        json!({"blockHash": self.hash})
    }
    fn pin(&self, selector: &Value) -> Value {
        if selector.get("blockHash").is_some() || selector.as_str().is_some_and(|s| s.len() == 66) {
            selector.clone()
        } else {
            self.id()
        }
    }
    fn number_id(&self) -> Value {
        json!(format!("0x{:x}", self.number))
    }
}

/// Execution-independent request adapter. The live adapter may invoke native RPC callbacks
/// directly; historical adapters may start a frozen worker lazily.
pub trait Backend: Send + Sync {
    fn request<'a>(
        &'a self,
        era: usize,
        method: &'a str,
        params: RpcParams,
    ) -> BoxFuture<'a, RpcResult<Value>>;

    /// Only the chain-specific adapter knows the raw block encoding.
    fn raw_block_timestamp<'a>(&'a self, _params: &'a RpcParams) -> BoxFuture<'a, RpcResult<u64>> {
        Box::pin(async {
            Err(unsupported(
                "raw-block tracing requires a chain-specific decoder; use debug_traceBlockByHash or debug_traceBlockByNumber",
            ))
        })
    }
}

struct HttpBackend {
    manifest: Arc<Manifest>,
    clients: Vec<HttpClient>,
    methods: Vec<Option<HashSet<String>>>,
}

impl Backend for HttpBackend {
    fn request<'a>(
        &'a self,
        era: usize,
        method: &'a str,
        params: RpcParams,
    ) -> BoxFuture<'a, RpcResult<Value>> {
        Box::pin(async move {
            let methods = self.methods[era].as_ref().ok_or_else(|| {
                unsupported("historical execution is disabled; start serve with --history")
            })?;
            if !methods.contains(method) {
                return Err(unsupported(format!(
                    "{method} is unavailable in era {}",
                    self.manifest.eras[era].name
                )));
            }
            self.clients[era]
                .request(method, params)
                .await
                .map_err(upstream_error)
        })
    }
}

pub struct Route {
    pub era: usize,
    pub params: RpcParams,
}

/// Resolve identifiers through the live node. Frozen workers receive pinned historical IDs.
pub struct Router {
    schedule: ChainEras,
    backend: Arc<dyn Backend>,
    live_methods: HashSet<String>,
}

impl Router {
    pub fn new(
        manifest: Arc<Manifest>,
        clients: Vec<HttpClient>,
        info: Vec<Option<ExecutionInfo>>,
    ) -> eyre::Result<Self> {
        manifest.validate()?;
        eyre::ensure!(
            clients.len() == manifest.eras.len() && info.len() == clients.len(),
            "one worker per era is required"
        );
        let live = clients.len() - 1;
        eyre::ensure!(info[live].is_some(), "the live worker is required");
        for (index, metadata) in info.iter().enumerate() {
            if let Some(metadata) = metadata {
                metadata.validate(
                    WorkerIdentity {
                        chain_id: &manifest.chain_id,
                        genesis_hash: &manifest.genesis_hash,
                        read_only: index != live,
                    },
                    None,
                )?;
            }
        }
        let live_methods = info[live]
            .as_ref()
            .expect("validated live worker")
            .methods
            .iter()
            .cloned()
            .collect();
        let schedule = ChainEras {
            chain_id: manifest.chain_id.clone(),
            genesis_hash: manifest.genesis_hash.clone(),
            eras: manifest
                .eras
                .iter()
                .enumerate()
                .map(|(index, era)| ReleaseEra {
                    name: era.name.clone(),
                    start_timestamp: era.start_timestamp,
                    binary: (index != live).then(|| era.binary.clone()),
                })
                .collect(),
        };
        let backend = Arc::new(HttpBackend {
            manifest,
            clients,
            methods: info
                .into_iter()
                .map(|i| i.map(|i| i.methods.into_iter().collect()))
                .collect(),
        });
        Self::with_backend(schedule, backend, live_methods)
    }

    pub fn with_backend(
        schedule: ChainEras,
        backend: Arc<dyn Backend>,
        live_methods: HashSet<String>,
    ) -> eyre::Result<Self> {
        schedule.validate()?;
        Ok(Self {
            schedule,
            backend,
            live_methods,
        })
    }

    pub fn live_methods(&self) -> &HashSet<String> {
        &self.live_methods
    }
    pub fn live_index(&self) -> usize {
        self.schedule.eras.len() - 1
    }
    fn era(&self, timestamp: u64) -> usize {
        self.schedule.era_for_timestamp(timestamp)
    }

    async fn block(&self, selector: &Value) -> RpcResult<Block> {
        let hash = selector
            .get("blockHash")
            .and_then(Value::as_str)
            .or_else(|| {
                selector
                    .as_str()
                    .filter(|s| s.len() == 66 && s.starts_with("0x"))
            });
        let (method, selector) = match hash {
            Some(hash) => ("eth_getBlockByHash", json!(hash)),
            None => (
                "eth_getBlockByNumber",
                selector.get("blockNumber").unwrap_or(selector).clone(),
            ),
        };
        Block::parse(
            self.forward(
                self.live_index(),
                method,
                RpcParams(json!([selector, false])),
            )
            .await?,
        )
    }

    pub async fn forward(&self, era: usize, method: &str, params: RpcParams) -> RpcResult<Value> {
        self.backend.request(era, method, params).await
    }

    pub async fn call(&self, method: &str, params: RpcParams) -> RpcResult<Value> {
        let route = self.route(method, params).await?;
        self.forward(route.era, method, route.params).await
    }

    pub async fn route(&self, method: &str, mut params: RpcParams) -> RpcResult<Route> {
        if !params.0.is_null() && !params.0.is_array() && !params.0.is_object() {
            return Err(invalid("params must be an array or an object"));
        }
        let live = self.live_index();
        let era = match method {
            "debug_subscribe" => {
                if params.get(0, &["subscription"]).and_then(Value::as_str) != Some("traceChain") {
                    live
                } else {
                    let start = self
                        .block(
                            params
                                .get(1, &["start_exclusive", "startExclusive"])
                                .ok_or_else(|| invalid("missing start block"))?,
                        )
                        .await?;
                    let end = self
                        .block(
                            params
                                .get(2, &["end_inclusive", "endInclusive"])
                                .ok_or_else(|| invalid("missing end block"))?,
                        )
                        .await?;
                    if start.number < end.number {
                        let first = self
                            .block(&json!(format!("0x{:x}", start.number + 1)))
                            .await?;
                        if self.era(first.timestamp) != live || self.era(end.timestamp) != live {
                            return Err(unsupported(
                                "historical debug trace subscriptions are unavailable; use block tracing",
                            ));
                        }
                    }
                    live
                }
            }
            "eth_simulateV1" | "tempo_simulateV1" => self.simulation(method, &mut params).await?,
            "eth_callBundle" => self.call_bundle(&mut params).await?,
            "mev_simBundle" => self.mev_bundle(&mut params).await?,
            "reth_getBlockExecutionOutcome" => self.execution_outcome(&mut params).await?,
            "eth_callMany" | "debug_traceCallMany" => self.bundles(method, &mut params).await?,
            "trace_filter" => self.filter(&mut params).await?,
            "debug_traceBlock" => self.era(self.backend.raw_block_timestamp(&params).await?),
            "debug_traceTransaction"
            | "trace_transaction"
            | "trace_get"
            | "trace_replayTransaction"
            | "trace_transactionOpcodeGas"
            | "ots_getInternalOperations"
            | "ots_getTransactionError"
            | "ots_traceTransaction" => {
                let hash = params
                    .get(0, &["tx_hash", "txHash", "hash", "transaction"])
                    .ok_or_else(|| invalid("missing transaction hash"))?;
                let tx: Value = self
                    .forward(live, "eth_getTransactionByHash", RpcParams(json!([hash])))
                    .await?;
                match tx.get("blockHash").filter(|v| !v.is_null()) {
                    Some(hash) => self.era(self.block(hash).await?.timestamp),
                    // The native implementation defines missing/pending transaction behavior.
                    None => live,
                }
            }
            _ => {
                if let Some((index, names, number_only)) = block_argument(method) {
                    let selector = params.get(index, names).cloned().unwrap_or_else(|| {
                        json!(if method == "eth_estimateGas" {
                            "pending"
                        } else {
                            "latest"
                        })
                    });
                    if selector == "pending" {
                        self.check_overrides(method, &params, live)?;
                        live
                    } else {
                        let block = self.block(&selector).await?;
                        let era = self.era(block.timestamp);
                        self.check_overrides(method, &params, era)?;
                        // Preserve explicit hashes and EIP-1898 requireCanonical. Pin tags/numbers.
                        let id = if selector.get("blockHash").is_some()
                            || selector.as_str().is_some_and(|s| s.len() == 66)
                        {
                            selector
                        } else if number_only {
                            block.number_id()
                        } else {
                            block.id()
                        };
                        params.set(index, names, id);
                        era
                    }
                } else if stored_or_live_method(method) {
                    live
                } else {
                    return Err(unsupported(format!("{method} has no era routing policy")));
                }
            }
        };
        Ok(Route { era, params })
    }

    fn check_time(&self, era: usize, overrides: Option<&Value>) -> RpcResult<()> {
        if let Some(time) = overrides
            .and_then(|o| o.get("time").or_else(|| o.get("timestamp")))
            .filter(|v| !v.is_null())
            && self.era(quantity(time)?) != era
        {
            return Err(unsupported("block override crosses an era boundary"));
        }
        Ok(())
    }

    fn check_overrides(&self, method: &str, params: &RpcParams, era: usize) -> RpcResult<()> {
        let overrides = match method {
            "eth_call" | "eth_estimateGas" => params.get(3, &["block_overrides", "blockOverrides"]),
            "trace_call" => params.get(4, &["block_overrides", "blockOverrides"]),
            "debug_traceCall" => params
                .get(2, &["opts"])
                .and_then(|o| o.get("blockOverrides")),
            _ => None,
        };
        self.check_time(era, overrides)
    }

    async fn filter(&self, params: &mut RpcParams) -> RpcResult<usize> {
        let mut filter = params
            .get(0, &["filter"])
            .cloned()
            .ok_or_else(|| invalid("missing trace filter"))?;
        let from_selector = filter.get("fromBlock").filter(|v| !v.is_null());
        let to_selector = filter.get("toBlock").filter(|v| !v.is_null());
        let latest = if from_selector.is_none() || to_selector.is_none() {
            Some(self.block(&json!("latest")).await?.id())
        } else {
            None
        };
        let from = self
            .block(from_selector.or(latest.as_ref()).expect("resolved default"))
            .await?;
        let to = self
            .block(to_selector.or(latest.as_ref()).expect("resolved default"))
            .await?;
        let era = self.era(from.timestamp);
        if era != self.era(to.timestamp) {
            return Err(unsupported(
                "trace_filter spans multiple eras; split the block range",
            ));
        }
        if !filter.is_object() {
            return Err(invalid("trace filter must be an object"));
        }
        filter["fromBlock"] = from.number_id();
        filter["toBlock"] = to.number_id();
        params.set(0, &["filter"], filter);
        Ok(era)
    }

    async fn call_bundle(&self, params: &mut RpcParams) -> RpcResult<usize> {
        let mut request = params
            .get(0, &["request"])
            .filter(|value| value.is_object())
            .cloned()
            .ok_or_else(|| invalid("missing bundle request"))?;
        // Unlike BlockId, the native bundle API accepts only a block number or tag here.
        let selector = request
            .get("stateBlockNumber")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("stateBlockNumber must be a block number or tag"))?;
        if !matches!(
            selector,
            "earliest" | "latest" | "safe" | "finalized" | "pending"
        ) {
            quantity(&json!(selector))?;
        }
        let timestamp = request
            .get("timestamp")
            .filter(|value| !value.is_null())
            .map(quantity)
            .transpose()?;
        if selector == "pending" {
            let live = self.live_index();
            if timestamp.is_some_and(|timestamp| self.era(timestamp) != live) {
                return Err(unsupported("bundle timestamp crosses an era boundary"));
            }
            // The native pending environment supplies its own timestamp and remains live.
            return Ok(live);
        }
        let parent = self.block(&json!(selector)).await?;
        let era = self.era(parent.timestamp);
        let timestamp = match timestamp {
            Some(timestamp) => timestamp,
            None => parent
                .timestamp
                .checked_add(12)
                .ok_or_else(|| invalid("timestamp overflow"))?,
        };
        // Reth selects its configuration from the state block before changing its timestamp.
        // Require both environments to belong to one binary until that native behavior changes.
        if self.era(timestamp) != era {
            return Err(unsupported("bundle timestamp crosses an era boundary"));
        }
        request["stateBlockNumber"] = parent.number_id();
        params.set(0, &["request"], request);
        Ok(era)
    }

    async fn mev_bundle(&self, params: &mut RpcParams) -> RpcResult<usize> {
        let names = &["sim_overrides", "simOverrides"];
        let mut overrides = params
            .get(1, names)
            .filter(|value| value.is_object())
            .cloned()
            .ok_or_else(|| invalid("missing bundle simulation overrides"))?;
        let selector = overrides
            .get("parentBlock")
            .filter(|value| !value.is_null())
            .cloned()
            .unwrap_or_else(|| json!("latest"));
        if selector == "pending" {
            let live = self.live_index();
            self.check_time(live, Some(&overrides))?;
            return Ok(live);
        }
        let parent = self.block(&selector).await?;
        let era = self.era(parent.timestamp);
        // Native cfg is selected for parent + 12 before flattened block overrides are applied.
        if self.era(parent.timestamp.saturating_add(12)) != era {
            return Err(unsupported("bundle simulation crosses an era boundary"));
        }
        self.check_time(era, Some(&overrides))?;
        overrides["parentBlock"] = parent.pin(&selector);
        params.set(1, names, overrides);
        Ok(era)
    }

    async fn execution_outcome(&self, params: &mut RpcParams) -> RpcResult<usize> {
        let count = params
            .get(1, &["count"])
            .map(quantity)
            .transpose()?
            .unwrap_or(1);
        if !(1..=128).contains(&count) {
            return Err(invalid("block count must be between 1 and 128"));
        }
        let selector = params
            .get(0, &["block_id", "blockId"])
            .cloned()
            .ok_or_else(|| invalid("missing block identifier"))?;
        if selector == "pending" {
            return Ok(self.live_index());
        }
        let mut first = self.block(&selector).await?;
        if selector.get("blockHash").is_some()
            || selector.as_str().is_some_and(|value| value.len() == 66)
        {
            // Native replay resolves a hash to a height, then executes canonical blocks by height.
            first = self.block(&first.number_id()).await?;
        }
        // The native method returns an empty execution outcome for genesis without executing.
        if first.number == 0 {
            return Ok(self.live_index());
        }
        let era = self.era(first.timestamp);
        let last = first
            .number
            .checked_add(count - 1)
            .ok_or_else(|| invalid("block number overflow"))?;
        if count > 1 {
            // Native replay stops at the first absent block when a range extends past the head.
            let head = self.block(&json!("latest")).await?;
            let last = last.min(head.number);
            if last > first.number {
                let end = self.block(&json!(format!("0x{last:x}"))).await?;
                if self.era(end.timestamp) != era {
                    return Err(unsupported("block execution outcome spans multiple eras"));
                }
            }
        }
        params.set(0, &["block_id", "blockId"], first.pin(&selector));
        Ok(era)
    }

    async fn bundles(&self, method: &str, params: &mut RpcParams) -> RpcResult<usize> {
        let bundles = params
            .get(0, &["bundles"])
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("missing bundles"))?;
        let mut context = params
            .get(1, &["state_context", "stateContext"])
            .cloned()
            .unwrap_or_else(|| json!({}));
        let selector = context
            .get("blockNumber")
            .filter(|v| !v.is_null())
            .cloned()
            .unwrap_or_else(|| json!("latest"));
        let pending = selector == "pending";
        let policy_selector = if pending {
            json!("latest")
        } else {
            selector.clone()
        };
        let block = self.block(&policy_selector).await?;
        let era = if pending {
            self.live_index()
        } else {
            self.era(block.timestamp)
        };
        for (i, bundle) in bundles.iter().enumerate() {
            let timestamp = if method == "debug_traceCallMany" {
                block
                    .timestamp
                    .checked_add(
                        (i as u64)
                            .checked_mul(12)
                            .ok_or_else(|| invalid("timestamp overflow"))?,
                    )
                    .ok_or_else(|| invalid("timestamp overflow"))?
            } else {
                block.timestamp
            };
            if self.era(timestamp) != era {
                return Err(unsupported("call bundles span multiple eras"));
            }
            self.check_time(era, bundle.get("blockOverride"))?;
        }
        if !pending {
            if !context.is_object() {
                return Err(invalid("state context must be an object"));
            }
            context["blockNumber"] = block.pin(&selector);
            params.set(1, &["state_context", "stateContext"], context);
        }
        Ok(era)
    }

    async fn simulation(&self, method: &str, params: &mut RpcParams) -> RpcResult<usize> {
        let payload_names: &[&str] = if method == "eth_simulateV1" {
            &["opts"]
        } else {
            &["payload"]
        };
        let block_names: &[&str] = if method == "eth_simulateV1" {
            &["block_number", "blockNumber"]
        } else {
            &["block"]
        };
        let payload = params
            .get(0, payload_names)
            .ok_or_else(|| invalid("missing simulation payload"))?;
        let calls = payload
            .get("blockStateCalls")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("missing blockStateCalls"))?;
        let selector = params
            .get(1, block_names)
            .cloned()
            .unwrap_or_else(|| json!("latest"));
        // Pending is always live. Validate explicit timestamps without changing its semantics.
        if selector == "pending" {
            let era = self.live_index();
            for call in calls {
                self.check_time(era, call.get("blockOverrides"))?;
            }
            return Ok(era);
        }
        let base = self.block(&selector).await?;
        let chain_id = quantity(&json!(self.schedule.chain_id))?;
        let step = alloy_chains::Chain::from(chain_id)
            .average_blocktime_hint()
            .map(|d| d.as_secs().saturating_add(u64::from(d.subsec_nanos() > 0)))
            .filter(|s| *s > 0)
            .unwrap_or(12);
        let mut number = base.number;
        let mut time = base.timestamp;
        let mut era = None;
        for call in calls {
            let overrides = call.get("blockOverrides");
            let next_number = overrides
                .and_then(|o| o.get("number").or_else(|| o.get("blockNumber")))
                .filter(|v| !v.is_null())
                .map(quantity)
                .transpose()?
                .unwrap_or(
                    number
                        .checked_add(1)
                        .ok_or_else(|| invalid("block number overflow"))?,
                );
            if next_number <= number {
                return Err(invalid("simulation block numbers must increase"));
            }
            let gap = next_number - number;
            // Reth fills number gaps using the chain's block time hint. Test only the endpoints;
            // era ranges and generated timestamps are monotonic, so no filler allocation is needed.
            if gap > 1 {
                let first = time
                    .checked_add(step)
                    .ok_or_else(|| invalid("timestamp overflow"))?;
                let last = time
                    .checked_add(
                        step.checked_mul(gap - 1)
                            .ok_or_else(|| invalid("timestamp overflow"))?,
                    )
                    .ok_or_else(|| invalid("timestamp overflow"))?;
                ensure_same_era(&mut era, self.era(first))?;
                ensure_same_era(&mut era, self.era(last))?;
                time = last;
            }
            let next_time = overrides
                .and_then(|o| o.get("time").or_else(|| o.get("timestamp")))
                .filter(|v| !v.is_null())
                .map(quantity)
                .transpose()?
                .unwrap_or(
                    time.checked_add(step)
                        .ok_or_else(|| invalid("timestamp overflow"))?,
                );
            if next_time <= time {
                return Err(invalid("simulation timestamps must increase"));
            }
            ensure_same_era(&mut era, self.era(next_time))?;
            number = next_number;
            time = next_time;
        }
        params.set(1, block_names, base.pin(&selector));
        Ok(era.unwrap_or(self.era(base.timestamp)))
    }
}

fn ensure_same_era(era: &mut Option<usize>, next: usize) -> RpcResult<()> {
    if era.is_some_and(|previous| previous != next) {
        return Err(unsupported(
            "simulation spans multiple eras; split the request",
        ));
    }
    *era = Some(next);
    Ok(())
}

fn block_argument(method: &str) -> Option<(usize, &'static [&'static str], bool)> {
    Some(match method {
        "eth_call" | "eth_estimateGas" | "eth_createAccessList" => {
            (1, &["block_number", "blockNumber"], false)
        }
        "debug_traceCall" => (1, &["block_id", "blockId"], false),
        "trace_call" | "trace_rawTransaction" => (2, &["block_id", "blockId"], false),
        "trace_callMany" => (1, &["block_id", "blockId"], false),
        "debug_traceBlockByNumber" | "debug_standardTraceBlockToFile" => (0, &["block"], true),
        "debug_traceBlockByHash" => (0, &["block"], false),
        "eth_getBlockAccessListByBlockHash" => (0, &["hash"], false),
        "eth_getBlockAccessListByBlockNumber" => (0, &["number"], true),
        "eth_getBlockAccessList" => (0, &["block_id", "blockId"], false),
        "eth_getBlockAccessListRaw" | "debug_getRawBlockAccessList" => {
            (0, &["block", "block_id", "blockId"], false)
        }
        "debug_executionWitnessByBlockHash" => (0, &["hash"], false),
        "debug_storageRangeAt" | "debug_intermediateRoots" => {
            (0, &["block_hash", "blockHash"], false)
        }
        "debug_executionWitness" => (0, &["block"], false),
        "debug_accountAt"
        | "debug_accountInfoAt"
        | "trace_block"
        | "trace_replayBlockTransactions"
        | "trace_blockOpcodeGas" => (0, &["block_id", "blockId"], false),
        _ => return None,
    })
}

/// Decorate only callbacks that can execute an EVM. Unreviewed debug/trace calls fail closed;
/// storage and operational callbacks continue through the native handler unchanged.
pub fn is_execution_method(method: &str) -> bool {
    !stored_or_live_method(method)
        && (matches!(
            method,
            "mev_simBundle"
                | "reth_getBlockExecutionOutcome"
                | "ots_getInternalOperations"
                | "ots_getTransactionError"
                | "ots_traceTransaction"
                | "ots_getContractCreator"
        ) || (["debug_", "trace_", "eth_", "tempo_"]
            .iter()
            .any(|prefix| method.starts_with(prefix))
            && !matches!(
                method,
                "debug_subscribe" | "debug_unsubscribe" | "eth_subscribe" | "eth_unsubscribe"
            )))
}

/// Unknown execution namespaces fail closed until their selector semantics have been reviewed.
fn stored_or_live_method(method: &str) -> bool {
    if [
        "net_",
        "web3_",
        "rpc_",
        "txpool_",
        "admin_",
        "operator_",
        "consensus_",
    ]
    .iter()
    .any(|prefix| method.starts_with(prefix))
    {
        return true;
    }
    matches!(
        method,
        "eth_protocolVersion"
            | "eth_syncing"
            | "eth_coinbase"
            | "eth_accounts"
            | "eth_blockNumber"
            | "eth_chainId"
            | "eth_capabilities"
            | "eth_getBlockByHash"
            | "eth_getBlockByNumber"
            | "eth_getBlockTransactionCountByHash"
            | "eth_getBlockTransactionCountByNumber"
            | "eth_getUncleCountByBlockHash"
            | "eth_getUncleCountByBlockNumber"
            | "eth_getBlockReceipts"
            | "eth_getUncleByBlockHashAndIndex"
            | "eth_getUncleByBlockNumberAndIndex"
            | "eth_getRawTransactionByHash"
            | "eth_getTransactionByHash"
            | "eth_getRawTransactionByBlockHashAndIndex"
            | "eth_getTransactionByBlockHashAndIndex"
            | "eth_getRawTransactionByBlockNumberAndIndex"
            | "eth_getTransactionByBlockNumberAndIndex"
            | "eth_getTransactionBySenderAndNonce"
            | "eth_pendingTransactions"
            | "eth_getTransactionReceipt"
            | "eth_getBalance"
            | "eth_getStorageAt"
            | "eth_getStorageValues"
            | "eth_getTransactionCount"
            | "eth_getCode"
            | "eth_getHeaderByNumber"
            | "eth_getHeaderByHash"
            | "eth_gasPrice"
            | "eth_getAccount"
            | "eth_maxPriorityFeePerGas"
            | "eth_baseFee"
            | "eth_blobBaseFee"
            | "eth_feeHistory"
            | "eth_mining"
            | "eth_hashrate"
            | "eth_getWork"
            | "eth_submitHashrate"
            | "eth_submitWork"
            | "eth_sendTransaction"
            | "eth_sendRawTransaction"
            | "eth_sendRawTransactionSync"
            | "eth_sendRawTransactionConditional"
            | "eth_sign"
            | "eth_signTransaction"
            | "eth_signTypedData"
            | "eth_fillTransaction"
            | "eth_getProof"
            | "eth_getMultiProof"
            | "eth_getAccountInfo"
            | "eth_getLogs"
            | "eth_newFilter"
            | "eth_newBlockFilter"
            | "eth_newPendingTransactionFilter"
            | "eth_uninstallFilter"
            | "eth_getFilterChanges"
            | "eth_getFilterLogs"
            | "eth_getTransactions"
            | "eth_config"
            | "token_getRoleHistory"
            | "token_getTokens"
            | "token_getTokensByAddress"
            | "tempo_fundAddress"
            | "tempo_forkSchedule"
            | EXECUTION_INFO_METHOD
            | "debug_getRawHeader"
            | "debug_getRawBlock"
            | "debug_getRawTransaction"
            | "debug_getRawTransactions"
            | "debug_getRawReceipts"
            | "debug_getBadBlocks"
            | "debug_clearTxpool"
            | "debug_chaindbCompact"
            | "debug_chainConfig"
            | "debug_chaindbProperty"
            | "debug_codeByHash"
            | "debug_dbAncient"
            | "debug_dbAncients"
            | "debug_dbGet"
            | "debug_dumpBlock"
            | "debug_freeOSMemory"
            | "debug_gcStats"
            | "debug_getAccessibleState"
            | "debug_accountRange"
            | "debug_getModifiedAccountsByNumber"
            | "debug_getModifiedAccountsByHash"
            | "debug_memStats"
            | "debug_preimage"
            | "debug_printBlock"
            | "debug_seedHash"
            | "debug_setGCPercent"
            | "debug_setHead"
            | "debug_setTrieFlushInterval"
            // These APIs are currently non-executing stubs in the pinned native backend.
            | "debug_standardTraceBadBlockToFile"
            | "debug_standardTraceBlockToFile"
            | "debug_storageRangeAt"
            | "debug_stateRootWithUpdates"
    )
}
