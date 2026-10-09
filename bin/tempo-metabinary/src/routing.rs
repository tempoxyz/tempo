use crate::{catalog::ChainEras, handshake::EXECUTION_INFO_METHOD};
use alloy_primitives::{B256, U64};
use futures::future::BoxFuture;
use jsonrpsee::{
    core::{RpcResult, client::Error as ClientError, traits::ToRpcParams},
    types::{
        ErrorObjectOwned,
        error::{CALL_EXECUTION_FAILED_CODE, INVALID_PARAMS_CODE},
    },
};
use serde_json::{Value, json, value::RawValue};
use std::sync::Arc;

const BLOCK_HASH_HEX_LEN: usize = 2 + 2 * B256::len_bytes();
// Match Reth's generated bundle environments and its separate simulation fallback.
const BUNDLE_TIMESTAMP_INCREMENT: u64 = 12;
const SIMULATE_FALLBACK_TIMESTAMP_INCREMENT: u64 = 12;
const MAX_EXECUTION_OUTCOME_BLOCKS: u64 = 128;

/// Resolve identifiers through the live node. Frozen workers receive pinned historical IDs.
pub struct Router {
    schedule: ChainEras,
    pub(crate) backend: Arc<dyn Backend>,
}

impl Router {
    pub fn new(schedule: ChainEras, backend: Arc<dyn Backend>) -> eyre::Result<Self> {
        schedule.validate()?;
        Ok(Self { schedule, backend })
    }

    pub fn live_index(&self) -> usize {
        self.schedule.eras.len() - 1
    }
    fn era(&self, timestamp: u64) -> usize {
        self.schedule.era_for_timestamp(timestamp)
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
                        .backend
                        .block(
                            params
                                .get(1, &["start_exclusive", "startExclusive"])
                                .ok_or_else(|| invalid("missing start block"))?,
                        )
                        .await?;
                    let end = self
                        .backend
                        .block(
                            params
                                .get(2, &["end_inclusive", "endInclusive"])
                                .ok_or_else(|| invalid("missing end block"))?,
                        )
                        .await?;
                    if start.number < end.number {
                        let first = self
                            .backend
                            .block(&json!(U64::from(start.number + 1)))
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
            "debug_traceBlock" => self.era(self.backend.raw_block_timestamp(&params)?),
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
                self.backend
                    .transaction_timestamp(hash)
                    .await?
                    .map_or(live, |timestamp| self.era(timestamp))
            }
            _ => match policy(method) {
                Policy::Block(index, names, number_only)
                | Policy::NativeBlock(index, names, number_only) => {
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
                        let block = self.backend.block(&selector).await?;
                        let era = self.era(block.timestamp);
                        self.check_overrides(method, &params, era)?;
                        // Preserve explicit hashes and EIP-1898 requireCanonical. Pin tags/numbers.
                        let id = block.pin(selector, number_only);
                        params.set(index, names, id);
                        era
                    }
                }
                Policy::Native => live,
                Policy::Execution | Policy::Unrouted => {
                    return Err(unsupported(format!("{method} has no era routing policy")));
                }
            },
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
        let filter = params
            .get_mut(0, &["filter"])
            .filter(|filter| filter.is_object())
            .ok_or_else(|| invalid("missing trace filter"))?;
        let latest = json!("latest");
        let from_selector = filter
            .get("fromBlock")
            .filter(|v| !v.is_null())
            .unwrap_or(&latest);
        let to_selector = filter
            .get("toBlock")
            .filter(|v| !v.is_null())
            .unwrap_or(&latest);
        let from = self.backend.block(from_selector).await?;
        let to = if from_selector == to_selector {
            None
        } else {
            Some(self.backend.block(to_selector).await?)
        };
        let to = to.as_ref().unwrap_or(&from);
        let era = self.era(from.timestamp);
        if era != self.era(to.timestamp) {
            return Err(unsupported(
                "trace_filter spans multiple eras; split the block range",
            ));
        }
        filter["fromBlock"] = from.number_id();
        filter["toBlock"] = to.number_id();
        Ok(era)
    }

    async fn call_bundle(&self, params: &mut RpcParams) -> RpcResult<usize> {
        let request = params
            .get_mut(0, &["request"])
            .filter(|value| value.is_object())
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
        let parent = self.backend.block(&json!(selector)).await?;
        let era = self.era(parent.timestamp);
        let timestamp = match timestamp {
            Some(timestamp) => timestamp,
            None => parent
                .timestamp
                .checked_add(BUNDLE_TIMESTAMP_INCREMENT)
                .ok_or_else(|| invalid("timestamp overflow"))?,
        };
        // Reth selects its configuration from the state block before changing its timestamp.
        // Require both environments to belong to one binary until that native behavior changes.
        if self.era(timestamp) != era {
            return Err(unsupported("bundle timestamp crosses an era boundary"));
        }
        request["stateBlockNumber"] = parent.number_id();
        Ok(era)
    }

    async fn mev_bundle(&self, params: &mut RpcParams) -> RpcResult<usize> {
        let names = &["sim_overrides", "simOverrides"];
        let overrides = params
            .get_mut(1, names)
            .filter(|value| value.is_object())
            .ok_or_else(|| invalid("missing bundle simulation overrides"))?;
        let selector = overrides
            .get("parentBlock")
            .filter(|value| !value.is_null())
            .cloned()
            .unwrap_or_else(|| json!("latest"));
        if selector == "pending" {
            let live = self.live_index();
            self.check_time(live, Some(overrides))?;
            return Ok(live);
        }
        let parent = self.backend.block(&selector).await?;
        let era = self.era(parent.timestamp);
        // Native cfg is selected for the generated child before applying block overrides.
        if self.era(parent.timestamp.saturating_add(BUNDLE_TIMESTAMP_INCREMENT)) != era {
            return Err(unsupported("bundle simulation crosses an era boundary"));
        }
        self.check_time(era, Some(overrides))?;
        overrides["parentBlock"] = parent.pin(selector, false);
        Ok(era)
    }

    async fn execution_outcome(&self, params: &mut RpcParams) -> RpcResult<usize> {
        let count = params
            .get(1, &["count"])
            .map(quantity)
            .transpose()?
            .unwrap_or(1);
        if !(1..=MAX_EXECUTION_OUTCOME_BLOCKS).contains(&count) {
            return Err(invalid(format!(
                "block count must be between 1 and {MAX_EXECUTION_OUTCOME_BLOCKS}"
            )));
        }
        let selector = params
            .get(0, &["block_id", "blockId"])
            .cloned()
            .ok_or_else(|| invalid("missing block identifier"))?;
        if selector == "pending" {
            return Ok(self.live_index());
        }
        let mut first = self.backend.block(&selector).await?;
        if selector.get("blockHash").is_some()
            || selector
                .as_str()
                .is_some_and(|value| value.len() == BLOCK_HASH_HEX_LEN)
        {
            // Native replay resolves a hash to a height, then executes canonical blocks by height.
            first = self.backend.block(&first.number_id()).await?;
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
            let head = self.backend.block(&json!("latest")).await?;
            let last = last.min(head.number);
            if last > first.number {
                let end = self.backend.block(&json!(U64::from(last))).await?;
                if self.era(end.timestamp) != era {
                    return Err(unsupported("block execution outcome spans multiple eras"));
                }
            }
        }
        params.set(0, &["block_id", "blockId"], first.pin(selector, false));
        Ok(era)
    }

    async fn bundles(&self, method: &str, params: &mut RpcParams) -> RpcResult<usize> {
        let bundles = params
            .get(0, &["bundles"])
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("missing bundles"))?;
        let names = &["state_context", "stateContext"];
        let context = params.get(1, names);
        let selector = context
            .and_then(|context| context.get("blockNumber"))
            .filter(|v| !v.is_null())
            .cloned()
            .unwrap_or_else(|| json!("latest"));
        let pending = selector == "pending";
        let policy_selector = if pending {
            json!("latest")
        } else {
            selector.clone()
        };
        let block = self.backend.block(&policy_selector).await?;
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
                            .checked_mul(BUNDLE_TIMESTAMP_INCREMENT)
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
            if context.is_some_and(|context| !context.is_object()) {
                return Err(invalid("state context must be an object"));
            }
            let block = block.pin(selector, false);
            if let Some(context) = params.get_mut(1, names) {
                context["blockNumber"] = block;
            } else {
                params.set(1, names, json!({"blockNumber":block}));
            }
        }
        Ok(era)
    }

    async fn simulation(&self, method: &str, params: &mut RpcParams) -> RpcResult<usize> {
        let (payload_names, block_names): (&[&str], &[&str]) = if method == "eth_simulateV1" {
            (&["opts"], &["block_number", "blockNumber"])
        } else {
            (&["payload"], &["block"])
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
        let base = self.backend.block(&selector).await?;
        let chain_id = self.schedule.chain_id.to::<u64>();
        let step = alloy_chains::Chain::from(chain_id)
            .average_blocktime_hint()
            .map(|d| d.as_secs().saturating_add(u64::from(d.subsec_nanos() > 0)))
            .filter(|s| *s > 0)
            .unwrap_or(SIMULATE_FALLBACK_TIMESTAMP_INCREMENT);
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
        params.set(1, block_names, base.pin(selector, false));
        Ok(era.unwrap_or(self.era(base.timestamp)))
    }
}

/// JSON-RPC supports both positional and named params. Keep that representation when forwarding.
#[derive(Debug, Clone)]
pub struct RpcParams(pub Value);

impl ToRpcParams for RpcParams {
    fn to_rpc_params(self) -> Result<Option<Box<RawValue>>, serde_json::Error> {
        (!self.0.is_null())
            .then(|| serde_json::value::to_raw_value(&self.0))
            .transpose()
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

    fn get_mut(&mut self, index: usize, names: &[&str]) -> Option<&mut Value> {
        match &mut self.0 {
            Value::Array(a) => a.get_mut(index),
            Value::Object(o) => names
                .iter()
                .find(|n| o.contains_key(**n))
                .and_then(|n| o.get_mut(*n)),
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
        other => execution_error(format_args!("era RPC unavailable: {other}")),
    }
}

pub(crate) fn execution_error(error: impl std::fmt::Display) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(CALL_EXECUTION_FAILED_CODE, error.to_string(), None::<()>)
}

pub fn invalid(message: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(INVALID_PARAMS_CODE, message.into(), None::<()>)
}

pub(crate) fn unsupported(message: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32004, message.into(), None::<()>)
}

pub fn quantity(value: &Value) -> RpcResult<u64> {
    value
        .as_u64()
        .or_else(|| u64::from_str_radix(value.as_str()?.strip_prefix("0x")?, 16).ok())
        .ok_or_else(|| invalid("expected a hexadecimal quantity"))
}

/// Header metadata used to select an execution era and pin block selectors.
#[derive(Debug)]
pub struct BlockMetadata {
    pub number: u64,
    pub hash: B256,
    pub timestamp: u64,
}

impl BlockMetadata {
    fn pin(&self, selector: Value, number_only: bool) -> Value {
        if selector.get("blockHash").is_some()
            || selector
                .as_str()
                .is_some_and(|s| s.len() == BLOCK_HASH_HEX_LEN)
        {
            selector
        } else if number_only {
            self.number_id()
        } else {
            json!({"blockHash": self.hash})
        }
    }
    fn number_id(&self) -> Value {
        json!(U64::from(self.number))
    }
}

/// Execution-independent adapter for live RPC resolution and frozen worker forwarding.
pub trait Backend: Send + Sync {
    /// Resolve only the header metadata needed for era selection.
    fn block<'a>(&'a self, selector: &'a Value) -> BoxFuture<'a, RpcResult<BlockMetadata>>;

    /// Missing and pool transactions remain on the native live path.
    fn transaction_timestamp<'a>(
        &'a self,
        hash: &'a Value,
    ) -> BoxFuture<'a, RpcResult<Option<u64>>>;

    /// Execution results are opaque to the router.
    fn forward<'a>(
        &'a self,
        _era: usize,
        _method: &'a str,
        _params: RpcParams,
    ) -> BoxFuture<'a, RpcResult<Box<RawValue>>> {
        Box::pin(async { Err(unsupported("historical execution is unavailable")) })
    }

    /// Only the chain-specific adapter knows the raw block encoding.
    fn raw_block_timestamp(&self, _params: &RpcParams) -> RpcResult<u64> {
        Err(unsupported(
            "raw-block tracing requires a chain-specific decoder; use debug_traceBlockByHash or debug_traceBlockByNumber",
        ))
    }
}

/// Selected execution era and parameters prepared for its RPC implementation.
pub struct Route {
    pub era: usize,
    pub params: RpcParams,
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

/// One classification controls selector routing and native callback decoration.
enum Policy {
    Native,
    Block(usize, &'static [&'static str], bool),
    // Native stubs keep their callbacks and their existing direct block-routing behavior.
    NativeBlock(usize, &'static [&'static str], bool),
    Execution,
    Unrouted,
}

fn policy(method: &str) -> Policy {
    match method {
        "debug_subscribe" | "eth_subscribe" | "eth_unsubscribe" | "debug_unsubscribe" => Policy::Unrouted,
        "eth_call" | "eth_estimateGas" | "eth_createAccessList" => {
            Policy::Block(1, &["block_number", "blockNumber"], false)
        }
        "debug_traceCall" => Policy::Block(1, &["block_id", "blockId"], false),
        "trace_call" | "trace_rawTransaction" => Policy::Block(2, &["block_id", "blockId"], false),
        "trace_callMany" => Policy::Block(1, &["block_id", "blockId"], false),
        "debug_traceBlockByNumber" => Policy::Block(0, &["block"], true),
        "debug_standardTraceBlockToFile" => Policy::NativeBlock(0, &["block"], true),
        "debug_traceBlockByHash" => Policy::Block(0, &["block"], false),
        "eth_getBlockAccessListByBlockHash" => Policy::Block(0, &["hash"], false),
        "eth_getBlockAccessListByBlockNumber" => Policy::Block(0, &["number"], true),
        "eth_getBlockAccessList" => Policy::Block(0, &["block_id", "blockId"], false),
        "eth_getBlockAccessListRaw" | "debug_getRawBlockAccessList" => {
            Policy::Block(0, &["block", "block_id", "blockId"], false)
        }
        "debug_executionWitnessByBlockHash" => Policy::Block(0, &["hash"], false),
        "debug_storageRangeAt" => Policy::NativeBlock(0, &["block_hash", "blockHash"], false),
        "debug_intermediateRoots" => Policy::Block(0, &["block_hash", "blockHash"], false),
        "debug_executionWitness" => Policy::Block(0, &["block"], false),
        "debug_accountAt"
        | "debug_accountInfoAt"
        | "trace_block"
        | "trace_replayBlockTransactions"
        | "trace_blockOpcodeGas" => Policy::Block(0, &["block_id", "blockId"], false),
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
        | "debug_stateRootWithUpdates" => {
            Policy::Native
        }
        "mev_simBundle"
        | "reth_getBlockExecutionOutcome"
        | "ots_getInternalOperations"
        | "ots_getTransactionError"
        | "ots_traceTransaction"
        | "ots_getContractCreator" => Policy::Execution,
        _ if ["net_", "web3_", "rpc_", "txpool_", "admin_", "operator_", "consensus_"]
            .iter()
            .any(|prefix| method.starts_with(prefix)) =>
        {
            Policy::Native
        }
        _ if ["debug_", "trace_", "eth_", "tempo_"]
            .iter()
            .any(|prefix| method.starts_with(prefix)) =>
        {
            Policy::Execution
        }
        _ => Policy::Unrouted,
    }
}

/// Decorate execution callbacks and fail closed for unreviewed execution methods.
pub fn is_execution_method(method: &str) -> bool {
    !matches!(
        policy(method),
        Policy::Native | Policy::NativeBlock(..) | Policy::Unrouted
    )
}
