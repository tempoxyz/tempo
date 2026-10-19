//! Routes each RPC request to its rule era: the era whose binary owns the rules it executes under.

use alloy_primitives::B256;
use futures::{future::BoxFuture, stream::BoxStream};
use jsonrpsee::{
    core::{RpcResult, traits::ToRpcParams},
    types::{
        ErrorObjectOwned,
        error::{CALL_EXECUTION_FAILED_CODE, INTERNAL_ERROR_CODE, INVALID_PARAMS_CODE},
    },
};
use serde_json::{Map, Value, json, value::RawValue};
use std::{collections::BTreeSet, future::Future, sync::Arc};

/// Error code for multi-era simulations, methods a worker lacks, and unrouted methods.
pub const UNSUPPORTED_CODE: i32 = -32004;

/// Error code backends return for blocks they cannot resolve.
pub const UNKNOWN_BLOCK_CODE: i32 = -32001;

/// Largest `reth_getBlockExecutionOutcome` block count, matching the native limit.
const MAX_EXECUTION_OUTCOME_BLOCKS: u64 = 128;

const BLOCK_ID: &[&str] = &["block_id", "blockId"];
const TRANSACTION_HASH: &[&str] = &["tx_hash", "txHash", "hash", "transaction"];
const TRACE_CHAIN_START: &[&str] = &["start_exclusive", "startExclusive"];
const TRACE_CHAIN_END: &[&str] = &["end_inclusive", "endInclusive"];
const STATE_CONTEXT: &[&str] = &["state_context", "stateContext"];
const SIM_OVERRIDES: &[&str] = &["sim_overrides", "simOverrides"];
const OVERRIDE_TIME: &[&str] = &["time", "timestamp"];

/// Prefixes of namespaces that never execute blocks.
const NATIVE_PREFIXES: &[&str] = &[
    "engine_",
    "net_",
    "web3_",
    "rpc_",
    "txpool_",
    "admin_",
    "miner_",
    "operator_",
    "consensus_",
    "token_",
];

/// Reviewed methods that only read stored data or don't execute.
const NATIVE_METHODS: &[&str] = &[
    "reth_newPayload",
    "reth_forkchoiceUpdated",
    "eth_subscribe",
    "eth_unsubscribe",
    "eth_protocolVersion",
    "eth_syncing",
    "eth_coinbase",
    "eth_accounts",
    "eth_blockNumber",
    "eth_chainId",
    "eth_capabilities",
    "eth_getBlockByHash",
    "eth_getBlockByNumber",
    "eth_getBlockTransactionCountByHash",
    "eth_getBlockTransactionCountByNumber",
    "eth_getUncleCountByBlockHash",
    "eth_getUncleCountByBlockNumber",
    "eth_getBlockReceipts",
    "eth_getUncleByBlockHashAndIndex",
    "eth_getUncleByBlockNumberAndIndex",
    "eth_getRawTransactionByHash",
    "eth_getTransactionByHash",
    "eth_getRawTransactionByBlockHashAndIndex",
    "eth_getRawTransactionByBlockNumberAndIndex",
    "eth_getTransactionByBlockHashAndIndex",
    "eth_getTransactionByBlockNumberAndIndex",
    "eth_getTransactionBySenderAndNonce",
    "eth_pendingTransactions",
    "eth_getTransactionReceipt",
    "eth_getBalance",
    "eth_getStorageAt",
    "eth_getStorageValues",
    "eth_getTransactionCount",
    "eth_getCode",
    "eth_getHeaderByNumber",
    "eth_getHeaderByHash",
    "eth_gasPrice",
    "eth_getAccount",
    "eth_maxPriorityFeePerGas",
    "eth_baseFee",
    "eth_blobBaseFee",
    "eth_mining",
    "eth_hashrate",
    "eth_getWork",
    "eth_submitHashrate",
    "eth_submitWork",
    "eth_sendTransaction",
    "eth_sendRawTransaction",
    "eth_sendRawTransactionSync",
    "eth_sendRawTransactionConditional",
    "eth_sign",
    "eth_signTransaction",
    "eth_signTypedData",
    "eth_fillTransaction",
    "eth_getProof",
    "eth_getMultiProof",
    "eth_getAccountInfo",
    "eth_getLogs",
    "eth_newFilter",
    "eth_newBlockFilter",
    "eth_newPendingTransactionFilter",
    "eth_getFilterChanges",
    "eth_getFilterLogs",
    "eth_uninstallFilter",
    "eth_getTransactions",
    "eth_config",
    "tempo_fundAddress",
    "tempo_forkSchedule",
    "debug_getRawHeader",
    "debug_getRawBlock",
    "debug_getRawTransaction",
    "debug_getRawTransactions",
    "debug_getRawReceipts",
    "debug_getBadBlocks",
    "debug_clearTxpool",
    "debug_chaindbCompact",
    "debug_chaindbProperty",
    "debug_chainConfig",
    "debug_codeByHash",
    "debug_dbAncient",
    "debug_dbAncients",
    "debug_dbGet",
    "debug_dumpBlock",
    "debug_freeOSMemory",
    "debug_gcStats",
    "debug_getAccessibleState",
    "debug_accountRange",
    "debug_getModifiedAccountsByNumber",
    "debug_getModifiedAccountsByHash",
    "debug_memStats",
    "debug_preimage",
    "debug_printBlock",
    "debug_seedHash",
    "debug_setGCPercent",
    "debug_setHead",
    "debug_setTrieFlushInterval",
    // Stubs in the pinned backend.
    "debug_standardTraceBlockToFile",
    "debug_storageRangeAt",
    "debug_standardTraceBadBlockToFile",
    "debug_stateRootWithUpdates",
    "reth_getBalanceChangesInBlock",
    "reth_jit",
    "ots_getApiLevel",
    "ots_getHeaderByNumber",
    "erigon_getHeaderByNumber",
    "ots_hasCode",
    "ots_getBlockDetails",
    "ots_getBlockDetailsByHash",
    "ots_getBlockTransactions",
    "ots_getTransactionBySenderAndNonce",
    "ots_searchTransactionsBefore",
    "ots_searchTransactionsAfter",
];

/// Node-specific operations the router needs. Implemented by the chain adapter.
pub trait Backend: Send + Sync {
    /// Resolves a tag, number, hash, or EIP-1898 selector, or fails with [`UNKNOWN_BLOCK_CODE`].
    fn block<'a>(&'a self, selector: &'a Value) -> BoxFuture<'a, RpcResult<BlockMetadata>>;

    /// Returns the timestamp of the block containing `hash`, `None` for pooled or unknown txs.
    fn transaction_timestamp<'a>(
        &'a self,
        hash: &'a Value,
    ) -> BoxFuture<'a, RpcResult<Option<u64>>>;

    /// Forwards a call to frozen era `era`.
    fn forward<'a>(
        &'a self,
        era: usize,
        method: &'a str,
        params: RpcParams,
    ) -> BoxFuture<'a, RpcResult<Box<RawValue>>>;

    /// Opens a `debug_subscribe` subscription on frozen era `era`, yielding raw results.
    fn subscribe<'a>(
        &'a self,
        era: usize,
        params: RpcParams,
    ) -> BoxFuture<'a, RpcResult<BoxStream<'static, Box<RawValue>>>>;

    /// Decodes the header timestamp of the RLP block in `debug_traceBlock` params.
    fn raw_block_timestamp(&self, params: &RpcParams) -> RpcResult<u64>;

    /// Merges consecutive `reth_getBlockExecutionOutcome` results, oldest first.
    fn merge_execution_outcomes(&self, parts: Vec<Box<RawValue>>) -> RpcResult<Box<RawValue>>;
}

/// A resolved canonical or pending block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockMetadata {
    /// Block number.
    pub number: u64,
    /// Block hash.
    pub hash: B256,
    /// Block timestamp in seconds.
    pub timestamp: u64,
}

impl BlockMetadata {
    /// Pins `selector` to this block, keeping explicit hashes (and `requireCanonical`) verbatim.
    pub fn pin(&self, selector: &Value, number_only: bool) -> Value {
        if is_explicit_hash(selector) {
            selector.clone()
        } else if number_only {
            hex(self.number)
        } else {
            json!({ "blockHash": self.hash })
        }
    }
}

/// JSON-RPC params: a positional array, a named object, or null. Forwarded in the same shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcParams(pub Value);

impl RpcParams {
    /// Returns the param at `index`, or under the first of `names` present. Null is absent.
    pub fn get(&self, index: usize, names: &[&str]) -> Option<&Value> {
        match &self.0 {
            Value::Array(params) => params.get(index),
            Value::Object(params) => names.iter().find_map(|name| params.get(*name)),
            _ => None,
        }
        .filter(|value| !value.is_null())
    }

    /// Writes the param at `index`, or under the caller's spelling of `names` (else `names[0]`).
    pub fn set(&mut self, index: usize, names: &[&str], value: Value) {
        if self.0.is_null() {
            self.0 = Value::Array(Vec::new());
        }
        match &mut self.0 {
            Value::Array(params) => {
                if params.len() <= index {
                    params.resize(index + 1, Value::Null);
                }
                params[index] = value;
            }
            Value::Object(params) => {
                let name = names
                    .iter()
                    .find(|name| params.contains_key(**name))
                    .unwrap_or(&names[0]);
                params.insert((*name).to_owned(), value);
            }
            // Rejected by `ensure_shape` before any write.
            _ => {}
        }
    }

    fn ensure_shape(&self) -> RpcResult<()> {
        match self.0 {
            Value::Null | Value::Array(_) | Value::Object(_) => Ok(()),
            _ => Err(invalid_params("params must be an array or an object")),
        }
    }
}

impl ToRpcParams for RpcParams {
    fn to_rpc_params(self) -> Result<Option<Box<RawValue>>, serde_json::Error> {
        match self.0 {
            Value::Null => Ok(None),
            params => serde_json::value::to_raw_value(&params).map(Some),
        }
    }
}

/// Where a request executes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// The live era executes the request natively, with its original params.
    Live,
    /// A frozen era executes the whole request.
    Era(usize, RpcParams),
    /// A canonical range split into non-empty, ascending, single-era segments run in order.
    Split {
        /// Era and params of each segment.
        segments: Vec<(usize, RpcParams)>,
        /// How segment results combine.
        merge: Merge,
    },
    /// A historical `traceChain` subscription, chaining one upstream subscription per segment.
    Relay {
        /// Segments in block order.
        segments: Vec<RelaySegment>,
    },
}

/// How split results combine into the response of a single native call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Merge {
    /// Concatenate trace arrays, then apply the caller's pagination once over the whole range.
    TraceFilter {
        /// Matching traces to skip.
        after: Option<u64>,
        /// Maximum traces to return after skipping.
        count: Option<u64>,
    },
    /// Stop at the first `null` part, then [`Backend::merge_execution_outcomes`].
    ExecutionOutcome,
}

/// One upstream `traceChain` subscription of a relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySegment {
    /// Era serving the segment.
    pub era: usize,
    /// `["traceChain", start_exclusive, end_inclusive, opts]` in the caller's shape.
    pub params: RpcParams,
    /// The segment's inclusive end block.
    pub last_block: u64,
    /// Whether this is the relay's final segment.
    pub is_last: bool,
}

/// Selects the era that executes each request.
pub struct Router {
    boundaries: Vec<u64>,
    max_trace_filter_blocks: u64,
    backend: Arc<dyn Backend>,
}

impl Router {
    /// Creates a router for eras ending at `boundaries`, with the node's `trace_filter` limit.
    pub fn new(
        boundaries: Vec<u64>,
        max_trace_filter_blocks: u64,
        backend: Arc<dyn Backend>,
    ) -> Self {
        Self {
            boundaries,
            max_trace_filter_blocks,
            backend,
        }
    }

    /// Returns the era containing blocks with timestamp `timestamp`.
    pub fn era(&self, timestamp: u64) -> usize {
        self.boundaries.partition_point(|end| *end <= timestamp)
    }

    /// Returns the index of the live era, which runs in-process.
    pub fn live_index(&self) -> usize {
        self.boundaries.len()
    }

    /// Returns the backend the router resolves blocks with.
    pub fn backend(&self) -> &dyn Backend {
        &*self.backend
    }

    /// Routes `method`.
    pub async fn route(&self, method: &str, mut params: RpcParams) -> RpcResult<Route> {
        let policy = policy(method);
        if !matches!(policy, Policy::Native) {
            params.ensure_shape()?;
        }
        match policy {
            Policy::Native => Ok(Route::Live),
            Policy::Execution => Err(unsupported(format!("{method} has no era routing policy"))),
            Policy::Block {
                index,
                names,
                number_only,
            } => {
                let default = if method == "eth_estimateGas" {
                    "pending"
                } else {
                    "latest"
                };
                let selector = params
                    .get(index, names)
                    .cloned()
                    .unwrap_or_else(|| default.into());
                if is_pending(&selector) {
                    return Ok(Route::Live);
                }
                let block = self.backend.block(&selector).await?;
                params.set(index, names, block.pin(&selector, number_only));
                Ok(self.era_route(self.era(block.timestamp), params))
            }
            Policy::FeeHistory => self.route_fee_history(params).await,
            Policy::Transaction => {
                let hash = params
                    .get(0, TRANSACTION_HASH)
                    .ok_or_else(|| invalid_params("missing transaction hash"))?;
                Ok(match self.backend.transaction_timestamp(hash).await? {
                    Some(timestamp) => self.era_route(self.era(timestamp), params),
                    None => Route::Live,
                })
            }
            Policy::Simulation { payload, base } => {
                self.route_simulation(params, payload, base).await
            }
            Policy::BaseBlock {
                index,
                names,
                field,
                number_only,
            } => {
                let Some(Value::Object(mut container)) = params.get(index, names).cloned() else {
                    return Ok(Route::Live);
                };
                let Some(selector) = container.get(field).filter(|v| !v.is_null()).cloned() else {
                    return Ok(Route::Live);
                };
                if is_pending(&selector) {
                    return Ok(Route::Live);
                }
                let block = self.backend.block(&selector).await?;
                container.insert(field.to_owned(), block.pin(&selector, number_only));
                params.set(index, names, Value::Object(container));
                Ok(self.era_route(self.era(block.timestamp), params))
            }
            Policy::MevBundle => {
                let mut overrides = match params.get(1, SIM_OVERRIDES) {
                    Some(Value::Object(overrides)) => overrides.clone(),
                    _ => Map::new(),
                };
                let parent = overrides
                    .get("parentBlock")
                    .filter(|v| !v.is_null())
                    .cloned()
                    .unwrap_or_else(|| "latest".into());
                if is_pending(&parent) {
                    return Ok(Route::Live);
                }
                let time = override_time(&overrides)?;
                let block = self.backend.block(&parent).await?;
                overrides.insert("parentBlock".to_owned(), block.pin(&parent, false));
                params.set(1, SIM_OVERRIDES, Value::Object(overrides));
                Ok(self.era_route(self.era(time.unwrap_or(block.timestamp)), params))
            }
            Policy::ExecutionOutcome => self.route_execution_outcome(params).await,
            Policy::TraceFilter => self.route_trace_filter(params).await,
            Policy::RawBlock => {
                let timestamp = self.backend.raw_block_timestamp(&params)?;
                Ok(self.era_route(self.era(timestamp), params))
            }
            Policy::TraceChain => self.route_trace_chain(params).await,
        }
    }

    async fn route_fee_history(&self, mut params: RpcParams) -> RpcResult<Route> {
        const BLOCK_COUNT: &[&str] = &["block_count", "blockCount"];
        const NEWEST: &[&str] = &["newest_block", "newestBlock"];
        // Native validates malformed params and answers a zero count without storage.
        let count = params.get(0, BLOCK_COUNT).and_then(quantity);
        let newest = params.get(1, NEWEST).filter(|v| is_block_number_or_tag(v));
        let (Some(count), Some(newest)) = (count, newest) else {
            return Ok(Route::Live);
        };
        if count == 0 {
            return Ok(Route::Live);
        }
        let newest = if newest.as_str() == Some("pending") {
            "latest".into()
        } else {
            newest.clone()
        };
        let block = self.backend.block(&newest).await?;
        params.set(1, NEWEST, block.pin(&newest, true));
        Ok(self.era_route(self.era(block.timestamp), params))
    }

    async fn route_simulation(
        &self,
        mut params: RpcParams,
        payload: &'static [&'static str],
        base: &'static [&'static str],
    ) -> RpcResult<Route> {
        // Each generated block takes its rules from its own timestamp.
        let mut eras = BTreeSet::new();
        let calls = params
            .get(0, payload)
            .and_then(|payload| payload.get("blockStateCalls"))
            .and_then(Value::as_array);
        for call in calls.into_iter().flatten() {
            if let Some(Value::Object(overrides)) = call.get("blockOverrides")
                && let Some(time) = override_time(overrides)?
            {
                eras.insert(self.era(time));
            }
        }
        if eras.len() > 1 {
            return Err(unsupported("simulated blocks span multiple eras"));
        }

        let base_era = match params.get(1, base).cloned() {
            Some(selector) if !is_pending(&selector) => {
                let block = self.backend.block(&selector).await?;
                params.set(1, base, block.pin(&selector, false));
                self.era(block.timestamp)
            }
            _ => self.live_index(),
        };
        // The executor rejects simulated times that precede the parent.
        let era = eras.first().copied().unwrap_or(base_era).max(base_era);
        Ok(self.era_route(era, params))
    }

    async fn route_execution_outcome(&self, mut params: RpcParams) -> RpcResult<Route> {
        const COUNT: &[&str] = &["count"];
        let count = match params.get(1, COUNT) {
            None => 1,
            Some(count) => quantity(count).ok_or_else(|| invalid_params("invalid block count"))?,
        };
        if !(1..=MAX_EXECUTION_OUTCOME_BLOCKS).contains(&count) {
            return Err(invalid_params(format!(
                "block count must be between 1 and {MAX_EXECUTION_OUTCOME_BLOCKS}"
            )));
        }
        let selector = params
            .get(0, BLOCK_ID)
            .cloned()
            .ok_or_else(|| invalid_params("missing block id"))?;
        if is_pending(&selector) {
            return Ok(Route::Live);
        }
        let mut first = self.backend.block(&selector).await?;
        if is_explicit_hash(&selector) {
            // Native replays canonical blocks by height.
            first = self.block_at(first.number).await?;
        }
        if first.number == 0 {
            // Native answers genesis with an empty outcome without executing.
            return Ok(Route::Live);
        }
        let head = self.backend.block(&"latest".into()).await?;
        let last_number = first
            .number
            .checked_add(count - 1)
            .ok_or_else(|| invalid_params("block range overflows"))?
            .min(head.number);
        let last = self.block_at(last_number).await?;
        let segments = self.split(first, last).await?;
        if let [(era, _, _)] = segments[..] {
            params.set(0, BLOCK_ID, first.pin(&selector, false));
            return Ok(self.era_route(era, params));
        }
        let segments = segments
            .into_iter()
            .map(|(era, start, end)| {
                let mut params = params.clone();
                params.set(0, BLOCK_ID, hex(start));
                params.set(1, COUNT, hex(end - start + 1));
                (era, params)
            })
            .collect();
        Ok(Route::Split {
            segments,
            merge: Merge::ExecutionOutcome,
        })
    }

    async fn route_trace_filter(&self, mut params: RpcParams) -> RpcResult<Route> {
        const FILTER: &[&str] = &["filter"];
        let Some(Value::Object(filter)) = params.get(0, FILTER).cloned() else {
            return Err(invalid_params("trace filter must be an object"));
        };
        let bound = |name: &str| -> Value {
            filter
                .get(name)
                .filter(|v| !v.is_null())
                .cloned()
                .unwrap_or_else(|| "latest".into())
        };
        let (from_selector, to_selector) = (bound("fromBlock"), bound("toBlock"));
        let from = self.backend.block(&from_selector).await?;
        let to = if to_selector == from_selector {
            from
        } else {
            self.backend.block(&to_selector).await?
        };
        if from.number > to.number {
            return Err(invalid_params(
                "invalid parameters: fromBlock cannot be greater than toBlock",
            ));
        }
        if to.number - from.number > self.max_trace_filter_blocks {
            return Err(invalid_params(format!(
                "Block range too large; currently limited to {} blocks",
                self.max_trace_filter_blocks
            )));
        }
        let pagination = |name: &str| -> RpcResult<Option<u64>> {
            match filter.get(name).filter(|v| !v.is_null()) {
                None => Ok(None),
                Some(value) => quantity(value)
                    .map(Some)
                    .ok_or_else(|| invalid_params(format!("invalid trace filter {name}"))),
            }
        };
        let merge = Merge::TraceFilter {
            after: pagination("after")?,
            count: pagination("count")?,
        };

        let segment_filter = |start: u64, end: u64, paginated: bool| {
            let mut filter = filter.clone();
            filter.insert("fromBlock".to_owned(), hex(start));
            filter.insert("toBlock".to_owned(), hex(end));
            if !paginated {
                filter.remove("after");
                filter.remove("count");
            }
            Value::Object(filter)
        };
        let segments = self.split(from, to).await?;
        if let [(era, start, end)] = segments[..] {
            params.set(0, FILTER, segment_filter(start, end, true));
            return Ok(self.era_route(era, params));
        }
        let segments = segments
            .into_iter()
            .map(|(era, start, end)| {
                let mut params = params.clone();
                params.set(0, FILTER, segment_filter(start, end, false));
                (era, params)
            })
            .collect();
        Ok(Route::Split { segments, merge })
    }

    async fn route_trace_chain(&self, params: RpcParams) -> RpcResult<Route> {
        if params.get(0, &["subscription"]).and_then(Value::as_str) != Some("traceChain") {
            return Ok(Route::Live);
        }
        let (Some(start), Some(end)) = (
            params.get(1, TRACE_CHAIN_START),
            params.get(2, TRACE_CHAIN_END),
        ) else {
            return Ok(Route::Live);
        };
        let start = self.backend.block(start).await?;
        let end = self.backend.block(end).await?;
        if start.number >= end.number {
            // Native rejects the empty range with its own error.
            return Ok(Route::Live);
        }
        let first = self.block_at(start.number + 1).await?;
        if self.era(first.timestamp) == self.live_index() {
            return Ok(Route::Live);
        }
        let segments = self.split(first, end).await?;
        let count = segments.len();
        let segments = segments
            .into_iter()
            .enumerate()
            .map(|(i, (era, first, last))| {
                let mut params = params.clone();
                params.set(1, TRACE_CHAIN_START, hex(first - 1));
                params.set(2, TRACE_CHAIN_END, hex(last));
                RelaySegment {
                    era,
                    params,
                    last_block: last,
                    is_last: i + 1 == count,
                }
            })
            .collect();
        Ok(Route::Relay { segments })
    }

    /// Splits `[first, last]` into non-empty, ascending `(era, start, end)` segments.
    async fn split(
        &self,
        first: BlockMetadata,
        last: BlockMetadata,
    ) -> RpcResult<Vec<(usize, u64, u64)>> {
        let (first_era, last_era) = (self.era(first.timestamp), self.era(last.timestamp));
        let end = last
            .number
            .checked_add(1)
            .ok_or_else(|| invalid_params("block range overflows"))?;
        let mut starts = vec![(first.number, first_era)];
        let mut low = first.number + 1;
        for (offset, boundary) in self.boundaries[first_era..last_era].iter().enumerate() {
            let start = first_block_at(low, end, *boundary, |number| async move {
                Ok::<_, ErrorObjectOwned>(self.block_at(number).await?.timestamp)
            })
            .await?;
            let era = first_era + offset + 1;
            match starts.last_mut() {
                // The previous era has no blocks in range.
                Some(last) if last.0 == start => last.1 = era,
                _ => starts.push((start, era)),
            }
            low = start;
        }
        Ok(starts
            .iter()
            .enumerate()
            .map(|(i, (start, era))| {
                let end = starts.get(i + 1).map_or(last.number, |next| next.0 - 1);
                (*era, *start, end)
            })
            .collect())
    }

    fn era_route(&self, era: usize, params: RpcParams) -> Route {
        if era == self.live_index() {
            Route::Live
        } else {
            Route::Era(era, params)
        }
    }

    async fn block_at(&self, number: u64) -> RpcResult<BlockMetadata> {
        self.backend.block(&hex(number)).await
    }
}

/// Binary-searches the first block in `low..high` with timestamp `>= boundary`, else `high`.
pub async fn first_block_at<E, F, Fut>(
    mut low: u64,
    mut high: u64,
    boundary: u64,
    mut timestamp_of: F,
) -> Result<u64, E>
where
    F: FnMut(u64) -> Fut,
    Fut: Future<Output = Result<u64, E>>,
{
    while low < high {
        let mid = low + (high - low) / 2;
        if timestamp_of(mid).await? >= boundary {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    Ok(low)
}

/// Whether `method` must be routed. `debug_subscribe` is only routed for `traceChain`.
pub fn is_execution_method(method: &str) -> bool {
    !matches!(policy(method), Policy::Native | Policy::TraceChain)
}

/// Builds a `-32602` invalid params error.
pub fn invalid_params(message: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(INVALID_PARAMS_CODE, message.into(), None::<()>)
}

/// Builds a [`UNSUPPORTED_CODE`] error.
pub fn unsupported(message: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(UNSUPPORTED_CODE, message.into(), None::<()>)
}

/// Builds a `-32603` internal error.
pub fn internal(message: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, message.into(), None::<()>)
}

/// Builds a `-32000` error for an unavailable worker.
pub fn unavailable(message: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(CALL_EXECUTION_FAILED_CODE, message.into(), None::<()>)
}

/// Builds a [`UNKNOWN_BLOCK_CODE`] error.
pub fn unknown_block() -> ErrorObjectOwned {
    ErrorObjectOwned::owned(UNKNOWN_BLOCK_CODE, "unknown block", None::<()>)
}

/// How a method is routed.
#[derive(Debug, Clone, Copy)]
enum Policy {
    /// Runs where the block selected by param `index`/`names` lives.
    Block {
        index: usize,
        names: &'static [&'static str],
        number_only: bool,
    },
    /// `eth_feeHistory`: routed by its newest block.
    FeeHistory,
    /// Runs where the block containing the transaction lives.
    Transaction,
    /// Generates blocks whose rules follow their own timestamps.
    Simulation {
        payload: &'static [&'static str],
        base: &'static [&'static str],
    },
    /// Runs under the rules of the base block in `field` of param `index`/`names`.
    BaseBlock {
        index: usize,
        names: &'static [&'static str],
        field: &'static str,
        number_only: bool,
    },
    /// `mev_simBundle`: generates one block on a parent.
    MevBundle,
    /// `reth_getBlockExecutionOutcome`: replays a canonical range.
    ExecutionOutcome,
    /// `trace_filter`: traces a canonical range.
    TraceFilter,
    /// `debug_traceBlock`: routed by the RLP block's header.
    RawBlock,
    /// `debug_subscribe`: relays historical `traceChain` subscriptions.
    TraceChain,
    /// Served natively with untouched params.
    Native,
    /// Executes without a reviewed policy, so it is rejected.
    Execution,
}

fn policy(method: &str) -> Policy {
    let block = |index, names, number_only| Policy::Block {
        index,
        names,
        number_only,
    };
    match method {
        "eth_call" | "eth_estimateGas" | "eth_createAccessList" => {
            block(1, &["block_number", "blockNumber"], false)
        }
        "debug_traceCall" => block(1, BLOCK_ID, false),
        "trace_call" | "trace_rawTransaction" => block(2, BLOCK_ID, false),
        "trace_callMany" => block(1, BLOCK_ID, false),
        "debug_traceBlockByNumber" => block(0, &["block"], true),
        "debug_traceBlockByHash" => block(0, &["block"], false),
        "eth_getBlockAccessListByBlockHash" => block(0, &["hash"], false),
        "eth_getBlockAccessListByBlockNumber" => block(0, &["number"], true),
        "eth_getBlockAccessList" => block(0, BLOCK_ID, false),
        "eth_getBlockAccessListRaw" | "debug_getRawBlockAccessList" => {
            block(0, &["block", "block_id", "blockId"], false)
        }
        "debug_executionWitnessByBlockHash" => block(0, &["hash"], false),
        "debug_intermediateRoots" => block(0, &["block_hash", "blockHash"], false),
        "debug_executionWitness" => block(0, &["block"], false),
        "debug_accountAt"
        | "debug_accountInfoAt"
        | "trace_block"
        | "trace_replayBlockTransactions"
        | "trace_blockOpcodeGas" => block(0, BLOCK_ID, false),
        "eth_feeHistory" => Policy::FeeHistory,
        "debug_traceTransaction"
        | "trace_transaction"
        | "trace_get"
        | "trace_replayTransaction"
        | "trace_transactionOpcodeGas"
        | "ots_getInternalOperations"
        | "ots_getTransactionError"
        | "ots_traceTransaction" => Policy::Transaction,
        "eth_simulateV1" => Policy::Simulation {
            payload: &["opts"],
            base: &["block_number", "blockNumber"],
        },
        "tempo_simulateV1" => Policy::Simulation {
            payload: &["payload"],
            base: &["block"],
        },
        "eth_callBundle" => Policy::BaseBlock {
            index: 0,
            names: &["request"],
            field: "stateBlockNumber",
            number_only: true,
        },
        "eth_callMany" | "debug_traceCallMany" => Policy::BaseBlock {
            index: 1,
            names: STATE_CONTEXT,
            field: "blockNumber",
            number_only: false,
        },
        "mev_simBundle" => Policy::MevBundle,
        "reth_getBlockExecutionOutcome" => Policy::ExecutionOutcome,
        "trace_filter" => Policy::TraceFilter,
        "debug_traceBlock" => Policy::RawBlock,
        "debug_subscribe" => Policy::TraceChain,
        _ if NATIVE_METHODS.contains(&method)
            || NATIVE_PREFIXES
                .iter()
                .any(|prefix| method.starts_with(prefix)) =>
        {
            Policy::Native
        }
        _ => Policy::Execution,
    }
}

/// Reads a block-override time from `time` or its alias `timestamp`.
fn override_time(overrides: &Map<String, Value>) -> RpcResult<Option<u64>> {
    match OVERRIDE_TIME
        .iter()
        .find_map(|name| overrides.get(*name).filter(|v| !v.is_null()))
    {
        None => Ok(None),
        Some(time) => quantity(time)
            .map(Some)
            .ok_or_else(|| invalid_params("invalid block override time")),
    }
}

/// Parses a hex quantity or JSON number.
fn quantity(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64(),
        Value::String(hex) => u64::from_str_radix(hex.strip_prefix("0x")?, 16).ok(),
        _ => None,
    }
}

fn hex(number: u64) -> Value {
    Value::String(format!("{number:#x}"))
}

fn is_explicit_hash(selector: &Value) -> bool {
    match selector {
        Value::String(hash) => hash.len() == 66 && hash.starts_with("0x"),
        Value::Object(selector) => selector.contains_key("blockHash"),
        _ => false,
    }
}

fn is_pending(selector: &Value) -> bool {
    match selector {
        Value::String(tag) => tag == "pending",
        Value::Object(selector) => {
            selector.get("blockNumber").and_then(Value::as_str) == Some("pending")
        }
        _ => false,
    }
}

fn is_block_number_or_tag(selector: &Value) -> bool {
    match selector {
        Value::String(tag) => {
            matches!(
                tag.as_str(),
                "latest" | "earliest" | "pending" | "safe" | "finalized"
            ) || quantity(selector).is_some()
        }
        Value::Number(_) => quantity(selector).is_some(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reviewed_native_methods_do_not_execute() {
        for method in NATIVE_METHODS {
            assert!(matches!(policy(method), Policy::Native), "{method}");
            assert!(!is_execution_method(method), "{method}");
        }
        for prefix in NATIVE_PREFIXES {
            assert!(
                !is_execution_method(&format!("{prefix}anything")),
                "{prefix}"
            );
        }
    }
}
