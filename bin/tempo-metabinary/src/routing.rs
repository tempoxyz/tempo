//! Select an RPC request's era from native block metadata and pin its block selectors.
//!
//! `pending` stays live, cross-era requests fail with `-32004`, and unclassified methods fail.

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
const MAX_EXECUTION_OUTCOME_BLOCKS: u64 = 128;

/// Resolve identifiers through the live node. Frozen workers receive pinned historical IDs.
pub struct Router {
    /// Strictly increasing exclusive end timestamps of the frozen eras, from
    /// [`crate::catalog::ChainEras::boundaries`].
    boundaries: Vec<u64>,
    pub(crate) backend: Arc<dyn Backend>,
}

impl Router {
    pub fn new(boundaries: Vec<u64>, backend: Arc<dyn Backend>) -> Self {
        Self {
            boundaries,
            backend,
        }
    }

    pub fn live_index(&self) -> usize {
        self.boundaries.len()
    }
    fn era(&self, timestamp: u64) -> usize {
        self.boundaries.partition_point(|end| *end <= timestamp)
    }

    /// Returns the selected era, [`Self::live_index`] for native execution, and its parameters.
    pub async fn route(
        &self,
        method: &str,
        mut params: RpcParams,
    ) -> RpcResult<(usize, RpcParams)> {
        if !params.0.is_null() && !params.0.is_array() && !params.0.is_object() {
            return Err(invalid("params must be an array or an object"));
        }
        let live = self.live_index();
        let era = match policy(method) {
            Policy::TraceChain => {
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
            Policy::Simulation => {
                let (payload, block): (&[&str], &[&str]) = if method == "eth_simulateV1" {
                    (&["opts"], &["block_number", "blockNumber"])
                } else {
                    (&["payload"], &["block"])
                };
                let calls = params
                    .get(0, payload)
                    .and_then(|payload| payload.get("blockStateCalls"))
                    .and_then(Value::as_array);
                self.live_base(
                    params.get(1, block),
                    calls
                        .into_iter()
                        .flatten()
                        .map(|call| call.get("blockOverrides")),
                )
                .await?
            }
            Policy::CallBundle => {
                // The bundle request carries its own `timestamp` override.
                let request = params.get(0, &["request"]);
                self.live_base(
                    request.and_then(|request| request.get("stateBlockNumber")),
                    [request],
                )
                .await?
            }
            Policy::MevBundle => {
                let overrides = params.get(1, &["sim_overrides", "simOverrides"]);
                self.live_base(
                    overrides.and_then(|overrides| overrides.get("parentBlock")),
                    [overrides],
                )
                .await?
            }
            Policy::CallMany => {
                let bundles = params.get(0, &["bundles"]).and_then(Value::as_array);
                self.live_base(
                    params
                        .get(1, &["state_context", "stateContext"])
                        .and_then(|context| context.get("blockNumber")),
                    bundles
                        .into_iter()
                        .flatten()
                        .map(|bundle| bundle.get("blockOverride")),
                )
                .await?
            }
            Policy::ExecutionOutcome => self.execution_outcome(&mut params).await?,
            Policy::TraceFilter => self.filter(&mut params).await?,
            Policy::RawBlock => self.era(self.backend.raw_block_timestamp(&params)?),
            Policy::Transaction => {
                let hash = params
                    .get(0, &["tx_hash", "txHash", "hash", "transaction"])
                    .ok_or_else(|| invalid("missing transaction hash"))?;
                self.backend
                    .transaction_timestamp(hash)
                    .await?
                    .map_or(live, |timestamp| self.era(timestamp))
            }
            Policy::Block(index, names, number_only) => {
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
            Policy::Execution => {
                return Err(unsupported(format!("{method} has no era routing policy")));
            }
        };
        Ok((era, params))
    }

    /// Generated children never precede their base, so a live base and live overrides stay live.
    async fn live_base<'a>(
        &self,
        base: Option<&Value>,
        overrides: impl IntoIterator<Item = Option<&'a Value>>,
    ) -> RpcResult<usize> {
        let live = self.live_index();
        for overrides in overrides {
            self.check_time(live, overrides)?;
        }
        if let Some(base) = base.filter(|base| !base.is_null() && *base != "pending")
            && self.era(self.backend.block(base).await?.timestamp) != live
        {
            return Err(unsupported(
                "historical simulations and bundles require a live base block",
            ));
        }
        Ok(live)
    }

    fn check_time(&self, era: usize, overrides: Option<&Value>) -> RpcResult<()> {
        if override_time(overrides)?.is_some_and(|time| self.era(time) != era) {
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
        if is_hash(&selector) {
            // Native replay resolves a hash to a height, then executes canonical blocks by height.
            first = self.backend.block(&first.number_id()).await?;
        }
        // The native method returns an empty execution outcome for genesis without executing.
        if first.number == 0 {
            return Ok(self.live_index());
        }
        let era = self.era(first.timestamp);
        if count > 1 {
            // Native replay stops at the first absent block when a range extends past the head.
            let head = self.backend.block(&json!("latest")).await?;
            let last = first.number.saturating_add(count - 1).min(head.number);
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
            Value::Object(o) => o.get(param_name(o, names)?),
            _ => None,
        }
        .filter(|v| !v.is_null())
    }

    fn get_mut(&mut self, index: usize, names: &[&str]) -> Option<&mut Value> {
        match &mut self.0 {
            Value::Array(a) => a.get_mut(index),
            Value::Object(o) => o.get_mut(param_name(o, names)?),
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
                o.insert(param_name(o, names).unwrap_or(names[0]).into(), value);
            }
            _ => {}
        }
    }
}

/// The first alias present in named params, so forwarding keeps the caller's spelling.
fn param_name<'n>(params: &serde_json::Map<String, Value>, names: &[&'n str]) -> Option<&'n str> {
    names.iter().find(|n| params.contains_key(**n)).copied()
}

/// Worker call errors pass through; transport failures become execution errors.
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

fn quantity(value: &Value) -> RpcResult<u64> {
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
        if is_hash(&selector) {
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
        era: usize,
        method: &'a str,
        params: RpcParams,
    ) -> BoxFuture<'a, RpcResult<Box<RawValue>>>;

    /// Only the chain-specific adapter knows the raw block encoding.
    fn raw_block_timestamp(&self, params: &RpcParams) -> RpcResult<u64>;
}

/// Block hashes and EIP-1898 hash objects, as opposed to tags and numbers.
fn is_hash(selector: &Value) -> bool {
    selector.get("blockHash").is_some()
        || selector
            .as_str()
            .is_some_and(|s| s.len() == BLOCK_HASH_HEX_LEN)
}

/// Block overrides accept `time` or its `timestamp` alias.
fn override_time(overrides: Option<&Value>) -> RpcResult<Option<u64>> {
    overrides
        .and_then(|o| o.get("time").or_else(|| o.get("timestamp")))
        .filter(|v| !v.is_null())
        .map(quantity)
        .transpose()
}

/// One classification controls selector routing and native callback decoration.
enum Policy {
    Native,
    /// `(param index, named-param aliases, number_only)`; `number_only` pins tags to numbers.
    Block(usize, &'static [&'static str], bool),
    Transaction,
    Simulation,
    CallBundle,
    MevBundle,
    ExecutionOutcome,
    CallMany,
    TraceFilter,
    RawBlock,
    /// Guarded through its subscription callback, not as an ordinary execution method.
    TraceChain,
    /// Rejected, including unknown methods.
    Execution,
}

fn policy(method: &str) -> Policy {
    match method {
        "debug_subscribe" => Policy::TraceChain,
        "eth_simulateV1" | "tempo_simulateV1" => Policy::Simulation,
        "eth_callBundle" => Policy::CallBundle,
        "mev_simBundle" => Policy::MevBundle,
        "reth_getBlockExecutionOutcome" => Policy::ExecutionOutcome,
        "eth_callMany" | "debug_traceCallMany" => Policy::CallMany,
        "trace_filter" => Policy::TraceFilter,
        "debug_traceBlock" => Policy::RawBlock,
        "debug_traceTransaction"
        | "trace_transaction"
        | "trace_get"
        | "trace_replayTransaction"
        | "trace_transactionOpcodeGas"
        | "ots_getInternalOperations"
        | "ots_getTransactionError"
        | "ots_traceTransaction" => Policy::Transaction,
        "eth_call" | "eth_estimateGas" | "eth_createAccessList" => {
            Policy::Block(1, &["block_number", "blockNumber"], false)
        }
        "debug_traceCall" => Policy::Block(1, &["block_id", "blockId"], false),
        "trace_call" | "trace_rawTransaction" => Policy::Block(2, &["block_id", "blockId"], false),
        "trace_callMany" => Policy::Block(1, &["block_id", "blockId"], false),
        "debug_traceBlockByNumber" => Policy::Block(0, &["block"], true),
        "debug_traceBlockByHash" => Policy::Block(0, &["block"], false),
        "eth_getBlockAccessListByBlockHash" => Policy::Block(0, &["hash"], false),
        "eth_getBlockAccessListByBlockNumber" => Policy::Block(0, &["number"], true),
        "eth_getBlockAccessList" => Policy::Block(0, &["block_id", "blockId"], false),
        "eth_getBlockAccessListRaw" | "debug_getRawBlockAccessList" => {
            Policy::Block(0, &["block", "block_id", "blockId"], false)
        }
        "debug_executionWitnessByBlockHash" => Policy::Block(0, &["hash"], false),
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
        | "tempo_fundAddress"
        | "tempo_forkSchedule"
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
        | "debug_standardTraceBlockToFile"
        | "debug_storageRangeAt"
        | "debug_standardTraceBadBlockToFile"
        | "debug_stateRootWithUpdates"
        | "reth_getBalanceChangesInBlock"
        | "reth_jit"
        | "ots_getApiLevel"
        | "ots_getHeaderByNumber"
        | "erigon_getHeaderByNumber"
        | "ots_hasCode"
        | "ots_getBlockDetails"
        | "ots_getBlockDetailsByHash"
        | "ots_getBlockTransactions"
        | "ots_getTransactionBySenderAndNonce"
        // Unimplemented in the pinned native backend.
        | "ots_searchTransactionsBefore"
        | "ots_searchTransactionsAfter" => Policy::Native,
        _ if [
            "net_",
            "web3_",
            "rpc_",
            "txpool_",
            "admin_",
            "miner_",
            "operator_",
            "consensus_",
            "token_",
        ]
        .iter()
        .any(|prefix| method.starts_with(prefix)) =>
        {
            Policy::Native
        }
        // Unknown methods may execute blocks, e.g. `testing_buildBlockV1`.
        _ => Policy::Execution,
    }
}

/// Whether a method is routed or rejected rather than left native.
pub fn is_execution_method(method: &str) -> bool {
    !matches!(policy(method), Policy::Native | Policy::TraceChain)
}
