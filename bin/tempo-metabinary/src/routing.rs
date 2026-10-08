use std::{collections::HashSet, sync::Arc};

use jsonrpsee::{
    core::{
        RpcResult,
        client::{ClientT, Error as ClientError},
        traits::ToRpcParams,
    },
    http_client::HttpClient,
    types::ErrorObjectOwned,
};
use serde::Deserialize;
use serde_json::{Value, json, value::RawValue};

use crate::manifest::Manifest;

/// This describes the actual private transport's registered methods, not a global RPC catalogue.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionInfo {
    pub protocol_version: u64,
    pub chain_id: String,
    pub genesis_hash: String,
    pub read_only: bool,
    pub process_id: u32,
    pub methods: Vec<String>,
}

impl ExecutionInfo {
    pub fn validate(&self, manifest: &Manifest, read_only: bool) -> eyre::Result<()> {
        eyre::ensure!(self.protocol_version == 1, "unsupported worker protocol");
        eyre::ensure!(
            self.chain_id.eq_ignore_ascii_case(&manifest.chain_id),
            "worker chain ID mismatch"
        );
        eyre::ensure!(
            self.genesis_hash
                .eq_ignore_ascii_case(&manifest.genesis_hash),
            "worker genesis mismatch"
        );
        eyre::ensure!(
            self.read_only == read_only,
            "worker read-only mode mismatch"
        );
        eyre::ensure!(
            self.methods.len() <= 1024,
            "worker reports too many RPC methods"
        );
        eyre::ensure!(
            self.methods.iter().all(|m| m.len() <= 256),
            "worker method name too long"
        );
        Ok(())
    }
}

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

/// Resolve identifiers through the writer. Workers only receive pinned historical identifiers.
pub struct Router {
    manifest: Arc<Manifest>,
    clients: Vec<HttpClient>,
    methods: Vec<Option<HashSet<String>>>,
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
                metadata.validate(&manifest, index != live)?;
            }
        }
        Ok(Self {
            manifest,
            clients,
            methods: info
                .into_iter()
                .map(|i| i.map(|i| i.methods.into_iter().collect()))
                .collect(),
        })
    }

    pub fn live_methods(&self) -> &HashSet<String> {
        self.methods
            .last()
            .and_then(Option::as_ref)
            .expect("validated live worker")
    }
    fn live_index(&self) -> usize {
        self.clients.len() - 1
    }
    fn live(&self) -> &HttpClient {
        &self.clients[self.live_index()]
    }
    fn era(&self, timestamp: u64) -> usize {
        self.manifest.era_for_timestamp(timestamp)
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
        let value = if let Some(hash) = hash {
            self.live()
                .request("eth_getBlockByHash", (hash, false))
                .await
        } else {
            let number = selector.get("blockNumber").unwrap_or(selector);
            self.live()
                .request("eth_getBlockByNumber", (number, false))
                .await
        }
        .map_err(upstream_error)?;
        Block::parse(value)
    }

    async fn forward(&self, era: usize, method: &str, params: RpcParams) -> RpcResult<Value> {
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
    }

    pub async fn call(&self, method: &str, mut params: RpcParams) -> RpcResult<Value> {
        if !params.0.is_null() && !params.0.is_array() && !params.0.is_object() {
            return Err(invalid("params must be an array or an object"));
        }
        let live = self.live_index();
        let era = match method {
            "eth_simulateV1" | "tempo_simulateV1" => self.simulation(method, &mut params).await?,
            "eth_callMany" | "debug_traceCallMany" => self.bundles(method, &mut params).await?,
            "trace_filter" => self.filter(&mut params).await?,
            "debug_traceBlock" => {
                return Err(unsupported(
                    "raw-block tracing is unsupported; use debug_traceBlockByHash or debug_traceBlockByNumber",
                ));
            }
            "debug_traceTransaction"
            | "trace_transaction"
            | "trace_get"
            | "trace_replayTransaction"
            | "trace_transactionOpcodeGas" => {
                let hash = params
                    .get(0, &["tx_hash", "txHash", "hash", "transaction"])
                    .ok_or_else(|| invalid("missing transaction hash"))?;
                let tx: Value = self
                    .live()
                    .request("eth_getTransactionByHash", (hash,))
                    .await
                    .map_err(upstream_error)?;
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
        self.forward(era, method, params).await
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
        let chain_id = quantity(&json!(self.manifest.chain_id))?;
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
            | "eth_sign"
            | "eth_signTransaction"
            | "eth_signTypedData"
            | "eth_fillTransaction"
            | "eth_getProof"
            | "eth_getMultiProof"
            | "eth_getAccountInfo"
            | "eth_getBlockAccessListByBlockHash"
            | "eth_getBlockAccessListByBlockNumber"
            | "eth_getBlockAccessList"
            | "eth_getBlockAccessListRaw"
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
            | "debug_getRawHeader"
            | "debug_getRawBlock"
            | "debug_getRawTransaction"
            | "debug_getRawTransactions"
            | "debug_getRawBlockAccessList"
            | "debug_getRawReceipts"
            | "debug_getBadBlocks"
            | "debug_codeByHash"
            | "debug_accountRange"
            | "debug_getModifiedAccountsByNumber"
            | "debug_getModifiedAccountsByHash"
            | "debug_stateRootWithUpdates"
    )
}
