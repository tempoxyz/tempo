//! Redacted RPC method handlers.
//!
//! Each handler calls the underlying EthApi via the [`ZoneRpcApi`] trait,
//! which performs typed privacy redactions internally before serialization.

use alloy_primitives::{Address, B256, Bytes, keccak256};
use alloy_rpc_types_eth::{BlockId, BlockNumberOrTag, Filter, FilterId, state::StateOverride};
use serde_json::{Value, value::RawValue};
use tempo_alloy::rpc::TempoTransactionRequest;
use tempo_contracts::precompiles::account_keychain::IAccountKeychain::KeyInfo;
use tracing::warn;

use crate::{
    auth::AuthContext,
    subscription::BoxWsSubscriptionFut,
    types::{BoxEyreFut, BoxFut, JsonRpcError, JsonRpcRequest, JsonRpcResponse, Method},
};

/// Interface to the underlying reth EthApi for the redacted zone RPC.
///
/// Implementations are responsible for:
/// - **Access control**: restricting responses based on the [`AuthContext`]
///   (e.g. returning `null` for transactions not owned by the caller).
/// - **Redaction**: scrubbing privacy-sensitive fields (e.g. zeroing
///   `logsBloom`, clearing transaction lists) on typed responses *before*
///   serializing to JSON.
pub trait ZoneRpcApi: Send + Sync + 'static {
    /// `AccountKeychain.getKey(account, keyId)` — returns the current keychain
    /// authorization for a recovered access key.
    fn get_keychain_key(&self, account: Address, key_id: Address) -> BoxEyreFut<'_, KeyInfo>;

    /// `eth_blockNumber` — returns the latest block number.
    fn block_number(&self) -> BoxFut<'_>;

    /// `eth_chainId` — returns the chain ID.
    fn chain_id(&self) -> BoxFut<'_>;

    /// `net_version` — returns the network ID as a decimal string.
    fn net_version(&self) -> BoxFut<'_>;

    /// `web3_clientVersion` — returns the native node client version.
    fn client_version(&self) -> BoxFut<'_>;

    /// `eth_syncing` — returns sync status from the upstream node.
    fn syncing(&self) -> BoxFut<'_>;

    /// `eth_coinbase` — returns the configured block beneficiary address.
    fn coinbase(&self) -> BoxFut<'_>;

    /// `eth_gasPrice` — returns the current gas price.
    fn gas_price(&self) -> BoxFut<'_>;

    /// `eth_maxPriorityFeePerGas` — returns the current max priority fee.
    fn max_priority_fee_per_gas(&self) -> BoxFut<'_>;

    /// `eth_feeHistory(blockCount, newestBlock, rewardPercentiles)` — returns fee history.
    fn fee_history(
        &self,
        block_count: u64,
        newest_block: BlockNumberOrTag,
        reward_percentiles: Option<Vec<f64>>,
    ) -> BoxFut<'_>;

    /// `eth_getBalance(address, block)` — returns the balance of an account.
    ///
    /// Returns `0x0` when querying an address that does not match `auth.caller`.
    fn get_balance(
        &self,
        address: Address,
        block: Option<BlockId>,
        auth: AuthContext,
    ) -> BoxFut<'_>;

    /// `eth_getTransactionCount(address, block)` — returns the nonce.
    ///
    /// Returns `0x0` when querying an address that does not match `auth.caller`.
    fn get_transaction_count(
        &self,
        address: Address,
        block: Option<BlockId>,
        auth: AuthContext,
    ) -> BoxFut<'_>;

    /// `eth_getBlockByNumber(number, full)` — returns a block by number.
    fn block_by_number(
        &self,
        number: BlockNumberOrTag,
        full: bool,
        auth: AuthContext,
    ) -> BoxFut<'_>;

    /// `eth_getBlockByHash(hash, full)` — returns a block by hash.
    fn block_by_hash(&self, hash: B256, full: bool, auth: AuthContext) -> BoxFut<'_>;

    /// `eth_getTransactionByHash(hash)` — returns a transaction by hash.
    fn transaction_by_hash(&self, hash: B256, auth: AuthContext) -> BoxFut<'_>;

    /// `eth_getTransactionReceipt(hash)` — returns a transaction receipt.
    fn transaction_receipt(&self, hash: B256, auth: AuthContext) -> BoxFut<'_>;

    /// `eth_call(request, block, state_override)` — executes a call without
    /// creating a transaction.
    ///
    /// Enforces that `from` equals the authenticated account (sets it if omitted,
    /// rejects with `-32004` on mismatch). State/block overrides are rejected
    /// with `-32602`.
    fn call(
        &self,
        request: TempoTransactionRequest,
        block: Option<BlockId>,
        state_override: Option<StateOverride>,
        auth: AuthContext,
    ) -> BoxFut<'_>;

    /// `eth_estimateGas(request, block, state_override)` — estimates gas for a transaction.
    ///
    /// Same `from`-enforcement as [`call`](Self::call). State overrides are
    /// rejected with `-32602`.
    fn estimate_gas(
        &self,
        request: TempoTransactionRequest,
        block: Option<BlockId>,
        state_override: Option<StateOverride>,
        auth: AuthContext,
    ) -> BoxFut<'_>;

    /// `eth_sendRawTransaction(data)` — submits a signed transaction to the pool.
    ///
    /// Verifies that the recovered tx sender matches the authenticated account;
    /// rejects with `-32003` on mismatch.
    fn send_raw_transaction(&self, data: Bytes, auth: AuthContext) -> BoxFut<'_>;

    /// `eth_sendRawTransactionSync(data)` — submits a signed transaction and
    /// waits for inclusion, returning the receipt.
    ///
    /// Same sender verification as [`send_raw_transaction`](Self::send_raw_transaction).
    fn send_raw_transaction_sync(&self, data: Bytes, auth: AuthContext) -> BoxFut<'_>;

    /// `eth_fillTransaction(request)` — fills defaults on an unsigned transaction
    /// (nonce, gas limit, fees, chain ID) and returns the filled + RLP-encoded
    /// result without signing or submitting.
    ///
    /// Same `from`-enforcement as [`call`](Self::call).
    fn fill_transaction(&self, request: TempoTransactionRequest, auth: AuthContext) -> BoxFut<'_>;

    /// `eth_getLogs(filter)` — returns logs matching the filter, scoped to the caller.
    fn get_logs(&self, filter: Filter, auth: AuthContext) -> BoxFut<'_>;

    /// `eth_newFilter(filter)` — creates a new log filter, scoped to the caller.
    fn new_filter(&self, filter: Filter, auth: AuthContext) -> BoxFut<'_>;

    /// `eth_getFilterLogs(id)` — returns all logs for a filter.
    fn get_filter_logs(&self, id: FilterId, auth: AuthContext) -> BoxFut<'_>;

    /// `eth_getFilterChanges(id)` — returns new logs since last poll.
    fn get_filter_changes(&self, id: FilterId, auth: AuthContext) -> BoxFut<'_>;

    /// `eth_newBlockFilter` — creates a new block filter.
    fn new_block_filter(&self, auth: AuthContext) -> BoxFut<'_>;

    /// `eth_uninstallFilter(id)` — removes a filter.
    fn uninstall_filter(&self, id: FilterId, auth: AuthContext) -> BoxFut<'_>;

    /// `eth_subscribe("newHeads")` — opens a stream of new block headers.
    fn ws_subscribe_new_heads(&self, _auth: AuthContext) -> BoxWsSubscriptionFut<'_> {
        Box::pin(async { Err(JsonRpcError::method_disabled()) })
    }

    /// `eth_subscribe("logs", filter)` — opens a stream of matching logs.
    fn ws_subscribe_logs(&self, _filter: Filter, _auth: AuthContext) -> BoxWsSubscriptionFut<'_> {
        Box::pin(async { Err(JsonRpcError::method_disabled()) })
    }

    /// `zone_getAuthorizationTokenInfo()` — returns the authenticated account
    /// and token expiry.
    fn zone_get_authorization_token_info(&self, auth: AuthContext) -> BoxFut<'_>;

    /// `zone_getZoneInfo()` — returns zone metadata.
    fn zone_get_zone_info(&self, auth: AuthContext) -> BoxFut<'_>;

    /// `zone_getEncryptionKey()` — returns the active encryption key at the
    /// current Tempo L1 head.
    fn zone_get_encryption_key(&self, auth: AuthContext) -> BoxFut<'_>;
}

/// Deserialize JSON-RPC params, returning an error response on failure.
#[allow(clippy::result_large_err)]
fn parse_params<T: serde::de::DeserializeOwned>(
    raw: &str,
    id: &Value,
    msg: &'static str,
) -> Result<T, JsonRpcResponse> {
    serde_json::from_str(raw)
        .map_err(|_| JsonRpcResponse::error(id.clone(), JsonRpcError::invalid_params(msg)))
}

/// Params for `eth_call` / `eth_estimateGas`: `[request, block?, stateOverride?]`.
///
/// Supports 1–3 element arrays with null-as-absent semantics for trailing optionals.
struct CallParams(
    TempoTransactionRequest,
    Option<BlockId>,
    Option<StateOverride>,
);

impl<'de> serde::Deserialize<'de> for CallParams {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Vis;
        impl<'de> serde::de::Visitor<'de> for Vis {
            type Value = CallParams;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("[request, block?, stateOverride?]")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let request = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let block = seq.next_element::<Option<BlockId>>()?.flatten();
                let state_override = seq.next_element::<Option<StateOverride>>()?.flatten();
                Ok(CallParams(request, block, state_override))
            }
        }
        deserializer.deserialize_seq(Vis)
    }
}

/// Convert an API result into a JSON-RPC response, logging failures.
fn api_result(
    id: Value,
    method: Method,
    res: Result<Box<RawValue>, JsonRpcError>,
) -> JsonRpcResponse {
    match res {
        Ok(v) => JsonRpcResponse::success(id, v),
        Err(e) => {
            warn!(target: "zone::rpc", err = %e, method = method.name(), "RPC call failed");
            JsonRpcResponse::error(id, e)
        }
    }
}

/// Dispatch a single JSON-RPC request through the redacted zone RPC pipeline.
///
/// Enforces the strict allowlist in the typed method registry. Individual handlers may apply
/// additional per-method access checks.
pub async fn dispatch(
    req: &JsonRpcRequest,
    auth: &AuthContext,
    api: &dyn ZoneRpcApi,
) -> JsonRpcResponse {
    let id = req.id.clone();

    let method = match Method::from_name(&req.method) {
        Some(method) => method,
        None => return JsonRpcResponse::error(id, JsonRpcError::method_not_found()),
    };

    // Raw params JSON — handlers deserialize directly, no intermediate Vec<Value>.
    let raw = req.params.as_deref().map(|p| p.get()).unwrap_or("[]");

    match method {
        // Simple passthrough methods (no params, no auth scoping)
        Method::EthBlockNumber => api_result(id, method, api.block_number().await),
        Method::EthChainId => api_result(id, method, api.chain_id().await),
        Method::EthGasPrice => api_result(id, method, api.gas_price().await),
        Method::EthMaxPriorityFeePerGas => {
            api_result(id, method, api.max_priority_fee_per_gas().await)
        }
        Method::NetVersion => api_result(id, method, api.net_version().await),
        Method::NetListening => api_result(id, method, crate::types::to_raw(&true)),
        Method::EthSyncing => api_result(id, method, api.syncing().await),
        Method::EthCoinbase => api_result(id, method, api.coinbase().await),
        Method::Web3Sha3 => handle_web3_sha3(id, raw).await,
        Method::Web3ClientVersion => api_result(id, method, api.client_version().await),

        // Fee history
        Method::EthFeeHistory => handle_fee_history(id, raw, api).await,

        // Scoped state queries
        Method::EthGetBalance => handle_get_balance(id, raw, auth, api).await,
        Method::EthGetTransactionCount => handle_get_transaction_count(id, raw, auth, api).await,

        // Block queries
        Method::EthGetBlockByNumber => handle_get_block_by_number(id, raw, auth, api).await,
        Method::EthGetBlockByHash => handle_get_block_by_hash(id, raw, auth, api).await,

        // Transaction queries
        Method::EthGetTransactionByHash => handle_get_transaction_by_hash(id, raw, auth, api).await,
        Method::EthGetTransactionReceipt => {
            handle_get_transaction_receipt(id, raw, auth, api).await
        }

        // Simulation
        Method::EthCall => handle_call(id, raw, auth, api).await,
        Method::EthEstimateGas => handle_estimate_gas(id, raw, auth, api).await,

        // Transaction preparation & submission
        Method::EthFillTransaction => handle_fill_transaction(id, raw, auth, api).await,
        Method::EthSendRawTransaction => handle_send_raw_transaction(id, raw, auth, api).await,
        Method::EthSendRawTransactionSync => {
            handle_send_raw_transaction_sync(id, raw, auth, api).await
        }

        // Log & filter queries
        Method::EthGetLogs => handle_get_logs(id, raw, auth, api).await,
        Method::EthNewFilter => handle_new_filter(id, raw, auth, api).await,
        Method::EthGetFilterLogs => handle_get_filter_logs(id, raw, auth, api).await,
        Method::EthGetFilterChanges => handle_get_filter_changes(id, raw, auth, api).await,
        Method::EthNewBlockFilter => handle_new_block_filter(id, auth, api).await,
        Method::EthUninstallFilter => handle_uninstall_filter(id, raw, auth, api).await,
        Method::ZoneGetAuthorizationTokenInfo => api_result(
            id,
            method,
            api.zone_get_authorization_token_info(auth.clone()).await,
        ),
        Method::ZoneGetZoneInfo => {
            api_result(id, method, api.zone_get_zone_info(auth.clone()).await)
        }
        Method::ZoneGetEncryptionKey => {
            api_result(id, method, api.zone_get_encryption_key(auth.clone()).await)
        }
    }
}

/// Handle `web3_sha3(data)` locally.
async fn handle_web3_sha3(id: Value, raw: &str) -> JsonRpcResponse {
    let (data,) = match parse_params::<(Bytes,)>(raw, &id, "expected [data]") {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    api_result(id, Method::Web3Sha3, crate::types::to_raw(&keccak256(data)))
}

/// Handle `eth_getBlockByNumber`. Rejects `full=true` on the redacted RPC.
async fn handle_get_block_by_number(
    id: Value,
    raw: &str,
    auth: &AuthContext,
    api: &dyn ZoneRpcApi,
) -> JsonRpcResponse {
    let (number, full) = match parse_params::<(BlockNumberOrTag, bool)>(
        raw,
        &id,
        "expected [blockNumberOrTag, full]",
    ) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let number = normalize_block_number(number);

    if full {
        return JsonRpcResponse::error(id, JsonRpcError::sequencer_only());
    }

    api_result(
        id,
        Method::EthGetBlockByNumber,
        api.block_by_number(number, full, auth.clone()).await,
    )
}

/// Handle `eth_getBlockByHash`. Rejects `full=true`.
async fn handle_get_block_by_hash(
    id: Value,
    raw: &str,
    auth: &AuthContext,
    api: &dyn ZoneRpcApi,
) -> JsonRpcResponse {
    let (hash, full) = match parse_params::<(B256, bool)>(raw, &id, "expected [blockHash, full]") {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    if full {
        return JsonRpcResponse::error(id, JsonRpcError::sequencer_only());
    }

    api_result(
        id,
        Method::EthGetBlockByHash,
        api.block_by_hash(hash, full, auth.clone()).await,
    )
}

/// Handle `eth_getTransactionByHash`. Access control is delegated to the API impl.
async fn handle_get_transaction_by_hash(
    id: Value,
    raw: &str,
    auth: &AuthContext,
    api: &dyn ZoneRpcApi,
) -> JsonRpcResponse {
    let (hash,) = match parse_params::<(B256,)>(raw, &id, "expected [txHash]") {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    api_result(
        id,
        Method::EthGetTransactionByHash,
        api.transaction_by_hash(hash, auth.clone()).await,
    )
}

/// Handle `eth_getTransactionReceipt`. Access control is delegated to the API impl.
async fn handle_get_transaction_receipt(
    id: Value,
    raw: &str,
    auth: &AuthContext,
    api: &dyn ZoneRpcApi,
) -> JsonRpcResponse {
    let (hash,) = match parse_params::<(B256,)>(raw, &id, "expected [txHash]") {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    api_result(
        id,
        Method::EthGetTransactionReceipt,
        api.transaction_receipt(hash, auth.clone()).await,
    )
}

/// Handle `eth_call`. Enforces `from` matches the authenticated account and
/// rejects state overrides.
async fn handle_call(
    id: Value,
    raw: &str,
    auth: &AuthContext,
    api: &dyn ZoneRpcApi,
) -> JsonRpcResponse {
    let CallParams(request, block, state_override) =
        match parse_params(raw, &id, "expected [request, block?, stateOverride?]") {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    if state_override.is_some() {
        return JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_params("state overrides not allowed"),
        );
    }

    let block = block.map(normalize_block_id);

    api_result(
        id,
        Method::EthCall,
        api.call(request, block, state_override, auth.clone()).await,
    )
}

/// Handle `eth_estimateGas`. Same `from`-enforcement as `eth_call`.
/// Rejects state overrides.
async fn handle_estimate_gas(
    id: Value,
    raw: &str,
    auth: &AuthContext,
    api: &dyn ZoneRpcApi,
) -> JsonRpcResponse {
    let CallParams(request, block, state_override) =
        match parse_params(raw, &id, "expected [request, block?, stateOverride?]") {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    if state_override.is_some() {
        return JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_params("state overrides not allowed"),
        );
    }

    let block = block.map(normalize_block_id);

    api_result(
        id,
        Method::EthEstimateGas,
        api.estimate_gas(request, block, state_override, auth.clone())
            .await,
    )
}

/// Handle `eth_fillTransaction`. `from`-enforcement is delegated to the API impl.
async fn handle_fill_transaction(
    id: Value,
    raw: &str,
    auth: &AuthContext,
    api: &dyn ZoneRpcApi,
) -> JsonRpcResponse {
    let (request,) =
        match parse_params::<(TempoTransactionRequest,)>(raw, &id, "expected [request]") {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    api_result(
        id,
        Method::EthFillTransaction,
        api.fill_transaction(request, auth.clone()).await,
    )
}

/// Handle `eth_sendRawTransaction`. Sender verification is delegated to the API impl.
async fn handle_send_raw_transaction(
    id: Value,
    raw: &str,
    auth: &AuthContext,
    api: &dyn ZoneRpcApi,
) -> JsonRpcResponse {
    let (data,) = match parse_params::<(Bytes,)>(raw, &id, "expected [data]") {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    api_result(
        id,
        Method::EthSendRawTransaction,
        api.send_raw_transaction(data, auth.clone()).await,
    )
}

/// Handle `eth_sendRawTransactionSync`. Sender verification is delegated to
/// the API impl.
async fn handle_send_raw_transaction_sync(
    id: Value,
    raw: &str,
    auth: &AuthContext,
    api: &dyn ZoneRpcApi,
) -> JsonRpcResponse {
    let (data,) = match parse_params::<(Bytes,)>(raw, &id, "expected [data]") {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    api_result(
        id,
        Method::EthSendRawTransactionSync,
        api.send_raw_transaction_sync(data, auth.clone()).await,
    )
}

/// Handle `eth_feeHistory`. Public method, no auth scoping needed.
async fn handle_fee_history(id: Value, raw: &str, api: &dyn ZoneRpcApi) -> JsonRpcResponse {
    let (block_count, newest_block, reward_percentiles) =
        match parse_params::<(u64, BlockNumberOrTag, Option<Vec<f64>>)>(
            raw,
            &id,
            "expected [blockCount, newestBlock, rewardPercentiles?]",
        ) {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    api_result(
        id,
        Method::EthFeeHistory,
        api.fee_history(block_count, newest_block, reward_percentiles)
            .await,
    )
}

/// Handle `eth_getBalance`. Returns `0x0` when querying a different address
/// (checked in API impl, no timing leak since check is pre-fetch).
async fn handle_get_balance(
    id: Value,
    raw: &str,
    auth: &AuthContext,
    api: &dyn ZoneRpcApi,
) -> JsonRpcResponse {
    let (address, block) =
        match parse_params::<(Address, Option<BlockId>)>(raw, &id, "expected [address, block?]") {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    api_result(
        id,
        Method::EthGetBalance,
        api.get_balance(address, block, auth.clone()).await,
    )
}

/// Handle `eth_getTransactionCount`. Returns `0x0` when querying a different address
/// (checked in API impl, no timing leak).
async fn handle_get_transaction_count(
    id: Value,
    raw: &str,
    auth: &AuthContext,
    api: &dyn ZoneRpcApi,
) -> JsonRpcResponse {
    let (address, block) =
        match parse_params::<(Address, Option<BlockId>)>(raw, &id, "expected [address, block?]") {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    api_result(
        id,
        Method::EthGetTransactionCount,
        api.get_transaction_count(address, block, auth.clone())
            .await,
    )
}

/// Handle `eth_getLogs`.
async fn handle_get_logs(
    id: Value,
    raw: &str,
    auth: &AuthContext,
    api: &dyn ZoneRpcApi,
) -> JsonRpcResponse {
    let (filter,) = match parse_params::<(Filter,)>(raw, &id, "expected [filter]") {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    api_result(
        id,
        Method::EthGetLogs,
        api.get_logs(filter, auth.clone()).await,
    )
}

/// Handle `eth_newFilter`.
async fn handle_new_filter(
    id: Value,
    raw: &str,
    auth: &AuthContext,
    api: &dyn ZoneRpcApi,
) -> JsonRpcResponse {
    let (filter,) = match parse_params::<(Filter,)>(raw, &id, "expected [filter]") {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    api_result(
        id,
        Method::EthNewFilter,
        api.new_filter(filter, auth.clone()).await,
    )
}

/// Handle `eth_getFilterLogs`.
async fn handle_get_filter_logs(
    id: Value,
    raw: &str,
    auth: &AuthContext,
    api: &dyn ZoneRpcApi,
) -> JsonRpcResponse {
    let (filter_id,) = match parse_params::<(FilterId,)>(raw, &id, "expected [filterId]") {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    api_result(
        id,
        Method::EthGetFilterLogs,
        api.get_filter_logs(filter_id, auth.clone()).await,
    )
}

/// Handle `eth_getFilterChanges`.
async fn handle_get_filter_changes(
    id: Value,
    raw: &str,
    auth: &AuthContext,
    api: &dyn ZoneRpcApi,
) -> JsonRpcResponse {
    let (filter_id,) = match parse_params::<(FilterId,)>(raw, &id, "expected [filterId]") {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    api_result(
        id,
        Method::EthGetFilterChanges,
        api.get_filter_changes(filter_id, auth.clone()).await,
    )
}

/// Handle `eth_newBlockFilter`.
async fn handle_new_block_filter(
    id: Value,
    auth: &AuthContext,
    api: &dyn ZoneRpcApi,
) -> JsonRpcResponse {
    api_result(
        id,
        Method::EthNewBlockFilter,
        api.new_block_filter(auth.clone()).await,
    )
}

/// Handle `eth_uninstallFilter`.
async fn handle_uninstall_filter(
    id: Value,
    raw: &str,
    auth: &AuthContext,
    api: &dyn ZoneRpcApi,
) -> JsonRpcResponse {
    let (filter_id,) = match parse_params::<(FilterId,)>(raw, &id, "expected [filterId]") {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    api_result(
        id,
        Method::EthUninstallFilter,
        api.uninstall_filter(filter_id, auth.clone()).await,
    )
}

/// Zones do not have a real pending block, so treat `pending` as `latest`.
fn normalize_block_number(number: BlockNumberOrTag) -> BlockNumberOrTag {
    if number.is_pending() {
        BlockNumberOrTag::Latest
    } else {
        number
    }
}

/// Applies [`normalize_block_number`] to a block id. Without it `pending` resolves to a block
/// the engine has executed but not yet made canonical.
fn normalize_block_id(block: BlockId) -> BlockId {
    match block {
        BlockId::Number(number) => BlockId::Number(normalize_block_number(number)),
        hash @ BlockId::Hash(_) => hash,
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::Address;
    use serde_json::json;

    use super::*;
    use crate::types::to_raw;

    #[derive(Default)]
    struct MockZoneRpcApi;

    macro_rules! stub {
        ($method:ident $(, $arg:ident : $ty:ty)*) => {
            fn $method(&self $(, $arg: $ty)*) -> BoxFut<'_> {
                Box::pin(async { Err(JsonRpcError::internal("not implemented")) })
            }
        };
    }

    impl ZoneRpcApi for MockZoneRpcApi {
        fn get_keychain_key(&self, _account: Address, _key_id: Address) -> BoxEyreFut<'_, KeyInfo> {
            Box::pin(async { Err(eyre::eyre!("not implemented")) })
        }

        stub!(block_number);
        stub!(chain_id);
        stub!(net_version);
        fn client_version(&self) -> BoxFut<'_> {
            Box::pin(async { to_raw(&"tempo-zone/vtest/test-target") })
        }
        stub!(gas_price);
        stub!(max_priority_fee_per_gas);
        stub!(fee_history, _block_count: u64, _newest_block: BlockNumberOrTag, _reward_percentiles: Option<Vec<f64>>);
        stub!(get_balance, _address: Address, _block: Option<BlockId>, _auth: AuthContext);
        stub!(get_transaction_count, _address: Address, _block: Option<BlockId>, _auth: AuthContext);
        stub!(block_by_number, _number: BlockNumberOrTag, _full: bool, _auth: AuthContext);
        stub!(block_by_hash, _hash: B256, _full: bool, _auth: AuthContext);
        stub!(transaction_by_hash, _hash: B256, _auth: AuthContext);
        stub!(transaction_receipt, _hash: B256, _auth: AuthContext);
        fn call(
            &self,
            _request: TempoTransactionRequest,
            block: Option<BlockId>,
            _state_override: Option<StateOverride>,
            _auth: AuthContext,
        ) -> BoxFut<'_> {
            Box::pin(async move { to_raw(&block) })
        }
        fn estimate_gas(
            &self,
            _request: TempoTransactionRequest,
            block: Option<BlockId>,
            _state_override: Option<StateOverride>,
            _auth: AuthContext,
        ) -> BoxFut<'_> {
            Box::pin(async move { to_raw(&block) })
        }
        stub!(send_raw_transaction, _data: Bytes, _auth: AuthContext);
        stub!(send_raw_transaction_sync, _data: Bytes, _auth: AuthContext);
        stub!(fill_transaction, _request: TempoTransactionRequest, _auth: AuthContext);
        stub!(get_logs, _filter: Filter, _auth: AuthContext);
        stub!(new_filter, _filter: Filter, _auth: AuthContext);
        stub!(get_filter_logs, _id: FilterId, _auth: AuthContext);
        stub!(get_filter_changes, _id: FilterId, _auth: AuthContext);
        stub!(new_block_filter, _auth: AuthContext);
        stub!(uninstall_filter, _id: FilterId, _auth: AuthContext);
        fn zone_get_authorization_token_info(&self, auth: AuthContext) -> BoxFut<'_> {
            Box::pin(async move {
                to_raw(&json!({
                    "account": auth.caller,
                    "expiresAt": alloy_primitives::U64::from(auth.expires_at),
                }))
            })
        }

        fn syncing(&self) -> BoxFut<'_> {
            Box::pin(async move { to_raw(&false) })
        }

        fn coinbase(&self) -> BoxFut<'_> {
            Box::pin(async move { to_raw(&Address::repeat_byte(0xbb)) })
        }

        fn zone_get_zone_info(&self, _auth: AuthContext) -> BoxFut<'_> {
            Box::pin(async move {
                to_raw(&json!({
                    "zoneId": "0x1",
                    "zoneTokens": [format!("{:#x}", Address::repeat_byte(0x11))],
                    "sequencers": [format!("{:#x}", Address::repeat_byte(0x22))],
                    "chainId": "0x2a",
                    "tempoBlockNumber": "0x7",
                }))
            })
        }

        stub!(zone_get_encryption_key, _auth: AuthContext);
    }

    fn auth() -> AuthContext {
        AuthContext {
            caller: Address::repeat_byte(0xaa),
            expires_at: 1_700_000_000,
            keychain_key_id: None,
        }
    }

    fn request(method: &str, params: serde_json::Value) -> JsonRpcRequest {
        serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        }))
        .expect("request should deserialize")
    }

    #[tokio::test]
    async fn redacted_rpc_excludes_operator_sequencer_methods() {
        let api = MockZoneRpcApi::default();
        let excluded = dispatch(&request("zone_setLeader", json!([])), &auth(), &api).await;
        assert_eq!(excluded.error.unwrap().code, -32601);

        let excluded = dispatch(&request("zone_getSequencerInfo", json!([])), &auth(), &api).await;
        assert_eq!(excluded.error.unwrap().code, -32601);
    }

    #[tokio::test]
    async fn dispatches_zone_get_authorization_token_info() {
        let api = MockZoneRpcApi::default();
        let resp = dispatch(
            &request("zone_getAuthorizationTokenInfo", json!([])),
            &auth(),
            &api,
        )
        .await;

        assert!(resp.error.is_none());
        let body: serde_json::Value =
            serde_json::from_str(resp.result.as_ref().unwrap().get()).unwrap();
        assert_eq!(
            body["account"].as_str().unwrap(),
            format!("{:#x}", Address::repeat_byte(0xaa)),
        );
        assert_eq!(body["expiresAt"], "0x6553f100");
    }

    #[tokio::test]
    async fn dispatches_allowed_compatibility_methods() {
        let api = MockZoneRpcApi::default();

        let syncing = dispatch(&request("eth_syncing", json!([])), &auth(), &api).await;
        assert_eq!(
            serde_json::from_str::<Value>(syncing.result.as_ref().unwrap().get()).unwrap(),
            false
        );

        let coinbase = dispatch(&request("eth_coinbase", json!([])), &auth(), &api).await;
        assert_eq!(
            serde_json::from_str::<Value>(coinbase.result.as_ref().unwrap().get()).unwrap(),
            format!("{:#x}", Address::repeat_byte(0xbb))
        );

        let sha3 = dispatch(
            &request("web3_sha3", json!(["0x68656c6c6f"])),
            &auth(),
            &api,
        )
        .await;
        assert_eq!(
            serde_json::from_str::<Value>(sha3.result.as_ref().unwrap().get()).unwrap(),
            "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
        );
    }

    #[tokio::test]
    async fn dispatches_web3_client_version_from_api() {
        let api = MockZoneRpcApi::default();
        let response = dispatch(&request("web3_clientVersion", json!([])), &auth(), &api).await;

        assert_eq!(
            serde_json::from_str::<Value>(response.result.as_ref().unwrap().get()).unwrap(),
            "tempo-zone/vtest/test-target"
        );
    }

    #[tokio::test]
    async fn dispatches_zone_get_zone_info() {
        let api = MockZoneRpcApi::default();
        let resp = dispatch(&request("zone_getZoneInfo", json!([])), &auth(), &api).await;

        assert!(resp.error.is_none());
        let body: serde_json::Value =
            serde_json::from_str(resp.result.as_ref().unwrap().get()).unwrap();
        assert_eq!(body["zoneId"], "0x1");
        assert_eq!(
            body["zoneTokens"][0],
            format!("{:#x}", Address::repeat_byte(0x11))
        );
        assert_eq!(
            body["sequencers"][0],
            format!("{:#x}", Address::repeat_byte(0x22))
        );
        assert_eq!(body["chainId"], "0x2a");
        assert_eq!(body["tempoBlockNumber"], "0x7");
    }

    #[tokio::test]
    async fn does_not_expose_pending_transaction_filter_endpoint() {
        let api = MockZoneRpcApi::default();

        let resp = dispatch(
            &request("eth_newPendingTransactionFilter", json!([])),
            &auth(),
            &api,
        )
        .await;

        assert!(resp.result.is_none());
        assert_eq!(resp.error.as_ref().unwrap().code, -32601);
    }

    #[tokio::test]
    async fn rejects_state_override_for_eth_call() {
        let api = MockZoneRpcApi::default();
        let resp = dispatch(
            &request(
                "eth_call",
                json!([
                    {"to": format!("{:#x}", Address::repeat_byte(0x11)), "data": "0x"},
                    "latest",
                    {}
                ]),
            ),
            &auth(),
            &api,
        )
        .await;

        assert!(resp.result.is_none());
        let err = resp.error.expect("should reject state overrides");
        assert_eq!(err.code, -32602);
        assert_eq!(err.message, "state overrides not allowed");
    }

    #[tokio::test]
    async fn rejects_state_override_for_estimate_gas() {
        let api = MockZoneRpcApi::default();
        let resp = dispatch(
            &request(
                "eth_estimateGas",
                json!([
                    {"to": format!("{:#x}", Address::repeat_byte(0x11)), "data": "0x"},
                    "latest",
                    {}
                ]),
            ),
            &auth(),
            &api,
        )
        .await;

        assert!(resp.result.is_none());
        let err = resp.error.expect("should reject state overrides");
        assert_eq!(err.code, -32602);
        assert_eq!(err.message, "state overrides not allowed");
    }

    #[tokio::test]
    async fn simulations_treat_pending_as_latest() {
        let api = MockZoneRpcApi::default();
        for method in ["eth_call", "eth_estimateGas"] {
            // The mock echoes the block it is asked to run against.
            for (requested, forwarded) in [
                (json!("pending"), json!("latest")),
                (json!("latest"), json!("latest")),
                (json!("0x10"), json!("0x10")),
            ] {
                let resp = dispatch(
                    &request(
                        method,
                        json!([
                            {"to": format!("{:#x}", Address::repeat_byte(0x11)), "data": "0x"},
                            requested,
                        ]),
                    ),
                    &auth(),
                    &api,
                )
                .await;

                let block: serde_json::Value =
                    serde_json::from_str(resp.result.expect("should dispatch").get()).unwrap();
                assert_eq!(block, forwarded, "{method} at {requested}");
            }
        }
    }

    #[tokio::test]
    async fn rejects_extra_block_override_param_for_eth_call() {
        let api = MockZoneRpcApi::default();
        let resp = dispatch(
            &request(
                "eth_call",
                json!([
                    {"to": format!("{:#x}", Address::repeat_byte(0x11)), "data": "0x"},
                    "latest",
                    {},
                    {}
                ]),
            ),
            &auth(),
            &api,
        )
        .await;

        assert!(resp.result.is_none());
        let err = resp.error.expect("should reject extra simulation params");
        assert_eq!(err.code, -32602);
        assert_eq!(err.message, "expected [request, block?, stateOverride?]");
    }
    #[tokio::test]
    async fn registered_methods_are_dispatchable_and_have_bounded_metric_labels() {
        let api = MockZoneRpcApi::default();

        for &method in Method::ALL {
            let name = method.name();
            assert_eq!(Method::from_name(name), Some(method), "method: {name}");
            assert_eq!(Method::metric_label(name), name, "method: {name}");

            if let Some(error) = dispatch(&request(name, json!([])), &auth(), &api)
                .await
                .error
            {
                assert!(
                    ![-32601, -32005, -32006].contains(&error.code),
                    "registered method {name} was rejected by dispatch policy: {error}"
                );
            }
        }
    }

    #[tokio::test]
    async fn unregistered_methods_are_not_found_and_share_the_unknown_metric_label() {
        let api = MockZoneRpcApi::default();

        for name in [
            "eth_getCode",
            "eth_getProof",
            "admin_peers",
            "debug_accountRange",
            "txpool_contentFrom",
            "missing_method",
        ] {
            assert_eq!(Method::from_name(name), None, "method: {name}");
            assert_eq!(Method::metric_label(name), "unknown");
            let error = dispatch(&request(name, json!([])), &auth(), &api)
                .await
                .error
                .expect("method must return an error");
            assert_eq!(error.code, -32601, "method: {name}");
            assert_eq!(error.message, "Method not found", "method: {name}");
        }
    }
}
