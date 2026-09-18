use crate::config::Config;
use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use futures::StreamExt;
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;

type RpcResult<T> = Result<T, Value>;

fn error(code: i64, message: &str) -> Value {
    json!({"code": code, "message": message})
}

fn invalid() -> Value {
    error(-32602, "Invalid params")
}

fn quantity(value: &Value) -> RpcResult<u64> {
    let value = value.as_str().ok_or_else(invalid)?;
    let hex = value.strip_prefix("0x").ok_or_else(invalid)?;
    if hex.is_empty() || (hex.len() > 1 && hex.starts_with('0')) {
        return Err(invalid());
    }
    u64::from_str_radix(hex, 16).map_err(|_| invalid())
}

fn hash(value: &Value) -> RpcResult<&str> {
    let hash = value.as_str().ok_or_else(invalid)?;
    if hash.len() != 66
        || !hash.starts_with("0x")
        || !hash[2..].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(invalid());
    }
    Ok(hash)
}

#[derive(Clone)]
pub(crate) struct Rpc {
    client: reqwest::Client,
    urls: [String; 2],
    cutover: u64,
    parent_hash: String,
    inflight: Arc<Semaphore>,
}

impl Rpc {
    pub(crate) fn new(config: &Config) -> eyre::Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .connect_timeout(Duration::from_secs(3))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            urls: [config.v1.rpc.clone(), config.v2.rpc.clone()],
            cutover: config.cutover_block,
            parent_hash: config.parent_hash.clone(),
            inflight: Arc::new(Semaphore::new(64)),
        })
    }

    /// Do not retry writes or fail over execution to a different protocol version.
    async fn call(&self, backend: usize, method: &str, params: Value) -> RpcResult<Value> {
        let response = self
            .client
            .post(&self.urls[backend])
            .json(&json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params}))
            .send()
            .await
            .map_err(|_| error(-32002, "Tempo backend unavailable"))?
            .error_for_status()
            .map_err(|_| error(-32002, "Tempo backend HTTP error"))?;
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| error(-32002, "Tempo backend response failed"))?;
            if bytes.len() + chunk.len() > 32 * 1024 * 1024 {
                return Err(error(-32005, "Tempo backend response exceeds 32 MiB"));
            }
            bytes.extend_from_slice(&chunk);
        }
        let response: Value = serde_json::from_slice(&bytes)
            .map_err(|_| error(-32603, "Invalid Tempo backend response"))?;
        if response.get("jsonrpc") != Some(&json!("2.0")) || response.get("id") != Some(&json!(1)) {
            return Err(error(-32603, "Invalid Tempo backend envelope"));
        }
        match (response.get("result"), response.get("error")) {
            (Some(result), None) => Ok(result.clone()),
            (None, Some(err)) if err["code"].is_i64() && err["message"].is_string() => {
                Err(err.clone())
            }
            _ => Err(error(-32603, "Invalid Tempo backend result")),
        }
    }

    pub(crate) async fn wait_ready(&self) -> eyre::Result<()> {
        loop {
            let (v1, v2) = tokio::join!(
                self.call(0, "eth_chainId", json!([])),
                self.call(1, "eth_chainId", json!([]))
            );
            if let (Ok(v1), Ok(v2)) = (v1, v2) {
                eyre::ensure!(v1 == v2, "backend chain IDs disagree");
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        match self.call(0, "tempo_executionRules", json!([])).await {
            Ok(rules) => eyre::ensure!(
                rules["fixed"] == false,
                "v1 must retain historical execution rules"
            ),
            Err(error) if error["code"] == -32601 => {} // Unmodified v1.14.0 predates this handshake.
            Err(error) => {
                eyre::bail!("v1 capability check failed: {error}");
            }
        }
        for number in [0, self.cutover - 1] {
            let params = json!([format!("0x{number:x}"), false]);
            let v1 = self
                .call(0, "eth_getBlockByNumber", params.clone())
                .await
                .map_err(|e| eyre::eyre!("{e}"))?;
            let v2 = self
                .call(1, "eth_getBlockByNumber", params)
                .await
                .map_err(|e| eyre::eyre!("{e}"))?;
            eyre::ensure!(
                !v1.is_null() && !v2.is_null(),
                "both databases must contain block {number}"
            );
            eyre::ensure!(
                v1["hash"] == v2["hash"],
                "backend histories disagree at block {number}"
            );
            if number == self.cutover - 1 {
                eyre::ensure!(
                    v1["hash"]
                        .as_str()
                        .is_some_and(|h| h.eq_ignore_ascii_case(&self.parent_hash)),
                    "cutover parent hash mismatch"
                );
            }
        }
        let rules = self
            .call(1, "tempo_executionRules", json!([]))
            .await
            .map_err(|e| eyre::eyre!("v2 fixed-rule handshake failed: {e}"))?;
        eyre::ensure!(
            rules["fixed"] == true && rules["protocol"] == "T11",
            "v2 must use fixed T11 execution rules"
        );
        let activation = rules["activationTimestamp"]
            .as_u64()
            .ok_or_else(|| eyre::eyre!("v2 has no T11 activation timestamp"))?;
        let parent = self
            .call(
                1,
                "eth_getBlockByNumber",
                json!([format!("0x{:x}", self.cutover - 1), false]),
            )
            .await
            .map_err(|e| eyre::eyre!("{e}"))?;
        let first = self
            .call(
                1,
                "eth_getBlockByNumber",
                json!([format!("0x{:x}", self.cutover), false]),
            )
            .await
            .map_err(|e| eyre::eyre!("{e}"))?;
        let parent_timestamp = quantity(&parent["timestamp"])
            .map_err(|e| eyre::eyre!("invalid parent timestamp: {e}"))?;
        let first_timestamp = quantity(&first["timestamp"])
            .map_err(|e| eyre::eyre!("checkpoint must contain the first T11 block: {e}"))?;
        eyre::ensure!(
            parent_timestamp < activation && first_timestamp >= activation,
            "cutover does not straddle the T11 activation timestamp"
        );
        eyre::ensure!(
            first["parentHash"] == parent["hash"],
            "cutover parent linkage mismatch"
        );
        Ok(())
    }

    fn backend(&self, number: u64) -> usize {
        usize::from(number >= self.cutover)
    }

    async fn block_number(&self, selector: &Value) -> RpcResult<u64> {
        match selector.as_str() {
            Some("earliest") => Ok(0),
            Some(tag @ ("latest" | "safe" | "finalized")) => {
                let block = self
                    .call(1, "eth_getBlockByNumber", json!([tag, false]))
                    .await?;
                quantity(&block["number"])
            }
            Some("pending") => Err(error(-32602, "Pending is not a mined block")),
            Some(_) => quantity(selector),
            None => Err(invalid()),
        }
    }

    async fn hash_backend(&self, value: &Value) -> RpcResult<usize> {
        hash(value)?;
        // v2 can contain historical headers even though it cannot execute their rules.
        for backend in [1, 0] {
            let block = self
                .call(backend, "eth_getBlockByHash", json!([value, false]))
                .await?;
            if !block.is_null() {
                return Ok(self.backend(quantity(&block["number"])?));
            }
        }
        // Let the upstream preserve the method's normal unknown-block result (null vs error).
        Ok(1)
    }

    async fn selector_backend(&self, selector: &Value) -> RpcResult<usize> {
        if selector.is_null() || selector == "pending" {
            return Ok(1);
        }
        if let Some(object) = selector.as_object() {
            return match (object.get("blockHash"), object.get("blockNumber")) {
                (Some(hash), None) => self.hash_backend(hash).await,
                (None, Some(number)) => Ok(self.backend(self.block_number(number).await?)),
                _ => Err(invalid()),
            };
        }
        // Raw 32-byte selectors are accepted by several trace/block methods.
        if selector.as_str().is_some_and(|s| s.len() == 66) {
            return self.hash_backend(selector).await;
        }
        Ok(self.backend(self.block_number(selector).await?))
    }

    async fn transaction_backend(&self, tx: &Value) -> RpcResult<usize> {
        hash(tx)?;
        for backend in [1, 0] {
            let receipt = self
                .call(backend, "eth_getTransactionReceipt", json!([tx]))
                .await?;
            if !receipt.is_null() {
                return Ok(self.backend(quantity(&receipt["blockNumber"])?));
            }
        }
        Ok(1) // Unknown/pending transactions belong to the live node.
    }

    async fn logs(&self, params: &[Value]) -> RpcResult<Value> {
        if params.len() != 1 {
            return Err(invalid());
        }
        let filter = params[0].as_object().ok_or_else(invalid)?;
        if let Some(hash) = filter.get("blockHash") {
            if filter.contains_key("fromBlock") || filter.contains_key("toBlock") {
                return Err(invalid());
            }
            return self
                .call(self.hash_backend(hash).await?, "eth_getLogs", json!(params))
                .await;
        }
        let latest = json!("latest");
        let from = self
            .block_number(filter.get("fromBlock").unwrap_or(&latest))
            .await?;
        let to = self
            .block_number(filter.get("toBlock").unwrap_or(&latest))
            .await?;
        if from > to {
            return Err(invalid());
        }
        let mut logs = Vec::new();
        for (backend, start, end) in [
            (0, from, to.min(self.cutover - 1)),
            (1, from.max(self.cutover), to),
        ] {
            if start > end {
                continue;
            }
            let mut part = filter.clone();
            part.insert("fromBlock".into(), json!(format!("0x{start:x}")));
            part.insert("toBlock".into(), json!(format!("0x{end:x}")));
            let response = self.call(backend, "eth_getLogs", json!([part])).await?;
            logs.extend(
                response
                    .as_array()
                    .ok_or_else(|| error(-32603, "Invalid logs response"))?
                    .iter()
                    .cloned(),
            );
        }
        Ok(json!(logs))
    }

    async fn fee_history(&self, params: &[Value]) -> RpcResult<Value> {
        if !(2..=3).contains(&params.len()) {
            return Err(invalid());
        }
        let count = quantity(&params[0])?;
        if count == 0 || count > 1024 {
            return Err(invalid());
        }
        let newest = self.block_number(&params[1]).await?;
        let oldest = newest.saturating_sub(count - 1);
        if self.backend(oldest) == self.backend(newest) {
            return self
                .call(self.backend(newest), "eth_feeHistory", json!(params))
                .await;
        }
        let mut old_params = params.to_vec();
        old_params[0] = json!(format!("0x{:x}", self.cutover - oldest));
        old_params[1] = json!(format!("0x{:x}", self.cutover - 1));
        let mut new_params = params.to_vec();
        new_params[0] = json!(format!("0x{:x}", newest - self.cutover + 1));
        new_params[1] = json!(format!("0x{newest:x}"));
        let mut old = self.call(0, "eth_feeHistory", json!(old_params)).await?;
        let new = self.call(1, "eth_feeHistory", json!(new_params)).await?;
        let old_start = quantity(&old["oldestBlock"])?;
        let new_start = quantity(&new["oldestBlock"])?;
        let old_count = old["gasUsedRatio"].as_array().ok_or_else(invalid)?.len() as u64;
        let new_count = new["gasUsedRatio"].as_array().ok_or_else(invalid)?.len() as u64;
        if old_start.checked_add(old_count) != Some(self.cutover)
            || new_start != self.cutover
            || new_count != newest - self.cutover + 1
        {
            return Err(error(
                -32001,
                "Fee history is missing at the protocol boundary",
            ));
        }
        for key in [
            "baseFeePerGas",
            "gasUsedRatio",
            "reward",
            "baseFeePerBlobGas",
            "blobGasUsedRatio",
        ] {
            match (old.get_mut(key), new.get(key)) {
                (Some(Value::Array(a)), Some(Value::Array(b))) => {
                    if key == "baseFeePerGas" || key == "baseFeePerBlobGas" {
                        // The trailing predicted fee of the old half overlaps the first new fee.
                        a.pop();
                    }
                    a.extend(b.iter().cloned());
                }
                (None, None) => {}
                _ => return Err(error(-32603, "Incompatible fee history responses")),
            }
        }
        Ok(old)
    }

    async fn route(&self, method: &str, params: &[Value]) -> RpcResult<Value> {
        if method == "eth_getLogs" {
            return self.logs(params).await;
        }
        if method == "eth_feeHistory" {
            return self.fee_history(params).await;
        }
        if method == "tempo_multiplexStatus" {
            return Ok(
                json!({"cutoverBlock":format!("0x{:x}", self.cutover), "parentHash":self.parent_hash, "protocol":"T11"}),
            );
        }
        let selector_index = match method {
            "eth_getBlockByNumber"
            | "eth_getBlockTransactionCountByNumber"
            | "eth_getUncleCountByBlockNumber"
            | "eth_getUncleByBlockNumberAndIndex"
            | "eth_getTransactionByBlockNumberAndIndex"
            | "eth_getRawTransactionByBlockNumberAndIndex"
            | "eth_getBlockReceipts"
            | "debug_getRawHeader"
            | "debug_getRawBlock"
            | "debug_getRawReceipts"
            | "debug_traceBlockByNumber"
            | "trace_block"
            | "trace_replayBlockTransactions" => Some(0),
            "eth_getBalance"
            | "eth_getAccount"
            | "eth_getCode"
            | "eth_getTransactionCount"
            | "eth_call"
            | "eth_estimateGas"
            | "eth_createAccessList"
            | "debug_traceCall"
            | "eth_simulateV1"
            | "tempo_simulateV1"
            | "trace_callMany" => Some(1),
            "eth_getStorageAt" | "eth_getProof" | "trace_call" => Some(2),
            _ => None,
        };
        let mut forwarded = params.to_vec();
        if let Some(index) = selector_index
            && let Some(selector) = forwarded.get_mut(index)
            && selector
                .as_str()
                .is_some_and(|s| matches!(s, "latest" | "safe" | "finalized" | "earliest"))
        {
            // Resolve once so a moving safe/finalized tag cannot cross the boundary between
            // backend selection and execution. All tags refer to v2's canonical view.
            *selector = json!(format!("0x{:x}", self.block_number(selector).await?));
        }
        let backend = if let Some(index) = selector_index {
            self.selector_backend(forwarded.get(index).unwrap_or(&Value::Null))
                .await?
        } else {
            match method {
                "eth_getBlockByHash"
                | "eth_getBlockTransactionCountByHash"
                | "eth_getTransactionByBlockHashAndIndex"
                | "eth_getRawTransactionByBlockHashAndIndex"
                | "eth_getUncleCountByBlockHash"
                | "eth_getUncleByBlockHashAndIndex"
                | "debug_traceBlockByHash" => {
                    self.hash_backend(params.first().ok_or_else(invalid)?)
                        .await?
                }
                "eth_getTransactionByHash"
                | "eth_getTransactionReceipt"
                | "eth_getRawTransactionByHash"
                | "debug_getRawTransaction"
                | "debug_traceTransaction"
                | "trace_transaction"
                | "trace_replayTransaction"
                | "trace_get" => {
                    self.transaction_backend(params.first().ok_or_else(invalid)?)
                        .await?
                }
                "eth_chainId"
                | "eth_blockNumber"
                | "eth_syncing"
                | "eth_gasPrice"
                | "eth_maxPriorityFeePerGas"
                | "eth_blobBaseFee"
                | "eth_accounts"
                | "eth_sendRawTransaction"
                | "eth_sendRawTransactionSync"
                | "web3_clientVersion"
                | "web3_sha3"
                | "net_version"
                | "net_listening"
                | "net_peerCount"
                | "tempo_forkSchedule"
                | "tempo_executionRules"
                | "consensus_getLatest" => 1,
                "consensus_getFinalization" => {
                    let query = params.first().ok_or_else(invalid)?;
                    if query == "latest" {
                        1
                    } else {
                        self.backend(query["height"].as_u64().ok_or_else(invalid)?)
                    }
                }
                _ => return Err(error(-32601, "Method not supported by tempo-multiplex")),
            }
        };
        self.call(backend, method, json!(forwarded)).await
    }

    async fn request(&self, request: Value) -> Option<Value> {
        let invalid_request =
            || Some(json!({"jsonrpc":"2.0", "id":null, "error":error(-32600,"Invalid Request")}));
        if !request.is_object()
            || request["jsonrpc"] != "2.0"
            || !request["method"].is_string()
            || request
                .get("id")
                .is_some_and(|id| !(id.is_null() || id.is_string() || id.is_number()))
        {
            return invalid_request();
        }
        let id = request.get("id").cloned();
        let result = match self.inflight.try_acquire() {
            Ok(_permit) => match request.get("params") {
                None => self.route(request["method"].as_str().unwrap(), &[]).await,
                Some(Value::Array(params)) => {
                    self.route(request["method"].as_str().unwrap(), params)
                        .await
                }
                _ => Err(invalid()),
            },
            Err(_) => Err(error(-32005, "Too many requests")),
        };
        id.map(|id| match result {
            Ok(result) => json!({"jsonrpc":"2.0", "id":id, "result":result}),
            Err(error) => json!({"jsonrpc":"2.0", "id":id, "error":error}),
        })
    }
}

pub(crate) async fn handle(State(rpc): State<Rpc>, body: Bytes) -> Response {
    let request: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => {
            return Json(json!({"jsonrpc":"2.0", "id":null, "error":error(-32700, "Parse error")}))
                .into_response();
        }
    };
    let response = if let Value::Array(batch) = request {
        if batch.is_empty() || batch.len() > 100 {
            Some(
                json!({"jsonrpc":"2.0", "id":null, "error":error(-32600,"Batch must contain 1 to 100 requests")}),
            )
        } else {
            let responses: Vec<_> =
                futures::stream::iter(batch.into_iter().map(|request| rpc.request(request)))
                    .buffered(16)
                    .filter_map(|response| async { response })
                    .collect()
                    .await;
            (!responses.is_empty()).then(|| json!(responses))
        }
    } else {
        rpc.request(request).await
    };
    match response {
        Some(response) => Json(response).into_response(),
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

#[cfg(test)]
mod tests;
