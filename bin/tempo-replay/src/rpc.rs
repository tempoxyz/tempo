use crate::model::{CapturedBlock, Point};
use alloy_primitives::{B256, Sealable};
use anyhow::{Context, Result, ensure};
use futures_util::{SinkExt, StreamExt};
use reqwest::{
    Client,
    header::{AUTHORIZATION, HeaderMap, HeaderValue},
};
use serde_json::{Value, json};
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{sync::watch, task::JoinHandle};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct Rpc {
    client: Client,
    url: String,
    seq: Arc<AtomicU64>,
    max_bytes: u64,
}
#[derive(Debug)]
pub struct EvidenceError {
    pub value: Value,
    detail: String,
}
impl fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "incompatible execution block: {}", self.detail)
    }
}
impl std::error::Error for EvidenceError {}
#[derive(Debug, Clone)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    pub retry_ms: Option<u64>,
    pub ambiguous: bool,
}
impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RPC failure code {}", self.code)
    }
}
impl std::error::Error for RpcError {}
impl Rpc {
    pub fn new(
        url: &str,
        timeout_ms: u64,
        max_bytes: u64,
        ca: Option<&[u8]>,
        credential: Option<&str>,
    ) -> Result<Self> {
        // Select the workspace TLS provider before HTTP or WebSocket clients are built.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut headers = HeaderMap::new();
        if let Some(secret) = credential {
            ensure!(!secret.is_empty(), "empty RPC credential");
            let mut h = HeaderValue::from_str(&format!("Bearer {secret}"))
                .context("invalid credential header")?;
            h.set_sensitive(true);
            headers.insert(AUTHORIZATION, h);
        }
        let mut builder = Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .redirect(reqwest::redirect::Policy::none())
            .default_headers(headers);
        if let Some(pem) = ca {
            builder = builder.tls_certs_merge([
                reqwest::Certificate::from_pem(pem).context("invalid shadow CA")?
            ]);
        }
        Ok(Self {
            client: builder.build()?,
            url: url.into(),
            seq: Arc::new(AtomicU64::new(1)),
            max_bytes,
        })
    }
    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let id = self.seq.fetch_add(1, Ordering::Relaxed);
        let mut response = self
            .client
            .post(&self.url)
            .json(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
            .send()
            .await
            .map_err(|_| RpcError {
                code: -1,
                message: "transport failure".into(),
                retry_ms: None,
                ambiguous: true,
            })?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let retry_ms = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| {
                    s.parse::<u64>()
                        .ok()
                        .map(|seconds| seconds.saturating_mul(1000))
                        .or_else(|| {
                            httpdate::parse_http_date(s).ok().map(|date| {
                                date.duration_since(std::time::SystemTime::now())
                                    .unwrap_or_default()
                                    .as_millis()
                                    .min(u128::from(u64::MAX))
                                    as u64
                            })
                        })
                });
            return Err(RpcError {
                code: i64::from(status),
                message: "HTTP failure".into(),
                retry_ms,
                ambiguous: status >= 500,
            }
            .into());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| RpcError {
            code: -1,
            message: "response interrupted".into(),
            retry_ms: None,
            ambiguous: true,
        })? {
            ensure!(
                (bytes.len() as u64).saturating_add(chunk.len() as u64) <= self.max_bytes,
                "RPC response exceeds configured byte bound"
            );
            bytes.extend_from_slice(&chunk);
        }
        let v: Value = serde_json::from_slice(&bytes).context("invalid JSON-RPC response")?;
        ensure!(
            v.get("id").and_then(Value::as_u64) == Some(id)
                && v.get("jsonrpc").and_then(Value::as_str) == Some("2.0"),
            "JSON-RPC response identity mismatch"
        );
        if let Some(e) = v.get("error") {
            return Err(RpcError {
                code: e["code"].as_i64().unwrap_or(-1),
                message: e["message"].as_str().unwrap_or("unknown RPC error").into(),
                retry_ms: None,
                ambiguous: false,
            }
            .into());
        }
        v.get("result").cloned().context("missing RPC result")
    }
    pub async fn chain_id(&self) -> Result<u64> {
        quantity(&self.call("eth_chainId", json!([])).await?)
    }
    pub async fn latest_finalized(&self, chain: u64) -> Result<CapturedBlock> {
        let value = self.call("consensus_getLatest", json!([])).await?;
        CapturedBlock::from_certified(
            value
                .get("finalized")
                .filter(|v| !v.is_null())
                .context("source has no finalized block")?
                .clone(),
            chain,
        )
    }
    pub async fn certified(&self, height: u64, chain: u64) -> Result<CapturedBlock> {
        let b = CapturedBlock::from_certified(
            self.call("consensus_getFinalization", json!([{"height":height}]))
                .await?,
            chain,
        )?;
        ensure!(b.point.height == height, "certified height mismatch");
        Ok(b)
    }
    pub async fn execution(
        &self,
        height: u64,
        chain: u64,
        prefer_raw: bool,
    ) -> Result<CapturedBlock> {
        let value = self
            .call(
                "eth_getBlockByNumber",
                json!([format!("0x{height:x}"), true]),
            )
            .await?;
        let typed =
            CapturedBlock::from_execution(value.clone(), chain).map_err(|e| EvidenceError {
                value,
                detail: format!("{e:#}"),
            })?;
        ensure!(typed.point.height == height, "execution height mismatch");
        if prefer_raw {
            match self
                .call("debug_getRawBlock", json!([format!("0x{height:x}")]))
                .await
            {
                Ok(v) => {
                    let raw = v.as_str().context("invalid raw block result")?;
                    let bytes =
                        hex::decode(raw.strip_prefix("0x").context("raw block must be hex")?)?;
                    let mut input = bytes.as_slice();
                    let block: tempo_primitives::Block = alloy_rlp::Decodable::decode(&mut input)
                        .context("decode raw Tempo block")?;
                    ensure!(input.is_empty(), "trailing raw block bytes");
                    let decoded = CapturedBlock::verified(
                        block,
                        Some(typed.point.hash),
                        json!({"rawBlock":raw}),
                        "anchored_execution_range",
                        chain,
                    )?;
                    ensure!(
                        decoded
                            .transactions
                            .iter()
                            .map(|t| &t.raw)
                            .eq(typed.transactions.iter().map(|t| &t.raw)),
                        "raw/typed block transaction mismatch"
                    );
                }
                Err(e) if e.downcast_ref::<RpcError>().is_some() => {}
                Err(e) => return Err(e),
            }
        }
        Ok(typed)
    }
    pub async fn header_point(&self, height: u64) -> Result<Point> {
        let v = self
            .call(
                "eth_getBlockByNumber",
                json!([format!("0x{height:x}"), false]),
            )
            .await?;
        ensure!(!v.is_null(), "checkpoint unavailable");
        let h: tempo_primitives::TempoHeader = serde_json::from_value(v.clone())?;
        let hash: B256 = serde_json::from_value(v["hash"].clone())?;
        ensure!(
            h.inner.number == height && h.hash_slow() == hash,
            "checkpoint header hash mismatch"
        );
        Ok(Point { height, hash })
    }
}
pub fn quantity(v: &Value) -> Result<u64> {
    if let Some(n) = v.as_u64() {
        return Ok(n);
    }
    u64::from_str_radix(
        v.as_str()
            .and_then(|s| s.strip_prefix("0x"))
            .context("expected hex quantity")?,
        16,
    )
    .context("quantity overflow")
}
// A bounded latest-event notification is intentional: HTTP gap repair is authoritative,
// so socket loss, coalescing, and dropped events cannot skip a finalized height.
pub fn source_subscription(
    url: String,
    max_bytes: usize,
    stop: CancellationToken,
) -> (watch::Receiver<Option<Value>>, JoinHandle<()>) {
    let (tx, rx) = watch::channel(None);
    let task = tokio::spawn(async move {
        loop {
            let connected = tokio::select! { _ = stop.cancelled() => break, result = tokio_tungstenite::connect_async_with_config(&url, Some(tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default().max_message_size(Some(max_bytes)).max_frame_size(Some(max_bytes))), false) => result };
            if let Ok((mut ws, _)) = connected {
                let request =
                    json!({"jsonrpc":"2.0","id":1,"method":"consensus_subscribe","params":[]})
                        .to_string();
                if ws
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        request.into(),
                    ))
                    .await
                    .is_ok()
                {
                    loop {
                        let msg = tokio::select! { _ = stop.cancelled() => break, msg = ws.next() => msg };
                        match msg {
                            Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text))) => {
                                if let Ok(v) = serde_json::from_str::<Value>(&text)
                                    && v["method"] == "consensus_event"
                                    && v["params"]["result"]["type"] == "finalized"
                                {
                                    tx.send_replace(Some(v["params"]["result"].clone()));
                                }
                            }
                            Some(Ok(tokio_tungstenite::tungstenite::Message::Ping(data))) => {
                                let _ = ws
                                    .send(tokio_tungstenite::tungstenite::Message::Pong(data))
                                    .await;
                            }
                            Some(Ok(_)) => {}
                            _ => break,
                        }
                    }
                }
                // Dropping the socket closes it without waiting for a peer's close handshake.
            }
            tokio::select! { _ = stop.cancelled() => break, _ = tokio::time::sleep(Duration::from_secs(2)) => {} }
        }
    });
    (rx, task)
}
