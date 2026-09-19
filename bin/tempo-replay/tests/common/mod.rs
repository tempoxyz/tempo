#![allow(dead_code)]
use alloy_consensus::{SignableTransaction, TxLegacy, proofs::calculate_transaction_root};
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_primitives::{B256, Bytes, Sealable, Signature, TxKind, U256, keccak256};
use axum::{Json, Router, extract::State as AxumState, routing::post};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tempo_primitives::{Block, TempoHeader, TempoTransaction, TempoTxEnvelope};
use tempo_replay::{
    config::*,
    model::{CapturedBlock, now_ms},
    rpc::Rpc,
    verify::{Qualified, Target},
};
use tokio_util::sync::CancellationToken;

pub(crate) fn sign(hash: B256, key: u8) -> Signature {
    let sk = k256::ecdsa::SigningKey::from_slice(&[key; 32]).unwrap();
    let (sig, recovery) = sk.sign_prehash_recoverable(hash.as_slice()).unwrap();
    Signature::from_signature_and_parity(sig, recovery.is_y_odd())
}
pub(crate) fn legacy(nonce: u64, key: u8) -> TempoTxEnvelope {
    let tx = TxLegacy {
        chain_id: Some(4217),
        nonce,
        gas_price: 1_000_000_000,
        gas_limit: 21000,
        to: TxKind::Call(alloy_primitives::Address::repeat_byte(0x42)),
        value: U256::ZERO,
        input: Bytes::new(),
    };
    let signature = sign(tx.signature_hash(), key);
    TempoTxEnvelope::Legacy(tx.into_signed(signature))
}
pub(crate) fn aa(
    nonce: u64,
    nonce_key: U256,
    valid_before: Option<u64>,
    key: u8,
) -> TempoTxEnvelope {
    let tx = TempoTransaction {
        chain_id: 4217,
        nonce,
        nonce_key,
        gas_limit: 100000,
        max_fee_per_gas: 1000000000,
        valid_before: valid_before.and_then(std::num::NonZeroU64::new),
        calls: vec![tempo_primitives::transaction::Call {
            to: TxKind::Call(alloy_primitives::Address::repeat_byte(0x33)),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        ..Default::default()
    };
    let signature = sign(tx.signature_hash(), key);
    TempoTxEnvelope::AA(tx.into_signed(signature.into()))
}
pub(crate) fn block(
    height: u64,
    parent: B256,
    timestamp: u64,
    txs: Vec<TempoTxEnvelope>,
    shadow: bool,
) -> Block {
    let mut header = TempoHeader::default();
    header.inner.number = height;
    header.inner.parent_hash = parent;
    header.inner.timestamp = timestamp / 1000;
    header.timestamp_millis_part = timestamp % 1000;
    header.inner.extra_data = Bytes::from(vec![u8::from(shadow)]);
    header.inner.transactions_root = calculate_transaction_root(&txs);
    Block {
        header,
        body: alloy_consensus::BlockBody {
            transactions: txs,
            ommers: vec![],
            withdrawals: None,
        },
    }
}
pub(crate) fn certified(b: &Block) -> Value {
    json!({"epoch":1,"view":b.header.inner.number,"digest":b.header.hash_slow(),"certificate":"0x1234","block":b,"seen":now_ms()})
}
pub(crate) fn captured(b: &Block) -> CapturedBlock {
    CapturedBlock::from_certified(certified(b), 4217).unwrap()
}
pub(crate) fn execution(b: &Block, full: bool) -> Value {
    let mut v = serde_json::to_value(&b.header).unwrap();
    v["hash"] = json!(b.header.hash_slow());
    v["transactions"] = Value::Array(
        b.body
            .transactions
            .iter()
            .map(|t| {
                let hash = keccak256(t.encoded_2718());
                if full {
                    let mut value = serde_json::to_value(t).unwrap();
                    value["hash"] = json!(hash);
                    value
                } else {
                    json!(hash)
                }
            })
            .collect(),
    );
    v
}
pub(crate) fn config(path: &Path) -> Config {
    Config {
        run: Run {
            schema_version: 2,
            id: "test".into(),
            mode: "finalized_bursts".into(),
            chain_id: 4217,
            tempo_revision: TEMPO_REVISION.into(),
            reth_revision: RETH_REVISION.into(),
            workload_profile: None,
        },
        source: Source {
            rpc_http: "https://source.example".into(),
            consensus_ws: "wss://source.example".into(),
            finality: "finalized".into(),
            fallback: "verified_execution_layer".into(),
            raw_blocks: "prefer_if_verified".into(),
            recovery_horizon_blocks: 1000,
            history_probe_blocks: 16385,
        },
        journal: JournalConfig {
            path: path.into(),
            sync_writes: true,
            group_commit_max_ms: 5,
            max_bytes: 1000000000,
            min_free_bytes: 0,
        },
        checkpoint: None,
        shadow: None,
        timing: Timing {
            guard_ms: 1,
            target_progress_timeout_ms: 10000,
            ..Default::default()
        },
        delivery: Delivery::default(),
        limits: Limits {
            rpc_timeout_ms: 100,
            ..Default::default()
        },
        metrics: Metrics::default(),
    }
}
pub(crate) struct MockState {
    pub(crate) blocks: BTreeMap<u64, Block>,
    pub(crate) missing_certificates: BTreeSet<u64>,
    pub(crate) is_shadow: bool,
    pub(crate) sent: Vec<String>,
    pub(crate) queued: Vec<TempoTxEnvelope>,
    pub(crate) reject: BTreeMap<B256, String>,
    pub(crate) lose_response: BTreeSet<B256>,
    pub(crate) corrupt_height: Option<u64>,
    pub(crate) auto_mine: bool,
}
pub(crate) struct Mock {
    pub(crate) state: Arc<Mutex<MockState>>,
    pub(crate) url: String,
    stop: CancellationToken,
    task: Option<tokio::task::JoinHandle<()>>,
}
impl Mock {
    pub(crate) async fn start(blocks: Vec<Block>, shadow: bool) -> Self {
        let state = Arc::new(Mutex::new(MockState {
            blocks: blocks
                .into_iter()
                .map(|b| (b.header.inner.number, b))
                .collect(),
            missing_certificates: BTreeSet::new(),
            is_shadow: shadow,
            sent: vec![],
            queued: vec![],
            reject: BTreeMap::new(),
            lose_response: BTreeSet::new(),
            corrupt_height: None,
            auto_mine: true,
        }));
        let app = Router::new()
            .route("/", post(handler))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let stop = CancellationToken::new();
        let stopped = stop.clone();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(stopped.cancelled_owned())
                .await
                .unwrap();
        });
        Self {
            state,
            url,
            stop,
            task: Some(task),
        }
    }
    pub(crate) fn rpc(&self, timeout: u64) -> Rpc {
        Rpc::new(&self.url, timeout, 16 * 1024 * 1024, None, None).unwrap()
    }
    pub(crate) async fn close(mut self) {
        self.stop.cancel();
        if let Some(task) = self.task.take() {
            task.await.unwrap();
        }
    }
}
impl Drop for Mock {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
async fn handler(
    AxumState(state): AxumState<Arc<Mutex<MockState>>>,
    Json(request): Json<Value>,
) -> Json<Value> {
    let (response, delay) = {
        let mut s = state.lock().unwrap();
        let method = request["method"].as_str().unwrap();
        let p = &request["params"];
        let mut delay = false;
        let result: std::result::Result<Value, String> = match method {
            "eth_chainId" => Ok(json!("0x1079")),
            "consensus_getLatest" => {
                if s.is_shadow && s.auto_mine {
                    let latest = s.blocks.last_key_value().unwrap().1;
                    let h = latest.header.inner.number + 1;
                    let parent = latest.header.hash_slow();
                    let ts = now_ms().max(latest.header.timestamp_millis() + 1);
                    let txs = std::mem::take(&mut s.queued);
                    s.blocks.insert(h, block(h, parent, ts, txs, true));
                }
                Ok(
                    json!({"finalized":certified(s.blocks.last_key_value().unwrap().1),"notarized":null}),
                )
            }
            "consensus_getFinalization" => {
                let h = p[0]["height"].as_u64().unwrap();
                if s.missing_certificates.contains(&h) {
                    Err("missing historical certificate".into())
                } else {
                    s.blocks
                        .get(&h)
                        .map(certified)
                        .ok_or("missing block".into())
                }
            }
            "eth_getBlockByNumber" | "debug_getRawBlock" => {
                let h = u64::from_str_radix(p[0].as_str().unwrap().trim_start_matches("0x"), 16)
                    .unwrap();
                match s.blocks.get(&h) {
                    Some(b) if method == "debug_getRawBlock" => {
                        Ok(json!(format!("0x{}", hex::encode(alloy_rlp::encode(b)))))
                    }
                    Some(b) => {
                        let mut v = execution(b, p[1].as_bool().unwrap_or(false));
                        if s.corrupt_height == Some(h) {
                            v["parentHash"] = json!(B256::repeat_byte(0x66));
                        }
                        Ok(v)
                    }
                    None => Ok(Value::Null),
                }
            }
            "eth_sendRawTransaction" => {
                let raw = p[0].as_str().unwrap().to_string();
                let bytes = hex::decode(raw.trim_start_matches("0x")).unwrap();
                let hash = keccak256(&bytes);
                s.sent.push(raw);
                delay = s.lose_response.remove(&hash);
                if let Some(error) = s.reject.get(&hash) {
                    Err(error.clone())
                } else {
                    if !s.queued.iter().any(|t| keccak256(t.encoded_2718()) == hash) {
                        let tx = TempoTxEnvelope::decode_2718(&mut bytes.as_slice()).unwrap();
                        s.queued.push(tx);
                    }
                    Ok(json!(hash))
                }
            }
            "eth_getTransactionReceipt" => {
                let hash: B256 = serde_json::from_value(p[0].clone()).unwrap();
                let mut receipt = Value::Null;
                for b in s.blocks.values() {
                    for (index, t) in b.body.transactions.iter().enumerate() {
                        if keccak256(t.encoded_2718()) == hash {
                            receipt = json!({"transactionHash":hash,"blockHash":b.header.hash_slow(),"blockNumber":format!("0x{:x}",b.header.inner.number),"transactionIndex":format!("0x{index:x}"),"status":"0x1","gasUsed":"0x5208","logs":[]});
                        }
                    }
                }
                Ok(receipt)
            }
            "eth_getTransactionByHash" => {
                let hash: B256 = serde_json::from_value(p[0].clone()).unwrap();
                if s.queued
                    .iter()
                    .chain(s.blocks.values().flat_map(|b| b.body.transactions.iter()))
                    .any(|t| keccak256(t.encoded_2718()) == hash)
                {
                    Ok(json!({"hash":hash}))
                } else {
                    Ok(Value::Null)
                }
            }
            "eth_getTransactionCount" => Ok(json!("0x0")),
            _ => Err("method not found".into()),
        };
        let response = match result {
            Ok(value) => json!({"jsonrpc":"2.0","id":request["id"],"result":value}),
            Err(message) => {
                json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-32000,"message":message}})
            }
        };
        (response, delay)
    };
    if delay {
        tokio::time::sleep(Duration::from_millis(350)).await;
    }
    Json(response)
}
pub(crate) fn qualified(mock: &Mock) -> Qualified {
    let evidence = ValidatorEvidence {
        id: "shadow-a".into(),
        public_key: "test".into(),
        rpc_http: mock.url.clone(),
        max_sender_slots: 16,
        pending_count: 10000,
        queued_count: 10000,
        pending_bytes: 20000000,
        queued_bytes: 20000000,
        pool_fixed_overhead_bytes: 1024,
        pool_raw_size_multiplier: 2,
        future_nonce_types: vec![0, 1, 2, 4, 0x76],
        pool_observation: "conservative_retained_reservations".into(),
    };
    Qualified {
        targets: vec![Target {
            id: "shadow-a".into(),
            rpc: mock.rpc(100),
            evidence: evidence.clone(),
        }],
        binding: "test-binding".into(),
        sender_budget: 12,
        count_budget: 8000,
        byte_budget: 16000000,
        overhead: 1024,
        multiplier: 2,
        deployment: Deployment {
            schema_version: 1,
            run_id: "test".into(),
            chain_id: 4217,
            tempo_revision: TEMPO_REVISION.into(),
            reth_revision: RETH_REVISION.into(),
            bootstrap_artifact_digest: String::new(),
            binary_sha256: String::new(),
            chainspec_sha256: String::new(),
            isolated_network: true,
            exclusive_workload: true,
            fork_rules_match_source: true,
            fee_token_and_amm_parity: true,
            validity_buffer_seconds: 3,
            source_capture_p99_ms: 100,
            measured_rpc_p99_ms: 10,
            measured_sustained_tps: 10000.,
            validators: vec![evidence],
        },
    }
}
pub(crate) fn attach_shadow(c: &mut Config, source: &Block, target: &Block) {
    c.checkpoint = Some(Checkpoint {
        manifest: Path::new("unused").into(),
        source_height: source.header.inner.number,
        source_hash: source.header.hash_slow().to_string(),
        shadow_hash: target.header.hash_slow().to_string(),
        bootstrap_artifact_digest: String::new(),
    });
    c.shadow = Some(Shadow {
        deployment_manifest: Path::new("unused").into(),
        ingress_policy: "sticky_sender".into(),
        ca_file: Path::new("unused").into(),
        identity_check_interval_ms: 100000,
        validators: vec![],
    });
}
