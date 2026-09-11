use alloy_consensus::{
    Transaction, proofs::calculate_transaction_root, transaction::SignerRecoverable,
};
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_primitives::{Address, B256, Sealable, U256, keccak256};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tempo_primitives::{Block, TempoTxEnvelope};

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Point {
    pub height: u64,
    pub hash: B256,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Class {
    User,
    System,
    Subblock,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tx {
    pub hash: B256,
    pub raw: String,
    pub sender: Address,
    pub nonce_key: U256,
    pub nonce: u64,
    pub expiring: bool,
    pub tx_type: u8,
    pub gas_limit: u64,
    pub valid_before: Option<u64>,
    pub valid_after: Option<u64>,
    pub class: Class,
}
impl Tx {
    pub fn from_envelope(e: &TempoTxEnvelope, chain_id: u64) -> Result<Self> {
        let raw = e.encoded_2718();
        let hash = keccak256(&raw);
        let mut bytes = raw.as_slice();
        let decoded =
            TempoTxEnvelope::decode_2718(&mut bytes).context("unsupported signed envelope")?;
        ensure!(
            bytes.is_empty() && decoded.encoded_2718() == raw,
            "noncanonical transaction encoding"
        );
        let system = e.is_system_tx();
        if !system {
            ensure!(
                e.chain_id().is_none_or(|c| c == chain_id),
                "source transaction chain id mismatch"
            );
        }
        let sender = e.recover_signer().context("invalid source signature")?;
        Ok(Self {
            hash,
            raw: format!("0x{}", hex::encode(raw)),
            sender,
            nonce_key: e.nonce_key().unwrap_or(U256::ZERO),
            nonce: e.nonce(),
            expiring: e.is_expiring_nonce(),
            tx_type: e.tx_type() as u8,
            gas_limit: e.gas_limit(),
            valid_before: e.valid_before(),
            valid_after: e.valid_after(),
            class: if system {
                Class::System
            } else if e.has_sub_block_nonce_key_prefix() {
                Class::Subblock
            } else {
                Class::User
            },
        })
    }
    pub fn lane(&self) -> Option<String> {
        (!self.expiring).then(|| format!("{}:{}", self.sender, self.nonce_key))
    }
    pub fn raw_len(&self) -> u64 {
        (self.raw.len().saturating_sub(2) / 2) as u64
    }
    pub fn expired_at(&self, tip_seconds: u64) -> bool {
        self.valid_before
            .is_some_and(|v| v <= tip_seconds.saturating_add(3))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapturedBlock {
    pub point: Point,
    pub parent: B256,
    pub timestamp_ms: u64,
    pub seen_ms: Option<u64>,
    pub received_ms: u64,
    pub committed_ms: u64,
    pub provenance: String,
    pub evidence: Value,
    pub transactions: Vec<Tx>,
}
impl CapturedBlock {
    pub fn verified(
        block: Block,
        expected: Option<B256>,
        evidence: Value,
        provenance: &str,
        chain: u64,
    ) -> Result<Self> {
        let hash = block.header.hash_slow();
        ensure!(
            expected.is_none_or(|h| h == hash),
            "source header hash mismatch"
        );
        ensure!(
            block.header.timestamp_millis_part < 1000,
            "invalid header millisecond part"
        );
        ensure!(
            block.header.inner.transactions_root
                == calculate_transaction_root(&block.body.transactions),
            "transaction root mismatch"
        );
        let timestamp_ms = block
            .header
            .inner
            .timestamp
            .checked_mul(1000)
            .and_then(|t| t.checked_add(block.header.timestamp_millis_part))
            .context("timestamp overflow")?;
        let transactions = block
            .body
            .transactions
            .iter()
            .map(|e| Tx::from_envelope(e, chain))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            point: Point {
                height: block.header.inner.number,
                hash,
            },
            parent: block.header.inner.parent_hash,
            timestamp_ms,
            seen_ms: evidence.get("seen").and_then(Value::as_u64),
            received_ms: now_ms(),
            committed_ms: 0,
            provenance: provenance.into(),
            evidence,
            transactions,
        })
    }
    pub fn from_certified(value: Value, chain: u64) -> Result<Self> {
        let block = serde_json::from_value(
            value
                .get("block")
                .context("certified block body missing")?
                .clone(),
        )
        .context("decode native Tempo block")?;
        // The owned consensus RPC is the finality trust boundary. The consensus proposal
        // digest is kept as evidence; it is not substituted for the execution header hash.
        ensure!(
            value
                .get("certificate")
                .and_then(Value::as_str)
                .is_some_and(|s| s.starts_with("0x") && s.len() > 2),
            "missing finality certificate"
        );
        Self::verified(block, None, value, "certified_event", chain)
    }
    pub fn from_execution(value: Value, chain: u64) -> Result<Self> {
        ensure!(!value.is_null(), "execution history missing");
        let header =
            serde_json::from_value(value.clone()).context("decode Tempo execution header")?;
        let values = value
            .get("transactions")
            .and_then(Value::as_array)
            .context("full transactions required")?;
        let mut transactions = Vec::with_capacity(values.len());
        for v in values {
            let tx: TempoTxEnvelope =
                serde_json::from_value(v.clone()).context("decode complete Tempo RPC envelope")?;
            if let Some(hash) = v.get("hash") {
                ensure!(
                    serde_json::from_value::<B256>(hash.clone())? == keccak256(tx.encoded_2718()),
                    "RPC transaction hash mismatch"
                );
            }
            transactions.push(tx);
        }
        let hash =
            serde_json::from_value(value.get("hash").context("RPC block hash missing")?.clone())?;
        Self::verified(
            Block {
                header,
                body: alloy_consensus::BlockBody {
                    transactions,
                    ommers: vec![],
                    withdrawals: None,
                },
            },
            Some(hash),
            value,
            "anchored_execution_range",
            chain,
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum State {
    Ready,
    Attempting,
    Accepted,
    Unknown,
    Deferred,
    Finalized,
    Gap { reason: String },
    GeneratedByShadowConsensus,
}
impl State {
    pub fn terminal(&self) -> bool {
        matches!(
            self,
            Self::Finalized | Self::Gap { .. } | Self::GeneratedByShadowConsensus
        )
    }
    pub fn holds_credit(&self) -> bool {
        matches!(self, Self::Attempting | Self::Accepted | Self::Unknown)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Occurrence {
    pub source: Point,
    pub index: usize,
    pub tx: Tx,
    pub source_timestamp_ms: u64,
    pub state: State,
    pub attempts: u32,
    pub ambiguous_resends: u32,
    pub first_attempt_ms: Option<u64>,
    pub last_attempt_ms: Option<u64>,
    pub retry_at_ms: u64,
    pub dependency_since_ms: Option<u64>,
    pub endpoint: Option<String>,
    pub receipt: Option<Value>,
    pub source_receipt: Option<Value>,
    pub receipt_mismatch: Option<bool>,
    pub history: Vec<Event>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub at_ms: u64,
    pub state: State,
    pub detail: String,
}
impl Occurrence {
    pub fn new(b: &CapturedBlock, index: usize) -> Self {
        let tx = b.transactions[index].clone();
        let state = if tx.class == Class::System {
            State::GeneratedByShadowConsensus
        } else {
            State::Ready
        };
        Self {
            source: b.point.clone(),
            index,
            tx,
            source_timestamp_ms: b.timestamp_ms,
            state,
            attempts: 0,
            ambiguous_resends: 0,
            first_attempt_ms: None,
            last_attempt_ms: None,
            retry_at_ms: 0,
            dependency_since_ms: None,
            endpoint: None,
            receipt: None,
            source_receipt: None,
            receipt_mismatch: None,
            history: vec![],
        }
    }
    pub fn key(&self) -> String {
        format!("o/{:020}/{:010}", self.source.height, self.index)
    }
    pub fn transition(&mut self, state: State, detail: impl Into<String>) {
        self.history.push(Event {
            at_ms: now_ms(),
            state: state.clone(),
            detail: detail.into(),
        });
        self.state = state;
    }
    pub fn dispatch_accounted(&self) -> bool {
        self.attempts > 0 || self.state.terminal()
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Cursors {
    pub captured_through: Option<Point>,
    pub dispatch_accounted_through: Option<u64>,
    pub accounted_through: Option<u64>,
    pub included_through: Option<u64>,
    pub shadow_observed_through: Option<Point>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Phase {
    CaptureOnly,
    Verify,
    Reconcile,
    CatchUp,
    Live,
    PausedIncident,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counts {
    pub user_occurrences: u64,
    pub system_occurrences: u64,
    pub subblock_occurrences: u64,
    pub offered: u64,
    pub finalized: u64,
    pub gaps: u64,
    pub attempts: u64,
    pub receipt_mismatches: u64,
    pub reserved_count: u64,
    pub reserved_bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunState {
    pub schema_version: u32,
    pub run_id: String,
    pub chain_id: u64,
    pub source_identity: String,
    pub first_height: u64,
    pub replay_boundary: Option<u64>,
    pub binding: Option<String>,
    pub phase: Phase,
    pub incident: Option<String>,
    pub cursors: Cursors,
    pub counts: Counts,
    pub last_release_height: Option<u64>,
    pub lag_ms: u64,
    pub slip_ms: u64,
    pub target_tip_seconds: u64,
    pub capture_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Inclusion {
    pub point: Point,
    pub index: usize,
}
