//! Streamed State Machine Replication support.

use std::collections::BTreeMap;

use alloy_primitives::{B256, Bytes};
use alloy_rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable};
use tempo_payload_types::TempoBuiltPayload;
use tempo_primitives::{TempoConsensusContext, ed25519::PublicKey};

mod actor;

pub(crate) use actor::{Actor, Config, Mailbox, ProposalStream};

const SSMR_START_TAG: u8 = 0;
const SSMR_TX_SHARD_TAG: u8 = 1;
const SSMR_END_TAG: u8 = 2;

/// Default target shard size used when SSMR is enabled.
pub(crate) const DEFAULT_SHARD_TARGET_BYTES: usize = 10 * 1024;
/// Lower flush target for low-traffic periods.
pub(crate) const LOW_TRAFFIC_SHARD_TARGET_BYTES: usize = 5 * 1024;
/// Upper bound accepted by the PoC configuration.
pub(crate) const MAX_SHARD_TARGET_BYTES: usize = 64 * 1024;

/// Deterministic identity for an in-flight SSMR stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, RlpEncodable, RlpDecodable)]
pub(crate) struct StreamKey {
    /// Parent block hash/digest.
    pub(crate) parent_hash: B256,
    /// Block height being proposed.
    pub(crate) block_height: u64,
    /// Block timestamp in seconds.
    pub(crate) timestamp: u64,
    /// Milliseconds portion of the block timestamp.
    pub(crate) timestamp_millis_part: u64,
    /// Consensus context for the proposed block.
    pub(crate) consensus_context: TempoConsensusContext,
}

impl StreamKey {
    pub(crate) const fn new(
        parent_hash: B256,
        block_height: u64,
        timestamp: u64,
        timestamp_millis_part: u64,
        consensus_context: TempoConsensusContext,
    ) -> Self {
        Self {
            parent_hash,
            block_height,
            timestamp,
            timestamp_millis_part,
            consensus_context,
        }
    }

    pub(crate) fn proposer(&self) -> PublicKey {
        self.consensus_context.proposer
    }
}

/// SSMR feature flags announced by the leader.
#[derive(Clone, Copy, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub(crate) struct SsmrFlags {
    /// Whether the final block is expected to carry BAL data.
    pub(crate) bal_enabled: bool,
    /// Whether shards contain only EIP-2718 transaction bytes.
    pub(crate) tx_only: bool,
    /// Whether shards carry BAL data for optimistic BAL replay.
    pub(crate) shard_bal_enabled: bool,
}

impl SsmrFlags {
    pub(crate) const fn tx_only(bal_enabled: bool) -> Self {
        Self {
            bal_enabled,
            tx_only: true,
            shard_bal_enabled: bal_enabled,
        }
    }
}

/// Transaction bytes carried in a single ordered shard.
#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
#[rlp(trailing)]
pub(crate) struct SsmrShardPayload {
    /// Shard index. `SsmrStart` always carries index `0`.
    pub(crate) shard_index: u64,
    /// Index of the first transaction in the final block body.
    pub(crate) first_tx_index: u64,
    /// EIP-2718 encoded transactions.
    pub(crate) transactions: Vec<Bytes>,
    /// Cumulative transaction bytes observed through this shard.
    pub(crate) cumulative_tx_bytes: u64,
    /// Cumulative gas estimate observed through this shard.
    pub(crate) cumulative_gas_estimate: u64,
    /// Encoded BAL data usable to replay the shard optimistically.
    pub(crate) block_access_list: Option<Bytes>,
}

impl SsmrShardPayload {
    pub(crate) fn tx_count(&self) -> usize {
        self.transactions.len()
    }

    pub(crate) fn byte_len(&self) -> usize {
        self.transactions
            .iter()
            .map(|tx| tx.as_ref().len())
            .sum::<usize>()
            + self
                .block_access_list
                .as_ref()
                .map(|bal| bal.as_ref().len())
                .unwrap_or_default()
    }
}

/// First SSMR message for a block stream.
#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub(crate) struct SsmrStart {
    pub(crate) stream_key: StreamKey,
    pub(crate) parent_height: u64,
    pub(crate) proposer: PublicKey,
    pub(crate) extra_data: Bytes,
    pub(crate) gas_limit: u64,
    pub(crate) general_gas_limit: u64,
    pub(crate) shared_gas_limit: u64,
    pub(crate) shard_target_bytes: u64,
    pub(crate) flags: SsmrFlags,
    pub(crate) first_shard: SsmrShardPayload,
}

impl SsmrStart {
    pub(crate) fn validate_shape(&self) -> Result<(), SsmrError> {
        if self.first_shard.shard_index != 0 {
            return Err(SsmrError::StartShardIndex);
        }
        if self.first_shard.first_tx_index != 0 {
            return Err(SsmrError::UnexpectedFirstTxIndex {
                expected: 0,
                got: self.first_shard.first_tx_index,
            });
        }
        if self.proposer != self.stream_key.proposer() {
            return Err(SsmrError::ProposerMismatch);
        }
        if !self.flags.tx_only {
            return Err(SsmrError::NonTxOnlyShard);
        }
        Ok(())
    }
}

/// Follow-up tx-only shard.
#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub(crate) struct SsmrTxShard {
    pub(crate) stream_key: StreamKey,
    pub(crate) shard: SsmrShardPayload,
}

/// End-of-stream marker.
#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub(crate) struct SsmrEnd {
    pub(crate) stream_key: StreamKey,
    pub(crate) total_shards: u64,
    pub(crate) total_transactions: u64,
}

/// Network message for the SSMR side channel.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum SsmrMessage {
    Start(SsmrStart),
    TxShard(SsmrTxShard),
    End(SsmrEnd),
}

impl SsmrMessage {
    pub(crate) fn stream_key(&self) -> StreamKey {
        match self {
            Self::Start(start) => start.stream_key,
            Self::TxShard(shard) => shard.stream_key,
            Self::End(end) => end.stream_key,
        }
    }

    pub(crate) fn encode(self) -> Bytes {
        let mut out = Vec::new();
        match self {
            Self::Start(start) => {
                out.push(SSMR_START_TAG);
                start.encode(&mut out);
            }
            Self::TxShard(shard) => {
                out.push(SSMR_TX_SHARD_TAG);
                shard.encode(&mut out);
            }
            Self::End(end) => {
                out.push(SSMR_END_TAG);
                end.encode(&mut out);
            }
        }
        out.into()
    }

    pub(crate) fn decode(mut input: &[u8]) -> alloy_rlp::Result<Self> {
        let Some((tag, rest)) = input.split_first() else {
            return Err(alloy_rlp::Error::InputTooShort);
        };
        input = rest;
        match *tag {
            SSMR_START_TAG => Ok(Self::Start(SsmrStart::decode(&mut input)?)),
            SSMR_TX_SHARD_TAG => Ok(Self::TxShard(SsmrTxShard::decode(&mut input)?)),
            SSMR_END_TAG => Ok(Self::End(SsmrEnd::decode(&mut input)?)),
            _ => Err(alloy_rlp::Error::Custom("invalid SSMR message tag")),
        }
    }
}

/// In-memory transcript for one SSMR stream.
#[derive(Clone, Debug)]
pub(crate) struct SsmrTranscript {
    key: StreamKey,
    start: SsmrStart,
    shards: BTreeMap<u64, SsmrShardPayload>,
    end: Option<SsmrEnd>,
}

/// Complete in-memory SSMR stream plus any optimistic execution artifact.
#[derive(Clone, Debug)]
pub(crate) struct SsmrCompleteStream {
    pub(crate) transcript: SsmrTranscript,
    pub(crate) optimistic_payload: Option<TempoBuiltPayload>,
    pub(crate) optimistic_execution_finalizing: bool,
    pub(crate) optimistic_execution_failed: bool,
}

/// Current SSMR state for one block stream.
#[derive(Clone, Debug)]
pub(crate) struct SsmrStreamSnapshot {
    pub(crate) started: bool,
    pub(crate) end_received: bool,
    pub(crate) received_shards: u64,
    pub(crate) expected_shards: Option<u64>,
    pub(crate) received_transactions: u64,
    pub(crate) expected_transactions: Option<u64>,
    pub(crate) buffered_bytes: usize,
    pub(crate) next_missing_shard: Option<u64>,
    pub(crate) next_execution_shard: u64,
    pub(crate) optimistic_execution_started: bool,
    pub(crate) optimistic_execution_finalizing: bool,
    pub(crate) optimistic_execution_failed: bool,
    pub(crate) optimistic_payload_ready: bool,
    pub(crate) complete: Option<SsmrCompleteStream>,
}

impl SsmrTranscript {
    pub(crate) fn new(start: SsmrStart) -> Result<Self, SsmrError> {
        start.validate_shape()?;
        let key = start.stream_key;
        let mut shards = BTreeMap::new();
        shards.insert(0, start.first_shard.clone());
        Ok(Self {
            key,
            start,
            shards,
            end: None,
        })
    }

    pub(crate) fn key(&self) -> StreamKey {
        self.key
    }

    pub(crate) fn start(&self) -> &SsmrStart {
        &self.start
    }

    pub(crate) fn has_shard(&self, shard_index: u64) -> bool {
        self.shards.contains_key(&shard_index)
    }

    pub(crate) fn shard(&self, shard_index: u64) -> Option<&SsmrShardPayload> {
        self.shards.get(&shard_index)
    }

    pub(crate) fn take_shard_block_access_list(&mut self, shard_index: u64) -> Option<Bytes> {
        if shard_index == 0 {
            self.start.first_shard.block_access_list.take();
        }
        self.shards.get_mut(&shard_index)?.block_access_list.take()
    }

    pub(crate) fn shard_count(&self) -> u64 {
        self.shards.len() as u64
    }

    pub(crate) fn insert_shard(&mut self, shard: SsmrTxShard) -> Result<(), SsmrError> {
        if shard.stream_key != self.key {
            return Err(SsmrError::StreamKeyMismatch);
        }
        if shard.shard.shard_index == 0 {
            return Err(SsmrError::DuplicateStartShard);
        }
        self.insert_payload(shard.shard)
    }

    pub(crate) fn finish(&mut self, end: SsmrEnd) -> Result<(), SsmrError> {
        if end.stream_key != self.key {
            return Err(SsmrError::StreamKeyMismatch);
        }
        if end.total_shards == 0 {
            return Err(SsmrError::EmptyShardCount);
        }
        if let Some(existing) = &self.end
            && existing != &end
        {
            return Err(SsmrError::ConflictingEnd);
        }
        self.end = Some(end);
        Ok(())
    }

    pub(crate) fn is_complete(&self) -> bool {
        let Some(end) = &self.end else {
            return false;
        };
        if self.shards.len() as u64 != end.total_shards {
            return false;
        }
        (0..end.total_shards).all(|index| self.shards.contains_key(&index))
            && self.total_transactions() == end.total_transactions
    }

    pub(crate) fn total_transactions(&self) -> u64 {
        self.shards
            .values()
            .map(|payload| payload.tx_count() as u64)
            .sum()
    }

    pub(crate) fn ordered_transactions(&self) -> Result<Vec<Bytes>, SsmrError> {
        if !self.is_complete() {
            return Err(SsmrError::IncompleteTranscript);
        }

        let mut expected_tx_index = 0u64;
        let mut transactions = Vec::with_capacity(self.total_transactions() as usize);
        for payload in self.shards.values() {
            if payload.first_tx_index != expected_tx_index {
                return Err(SsmrError::UnexpectedFirstTxIndex {
                    expected: expected_tx_index,
                    got: payload.first_tx_index,
                });
            }
            expected_tx_index = expected_tx_index.saturating_add(payload.tx_count() as u64);
            transactions.extend(payload.transactions.iter().cloned());
        }
        Ok(transactions)
    }

    fn insert_payload(&mut self, payload: SsmrShardPayload) -> Result<(), SsmrError> {
        if let Some(existing) = self.shards.get(&payload.shard_index) {
            if existing == &payload {
                return Ok(());
            }
            return Err(SsmrError::ConflictingShard {
                shard_index: payload.shard_index,
            });
        }

        self.shards.insert(payload.shard_index, payload);
        Ok(())
    }
}

/// SSMR transcript validation errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum SsmrError {
    #[error("start message must carry shard index 0")]
    StartShardIndex,
    #[error("start message proposer does not match stream key proposer")]
    ProposerMismatch,
    #[error("SSMR PoC only accepts tx-only shards")]
    NonTxOnlyShard,
    #[error("message stream key does not match transcript")]
    StreamKeyMismatch,
    #[error("shard index 0 is reserved for SsmrStart")]
    DuplicateStartShard,
    #[error("conflicting shard content for shard {shard_index}")]
    ConflictingShard { shard_index: u64 },
    #[error("end message conflicts with previous end marker")]
    ConflictingEnd,
    #[error("end message must report at least one shard")]
    EmptyShardCount,
    #[error("transcript is incomplete")]
    IncompleteTranscript,
    #[error("unexpected first tx index, expected {expected}, got {got}")]
    UnexpectedFirstTxIndex { expected: u64, got: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes as RawBytes;

    fn stream_key() -> StreamKey {
        StreamKey::new(
            B256::from([1u8; 32]),
            7,
            1_000,
            123,
            TempoConsensusContext {
                epoch: 3,
                view: 4,
                parent_view: 2,
                proposer: PublicKey::from_seed([9u8; 32]),
            },
        )
    }

    fn payload(shard_index: u64, first_tx_index: u64, txs: &[&[u8]]) -> SsmrShardPayload {
        SsmrShardPayload {
            shard_index,
            first_tx_index,
            transactions: txs
                .iter()
                .map(|tx| Bytes(RawBytes::copy_from_slice(tx)))
                .collect(),
            block_access_list: None,
            cumulative_tx_bytes: txs.iter().map(|tx| tx.len() as u64).sum(),
            cumulative_gas_estimate: 21_000 * txs.len() as u64,
        }
    }

    fn start() -> SsmrStart {
        let key = stream_key();
        SsmrStart {
            stream_key: key,
            parent_height: 6,
            proposer: key.proposer(),
            extra_data: Bytes::default(),
            gas_limit: 30_000_000,
            general_gas_limit: 15_000_000,
            shared_gas_limit: 5_000_000,
            shard_target_bytes: DEFAULT_SHARD_TARGET_BYTES as u64,
            flags: SsmrFlags::tx_only(true),
            first_shard: payload(0, 0, &[b"tx0", b"tx1"]),
        }
    }

    #[test]
    fn message_round_trips() {
        let messages = [
            SsmrMessage::Start(start()),
            SsmrMessage::TxShard(SsmrTxShard {
                stream_key: stream_key(),
                shard: payload(1, 2, &[b"tx2"]),
            }),
            SsmrMessage::End(SsmrEnd {
                stream_key: stream_key(),
                total_shards: 2,
                total_transactions: 3,
            }),
        ];

        for message in messages {
            let encoded = message.clone().encode();
            assert_eq!(SsmrMessage::decode(encoded.as_ref()).unwrap(), message);
        }
    }

    #[test]
    fn shard_bal_round_trips() {
        let block_access_list = Bytes(RawBytes::from_static(b"bal"));
        let mut shard = payload(1, 2, &[b"tx2"]);
        shard.block_access_list = Some(block_access_list.clone());
        let message = SsmrMessage::TxShard(SsmrTxShard {
            stream_key: stream_key(),
            shard,
        });

        let encoded = message.clone().encode();

        assert_eq!(SsmrMessage::decode(encoded.as_ref()).unwrap(), message);
        let SsmrMessage::TxShard(decoded) = SsmrMessage::decode(encoded.as_ref()).unwrap() else {
            panic!("expected shard");
        };
        assert_eq!(decoded.shard.block_access_list, Some(block_access_list));
    }

    #[test]
    fn transcript_reconstructs_ordered_transactions() {
        let mut transcript = SsmrTranscript::new(start()).unwrap();
        transcript
            .insert_shard(SsmrTxShard {
                stream_key: stream_key(),
                shard: payload(2, 3, &[b"tx3"]),
            })
            .unwrap();
        transcript
            .insert_shard(SsmrTxShard {
                stream_key: stream_key(),
                shard: payload(1, 2, &[b"tx2"]),
            })
            .unwrap();
        transcript
            .finish(SsmrEnd {
                stream_key: stream_key(),
                total_shards: 3,
                total_transactions: 4,
            })
            .unwrap();

        let ordered = transcript.ordered_transactions().unwrap();
        let ordered = ordered.iter().map(|tx| tx.as_ref()).collect::<Vec<&[u8]>>();
        assert_eq!(ordered, vec![b"tx0", b"tx1", b"tx2", b"tx3"]);
    }

    #[test]
    fn duplicate_shards_are_idempotent_but_conflicts_fail() {
        let mut transcript = SsmrTranscript::new(start()).unwrap();
        let shard = SsmrTxShard {
            stream_key: stream_key(),
            shard: payload(1, 2, &[b"tx2"]),
        };
        transcript.insert_shard(shard.clone()).unwrap();
        transcript.insert_shard(shard).unwrap();

        let err = transcript
            .insert_shard(SsmrTxShard {
                stream_key: stream_key(),
                shard: payload(1, 2, &[b"different"]),
            })
            .unwrap_err();
        assert_eq!(err, SsmrError::ConflictingShard { shard_index: 1 });
    }

    #[test]
    fn gaps_make_transcript_incomplete() {
        let mut transcript = SsmrTranscript::new(start()).unwrap();
        transcript
            .insert_shard(SsmrTxShard {
                stream_key: stream_key(),
                shard: payload(2, 2, &[b"tx2"]),
            })
            .unwrap();
        transcript
            .finish(SsmrEnd {
                stream_key: stream_key(),
                total_shards: 3,
                total_transactions: 3,
            })
            .unwrap();

        assert!(!transcript.is_complete());
        assert_eq!(
            transcript.ordered_transactions().unwrap_err(),
            SsmrError::IncompleteTranscript
        );
    }

    #[test]
    fn start_validates_shape() {
        let mut bad_start = start();
        bad_start.first_shard.shard_index = 1;
        assert_eq!(
            bad_start.validate_shape().unwrap_err(),
            SsmrError::StartShardIndex
        );

        let mut bad_start = start();
        bad_start.proposer = PublicKey::from_seed([8u8; 32]);
        assert_eq!(
            bad_start.validate_shape().unwrap_err(),
            SsmrError::ProposerMismatch
        );
    }
}
