//! RPC types for the consensus namespace.

use std::fmt::Display;

use alloy_primitives::B256;
use futures::Future;
use reth_primitives_traits::SealedOrRecoveredBlock;
use serde::{Deserialize, Serialize};
use tempo_payload_types::serde_sealed_or_recovered_block;
use tempo_primitives::Block;
use tokio::sync::broadcast;

/// A block with a threshold BLS certificate (notarization or finalization).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CertifiedBlock {
    pub epoch: u64,
    pub view: u64,
    pub digest: B256,

    /// Hex-encoded full notarization or finalization.
    pub certificate: String,

    /// The Tempo block.
    #[serde(with = "serde_sealed_or_recovered_block")]
    pub block: SealedOrRecoveredBlock<Block>,
}

impl Display for CertifiedBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match serde_json::to_string(self) {
            Ok(s) => f.write_str(&s),
            Err(err) => write!(f, "<failed formatting certified block: {err}"),
        }
    }
}

/// Consensus event emitted.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Event {
    /// A block was notarized.
    Notarized {
        #[serde(flatten)]
        block: CertifiedBlock,
        /// Unix timestamp in milliseconds when this event was observed.
        seen: u64,
    },
    /// A block was finalized.
    Finalized {
        #[serde(flatten)]
        block: CertifiedBlock,
        /// Unix timestamp in milliseconds when this event was observed.
        seen: u64,
    },
    /// A view was nullified.
    Nullified {
        epoch: u64,
        view: u64,
        /// Unix timestamp in milliseconds when this event was observed.
        seen: u64,
    },
}

/// Query for consensus data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Query {
    /// Get the latest item.
    Latest,
    /// Get by block height.
    Height(u64),
}

impl Display for Query {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match serde_json::to_string(self) {
            Ok(s) => f.write_str(&s),
            Err(err) => write!(f, "<failed formatting query: {err}>"),
        }
    }
}

/// Response for get_latest - current consensus state snapshot.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsensusState {
    /// The latest finalized block (if any).
    pub finalized: Option<CertifiedBlock>,
    /// The latest notarized block (if any, and not yet finalized).
    pub notarized: Option<CertifiedBlock>,
}

#[derive(Debug)]
pub enum Response<T> {
    Success(T),
    NotReady,
    Missing(&'static str),
}

impl<T> Response<T>
where
    T: std::fmt::Debug,
{
    pub fn unwrap(self) -> T {
        let Self::Success(val) = self else {
            panic!("not a success: {self:?}")
        };
        val
    }
}

impl<T> Display for Response<T>
where
    T: Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success(obj) => write!(f, "success: {obj}"),
            Self::NotReady => write!(f, "service not ready"),
            Self::Missing(msg) => write!(f, "missing: {msg}"),
        }
    }
}

/// Trait for accessing consensus feed data.
pub trait ConsensusFeed: Send + Sync + 'static {
    /// Get a finalization by query (supports `Latest` or `Height`).
    fn get_finalization(
        &self,
        query: Query,
    ) -> impl Future<Output = Response<CertifiedBlock>> + Send;

    /// Get the current consensus state (latest finalized + latest notarized).
    fn get_latest(&self) -> impl Future<Output = ConsensusState> + Send;

    /// Subscribe to consensus events.
    fn subscribe(&self) -> impl Future<Output = Option<broadcast::Receiver<Event>>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certified_block_roundtrips_legacy_plain_block_json() {
        let fixture = serde_json::json!({
            "epoch": 7,
            "view": 11,
            "digest": "0x1111111111111111111111111111111111111111111111111111111111111111",
            "certificate": "0x1234",
            "block": {
                "body": {
                    "ommers": [],
                    "transactions": [],
                    "withdrawals": null
                },
                "header": {
                    "difficulty": "0x0",
                    "extraData": "0x",
                    "gasLimit": "0x0",
                    "gasUsed": "0x0",
                    "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "mainBlockGeneralGasLimit": "0x0",
                    "miner": "0x0000000000000000000000000000000000000000",
                    "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "nonce": "0x0000000000000000",
                    "number": "0x0",
                    "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
                    "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
                    "sharedGasLimit": "0x0",
                    "stateRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
                    "timestamp": "0x0",
                    "timestampMillisPart": "0x0",
                    "transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
                }
            }
        });

        let certified: CertifiedBlock = serde_json::from_value(fixture.clone()).unwrap();
        let roundtripped = serde_json::to_value(certified).unwrap();

        assert_eq!(roundtripped, fixture);
    }
}
