//! Shared replay identity, finalized cursors, failure evidence, and JSON report output.

use alloy::primitives::B256;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Immutable chain and source/shadow checkpoint identity for a replay.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayIdentity {
    pub chain_id: u64,
    pub checkpoint_height: u64,
    pub source_hash: B256,
    pub target_hash: B256,
}

impl ReplayIdentity {
    pub fn source_cursor(self) -> BlockCursor {
        BlockCursor {
            height: self.checkpoint_height,
            hash: self.source_hash,
        }
    }

    pub fn target_cursor(self) -> BlockCursor {
        BlockCursor {
            height: self.checkpoint_height,
            hash: self.target_hash,
        }
    }
}

/// Block height/hash pair used as a durable finalized-history cursor.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockCursor {
    pub height: u64,
    pub hash: B256,
}

/// Stable identity of one transaction occurrence in finalized source history.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct OccurrenceId {
    pub source_height: u64,
    pub source_index: u32,
}

impl OccurrenceId {
    pub fn key(self) -> [u8; 12] {
        let mut key = [0; 12];
        key[..8].copy_from_slice(&self.source_height.to_be_bytes());
        key[8..].copy_from_slice(&self.source_index.to_be_bytes());
        key
    }

    pub fn decode(key: &[u8]) -> Option<Self> {
        if key.len() != 12 {
            return None;
        }
        Some(Self {
            source_height: u64::from_be_bytes(key[..8].try_into().ok()?),
            source_index: u32::from_be_bytes(key[8..].try_into().ok()?),
        })
    }
}

/// Whether a classification is directly observed, RPC-reported, or inferred.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLevel {
    Observed,
    RpcReported,
    Inferred,
}

/// Evidence retained for a classified release-test result.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FailureEvidence {
    pub level: EvidenceLevel,
    pub rpc_code: Option<i64>,
    pub message: String,
    pub first_observed_ms: u64,
    pub last_observed_ms: u64,
}

pub fn tx_index_key(hash: B256, occurrence: OccurrenceId) -> [u8; 44] {
    let mut key = [0u8; 44];
    key[..32].copy_from_slice(hash.as_slice());
    key[32..].copy_from_slice(&occurrence.key());
    key
}

/// Writes an immutable JSON report atomically.
pub fn atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    if let Some(parent) = parent {
        std::fs::create_dir_all(parent)?;
    }
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let temporary = temporary_path(path);
    std::fs::write(&temporary, bytes)?;
    std::fs::File::open(&temporary)?.sync_all()?;
    std::fs::rename(&temporary, path)?;
    if let Some(parent) = parent {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn temporary_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("report");
    path.with_file_name(format!(".{name}.tmp-{}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn occurrence_keys_are_ordered_and_exact() {
        let first = OccurrenceId {
            source_height: 9,
            source_index: 4,
        };
        let second = OccurrenceId {
            source_height: 10,
            source_index: 0,
        };
        assert!(first.key() < second.key());
        assert_eq!(OccurrenceId::decode(&first.key()), Some(first));
        assert!(OccurrenceId::decode(&first.key()[..11]).is_none());
    }
}
