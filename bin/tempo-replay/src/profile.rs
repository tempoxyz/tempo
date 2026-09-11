//! Workload profiling over an exact finalized source block range.

use crate::{
    now_ms,
    source::{FinalizedBlock, TempoProvider, TxMetadata, fetch_finalized_block},
};
use alloy::{consensus::BlockHeader, primitives::B256};
use anyhow::{Result, ensure};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tempo_consensus::finalized_header_stream::FinalizedHeaderStream;

/// Source-observable workload facts compatible with the original profiler.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WorkloadProfile {
    pub schema_version: u32,
    pub chain_id: u64,
    pub first_height: u64,
    pub first_hash: B256,
    pub last_height: u64,
    pub last_hash: B256,
    pub observed_at_ms: u64,
    pub blocks: u64,
    pub duration_ms: u64,
    pub users: u64,
    pub systems: u64,
    pub subblocks: u64,
    pub raw_bytes: u64,
    pub gas_limit: u64,
    pub transaction_types: BTreeMap<u8, u64>,
    pub expiring_nonces: u64,
    pub nonzero_nonce_keys: u64,
    pub deadlines: u64,
    pub earliest_valid_before: Option<u64>,
    pub latest_valid_before: Option<u64>,
    pub mean_tps: f64,
    pub peak_block_users: u64,
    pub peak_block_raw_bytes: u64,
    pub peak_sender_block_users: u64,
}

impl WorkloadProfile {
    pub async fn profile(
        chain_id: u64,
        provider: TempoProvider,
        mut finalized: FinalizedHeaderStream,
        from: u64,
        to: u64,
    ) -> Result<Self> {
        ensure!(from <= to, "profile start must not exceed end");
        let mut profile = Self {
            schema_version: 1,
            chain_id,
            first_height: from,
            last_height: to,
            observed_at_ms: now_ms(),
            ..Default::default()
        };
        let mut first_timestamp_ms = None;
        let mut last_timestamp_ms = None;
        while let Some(header) = finalized.next().await {
            let header = header?;
            if header.number() > to {
                break;
            }
            let block = fetch_finalized_block(&provider, &header).await?;
            first_timestamp_ms.get_or_insert(block.timestamp_ms);
            last_timestamp_ms = Some(block.timestamp_ms);
            profile.record(block)?;
        }
        ensure!(
            profile.blocks == to - from + 1,
            "profile range is not fully finalized"
        );
        profile.duration_ms = last_timestamp_ms
            .unwrap_or_default()
            .saturating_sub(first_timestamp_ms.unwrap_or_default());
        profile.mean_tps = profile.users as f64 * 1000.0 / profile.duration_ms.max(1) as f64;
        Ok(profile)
    }

    fn record(&mut self, block: FinalizedBlock) -> Result<()> {
        if self.blocks == 0 {
            self.first_hash = block.cursor.hash;
        }
        self.last_hash = block.cursor.hash;
        self.blocks += 1;

        let mut block_users = 0;
        let mut block_bytes = 0;
        let mut senders = BTreeMap::new();
        for transaction in block.transactions {
            let metadata = match TxMetadata::from_envelope(&transaction)? {
                TxMetadata::System => {
                    self.systems += 1;
                    continue;
                }
                TxMetadata::Subblock(metadata) => {
                    self.subblocks += 1;
                    metadata
                }
                TxMetadata::Replayable(metadata) => metadata,
            };
            block_users += 1;
            block_bytes += metadata.encoded_length;
            self.users += 1;
            self.raw_bytes += metadata.encoded_length;
            self.gas_limit = self.gas_limit.saturating_add(metadata.gas_limit);
            *self
                .transaction_types
                .entry(metadata.transaction_type)
                .or_default() += 1;
            self.expiring_nonces += u64::from(metadata.expiring);
            self.nonzero_nonce_keys += u64::from(!metadata.nonce_key.is_zero());
            let sender_count = senders.entry(metadata.sender).or_insert(0u64);
            *sender_count += 1;
            self.peak_sender_block_users = self.peak_sender_block_users.max(*sender_count);
            if let Some(valid_before) = metadata.valid_before {
                self.deadlines += 1;
                self.earliest_valid_before = Some(
                    self.earliest_valid_before
                        .map_or(valid_before, |old| old.min(valid_before)),
                );
                self.latest_valid_before = Some(
                    self.latest_valid_before
                        .map_or(valid_before, |old| old.max(valid_before)),
                );
            }
        }
        self.peak_block_users = self.peak_block_users.max(block_users);
        self.peak_block_raw_bytes = self.peak_block_raw_bytes.max(block_bytes);
        Ok(())
    }
}
