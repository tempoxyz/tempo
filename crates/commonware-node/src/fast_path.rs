use std::{collections::VecDeque, sync::Arc};

use alloy_primitives::B256;
use commonware_consensus::types::Height;
use parking_lot::Mutex;
use tempo_payload_types::TempoBuiltPayloadExecutedBlock;

use crate::consensus::Digest;

const MAX_FAST_PATH_PAYLOADS: usize = 32;

/// Locally built executed payloads that may be inserted once consensus finalizes them.
#[derive(Clone, Debug, Default)]
pub(crate) struct FastPathPayloadCache {
    inner: Arc<Mutex<VecDeque<FastPathPayload>>>,
}

#[derive(Clone, Debug)]
struct FastPathPayload {
    digest: Digest,
    height: Height,
    block_hash: B256,
    executed_block: TempoBuiltPayloadExecutedBlock,
}

impl FastPathPayloadCache {
    pub(crate) fn insert(
        &self,
        digest: Digest,
        height: Height,
        block_hash: B256,
        executed_block: TempoBuiltPayloadExecutedBlock,
    ) {
        let mut entries = self.inner.lock();
        entries.retain(|entry| entry.digest != digest);
        entries.push_back(FastPathPayload {
            digest,
            height,
            block_hash,
            executed_block,
        });

        while entries.len() > MAX_FAST_PATH_PAYLOADS {
            entries.pop_front();
        }
    }

    pub(crate) fn take(
        &self,
        digest: Digest,
        height: Height,
        block_hash: B256,
    ) -> Option<TempoBuiltPayloadExecutedBlock> {
        let mut entries = self.inner.lock();
        let index = entries.iter().position(|entry| {
            entry.digest == digest && entry.height == height && entry.block_hash == block_hash
        })?;

        entries.remove(index).map(|entry| entry.executed_block)
    }
}
