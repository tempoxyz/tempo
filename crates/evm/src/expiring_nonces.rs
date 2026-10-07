//! Reconstructible nonce snapshots. The block database is the durable source of truth.

use alloy_consensus::{
    BlockHeader, Sealable,
    transaction::{SignerRecoverable, TxHashRef},
};
use alloy_primitives::B256;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard},
};
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardforks};
use tempo_expiring_nonces::{ExpiringNonceState, MAX_EXPIRY_SECS};
use tempo_primitives::Block;

type BlockSource = dyn Fn(B256) -> Result<Option<Block>, String> + Send + Sync;
type Snapshots = VecDeque<(B256, Option<B256>, ExpiringNonceState)>;

/// A small cache of immutable snapshots, shared by validation and payload building.
/// Eviction is safe: a cache miss reconstructs from the requested branch's blocks.
#[derive(Clone)]
pub struct ExpiringNonceCache {
    source: Arc<BlockSource>,
    snapshots: Arc<Mutex<Snapshots>>,
}

impl core::fmt::Debug for ExpiringNonceCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExpiringNonceCache").finish_non_exhaustive()
    }
}

impl ExpiringNonceCache {
    fn lock(&self) -> MutexGuard<'_, Snapshots> {
        self.snapshots.lock().expect("nonce cache poisoned")
    }

    /// Creates an empty cache backed by a branch-aware block lookup.
    pub fn new(
        source: impl Fn(B256) -> Result<Option<Block>, String> + Send + Sync + 'static,
    ) -> Self {
        Self {
            source: Arc::new(source),
            snapshots: Default::default(),
        }
    }

    pub(crate) fn remember(&self, state: &ExpiringNonceState, block_hash: Option<B256>) {
        let root = state.root();
        let evicted = {
            let mut snapshots = self.lock();
            if snapshots
                .iter()
                .any(|(key, hash, _)| *key == root && *hash == block_hash)
            {
                return;
            }
            snapshots.push_back((root, block_hash, state.clone()));
            if snapshots.len() > 16 {
                snapshots.pop_front()
            } else {
                None
            }
        };
        // Releasing a large snapshot must not hold the shared cache mutex.
        drop(evicted);
    }

    /// Clones an already verified snapshot without reading or replaying block bodies.
    pub fn cached_state_at(&self, hash: B256) -> Option<ExpiringNonceState> {
        self.lock()
            .iter()
            .find(|(_, block_hash, _)| *block_hash == Some(hash))
            .map(|(_, _, state)| state.clone())
    }

    /// Loads the state of exactly `hash`, never the canonical tip as a substitute.
    pub(crate) fn state_at(
        &self,
        hash: B256,
        chainspec: &TempoChainSpec,
    ) -> Result<ExpiringNonceState, String> {
        if let Some(state) = self.cached_state_at(hash) {
            return Ok(state);
        }
        let mut block =
            (self.source)(hash)?.ok_or_else(|| format!("missing nonce history block {hash}"))?;
        if block.header.hash_slow() != hash {
            return Err("nonce history block hash mismatch".into());
        }
        let timestamp = block.header.timestamp();
        if block.header.number() == 0 {
            let mut state = ExpiringNonceState::default();
            state.advance(timestamp).map_err(|e| e.to_string())?;
            return Ok(state);
        }
        let root = block
            .header
            .expiring_nonce_root
            .ok_or("missing parent expiring nonce commitment")?;
        let cached = self
            .lock()
            .iter()
            .find(|(key, _, _)| *key == root)
            .map(|(_, _, state)| state.clone());
        if let Some(mut state) = cached {
            // Equal roots may occur in empty blocks with different timestamps.
            // Reconstruct if a cached timestamp belongs to a later block.
            if state.advance(timestamp).is_ok() && state.root() == root {
                return Ok(state);
            }
        }
        let mut history = Vec::new();
        loop {
            let parent_hash = block.header.parent_hash();
            let number = block.header.number();
            let block_time = block.header.timestamp();
            if number == 0 || block_time.saturating_add(MAX_EXPIRY_SECS) <= timestamp {
                break;
            }
            let spec = chainspec.tempo_hardfork_at(block_time);
            let mut nonces = Vec::new();
            for tx in &block.body.transactions {
                if !spec.is_t1() || !tx.is_expiring_nonce() {
                    continue;
                }
                let signed = tx.as_aa().expect("expiring nonce is AA");
                let expiry = signed
                    .tx()
                    .valid_before
                    .ok_or("missing nonce expiry in history")?
                    .get();
                if expiry <= timestamp {
                    continue;
                }
                let id = if spec.is_t1b() {
                    signed.expiring_nonce_hash(tx.recover_signer().map_err(|e| e.to_string())?)
                } else {
                    *tx.tx_hash()
                };
                nonces.push((id, expiry));
            }
            history.push(nonces);
            block = (self.source)(parent_hash)?
                .ok_or_else(|| format!("missing nonce history block {parent_hash}"))?;
            if block.header.hash_slow() != parent_hash
                || block.header.number().checked_add(1) != Some(number)
                || block.header.timestamp() > block_time
            {
                return Err("invalid nonce history ancestry".into());
            }
        }
        let mut state = ExpiringNonceState::default();
        state.advance(timestamp).map_err(|e| e.to_string())?;
        for nonces in history.into_iter().rev() {
            for (id, expiry) in nonces {
                state
                    .insert(id, expiry, MAX_EXPIRY_SECS, usize::MAX)
                    .map_err(|e| e.to_string())?;
            }
        }
        if state.root() != root {
            return Err("reconstructed expiring nonce commitment mismatch".into());
        }
        self.remember(&state, Some(hash));
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use std::collections::HashMap;
    use tempo_primitives::{TempoHeader, TempoTransaction, TempoTxEnvelope};

    #[test]
    fn history_bound_covers_every_hardfork() {
        for spec in tempo_chainspec::hardfork::TempoHardfork::VARIANTS {
            assert!(spec.expiring_nonce_max_expiry_secs() <= MAX_EXPIRY_SECS);
        }
    }

    fn transaction(nonce: u64, expiry: u64) -> TempoTxEnvelope {
        let signer = PrivateKeySigner::from_bytes(&B256::repeat_byte(1)).unwrap();
        let tx = TempoTransaction {
            nonce_key: U256::MAX,
            nonce,
            valid_before: std::num::NonZeroU64::new(expiry),
            ..Default::default()
        };
        let signature = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
        tx.into_signed(signature.into()).into()
    }

    fn child(
        parent: &Block,
        state: &mut ExpiringNonceState,
        time: u64,
        transactions: Vec<TempoTxEnvelope>,
    ) -> Block {
        state.advance(time).unwrap();
        for tx in &transactions {
            let signed = tx.as_aa().unwrap();
            state
                .insert(
                    signed.expiring_nonce_hash(tx.recover_signer().unwrap()),
                    signed.tx().valid_before.unwrap().get(),
                    300,
                    3_000_000,
                )
                .unwrap();
        }
        Block {
            header: TempoHeader {
                inner: alloy_consensus::Header {
                    parent_hash: parent.header.hash_slow(),
                    number: parent.header.number() + 1,
                    timestamp: time,
                    ..Default::default()
                },
                expiring_nonce_root: Some(state.root()),
                ..Default::default()
            },
            body: alloy_consensus::BlockBody {
                transactions,
                ..Default::default()
            },
        }
    }

    fn source(blocks: &[Block]) -> ExpiringNonceCache {
        let blocks: HashMap<_, _> = blocks
            .iter()
            .map(|block| (block.header.hash_slow(), block.clone()))
            .collect();
        ExpiringNonceCache::new(move |hash| Ok(blocks.get(&hash).cloned()))
    }

    #[test]
    fn restart_and_reorg_reconstruct_the_requested_branch() {
        let genesis = Block::default();
        let mut state = ExpiringNonceState::default();
        let first = child(&genesis, &mut state, 100, vec![transaction(1, 120)]);
        let parent_state = state.clone();
        let left = child(&first, &mut state, 110, vec![transaction(2, 130)]);
        let mut right_state = parent_state;
        let right = child(&first, &mut right_state, 120, vec![transaction(3, 140)]);
        let cache = source(&[genesis, first, left.clone(), right.clone()]);
        let chainspec = tempo_chainspec::spec::DEV.clone();
        assert_eq!(
            cache.state_at(left.header.hash_slow(), &chainspec).unwrap(),
            state
        );
        assert_eq!(
            cache
                .state_at(right.header.hash_slow(), &chainspec)
                .unwrap(),
            right_state
        );
        assert_ne!(state.root(), right_state.root());
        assert_eq!(right_state.len(), 1, "expired parent entry is gone");
    }

    #[test]
    fn missing_history_and_wrong_commitments_fail_closed() {
        let genesis = Block::default();
        let mut state = ExpiringNonceState::default();
        let first = child(&genesis, &mut state, 100, vec![transaction(1, 120)]);
        let second = child(&first, &mut state, 101, vec![]);
        let chainspec = tempo_chainspec::spec::DEV.clone();
        assert!(
            source(&[genesis.clone(), second.clone()])
                .state_at(second.header.hash_slow(), &chainspec)
                .unwrap_err()
                .contains("missing nonce history")
        );
        let mut corrupt = second;
        corrupt.header.expiring_nonce_root = Some(B256::ZERO);
        assert!(
            source(&[genesis, first, corrupt.clone()])
                .state_at(corrupt.header.hash_slow(), &chainspec)
                .unwrap_err()
                .contains("commitment mismatch")
        );
    }

    #[test]
    fn history_before_the_window_is_not_required() {
        let genesis = Block::default();
        let mut state = ExpiringNonceState::default();
        let first = child(&genesis, &mut state, 100, vec![transaction(1, 400)]);
        let second = child(&first, &mut state, 400, vec![]);
        let cache = source(&[first, second.clone()]);
        assert!(
            cache
                .state_at(second.header.hash_slow(), &tempo_chainspec::spec::DEV)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn cached_commitment_cannot_retain_expired_entries() {
        let genesis = Block::default();
        let mut state = ExpiringNonceState::default();
        let first = child(&genesis, &mut state, 100, vec![transaction(1, 120)]);
        let live_state = state.clone();
        let mut expired = child(&first, &mut state, 120, vec![]);
        expired.header.expiring_nonce_root = first.header.expiring_nonce_root;
        let cache = source(&[genesis, first.clone(), expired.clone()]);
        cache.remember(&live_state, Some(first.header.hash_slow()));
        assert!(
            cache
                .state_at(expired.header.hash_slow(), &tempo_chainspec::spec::DEV)
                .unwrap_err()
                .contains("commitment mismatch")
        );
    }
}
