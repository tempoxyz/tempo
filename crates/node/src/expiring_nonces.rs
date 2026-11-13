//! Seeds and repairs the expiring nonce set snapshots from the canonical chain.
//!
//! Block execution derives each block's set from its parent's. This task stores the set of every
//! canonical block whose set is still unknown (after a restart, or when a block was executed before
//! its parent's set existed), rebuilding it from the blocks inside the expiry window when needed.

use alloy::consensus::BlockHeader as _;
use alloy_primitives::BlockNumber;
use metrics::Counter;
use reth_ethereum::tasks::TaskExecutor;
use reth_primitives_traits::RecoveredBlock;
use reth_provider::{
    BlockNumReader, BlockReader, CanonStateSubscriptions, ChainSpecProvider, HeaderProvider,
    ProviderResult,
};
use reth_tracing::tracing::{debug, error, info};
use tempo_chainspec::spec::{TempoChainSpec, TempoHardforks as _};
use tempo_evm::expiring_nonces::{ExpiringNonce, ExpiringNonceSet, ExpiringNonceSets};
use tempo_primitives::{Block, TempoHeader, TempoPrimitives};
use tokio::sync::broadcast::error::RecvError;

/// Keeps the expiring nonce set of every canonical block known.
#[derive(Debug)]
pub struct ExpiringNonceTracker<P> {
    provider: P,
    sets: ExpiringNonceSets,
    rebuilds: Counter,
}

impl<P> ExpiringNonceTracker<P> {
    /// Creates a tracker that maintains `sets`, the snapshots the node's EVM config uses.
    pub fn new(provider: P, sets: ExpiringNonceSets) -> Self {
        Self {
            provider,
            sets,
            rebuilds: metrics::counter!("tempo_expiring_nonce_set_rebuilds_total"),
        }
    }
}

impl<P> ExpiringNonceTracker<P>
where
    P: BlockReader<Block = Block>
        + HeaderProvider<Header = TempoHeader>
        + BlockNumReader
        + ChainSpecProvider<ChainSpec = TempoChainSpec>
        + CanonStateSubscriptions<Primitives = TempoPrimitives>
        + 'static,
{
    /// Spawns the task: seeds the set at the canonical tip, then follows canonical notifications.
    pub fn spawn(self, executor: TaskExecutor) {
        let mut notifs = self.provider.subscribe_to_canonical_state();
        executor.spawn_blocking_task(async move {
            match self
                .provider
                .best_block_number()
                .and_then(|tip| self.rebuild(tip))
            {
                Ok(()) => info!(target: "expiring_nonces", "Seeded expiring nonce set"),
                Err(err) => {
                    error!(target: "expiring_nonces", %err, "Failed to seed expiring nonce set")
                }
            }
            loop {
                let notif = match notifs.recv().await {
                    Ok(notif) => notif,
                    // Missed blocks are rebuilt when the next notification finds no parent set.
                    Err(RecvError::Lagged(skipped)) => {
                        debug!(target: "expiring_nonces", skipped, "Expiring nonce tracker lagged");
                        continue;
                    }
                    Err(RecvError::Closed) => return,
                };
                for block in notif.committed().blocks().values() {
                    if let Err(err) = self.track(block) {
                        error!(
                            target: "expiring_nonces",
                            number = block.number(),
                            %err,
                            "Failed to rebuild expiring nonce set"
                        );
                    }
                }
            }
        });
    }

    /// Stores `block`'s set unless it is known, deriving it from the parent's set, or rebuilding
    /// it from the provider when the parent's set is unknown too.
    fn track(&self, block: &RecoveredBlock<Block>) -> ProviderResult<()> {
        if self.sets.contains(block.hash()) {
            return Ok(());
        }
        let entries = self.entries(block);
        match self
            .sets
            .derive(block.parent_hash(), block.timestamp(), &entries)
        {
            Some(set) => self.sets.insert(block.hash(), set),
            None => self.rebuild(block.number())?,
        }
        Ok(())
    }

    /// Rebuilds the set at canonical block `tip` from the blocks that can still hold unexpired
    /// entries.
    fn rebuild(&self, tip: BlockNumber) -> ProviderResult<()> {
        let Some(tip_header) = self.provider.sealed_header(tip)? else {
            return Ok(());
        };
        let tip_timestamp = tip_header.timestamp();
        // Forks only ever widen the window, so the tip's window covers every earlier block. A
        // block at `timestamp` only holds entries with `valid_before <= timestamp + window`.
        let window = self
            .provider
            .chain_spec()
            .tempo_hardfork_at(tip_timestamp)
            .expiring_nonce_max_expiry_secs();
        let mut first = tip;
        while first > 0 {
            let Some(header) = self.provider.sealed_header(first - 1)? else {
                break;
            };
            if header.timestamp().saturating_add(window) <= tip_timestamp {
                break;
            }
            first -= 1;
        }

        let mut set = ExpiringNonceSet::default();
        for block in self.provider.recovered_block_range(first..=tip)? {
            let replays = match set.apply(block.timestamp(), &self.entries(&block)) {
                Ok(replays) => replays,
                Err(err) => {
                    error!(target: "expiring_nonces", number = block.number(), %err, "Failed to apply block to expiring nonce set");
                    return Ok(());
                }
            };
            if !replays.is_empty() {
                error!(
                    target: "expiring_nonces",
                    number = block.number(),
                    replays = replays.len(),
                    "Canonical block repeats unexpired expiring nonce hashes"
                );
            }
        }
        debug!(target: "expiring_nonces", tip, first, root = %set.root(), "Rebuilt expiring nonce set");
        self.rebuilds.increment(1);
        self.sets.insert(tip_header.hash(), set);
        Ok(())
    }

    fn entries(&self, block: &RecoveredBlock<Block>) -> Vec<ExpiringNonce> {
        let spec = self
            .provider
            .chain_spec()
            .tempo_hardfork_at(block.timestamp());
        block
            .transactions_with_sender()
            .filter_map(|(sender, tx)| ExpiringNonce::from_tx(tx, *sender, spec))
            .collect()
    }
}
