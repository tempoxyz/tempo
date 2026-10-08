//! Independent nonce pruning against a pinned parent-state provider.

use crate::{TempoEvmConfig, evm::TempoEvm};
use alloy_evm::{Database, EvmEnv, block::BlockExecutionError};
use reth_revm::{
    Database as _, context::JournalTr, database::StateProviderDatabase, state::EvmState,
};
use reth_storage_api::{StateProvider as _, StateProviderBox, errors::ProviderResult};
use std::sync::{Arc, Mutex, mpsc};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{
    EXPIRING_NONCE_PRECOMPILE_ADDRESS,
    expiring_nonce::{ExpiringNonceManager, PruneCursor},
    storage::{StorageActions, StorageCtx},
};
use tempo_primitives::TempoBlockEnv;

// An explicit completion marker distinguishes success from a worker that exits early.
pub(crate) type PruneReceiver = mpsc::Receiver<Result<Option<EvmState>, BlockExecutionError>>;
pub(crate) type PruneTask = Arc<Mutex<Option<(mpsc::Sender<u64>, PruneReceiver)>>>;
pub(crate) const NONCES_PER_REQUEST: u64 = 256;
const NONCES_PER_CHUNK: u64 = 1024;

// Start on the first available credit batch; combine queued credits when behind.
fn prune_budgets(requests: &mpsc::Receiver<u64>) -> impl Iterator<Item = u64> + '_ {
    requests.iter().map(move |mut limit| {
        while limit <= NONCES_PER_CHUNK - NONCES_PER_REQUEST {
            let Ok(next) = requests.try_recv() else { break };
            limit += next;
        }
        limit
    })
}

/// Runs the same pruning algorithm used by sequential execution and reconstruction.
pub(crate) fn prune<DB: Database, I>(
    evm: &mut TempoEvm<DB, I>,
    limit: u64,
) -> Result<EvmState, BlockExecutionError> {
    prune_chunk(evm, &mut PruneCursor::default(), limit).map(|(state, _)| state)
}

pub(crate) fn prune_chunk<DB: Database, I>(
    evm: &mut TempoEvm<DB, I>,
    cursor: &mut PruneCursor,
    limit: u64,
) -> Result<(EvmState, bool), BlockExecutionError> {
    let ctx = evm.ctx_mut();
    let done = StorageCtx::enter_evm_without_tip1060_accounting(
        &mut ctx.journaled_state,
        &ctx.block,
        &ctx.cfg,
        &ctx.tx,
        StorageActions::disabled(),
        || ExpiringNonceManager::new().prune_chunk(cursor, limit),
    )
    .map_err(BlockExecutionError::other)?;
    Ok((ctx.journaled_state.finalize(), done))
}

impl TempoEvmConfig {
    pub(crate) fn start_nonce_pruning(
        mut self,
        env: EvmEnv<TempoHardfork, TempoBlockEnv>,
        provider: impl FnOnce() -> ProviderResult<StateProviderBox> + Send + 'static,
    ) -> Result<Self, BlockExecutionError> {
        let (sender, receiver) = mpsc::sync_channel(2);
        let (budget, requests) = mpsc::channel();
        std::thread::Builder::new()
            .name("nonce-prune".into())
            .spawn(move || {
                let start = std::time::Instant::now();
                let block = env.block_env.number;
                let result = (|| {
                    let mut db = StateProviderDatabase::new(
                        provider()
                            .map_err(BlockExecutionError::other)?
                            .into_evm_state_provider(),
                    );
                    // Deployment initializes the cursor on the execution thread. There is
                    // nothing to prune in the parent of the deployment block.
                    let info = db.basic(EXPIRING_NONCE_PRECOMPILE_ADDRESS)
                        .map_err(BlockExecutionError::other)?;
                    if info.is_none_or(|info| info.is_empty_code_hash()) {
                        return Ok(());
                    }
                    let mut evm = TempoEvm::new(db, env);
                    let mut cursor = PruneCursor::default();
                    // Credits come only from committed expiring-nonce transactions.
                    // Closing requests finishes the block; dropping results cancels it.
                    for limit in prune_budgets(&requests) {
                        let chunk_start = std::time::Instant::now();
                        let (mut state, done) = prune_chunk(&mut evm, &mut cursor, limit)?;
                        for account in state.values_mut() {
                            account.storage.retain(|_, slot| slot.is_changed());
                        }
                        state.retain(|_, account| !account.storage.is_empty());
                        let slots: usize = state.values().map(|account| account.storage.len()).sum();
                        tracing::debug!(target: "tempo::nonce_prune", %block, limit, slots, elapsed = ?chunk_start.elapsed(), "Prepared nonce prune chunk");
                        // Cancellation releases the parent view without scanning more buckets.
                        if !state.is_empty() && sender.send(Ok(Some(state))).is_err() {
                            return Ok(());
                        }
                        if done {
                            return Ok(());
                        }
                    }
                    Ok(())
                })();
                tracing::debug!(target: "tempo::nonce_prune", %block, elapsed = ?start.elapsed(), "Background nonce pruning finished");
                // A cancelled payload drops its receiver; the worker then releases its
                // parent view and computed delta without changing any shared state.
                let _ = sender.send(result.map(|()| None));
            })
            .map_err(BlockExecutionError::other)?;
        self.nonce_prune = Some(Arc::new(Mutex::new(Some((budget, receiver)))));
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prune_budgets_start_early_and_coalesce_without_exceeding_limit() {
        let (sender, receiver) = mpsc::channel();
        let mut budgets = prune_budgets(&receiver);
        sender.send(NONCES_PER_REQUEST).unwrap();
        // Does not wait for a full chunk or for the sender to close.
        assert_eq!(budgets.next(), Some(NONCES_PER_REQUEST));

        for _ in 0..2 * NONCES_PER_CHUNK / NONCES_PER_REQUEST {
            sender.send(NONCES_PER_REQUEST).unwrap();
        }
        sender.send(3).unwrap();
        drop(sender);
        assert_eq!(
            budgets.collect::<Vec<_>>(),
            [NONCES_PER_CHUNK, NONCES_PER_CHUNK, 3]
        );
    }
}
