//! Independent nonce pruning against a pinned parent-state provider.

use crate::{TempoEvmConfig, evm::TempoEvm};
use alloy_evm::{Database, EvmEnv, block::BlockExecutionError};
use reth_revm::{
    Database as _, context::JournalTr, database::StateProviderDatabase, state::EvmState,
};
use reth_storage_api::{StateProviderBox, errors::ProviderResult};
use std::sync::{Arc, Mutex, mpsc};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{
    EXPIRING_NONCE_PRECOMPILE_ADDRESS,
    expiring_nonce::ExpiringNonceManager,
    storage::{StorageActions, StorageCtx},
};
use tempo_primitives::TempoBlockEnv;

pub(crate) type PruneReceiver = mpsc::Receiver<Result<EvmState, BlockExecutionError>>;
pub(crate) type PruneTask = Arc<Mutex<Option<PruneReceiver>>>;

/// Runs the same pruning algorithm used by sequential execution and reconstruction.
pub(crate) fn prune<DB: Database, I>(
    evm: &mut TempoEvm<DB, I>,
) -> Result<EvmState, BlockExecutionError> {
    let ctx = evm.ctx_mut();
    StorageCtx::enter_evm_without_tip1060_accounting(
        &mut ctx.journaled_state,
        &ctx.block,
        &ctx.cfg,
        &ctx.tx,
        StorageActions::disabled(),
        || ExpiringNonceManager::new().prune(),
    )
    .map_err(BlockExecutionError::other)?;
    Ok(ctx.journaled_state.finalize())
}

impl TempoEvmConfig {
    pub(crate) fn start_nonce_pruning(
        mut self,
        env: EvmEnv<TempoHardfork, TempoBlockEnv>,
        provider: impl FnOnce() -> ProviderResult<StateProviderBox> + Send + 'static,
    ) -> Result<Self, BlockExecutionError> {
        let (sender, receiver) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("nonce-prune".into())
            .spawn(move || {
                let start = std::time::Instant::now();
                let block = env.block_env.number;
                let result = (|| {
                    let mut db = StateProviderDatabase::new(provider().map_err(BlockExecutionError::other)?);
                    // Deployment initializes the cursor on the execution thread. There is
                    // nothing to prune in the parent of the deployment block.
                    let info = db.basic(EXPIRING_NONCE_PRECOMPILE_ADDRESS)
                        .map_err(BlockExecutionError::other)?;
                    if info.is_none_or(|info| info.is_empty_code_hash()) {
                        return Ok(EvmState::default());
                    }
                    let mut evm = TempoEvm::new(db, env);
                    let mut state = prune(&mut evm)?;
                    for account in state.values_mut() {
                        account.storage.retain(|_, slot| slot.is_changed());
                    }
                    state.retain(|_, account| !account.storage.is_empty());
                    Ok(state)
                })();
                tracing::debug!(target: "tempo::nonce_prune", %block, elapsed = ?start.elapsed(), "Background nonce pruning finished");
                // A cancelled payload drops its receiver; the worker then releases its
                // parent view and computed delta without changing any shared state.
                let _ = sender.send(result);
            })
            .map_err(BlockExecutionError::other)?;
        self.nonce_prune = Some(Arc::new(Mutex::new(Some(receiver))));
        Ok(self)
    }
}
