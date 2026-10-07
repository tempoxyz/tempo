//! Builder-local `advanceTempo` cache prewarming.
//!
//! Each queued deposit is executed in an independent throwaway Zone builder. Execution output is
//! discarded; only exact-L1 reads populate the cache shared with canonical execution.

use crate::builder::build_advance_tempo_tx_owned;
use alloy_evm::block::BlockExecutor;
use alloy_primitives::B256;
use reth_errors::ProviderError;
use reth_evm::{ConfigureEvm, Database, execute::BlockBuilder};
use reth_primitives_traits::SealedHeader;
use reth_revm::{State, database::StateProviderDatabase};
use reth_storage_api::{StateProvider, StateProviderFactory};
use reth_tasks::{TaskExecutor, cancel::ManualCancel};
use std::{error::Error, sync::Arc};
use tempo_evm::TempoNextBlockEnvAttributes;
use tempo_primitives::TempoHeader;
use tempo_zone_contracts::DepositType;
use zone_evm::ZoneEvmConfig;
use zone_l1::PreparedL1Block;

/// Immutable canonical inputs used to construct isolated prewarming workers.
pub(crate) struct PrewarmingExecutionContext<Provider> {
    pub(crate) provider: Provider,
    pub(crate) evm_config: ZoneEvmConfig,
    pub(crate) parent_hash: B256,
    pub(crate) parent_header: SealedHeader<TempoHeader>,
    pub(crate) next_block_env_attributes: TempoNextBlockEnvAttributes,
    pub(crate) chain_id: u64,
}

impl<Provider> PrewarmingExecutionContext<Provider>
where
    Provider: StateProviderFactory + Clone + 'static,
{
    /// Enqueue one disposable simulation per deposit directly on the prewarming pool.
    pub(crate) fn start(
        self,
        task_executor: &TaskExecutor,
        prepared: &PreparedL1Block,
    ) -> AdvanceTempoPrewarming {
        let handle = AdvanceTempoPrewarming::default();
        if prepared.queued_deposits.is_empty() {
            return handle;
        }

        let context = Arc::new(self);
        let pool = task_executor.prewarming_pool();
        let mut decryptions = prepared.decryptions.iter();

        // The pool bounds concurrency; cancelled queued jobs skip EVM initialization.
        for deposit in &prepared.queued_deposits {
            let decryptions = (deposit.depositType == DepositType::Deposit)
                .then(|| decryptions.next().cloned())
                .flatten()
                .into_iter()
                .collect();
            let partial = PreparedL1Block {
                header: prepared.header.clone(),
                enabled_tokens: prepared.enabled_tokens.clone(),
                queued_deposits: vec![deposit.clone()],
                decryptions,
                follows_checkpoint_blocks: false,
            };
            let context = context.clone();
            let cancel = handle.cancel.clone();
            pool.spawn(move || {
                if !cancel.is_cancelled() {
                    let _ = context.prewarm_deposit(partial);
                }
            });
        }

        handle
    }

    fn prewarm_deposit(
        &self,
        partial: PreparedL1Block,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let state = StateProviderDatabase::new(
            self.provider
                .state_by_block_hash(self.parent_hash)?
                .into_evm_state_provider(),
        );
        let mut db = State::builder()
            .with_database(Box::new(state) as Box<dyn Database<Error = ProviderError>>)
            .with_bundle_update()
            .build();

        let mut worker = self.evm_config.builder_for_next_block(
            &mut db,
            &self.parent_header,
            self.next_block_env_attributes.clone(),
        )?;
        worker.apply_pre_execution_changes()?;

        // Queue-hash validation may fail, but preceding reads have already warmed the shared cache.
        _ = worker
            .executor_mut()
            .execute_transaction_without_commit(build_advance_tempo_tx_owned(
                partial,
                self.chain_id,
            ));
        Ok(())
    }
}

/// Cancels queued work that has not started when dropped.
#[derive(Debug, Default)]
pub(crate) struct AdvanceTempoPrewarming {
    cancel: ManualCancel,
}

impl Drop for AdvanceTempoPrewarming {
    fn drop(&mut self) {
        self.cancel.clone().cancel();
    }
}
