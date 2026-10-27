//! Builder-local L1 cache prewarming.
//!
//! Each queued deposit is executed in an independent throwaway Zone builder, and pool transactions
//! are simulated against the state after `advanceTempo`. Execution output is discarded; only
//! exact-L1 reads populate the cache shared with canonical execution.

use crate::builder::build_advance_tempo_tx_owned;
use alloy_evm::block::BlockExecutor;
use alloy_primitives::B256;
use reth_errors::ProviderError;
use reth_evm::{ConfigureEvm, Database, Evm, EvmEnvFor, execute::BlockBuilder};
use reth_primitives_traits::SealedHeader;
use reth_revm::{State, database::StateProviderDatabase, db::CacheState};
use reth_storage_api::{StateProvider, StateProviderFactory};
use reth_tasks::{TaskExecutor, cancel::ManualCancel};
use reth_transaction_pool::ValidPoolTransaction;
use std::{error::Error, sync::Arc};
use tempo_contracts::zones::DepositType;
use tempo_evm::TempoNextBlockEnvAttributes;
use tempo_primitives::TempoHeader;
use tempo_transaction_pool::transaction::TempoPooledTransaction;
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
    pub(crate) fn start_deposits(
        self: &Arc<Self>,
        task_executor: &TaskExecutor,
        prepared: &PreparedL1Block,
    ) -> Prewarming {
        let handle = Prewarming::default();
        if prepared.queued_deposits.is_empty() {
            return handle;
        }

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
            let context = self.clone();
            let cancel = handle.cancel.clone();
            pool.spawn(move || {
                if !cancel.is_cancelled() {
                    let _ = context.prewarm_deposit(partial);
                }
            });
        }

        handle
    }

    /// Simulate `transactions` on the prewarming pool so their L1 cache misses are fetched in
    /// parallel rather than one at a time during canonical execution.
    ///
    /// `opened` is the builder's state cache after `advanceTempo`, which selects the L1 block that
    /// reads resolve at. Nonce and balance checks are disabled so a transaction still runs when an
    /// earlier one in the block funds it or uses the preceding nonce.
    pub(crate) fn start_pool_transactions(
        self: &Arc<Self>,
        task_executor: &TaskExecutor,
        mut evm_env: EvmEnvFor<ZoneEvmConfig>,
        opened: &CacheState,
        transactions: Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
    ) -> Prewarming {
        let handle = Prewarming::default();
        if transactions.is_empty() {
            return handle;
        }

        evm_env.cfg_env.disable_nonce_check = true;
        evm_env.cfg_env.disable_balance_check = true;
        let evm_env = Arc::new(evm_env);
        let opened = Arc::new(opened.clone());
        let transactions: Arc<[_]> = transactions.into();
        let pool = task_executor.prewarming_pool();
        let workers = pool.current_num_threads().clamp(1, transactions.len());

        // Each worker takes every `workers`-th transaction from its index, so the transactions
        // canonical execution reaches first are fetched first.
        for worker in 0..workers {
            let context = self.clone();
            let evm_env = evm_env.clone();
            let opened = opened.clone();
            let transactions = transactions.clone();
            let cancel = handle.cancel.clone();
            pool.spawn(move || {
                let transactions = transactions.iter().skip(worker).step_by(workers);
                let _ = context.prewarm_pool_transactions(&evm_env, &opened, transactions, &cancel);
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

        // Disabling both checks marks the reads as prewarming (see `ZoneEvm::transact_raw`).
        let mut evm_env = self
            .evm_config
            .next_evm_env(&self.parent_header, &self.next_block_env_attributes)?;
        evm_env.cfg_env.disable_nonce_check = true;
        evm_env.cfg_env.disable_balance_check = true;
        let evm = self.evm_config.evm_with_env(&mut db, evm_env);
        let ctx = self
            .evm_config
            .context_for_next_block(&self.parent_header, self.next_block_env_attributes.clone())?;
        let mut worker = self
            .evm_config
            .create_block_builder(evm, &self.parent_header, ctx);
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

    fn prewarm_pool_transactions<'a>(
        &self,
        evm_env: &EvmEnvFor<ZoneEvmConfig>,
        opened: &CacheState,
        transactions: impl Iterator<Item = &'a Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
        cancel: &ManualCancel,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Skips opening state and cloning the cache for a build that has already finished.
        if cancel.is_cancelled() {
            return Ok(());
        }
        let state = StateProviderDatabase::new(
            self.provider
                .state_by_block_hash(self.parent_hash)?
                .into_evm_state_provider(),
        );
        let mut db = State::builder()
            .with_database(Box::new(state) as Box<dyn Database<Error = ProviderError>>)
            .with_cached_prestate(opened.clone())
            .build();
        let mut evm = self.evm_config.evm_with_env(&mut db, evm_env.clone());

        for tx in transactions {
            if cancel.is_cancelled() {
                break;
            }
            // Reads made before a failure have already warmed the shared cache.
            _ = evm.transact(tx.transaction.clone_tx_env());
        }
        Ok(())
    }
}

/// Cancels queued work that has not started when dropped.
#[derive(Debug, Default)]
pub(crate) struct Prewarming {
    cancel: ManualCancel,
}

impl Drop for Prewarming {
    fn drop(&mut self) {
        self.cancel.clone().cancel();
    }
}
