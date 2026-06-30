use alloy_primitives::U256;
use reth_revm::ExecuteEvm;
use reth_storage_api::StateProviderFactory;
use reth_tasks::WorkerPool;
use tempo_evm::{ExpiringNonceReplay, StorageActionReplay};
use tempo_transaction_pool::best::BestTransaction;
use tracing::trace;

use crate::prewarming::{PrewarmedTransaction, PrewarmingExecutionContext};

pub(crate) fn plan_transaction_replay<Provider>(
    prewarm: PrewarmingExecutionContext<Provider>,
    tx: BestTransaction,
    expiring_nonce_offset: Option<usize>,
) -> PrewarmedTransaction
where
    Provider: StateProviderFactory + Clone + 'static,
{
    if prewarm.is_stopped() {
        return PrewarmedTransaction { tx, replay: None };
    }

    let replay = WorkerPool::with_worker_mut(|worker| {
        if !is_replay_candidate(&tx) {
            return None;
        }

        let Some(evm) = worker.get_or_init(|| prewarm.evm_for_ctx()) else {
            return None;
        };

        let tx_hash = *tx.hash();

        if prewarm.is_stopped() {
            return None;
        }

        let expiring_nonce = tx
            .transaction
            .is_expiring_nonce()
            .then(|| {
                let valid_before = tx
                    .transaction
                    .tx_env()
                    .tempo_tx_env
                    .as_ref()?
                    .valid_before?;
                Some(ExpiringNonceReplay {
                    hash: tx.transaction.expiring_nonce_hash()?,
                    valid_before,
                })
            })
            .flatten();
        let mut tx_env = tx.transaction.clone_tx_env();
        if let Some(tempo_tx_env) = tx_env.tempo_tx_env.as_mut() {
            tempo_tx_env.expiring_nonce_idx = expiring_nonce_offset;
        }

        let result = match evm.inner_mut().transact(tx_env) {
            Ok(result) => result,
            Err(err) => {
                evm.clear_actions();
                trace!(
                    target: "payload_builder",
                    %err,
                    ?tx_hash,
                    "Failed to collect prewarm storage actions"
                );
                return None;
            }
        }
        .result;

        Some(Box::new(StorageActionReplay {
            result,
            actions: evm.take_actions()?,
            validator_fee: evm.validator_fee(),
            expiring_nonce,
        }))
    });

    PrewarmedTransaction { tx, replay }
}

fn is_replay_candidate(tx: &BestTransaction) -> bool {
    if !tx.transaction.is_payment() {
        return false;
    }
    if tx
        .transaction
        .nonce_key()
        .is_none_or(|nonce_key| nonce_key == U256::ZERO)
    {
        return false;
    }

    true
}
