use reth_revm::ExecuteEvm;
use reth_storage_api::StateProviderFactory;
use reth_tasks::WorkerPool;
use tempo_evm::{ExpiringNonceReplay, StorageActionReplay, evm::TempoEvm};
use tempo_precompiles::storage::StorageAction;
use tempo_transaction_pool::best::BestTransaction;
use tracing::trace;

use crate::prewarming::{PrewarmEvmState, PrewarmedTransaction, PrewarmingExecutionContext};

pub(crate) fn plan_transaction_replay<Provider>(
    prewarm: PrewarmingExecutionContext<Provider>,
    tx: BestTransaction,
    mut action_buffer: Option<Vec<StorageAction>>,
    expiring_nonce_offset: Option<usize>,
) -> PrewarmedTransaction
where
    Provider: StateProviderFactory + Clone + 'static,
{
    if prewarm.is_stopped() {
        return PrewarmedTransaction {
            tx,
            replay: None,
            action_buffer,
        };
    }

    let replay = WorkerPool::with_worker_mut(|worker| {
        let Some(evm) = worker
            .get_or_init::<PrewarmEvmState>(|| prewarm.evm_for_ctx().map(TempoEvm::with_actions))
        else {
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
                    "Failed to prewarm transaction for replay"
                );
                return None;
            }
        }
        .result;

        if !result.is_success() {
            evm.clear_actions();
            trace!(
                target: "payload_builder",
                ?tx_hash,
                result = ?result,
                "Prewarm action collection produced non-success result"
            );
            return None;
        }

        let actions = evm.replace_actions(action_buffer.take().unwrap_or_default())?;
        Some(Box::new(StorageActionReplay {
            result,
            actions,
            validator_fee: evm.validator_fee(),
            expiring_nonce,
        }))
    });

    PrewarmedTransaction {
        tx,
        replay,
        action_buffer,
    }
}
