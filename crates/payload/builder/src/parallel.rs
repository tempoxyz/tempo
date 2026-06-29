use alloy_primitives::{Address, TxKind};
use alloy_sol_types::SolInterface;
use reth_evm::RecoveredTx;
use reth_revm::{ExecuteEvm, context::Transaction as _};
use reth_storage_api::StateProviderFactory;
use reth_tasks::WorkerPool;
use tempo_contracts::precompiles::ITIP20;
use tempo_evm::{ExpiringNonceReplay, StorageActionReplay, evm::TempoEvm};
use tempo_precompiles::{NONCE_PRECOMPILE_ADDRESS, storage::StorageAction};
use tempo_primitives::TempoAddressExt;
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

        if !is_storage_action_replay_candidate(&tx) {
            evm.clear_actions();
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

        let mut actions = evm.replace_actions(action_buffer.take().unwrap_or_default())?;

        // Filter out expiring nonce actions, they will be handled separately
        if expiring_nonce.is_some() {
            actions.retain(|action| !is_nonce_manager_action(action));
        }

        if actions.is_empty() && expiring_nonce.is_none() {
            action_buffer = Some(actions);
            return None;
        }

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

fn is_storage_action_replay_candidate(tx: &BestTransaction) -> bool {
    let tx_env = tx.transaction.tx_env();

    if tx.transaction.inner().tx().subblock_proposer().is_some() {
        return false;
    }
    if !tx_env.value().is_zero() {
        return false;
    }
    if tx_env
        .access_list()
        .is_some_and(|mut access_list| access_list.next().is_some())
    {
        return false;
    }
    if tx_env.authorization_list_len() != 0 {
        return false;
    }

    let Some(aa_env) = tx_env.tempo_tx_env.as_ref() else {
        return false;
    };
    if !aa_env.tempo_authorization_list.is_empty() {
        return false;
    }
    if aa_env.key_authorization.is_some() {
        return false;
    }
    if tx_env.nonce() != 0 {
        return false;
    }
    if tx
        .transaction
        .inner()
        .tx()
        .as_aa()
        .is_some_and(|aa| aa.signature().as_keychain().is_some())
    {
        return false;
    }
    if tx_env.fee_payer().is_err() {
        return false;
    }

    let mut calls = tx_env.calls();
    let Some((kind, input)) = calls.next() else {
        return false;
    };
    if !is_valid_tip20_transfer_call(*kind, input) {
        return false;
    }
    calls.next().is_none()
}

fn is_valid_tip20_transfer_call(kind: TxKind, input: &[u8]) -> bool {
    let TxKind::Call(token) = kind else {
        return false;
    };
    if !token.is_tip20() {
        return false;
    }

    match ITIP20::ITIP20Calls::abi_decode(input) {
        Ok(ITIP20::ITIP20Calls::transfer(call)) => is_valid_direct_recipient(call.to),
        Ok(ITIP20::ITIP20Calls::transferWithMemo(call)) => is_valid_direct_recipient(call.to),
        Ok(ITIP20::ITIP20Calls::transferFrom(_))
        | Ok(ITIP20::ITIP20Calls::transferFromWithMemo(_))
        | Ok(_) => false,
        Err(_) => false,
    }
}

fn is_valid_direct_recipient(to: Address) -> bool {
    !to.is_zero() && !to.is_tip20() && !to.is_virtual()
}

fn is_nonce_manager_action(action: &StorageAction) -> bool {
    let address = match *action {
        StorageAction::Sload(address, ..)
        | StorageAction::Sstore(address, ..)
        | StorageAction::Sinc(address, ..)
        | StorageAction::Sdec(address, ..)
        | StorageAction::FeeAmmSwap(address, ..) => address,
    };
    address == NONCE_PRECOMPILE_ADDRESS
}
