//! Storage prewarming helpers for transactions that have entered the pool.

use crate::transaction::TempoPooledTransaction;
use alloy_consensus::Transaction as _;
use alloy_primitives::{Address, TxKind, U256};
use alloy_sol_types::SolInterface;
use reth_storage_api::{StateProvider, errors::ProviderError};
use reth_transaction_pool::PoolTransaction;
use tempo_precompiles::{
    DEFAULT_FEE_TOKEN, NONCE_PRECOMPILE_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
    nonce::slots as nonce_slots,
    storage::StorageKey as _,
    tip_fee_manager::slots as fee_manager_slots,
    tip20::{ITIP20, tip20_slots},
};
use tempo_primitives::TempoAddressExt;
use tempo_revm::TempoStorageTouch;

/// Reads and discards predicted execution-time storage for a transaction.
///
/// This is intentionally best-effort at the caller boundary: callers decide whether
/// a read error should fail their current operation or only be traced.
pub(crate) fn prewarm_transaction_storage<P>(
    provider: &P,
    transaction: &TempoPooledTransaction,
    fee_recipient: Address,
) -> Result<usize, ProviderError>
where
    P: StateProvider + ?Sized,
{
    if transaction.tx_env().prewarm_storage_touches().is_empty() {
        let touches = storage_touches_for_transaction(transaction, fee_recipient);
        transaction.tx_env().set_prewarm_storage_touches(touches);
    }

    let touches = transaction.tx_env().prewarm_storage_touches();
    for touch in touches {
        warm_state_provider(touch, provider)?;
    }
    Ok(touches.len())
}

/// Reads this touch from a reth [`StateProvider`] and discards the value.
fn warm_state_provider<P>(touch: &TempoStorageTouch, provider: &P) -> Result<(), ProviderError>
where
    P: StateProvider + ?Sized,
{
    match *touch {
        TempoStorageTouch::Account(address) => {
            let _ = provider.basic_account(&address)?;
        }
        TempoStorageTouch::Storage { address, slot } => {
            let _ = provider.storage(address, slot.into())?;
        }
    }

    Ok(())
}

/// Predicts the storage locations touched by Tempo fee handling and TIP-20 payments.
fn storage_touches_for_transaction(
    tx: &TempoPooledTransaction,
    fee_recipient: Address,
) -> Vec<TempoStorageTouch> {
    let mut touches = Vec::new();
    let sender = tx.sender();
    let fee_payer = tx.inner().fee_payer(sender).unwrap_or(sender);
    let fee_token = tx
        .resolved_fee_token()
        .unwrap_or_else(|| tx.inner().fee_token().unwrap_or(DEFAULT_FEE_TOKEN));

    add_access_list_touches(&mut touches, tx);
    add_tip20_fee_touches(&mut touches, fee_token, fee_payer);
    add_fee_manager_touches(&mut touches, fee_recipient, fee_token);

    if tx.is_payment() {
        for (kind, input) in tx.inner().calls() {
            add_tip20_call_touches(&mut touches, sender, kind, input);
        }
    }

    add_expiring_nonce_touches(&mut touches, tx);

    touches
}

fn add_access_list_touches(touches: &mut Vec<TempoStorageTouch>, tx: &TempoPooledTransaction) {
    let Some(access_list) = tx.access_list() else {
        return;
    };

    for item in &access_list.0 {
        add_account_touch(touches, item.address);
        for storage_key in &item.storage_keys {
            add_storage_touch(touches, item.address, U256::from_be_bytes(storage_key.0));
        }
    }
}

fn add_tip20_fee_touches(
    touches: &mut Vec<TempoStorageTouch>,
    fee_token: Address,
    fee_payer: Address,
) {
    if !fee_token.is_tip20() {
        return;
    }

    add_tip20_common_touches(touches, fee_token);
    add_tip20_balance_touch(touches, fee_token, fee_payer);
    add_tip20_balance_touch(touches, fee_token, TIP_FEE_MANAGER_ADDRESS);
    add_tip20_reward_touches(touches, fee_token, fee_payer);
}

fn add_tip20_call_touches(
    touches: &mut Vec<TempoStorageTouch>,
    sender: Address,
    kind: TxKind,
    input: &[u8],
) {
    let Some(token) = kind.to().copied() else {
        return;
    };
    if !token.is_tip20() {
        return;
    }

    add_tip20_common_touches(touches, token);
    let Ok(call) = ITIP20::ITIP20Calls::abi_decode(input) else {
        return;
    };

    match call {
        ITIP20::ITIP20Calls::transfer(call) => {
            add_tip20_balance_touch(touches, token, sender);
            add_tip20_balance_touch(touches, token, call.to);
            add_tip20_reward_touches(touches, token, sender);
            add_tip20_reward_touches(touches, token, call.to);
        }
        ITIP20::ITIP20Calls::transferWithMemo(call) => {
            add_tip20_balance_touch(touches, token, sender);
            add_tip20_balance_touch(touches, token, call.to);
            add_tip20_reward_touches(touches, token, sender);
            add_tip20_reward_touches(touches, token, call.to);
        }
        ITIP20::ITIP20Calls::transferFrom(call) => {
            add_tip20_balance_touch(touches, token, call.from);
            add_tip20_balance_touch(touches, token, call.to);
            add_tip20_allowance_touch(touches, token, call.from, sender);
            add_tip20_reward_touches(touches, token, call.from);
            add_tip20_reward_touches(touches, token, call.to);
        }
        ITIP20::ITIP20Calls::transferFromWithMemo(call) => {
            add_tip20_balance_touch(touches, token, call.from);
            add_tip20_balance_touch(touches, token, call.to);
            add_tip20_allowance_touch(touches, token, call.from, sender);
            add_tip20_reward_touches(touches, token, call.from);
            add_tip20_reward_touches(touches, token, call.to);
        }
        ITIP20::ITIP20Calls::approve(call) => {
            add_tip20_allowance_touch(touches, token, sender, call.spender);
        }
        ITIP20::ITIP20Calls::mint(call) => {
            add_tip20_balance_touch(touches, token, call.to);
            add_tip20_reward_touches(touches, token, call.to);
        }
        ITIP20::ITIP20Calls::mintWithMemo(call) => {
            add_tip20_balance_touch(touches, token, call.to);
            add_tip20_reward_touches(touches, token, call.to);
        }
        ITIP20::ITIP20Calls::burn(_) | ITIP20::ITIP20Calls::burnWithMemo(_) => {
            add_tip20_balance_touch(touches, token, sender);
            add_tip20_reward_touches(touches, token, sender);
        }
        _ => {}
    }
}

fn add_tip20_common_touches(touches: &mut Vec<TempoStorageTouch>, token: Address) {
    add_account_touch(touches, token);
    add_storage_touch(touches, token, tip20_slots::CURRENCY);
    add_storage_touch(touches, token, tip20_slots::PAUSED);
    add_storage_touch(touches, token, tip20_slots::TRANSFER_POLICY_ID);
    add_storage_touch(touches, token, tip20_slots::GLOBAL_REWARD_PER_TOKEN);
    add_storage_touch(touches, token, tip20_slots::OPTED_IN_SUPPLY);
}

fn add_tip20_balance_touch(touches: &mut Vec<TempoStorageTouch>, token: Address, account: Address) {
    add_storage_touch(touches, token, account.mapping_slot(tip20_slots::BALANCES));
}

fn add_tip20_allowance_touch(
    touches: &mut Vec<TempoStorageTouch>,
    token: Address,
    owner: Address,
    spender: Address,
) {
    add_storage_touch(
        touches,
        token,
        spender.mapping_slot(owner.mapping_slot(tip20_slots::ALLOWANCES)),
    );
}

fn add_tip20_reward_touches(
    touches: &mut Vec<TempoStorageTouch>,
    token: Address,
    account: Address,
) {
    let base_slot = account.mapping_slot(tip20_slots::USER_REWARD_INFO);
    add_storage_touch(touches, token, base_slot);
    add_storage_touch(touches, token, base_slot + U256::from(1));
    add_storage_touch(touches, token, base_slot + U256::from(2));
}

fn add_fee_manager_touches(
    touches: &mut Vec<TempoStorageTouch>,
    fee_recipient: Address,
    fee_token: Address,
) {
    add_account_touch(touches, TIP_FEE_MANAGER_ADDRESS);
    add_storage_touch(
        touches,
        TIP_FEE_MANAGER_ADDRESS,
        fee_recipient.mapping_slot(fee_manager_slots::VALIDATOR_TOKENS),
    );
    add_storage_touch(
        touches,
        TIP_FEE_MANAGER_ADDRESS,
        fee_token.mapping_slot(fee_recipient.mapping_slot(fee_manager_slots::COLLECTED_FEES)),
    );
}

fn add_expiring_nonce_touches(touches: &mut Vec<TempoStorageTouch>, tx: &TempoPooledTransaction) {
    let Some(expiring_nonce_slot) = tx.expiring_nonce_slot() else {
        return;
    };

    add_account_touch(touches, NONCE_PRECOMPILE_ADDRESS);
    add_storage_touch(touches, NONCE_PRECOMPILE_ADDRESS, expiring_nonce_slot);
    add_storage_touch(
        touches,
        NONCE_PRECOMPILE_ADDRESS,
        nonce_slots::EXPIRING_NONCE_RING_PTR,
    );
}

fn add_account_touch(touches: &mut Vec<TempoStorageTouch>, address: Address) {
    add_unique_touch(touches, TempoStorageTouch::Account(address));
}

fn add_storage_touch(touches: &mut Vec<TempoStorageTouch>, address: Address, slot: U256) {
    add_account_touch(touches, address);
    add_unique_touch(touches, TempoStorageTouch::Storage { address, slot });
}

fn add_unique_touch(touches: &mut Vec<TempoStorageTouch>, touch: TempoStorageTouch) {
    if !touches.contains(&touch) {
        touches.push(touch);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TxBuilder;
    use alloy_eips::eip2930::{AccessList, AccessListItem};
    use alloy_primitives::B256;
    use alloy_sol_types::SolCall;

    #[test]
    fn tip20_touch_collection_dedups_overlapping_fee_and_call_slots() {
        let sender = Address::random();
        let recipient = Address::random();
        let token = DEFAULT_FEE_TOKEN;
        let mut touches = Vec::new();

        add_tip20_fee_touches(&mut touches, token, sender);
        add_tip20_call_touches(
            &mut touches,
            sender,
            TxKind::Call(token),
            &ITIP20::transferCall {
                to: recipient,
                amount: U256::from(1),
            }
            .abi_encode(),
        );

        for (index, touch) in touches.iter().enumerate() {
            assert!(
                !touches[index + 1..].contains(touch),
                "duplicate storage prewarm touch: {touch:?}"
            );
        }

        assert!(touches.contains(&TempoStorageTouch::Account(token)));
        assert!(touches.contains(&TempoStorageTouch::Storage {
            address: token,
            slot: sender.mapping_slot(tip20_slots::BALANCES)
        }));
        assert!(touches.contains(&TempoStorageTouch::Storage {
            address: token,
            slot: recipient.mapping_slot(tip20_slots::BALANCES)
        }));
    }

    #[test]
    fn access_list_touches_are_included() {
        let account = Address::random();
        let storage_key = B256::repeat_byte(0x42);
        let tx = TxBuilder::aa(Address::random())
            .access_list(AccessList(vec![AccessListItem {
                address: account,
                storage_keys: vec![storage_key],
            }]))
            .build();

        let touches = storage_touches_for_transaction(&tx, Address::random());

        assert!(touches.contains(&TempoStorageTouch::Account(account)));
        assert!(touches.contains(&TempoStorageTouch::Storage {
            address: account,
            slot: U256::from_be_bytes(storage_key.0)
        }));
    }
}
