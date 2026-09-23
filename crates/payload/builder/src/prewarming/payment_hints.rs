//! Advisory reads for direct TIP-20 transfers, without touching an EVM journal.

use alloy_primitives::{Address, TxKind, U256};
use reth_evm::Database;
use reth_transaction_pool::PoolTransaction;
use tempo_contracts::precompiles::PaymentSlots;
use tempo_precompiles::{
    NONCE_PRECOMPILE_ADDRESS, TIP_FEE_MANAGER_ADDRESS, TIP403_REGISTRY_ADDRESS,
    nonce::NonceManager, storage::StorageKey, tip_fee_manager::TipFeeManager, tip20::tip20_slots,
    tip403_registry::tip403_registry_slots,
};
use tempo_primitives::TempoAddressExt;
use tempo_transaction_pool::transaction::TempoPooledTransaction;

pub(super) const MAX_READS: usize = 128;
const MAX_CALLS: usize = 16;

pub(super) fn prewarm(
    db: &mut impl Database,
    tx: &TempoPooledTransaction,
    beneficiary: Address,
) -> bool {
    visit(tx, beneficiary, |address, slot| {
        // A failed hint cannot reject a transaction. Ordered execution still
        // performs its ordinary reads and propagates the authoritative error.
        if let Some(slot) = slot {
            let _ = db.storage(address, slot);
        } else {
            let _ = db.basic(address);
        }
    })
}

pub(super) fn visit(
    tx: &TempoPooledTransaction,
    beneficiary: Address,
    mut read: impl FnMut(Address, Option<U256>),
) -> bool {
    if !tx.is_payment() {
        return false;
    }
    let mut calls = 0;
    for (kind, input) in tx.inner().calls() {
        calls += 1;
        if calls > MAX_CALLS
            || !matches!(kind, TxKind::Call(token) if token.is_tip20())
            || !matches!(
                input.get(..4),
                Some(
                    [0xa9, 0x05, 0x9c, 0xbb]
                        | [0x95, 0x77, 0x7d, 0x59]
                        | [0x23, 0xb8, 0x72, 0xdd]
                        | [0x92, 0x9c, 0x25, 0x39]
                )
            )
            || PaymentSlots::classify(input).is_none()
        {
            return false;
        }
    }
    if calls == 0 {
        return false;
    }

    let mut remaining = MAX_READS;
    let mut emit = |address, slot| {
        if remaining > 0 {
            remaining -= 1;
            read(address, slot);
        }
    };
    let sender = tx.sender();
    emit(sender, None);
    if let Ok(payer) = tx.fee_payer() {
        emit(payer, None);
        emit(
            TIP_FEE_MANAGER_ADDRESS,
            Some(TipFeeManager::new().user_tokens[payer].slot()),
        );
    }
    if let Some((token, slot)) = tx.fee_balance_slot() {
        emit(token, None);
        emit(token, Some(slot));
        emit(
            token,
            Some(TIP_FEE_MANAGER_ADDRESS.mapping_slot(tip20_slots::BALANCES)),
        );
        emit(token, Some(tip20_slots::CURRENCY));
    }
    emit(
        TIP_FEE_MANAGER_ADDRESS,
        Some(TipFeeManager::new().validator_tokens[beneficiary].slot()),
    );
    if tx.is_expiring_nonce() {
        emit(NONCE_PRECOMPILE_ADDRESS, tx.expiring_nonce_slot());
        emit(
            NONCE_PRECOMPILE_ADDRESS,
            Some(NonceManager::new().expiring_nonce_ring_ptr.slot()),
        );
    } else if tx.nonce_key_ref().is_some_and(|key| !key.is_zero()) {
        emit(NONCE_PRECOMPILE_ADDRESS, tx.nonce_key_slot());
    }

    for (kind, input) in tx.inner().calls() {
        let TxKind::Call(token) = kind else {
            unreachable!()
        };
        let payment = PaymentSlots::classify(input).expect("classified above");
        emit(token, None);
        emit(token, Some(sender.mapping_slot(tip20_slots::BALANCES)));
        emit(token, Some(tip20_slots::PAUSED));
        emit(token, Some(tip20_slots::TRANSFER_POLICY_ID));
        emit(
            TIP403_REGISTRY_ADDRESS,
            Some(token.mapping_slot(tip403_registry_slots::TOKEN_TRANSFER_POLICIES)),
        );
        for &address in payment.addresses() {
            emit(token, Some(address.mapping_slot(tip20_slots::BALANCES)));
        }
        if let Some(to) = payment.to() {
            emit(
                TIP403_REGISTRY_ADDRESS,
                Some(to.mapping_slot(tip403_registry_slots::RECEIVE_POLICIES)),
            );
        }
        if let Some(from) = payment.from() {
            emit(
                token,
                Some(sender.mapping_slot(from.mapping_slot(tip20_slots::ALLOWANCES))),
            );
        }
    }
    true
}
