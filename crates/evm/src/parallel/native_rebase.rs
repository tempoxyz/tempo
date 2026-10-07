//! A narrowly certified T14 channel-reserve custody increment.
//!
//! `open` makes no external EVM calls and its return value/logs do not depend on
//! the aggregate custody balance. The native recorder proves that this balance
//! is used only by one metered increment. Keeping its complete SSTORE gas class
//! unchanged also keeps T14 storage credits unchanged. Every other dependency
//! still passes the ordinary ordered validator.

use super::*;
use alloy_primitives::TxKind;
use alloy_sol_types::SolCall;
use tempo_precompiles::{
    TIP20_CHANNEL_RESERVE_ADDRESS,
    storage::native_increment::{NativeIncrementTarget, NativeIncrementWitness},
    tip20::{is_tip20_prefix, slots as tip20_slots},
    tip20_channel_reserve::ITIP20ChannelReserve,
};

pub(super) fn target(tx: &TempoTxEnv, env: &Env) -> Option<NativeIncrementTarget> {
    if env.cfg_env.spec != TempoHardfork::T14
        || env.cfg_env.enable_amsterdam_eip8037
        || tx.is_system_tx
        || tx.inner.tx_type != tempo_primitives::TempoTxType::AA as u8
    {
        return None;
    }
    let aa = tx.tempo_tx_env.as_ref()?;
    let [call] = aa.aa_calls.as_slice() else {
        return None;
    };
    if call.to != TxKind::Call(TIP20_CHANNEL_RESERVE_ADDRESS) || !call.value.is_zero() {
        return None;
    }
    // Ordinary transactions never clone or compare the gas table for this path.
    if tx.inner.caller == TIP20_CHANNEL_RESERVE_ADDRESS
        || tx.fee_payer().ok()? == TIP20_CHANNEL_RESERVE_ADDRESS
        || !tx.inner.authorization_list.is_empty()
        || !aa.tempo_authorization_list.is_empty()
        || aa.key_authorization.is_some()
        || !tempo_revm::gas_params::matches_tempo_gas_params(
            &env.cfg_env.gas_params,
            TempoHardfork::T14,
        )
    {
        return None;
    }
    let open = ITIP20ChannelReserve::openCall::abi_decode(&call.input).ok()?;
    if !is_tip20_prefix(open.token) || open.deposit.is_zero() {
        return None;
    }
    let slot = TIP20_CHANNEL_RESERVE_ADDRESS.mapping_slot(tip20_slots::BALANCES);
    if tx
        .inner
        .access_list
        .0
        .iter()
        .any(|item| item.address == open.token && item.storage_keys.contains(&B256::from(slot)))
    {
        return None;
    }
    Some(NativeIncrementTarget {
        address: open.token,
        slot,
        delta: U256::from(open.deposit),
    })
}

/// Tie the journal witness to one exact database dependency and the final result.
/// A failed transaction, reverted increment or any overlapping fee annotation
/// retains ordinary validation. No result can be certified from action logs alone.
pub(super) fn certify(
    witness: Option<NativeIncrementWitness>,
    result: Option<&ResultAndState<TempoHaltReason>>,
    reads: &[(ReadKey, ReadValue)],
    fees: &[FeeUpdate],
) -> Option<NativeIncrementWitness> {
    let witness = witness?;
    let target = witness.target;
    let key = ReadKey::Storage(target.address, target.slot);
    let mut matching = reads.iter().filter(|(read, _)| *read == key);
    if matching.next()?.1 != ReadValue::Storage(witness.original)
        || matching.next().is_some()
        || fees
            .iter()
            .any(|fee| fee.address == target.address && fee.slot == target.slot)
        || !matches_result(&witness, result?)
    {
        return None;
    }
    Some(witness)
}

pub(super) fn matches_result(
    witness: &NativeIncrementWitness,
    result: &ResultAndState<TempoHaltReason>,
) -> bool {
    let Some(account) = result.state.get(&witness.target.address) else {
        return false;
    };
    let Some(storage) = account.storage.get(&witness.target.slot) else {
        return false;
    };
    result.result.is_success()
        && !account.is_created()
        && !account.is_selfdestructed()
        && !account_is_removed(account)
        && storage.original_value == witness.original
        && storage.present_value == witness.new
        && witness.rebase(witness.original) == Some(witness.new)
}
