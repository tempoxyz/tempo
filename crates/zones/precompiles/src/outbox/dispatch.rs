//! ABI dispatch for the [`ZoneOutbox`] precompile.

use alloy_primitives::{Address, B256, U256};
use revm::precompile::PrecompileResult;
use tempo_precompiles::{charge_input_cost, dispatch, storage::Handler, view};
use tempo_contracts::zones::IZoneOutbox;
use zone_primitives::constants::MAX_WITHDRAWAL_GAS_LIMIT;

use crate::{
    dispatch::{mutate, view as typed_view},
    ecies::{AUTHENTICATED_WITHDRAWAL_ENCRYPTED_SIZE, COMPRESSED_PUBLIC_KEY_SIZE},
    storage::{L1State, L1StorageReader},
};

use super::{MAX_CALLBACK_DATA_SIZE, WITHDRAWAL_BASE_GAS, ZoneOutbox};

impl ZoneOutbox {
    pub(crate) fn call_with_transaction<P: L1StorageReader>(
        &mut self,
        l1: &L1State<P>,
        calldata: &[u8],
        msg_sender: Address,
        tx_hash: B256,
        fee_payer: Address,
    ) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(calldata, |call| match call {
            IZoneOutbox::IZoneOutboxCalls {
                tempoGasRate(call) => view(call, |_| self.tempo_gas_rate.read()),
                maxWithdrawalsPerBlock(call) => view(call, |_| self.max_withdrawals_per_block.read()),
                lastBatch(call) => view(call, |_| self.last_batch()),
                lastFinalizedTimestamp(call) => view(call, |_| self.last_finalized_timestamp.read()),
                nextWithdrawalIndex(call) => view(call, |_| self.next_withdrawal_index.read()),
                lastFallbackNonce(call) => view(call, |_| self.last_fallback_nonce.read()),
                pendingWithdrawalsCount(call) => typed_view(call, |_| {
                    self.pending_withdrawals_count(l1, msg_sender)
                }),
                getPendingWithdrawals(call) => typed_view(call, |_| {
                    self.get_pending_withdrawals(l1, msg_sender)
                }),
                calculateWithdrawalFee(call) => typed_view(call, |call| self.calculate_withdrawal_fee(call.gasLimit)),
                MAX_CALLBACK_DATA_SIZE(call) => view(call, |_| Ok(U256::from(MAX_CALLBACK_DATA_SIZE))),
                MAX_WITHDRAWAL_GAS_LIMIT(call) => view(call, |_| Ok(MAX_WITHDRAWAL_GAS_LIMIT)),
                WITHDRAWAL_BASE_GAS(call) => view(call, |_| Ok(WITHDRAWAL_BASE_GAS)),
                REVEAL_TO_KEY_LENGTH(call) => view(call, |_| Ok(U256::from(COMPRESSED_PUBLIC_KEY_SIZE))),
                AUTHENTICATED_WITHDRAWAL_CIPHERTEXT_LENGTH(call) => view(call, |_| Ok(U256::from(AUTHENTICATED_WITHDRAWAL_ENCRYPTED_SIZE))),
                setTempoGasRate(call) => mutate(call, msg_sender, |sender, call| self.set_tempo_gas_rate(l1, sender, call)),
                setMaxWithdrawalsPerBlock(call) => mutate(call, msg_sender, |sender, call| self.set_max_withdrawals_per_block(l1, sender, call)),
                requestWithdrawal(call) => mutate(call, msg_sender, |sender, call| {
                    self.request_withdrawal(l1, sender, fee_payer, tx_hash, call)
                }),
                enqueueDepositBounceBack(call) => mutate(call, msg_sender, |sender, call| self.enqueue_deposit_bounce_back(sender, call)),
                consumeFallbackRecipient(call) => mutate(call, msg_sender, |sender, call| self.consume_fallback_recipient(sender, call.fallbackNonce)),
                finalizeWithdrawalBatch(call) => mutate(call, msg_sender, |sender, call| self.finalize_withdrawal_batch(l1, sender, call)),
            }
        })
    }
}
