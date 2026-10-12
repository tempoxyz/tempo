//! Native `ZoneOutbox` precompile.
//!
mod dispatch;
#[cfg(test)]
mod tests;

use alloc::vec::Vec;

use alloy_primitives::{Address, B256, Bytes, U256};
use tempo_precompiles::{
    Result as TempoResult,
    error::TempoPrecompileError,
    storage::{ContractStorage, Handler, Mapping},
    tip20::{ITIP20, TIP20Error, TIP20Token},
};
use tempo_precompiles_macros::{Storable, contract};
use tempo_contracts::zones::{
    IZoneOutbox, Withdrawal, ZoneOutboxError, ZoneOutboxEvent, ZonePortal::Role, ZonePortalError,
};
use zone_primitives::constants::{
    MAX_WITHDRAWAL_GAS_LIMIT, ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS,
};

use crate::{
    ZoneResult,
    ecies::{AUTHENTICATED_WITHDRAWAL_ENCRYPTED_SIZE, decode_compressed_public_key},
    storage::{L1State, L1StorageReader},
};

/// Maximum callback payload accepted by the Zone Outbox.
pub const MAX_CALLBACK_DATA_SIZE: usize = 1024;
const WITHDRAWAL_BASE_GAS: u64 = 50_000;

#[contract(addr = ZONE_OUTBOX_ADDRESS)]
pub struct ZoneOutbox {
    tempo_gas_rate: u128,
    next_withdrawal_index: u64,
    withdrawal_queue_hash: B256,
    withdrawal_batch_index: u64,
    max_withdrawals_per_block: u32,
    withdrawals_this_block: u32,
    current_block_number: u64,
    last_finalized_timestamp: u64,
    pending_withdrawals: Vec<PendingWithdrawal>,
    last_fallback_nonce: u64,
    fallback_recipients: Mapping<u64, Address>,
}

impl ZoneOutbox {
    /// Initializes the precompile account code.
    pub fn initialize(&mut self) -> TempoResult<()> {
        self.__initialize()
    }

    fn ensure_sequencer<P: L1StorageReader>(
        &self,
        l1: &L1State<P>,
        caller: Address,
    ) -> ZoneResult<()> {
        if !caller.is_zero() && !l1.has_portal_role(caller, Role::Sequencer)? {
            return Err(ZoneOutboxError::only_sequencer().into());
        }
        Ok(())
    }

    fn validate_withdrawal_policy<P: L1StorageReader>(
        &self,
        l1: &L1State<P>,
        token: Address,
        to: Address,
        gas_limit: u64,
    ) -> ZoneResult<()> {
        if !l1.read_portal(|portal| &portal.token_configs[token].enabled)? {
            return Err(ZonePortalError::token_not_enabled().into());
        }

        let pause_expiry = l1.read_portal(|portal| &portal.pause_expiry)?;
        if self.storage.timestamp().to::<u64>() < pause_expiry {
            return Err(ZonePortalError::portal_is_paused().into());
        }

        let access_enforced = l1.read_portal(|portal| &portal.is_access_enforced)?;
        let gateway_enforced = l1.read_portal(|portal| &portal.is_gateway_enforced)?;

        if gas_limit == 0 {
            if !access_enforced && !gateway_enforced {
                return Ok(());
            }

            if gateway_enforced && l1.has_portal_role(to, Role::CallbackGateway)? {
                return Err(ZonePortalError::invalid_callback_target().into());
            }
            if access_enforced && !l1.has_portal_role(to, Role::Account)? {
                return Err(ZonePortalError::account_not_allowed(to).into());
            }
        } else if gateway_enforced && !l1.has_portal_role(to, Role::CallbackGateway)? {
            return Err(ZonePortalError::invalid_callback_target().into());
        }

        Ok(())
    }

    fn calculate_fee_unchecked(&self, gas_limit: u64) -> TempoResult<u128> {
        let gas = u128::from(WITHDRAWAL_BASE_GAS) + u128::from(gas_limit);
        gas.checked_mul(self.tempo_gas_rate.read()?)
            .ok_or_else(TempoPrecompileError::under_overflow)
    }

    fn calculate_withdrawal_fee(&self, gas_limit: u64) -> ZoneResult<u128> {
        validate_gas_limit(gas_limit)?;
        self.calculate_fee_unchecked(gas_limit).map_err(Into::into)
    }

    fn enforce_withdrawal_block_cap(&mut self) -> ZoneResult<()> {
        let max = self.max_withdrawals_per_block.read()?;
        if max == 0 {
            return Ok(());
        }

        let block_number = self.storage.block_number();
        if block_number != self.current_block_number.read()? {
            self.current_block_number.write(block_number)?;
            self.withdrawals_this_block.write(0)?;
        }

        let withdrawals = self.withdrawals_this_block.read()?;
        if withdrawals >= max {
            return Err(ZoneOutboxError::too_many_withdrawals_this_block().into());
        }
        self.withdrawals_this_block.write(
            withdrawals
                .checked_add(1)
                .ok_or_else(TempoPrecompileError::under_overflow)?,
        )?;
        Ok(())
    }

    fn enqueue(&mut self, pending: PendingWithdrawal, fee: u128) -> ZoneResult<()> {
        let index = self.next_withdrawal_index.read()?;
        self.emit_event(pending.requested_event(index, fee))?;

        self.pending_withdrawals.push(pending)?;
        self.next_withdrawal_index.write(
            index
                .checked_add(1)
                .ok_or_else(TempoPrecompileError::under_overflow)?,
        )?;
        Ok(())
    }

    fn request_withdrawal<P: L1StorageReader>(
        &mut self,
        l1: &L1State<P>,
        caller: Address,
        fee_payer: Address,
        current_tx_hash: B256,
        call: IZoneOutbox::requestWithdrawalCall,
    ) -> ZoneResult<()> {
        if call.zoneFallbackRecipient.is_zero() {
            return Err(ZoneOutboxError::invalid_fallback_recipient().into());
        }
        if call.amount == 0 {
            return Err(ZoneOutboxError::zero_amount_withdrawal().into());
        }
        if call.data.len() > MAX_CALLBACK_DATA_SIZE {
            return Err(ZoneOutboxError::callback_data_too_large().into());
        }

        validate_gas_limit(call.gasLimit)?;

        if current_tx_hash.is_zero() {
            return Err(ZoneOutboxError::invalid_current_tx_hash().into());
        }
        let mut zone_token = TIP20Token::from_address(call.token)?;
        if !zone_token.is_initialized()? {
            return Err(TempoPrecompileError::from(TIP20Error::uninitialized()).into());
        }
        self.validate_withdrawal_policy(l1, call.token, call.to, call.gasLimit)?;
        self.enforce_withdrawal_block_cap()?;

        // If necessary, validate reveal
        if !call.revealTo.is_empty() && decode_compressed_public_key(&call.revealTo).is_none() {
            return Err(ZoneOutboxError::invalid_reveal_to().into());
        }

        let fee = self.calculate_fee_unchecked(call.gasLimit)?;
        if caller == fee_payer {
            let total = call
                .amount
                .checked_add(fee)
                .ok_or_else(TempoPrecompileError::under_overflow)?;
            self.transfer_and_burn(&mut zone_token, caller, total)?;
        } else {
            self.transfer_and_burn(&mut zone_token, caller, call.amount)?;
            if fee != 0 {
                self.transfer_and_burn(&mut zone_token, fee_payer, fee)?;
            }
        }

        let fallback_nonce = self
            .last_fallback_nonce
            .read()?
            .checked_add(1)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        self.last_fallback_nonce.write(fallback_nonce)?;
        self.fallback_recipients[fallback_nonce].write(call.zoneFallbackRecipient)?;
        self.enqueue(
            PendingWithdrawal::from_request(caller, current_tx_hash, fallback_nonce, call),
            fee,
        )
    }

    fn transfer_and_burn(
        &self,
        token: &mut TIP20Token,
        owner: Address,
        amount: u128,
    ) -> ZoneResult<()> {
        let amount = U256::from(amount);
        if !token.transfer_from(
            self.address,
            ITIP20::transferFromCall {
                from: owner,
                to: self.address,
                amount,
            },
        )? {
            return Err(ZoneOutboxError::transfer_failed().into());
        }
        token.burn(self.address, ITIP20::burnCall { amount })?;
        Ok(())
    }

    pub(crate) fn enqueue_deposit_bounce_back(
        &mut self,
        caller: Address,
        call: IZoneOutbox::enqueueDepositBounceBackCall,
    ) -> ZoneResult<()> {
        if caller != ZONE_INBOX_ADDRESS {
            return Err(ZoneOutboxError::only_zone_inbox().into());
        }

        self.enqueue(PendingWithdrawal::from_bounce_back(call), 0)
    }

    pub(crate) fn consume_fallback_recipient(
        &mut self,
        caller: Address,
        nonce: u64,
    ) -> ZoneResult<Address> {
        if caller != ZONE_INBOX_ADDRESS {
            return Err(ZoneOutboxError::only_zone_inbox().into());
        }
        let recipient = self.fallback_recipients[nonce].read()?;
        if recipient.is_zero() {
            return Err(ZoneOutboxError::invalid_fallback_recipient().into());
        }
        self.fallback_recipients[nonce].delete()?;
        Ok(recipient)
    }

    #[cfg(test)]
    pub(crate) fn seed_fallback_recipient(
        &mut self,
        nonce: u64,
        recipient: Address,
    ) -> TempoResult<()> {
        self.fallback_recipients[nonce].write(recipient)
    }

    #[cfg(test)]
    pub(crate) fn fallback_recipient(&self, nonce: u64) -> TempoResult<Address> {
        self.fallback_recipients[nonce].read()
    }

    fn finalize_withdrawal_batch<P: L1StorageReader>(
        &mut self,
        _l1: &L1State<P>,
        caller: Address,
        call: IZoneOutbox::finalizeWithdrawalBatchCall,
    ) -> ZoneResult<B256> {
        if !caller.is_zero() {
            return Err(ZoneOutboxError::only_sequencer().into());
        }
        if call.blockNumber != self.storage.block_number() {
            return Err(ZoneOutboxError::invalid_block_number().into());
        }

        let count = self.pending_withdrawals.len()?;
        if call.count != U256::from(count) {
            return Err(
                ZoneOutboxError::invalid_withdrawal_count(call.count, U256::from(count)).into(),
            );
        }
        if call.encryptedSenders.len() != count {
            return Err(ZoneOutboxError::invalid_encrypted_sender_count(
                U256::from(call.encryptedSenders.len()),
                U256::from(count),
            )
            .into());
        }

        let mut withdrawal_queue_hash = B256::ZERO;
        if count > 0 {
            for (index, encrypted_sender) in call.encryptedSenders.into_iter().enumerate().rev() {
                let pending = self.pending_withdrawals[index].read()?;
                let withdrawal = pending.into_withdrawal(encrypted_sender)?;
                withdrawal_queue_hash = withdrawal.hash_with_tail(withdrawal_queue_hash);
            }
            self.pending_withdrawals.delete()?;
        }

        let next_batch_index = self
            .withdrawal_batch_index
            .read()?
            .checked_add(1)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        self.withdrawal_batch_index.write(next_batch_index)?;
        self.withdrawal_queue_hash.write(withdrawal_queue_hash)?;
        self.last_finalized_timestamp
            .write(self.storage.timestamp().to::<u64>())?;
        self.emit_event(ZoneOutboxEvent::batch_finalized(
            withdrawal_queue_hash,
            next_batch_index,
        ))?;
        Ok(withdrawal_queue_hash)
    }

    fn set_tempo_gas_rate<P: L1StorageReader>(
        &mut self,
        l1: &L1State<P>,
        caller: Address,
        call: IZoneOutbox::setTempoGasRateCall,
    ) -> ZoneResult<()> {
        self.ensure_sequencer(l1, caller)?;
        let max_tempo_gas_rate = l1.read_portal(|portal| &portal.max_tempo_gas_rate)?;
        if call._tempoGasRate > max_tempo_gas_rate {
            return Err(ZoneOutboxError::gas_fee_rate_too_high().into());
        }
        self.tempo_gas_rate.write(call._tempoGasRate)?;
        self.emit_event(ZoneOutboxEvent::tempo_gas_rate_updated(call._tempoGasRate))?;
        Ok(())
    }

    fn set_max_withdrawals_per_block<P: L1StorageReader>(
        &mut self,
        l1: &L1State<P>,
        caller: Address,
        call: IZoneOutbox::setMaxWithdrawalsPerBlockCall,
    ) -> ZoneResult<()> {
        self.ensure_sequencer(l1, caller)?;
        self.max_withdrawals_per_block
            .write(call._maxWithdrawalsPerBlock)?;
        self.emit_event(ZoneOutboxEvent::max_withdrawals_per_block_updated(
            call._maxWithdrawalsPerBlock,
        ))?;
        Ok(())
    }

    fn pending_withdrawals_count<P: L1StorageReader>(
        &self,
        l1: &L1State<P>,
        caller: Address,
    ) -> ZoneResult<U256> {
        self.ensure_sequencer(l1, caller)?;
        self.pending_withdrawals
            .len()
            .map(U256::from)
            .map_err(Into::into)
    }

    fn get_pending_withdrawals<P: L1StorageReader>(
        &self,
        l1: &L1State<P>,
        caller: Address,
    ) -> ZoneResult<Vec<IZoneOutbox::PendingWithdrawal>> {
        self.ensure_sequencer(l1, caller)?;
        let len = self.pending_withdrawals.len()?;
        let mut pending = Vec::with_capacity(len);
        for index in 0..len {
            pending.push(self.pending_withdrawals[index].read()?.into());
        }
        Ok(pending)
    }

    /// Returns the last finalized withdrawal batch from Zone state.
    pub fn last_batch(&self) -> TempoResult<IZoneOutbox::LastBatch> {
        Ok(IZoneOutbox::LastBatch {
            withdrawalQueueHash: self.withdrawal_queue_hash.read()?,
            withdrawalBatchIndex: self.withdrawal_batch_index.read()?,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Storable)]
struct PendingWithdrawal {
    token: Address,
    sender: Address,
    tx_hash: B256,
    to: Address,
    amount: u128,
    memo: B256,
    gas_limit: u64,
    fallback_nonce: u64,
    callback_data: Bytes,
    reveal_to: Bytes,
}

impl PendingWithdrawal {
    fn from_request(
        sender: Address,
        tx_hash: B256,
        fallback_nonce: u64,
        call: IZoneOutbox::requestWithdrawalCall,
    ) -> Self {
        Self {
            token: call.token,
            sender,
            tx_hash,
            to: call.to,
            amount: call.amount,
            memo: call.memo,
            gas_limit: call.gasLimit,
            fallback_nonce,
            callback_data: call.data,
            reveal_to: call.revealTo,
        }
    }

    fn from_bounce_back(call: IZoneOutbox::enqueueDepositBounceBackCall) -> Self {
        Self {
            token: call.token,
            to: call.tempoRefundRecipient,
            amount: call.amount,
            ..Default::default()
        }
    }

    fn requested_event(&self, index: u64, fee: u128) -> ZoneOutboxEvent {
        ZoneOutboxEvent::withdrawal_requested(
            index,
            self.sender,
            self.token,
            self.to,
            self.amount,
            fee,
            self.memo,
            self.gas_limit,
            self.fallback_nonce,
            self.callback_data.clone(),
            self.reveal_to.clone(),
        )
    }

    fn into_withdrawal(self, encrypted_sender: Bytes) -> ZoneResult<Withdrawal> {
        let expected = if self.reveal_to.is_empty() {
            0
        } else {
            AUTHENTICATED_WITHDRAWAL_ENCRYPTED_SIZE
        };
        if encrypted_sender.len() != expected {
            return Err(ZoneOutboxError::invalid_encrypted_sender_length(
                U256::from(encrypted_sender.len()),
                U256::from(expected),
            )
            .into());
        }

        let sender_tag = Withdrawal::sender_tag(self.sender, self.tx_hash, self.fallback_nonce);
        Ok(Withdrawal {
            token: self.token,
            senderTag: sender_tag,
            to: self.to,
            amount: self.amount,
            memo: self.memo,
            gasLimit: self.gas_limit,
            fallbackNonce: self.fallback_nonce,
            callbackData: self.callback_data,
            encryptedSender: encrypted_sender,
        })
    }
}

impl From<PendingWithdrawal> for IZoneOutbox::PendingWithdrawal {
    fn from(pending: PendingWithdrawal) -> Self {
        Self {
            token: pending.token,
            sender: pending.sender,
            txHash: pending.tx_hash,
            to: pending.to,
            amount: pending.amount,
            memo: pending.memo,
            gasLimit: pending.gas_limit,
            fallbackNonce: pending.fallback_nonce,
            callbackData: pending.callback_data,
            revealTo: pending.reveal_to,
        }
    }
}

fn validate_gas_limit(gas_limit: u64) -> ZoneResult<()> {
    if gas_limit > MAX_WITHDRAWAL_GAS_LIMIT {
        return Err(ZoneOutboxError::gas_limit_too_high().into());
    }
    Ok(())
}
