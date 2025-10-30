use crate::{
    TIP20_REWARDS_REGISTRY_ADDRESS,
    error::TempoPrecompileError,
    storage::{PrecompileStorageProvider, slots::mapping_slot},
    tip20::TIP20Token,
    tip20_rewards_registry::TIP20RewardsRegistry,
};
use alloy::primitives::{Address, IntoLogData, U256, uint};
use revm::interpreter::instructions::utility::{IntoAddress, IntoU256};
use tempo_contracts::precompiles::{ITIP20, TIP20Error, TIP20Event};

pub const ACC_PRECISION: U256 = uint!(1000000000000000000_U256);

pub mod slots {
    use alloy::primitives::{U256, uint};

    // Rewards related slots
    pub const LAST_UPDATE_TIME: U256 = uint!(16_U256);
    pub const OPTED_IN_SUPPLY: U256 = uint!(17_U256);
    pub const NEXT_STREAM_ID: U256 = uint!(18_U256);
    pub const STREAMS: U256 = uint!(19_U256);
    pub const SCHEDULED_RATE_DECREASE: U256 = uint!(20_U256);
    pub const REWARD_RECIPIENT_OF: U256 = uint!(21_U256);
    pub const USER_REWARD_PER_TOKEN_PAID: U256 = uint!(22_U256);
    pub const DELEGATED_BALANCE: U256 = uint!(23_U256);
    pub const REWARD_PER_TOKEN_STORED: U256 = uint!(24_U256);
    pub const TOTAL_REWARD_PER_SECOND: U256 = uint!(25_U256);
}

impl<'a, S: PrecompileStorageProvider> TIP20Token<'a, S> {
    /// Starts a new reward stream for the token contract.
    ///
    /// This function allows an authorized user to fund a reward stream that distributes
    /// tokens to opted-in recipients either immediately if seconds=0, or over the specified
    /// duration.
    pub fn start_reward(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::startRewardCall,
    ) -> Result<u64, TempoPrecompileError> {
        self.check_not_paused()?;
        let token_address = self.token_address;
        self.ensure_transfer_authorized(msg_sender, &token_address)?;

        if call.amount == U256::ZERO {
            return Err(TIP20Error::invalid_amount().into());
        }

        self._transfer(msg_sender, &token_address, call.amount)?;

        if call.seconds == 0 {
            let opted_in_supply = self.get_opted_in_supply()?;
            if opted_in_supply.is_zero() {
                return Err(TIP20Error::no_opted_in_supply().into());
            }

            let delta_rpt = call
                .amount
                .checked_mul(ACC_PRECISION)
                .and_then(|v| v.checked_div(opted_in_supply))
                .ok_or(TempoPrecompileError::under_overflow())?;
            let current_rpt = self.get_reward_per_token_stored()?;
            let new_rpt = current_rpt
                .checked_add(delta_rpt)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_reward_per_token_stored(new_rpt)?;

            // Emit reward scheduled event for immediate payout
            self.storage.emit_event(
                self.token_address,
                TIP20Event::RewardScheduled(ITIP20::RewardScheduled {
                    funder: *msg_sender,
                    id: 0,
                    amount: call.amount,
                    durationSeconds: 0,
                })
                .into_log_data(),
            )?;

            Ok(0)
        } else {
            let rate = call
                .amount
                .checked_mul(ACC_PRECISION)
                .and_then(|v| v.checked_div(U256::from(call.seconds)))
                .ok_or(TempoPrecompileError::under_overflow())?;
            let stream_id = self.get_next_stream_id()?;
            let next_stream_id = stream_id
                .checked_add(1)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_next_stream_id(next_stream_id)?;

            let current_total = self.get_total_reward_per_second()?;
            let new_total = current_total
                .checked_add(rate)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_total_reward_per_second(new_total)?;

            let current_time = self.storage.timestamp().to::<u128>();
            let end_time = current_time
                .checked_add(call.seconds)
                .ok_or(TempoPrecompileError::under_overflow())?;

            RewardStream::new(
                stream_id,
                *msg_sender,
                current_time as u64,
                end_time as u64,
                rate,
                call.amount,
            )
            .store(self.storage, self.token_address)?;

            let current_decrease = self.get_scheduled_rate_decrease_at(end_time);
            let new_decrease = current_decrease
                .checked_add(rate)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_scheduled_rate_decrease_at(end_time, new_decrease)?;

            // Add stream to registry
            let mut registry = TIP20RewardsRegistry::new(self.storage);
            registry.add_stream(&self.token_address, end_time)?;

            // Emit reward scheduled event for streaming reward
            self.storage.emit_event(
                self.token_address,
                TIP20Event::RewardScheduled(ITIP20::RewardScheduled {
                    funder: *msg_sender,
                    id: stream_id,
                    amount: call.amount,
                    durationSeconds: call.seconds as u32,
                })
                .into_log_data(),
            )?;

            Ok(stream_id)
        }
    }

    /// Handles reward accounting when tokens are transferred from an address.
    ///
    /// This function updates the reward state for the sender's reward recipient,
    /// reducing their delegated balance and returns the resulting opted in supply delta if changed
    fn handle_sender_rewards(
        &mut self,
        from: &Address,
        amount: U256,
    ) -> Result<Option<U256>, TempoPrecompileError> {
        let from_recipient = self.get_reward_recipient_of(from)?;
        if from_recipient != Address::ZERO {
            self.update_rewards(&from_recipient)?;

            let delegated = self
                .get_delegated_balance(&from_recipient)?
                .checked_sub(amount)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_delegated_balance(&from_recipient, delegated)?;

            Ok(Some(amount))
        } else {
            Ok(None)
        }
    }

    /// Handles reward accounting when tokens are transferred to an address.
    ///
    /// This function updates the reward state for the receiver's reward recipient,
    /// increasing their delegated balance and returns the resulting opted in supply delta if changed
    fn handle_receiver_rewards(
        &mut self,
        to: &Address,
        amount: U256,
    ) -> Result<Option<U256>, TempoPrecompileError> {
        let to_recipient = self.get_reward_recipient_of(to)?;
        if to_recipient != Address::ZERO {
            self.update_rewards(&to_recipient)?;

            let delegated = self
                .get_delegated_balance(&to_recipient)?
                .checked_add(amount)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_delegated_balance(&to_recipient, delegated)?;

            Ok(Some(amount))
        } else {
            Ok(None)
        }
    }

    /// Accrues rewards based on elapsed time since last update.
    ///
    /// This function calculates and updates the reward per token stored based on
    /// the total reward rate and the time elapsed since the last update.
    /// Only processes rewards if there is an opted-in supply.
    pub fn accrue(&mut self, accrue_to_timestamp: U256) -> Result<(), TempoPrecompileError> {
        let elapsed = accrue_to_timestamp - U256::from(self.get_last_update_time()?);
        if elapsed.is_zero() {
            return Ok(());
        }

        self.set_last_update_time(accrue_to_timestamp)?;

        let opted_in_supply = self.get_opted_in_supply()?;
        if opted_in_supply == U256::ZERO {
            return Ok(());
        }

        let total_reward_per_second = self.get_total_reward_per_second()?;
        if total_reward_per_second > U256::ZERO {
            let delta_rpt = total_reward_per_second
                .checked_mul(elapsed)
                .and_then(|v| v.checked_div(opted_in_supply))
                .ok_or(TempoPrecompileError::under_overflow())?;
            let current_rpt = self.get_reward_per_token_stored()?;
            let new_rpt = current_rpt
                .checked_add(delta_rpt)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_reward_per_token_stored(new_rpt)?;
        }

        Ok(())
    }

    /// Updates and distributes accrued rewards for a specific recipient.
    ///
    /// This function calculates the rewards earned by a recipient based on their
    /// delegated balance and the reward per token difference since their last update.
    /// It then transfers the accrued rewards from the contract to the recipient.
    fn update_rewards(&mut self, recipient: &Address) -> Result<(), TempoPrecompileError> {
        if *recipient == Address::ZERO {
            return Ok(());
        }

        let delegated = self.get_delegated_balance(recipient)?;
        let reward_per_token_stored = self.get_reward_per_token_stored()?;
        let user_reward_per_token_paid = self.get_user_reward_per_token_paid(recipient)?;

        let mut accrued = reward_per_token_stored
            .checked_sub(user_reward_per_token_paid)
            .and_then(|diff| delegated.checked_mul(diff))
            .and_then(|v| v.checked_div(ACC_PRECISION))
            .ok_or(TempoPrecompileError::under_overflow())?;

        self.set_user_reward_per_token_paid(recipient, reward_per_token_stored)?;

        if accrued > U256::ZERO {
            let token_address = self.token_address;
            let contract_balance = self.get_balance(&token_address)?;

            if accrued > contract_balance {
                accrued = contract_balance;
            }

            let new_contract_balance = contract_balance
                .checked_sub(accrued)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_balance(&token_address, new_contract_balance)?;

            let recipient_balance = self
                .get_balance(recipient)?
                .checked_add(accrued)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_balance(recipient, recipient_balance)?;

            // Since rewards are being claimed, we need to increase the delegated balance
            // and opted-in supply to reflect that these tokens are now part of the reward pool.
            let delegated_balance = self
                .get_delegated_balance(recipient)?
                .checked_add(accrued)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_delegated_balance(recipient, delegated_balance)?;

            let opted_in_supply = self
                .get_opted_in_supply()?
                .checked_add(accrued)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_opted_in_supply(opted_in_supply)?;

            self.storage.emit_event(
                self.token_address,
                TIP20Event::Transfer(ITIP20::Transfer {
                    from: token_address,
                    to: *recipient,
                    amount: accrued,
                })
                .into_log_data(),
            )?;
        }

        Ok(())
    }

    /// Sets or changes the reward recipient for a token holder.
    ///
    /// This function allows a token holder to designate who should receive their
    /// share of rewards. Setting to zero address opts out of rewards.
    pub fn set_reward_recipient(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::setRewardRecipientCall,
    ) -> Result<(), TempoPrecompileError> {
        self.check_not_paused()?;
        if call.recipient != Address::ZERO {
            self.ensure_transfer_authorized(msg_sender, &call.recipient)?;
        }

        let timestamp = self.storage.timestamp();
        self.accrue(timestamp)?;

        let current_recipient = self.get_reward_recipient_of(msg_sender)?;
        if call.recipient == current_recipient {
            return Ok(());
        }

        let holder_balance = self.get_balance(msg_sender)?;
        if current_recipient != Address::ZERO {
            self.update_rewards(&current_recipient)?;
            let delegated_balance = self
                .get_delegated_balance(&current_recipient)?
                .checked_sub(holder_balance)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_delegated_balance(&current_recipient, delegated_balance)?;
        }

        self.set_reward_recipient_of(msg_sender, call.recipient)?;
        if call.recipient == Address::ZERO {
            let opted_in_supply = self
                .get_opted_in_supply()?
                .checked_sub(holder_balance)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_opted_in_supply(opted_in_supply)?;
        } else {
            let delegated = self.get_delegated_balance(&call.recipient)?;
            if delegated > U256::ZERO {
                self.update_rewards(&call.recipient)?;
            }

            let new_delegated = delegated
                .checked_add(holder_balance)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_delegated_balance(&call.recipient, new_delegated)?;

            if current_recipient.is_zero() {
                let opted_in = self
                    .get_opted_in_supply()?
                    .checked_add(holder_balance)
                    .ok_or(TempoPrecompileError::under_overflow())?;
                self.set_opted_in_supply(opted_in)?;
            }

            let rpt = self.get_reward_per_token_stored()?;
            self.set_user_reward_per_token_paid(&call.recipient, rpt)?;
        }

        // Emit reward recipient set event
        self.storage.emit_event(
            self.token_address,
            TIP20Event::RewardRecipientSet(ITIP20::RewardRecipientSet {
                holder: *msg_sender,
                recipient: call.recipient,
            })
            .into_log_data(),
        )?;

        Ok(())
    }

    /// Cancels an active reward stream and refunds remaining tokens.
    ///
    /// This function allows the funder of a reward stream to cancel it early,
    /// stopping future reward distribution and refunding unused tokens.
    pub fn cancel_reward(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::cancelRewardCall,
    ) -> Result<U256, TempoPrecompileError> {
        let stream_id = call.id;
        let stream = RewardStream::from_storage(stream_id, self.storage, self.token_address)?;

        if stream.funder.is_zero() {
            return Err(TIP20Error::stream_inactive().into());
        }

        if stream.funder != *msg_sender {
            return Err(TIP20Error::not_stream_funder().into());
        }

        let current_time = self.storage.timestamp();
        if current_time >= stream.end_time {
            return Err(TIP20Error::stream_inactive().into());
        }

        let timestamp = self.storage.timestamp();
        self.accrue(timestamp)?;

        let elapsed = if current_time > stream.start_time {
            current_time - U256::from(stream.start_time)
        } else {
            U256::ZERO
        };

        let mut distributed = stream
            .rate_per_second_scaled
            .checked_mul(elapsed)
            .and_then(|v| v.checked_div(ACC_PRECISION))
            .ok_or(TempoPrecompileError::under_overflow())?;
        distributed = distributed.min(stream.amount_total);
        let remaining = stream
            .amount_total
            .checked_sub(distributed)
            .ok_or(TempoPrecompileError::under_overflow())?;

        let total_rps = self
            .get_total_reward_per_second()?
            .checked_sub(stream.rate_per_second_scaled)
            .ok_or(TempoPrecompileError::under_overflow())?;
        self.set_total_reward_per_second(total_rps)?;

        // Update the rate decrease and remove the stream
        let end_time = stream.end_time as u128;
        let rate_decrease = self
            .get_scheduled_rate_decrease_at(end_time)
            .checked_sub(stream.rate_per_second_scaled)
            .ok_or(TempoPrecompileError::under_overflow())?;
        self.set_scheduled_rate_decrease_at(end_time, rate_decrease)?;

        stream.delete(self.storage, self.token_address)?;

        // Attempt to transfer remaining funds to funder
        let mut refund = U256::ZERO;
        if remaining > U256::ZERO {
            // Check if transfer is authorized
            if self.is_transfer_authorized(&stream.funder, &stream.funder)? {
                let contract_address = self.token_address;
                let contract_balance = self
                    .get_balance(&contract_address)?
                    .checked_sub(remaining)
                    .ok_or(TempoPrecompileError::under_overflow())?;
                self.set_balance(&contract_address, contract_balance)?;

                let funder_balance = self
                    .get_balance(&stream.funder)?
                    .checked_add(remaining)
                    .ok_or(TempoPrecompileError::under_overflow())?;
                self.set_balance(&stream.funder, funder_balance)?;

                self.storage.emit_event(
                    self.token_address,
                    TIP20Event::Transfer(ITIP20::Transfer {
                        from: self.token_address,
                        to: stream.funder,
                        amount: remaining,
                    })
                    .into_log_data(),
                )?;

                refund = remaining;
            }
        }

        // Emit reward canceled event
        self.storage.emit_event(
            self.token_address,
            TIP20Event::RewardCanceled(ITIP20::RewardCanceled {
                funder: stream.funder,
                id: stream_id,
                refund,
            })
            .into_log_data(),
        )?;

        Ok(refund)
    }

    /// Finalizes expired reward streams by updating the total reward rate.
    ///
    /// This function is called to clean up streams that have reached their end time,
    /// reducing the total reward per second rate by the amount of the expired streams.
    pub fn finalize_streams(
        &mut self,
        msg_sender: Address,
        end_time: u128,
    ) -> Result<(), TempoPrecompileError> {
        if msg_sender != TIP20_REWARDS_REGISTRY_ADDRESS {
            return Err(TIP20Error::unauthorized().into());
        }

        let rate_decrease = self.get_scheduled_rate_decrease_at(end_time);

        if rate_decrease == U256::ZERO {
            return Ok(());
        }

        self.accrue(U256::from(end_time))?;

        let total_rps = self
            .get_total_reward_per_second()?
            .checked_sub(rate_decrease)
            .ok_or(TempoPrecompileError::under_overflow())?;
        self.set_total_reward_per_second(total_rps)?;

        self.set_scheduled_rate_decrease_at(end_time, U256::ZERO)?;

        Ok(())
    }

    /// Gets the last recorded reward per token for a user.
    fn get_user_reward_per_token_paid(
        &mut self,
        account: &Address,
    ) -> Result<U256, TempoPrecompileError> {
        let slot = mapping_slot(account, slots::USER_REWARD_PER_TOKEN_PAID);
        self.storage.sload(self.token_address, slot)
    }

    /// Sets the last recorded reward per token for a user.
    fn set_user_reward_per_token_paid(
        &mut self,
        account: &Address,
        value: U256,
    ) -> Result<(), TempoPrecompileError> {
        let slot = mapping_slot(account, slots::USER_REWARD_PER_TOKEN_PAID);
        self.storage.sstore(self.token_address, slot, value)
    }

    /// Gets the next available stream ID (minimum 1).
    fn get_next_stream_id(&mut self) -> Result<u64, TempoPrecompileError> {
        let id = self
            .storage
            .sload(self.token_address, slots::NEXT_STREAM_ID)?
            .to::<u64>();

        Ok(id.max(1))
    }

    /// Sets the next stream ID counter.
    fn set_next_stream_id(&mut self, value: u64) -> Result<(), TempoPrecompileError> {
        self.storage
            .sstore(self.token_address, slots::NEXT_STREAM_ID, U256::from(value))
    }

    /// Gets the accumulated reward per token stored.
    fn get_reward_per_token_stored(&mut self) -> Result<U256, TempoPrecompileError> {
        self.storage
            .sload(self.token_address, slots::REWARD_PER_TOKEN_STORED)
    }

    /// Sets the accumulated reward per token in storage.
    fn set_reward_per_token_stored(&mut self, value: U256) -> Result<(), TempoPrecompileError> {
        self.storage
            .sstore(self.token_address, slots::REWARD_PER_TOKEN_STORED, value)
    }

    /// Gets the timestamp of the last reward update from storage.
    fn get_last_update_time(&mut self) -> Result<u64, TempoPrecompileError> {
        Ok(self
            .storage
            .sload(self.token_address, slots::LAST_UPDATE_TIME)?
            .to::<u64>())
    }

    /// Sets the timestamp of the last reward update in storage.
    fn set_last_update_time(&mut self, value: U256) -> Result<(), TempoPrecompileError> {
        self.storage
            .sstore(self.token_address, slots::LAST_UPDATE_TIME, value)
    }

    /// Gets the total supply of tokens opted into rewards from storage.
    pub fn get_opted_in_supply(&mut self) -> Result<U256, TempoPrecompileError> {
        self.storage
            .sload(self.token_address, slots::OPTED_IN_SUPPLY)
    }

    /// Sets the total supply of tokens opted into rewards in storage.
    pub fn set_opted_in_supply(&mut self, value: U256) -> Result<(), TempoPrecompileError> {
        self.storage
            .sstore(self.token_address, slots::OPTED_IN_SUPPLY, value)
    }

    /// Gets the reward recipient address for an account from storage.
    fn get_reward_recipient_of(
        &mut self,
        account: &Address,
    ) -> Result<Address, TempoPrecompileError> {
        let slot = mapping_slot(account, slots::REWARD_RECIPIENT_OF);
        Ok(self.storage.sload(self.token_address, slot)?.into_address())
    }

    /// Sets the reward recipient address for an account in storage.
    fn set_reward_recipient_of(
        &mut self,
        account: &Address,
        recipient: Address,
    ) -> Result<(), TempoPrecompileError> {
        let slot = mapping_slot(account, slots::REWARD_RECIPIENT_OF);
        self.storage
            .sstore(self.token_address, slot, recipient.into_u256())
    }

    /// Gets the delegated balance for an account from storage.
    fn get_delegated_balance(&mut self, account: &Address) -> Result<U256, TempoPrecompileError> {
        let slot = mapping_slot(account, slots::DELEGATED_BALANCE);
        self.storage.sload(self.token_address, slot)
    }

    /// Sets the delegated balance for an account in storage.
    fn set_delegated_balance(
        &mut self,
        account: &Address,
        amount: U256,
    ) -> Result<(), TempoPrecompileError> {
        let slot = mapping_slot(account, slots::DELEGATED_BALANCE);
        self.storage.sstore(self.token_address, slot, amount)
    }

    /// Gets the scheduled rate decrease at a specific time from storage.
    fn get_scheduled_rate_decrease_at(&mut self, end_time: u128) -> U256 {
        let slot = mapping_slot(end_time.to_be_bytes(), slots::SCHEDULED_RATE_DECREASE);
        self.storage
            .sload(self.token_address, slot)
            .unwrap_or(U256::ZERO)
    }

    /// Sets the scheduled rate decrease at a specific time in storage.
    fn set_scheduled_rate_decrease_at(
        &mut self,
        end_time: u128,
        value: U256,
    ) -> Result<(), TempoPrecompileError> {
        let slot = mapping_slot(end_time.to_be_bytes(), slots::SCHEDULED_RATE_DECREASE);
        self.storage.sstore(self.token_address, slot, value)
    }

    /// Gets the total reward per second rate from storage.
    pub fn get_total_reward_per_second(&mut self) -> Result<U256, TempoPrecompileError> {
        self.storage
            .sload(self.token_address, slots::TOTAL_REWARD_PER_SECOND)
    }

    /// Sets the total reward per second rate in storage.
    fn set_total_reward_per_second(&mut self, value: U256) -> Result<(), TempoPrecompileError> {
        self.storage
            .sstore(self.token_address, slots::TOTAL_REWARD_PER_SECOND, value)
    }

    /// Handles reward accounting for both sender and receiver during token transfers.
    ///
    /// This function manages the opted-in supply adjustments when tokens are transferred
    /// between addresses with different reward recipient settings. It returns the net
    /// change to the opted-in supply.
    pub fn handle_rewards_on_transfer(
        &mut self,
        from: &Address,
        to: &Address,
        amount: U256,
    ) -> Result<(), TempoPrecompileError> {
        let mut opted_in_delta = alloy::primitives::I256::ZERO;

        if let Some(delta) = self.handle_sender_rewards(from, amount)? {
            opted_in_delta = alloy::primitives::I256::from(delta);
        }

        if let Some(delta) = self.handle_receiver_rewards(to, amount)? {
            opted_in_delta -= alloy::primitives::I256::from(delta);
        }

        if opted_in_delta > alloy::primitives::I256::ZERO {
            let opted_in_supply = self
                .get_opted_in_supply()?
                .checked_sub(U256::from(opted_in_delta))
                .ok_or(crate::error::TempoPrecompileError::under_overflow())?;
            self.set_opted_in_supply(opted_in_supply)?;
        } else if opted_in_delta < alloy::primitives::I256::ZERO {
            let opted_in_supply = self
                .get_opted_in_supply()?
                .checked_add(U256::from(-opted_in_delta))
                .ok_or(crate::error::TempoPrecompileError::under_overflow())?;
            self.set_opted_in_supply(opted_in_supply)?;
        }

        Ok(())
    }

    /// Handles reward accounting when tokens are minted to an address.
    ///
    /// This function manages the opted-in supply adjustments when tokens are minted
    /// to an address with a reward recipient setting. It only handles receiver rewards
    /// since tokens are minted from the zero address.
    pub fn handle_rewards_on_mint(
        &mut self,
        to: &Address,
        amount: U256,
    ) -> Result<(), TempoPrecompileError> {
        if let Some(delta) = self.handle_receiver_rewards(to, amount)? {
            let opted_in_supply = self
                .get_opted_in_supply()?
                .checked_add(delta)
                .ok_or(crate::error::TempoPrecompileError::under_overflow())?;
            self.set_opted_in_supply(opted_in_supply)?;
        }

        Ok(())
    }

    /// Retrieves a reward stream by its ID.
    pub fn get_stream(&mut self, stream_id: u64) -> Result<RewardStream, TempoPrecompileError> {
        RewardStream::from_storage(stream_id, self.storage, self.token_address)
    }
}

#[derive(Debug, Clone)]
pub struct RewardStream {
    stream_id: u64,
    pub funder: Address,
    pub start_time: u64,
    pub end_time: u64,
    pub rate_per_second_scaled: U256,
    pub amount_total: U256,
}

impl RewardStream {
    pub const STREAM_FUNDER_OFFSET: U256 = uint!(0_U256);
    pub const STREAM_START_TIME_OFFSET: U256 = uint!(1_U256);
    pub const STREAM_END_TIME_OFFSET: U256 = uint!(2_U256);
    pub const STREAM_RATE_OFFSET: U256 = uint!(3_U256);
    pub const STREAM_AMOUNT_TOTAL_OFFSET: U256 = uint!(4_U256);

    /// Creates a new RewardStream instance.
    pub fn new(
        stream_id: u64,
        funder: Address,
        start_time: u64,
        end_time: u64,
        rate_per_second_scaled: U256,
        amount_total: U256,
    ) -> Self {
        Self {
            stream_id,
            funder,
            start_time,
            end_time,
            rate_per_second_scaled,
            amount_total,
        }
    }

    /// Loads a RewardStream from contract storage.
    pub fn from_storage<S: PrecompileStorageProvider>(
        stream_id: u64,
        storage: &mut S,
        token_address: Address,
    ) -> Result<Self, TempoPrecompileError> {
        let key = stream_id.to_be_bytes();

        let funder = storage
            .sload(
                token_address,
                mapping_slot(key, slots::STREAMS + Self::STREAM_FUNDER_OFFSET),
            )?
            .into_address();

        let start_time = storage
            .sload(
                token_address,
                mapping_slot(key, slots::STREAMS + Self::STREAM_START_TIME_OFFSET),
            )?
            .to::<u64>();

        let end_time = storage
            .sload(
                token_address,
                mapping_slot(key, slots::STREAMS + Self::STREAM_END_TIME_OFFSET),
            )?
            .to::<u64>();

        let rate_per_second_scaled = storage.sload(
            token_address,
            mapping_slot(key, slots::STREAMS + Self::STREAM_RATE_OFFSET),
        )?;

        let amount_total = storage.sload(
            token_address,
            mapping_slot(key, slots::STREAMS + Self::STREAM_AMOUNT_TOTAL_OFFSET),
        )?;

        Ok(Self {
            stream_id,
            funder,
            start_time,
            end_time,
            rate_per_second_scaled,
            amount_total,
        })
    }

    /// Stores this RewardStream to contract storage.
    pub fn store<S: PrecompileStorageProvider>(
        &self,
        storage: &mut S,
        token_address: Address,
    ) -> Result<(), TempoPrecompileError> {
        let key = self.stream_id.to_be_bytes();

        storage.sstore(
            token_address,
            mapping_slot(key, slots::STREAMS + Self::STREAM_FUNDER_OFFSET),
            self.funder.into_u256(),
        )?;

        storage.sstore(
            token_address,
            mapping_slot(key, slots::STREAMS + Self::STREAM_START_TIME_OFFSET),
            U256::from(self.start_time),
        )?;

        storage.sstore(
            token_address,
            mapping_slot(key, slots::STREAMS + Self::STREAM_END_TIME_OFFSET),
            U256::from(self.end_time),
        )?;

        storage.sstore(
            token_address,
            mapping_slot(key, slots::STREAMS + Self::STREAM_RATE_OFFSET),
            self.rate_per_second_scaled,
        )?;

        storage.sstore(
            token_address,
            mapping_slot(key, slots::STREAMS + Self::STREAM_AMOUNT_TOTAL_OFFSET),
            self.amount_total,
        )?;

        Ok(())
    }

    /// Deletes reward stream from contract storage for the corresponding `stream_id`.
    pub fn delete<S: PrecompileStorageProvider>(
        &self,
        storage: &mut S,
        token_address: Address,
    ) -> Result<(), TempoPrecompileError> {
        let key = self.stream_id.to_be_bytes();

        storage.sstore(
            token_address,
            mapping_slot(key, slots::STREAMS + Self::STREAM_FUNDER_OFFSET),
            U256::ZERO,
        )?;

        storage.sstore(
            token_address,
            mapping_slot(key, slots::STREAMS + Self::STREAM_START_TIME_OFFSET),
            U256::ZERO,
        )?;

        storage.sstore(
            token_address,
            mapping_slot(key, slots::STREAMS + Self::STREAM_END_TIME_OFFSET),
            U256::ZERO,
        )?;

        storage.sstore(
            token_address,
            mapping_slot(key, slots::STREAMS + Self::STREAM_RATE_OFFSET),
            U256::ZERO,
        )?;

        storage.sstore(
            token_address,
            mapping_slot(key, slots::STREAMS + Self::STREAM_AMOUNT_TOTAL_OFFSET),
            U256::ZERO,
        )?;

        Ok(())
    }
}

impl From<RewardStream> for ITIP20::RewardStream {
    fn from(value: RewardStream) -> Self {
        Self {
            funder: value.funder,
            startTime: value.start_time,
            endTime: value.end_time,
            ratePerSecondScaled: value.rate_per_second_scaled,
            amountTotal: value.amount_total,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        LINKING_USD_ADDRESS, storage::hashmap::HashMapStorageProvider, tip20::ISSUER_ROLE,
    };
    use alloy::primitives::{Address, U256};

    #[test]
    fn test_start_reward() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let current_time = storage.timestamp().to::<u64>();
        let admin = Address::random();

        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)?;

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE)?;

        let mint_amount = U256::from(1000e18);
        token.mint(
            &admin,
            ITIP20::mintCall {
                to: admin,
                amount: mint_amount,
            },
        )?;

        let reward_amount = U256::from(100e18);
        let stream_id = token.start_reward(
            &admin,
            ITIP20::startRewardCall {
                amount: reward_amount,
                seconds: 10,
            },
        )?;
        assert_eq!(stream_id, 1);

        let token_address = token.token_address;
        let balance = token.get_balance(&token_address)?;
        assert_eq!(balance, reward_amount);

        let stream = token.get_stream(stream_id)?;
        assert_eq!(stream.funder, admin);
        assert_eq!(stream.start_time, current_time);
        assert_eq!(stream.end_time, current_time + 10);

        let total_reward_per_second = token.get_total_reward_per_second()?;
        let expected_rate = (reward_amount * ACC_PRECISION) / U256::from(10);
        assert_eq!(total_reward_per_second, expected_rate);

        let reward_per_token_stored = token.get_reward_per_token_stored()?;
        assert_eq!(reward_per_token_stored, U256::ZERO);

        Ok(())
    }

    #[test]
    fn test_set_reward_recipient() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let alice = Address::random();

        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)?;

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE)?;

        let amount = U256::from(1000e18);
        token.mint(&admin, ITIP20::mintCall { to: alice, amount })?;

        token.set_reward_recipient(&alice, ITIP20::setRewardRecipientCall { recipient: alice })?;

        assert_eq!(token.get_reward_recipient_of(&alice)?, alice);
        assert_eq!(token.get_delegated_balance(&alice)?, amount);
        assert_eq!(token.get_opted_in_supply()?, amount);
        assert_eq!(token.get_user_reward_per_token_paid(&alice)?, U256::ZERO);

        token.set_reward_recipient(
            &alice,
            ITIP20::setRewardRecipientCall {
                recipient: Address::ZERO,
            },
        )?;

        assert_eq!(token.get_reward_recipient_of(&alice)?, Address::ZERO);
        assert_eq!(token.get_delegated_balance(&alice)?, U256::ZERO);
        assert_eq!(token.get_opted_in_supply()?, U256::ZERO);
        assert_eq!(token.get_user_reward_per_token_paid(&alice)?, U256::ZERO);

        Ok(())
    }

    #[test]
    fn test_cancel_reward() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)?;

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE)?;

        let mint_amount = U256::from(1000e18);
        token.mint(
            &admin,
            ITIP20::mintCall {
                to: admin,
                amount: mint_amount,
            },
        )?;

        let reward_amount = U256::from(100e18);
        let stream_id = token.start_reward(
            &admin,
            ITIP20::startRewardCall {
                amount: reward_amount,
                seconds: 10,
            },
        )?;

        let remaining = token.cancel_reward(&admin, ITIP20::cancelRewardCall { id: stream_id })?;

        let total_after = token.get_total_reward_per_second()?;
        assert_eq!(total_after, U256::ZERO);
        assert_eq!(remaining, reward_amount);

        let stream = token.get_stream(stream_id)?;
        assert!(stream.funder.is_zero());
        assert_eq!(stream.start_time, 0);
        assert_eq!(stream.end_time, 0);
        assert_eq!(stream.rate_per_second_scaled, U256::ZERO);

        let reward_per_token_stored = token.get_reward_per_token_stored()?;
        assert_eq!(reward_per_token_stored, U256::ZERO);

        let opted_in_supply = token.get_opted_in_supply()?;
        assert_eq!(opted_in_supply, U256::ZERO);

        Ok(())
    }

    #[test]
    fn test_update_rewards() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let alice = Address::random();

        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)?;

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE)?;

        let mint_amount = U256::from(1000e18);
        token.mint(
            &admin,
            ITIP20::mintCall {
                to: alice,
                amount: mint_amount,
            },
        )?;

        token.set_reward_recipient(&alice, ITIP20::setRewardRecipientCall { recipient: alice })?;

        let reward_amount = U256::from(100e18);
        token.mint(
            &admin,
            ITIP20::mintCall {
                to: admin,
                amount: reward_amount,
            },
        )?;

        // Distribute the reward immediately
        token.start_reward(
            &admin,
            ITIP20::startRewardCall {
                amount: reward_amount,
                seconds: 0,
            },
        )?;

        let alice_balance_before = token.get_balance(&alice)?;
        let reward_per_token_before = token.get_reward_per_token_stored()?;
        let _user_reward_per_token_paid_before = token.get_user_reward_per_token_paid(&alice)?;

        token.update_rewards(&alice)?;

        let alice_balance_after = token.get_balance(&alice)?;
        let reward_per_token_after = token.get_reward_per_token_stored()?;
        let user_reward_per_token_paid_after = token.get_user_reward_per_token_paid(&alice)?;

        assert!(alice_balance_after > alice_balance_before);
        assert!(reward_per_token_after >= reward_per_token_before);
        assert_eq!(user_reward_per_token_paid_after, reward_per_token_after);
        assert_eq!(token.get_opted_in_supply()?, mint_amount + reward_amount);
        assert_eq!(
            token.get_delegated_balance(&alice)?,
            mint_amount + reward_amount
        );

        Ok(())
    }

    #[test]
    fn test_accrue() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let alice = Address::random();

        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)?;

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE)?;

        let mint_amount = U256::from(1000e18);
        token.mint(
            &admin,
            ITIP20::mintCall {
                to: alice,
                amount: mint_amount,
            },
        )?;

        token.set_reward_recipient(&alice, ITIP20::setRewardRecipientCall { recipient: alice })?;

        let reward_amount = U256::from(100e18);
        token.mint(
            &admin,
            ITIP20::mintCall {
                to: admin,
                amount: reward_amount,
            },
        )?;

        token.start_reward(
            &admin,
            ITIP20::startRewardCall {
                amount: reward_amount,
                seconds: 100,
            },
        )?;

        let rpt_before = token.get_reward_per_token_stored()?;
        let last_update_before = token.get_last_update_time()?;

        let timestamp = token.storage.timestamp();
        token.accrue(timestamp)?;

        let rpt_after = token.get_reward_per_token_stored()?;
        let last_update_after = token.get_last_update_time()?;

        assert!(rpt_after >= rpt_before);
        assert!(last_update_after >= last_update_before);

        // Check total reward per second remains consistent
        let total_reward_per_second = token.get_total_reward_per_second()?;
        let expected_rate = (reward_amount * ACC_PRECISION) / U256::from(100);
        assert_eq!(total_reward_per_second, expected_rate);

        assert_eq!(token.get_opted_in_supply()?, mint_amount);
        assert_eq!(token.get_delegated_balance(&alice)?, mint_amount);
        assert_eq!(token.get_user_reward_per_token_paid(&alice)?, U256::ZERO);
        Ok(())
    }

    #[test]
    fn test_finalize_streams() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let current_time = storage.timestamp().to::<u128>();
        let admin = Address::random();
        let alice = Address::random();

        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)?;

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE)?;

        let mint_amount = U256::from(1000e18);
        token.mint(
            &admin,
            ITIP20::mintCall {
                to: alice,
                amount: mint_amount,
            },
        )?;

        token.set_reward_recipient(&alice, ITIP20::setRewardRecipientCall { recipient: alice })?;

        let reward_amount = U256::from(100e18);
        token.mint(
            &admin,
            ITIP20::mintCall {
                to: admin,
                amount: reward_amount,
            },
        )?;

        let stream_duration = 10u128;
        token.start_reward(
            &admin,
            ITIP20::startRewardCall {
                amount: reward_amount,
                seconds: stream_duration,
            },
        )?;

        let end_time = current_time + stream_duration;

        // Advance the timestamp to simulate time passing
        token.storage.set_timestamp(U256::from(end_time));

        let total_before = token.get_total_reward_per_second()?;
        token.finalize_streams(
            TIP20_REWARDS_REGISTRY_ADDRESS,
            token.storage.timestamp().to::<u128>(),
        )?;
        let total_after = token.get_total_reward_per_second()?;

        assert!(total_after < total_before);

        // Check reward per token stored has been updated
        let reward_per_token_stored = token.get_reward_per_token_stored()?;
        assert!(reward_per_token_stored > U256::ZERO);

        token.update_rewards(&alice)?;
        assert_eq!(token.get_opted_in_supply()?, mint_amount + reward_amount);
        assert_eq!(
            token.get_delegated_balance(&alice)?,
            mint_amount + reward_amount
        );
        assert_eq!(
            token.get_user_reward_per_token_paid(&alice)?,
            reward_per_token_stored
        );

        // TODO: assert balances

        Ok(())
    }

    #[test]
    fn test_start_reward_duration_0() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let alice = Address::random();

        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)?;

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE)?;

        // Mint tokens to Alice and have her opt in as reward recipient
        let mint_amount = U256::from(1000e18);
        token.mint(
            &admin,
            ITIP20::mintCall {
                to: alice,
                amount: mint_amount,
            },
        )?;

        token.set_reward_recipient(&alice, ITIP20::setRewardRecipientCall { recipient: alice })?;

        // Mint reward tokens to admin
        let reward_amount = U256::from(100e18);
        token.mint(
            &admin,
            ITIP20::mintCall {
                to: admin,
                amount: reward_amount,
            },
        )?;

        let alice_balance_before = token.get_balance(&alice)?;

        // Start immediate reward
        let id = token.start_reward(
            &admin,
            ITIP20::startRewardCall {
                amount: reward_amount,
                seconds: 0,
            },
        )?;

        assert_eq!(id, 0);

        let bob = Address::random();
        token.transfer(
            &alice,
            ITIP20::transferCall {
                to: bob,
                amount: U256::from(1),
            },
        )?;

        let alice_balance_after = token.get_balance(&alice)?;

        assert_eq!(
            alice_balance_after,
            alice_balance_before + reward_amount - U256::from(1)
        );

        let total_reward_per_second = token.get_total_reward_per_second()?;
        assert_eq!(total_reward_per_second, U256::ZERO);

        let opted_in_supply = token.get_opted_in_supply()?;
        assert_eq!(opted_in_supply, mint_amount + reward_amount - U256::ONE);

        Ok(())
    }

    #[test]
    fn test_reward_distribution_pro_rata() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let alice = Address::random();

        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)?;

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE)?;

        // Mint tokens to Alice and have her opt in as reward recipient
        let mint_amount = U256::from(1000e18);
        token.mint(
            &admin,
            ITIP20::mintCall {
                to: alice,
                amount: mint_amount,
            },
        )?;

        token.set_reward_recipient(&alice, ITIP20::setRewardRecipientCall { recipient: alice })?;

        // Mint reward tokens to admin
        let reward_amount = U256::from(100e18);
        token.mint(
            &admin,
            ITIP20::mintCall {
                to: admin,
                amount: reward_amount,
            },
        )?;

        let alice_balance_before = token.get_balance(&alice)?;

        // Start streaming reward for 20 seconds
        let stream_id = token.start_reward(
            &admin,
            ITIP20::startRewardCall {
                amount: reward_amount,
                seconds: 20,
            },
        )?;

        assert_eq!(stream_id, 1);

        // Simulate 10 blocks
        let current_timestamp = token.storage.timestamp();
        token
            .storage
            .set_timestamp(current_timestamp + uint!(10_U256));

        token.finalize_streams(
            TIP20_REWARDS_REGISTRY_ADDRESS,
            token.storage.timestamp().to::<u128>(),
        )?;
        token.transfer(
            &alice,
            ITIP20::transferCall {
                to: Address::random(),
                amount: U256::ONE,
            },
        )?;

        // Assert balances after first half elapsed
        let alice_balance_mid = token.get_balance(&alice)?;
        let expected_balance = alice_balance_before + (reward_amount / uint!(2_U256)) - U256::ONE;
        assert_eq!(alice_balance_mid, expected_balance);

        token
            .storage
            .set_timestamp(current_timestamp + uint!(20_U256));

        token.finalize_streams(
            TIP20_REWARDS_REGISTRY_ADDRESS,
            token.storage.timestamp().to::<u128>(),
        )?;
        token.transfer(
            &alice,
            ITIP20::transferCall {
                to: Address::random(),
                amount: U256::ONE,
            },
        )?;

        // Assert balances
        let alice_balance_after = token.get_balance(&alice)?;

        // NOTE: checking balance increased, loss precision due to rounding
        assert!(alice_balance_after > alice_balance_before);

        // Confirm that stream is finished
        let total_reward_per_second = token.get_total_reward_per_second()?;
        assert_eq!(total_reward_per_second, U256::ZERO);

        Ok(())
    }
}
