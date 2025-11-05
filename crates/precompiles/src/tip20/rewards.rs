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
    pub const GLOBAL_REWARD_PER_TOKEN: U256 = uint!(16_U256);
    pub const LAST_UPDATE_TIME: U256 = uint!(17_U256);
    pub const TOTAL_REWARD_PER_SECOND: U256 = uint!(18_U256);
    pub const OPTED_IN_SUPPLY: U256 = uint!(19_U256);
    pub const NEXT_STREAM_ID: U256 = uint!(20_U256);
    pub const STREAMS: U256 = uint!(21_U256);
    pub const SCHEDULED_RATE_DECREASE: U256 = uint!(22_U256);
    pub const USER_REWARD_INFO: U256 = uint!(23_U256);
}

impl<'a, S: PrecompileStorageProvider> TIP20Token<'a, S> {
    /// Starts a new reward stream for the token contract.
    ///
    /// This function allows an authorized user to fund a reward stream that distributes
    /// tokens to opted-in recipients either immediately if seconds=0, or over the specified
    /// duration.
    pub fn start_reward(
        &mut self,
        msg_sender: Address,
        call: ITIP20::startRewardCall,
    ) -> Result<u64, TempoPrecompileError> {
        self.check_not_paused()?;
        let token_address = self.token_address;
        self.ensure_transfer_authorized(msg_sender, token_address)?;

        if call.amount == U256::ZERO {
            return Err(TIP20Error::invalid_amount().into());
        }

        self._transfer(msg_sender, token_address, call.amount)?;

        if call.secs == 0 {
            let opted_in_supply = self.get_opted_in_supply()?;
            if opted_in_supply.is_zero() {
                return Err(TIP20Error::no_opted_in_supply().into());
            }

            let delta_rpt = call
                .amount
                .checked_mul(ACC_PRECISION)
                .and_then(|v| v.checked_div(opted_in_supply))
                .ok_or(TempoPrecompileError::under_overflow())?;
            let current_rpt = self.get_global_reward_per_token()?;
            let new_rpt = current_rpt
                .checked_add(delta_rpt)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_global_reward_per_token(new_rpt)?;

            // Emit reward scheduled event for immediate payout
            self.storage.emit_event(
                self.token_address,
                TIP20Event::RewardScheduled(ITIP20::RewardScheduled {
                    funder: msg_sender,
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
                .and_then(|v| v.checked_div(U256::from(call.secs)))
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
                .checked_add(call.secs as u128)
                .ok_or(TempoPrecompileError::under_overflow())?;

            RewardStream::new(
                stream_id,
                msg_sender,
                current_time as u64,
                end_time as u64,
                rate,
                call.amount,
            )
            .store(self.storage, self.token_address)?;

            let current_decrease = self.get_scheduled_rate_decrease_at(end_time)?;
            let new_decrease = current_decrease
                .checked_add(rate)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_scheduled_rate_decrease_at(end_time, new_decrease)?;

            // If the stream has not been added before, add it to the registry
            if current_decrease.is_zero() {
                let mut registry = TIP20RewardsRegistry::new(self.storage);
                registry.add_stream(self.token_address, end_time)?;
            }
            // Emit reward scheduled event for streaming reward
            self.storage.emit_event(
                self.token_address,
                TIP20Event::RewardScheduled(ITIP20::RewardScheduled {
                    funder: msg_sender,
                    id: stream_id,
                    amount: call.amount,
                    durationSeconds: call.secs,
                })
                .into_log_data(),
            )?;

            Ok(stream_id)
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
            let current_rpt = self.get_global_reward_per_token()?;
            let new_rpt = current_rpt
                .checked_add(delta_rpt)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_global_reward_per_token(new_rpt)?;
        }

        Ok(())
    }

    /// Updates and accumulates accrued rewards for a specific token holder.
    ///
    /// This function calculates the rewards earned by a holder based on their
    /// balance and the reward per token difference since their last update.
    /// Rewards are accumulated in the delegated recipient's rewardBalance.
    /// Returns the holder's delegated recipient address.
    pub fn update_rewards(&mut self, holder: Address) -> Result<Address, TempoPrecompileError> {
        let mut info = UserRewardInfo::from_storage(holder, self.storage, self.token_address)?;

        let cached_delegate = info.delegated_recipient;

        let global_reward_per_token = self.get_global_reward_per_token()?;
        let reward_per_token_delta = global_reward_per_token
            .checked_sub(info.reward_per_token)
            .ok_or(TempoPrecompileError::under_overflow())?;

        if reward_per_token_delta != U256::ZERO {
            if cached_delegate != Address::ZERO {
                let holder_balance = self.get_balance(holder)?;
                let reward = holder_balance
                    .checked_mul(reward_per_token_delta)
                    .and_then(|v| v.checked_div(ACC_PRECISION))
                    .ok_or(TempoPrecompileError::under_overflow())?;

                let mut delegate_info = UserRewardInfo::from_storage(
                    cached_delegate,
                    self.storage,
                    self.token_address,
                )?;
                delegate_info.reward_balance = delegate_info
                    .reward_balance
                    .checked_add(reward)
                    .ok_or(TempoPrecompileError::under_overflow())?;
                delegate_info.store(cached_delegate, self.storage, self.token_address)?;
            }
            info.reward_per_token = global_reward_per_token;
            info.store(holder, self.storage, self.token_address)?;
        }

        Ok(cached_delegate)
    }

    /// Sets or changes the reward recipient for a token holder.
    ///
    /// This function allows a token holder to designate who should receive their
    /// share of rewards. Setting to zero address opts out of rewards.
    pub fn set_reward_recipient(
        &mut self,
        msg_sender: Address,
        call: ITIP20::setRewardRecipientCall,
    ) -> Result<(), TempoPrecompileError> {
        self.check_not_paused()?;
        if call.recipient != Address::ZERO {
            self.ensure_transfer_authorized(msg_sender, call.recipient)?;
        }

        let timestamp = self.storage.timestamp();
        self.accrue(timestamp)?;

        let from_delegate = self.update_rewards(msg_sender)?;

        let holder_balance = self.get_balance(msg_sender)?;

        if from_delegate != Address::ZERO {
            if call.recipient == Address::ZERO {
                let opted_in_supply = self
                    .get_opted_in_supply()?
                    .checked_sub(holder_balance)
                    .ok_or(TempoPrecompileError::under_overflow())?;
                self.set_opted_in_supply(opted_in_supply)?;
            }
        } else if call.recipient != Address::ZERO {
            let opted_in_supply = self
                .get_opted_in_supply()?
                .checked_add(holder_balance)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_opted_in_supply(opted_in_supply)?;
        }

        let mut info = UserRewardInfo::from_storage(msg_sender, self.storage, self.token_address)?;
        info.delegated_recipient = call.recipient;
        info.store(msg_sender, self.storage, self.token_address)?;

        // Emit reward recipient set event
        self.storage.emit_event(
            self.token_address,
            TIP20Event::RewardRecipientSet(ITIP20::RewardRecipientSet {
                holder: msg_sender,
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
        msg_sender: Address,
        call: ITIP20::cancelRewardCall,
    ) -> Result<U256, TempoPrecompileError> {
        let stream_id = call.id;
        let stream = RewardStream::from_storage(stream_id, self.storage, self.token_address)?;

        if stream.funder.is_zero() {
            return Err(TIP20Error::stream_inactive().into());
        }

        if stream.funder != msg_sender {
            return Err(TIP20Error::not_stream_funder().into());
        }

        let current_time = self.storage.timestamp();
        if current_time >= stream.end_time {
            return Err(TIP20Error::stream_inactive().into());
        }

        self.accrue(current_time)?;

        let elapsed = if current_time > U256::from(stream.start_time) {
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
        let refund = stream
            .amount_total
            .checked_sub(distributed)
            .ok_or(TempoPrecompileError::under_overflow())?;

        let total_rps = self
            .get_total_reward_per_second()?
            .checked_sub(stream.rate_per_second_scaled)
            .ok_or(TempoPrecompileError::under_overflow())?;
        self.set_total_reward_per_second(total_rps)?;

        let end_time = stream.end_time as u128;
        let new_rate = self
            .get_scheduled_rate_decrease_at(end_time)?
            .checked_sub(stream.rate_per_second_scaled)
            .ok_or(TempoPrecompileError::under_overflow())?;
        self.set_scheduled_rate_decrease_at(end_time, new_rate)?;

        stream.delete(self.storage, self.token_address)?;

        let mut actual_refund = U256::ZERO;
        if refund > U256::ZERO && self.is_transfer_authorized(stream.funder, stream.funder)? {
            let funder_delegate = self.update_rewards(stream.funder)?;
            if funder_delegate != Address::ZERO {
                let opted_in_supply = self
                    .get_opted_in_supply()?
                    .checked_add(refund)
                    .ok_or(TempoPrecompileError::under_overflow())?;
                self.set_opted_in_supply(opted_in_supply)?;
            }

            let contract_address = self.token_address;
            let contract_balance = self
                .get_balance(contract_address)?
                .checked_sub(refund)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_balance(contract_address, contract_balance)?;

            let funder_balance = self
                .get_balance(stream.funder)?
                .checked_add(refund)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_balance(stream.funder, funder_balance)?;

            self.storage.emit_event(
                self.token_address,
                TIP20Event::Transfer(ITIP20::Transfer {
                    from: contract_address,
                    to: stream.funder,
                    amount: refund,
                })
                .into_log_data(),
            )?;

            actual_refund = refund;
        }

        self.storage.emit_event(
            self.token_address,
            TIP20Event::RewardCanceled(ITIP20::RewardCanceled {
                funder: stream.funder,
                id: stream_id,
                refund: actual_refund,
            })
            .into_log_data(),
        )?;

        Ok(actual_refund)
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

        let rate_decrease = self.get_scheduled_rate_decrease_at(end_time)?;

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

    /// Claims accumulated rewards for a recipient.
    ///
    /// This function allows a reward recipient to claim their accumulated rewards
    /// and receive them as token transfers to their own balance.
    pub fn claim_rewards(&mut self, msg_sender: Address) -> Result<U256, TempoPrecompileError> {
        self.check_not_paused()?;
        self.ensure_transfer_authorized(msg_sender, msg_sender)?;

        let timestamp = self.storage.timestamp();
        self.accrue(timestamp)?;
        self.update_rewards(msg_sender)?;

        let mut info = UserRewardInfo::from_storage(msg_sender, self.storage, self.token_address)?;
        let amount = info.reward_balance;
        let contract_address = self.token_address;
        let contract_balance = self.get_balance(contract_address)?;
        let max_amount = amount.min(contract_balance);

        info.reward_balance = amount
            .checked_sub(max_amount)
            .ok_or(TempoPrecompileError::under_overflow())?;
        info.store(msg_sender, self.storage, self.token_address)?;

        if max_amount > U256::ZERO {
            let new_contract_balance = contract_balance
                .checked_sub(max_amount)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_balance(contract_address, new_contract_balance)?;

            let recipient_balance = self
                .get_balance(msg_sender)?
                .checked_add(max_amount)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_balance(msg_sender, recipient_balance)?;

            if info.delegated_recipient != Address::ZERO {
                let opted_in_supply = self
                    .get_opted_in_supply()?
                    .checked_add(max_amount)
                    .ok_or(TempoPrecompileError::under_overflow())?;
                self.set_opted_in_supply(opted_in_supply)?;
            }

            self.storage.emit_event(
                self.token_address,
                TIP20Event::Transfer(ITIP20::Transfer {
                    from: contract_address,
                    to: msg_sender,
                    amount: max_amount,
                })
                .into_log_data(),
            )?;
        }

        Ok(max_amount)
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

    /// Gets the accumulated global reward per token.
    fn get_global_reward_per_token(&mut self) -> Result<U256, TempoPrecompileError> {
        self.storage
            .sload(self.token_address, slots::GLOBAL_REWARD_PER_TOKEN)
    }

    /// Sets the accumulated global reward per token in storage.
    fn set_global_reward_per_token(&mut self, value: U256) -> Result<(), TempoPrecompileError> {
        self.storage
            .sstore(self.token_address, slots::GLOBAL_REWARD_PER_TOKEN, value)
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

    /// Gets the scheduled rate decrease at a specific time from storage.
    fn get_scheduled_rate_decrease_at(
        &mut self,
        end_time: u128,
    ) -> Result<U256, TempoPrecompileError> {
        let slot = mapping_slot(end_time.to_be_bytes(), slots::SCHEDULED_RATE_DECREASE);
        self.storage.sload(self.token_address, slot)
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
    pub fn handle_rewards_on_transfer(
        &mut self,
        from: Address,
        to: Address,
        amount: U256,
    ) -> Result<(), TempoPrecompileError> {
        let from_delegate = self.update_rewards(from)?;
        let to_delegate = self.update_rewards(to)?;

        if !from_delegate.is_zero() {
            if to_delegate.is_zero() {
                let opted_in_supply = self
                    .get_opted_in_supply()?
                    .checked_sub(amount)
                    .ok_or(TempoPrecompileError::under_overflow())?;
                self.set_opted_in_supply(opted_in_supply)?;
            }
        } else if !to_delegate.is_zero() {
            let opted_in_supply = self
                .get_opted_in_supply()?
                .checked_add(amount)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_opted_in_supply(opted_in_supply)?;
        }

        Ok(())
    }

    /// Handles reward accounting when tokens are minted to an address.
    pub fn handle_rewards_on_mint(
        &mut self,
        to: Address,
        amount: U256,
    ) -> Result<(), TempoPrecompileError> {
        let to_delegate = self.update_rewards(to)?;

        if !to_delegate.is_zero() {
            let opted_in_supply = self
                .get_opted_in_supply()?
                .checked_add(amount)
                .ok_or(TempoPrecompileError::under_overflow())?;
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
pub struct UserRewardInfo {
    pub delegated_recipient: Address,
    pub reward_per_token: U256,
    pub reward_balance: U256,
}

impl UserRewardInfo {
    pub const DELEGATED_RECIPIENT_OFFSET: U256 = uint!(0_U256);
    pub const REWARD_PER_TOKEN_OFFSET: U256 = uint!(1_U256);
    pub const REWARD_BALANCE_OFFSET: U256 = uint!(2_U256);

    /// Loads a UserRewardInfo from contract storage.
    pub fn from_storage<S: PrecompileStorageProvider>(
        account: Address,
        storage: &mut S,
        token_address: Address,
    ) -> Result<Self, TempoPrecompileError> {
        let user_slot = mapping_slot(account, slots::USER_REWARD_INFO);

        let delegated_recipient = storage
            .sload(token_address, user_slot + Self::DELEGATED_RECIPIENT_OFFSET)?
            .into_address();

        let reward_per_token =
            storage.sload(token_address, user_slot + Self::REWARD_PER_TOKEN_OFFSET)?;

        let reward_balance =
            storage.sload(token_address, user_slot + Self::REWARD_BALANCE_OFFSET)?;

        Ok(Self {
            delegated_recipient,
            reward_per_token,
            reward_balance,
        })
    }

    /// Stores this UserRewardInfo to contract storage.
    pub fn store<S: PrecompileStorageProvider>(
        &self,
        account: Address,
        storage: &mut S,
        token_address: Address,
    ) -> Result<(), TempoPrecompileError> {
        let user_slot = mapping_slot(account, slots::USER_REWARD_INFO);

        storage.sstore(
            token_address,
            user_slot + Self::DELEGATED_RECIPIENT_OFFSET,
            self.delegated_recipient.into_u256(),
        )?;

        storage.sstore(
            token_address,
            user_slot + Self::REWARD_PER_TOKEN_OFFSET,
            self.reward_per_token,
        )?;

        storage.sstore(
            token_address,
            user_slot + Self::REWARD_BALANCE_OFFSET,
            self.reward_balance,
        )?;

        Ok(())
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
        let stream_slot = mapping_slot(stream_id.to_be_bytes(), slots::STREAMS);

        let funder = storage
            .sload(token_address, stream_slot + Self::STREAM_FUNDER_OFFSET)?
            .into_address();

        let start_time = storage
            .sload(token_address, stream_slot + Self::STREAM_START_TIME_OFFSET)?
            .to::<u64>();

        let end_time = storage
            .sload(token_address, stream_slot + Self::STREAM_END_TIME_OFFSET)?
            .to::<u64>();

        let rate_per_second_scaled =
            storage.sload(token_address, stream_slot + Self::STREAM_RATE_OFFSET)?;

        let amount_total = storage.sload(
            token_address,
            stream_slot + Self::STREAM_AMOUNT_TOTAL_OFFSET,
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
        let stream_slot = mapping_slot(self.stream_id.to_be_bytes(), slots::STREAMS);

        storage.sstore(
            token_address,
            stream_slot + Self::STREAM_FUNDER_OFFSET,
            self.funder.into_u256(),
        )?;

        storage.sstore(
            token_address,
            stream_slot + Self::STREAM_START_TIME_OFFSET,
            U256::from(self.start_time),
        )?;

        storage.sstore(
            token_address,
            stream_slot + Self::STREAM_END_TIME_OFFSET,
            U256::from(self.end_time),
        )?;

        storage.sstore(
            token_address,
            stream_slot + Self::STREAM_RATE_OFFSET,
            self.rate_per_second_scaled,
        )?;

        storage.sstore(
            token_address,
            stream_slot + Self::STREAM_AMOUNT_TOTAL_OFFSET,
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
        let stream_slot = mapping_slot(self.stream_id.to_be_bytes(), slots::STREAMS);

        storage.sstore(
            token_address,
            stream_slot + Self::STREAM_FUNDER_OFFSET,
            U256::ZERO,
        )?;

        storage.sstore(
            token_address,
            stream_slot + Self::STREAM_START_TIME_OFFSET,
            U256::ZERO,
        )?;

        storage.sstore(
            token_address,
            stream_slot + Self::STREAM_END_TIME_OFFSET,
            U256::ZERO,
        )?;

        storage.sstore(
            token_address,
            stream_slot + Self::STREAM_RATE_OFFSET,
            U256::ZERO,
        )?;

        storage.sstore(
            token_address,
            stream_slot + Self::STREAM_AMOUNT_TOTAL_OFFSET,
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
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, admin)?;

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(admin, *ISSUER_ROLE)?;

        let mint_amount = U256::from(1000e18);
        token.mint(
            admin,
            ITIP20::mintCall {
                to: admin,
                amount: mint_amount,
            },
        )?;

        let reward_amount = U256::from(100e18);
        let stream_id = token.start_reward(
            admin,
            ITIP20::startRewardCall {
                amount: reward_amount,
                secs: 10,
            },
        )?;
        assert_eq!(stream_id, 1);

        let token_address = token.token_address;
        let balance = token.get_balance(token_address)?;
        assert_eq!(balance, reward_amount);

        let stream = token.get_stream(stream_id)?;
        assert_eq!(stream.funder, admin);
        assert_eq!(stream.start_time, current_time);
        assert_eq!(stream.end_time, current_time + 10);

        let total_reward_per_second = token.get_total_reward_per_second()?;
        let expected_rate = (reward_amount * ACC_PRECISION) / U256::from(10);
        assert_eq!(total_reward_per_second, expected_rate);

        let global_reward_per_token = token.get_global_reward_per_token()?;
        assert_eq!(global_reward_per_token, U256::ZERO);

        Ok(())
    }

    #[test]
    fn test_set_reward_recipient() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let alice = Address::random();

        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, admin)?;

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(admin, *ISSUER_ROLE)?;

        let amount = U256::from(1000e18);
        token.mint(admin, ITIP20::mintCall { to: alice, amount })?;

        token.set_reward_recipient(alice, ITIP20::setRewardRecipientCall { recipient: alice })?;

        let info = UserRewardInfo::from_storage(alice, token.storage, token.token_address)?;
        assert_eq!(info.delegated_recipient, alice);
        assert_eq!(token.get_opted_in_supply()?, amount);
        assert_eq!(info.reward_per_token, U256::ZERO);

        token.set_reward_recipient(
            alice,
            ITIP20::setRewardRecipientCall {
                recipient: Address::ZERO,
            },
        )?;

        let info = UserRewardInfo::from_storage(alice, token.storage, token.token_address)?;
        assert_eq!(info.delegated_recipient, Address::ZERO);
        assert_eq!(token.get_opted_in_supply()?, U256::ZERO);
        assert_eq!(info.reward_per_token, U256::ZERO);

        Ok(())
    }

    #[test]
    fn test_cancel_reward() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, admin)?;

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(admin, *ISSUER_ROLE)?;

        let mint_amount = U256::from(1000e18);
        token.mint(
            admin,
            ITIP20::mintCall {
                to: admin,
                amount: mint_amount,
            },
        )?;

        let reward_amount = U256::from(100e18);
        let stream_id = token.start_reward(
            admin,
            ITIP20::startRewardCall {
                amount: reward_amount,
                secs: 10,
            },
        )?;

        let remaining = token.cancel_reward(admin, ITIP20::cancelRewardCall { id: stream_id })?;

        let total_after = token.get_total_reward_per_second()?;
        assert_eq!(total_after, U256::ZERO);
        assert_eq!(remaining, reward_amount);

        let stream = token.get_stream(stream_id)?;
        assert!(stream.funder.is_zero());
        assert_eq!(stream.start_time, 0);
        assert_eq!(stream.end_time, 0);
        assert_eq!(stream.rate_per_second_scaled, U256::ZERO);

        let global_reward_per_token = token.get_global_reward_per_token()?;
        assert_eq!(global_reward_per_token, U256::ZERO);

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
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, admin)?;

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(admin, *ISSUER_ROLE)?;

        let mint_amount = U256::from(1000e18);
        token.mint(
            admin,
            ITIP20::mintCall {
                to: alice,
                amount: mint_amount,
            },
        )?;

        token.set_reward_recipient(alice, ITIP20::setRewardRecipientCall { recipient: alice })?;

        let reward_amount = U256::from(100e18);
        token.mint(
            admin,
            ITIP20::mintCall {
                to: admin,
                amount: reward_amount,
            },
        )?;

        // Distribute the reward immediately
        token.start_reward(
            admin,
            ITIP20::startRewardCall {
                amount: reward_amount,
                secs: 0,
            },
        )?;

        token.update_rewards(alice)?;
        let info_after = UserRewardInfo::from_storage(alice, token.storage, token.token_address)?;
        let global_rpt_after = token.get_global_reward_per_token()?;

        assert_eq!(info_after.reward_per_token, global_rpt_after);

        Ok(())
    }

    #[test]
    fn test_accrue() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let alice = Address::random();

        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, admin)?;

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(admin, *ISSUER_ROLE)?;

        let mint_amount = U256::from(1000e18);
        token.mint(
            admin,
            ITIP20::mintCall {
                to: alice,
                amount: mint_amount,
            },
        )?;

        token.set_reward_recipient(alice, ITIP20::setRewardRecipientCall { recipient: alice })?;

        let reward_amount = U256::from(100e18);
        token.mint(
            admin,
            ITIP20::mintCall {
                to: admin,
                amount: reward_amount,
            },
        )?;

        token.start_reward(
            admin,
            ITIP20::startRewardCall {
                amount: reward_amount,
                secs: 100,
            },
        )?;

        let rpt_before = token.get_global_reward_per_token()?;
        let last_update_before = token.get_last_update_time()?;

        let timestamp = token.storage.timestamp();
        token.accrue(timestamp)?;

        let rpt_after = token.get_global_reward_per_token()?;
        let last_update_after = token.get_last_update_time()?;

        assert!(rpt_after >= rpt_before);
        assert!(last_update_after >= last_update_before);

        let total_reward_per_second = token.get_total_reward_per_second()?;
        let expected_rate = (reward_amount * ACC_PRECISION) / U256::from(100);
        assert_eq!(total_reward_per_second, expected_rate);

        assert_eq!(token.get_opted_in_supply()?, mint_amount);
        let info = UserRewardInfo::from_storage(alice, token.storage, token.token_address)?;
        assert_eq!(info.reward_per_token, U256::ZERO);
        Ok(())
    }

    #[test]
    fn test_finalize_streams() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let current_time = storage.timestamp().to::<u128>();
        let admin = Address::random();
        let alice = Address::random();

        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, admin)?;

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(admin, *ISSUER_ROLE)?;

        let mint_amount = U256::from(1000e18);
        token.mint(
            admin,
            ITIP20::mintCall {
                to: alice,
                amount: mint_amount,
            },
        )?;

        token.set_reward_recipient(alice, ITIP20::setRewardRecipientCall { recipient: alice })?;

        let reward_amount = U256::from(100e18);
        token.mint(
            admin,
            ITIP20::mintCall {
                to: admin,
                amount: reward_amount,
            },
        )?;

        let stream_duration = 10u32;
        token.start_reward(
            admin,
            ITIP20::startRewardCall {
                amount: reward_amount,
                secs: stream_duration,
            },
        )?;

        let end_time = current_time + stream_duration as u128;

        // Advance the timestamp to simulate time passing
        token.storage.set_timestamp(U256::from(end_time));

        let total_before = token.get_total_reward_per_second()?;
        token.finalize_streams(
            TIP20_REWARDS_REGISTRY_ADDRESS,
            token.storage.timestamp().to::<u128>(),
        )?;
        let total_after = token.get_total_reward_per_second()?;

        assert!(total_after < total_before);

        let global_rpt = token.get_global_reward_per_token()?;
        assert!(global_rpt > U256::ZERO);

        token.update_rewards(alice)?;
        let info = UserRewardInfo::from_storage(alice, token.storage, token.token_address)?;
        assert_eq!(info.reward_per_token, global_rpt);

        Ok(())
    }

    #[test]
    fn test_start_reward_duration_0() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let alice = Address::random();

        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, admin)?;

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(admin, *ISSUER_ROLE)?;

        // Mint tokens to Alice and have her opt in as reward recipient
        let mint_amount = U256::from(1000e18);
        token.mint(
            admin,
            ITIP20::mintCall {
                to: alice,
                amount: mint_amount,
            },
        )?;

        token.set_reward_recipient(alice, ITIP20::setRewardRecipientCall { recipient: alice })?;

        // Mint reward tokens to admin
        let reward_amount = U256::from(100e18);
        token.mint(
            admin,
            ITIP20::mintCall {
                to: admin,
                amount: reward_amount,
            },
        )?;

        // Start immediate reward
        let id = token.start_reward(
            admin,
            ITIP20::startRewardCall {
                amount: reward_amount,
                secs: 0,
            },
        )?;

        assert_eq!(id, 0);

        let total_reward_per_second = token.get_total_reward_per_second()?;
        assert_eq!(total_reward_per_second, U256::ZERO);

        Ok(())
    }

    #[test]
    fn test_reward_distribution_pro_rata() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let alice = Address::random();

        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, admin)?;

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(admin, *ISSUER_ROLE)?;

        // Mint tokens to Alice and have her opt in as reward recipient
        let mint_amount = U256::from(1000e18);
        token.mint(
            admin,
            ITIP20::mintCall {
                to: alice,
                amount: mint_amount,
            },
        )?;

        token.set_reward_recipient(alice, ITIP20::setRewardRecipientCall { recipient: alice })?;

        // Mint reward tokens to admin
        let reward_amount = U256::from(100e18);
        token.mint(
            admin,
            ITIP20::mintCall {
                to: admin,
                amount: reward_amount,
            },
        )?;

        // Start streaming reward for 20 seconds
        let stream_id = token.start_reward(
            admin,
            ITIP20::startRewardCall {
                amount: reward_amount,
                secs: 20,
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

        token
            .storage
            .set_timestamp(current_timestamp + uint!(20_U256));

        token.finalize_streams(
            TIP20_REWARDS_REGISTRY_ADDRESS,
            token.storage.timestamp().to::<u128>(),
        )?;

        let total_reward_per_second = token.get_total_reward_per_second()?;
        assert_eq!(total_reward_per_second, U256::ZERO);

        Ok(())
    }
}
