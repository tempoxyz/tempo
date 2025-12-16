use crate::{
    TIP20_REWARDS_REGISTRY_ADDRESS,
    account_keychain::AccountKeychain,
    error::{Result, TempoPrecompileError},
    storage::Handler,
    tip20::TIP20Token,
    tip20_rewards_registry::TIP20RewardsRegistry,
};
use alloy::primitives::{Address, U256, uint};
use tempo_contracts::precompiles::{ITIP20, TIP20Error, TIP20Event};
use tempo_precompiles_macros::Storable;

pub const ACC_PRECISION: U256 = uint!(1000000000000000000_U256);

impl TIP20Token {
    /// Starts a new reward stream for the token contract.
    ///
    /// This function allows an authorized user to fund a reward stream that distributes
    /// tokens to opted-in recipients either immediately if seconds=0, or over the specified
    /// duration.
    pub fn start_reward(
        &mut self,
        msg_sender: Address,
        call: ITIP20::startRewardCall,
    ) -> Result<u64> {
        self.check_not_paused()?;
        let token_address = self.address;
        self.ensure_transfer_authorized(msg_sender, token_address)?;

        if call.amount == U256::ZERO {
            return Err(TIP20Error::invalid_amount().into());
        }

        // Only check access keys after Allegro Moderato hardfork
        if self.storage.spec().is_allegro_moderato() {
            // Check and update spending limits for access keys
            let mut keychain = AccountKeychain::new();
            keychain.authorize_transfer(msg_sender, token_address, call.amount)?;
        }

        self._transfer(msg_sender, token_address, call.amount)?;

        if call.secs == 0 {
            let opted_in_supply = U256::from(self.get_opted_in_supply()?);
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
            self.emit_event(TIP20Event::RewardScheduled(ITIP20::RewardScheduled {
                funder: msg_sender,
                id: 0,
                amount: call.amount,
                durationSeconds: 0,
            }))?;

            Ok(0)
        } else {
            // Scheduled rewards are disabled post-Moderato hardfork
            if self.storage.spec().is_moderato() {
                return Err(TIP20Error::scheduled_rewards_disabled().into());
            }

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

            self.streams.at(stream_id).write(RewardStream::new(
                msg_sender,
                current_time as u64,
                end_time as u64,
                rate,
                call.amount,
            ))?;

            let current_decrease = self.get_scheduled_rate_decrease_at(end_time)?;
            let new_decrease = current_decrease
                .checked_add(rate)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_scheduled_rate_decrease_at(end_time, new_decrease)?;

            // If the stream has not been added before, add it to the registry
            if current_decrease.is_zero() {
                let mut registry = TIP20RewardsRegistry::new();
                registry.add_stream(self.address, end_time)?;
            }
            // Emit reward scheduled event for streaming reward
            self.emit_event(TIP20Event::RewardScheduled(ITIP20::RewardScheduled {
                funder: msg_sender,
                id: stream_id,
                amount: call.amount,
                durationSeconds: call.secs,
            }))?;

            Ok(stream_id)
        }
    }

    /// Accrues rewards based on elapsed time since last update.
    ///
    /// This function calculates and updates the reward per token stored based on
    /// the total reward rate and the time elapsed since the last update.
    /// Only processes rewards if there is an opted-in supply.
    pub fn accrue(&mut self, accrue_to_timestamp: U256) -> Result<()> {
        let elapsed = accrue_to_timestamp
            .checked_sub(U256::from(self.get_last_update_time()?))
            .ok_or(TempoPrecompileError::under_overflow())?;
        if elapsed.is_zero() {
            return Ok(());
        }

        // NOTE(rusowsky): first limb = u64, so it should be fine.
        // however, it would be easier to always work with U256, since
        // there is no possible slot packing in this slot (surrounded by U256)
        self.set_last_update_time(accrue_to_timestamp.to::<u64>())?;

        let opted_in_supply = U256::from(self.get_opted_in_supply()?);
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
    pub fn update_rewards(&mut self, holder: Address) -> Result<Address> {
        let mut info = self.user_reward_info.at(holder).read()?;

        let cached_delegate = info.reward_recipient;

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

                // Add reward to delegate's balance (or holder's own balance if self-delegated)
                if cached_delegate == holder {
                    info.reward_balance = info
                        .reward_balance
                        .checked_add(reward)
                        .ok_or(TempoPrecompileError::under_overflow())?;
                } else {
                    let mut delegate_info = self.user_reward_info.at(cached_delegate).read()?;
                    delegate_info.reward_balance = delegate_info
                        .reward_balance
                        .checked_add(reward)
                        .ok_or(TempoPrecompileError::under_overflow())?;
                    self.user_reward_info
                        .at(cached_delegate)
                        .write(delegate_info)?;
                }
            }
            info.reward_per_token = global_reward_per_token;
            self.user_reward_info.at(holder).write(info)?;
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
    ) -> Result<()> {
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
                let opted_in_supply = U256::from(self.get_opted_in_supply()?)
                    .checked_sub(holder_balance)
                    .ok_or(TempoPrecompileError::under_overflow())?;
                self.set_opted_in_supply(
                    opted_in_supply
                        .try_into()
                        .map_err(|_| TempoPrecompileError::under_overflow())?,
                )?;
            }
        } else if call.recipient != Address::ZERO {
            let opted_in_supply = U256::from(self.get_opted_in_supply()?)
                .checked_add(holder_balance)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_opted_in_supply(
                opted_in_supply
                    .try_into()
                    .map_err(|_| TempoPrecompileError::under_overflow())?,
            )?;
        }

        let mut info = self.user_reward_info.at(msg_sender).read()?;
        info.reward_recipient = call.recipient;
        self.user_reward_info.at(msg_sender).write(info)?;

        // Emit reward recipient set event
        self.emit_event(TIP20Event::RewardRecipientSet(ITIP20::RewardRecipientSet {
            holder: msg_sender,
            recipient: call.recipient,
        }))?;

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
    ) -> Result<U256> {
        let stream_id = call.id;
        let stream = self.streams.at(stream_id).read()?;

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
            current_time
                .checked_sub(U256::from(stream.start_time))
                .ok_or(TempoPrecompileError::under_overflow())?
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

        // Remove from registry when all streams at this end_time are cancelled (Moderato+)
        if self.storage.spec().is_moderato() && new_rate == U256::ZERO {
            let mut registry = TIP20RewardsRegistry::new();
            registry.remove_stream(self.address, end_time)?;
        }

        self.streams.at(stream_id).delete()?;

        let mut actual_refund = U256::ZERO;
        if refund > U256::ZERO && self.is_transfer_authorized(stream.funder, self.address)? {
            let funder_delegate = self.update_rewards(stream.funder)?;
            if funder_delegate != Address::ZERO {
                let opted_in_supply = U256::from(self.get_opted_in_supply()?)
                    .checked_add(refund)
                    .ok_or(TempoPrecompileError::under_overflow())?;
                self.set_opted_in_supply(
                    opted_in_supply
                        .try_into()
                        .map_err(|_| TempoPrecompileError::under_overflow())?,
                )?;
            }

            let contract_address = self.address;
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

            self.emit_event(TIP20Event::Transfer(ITIP20::Transfer {
                from: contract_address,
                to: stream.funder,
                amount: refund,
            }))?;

            actual_refund = refund;
        }

        self.emit_event(TIP20Event::RewardCanceled(ITIP20::RewardCanceled {
            funder: stream.funder,
            id: stream_id,
            refund: actual_refund,
        }))?;

        Ok(actual_refund)
    }

    /// Finalizes expired reward streams by updating the total reward rate.
    ///
    /// This function is called to clean up streams that have reached their end time,
    /// reducing the total reward per second rate by the amount of the expired streams.
    pub fn finalize_streams(&mut self, msg_sender: Address, end_time: u128) -> Result<()> {
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
    pub fn claim_rewards(&mut self, msg_sender: Address) -> Result<U256> {
        self.check_not_paused()?;
        self.ensure_transfer_authorized(msg_sender, msg_sender)?;

        let timestamp = self.storage.timestamp();
        self.accrue(timestamp)?;
        self.update_rewards(msg_sender)?;

        let mut info = self.user_reward_info.at(msg_sender).read()?;
        let amount = info.reward_balance;
        let contract_address = self.address;
        let contract_balance = self.get_balance(contract_address)?;
        let max_amount = amount.min(contract_balance);

        let reward_recipient = info.reward_recipient;
        info.reward_balance = amount
            .checked_sub(max_amount)
            .ok_or(TempoPrecompileError::under_overflow())?;
        self.user_reward_info.at(msg_sender).write(info)?;

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

            if reward_recipient != Address::ZERO {
                let opted_in_supply = U256::from(self.get_opted_in_supply()?)
                    .checked_add(max_amount)
                    .ok_or(TempoPrecompileError::under_overflow())?;
                self.set_opted_in_supply(
                    opted_in_supply
                        .try_into()
                        .map_err(|_| TempoPrecompileError::under_overflow())?,
                )?;
            }

            self.emit_event(TIP20Event::Transfer(ITIP20::Transfer {
                from: contract_address,
                to: msg_sender,
                amount: max_amount,
            }))?;
        }

        Ok(max_amount)
    }

    /// Gets the next available stream ID (minimum 1).
    pub fn get_next_stream_id(&self) -> Result<u64> {
        self.next_stream_id.read().map(|id| id.max(1))
    }

    /// Sets the next stream ID counter.
    fn set_next_stream_id(&mut self, value: u64) -> Result<()> {
        self.next_stream_id.write(value)
    }

    /// Gets the accumulated global reward per token.
    fn get_global_reward_per_token(&self) -> Result<U256> {
        self.global_reward_per_token.read()
    }

    /// Sets the accumulated global reward per token in storage.
    fn set_global_reward_per_token(&mut self, value: U256) -> Result<()> {
        self.global_reward_per_token.write(value)
    }

    /// Gets the timestamp of the last reward update from storage.
    fn get_last_update_time(&self) -> Result<u64> {
        self.last_update_time.read()
    }

    /// Sets the timestamp of the last reward update in storage.
    fn set_last_update_time(&mut self, value: u64) -> Result<()> {
        self.last_update_time.write(value)
    }

    /// Gets the total supply of tokens opted into rewards from storage.
    pub fn get_opted_in_supply(&self) -> Result<u128> {
        self.opted_in_supply.read()
    }

    /// Sets the total supply of tokens opted into rewards in storage.
    pub fn set_opted_in_supply(&mut self, value: u128) -> Result<()> {
        self.opted_in_supply.write(value)
    }

    /// Gets the scheduled rate decrease at a specific time from storage.
    fn get_scheduled_rate_decrease_at(&self, end_time: u128) -> Result<U256> {
        self.scheduled_rate_decrease.at(end_time).read()
    }

    /// Sets the scheduled rate decrease at a specific time in storage.
    fn set_scheduled_rate_decrease_at(&mut self, end_time: u128, value: U256) -> Result<()> {
        self.scheduled_rate_decrease.at(end_time).write(value)
    }

    /// Gets the total reward per second rate from storage.
    pub fn get_total_reward_per_second(&self) -> Result<U256> {
        self.total_reward_per_second.read()
    }

    /// Sets the total reward per second rate in storage.
    fn set_total_reward_per_second(&mut self, value: U256) -> Result<()> {
        self.total_reward_per_second.write(value)
    }

    /// Handles reward accounting for both sender and receiver during token transfers.
    pub fn handle_rewards_on_transfer(
        &mut self,
        from: Address,
        to: Address,
        amount: U256,
    ) -> Result<()> {
        let from_delegate = self.update_rewards(from)?;
        let to_delegate = self.update_rewards(to)?;

        if !from_delegate.is_zero() {
            if to_delegate.is_zero() {
                let opted_in_supply = U256::from(self.get_opted_in_supply()?)
                    .checked_sub(amount)
                    .ok_or(TempoPrecompileError::under_overflow())?;
                self.set_opted_in_supply(
                    opted_in_supply
                        .try_into()
                        .map_err(|_| TempoPrecompileError::under_overflow())?,
                )?;
            }
        } else if !to_delegate.is_zero() {
            let opted_in_supply = U256::from(self.get_opted_in_supply()?)
                .checked_add(amount)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_opted_in_supply(
                opted_in_supply
                    .try_into()
                    .map_err(|_| TempoPrecompileError::under_overflow())?,
            )?;
        }

        Ok(())
    }

    /// Handles reward accounting when tokens are minted to an address.
    pub fn handle_rewards_on_mint(&mut self, to: Address, amount: U256) -> Result<()> {
        let to_delegate = self.update_rewards(to)?;

        if !to_delegate.is_zero() {
            let opted_in_supply = U256::from(self.get_opted_in_supply()?)
                .checked_add(amount)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_opted_in_supply(
                opted_in_supply
                    .try_into()
                    .map_err(|_| TempoPrecompileError::under_overflow())?,
            )?;
        }

        Ok(())
    }

    /// Retrieves a reward stream by its ID.
    pub fn get_stream(&self, stream_id: u64) -> Result<RewardStream> {
        self.streams.at(stream_id).read()
    }

    /// Retrieves user reward information for a given account.
    pub fn get_user_reward_info(&self, account: Address) -> Result<UserRewardInfo> {
        self.user_reward_info.at(account).read()
    }
}

#[derive(Debug, Clone, Storable)]
pub struct UserRewardInfo {
    pub reward_recipient: Address,
    pub reward_per_token: U256,
    pub reward_balance: U256,
}

#[derive(Debug, Clone, Storable)]
pub struct RewardStream {
    funder: Address,
    start_time: u64,
    end_time: u64,
    rate_per_second_scaled: U256,
    amount_total: U256,
}

impl RewardStream {
    /// Creates a new RewardStream instance.
    pub fn new(
        funder: Address,
        start_time: u64,
        end_time: u64,
        rate_per_second_scaled: U256,
        amount_total: U256,
    ) -> Self {
        Self {
            funder,
            start_time,
            end_time,
            rate_per_second_scaled,
            amount_total,
        }
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

impl From<UserRewardInfo> for ITIP20::UserRewardInfo {
    fn from(value: UserRewardInfo) -> Self {
        Self {
            rewardRecipient: value.reward_recipient,
            rewardPerToken: value.reward_per_token,
            rewardBalance: value.reward_balance,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        PATH_USD_ADDRESS,
        storage::{
            ContractStorage, PrecompileStorageProvider, StorageCtx, hashmap::HashMapStorageProvider,
        },
        test_util::TIP20Setup,
        tip20::{ISSUER_ROLE, tests::initialize_path_usd},
        tip403_registry::TIP403Registry,
    };
    use alloy::primitives::{Address, U256};
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::ITIP403Registry;

    #[test]
    fn test_start_reward_pre_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let admin = Address::random();
        let current_time = storage.timestamp().to::<u64>();
        let token_id = 1;

        StorageCtx::enter(&mut storage, || {
            initialize_path_usd(admin)?;

            let mut token = TIP20Token::new(token_id);
            token.initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)?;
            token.grant_role_internal(admin, *ISSUER_ROLE)?;

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

            let token_address = token.address;
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
        })
    }

    #[test]
    fn test_set_reward_recipient() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let admin = Address::random();
        let alice = Address::random();
        let token_id = 1;

        StorageCtx::enter(&mut storage, || {
            initialize_path_usd(admin)?;

            let mut token = TIP20Token::new(token_id);
            token.initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)?;
            token.grant_role_internal(admin, *ISSUER_ROLE)?;

            let amount = U256::random().min(U256::from(u128::MAX)) % token.supply_cap()?;
            token.mint(admin, ITIP20::mintCall { to: alice, amount })?;
            token
                .set_reward_recipient(alice, ITIP20::setRewardRecipientCall { recipient: alice })?;

            let info = token.user_reward_info.at(alice).read()?;
            assert_eq!(info.reward_recipient, alice);
            assert_eq!(token.get_opted_in_supply()?, amount.to::<u128>());
            assert_eq!(info.reward_per_token, U256::ZERO);

            token.set_reward_recipient(
                alice,
                ITIP20::setRewardRecipientCall {
                    recipient: Address::ZERO,
                },
            )?;

            let info = token.user_reward_info.at(alice).read()?;
            assert_eq!(info.reward_recipient, Address::ZERO);
            assert_eq!(token.get_opted_in_supply()?, 0u128);
            assert_eq!(info.reward_per_token, U256::ZERO);

            Ok(())
        })
    }

    #[test]
    fn test_cancel_reward_pre_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let admin = Address::random();
        let token_id = 1;

        StorageCtx::enter(&mut storage, || {
            initialize_path_usd(admin)?;

            let mut token = TIP20Token::new(token_id);
            token.initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)?;
            token.grant_role_internal(admin, *ISSUER_ROLE)?;

            let mint_amount = (U256::random().min(U256::from(u128::MAX)) % token.supply_cap()?)
                .min(U256::from(10));
            token.mint(
                admin,
                ITIP20::mintCall {
                    to: admin,
                    amount: mint_amount,
                },
            )?;

            let reward_amount = mint_amount / U256::from(10);
            let stream_id = token.start_reward(
                admin,
                ITIP20::startRewardCall {
                    amount: reward_amount,
                    secs: 10,
                },
            )?;

            let remaining =
                token.cancel_reward(admin, ITIP20::cancelRewardCall { id: stream_id })?;

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
            assert_eq!(opted_in_supply, 0u128);

            Ok(())
        })
    }

    #[test]
    fn test_update_rewards_pre_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let admin = Address::random();
        let alice = Address::random();
        let token_id = 1;

        StorageCtx::enter(&mut storage, || {
            initialize_path_usd(admin)?;

            let mut token = TIP20Token::new(token_id);
            token.initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)?;
            token.grant_role_internal(admin, *ISSUER_ROLE)?;

            let mint_amount = (U256::random().min(U256::from(u128::MAX)) % token.supply_cap()?)
                .min(U256::from(10));
            token.mint(
                admin,
                ITIP20::mintCall {
                    to: alice,
                    amount: mint_amount,
                },
            )?;

            token
                .set_reward_recipient(alice, ITIP20::setRewardRecipientCall { recipient: alice })?;

            let reward_amount = mint_amount / U256::from(10);
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
            let info_after = token.user_reward_info.at(alice).read()?;
            let global_rpt_after = token.get_global_reward_per_token()?;

            assert_eq!(info_after.reward_per_token, global_rpt_after);

            Ok(())
        })
    }

    #[test]
    fn test_accrue_pre_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let admin = Address::random();
        let alice = Address::random();
        let token_id = 1;

        StorageCtx::enter(&mut storage, || {
            initialize_path_usd(admin)?;

            let mut token = TIP20Token::new(token_id);
            token.initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)?;
            token.grant_role_internal(admin, *ISSUER_ROLE)?;

            let mint_amount = (U256::random().min(U256::from(u128::MAX)) % token.supply_cap()?)
                .min(U256::from(10));
            token.mint(
                admin,
                ITIP20::mintCall {
                    to: alice,
                    amount: mint_amount,
                },
            )?;

            token
                .set_reward_recipient(alice, ITIP20::setRewardRecipientCall { recipient: alice })?;

            let reward_amount = mint_amount / U256::from(10);
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

            assert_eq!(token.get_opted_in_supply()?, mint_amount.to::<u128>());
            let info = token.user_reward_info.at(alice).read()?;
            assert_eq!(info.reward_per_token, U256::ZERO);
            Ok(())
        })
    }

    #[test]
    fn test_finalize_streams_pre_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let current_time = storage.timestamp().to::<u64>();
        let admin = Address::random();
        let alice = Address::random();
        let token_id = 1;

        StorageCtx::enter(&mut storage, || {
            initialize_path_usd(admin)?;

            let mut token = TIP20Token::new(token_id);
            token.initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)?;
            token.grant_role_internal(admin, *ISSUER_ROLE)?;

            let mint_amount = (U256::random().min(U256::from(u128::MAX)) % token.supply_cap()?)
                .min(U256::from(10));
            token.mint(
                admin,
                ITIP20::mintCall {
                    to: alice,
                    amount: mint_amount,
                },
            )?;

            token
                .set_reward_recipient(alice, ITIP20::setRewardRecipientCall { recipient: alice })?;

            let reward_amount = mint_amount / U256::from(10);
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

            let end_time = current_time + stream_duration as u64;

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
            let info = token.user_reward_info.at(alice).read()?;
            assert_eq!(info.reward_per_token, global_rpt);

            Ok(())
        })
    }

    #[test]
    fn test_start_reward_duration_0() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let admin = Address::random();
        let alice = Address::random();
        let token_id = 1;

        StorageCtx::enter(&mut storage, || {
            initialize_path_usd(admin)?;

            let mut token = TIP20Token::new(token_id);
            token.initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)?;
            token.grant_role_internal(admin, *ISSUER_ROLE)?;

            let mint_amount = (U256::random().min(U256::from(u128::MAX)) % token.supply_cap()?)
                .min(U256::from(10));
            token.mint(
                admin,
                ITIP20::mintCall {
                    to: alice,
                    amount: mint_amount,
                },
            )?;

            token
                .set_reward_recipient(alice, ITIP20::setRewardRecipientCall { recipient: alice })?;

            // Mint reward tokens to admin
            let reward_amount = mint_amount / U256::from(10);
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
        })
    }

    #[test]
    fn test_reward_distribution_pro_rata_pre_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let admin = Address::random();
        let alice = Address::random();
        let token_id = 1;

        StorageCtx::enter(&mut storage, || {
            initialize_path_usd(admin)?;

            let mut token = TIP20Token::new(token_id);
            token.initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)?;
            token.grant_role_internal(admin, *ISSUER_ROLE)?;

            // Mint tokens to Alice and have her opt in as reward recipient
            let mint_amount = U256::from(1000e18);
            token.mint(
                admin,
                ITIP20::mintCall {
                    to: alice,
                    amount: mint_amount,
                },
            )?;

            token
                .set_reward_recipient(alice, ITIP20::setRewardRecipientCall { recipient: alice })?;

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
        })
    }

    #[test]
    fn test_claim_rewards_pre_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let admin = Address::random();
        let alice = Address::random();
        let funder = Address::random();

        StorageCtx::enter(&mut storage, || {
            initialize_path_usd(admin)?;
            let mut token = TIP20Token::new(1);
            token.initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)?;

            token.grant_role_internal(admin, *ISSUER_ROLE)?;

            let alice_balance = U256::from(1000e18);
            token.mint(
                admin,
                ITIP20::mintCall {
                    to: alice,
                    amount: alice_balance,
                },
            )?;

            token
                .set_reward_recipient(alice, ITIP20::setRewardRecipientCall { recipient: alice })?;
            assert_eq!(token.get_opted_in_supply()?, alice_balance.to::<u128>());

            let reward_amount = U256::from(100e18);
            token.mint(
                admin,
                ITIP20::mintCall {
                    to: funder,
                    amount: reward_amount,
                },
            )?;

            token.start_reward(
                funder,
                ITIP20::startRewardCall {
                    amount: reward_amount,
                    secs: 100,
                },
            )?;

            let current_time = token.storage.timestamp();
            token.storage.set_timestamp(current_time + U256::from(50));

            let alice_balance_before_claim = token.get_balance(alice)?;
            let claimed_amount = token.claim_rewards(alice)?;

            assert!(claimed_amount > U256::ZERO);
            assert_eq!(
                token.get_balance(alice)?,
                alice_balance_before_claim + claimed_amount
            );

            let alice_info = token.get_user_reward_info(alice)?;
            assert_eq!(alice_info.reward_balance, U256::ZERO);

            Ok(())
        })
    }

    #[test]
    fn test_cancel_reward_removes_from_registry_post_moderato() -> eyre::Result<()> {
        // Test with Moderato hardfork - when cancelling the last stream at an end_time,
        // the token should be removed from the registry
        // Note that we start with the hardfork at pre-moderato so that scheduled rewards are still
        // enabled
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            // Setup and start stream in a scope to release the borrow
            let mint_amount = U256::from(1000e18);
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(admin, mint_amount)
                .apply()?;

            let reward_amount = U256::from(100e18);
            let stream_id = token.start_reward(
                admin,
                ITIP20::startRewardCall {
                    amount: reward_amount,
                    secs: 10,
                },
            )?;
            let stream = token.get_stream(stream_id)?;
            let end_time = stream.end_time as u128;

            // Update to Moderato to assert post hardfork cancellation behavior
            StorageCtx.set_spec(TempoHardfork::Moderato);

            // Verify the token is in the registry before cancellation
            let registry = TIP20RewardsRegistry::new();
            let count_before = registry.ending_streams.at(end_time).len()?;
            assert_eq!(
                count_before, 1,
                "Registry should have 1 stream before cancellation"
            );

            // Cancel the stream
            token.cancel_reward(admin, ITIP20::cancelRewardCall { id: stream_id })?;

            // Verify the token is removed from the registry (post-Moderato behavior)
            let count_after = registry.ending_streams.at(end_time).len()?;
            assert_eq!(
                count_after, 0,
                "Post-Moderato: Registry should have 0 streams after cancelling the last stream"
            );

            Ok(())
        })
    }

    #[test]
    fn test_cancel_reward_does_not_remove_from_registry_pre_moderato() -> eyre::Result<()> {
        // Test with Adagio (pre-Moderato) - token should NOT be removed from registry
        // even when all streams are cancelled (for consensus compatibility)
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            // Setup and start stream in a scope to release the borrow
            let mint_amount = U256::from(1000e18);
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(admin, mint_amount)
                .apply()?;

            let reward_amount = U256::from(100e18);
            let stream_id = token.start_reward(
                admin,
                ITIP20::startRewardCall {
                    amount: reward_amount,
                    secs: 10,
                },
            )?;
            let stream = token.get_stream(stream_id)?;
            let end_time = stream.end_time as u128;

            // Verify the token is in the registry before cancellation
            let registry = TIP20RewardsRegistry::new();
            let count_before = registry.ending_streams.at(end_time).len()?;
            assert_eq!(
                count_before, 1,
                "Registry should have 1 stream before cancellation"
            );

            // Cancel the stream
            token.cancel_reward(admin, ITIP20::cancelRewardCall { id: stream_id })?;

            // Pre-Moderato: token should NOT be removed from registry
            let count_after = registry.ending_streams.at(end_time).len()?;
            assert_eq!(
                count_after, 1,
                "Pre-Moderato: Registry should still have 1 stream (not removed for consensus compatibility)"
            );

            Ok(())
        })
    }

    #[test]
    fn test_scheduled_rewards_disabled_post_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            // Setup and start stream in a scope to release the borrow
            let mint_amount = U256::from(1000e18);
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(admin, mint_amount)
                .apply()?;

            let reward_amount = U256::from(100e18);
            let result = token.start_reward(
                admin,
                ITIP20::startRewardCall {
                    amount: reward_amount,
                    secs: 10,
                },
            );

            assert!(result.is_err());
            let error = result.unwrap_err();
            assert!(matches!(
                error,
                TempoPrecompileError::TIP20(TIP20Error::ScheduledRewardsDisabled(_))
            ));

            Ok(())
        })
    }

    #[test]
    fn test_cancel_reward_ensure_tip403_is_not_blacklisted() -> eyre::Result<()> {
        const STREAM_DURATION: u32 = 10;

        // Start at adagio hardfork so reward streams are enabled
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let current_timestamp = storage.timestamp();
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            // create a blacklist policy before token setup
            let mut tip403_registry = TIP403Registry::new();
            let policy_id = tip403_registry.create_policy(
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::BLACKLIST,
                },
            )?;

            // setup token with the blacklist policy and start a reward stream
            let mut token = TIP20Setup::create("TestToken", "TEST", admin)
                .with_issuer(admin)
                .apply()?;

            token.change_transfer_policy_id(
                admin,
                ITIP20::changeTransferPolicyIdCall {
                    newPolicyId: policy_id,
                },
            )?;

            let mint_amount = U256::from(1000e18);
            TIP20Setup::config(token.address())
                .with_mint(admin, mint_amount)
                .apply()?;

            let reward_amount = U256::from(100e18);
            let stream_id = token.start_reward(
                admin,
                ITIP20::startRewardCall {
                    amount: reward_amount,
                    secs: STREAM_DURATION,
                },
            )?;

            // blacklist the token address
            tip403_registry.modify_policy_blacklist(
                admin,
                ITIP403Registry::modifyPolicyBlacklistCall {
                    policyId: policy_id,
                    account: token.address,
                    restricted: true,
                },
            )?;

            // attempt to cancel the rewards
            StorageCtx.set_timestamp(current_timestamp + U256::from(STREAM_DURATION - 1));
            let refund = token.cancel_reward(admin, ITIP20::cancelRewardCall { id: stream_id })?;
            assert!(matches!(refund, U256::ZERO), "non-zero refund: {refund}");

            Ok(())
        })
    }
}
