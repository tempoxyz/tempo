use crate::{
    TIP20_REWARDS_REGISTRY_ADDRESS,
    error::{Result, TempoPrecompileError},
    storage::PrecompileStorageProvider,
    tip20_rewards_registry::TIP20RewardsRegistry,
    utils::MathUtils,
};
use alloy::primitives::{Address, I256, U256, uint};
use tempo_contracts::precompiles::{
    ITIP20, ITIP20Rewards, TIP20Error, TIP20Event, TIP20RewardsError,
};
use tempo_precompiles_macros::Storable;

use super::{TIP20Token, TIP20Token_ITIP20Rewards};

pub const ACC_PRECISION: U256 = uint!(1000000000000000000_U256);

/// Reward stream data structure occupying 4 consecutive storage slots.
/// Fields are stored in declaration order, with solidity-like slot-packing.
#[derive(Debug, Clone, PartialEq, Eq, Storable)]
pub struct RewardStream {
    pub funder: Address,
    pub start_time: u64,
    pub end_time: u64,
    pub rate_per_second_scaled: U256,
    pub amount_total: U256,
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

impl From<RewardStream> for ITIP20Rewards::RewardStream {
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

impl<'a, S: PrecompileStorageProvider> TIP20Token_ITIP20Rewards for TIP20Token<'a, S> {
    /// Starts a new reward stream for the token contract.
    ///
    /// This function allows an authorized user to fund a reward stream that distributes
    /// tokens to opted-in recipients either immediately if seconds=0, or over the specified
    /// duration.
    fn start_reward(&mut self, msg_sender: Address, amount: U256, seconds: u128) -> Result<u64> {
        self.check_not_paused()?;
        let token_address = self.address;
        self.ensure_transfer_authorized(msg_sender, token_address)?;

        if amount == U256::ZERO {
            return Err(TIP20Error::invalid_amount().into());
        }

        self._transfer(msg_sender, token_address, amount)?;

        if seconds == 0 {
            let opted_in_supply = self.sload_opted_in_supply()?;
            if opted_in_supply.is_zero() {
                return Err(TIP20RewardsError::no_opted_in_supply().into());
            }

            let delta_rpt = amount.mul_div(ACC_PRECISION, opted_in_supply)?;
            let current_rpt = self.sload_reward_per_token_stored()?;
            let new_rpt = current_rpt.add_checked(delta_rpt)?;
            self.sstore_reward_per_token_stored(new_rpt)?;

            // Emit reward scheduled event for immediate payout
            self.emit_reward_scheduled(msg_sender, 0, amount, 0)?;

            return Ok(0);
        }

        let rate = amount.mul_div(ACC_PRECISION, U256::from(seconds))?;
        let stream_id = self.get_next_stream_id()?;
        let next_stream_id = stream_id
            .checked_add(1)
            .ok_or(TempoPrecompileError::under_overflow())?;
        self.sstore_next_stream_id(next_stream_id)?;

        let current_total = self.sload_total_reward_per_second()?;
        let new_total = current_total.add_checked(rate)?;
        self.sstore_total_reward_per_second(new_total)?;

        let current_time = self.storage.timestamp().to::<u128>();
        let end_time = current_time
            .checked_add(seconds)
            .ok_or(TempoPrecompileError::under_overflow())?;

        self.sstore_streams(
            stream_id,
            RewardStream::new(
                msg_sender,
                current_time as u64,
                end_time as u64,
                rate,
                amount,
            ),
        )?;

        let current_decrease = self.sload_scheduled_rate_decrease(end_time)?;
        let new_decrease = current_decrease.add_checked(rate)?;
        self.sstore_scheduled_rate_decrease(end_time, new_decrease)?;

        // Add stream to registry
        let mut registry = TIP20RewardsRegistry::new(self.storage);
        registry.add_stream(self.address, end_time)?;

        // Emit reward scheduled event for streaming reward
        self.emit_reward_scheduled(msg_sender, stream_id, amount, seconds as u32)?;

        Ok(stream_id)
    }

    /// Sets or changes the reward recipient for a token holder.
    ///
    /// This function allows a token holder to designate who should receive their
    /// share of rewards. Setting to zero address opts out of rewards.
    fn set_reward_recipient(&mut self, msg_sender: Address, recipient: Address) -> Result<()> {
        self.check_not_paused()?;
        if recipient != Address::ZERO {
            self.ensure_transfer_authorized(msg_sender, recipient)?;
        }

        let timestamp = self.storage.timestamp();
        self.accrue(timestamp)?;

        let current_recipient = self.sload_reward_recipient_of(msg_sender)?;
        if recipient == current_recipient {
            return Ok(());
        }

        let holder_balance = self.sload_balances(msg_sender)?;
        if current_recipient != Address::ZERO {
            self.update_rewards(current_recipient)?;
            let delegated_balance = self
                .sload_delegated_balance(current_recipient)?
                .sub_checked(holder_balance)?;
            self.sstore_delegated_balance(current_recipient, delegated_balance)?;
        }

        self.sstore_reward_recipient_of(msg_sender, recipient)?;
        if recipient == Address::ZERO {
            let opted_in_supply = self
                .sload_opted_in_supply()?
                .sub_checked(holder_balance)?;
            self.sstore_opted_in_supply(opted_in_supply)?;
        } else {
            let delegated = self.sload_delegated_balance(recipient)?;
            if delegated > U256::ZERO {
                self.update_rewards(recipient)?;
            }

            let new_delegated = delegated.add_checked(holder_balance)?;
            self.sstore_delegated_balance(recipient, new_delegated)?;

            if current_recipient.is_zero() {
                let opted_in = self
                    .sload_opted_in_supply()?
                    .add_checked(holder_balance)?;
                self.sstore_opted_in_supply(opted_in)?;
            }

            let rpt = self.sload_reward_per_token_stored()?;
            self.sstore_user_reward_per_token_paid(recipient, rpt)?;
        }

        // Emit reward recipient set event
        self.emit_reward_recipient_set(msg_sender, recipient)
    }

    /// Cancels an active reward stream and refunds remaining tokens.
    ///
    /// This function allows the funder of a reward stream to cancel it early,
    /// stopping future reward distribution and refunding unused tokens.
    fn cancel_reward(&mut self, msg_sender: Address, stream_id: u64) -> Result<U256> {
        let stream = self.sload_streams(stream_id)?;

        if stream.funder.is_zero() {
            return Err(TIP20RewardsError::stream_inactive().into());
        }

        if stream.funder != msg_sender {
            return Err(TIP20RewardsError::not_stream_funder().into());
        }

        let current_time = self.storage.timestamp();
        if current_time >= stream.end_time {
            return Err(TIP20RewardsError::stream_inactive().into());
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
            .mul_div(elapsed, ACC_PRECISION)?;
        distributed = distributed.min(stream.amount_total);
        let remaining = stream.amount_total.sub_checked(distributed)?;

        let total_rps = self
            .sload_total_reward_per_second()?
            .sub_checked(stream.rate_per_second_scaled)?;
        self.sstore_total_reward_per_second(total_rps)?;

        // Update the rate decrease and remove the stream
        let end_time = stream.end_time as u128;
        let rate_decrease = self
            .sload_scheduled_rate_decrease(end_time)?
            .sub_checked(stream.rate_per_second_scaled)?;
        self.sstore_scheduled_rate_decrease(end_time, rate_decrease)?;

        self.clear_streams(stream_id)?;

        // Attempt to transfer remaining funds to funder
        let mut refund = U256::ZERO;
        if remaining > U256::ZERO {
            // Check if transfer is authorized
            if self.is_transfer_authorized(stream.funder, stream.funder)? {
                let contract_address = self.address;
                let contract_balance = self
                    .sload_balances(contract_address)?
                    .sub_checked(remaining)?;
                self.sstore_balances(contract_address, contract_balance)?;

                let funder_balance = self
                    .sload_balances(stream.funder)?
                    .add_checked(remaining)?;
                self.sstore_balances(stream.funder, funder_balance)?;

                self.emit_transfer(self.address, stream.funder, remaining)?;
                refund = remaining;
            }
        }

        // Emit reward canceled event
        self.emit_reward_canceled(stream.funder, stream_id, refund)?;

        Ok(refund)
    }
}

impl<'a, S: PrecompileStorageProvider> TIP20Token<'a, S> {
    /// Handles reward accounting when tokens are transferred from an address.
    ///
    /// This function updates the reward state for the sender's reward recipient,
    /// reducing their delegated balance and returns the resulting opted in supply delta if changed
    fn handle_sender_rewards(&mut self, from: Address, amount: U256) -> Result<Option<U256>> {
        let from_recipient = self.sload_reward_recipient_of(from)?;
        if from_recipient != Address::ZERO {
            self.update_rewards(from_recipient)?;

            let delegated = self
                .sload_delegated_balance(from_recipient)?
                .sub_checked(amount)?;
            self.sstore_delegated_balance(from_recipient, delegated)?;

            Ok(Some(amount))
        } else {
            Ok(None)
        }
    }

    /// Handles reward accounting when tokens are transferred to an address.
    ///
    /// This function updates the reward state for the receiver's reward recipient,
    /// increasing their delegated balance and returns the resulting opted in supply delta if changed
    fn handle_receiver_rewards(&mut self, to: Address, amount: U256) -> Result<Option<U256>> {
        let to_recipient = self.sload_reward_recipient_of(to)?;
        if to_recipient != Address::ZERO {
            self.update_rewards(to_recipient)?;

            let delegated = self
                .sload_delegated_balance(to_recipient)?
                .add_checked(amount)?;
            self.sstore_delegated_balance(to_recipient, delegated)?;

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
    pub fn accrue(&mut self, accrue_to_timestamp: U256) -> Result<()> {
        let elapsed = accrue_to_timestamp - U256::from(self.sload_last_update_time()?);
        if elapsed.is_zero() {
            return Ok(());
        }

        self.sstore_last_update_time(accrue_to_timestamp.to())?;

        let opted_in_supply = self.sload_opted_in_supply()?;
        if opted_in_supply == U256::ZERO {
            return Ok(());
        }

        let total_reward_per_second = self.sload_total_reward_per_second()?;
        if total_reward_per_second > U256::ZERO {
            let delta_rpt = total_reward_per_second.mul_div(elapsed, opted_in_supply)?;
            let current_rpt = self.sload_reward_per_token_stored()?;
            let new_rpt = current_rpt.add_checked(delta_rpt)?;
            self.sstore_reward_per_token_stored(new_rpt)?;
        }

        Ok(())
    }

    /// Updates and distributes accrued rewards for a specific recipient.
    ///
    /// This function calculates the rewards earned by a recipient based on their
    /// delegated balance and the reward per token difference since their last update.
    /// It then transfers the accrued rewards from the contract to the recipient.
    fn update_rewards(&mut self, recipient: Address) -> Result<()> {
        if recipient == Address::ZERO {
            return Ok(());
        }

        let delegated = self.sload_delegated_balance(recipient)?;
        let reward_per_token_stored = self.sload_reward_per_token_stored()?;
        let user_reward_per_token_paid = self.sload_user_reward_per_token_paid(recipient)?;

        let diff = reward_per_token_stored.sub_checked(user_reward_per_token_paid)?;
        let mut accrued = delegated.mul_div(diff, ACC_PRECISION)?;

        self.sstore_user_reward_per_token_paid(recipient, reward_per_token_stored)?;

        if accrued == U256::ZERO {
            return Ok(());
        }

        let token_address = self.address;
        let contract_balance = self.sload_balances(token_address)?;

        if accrued > contract_balance {
            accrued = contract_balance;
        }

        let new_contract_balance = contract_balance.sub_checked(accrued)?;
        self.sstore_balances(token_address, new_contract_balance)?;

        let recipient_balance = self.sload_balances(recipient)?.add_checked(accrued)?;
        self.sstore_balances(recipient, recipient_balance)?;

        // Since rewards are being claimed, we need to increase the delegated balance
        // and opted-in supply to reflect that these tokens are now part of the reward pool.
        let delegated_balance = self
            .sload_delegated_balance(recipient)?
            .add_checked(accrued)?;
        self.sstore_delegated_balance(recipient, delegated_balance)?;

        let opted_in_supply = self.sload_opted_in_supply()?.add_checked(accrued)?;
        self.sstore_opted_in_supply(opted_in_supply)?;

        self.emit_transfer(token_address, recipient, accrued)
    }

    /// Finalizes expired reward streams by updating the total reward rate.
    ///
    /// This function is called to clean up streams that have reached their end time,
    /// reducing the total reward per second rate by the amount of the expired streams.
    pub fn finalize_streams(&mut self, msg_sender: Address, end_time: u128) -> Result<()> {
        if msg_sender != TIP20_REWARDS_REGISTRY_ADDRESS {
            return Err(TIP20Error::unauthorized().into());
        }

        let rate_decrease = self.sload_scheduled_rate_decrease(end_time)?;
        if rate_decrease == U256::ZERO {
            return Ok(());
        }

        self.accrue(U256::from(end_time))?;

        let total_rps = self.sload_total_reward_per_second()?.sub_checked(rate_decrease)?;
        self.sstore_total_reward_per_second(total_rps)?;

        self.sstore_scheduled_rate_decrease(end_time, U256::ZERO)?;

        Ok(())
    }

    /// Gets the next available stream ID (minimum 1).
    fn get_next_stream_id(&mut self) -> Result<u64> {
        let id = self.sload_next_stream_id()?;

        // TODO(rusowsky): cmnt not aligned with impl min <> max
        Ok(id.max(1))
    }

    /// Handles reward accounting for both sender and receiver during token transfers.
    ///
    /// This function manages the opted-in supply adjustments when tokens are transferred
    /// between addresses with different reward recipient settings. It returns the net
    /// change to the opted-in supply.
    pub fn handle_rewards_on_transfer(
        &mut self,
        from: Address,
        to: Address,
        amount: U256,
    ) -> Result<()> {
        let mut opted_in_delta = I256::ZERO;

        if let Some(delta) = self.handle_sender_rewards(from, amount)? {
            opted_in_delta = I256::from(delta);
        }

        if let Some(delta) = self.handle_receiver_rewards(to, amount)? {
            opted_in_delta -= I256::from(delta);
        }

        if opted_in_delta > I256::ZERO {
            let opted_in_supply = self
                .sload_opted_in_supply()?
                .sub_checked(U256::from(opted_in_delta))?;
            self.sstore_opted_in_supply(opted_in_supply)?;
        } else if opted_in_delta < I256::ZERO {
            let opted_in_supply = self
                .sload_opted_in_supply()?
                .add_checked(U256::from(-opted_in_delta))?;
            self.sstore_opted_in_supply(opted_in_supply)?;
        }

        Ok(())
    }

    /// Handles reward accounting when tokens are minted to an address.
    ///
    /// This function manages the opted-in supply adjustments when tokens are minted
    /// to an address with a reward recipient setting. It only handles receiver rewards
    /// since tokens are minted from the zero address.
    pub fn handle_rewards_on_mint(&mut self, to: Address, amount: U256) -> Result<()> {
        if let Some(delta) = self.handle_receiver_rewards(to, amount)? {
            let opted_in_supply = self.sload_opted_in_supply()?.add_checked(delta)?;
            self.sstore_opted_in_supply(opted_in_supply)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        LINKING_USD_ADDRESS,
        storage::hashmap::HashMapStorageProvider,
        tip20_migrated::{ISSUER_ROLE, TIP20Token, TIP20Token_ITIP20, TIP20Token_ITIP20Rewards},
    };
    use alloy::primitives::{Address, U256, uint};

    #[test]
    fn test_start_reward() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let current_time = storage.timestamp().to::<u64>();
        let admin = Address::random();

        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, admin)?;

        token.grant_role_internal(admin, *ISSUER_ROLE)?;

        let mint_amount = U256::from(1000e18);
        token.mint(admin, admin, mint_amount)?;

        let reward_amount = U256::from(100e18);
        let stream_id = token.start_reward(admin, reward_amount, 10)?;
        assert_eq!(stream_id, 1);

        let token_address = token.address;
        let balance = token.sload_balances(token_address)?;
        assert_eq!(balance, reward_amount);

        let stream = token.sload_streams(stream_id)?;
        assert_eq!(stream.funder, admin);
        assert_eq!(stream.start_time, current_time);
        assert_eq!(stream.end_time, current_time + 10);

        let total_reward_per_second = token.sload_total_reward_per_second()?;
        let expected_rate = (reward_amount * ACC_PRECISION) / U256::from(10);
        assert_eq!(total_reward_per_second, expected_rate);

        let reward_per_token_stored = token.sload_reward_per_token_stored()?;
        assert_eq!(reward_per_token_stored, U256::ZERO);

        Ok(())
    }

    #[test]
    fn test_set_reward_recipient() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let alice = Address::random();

        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, admin)?;

        token.grant_role_internal(admin, *ISSUER_ROLE)?;

        let amount = U256::from(1000e18);
        token.mint(admin, alice, amount)?;

        token.set_reward_recipient(alice, alice)?;

        assert_eq!(token.sload_reward_recipient_of(alice)?, alice);
        assert_eq!(token.sload_delegated_balance(alice)?, amount);
        assert_eq!(token.sload_opted_in_supply()?, amount);
        assert_eq!(token.sload_user_reward_per_token_paid(alice)?, U256::ZERO);

        token.set_reward_recipient(alice, Address::ZERO)?;

        assert_eq!(token.sload_reward_recipient_of(alice)?, Address::ZERO);
        assert_eq!(token.sload_delegated_balance(alice)?, U256::ZERO);
        assert_eq!(token.sload_opted_in_supply()?, U256::ZERO);
        assert_eq!(token.sload_user_reward_per_token_paid(alice)?, U256::ZERO);

        Ok(())
    }

    #[test]
    fn test_cancel_reward() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, admin)?;

        token.grant_role_internal(admin, *ISSUER_ROLE)?;

        let mint_amount = U256::from(1000e18);
        token.mint(admin, admin, mint_amount)?;

        let reward_amount = U256::from(100e18);
        let stream_id = token.start_reward(admin, reward_amount, 10)?;

        let remaining = token.cancel_reward(admin, stream_id)?;

        let total_after = token.sload_total_reward_per_second()?;
        assert_eq!(total_after, U256::ZERO);
        assert_eq!(remaining, reward_amount);

        let stream = token.sload_streams(stream_id)?;
        assert!(stream.funder.is_zero());
        assert_eq!(stream.start_time, 0);
        assert_eq!(stream.end_time, 0);
        assert_eq!(stream.rate_per_second_scaled, U256::ZERO);

        let reward_per_token_stored = token.sload_reward_per_token_stored()?;
        assert_eq!(reward_per_token_stored, U256::ZERO);

        let opted_in_supply = token.sload_opted_in_supply()?;
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

        token.grant_role_internal(admin, *ISSUER_ROLE)?;

        let mint_amount = U256::from(1000e18);
        token.mint(admin, alice, mint_amount)?;

        token.set_reward_recipient(alice, alice)?;

        let reward_amount = U256::from(100e18);
        token.mint(admin, admin, reward_amount)?;

        // Distribute the reward immediately
        token.start_reward(admin, reward_amount, 0)?;

        let alice_balance_before = token.sload_balances(alice)?;
        let reward_per_token_before = token.sload_reward_per_token_stored()?;
        let _user_reward_per_token_paid_before = token.sload_user_reward_per_token_paid(alice)?;

        token.update_rewards(alice)?;

        let alice_balance_after = token.sload_balances(alice)?;
        let reward_per_token_after = token.sload_reward_per_token_stored()?;
        let user_reward_per_token_paid_after = token.sload_user_reward_per_token_paid(alice)?;

        assert!(alice_balance_after > alice_balance_before);
        assert!(reward_per_token_after >= reward_per_token_before);
        assert_eq!(user_reward_per_token_paid_after, reward_per_token_after);
        assert_eq!(token.sload_opted_in_supply()?, mint_amount + reward_amount);
        assert_eq!(
            token.sload_delegated_balance(alice)?,
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
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, admin)?;

        token.grant_role_internal(admin, *ISSUER_ROLE)?;

        let mint_amount = U256::from(1000e18);
        token.mint(admin, alice, mint_amount)?;

        token.set_reward_recipient(alice, alice)?;

        let reward_amount = U256::from(100e18);
        token.mint(admin, admin, reward_amount)?;

        token.start_reward(admin, reward_amount, 100)?;

        let rpt_before = token.sload_reward_per_token_stored()?;
        let last_update_before = token.sload_last_update_time()?;

        let timestamp = token.storage.timestamp();
        token.accrue(timestamp)?;

        let rpt_after = token.sload_reward_per_token_stored()?;
        let last_update_after = token.sload_last_update_time()?;

        assert!(rpt_after >= rpt_before);
        assert!(last_update_after >= last_update_before);

        // Check total reward per second remains consistent
        let total_reward_per_second = token.sload_total_reward_per_second()?;
        let expected_rate = (reward_amount * ACC_PRECISION) / U256::from(100);
        assert_eq!(total_reward_per_second, expected_rate);

        assert_eq!(token.sload_opted_in_supply()?, mint_amount);
        assert_eq!(token.sload_delegated_balance(alice)?, mint_amount);
        assert_eq!(token.sload_user_reward_per_token_paid(alice)?, U256::ZERO);
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

        token.grant_role_internal(admin, *ISSUER_ROLE)?;

        let mint_amount = U256::from(1000e18);
        token.mint(admin, alice, mint_amount)?;

        token.set_reward_recipient(alice, alice)?;

        let reward_amount = U256::from(100e18);
        token.mint(admin, admin, reward_amount)?;

        let stream_duration = 10u128;
        token.start_reward(admin, reward_amount, stream_duration)?;

        let end_time = current_time + stream_duration;

        // Advance the timestamp to simulate time passing
        token.storage.set_timestamp(U256::from(end_time));

        let total_before = token.sload_total_reward_per_second()?;
        token.finalize_streams(
            TIP20_REWARDS_REGISTRY_ADDRESS,
            token.storage.timestamp().to::<u128>(),
        )?;
        let total_after = token.sload_total_reward_per_second()?;

        assert!(total_after < total_before);

        // Check reward per token stored has been updated
        let reward_per_token_stored = token.sload_reward_per_token_stored()?;
        assert!(reward_per_token_stored > U256::ZERO);

        token.update_rewards(alice)?;
        assert_eq!(token.sload_opted_in_supply()?, mint_amount + reward_amount);
        assert_eq!(
            token.sload_delegated_balance(alice)?,
            mint_amount + reward_amount
        );
        assert_eq!(
            token.sload_user_reward_per_token_paid(alice)?,
            reward_per_token_stored
        );

        Ok(())
    }

    #[test]
    fn test_start_reward_duration_0() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let alice = Address::random();

        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, admin)?;

        token.grant_role_internal(admin, *ISSUER_ROLE)?;

        // Mint tokens to Alice and have her opt in as reward recipient
        let mint_amount = U256::from(1000e18);
        token.mint(admin, alice, mint_amount)?;

        token.set_reward_recipient(alice, alice)?;

        // Mint reward tokens to admin
        let reward_amount = U256::from(100e18);
        token.mint(admin, admin, reward_amount)?;

        let alice_balance_before = token.sload_balances(alice)?;

        // Start immediate reward
        let id = token.start_reward(admin, reward_amount, 0)?;

        assert_eq!(id, 0);

        let bob = Address::random();
        token.transfer(alice, bob, U256::from(1))?;

        let alice_balance_after = token.sload_balances(alice)?;

        assert_eq!(
            alice_balance_after,
            alice_balance_before + reward_amount - U256::from(1)
        );

        let total_reward_per_second = token.sload_total_reward_per_second()?;
        assert_eq!(total_reward_per_second, U256::ZERO);

        let opted_in_supply = token.sload_opted_in_supply()?;
        assert_eq!(opted_in_supply, mint_amount + reward_amount - U256::ONE);

        Ok(())
    }

    #[test]
    fn test_reward_distribution_pro_rata() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let alice = Address::random();

        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, admin)?;

        token.grant_role_internal(admin, *ISSUER_ROLE)?;

        // Mint tokens to Alice and have her opt in as reward recipient
        let mint_amount = U256::from(1000e18);
        token.mint(admin, alice, mint_amount)?;

        token.set_reward_recipient(alice, alice)?;

        // Mint reward tokens to admin
        let reward_amount = U256::from(100e18);
        token.mint(admin, admin, reward_amount)?;

        let alice_balance_before = token.sload_balances(alice)?;

        // Start streaming reward for 20 seconds
        let stream_id = token.start_reward(admin, reward_amount, 20)?;

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
        token.transfer(alice, Address::random(), U256::ONE)?;

        // Assert balances after first half elapsed
        let alice_balance_mid = token.sload_balances(alice)?;
        let expected_balance = alice_balance_before + (reward_amount / uint!(2_U256)) - U256::ONE;
        assert_eq!(alice_balance_mid, expected_balance);

        token
            .storage
            .set_timestamp(current_timestamp + uint!(20_U256));

        token.finalize_streams(
            TIP20_REWARDS_REGISTRY_ADDRESS,
            token.storage.timestamp().to::<u128>(),
        )?;
        token.transfer(alice, Address::random(), U256::ONE)?;

        // Assert balances
        let alice_balance_after = token.sload_balances(alice)?;

        // NOTE: checking balance increased, loss precision due to rounding
        assert!(alice_balance_after > alice_balance_before);

        // Confirm that stream is finished
        let total_reward_per_second = token.sload_total_reward_per_second()?;
        assert_eq!(total_reward_per_second, U256::ZERO);

        Ok(())
    }
}
