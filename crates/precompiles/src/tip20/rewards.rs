//! TIP20 Rewards distribution and claiming implementation.

use crate::{
    error::{Result, TempoPrecompileError},
    storage::Handler,
    tip20::{ACC_PRECISION, TIP20Error, TIP20Event, TIP20Token, abi},
};
use alloy::primitives::{Address, U256};

// Re-export types for backwards compatibility
pub use super::{IRewards, abi::UserRewardInfo};

use abi::IRewards as _;

impl abi::IRewards for TIP20Token {
    /// Allows an authorized user to distribute reward tokens to opted-in recipients.
    fn distribute_reward(&mut self, msg_sender: Address, amount: U256) -> Result<()> {
        self.check_not_paused()?;
        let token_address = self.address;

        if amount == U256::ZERO {
            return Err(TIP20Error::invalid_amount().into());
        }

        self.ensure_transfer_authorized(msg_sender, token_address)?;
        self.check_and_update_spending_limit(msg_sender, amount)?;

        self._transfer(msg_sender, token_address, amount)?;

        let opted_in_supply = U256::from(self.opted_in_supply()?);
        if opted_in_supply.is_zero() {
            return Err(TIP20Error::no_opted_in_supply().into());
        }

        let delta_rpt = amount
            .checked_mul(ACC_PRECISION)
            .and_then(|v| v.checked_div(opted_in_supply))
            .ok_or(TempoPrecompileError::under_overflow())?;
        let current_rpt = self.global_reward_per_token()?;
        let new_rpt = current_rpt
            .checked_add(delta_rpt)
            .ok_or(TempoPrecompileError::under_overflow())?;
        self.set_global_reward_per_token(new_rpt)?;

        // Emit distributed reward event for immediate payout
        self.emit_event(abi::Event::reward_distributed(msg_sender, amount))?;

        Ok(())
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

        let from_delegate = self.update_rewards(msg_sender)?;

        let holder_balance = self.get_balance(msg_sender)?;

        if from_delegate != Address::ZERO {
            if recipient == Address::ZERO {
                let opted_in_supply = U256::from(self.opted_in_supply()?)
                    .checked_sub(holder_balance)
                    .ok_or(TempoPrecompileError::under_overflow())?;
                self.set_opted_in_supply(
                    opted_in_supply
                        .try_into()
                        .map_err(|_| TempoPrecompileError::under_overflow())?,
                )?;
            }
        } else if recipient != Address::ZERO {
            let opted_in_supply = U256::from(self.opted_in_supply()?)
                .checked_add(holder_balance)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_opted_in_supply(
                opted_in_supply
                    .try_into()
                    .map_err(|_| TempoPrecompileError::under_overflow())?,
            )?;
        }

        let mut info = self.user_reward_info[msg_sender].read()?;
        info.reward_recipient = recipient;
        self.user_reward_info[msg_sender].write(info)?;

        // Emit reward recipient set event
        self.emit_event(abi::Event::reward_recipient_set(msg_sender, recipient))?;

        Ok(())
    }

    /// Claims accumulated rewards for a recipient.
    ///
    /// This function allows a reward recipient to claim their accumulated rewards
    /// and receive them as token transfers to their own balance.
    fn claim_rewards(&mut self, msg_sender: Address) -> Result<U256> {
        self.check_not_paused()?;
        self.ensure_transfer_authorized(self.address, msg_sender)?;

        self.update_rewards(msg_sender)?;

        let mut info = self.user_reward_info[msg_sender].read()?;
        let amount = info.reward_balance;
        let contract_address = self.address;
        let contract_balance = self.get_balance(contract_address)?;
        let max_amount = amount.min(contract_balance);

        let reward_recipient = info.reward_recipient;
        info.reward_balance = amount
            .checked_sub(max_amount)
            .ok_or(TempoPrecompileError::under_overflow())?;
        self.user_reward_info[msg_sender].write(info)?;

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
                let opted_in_supply = U256::from(self.opted_in_supply()?)
                    .checked_add(max_amount)
                    .ok_or(TempoPrecompileError::under_overflow())?;
                self.set_opted_in_supply(
                    opted_in_supply
                        .try_into()
                        .map_err(|_| TempoPrecompileError::under_overflow())?,
                )?;
            }

            self.emit_event(TIP20Event::transfer(
                contract_address,
                msg_sender,
                max_amount,
            ))?;
        }

        Ok(max_amount)
    }

    /// Gets the accumulated global reward per token.
    fn global_reward_per_token(&self) -> Result<U256> {
        self.global_reward_per_token.read()
    }

    /// Gets the total supply of tokens opted into rewards from storage.
    fn opted_in_supply(&self) -> Result<u128> {
        self.opted_in_supply.read()
    }

    /// Retrieves user reward information for a given account.
    fn user_reward_info(&self, account: Address) -> Result<UserRewardInfo> {
        self.user_reward_info[account].read()
    }

    /// Calculates the pending claimable rewards for an account without modifying state.
    ///
    /// This function returns the total pending claimable reward amount, which includes:
    /// 1. The stored reward balance from previous updates
    /// 2. Newly accrued rewards based on the current global reward per token
    ///
    /// For accounts that have delegated their rewards to another recipient, this returns 0
    /// since their rewards accrue to their delegate instead.
    fn get_pending_rewards(&self, account: Address) -> Result<u128> {
        let info = self.user_reward_info[account].read()?;

        // Start with the stored reward balance
        let mut pending = info.reward_balance;

        // For the account's own accrued rewards (if self-delegated):
        if info.reward_recipient == account {
            let holder_balance = self.get_balance(account)?;
            if holder_balance > U256::ZERO {
                let global_reward_per_token = self.global_reward_per_token()?;
                let reward_per_token_delta = global_reward_per_token
                    .checked_sub(info.reward_per_token)
                    .ok_or(TempoPrecompileError::under_overflow())?;

                if reward_per_token_delta > U256::ZERO {
                    let accrued = holder_balance
                        .checked_mul(reward_per_token_delta)
                        .and_then(|v| v.checked_div(ACC_PRECISION))
                        .ok_or(TempoPrecompileError::under_overflow())?;
                    pending = pending
                        .checked_add(accrued)
                        .ok_or(TempoPrecompileError::under_overflow())?;
                }
            }
        }

        pending
            .try_into()
            .map_err(|_| TempoPrecompileError::under_overflow())
    }
}

impl TIP20Token {
    /// Updates and accumulates accrued rewards for a specific token holder.
    ///
    /// This function calculates the rewards earned by a holder based on their
    /// balance and the reward per token difference since their last update.
    /// Rewards are accumulated in the delegated recipient's rewardBalance.
    /// Returns the holder's delegated recipient address.
    pub fn update_rewards(&mut self, holder: Address) -> Result<Address> {
        let mut info = self.user_reward_info[holder].read()?;

        let cached_delegate = info.reward_recipient;

        let global_reward_per_token = self.global_reward_per_token()?;
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
                    let mut delegate_info = self.user_reward_info[cached_delegate].read()?;
                    delegate_info.reward_balance = delegate_info
                        .reward_balance
                        .checked_add(reward)
                        .ok_or(TempoPrecompileError::under_overflow())?;
                    self.user_reward_info[cached_delegate].write(delegate_info)?;
                }
            }
            info.reward_per_token = global_reward_per_token;
            self.user_reward_info[holder].write(info)?;
        }

        Ok(cached_delegate)
    }

    /// Handles reward accounting when tokens are minted to an address.
    pub fn handle_rewards_on_mint(&mut self, to: Address, amount: U256) -> Result<()> {
        let to_delegate = self.update_rewards(to)?;

        if !to_delegate.is_zero() {
            let opted_in_supply = U256::from(self.opted_in_supply()?)
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
                let opted_in_supply = U256::from(self.opted_in_supply()?)
                    .checked_sub(amount)
                    .ok_or(TempoPrecompileError::under_overflow())?;
                self.set_opted_in_supply(
                    opted_in_supply
                        .try_into()
                        .map_err(|_| TempoPrecompileError::under_overflow())?,
                )?;
            }
        } else if !to_delegate.is_zero() {
            let opted_in_supply = U256::from(self.opted_in_supply()?)
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

    /// Sets the accumulated global reward per token in storage.
    fn set_global_reward_per_token(&mut self, value: U256) -> Result<()> {
        self.global_reward_per_token.write(value)
    }

    /// Sets the total supply of tokens opted into rewards in storage.
    pub fn set_opted_in_supply(&mut self, value: u128) -> Result<()> {
        self.opted_in_supply.write(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::TempoPrecompileError,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::TIP20Setup,
        tip20::{PolicyForbids, abi},
        tip403_registry::{ITIP403Registry, TIP403Registry},
    };
    use abi::IToken as _;
    use alloy::primitives::{Address, U256};

    #[test]
    fn test_set_reward_recipient() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let alice = Address::random();
        let amount = U256::random() % U256::from(u128::MAX);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(alice, amount)
                .apply()?;

            token.set_reward_recipient(alice, alice)?;

            let info = token.user_reward_info[alice].read()?;
            assert_eq!(info.reward_recipient, alice);
            assert_eq!(token.opted_in_supply()?, amount.to::<u128>());
            assert_eq!(info.reward_per_token, U256::ZERO);

            token.set_reward_recipient(alice, Address::ZERO)?;

            let info = token.user_reward_info[alice].read()?;
            assert_eq!(info.reward_recipient, Address::ZERO);
            assert_eq!(token.opted_in_supply()?, 0u128);
            assert_eq!(info.reward_per_token, U256::ZERO);

            Ok(())
        })
    }

    #[test]
    fn test_distribute_reward() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let alice = Address::random();
        let amount = U256::from(1000);
        let reward_amount = amount / U256::from(10);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(alice, amount)
                .with_mint(admin, reward_amount)
                .apply()?;

            token.set_reward_recipient(alice, alice)?;

            // Distribute rewards
            token.distribute_reward(admin, reward_amount)?;

            // Verify global_reward_per_token increased correctly
            let expected_rpt = reward_amount * ACC_PRECISION / amount;
            assert_eq!(token.global_reward_per_token()?, expected_rpt);

            // Verify contract balance increased (rewards transferred from admin to contract)
            assert_eq!(token.get_balance(token.address)?, reward_amount);
            assert_eq!(token.get_balance(admin)?, U256::ZERO);

            // Update rewards to accrue alice's share
            token.update_rewards(alice)?;
            let info = token.user_reward_info(alice)?;
            assert_eq!(info.reward_balance, reward_amount);

            // Alice claims the full reward
            let claimed = token.claim_rewards(alice)?;
            assert_eq!(claimed, reward_amount);
            assert_eq!(token.get_balance(alice)?, amount + reward_amount);
            assert_eq!(token.get_balance(token.address)?, U256::ZERO);

            // Distributing zero amount should fail
            token.mint(admin, admin, U256::from(1))?;
            let result = token.distribute_reward(admin, U256::ZERO);
            assert!(result.is_err());

            Ok(())
        })
    }

    #[test]
    fn test_get_pending_rewards() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let alice = Address::random();

        StorageCtx::enter(&mut storage, || {
            let alice_balance = U256::from(1000e18);
            let reward_amount = U256::from(100e18);

            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(alice, alice_balance)
                .with_mint(admin, reward_amount)
                .apply()?;

            token.set_reward_recipient(alice, alice)?;

            // Before any rewards, pending should be 0
            let pending_before = token.get_pending_rewards(alice)?;
            assert_eq!(pending_before, 0u128);

            // Distribute immediate reward
            token.distribute_reward(admin, reward_amount)?;

            // Now alice should have pending rewards equal to reward_amount (she's the only opted-in holder)
            let pending_after = token.get_pending_rewards(alice)?;
            assert_eq!(U256::from(pending_after), reward_amount);

            // Verify that calling get_pending_rewards did not modify state
            let user_info = token.user_reward_info(alice)?;
            assert_eq!(
                user_info.reward_balance,
                U256::ZERO,
                "get_pending_rewards should not modify state"
            );

            Ok(())
        })
    }

    #[test]
    fn test_get_pending_rewards_includes_stored_balance() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let alice = Address::random();

        StorageCtx::enter(&mut storage, || {
            let alice_balance = U256::from(1000e18);
            let reward_amount = U256::from(50e18);

            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(alice, alice_balance)
                .with_mint(admin, reward_amount * U256::from(2))
                .apply()?;

            token.set_reward_recipient(alice, alice)?;

            // Distribute first reward
            token.distribute_reward(admin, reward_amount)?;

            // Trigger an action to update alice's stored reward balance
            token.update_rewards(alice)?;
            let user_info = token.user_reward_info(alice)?;
            assert_eq!(user_info.reward_balance, reward_amount);

            // Distribute second reward
            token.distribute_reward(admin, reward_amount)?;

            // get_pending_rewards should return stored + new accrued
            let pending = token.get_pending_rewards(alice)?;
            assert_eq!(U256::from(pending), reward_amount * U256::from(2));

            Ok(())
        })
    }

    #[test]
    fn test_get_pending_rewards_with_delegation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let alice = Address::random();
        let bob = Address::random();

        StorageCtx::enter(&mut storage, || {
            let alice_balance = U256::from(1000e18);
            let reward_amount = U256::from(100e18);

            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(alice, alice_balance)
                .with_mint(admin, reward_amount)
                .apply()?;

            // Alice delegates to bob
            token.set_reward_recipient(alice, bob)?;

            // Distribute immediate reward
            token.distribute_reward(admin, reward_amount)?;

            // Alice's pending should be 0 (she delegated to bob)
            let alice_pending = token.get_pending_rewards(alice)?;
            assert_eq!(alice_pending, 0u128);

            // Bob's pending should be 0 until update_rewards is called for alice
            // (We can't iterate all delegators on-chain, so pending calculation is limited
            // to stored balance + self-delegated accrued rewards)
            let bob_pending_before_update = token.get_pending_rewards(bob)?;
            assert_eq!(bob_pending_before_update, 0u128);

            // After calling update_rewards on alice, bob's stored balance is updated
            token.update_rewards(alice)?;
            let bob_pending_after_update = token.get_pending_rewards(bob)?;
            assert_eq!(U256::from(bob_pending_after_update), reward_amount);

            Ok(())
        })
    }

    #[test]
    fn test_get_pending_rewards_not_opted_in() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let alice = Address::random();
        let bob = Address::random();

        StorageCtx::enter(&mut storage, || {
            let balance = U256::from(1000e18);
            let reward_amount = U256::from(100e18);

            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(alice, balance)
                .with_mint(bob, balance)
                .with_mint(admin, reward_amount)
                .apply()?;

            // Only alice opts in
            token.set_reward_recipient(alice, alice)?;

            // Distribute reward
            token.distribute_reward(admin, reward_amount)?;

            // Alice should have pending rewards
            let alice_pending = token.get_pending_rewards(alice)?;
            assert_eq!(U256::from(alice_pending), reward_amount);

            // Bob should have 0 pending rewards (not opted in)
            let bob_pending = token.get_pending_rewards(bob)?;
            assert_eq!(bob_pending, 0u128);

            Ok(())
        })
    }

    #[test]
    fn test_claim_rewards_unauthorized() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let alice = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();
            registry.initialize()?;

            let policy_id = registry.create_policy(
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::BLACKLIST,
                },
            )?;

            registry.modify_policy_blacklist(
                admin,
                ITIP403Registry::modifyPolicyBlacklistCall {
                    policyId: policy_id,
                    account: alice,
                    restricted: true,
                },
            )?;

            let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;

            token.change_transfer_policy_id(admin, policy_id)?;

            let err = token.claim_rewards(alice).unwrap_err();
            assert!(
                matches!(
                    err,
                    TempoPrecompileError::TIP20(TIP20Error::PolicyForbids(PolicyForbids))
                ),
                "Expected PolicyForbids error, got: {err:?}"
            );

            Ok(())
        })
    }
}
