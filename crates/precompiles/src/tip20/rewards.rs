use crate::{
    error::{Result, TempoPrecompileError},
    storage::Handler,
    tip20::TIP20Token,
};
use alloy::primitives::{Address, U256, uint};
use tempo_contracts::precompiles::{ITIP20, TIP20Error, TIP20Event};
use tempo_precompiles_macros::Storable;

pub const ACC_PRECISION: U256 = uint!(1000000000000000000_U256);

impl TIP20Token {
    /// Allows an authorized user to distribute reward tokens to opted-in recipients.
    pub fn distribute_reward(
        &mut self,
        msg_sender: Address,
        call: ITIP20::distributeRewardCall,
    ) -> Result<()> {
        self.check_not_paused()?;
        let token_address = self.address;

        if call.amount == U256::ZERO {
            return Err(TIP20Error::invalid_amount().into());
        }

        self.ensure_transfer_authorized(msg_sender, token_address)?;
        self.check_spending_limit(msg_sender, call.amount)?;

        self._transfer(msg_sender, token_address, call.amount)?;

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

        // Emit distributed reward event for immediate payout
        self.emit_event(TIP20Event::RewardDistributed(ITIP20::RewardDistributed {
            funder: msg_sender,
            amount: call.amount,
        }))?;

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

    /// Claims accumulated rewards for a recipient.
    ///
    /// This function allows a reward recipient to claim their accumulated rewards
    /// and receive them as token transfers to their own balance.
    pub fn claim_rewards(&mut self, msg_sender: Address) -> Result<U256> {
        self.check_not_paused()?;
        self.ensure_transfer_authorized(msg_sender, msg_sender)?;

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

    /// Gets the accumulated global reward per token.
    pub fn get_global_reward_per_token(&self) -> Result<U256> {
        self.global_reward_per_token.read()
    }

    /// Sets the accumulated global reward per token in storage.
    fn set_global_reward_per_token(&mut self, value: U256) -> Result<()> {
        self.global_reward_per_token.write(value)
    }

    /// Gets the total supply of tokens opted into rewards from storage.
    pub fn get_opted_in_supply(&self) -> Result<u128> {
        self.opted_in_supply.read()
    }

    /// Sets the total supply of tokens opted into rewards in storage.
    pub fn set_opted_in_supply(&mut self, value: u128) -> Result<()> {
        self.opted_in_supply.write(value)
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
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::TIP20Setup,
    };
    use alloy::primitives::{Address, U256};
    use tempo_chainspec::hardfork::TempoHardfork;

    #[test]
    fn test_set_reward_recipient() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let admin = Address::random();
        let alice = Address::random();
        let amount = U256::random() % U256::from(u128::MAX);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(alice, amount)
                .apply()?;

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
    fn test_distribute_reward() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
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

            token
                .set_reward_recipient(alice, ITIP20::setRewardRecipientCall { recipient: alice })?;

            // Distribute rewards
            token.distribute_reward(
                admin,
                ITIP20::distributeRewardCall {
                    amount: reward_amount,
                },
            )?;

            // Verify global_reward_per_token increased correctly
            let expected_rpt = reward_amount * ACC_PRECISION / amount;
            assert_eq!(token.get_global_reward_per_token()?, expected_rpt);

            // Verify contract balance increased (rewards transferred from admin to contract)
            assert_eq!(token.get_balance(token.address)?, reward_amount);
            assert_eq!(token.get_balance(admin)?, U256::ZERO);

            // Update rewards to accrue alice's share
            token.update_rewards(alice)?;
            let info = token.get_user_reward_info(alice)?;
            assert_eq!(info.reward_balance, reward_amount);

            // Alice claims the full reward
            let claimed = token.claim_rewards(alice)?;
            assert_eq!(claimed, reward_amount);
            assert_eq!(token.get_balance(alice)?, amount + reward_amount);
            assert_eq!(token.get_balance(token.address)?, U256::ZERO);

            // Distributing zero amount should fail
            token.mint(
                admin,
                ITIP20::mintCall {
                    to: admin,
                    amount: U256::from(1),
                },
            )?;
            let result =
                token.distribute_reward(admin, ITIP20::distributeRewardCall { amount: U256::ZERO });
            assert!(result.is_err());

            Ok(())
        })
    }
}
