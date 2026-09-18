//! Claims of settled TIP-20 rewards. New reward accrual and opt-in are disabled.

use crate::{
    error::{Result, TempoPrecompileError},
    storage::Handler,
    tip20::TIP20Token,
};
use alloy::primitives::{Address, U256, uint};
use tempo_contracts::precompiles::{ITIP20, TIP20Event};
use tempo_precompiles_macros::Storable;

/// Precision of the accumulator retained in existing on-chain storage.
pub const ACC_PRECISION: U256 = uint!(1000000000000000000_U256);

impl TIP20Token {
    /// Retained ABI selector; new reward distributions are disabled.
    pub fn distribute_reward(
        &mut self,
        _sender: Address,
        _call: ITIP20::distributeRewardCall,
    ) -> Result<()> {
        Ok(())
    }

    /// Rewards no longer accrue and no account is opted into new accrual.
    pub fn update_rewards(&mut self, _holder: Address) -> Result<Address> {
        Ok(Address::ZERO)
    }

    /// Retained ABI selector; changes to reward recipients are disabled.
    pub fn set_reward_recipient(
        &mut self,
        _sender: Address,
        _call: ITIP20::setRewardRecipientCall,
    ) -> Result<()> {
        Ok(())
    }

    /// Pays settled rewards, capped by the contract balance, preserving any unpaid remainder.
    /// The token must be unpaused and its transfer policy must authorize the claim.
    pub fn claim_rewards(&mut self, sender: Address) -> Result<U256> {
        self.check_not_paused()?;
        self.ensure_transfer_authorized(self.address, sender)?;
        let mut info = self.user_reward_info[sender].read()?;
        let contract = self.address;
        let balance = self.get_balance(contract)?;
        let amount = info.reward_balance.min(balance);
        info.reward_balance = info
            .reward_balance
            .checked_sub(amount)
            .ok_or(TempoPrecompileError::under_overflow())?;
        self.user_reward_info[sender].write(info)?;
        if amount > U256::ZERO {
            self.set_balance(
                contract,
                balance
                    .checked_sub(amount)
                    .ok_or(TempoPrecompileError::under_overflow())?,
            )?;
            let recipient_balance = self
                .get_balance(sender)?
                .checked_add(amount)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_balance(sender, recipient_balance)?;
            self.emit_event(TIP20Event::transfer(contract, sender, amount))?;
        }
        Ok(amount)
    }

    /// Reads the frozen accumulator without accruing new rewards.
    pub fn get_global_reward_per_token(&self) -> Result<U256> {
        self.global_reward_per_token.read()
    }

    /// Reads the legacy opted-in supply retained in storage.
    pub fn get_opted_in_supply(&self) -> Result<u128> {
        self.opted_in_supply.read()
    }

    /// Writes the stored opted-in supply, used by state initialization.
    pub fn set_opted_in_supply(&mut self, value: u128) -> Result<()> {
        self.opted_in_supply.write(value)
    }

    /// Transfers do not accrue rewards or mutate opted-in supply.
    pub fn handle_rewards_on_transfer(
        &mut self,
        _from: Address,
        _to: Address,
        _amount: U256,
    ) -> Result<()> {
        Ok(())
    }

    /// Minting does not accrue rewards or mutate opted-in supply.
    pub fn handle_rewards_on_mint(&mut self, _to: Address, _amount: U256) -> Result<()> {
        Ok(())
    }

    /// Reads reward records without modifying their persisted layout.
    pub fn get_user_reward_info(&self, account: Address) -> Result<UserRewardInfo> {
        self.user_reward_info[account].read()
    }

    /// Only previously settled rewards are claimable; lazy accrual is forfeited.
    pub fn get_pending_rewards(&self, account: Address) -> Result<u128> {
        self.user_reward_info[account]
            .read()?
            .reward_balance
            .try_into()
            .map_err(|_| TempoPrecompileError::under_overflow())
    }
}

/// Persisted reward record. Its layout must remain compatible with mainnet checkpoints.
#[derive(Debug, Clone, Storable)]
pub struct UserRewardInfo {
    /// Historical recipient, no longer used for accrual.
    pub reward_recipient: Address,
    /// Historical accumulator snapshot.
    pub reward_per_token: U256,
    /// Settled, unclaimed rewards.
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
    use tempo_chainspec::hardfork::TempoHardfork;

    #[test]
    fn settled_rewards_survive_without_legacy_execution() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::CURRENT);
        StorageCtx::enter(&mut storage, || {
            let admin = Address::random();
            let alice = Address::random();
            let bob = Address::random();
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .apply()?;
            // Model a checkpoint directly; never execute removed reward-accrual rules.
            token.set_balance(token.address, U256::from(60))?;
            token
                .global_reward_per_token
                .write(ACC_PRECISION * U256::from(1000))?;
            token.set_opted_in_supply(123)?;
            token.user_reward_info[alice].write(UserRewardInfo {
                reward_recipient: bob,
                reward_per_token: U256::ZERO,
                reward_balance: U256::from(100),
            })?;
            token.paused.write(true)?;
            token.distribute_reward(admin, ITIP20::distributeRewardCall { amount: U256::ZERO })?;
            token
                .set_reward_recipient(alice, ITIP20::setRewardRecipientCall { recipient: alice })?;
            assert_eq!(token.get_user_reward_info(alice)?.reward_recipient, bob);
            assert_eq!(token.get_pending_rewards(alice)?, 100);
            assert!(token.claim_rewards(alice).is_err());
            token.paused.write(false)?;
            assert_eq!(token.claim_rewards(alice)?, U256::from(60));
            assert_eq!(token.get_balance(alice)?, U256::from(60));
            assert_eq!(token.get_pending_rewards(alice)?, 40);
            assert_eq!(token.get_opted_in_supply()?, 123);
            assert_eq!(token.claim_rewards(alice)?, U256::ZERO);
            Ok(())
        })
    }

    #[test]
    fn reward_hooks_cannot_be_reactivated_by_metadata() -> eyre::Result<()> {
        for &metadata in TempoHardfork::VARIANTS {
            let mut storage = HashMapStorageProvider::new_with_spec(1, metadata);
            StorageCtx::enter(&mut storage, || {
                let admin = Address::random();
                let mut token = TIP20Setup::create("Test", "TST", admin)
                    .with_issuer(admin)
                    .apply()?;
                token.set_opted_in_supply(123)?;
                token.handle_rewards_on_transfer(admin, Address::random(), U256::MAX)?;
                token.handle_rewards_on_mint(admin, U256::MAX)?;
                assert_eq!(token.update_rewards(admin)?, Address::ZERO);
                assert_eq!(token.get_opted_in_supply()?, 123);
                Ok::<_, eyre::Report>(())
            })?;
        }
        Ok(())
    }
}
