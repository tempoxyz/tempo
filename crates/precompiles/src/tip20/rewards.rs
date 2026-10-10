//! Claims for settled TIP-20 rewards. Distribution and delegation are disabled.

use crate::{
    error::{Result, TempoPrecompileError},
    storage::Handler,
    tip20::TIP20Token,
};
use alloy::primitives::{Address, U256};
use tempo_contracts::precompiles::{ITIP20, TIP20Event};
use tempo_precompiles_macros::Storable;

impl TIP20Token {
    /// Retained ABI entrypoint; reward distribution is disabled.
    pub fn distribute_reward(
        &mut self,
        _msg_sender: Address,
        _call: ITIP20::distributeRewardCall,
    ) -> Result<()> {
        Ok(())
    }

    /// Retained ABI entrypoint; reward delegation is disabled.
    pub fn set_reward_recipient(
        &mut self,
        _msg_sender: Address,
        _call: ITIP20::setRewardRecipientCall,
    ) -> Result<()> {
        Ok(())
    }

    /// Pays settled rewards up to the contract balance, retaining any unpaid remainder.
    pub fn claim_rewards(&mut self, msg_sender: Address) -> Result<U256> {
        self.check_not_paused()?;
        self.ensure_transfer_authorized(self.address, msg_sender)?;

        let mut info = self.user_reward_info[msg_sender].read()?;
        let amount = info.reward_balance;
        let contract_address = self.address;
        let contract_balance = self.get_balance(contract_address)?;
        let max_amount = amount.min(contract_balance);

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

            self.emit_event(TIP20Event::transfer(
                contract_address,
                msg_sender,
                max_amount,
            ))?;
        }

        Ok(max_amount)
    }

    /// Returns the frozen reward-per-token accumulator.
    pub fn get_global_reward_per_token(&self) -> Result<U256> {
        self.global_reward_per_token.read()
    }

    /// Returns the frozen opted-in supply.
    pub fn get_opted_in_supply(&self) -> Result<u128> {
        self.opted_in_supply.read()
    }

    /// Retrieves settled reward information.
    pub fn get_user_reward_info(&self, account: Address) -> Result<UserRewardInfo> {
        self.user_reward_info[account].read()
    }

    /// Returns settled claimable rewards without accruing new rewards.
    pub fn get_pending_rewards(&self, account: Address) -> Result<u128> {
        self.user_reward_info[account]
            .read()?
            .reward_balance
            .try_into()
            .map_err(|_| TempoPrecompileError::under_overflow())
    }
}

/// Per-user reward tracking state for the opt-in staking rewards system.
#[derive(Debug, Clone, Storable)]
pub struct UserRewardInfo {
    /// Address that receives this user's accrued rewards (`Address::ZERO` = opted out).
    pub reward_recipient: Address,
    /// Snapshot of the global reward-per-token at the user's last update.
    pub reward_per_token: U256,
    /// Accumulated but unclaimed reward balance.
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
        tip403_registry::TIP403Registry,
    };
    use tempo_contracts::precompiles::{ITIP403Registry, TIP20Error};

    #[test]
    fn disabled_rewards_preserve_settled_state() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let alice = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", alice).apply()?;
            token.user_reward_info[alice].write(UserRewardInfo {
                reward_recipient: alice,
                reward_per_token: U256::ZERO,
                reward_balance: U256::from(7),
            })?;
            token.paused.write(true)?;
            let reads = StorageCtx.counter_sload();
            let writes = StorageCtx.counter_sstore();
            token.set_reward_recipient(
                alice,
                ITIP20::setRewardRecipientCall {
                    recipient: Address::random(),
                },
            )?;
            token.distribute_reward(alice, ITIP20::distributeRewardCall { amount: U256::ZERO })?;
            assert_eq!(
                (StorageCtx.counter_sload(), StorageCtx.counter_sstore()),
                (reads, writes)
            );
            assert_eq!(token.get_pending_rewards(alice)?, 7);
            assert_eq!(token.get_user_reward_info(alice)?.reward_recipient, alice);
            Ok(())
        })
    }

    #[test]
    fn claims_pay_settled_rewards_up_to_available_balance() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let alice = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", alice).apply()?;
            token.set_balance(token.address, U256::from(3))?;
            token.global_reward_per_token.write(U256::MAX)?;
            token.user_reward_info[alice].write(UserRewardInfo {
                reward_recipient: alice,
                reward_per_token: U256::ZERO,
                reward_balance: U256::from(7),
            })?;
            assert_eq!(token.claim_rewards(alice)?, U256::from(3));
            assert_eq!(token.get_balance(alice)?, U256::from(3));
            assert_eq!(token.get_pending_rewards(alice)?, 4);
            assert_eq!(token.opted_in_supply.read()?, 0);
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

            token.change_transfer_policy_id(
                admin,
                ITIP20::changeTransferPolicyIdCall {
                    newPolicyId: policy_id,
                },
            )?;

            let err = token.claim_rewards(alice).unwrap_err();
            assert!(
                matches!(
                    err,
                    TempoPrecompileError::TIP20(TIP20Error::PolicyForbids(_))
                ),
                "Expected PolicyForbids error, got: {err:?}"
            );

            Ok(())
        })
    }
}
