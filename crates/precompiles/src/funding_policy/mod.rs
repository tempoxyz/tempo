//! Shared funding policy storage. Registration and delegated execution are activated separately.

use alloy::{
    primitives::{Address, Bytes},
    sol_types::SolValue,
};
use tempo_contracts::precompiles::{
    FundingPolicyError, FundingPolicyEvent, IAccountKeychain, IFundingPolicy,
};
use tempo_precompiles_macros::contract;

use crate::{
    account_keychain::AccountKeychain,
    error::{Result, TempoPrecompileError},
    has_duplicates_metered, input_cost,
    storage::{Handler, Mapping},
    tip20_funder::permission,
};

#[contract]
pub struct FundingPolicy {
    next_policy_id: u64,
    /// Canonical ABI data keeps the stored policy and emitted policy hash consistent.
    policies: Mapping<u64, Bytes>,
}

fn invalid_policy() -> TempoPrecompileError {
    FundingPolicyError::InvalidPolicy(IFundingPolicy::InvalidPolicy {}).into()
}

fn unauthorized() -> TempoPrecompileError {
    FundingPolicyError::Unauthorized(IFundingPolicy::Unauthorized {}).into()
}

impl FundingPolicy {
    pub fn new(address: Address) -> Self {
        Self::__new(address)
    }

    pub fn policy_id_counter(&self) -> Result<u64> {
        Ok(self.next_policy_id.read()?.max(1))
    }

    pub fn policy_exists(&self, id: u64) -> Result<bool> {
        Ok(id != 0 && id < self.policy_id_counter()?)
    }

    pub fn get_policy(&mut self, id: u64) -> Result<IFundingPolicy::Policy> {
        if !self.policy_exists(id)? {
            return Err(
                FundingPolicyError::PolicyNotFound(IFundingPolicy::PolicyNotFound {}).into(),
            );
        }
        let bytes = self.policies[id].read()?;
        self.storage
            .deduct_gas(input_cost(self.storage.spec(), bytes.len())?)?;
        IFundingPolicy::Policy::abi_decode_validate(&bytes).map_err(|_| invalid_policy())
    }

    fn validate_admins(&mut self, admins: &[Address]) -> Result<()> {
        if admins.is_empty()
            || admins.iter().any(|admin| admin.is_zero())
            || has_duplicates_metered(&mut self.storage, admins.iter().copied())?
        {
            return Err(invalid_policy());
        }
        Ok(())
    }

    fn validate_routes(&mut self, slippage: u16, routes: &[IFundingPolicy::Route]) -> Result<()> {
        if slippage > 10_000
            || routes.iter().any(|route| route.token.is_zero())
            || routes.windows(2).any(|pair| pair[0].token >= pair[1].token)
        {
            return Err(invalid_policy());
        }
        for route in routes {
            if route.sources.iter().any(|source| source.target.is_zero())
                || has_duplicates_metered(
                    &mut self.storage,
                    route.sources.iter().map(|source| source.target),
                )?
            {
                return Err(invalid_policy());
            }
        }
        Ok(())
    }

    fn require_owner_context(&self, sender: Address) -> Result<()> {
        if permission::is_active()
            || !AccountKeychain::new()
                .get_transaction_key(IAccountKeychain::getTransactionKeyCall {}, sender)?
                .is_zero()
        {
            return Err(unauthorized());
        }
        Ok(())
    }

    fn require_admin(&mut self, sender: Address, id: u64) -> Result<IFundingPolicy::Policy> {
        self.require_owner_context(sender)?;
        let policy = self.get_policy(id)?;
        if !policy.admins.contains(&sender) {
            return Err(unauthorized());
        }
        Ok(policy)
    }

    pub fn create_policy(
        &mut self,
        sender: Address,
        policy: IFundingPolicy::Policy,
    ) -> Result<u64> {
        self.require_owner_context(sender)?;
        self.validate_admins(&policy.admins)?;
        self.validate_routes(policy.slippageBps, &policy.routes)?;
        let id = self.policy_id_counter()?;
        let next = id.checked_add(1).ok_or_else(invalid_policy)?;
        self.policies[id].write(policy.abi_encode().into())?;
        self.next_policy_id.write(next)?;
        self.emit_event(FundingPolicyEvent::PolicyCreated(
            IFundingPolicy::PolicyCreated {
                policyId: id,
                updater: sender,
            },
        ))?;
        Ok(id)
    }

    pub fn modify_policy(
        &mut self,
        sender: Address,
        id: u64,
        slippage: u16,
        routes: Vec<IFundingPolicy::Route>,
    ) -> Result<()> {
        let mut policy = self.require_admin(sender, id)?;
        self.validate_routes(slippage, &routes)?;
        policy.slippageBps = slippage;
        policy.routes = routes;
        let bytes = policy.abi_encode();
        let policy_hash = self.storage.keccak256(&bytes)?;
        self.policies[id].write(bytes.into())?;
        self.emit_event(FundingPolicyEvent::PolicyUpdated(
            IFundingPolicy::PolicyUpdated {
                policyId: id,
                updater: sender,
                policyHash: policy_hash,
            },
        ))
    }

    pub fn set_admins(&mut self, sender: Address, id: u64, admins: Vec<Address>) -> Result<()> {
        let mut policy = self.require_admin(sender, id)?;
        self.validate_admins(&admins)?;
        policy.admins = admins;
        self.policies[id].write(policy.abi_encode().into())?;
        self.emit_event(FundingPolicyEvent::PolicyAdminsUpdated(
            IFundingPolicy::PolicyAdminsUpdated {
                policyId: id,
                updater: sender,
                admins: policy.admins,
            },
        ))
    }
}

mod dispatch;

#[cfg(test)]
mod tests;
