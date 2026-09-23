use alloy::primitives::Address;
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::IFundingPolicy;

use super::FundingPolicy;
use crate::{Precompile, charge_input_cost, dispatch, mutate, mutate_void, view};

impl Precompile for FundingPolicy {
    fn call(&mut self, calldata: &[u8], sender: Address) -> PrecompileResult {
        if let Some(error) = charge_input_cost(&mut self.storage, calldata) {
            return error;
        }
        dispatch!(calldata, |call| match call {
            IFundingPolicy::IFundingPolicyCalls {
                policyIdCounter(call) => view(call, |_| self.policy_id_counter()),
                policyExists(call) => view(call, |c| self.policy_exists(c.policyId)),
                getPolicy(call) => view(call, |c| self.get_policy(c.policyId)),
                createPolicy(call) => mutate(call, sender, |s, c| self.create_policy(s, c.admins, c.rules)),
                setRules(call) => mutate_void(call, sender, |s, c| {
                    self.set_rules(s, c.policyId, c.rules)
                }),
                setAdmins(call) => mutate_void(call, sender, |s, c| {
                    self.set_admins(s, c.policyId, c.admins)
                })
            }
        })
    }
}
