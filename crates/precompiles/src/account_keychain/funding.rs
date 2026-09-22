use super::*;
use crate::funding_policy::FundingPolicy;
use tempo_contracts::precompiles::{FUNDING_POLICY_ADDRESS, IFundingPolicy};
use tempo_primitives::transaction::FundingPolicyAuthorization;

impl AccountKeychain {
    pub fn get_funding_policy_id(&self, account: Address, key: Address) -> Result<u64> {
        self.funding_policy_ids[account][key].read()
    }

    /// Binds a policy after native key installation, inside the same checkpoint.
    pub fn install_funding_policy(
        &mut self,
        account: Address,
        key: Address,
        policy: &FundingPolicyAuthorization,
    ) -> Result<()> {
        let mut registry = FundingPolicy::new(FUNDING_POLICY_ADDRESS);
        let id = match policy {
            FundingPolicyAuthorization::Id(id) => {
                if !registry.policy_exists(id.get())? {
                    return Err(
                        tempo_contracts::precompiles::FundingPolicyError::PolicyNotFound(
                            IFundingPolicy::PolicyNotFound {},
                        )
                        .into(),
                    );
                }
                id.get()
            }
            FundingPolicyAuthorization::Inline(policy) => {
                registry.install_policy(account, policy.clone().into())?
            }
        };
        self.funding_policy_ids[account][key].write(id)
    }
}
