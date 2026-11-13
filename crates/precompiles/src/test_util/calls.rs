//! Lowers test setups to the precompile calls that perform them, so they can run against a node.

use super::{Action, TIP20Setup, TIP403Setup};
use crate::{
    PATH_USD_ADDRESS, TIP20_FACTORY_ADDRESS, TIP403_REGISTRY_ADDRESS,
    tip20::{self, ITIP20},
    tip20_factory::{self, compute_tip20_address},
    tip403_registry::ITIP403Registry,
};
use alloy::{
    primitives::{Address, B256},
    sol_types::SolCall,
};
use tempo_contracts::precompiles::IRolesAuth;
use tempo_primitives::transaction::Call;

/// One call of a test setup lowered by [`TIP20Setup::calls`] or [`TIP403Setup::call`].
#[derive(Debug)]
pub struct SetupCall {
    /// Account that sends it.
    pub caller: Address,
    /// The call to a precompile.
    pub call: Call,
}

impl SetupCall {
    fn new(target: Address, caller: Address, call: &impl SolCall) -> Self {
        Self {
            caller,
            call: Call::new(target, call.abi_encode()),
        }
    }
}

impl TIP20Setup {
    /// Lowers the configuration to the token's address and the calls that perform it through the
    /// precompiles' ABI, in the order [`Self::apply`] performs it, so it can run against a node.
    ///
    /// Unlike [`Self::apply`], assumes pathUSD and the factory exist, as they do from genesis, and
    /// needs the admin set. A new token without a salt gets a random one. `next_policy_id` is the ID
    /// the TIP-403 registry assigns next, used only for the transfer policy.
    pub fn calls(&self, next_policy_id: u64) -> (Address, Vec<SetupCall>) {
        let admin = self.admin.expect("lowering to calls requires the admin");
        let mut calls = Vec::new();
        let token = match &self.action {
            Action::PathUSD => PATH_USD_ADDRESS,
            Action::ConfigureToken { address } => *address,
            Action::CreateToken {
                name,
                symbol,
                currency,
            } => {
                let salt = self.salt.unwrap_or_else(B256::random);
                let create = tip20_factory::createTokenCall {
                    name: name.to_string(),
                    symbol: symbol.to_string(),
                    currency: currency.clone(),
                    quoteToken: self.quote_token.unwrap_or(PATH_USD_ADDRESS),
                    admin,
                    salt,
                };
                calls.push(SetupCall::new(TIP20_FACTORY_ADDRESS, admin, &create));
                compute_tip20_address(admin, salt).0
            }
        };
        let grant = |account, role| {
            SetupCall::new(token, admin, &IRolesAuth::grantRoleCall { role, account })
        };

        calls.extend(
            self.roles
                .iter()
                .map(|&(account, role)| grant(account, role)),
        );
        if !self.mints.is_empty() {
            calls.push(grant(admin, tip20::ISSUER_ROLE));
        }
        calls.extend(
            self.mints.iter().map(|&(to, amount)| {
                SetupCall::new(token, admin, &ITIP20::mintCall { to, amount })
            }),
        );
        calls.extend(self.approvals.iter().map(|&(owner, spender, amount)| {
            SetupCall::new(token, owner, &ITIP20::approveCall { spender, amount })
        }));
        if let Some(policy) = &self.transfer_policy {
            calls.push(policy.call(admin));
            calls.push(SetupCall::new(
                token,
                admin,
                &ITIP20::changeTransferPolicyIdCall {
                    newPolicyId: next_policy_id,
                },
            ));
        }
        (token, calls)
    }
}

impl TIP403Setup {
    /// Lowers the policy to the call that creates it, sent by the admin, or for a compound policy
    /// by `creator`. [`Self::apply`] creates compound policies from the zero address, which no
    /// node can sign for; the registry doesn't record the creator, so the result is the same.
    pub fn call(&self, creator: Address) -> SetupCall {
        match self {
            Self::Simple {
                admin,
                policy_type,
                members,
            } => {
                let create = ITIP403Registry::createPolicyWithAccountsCall {
                    admin: *admin,
                    policyType: *policy_type,
                    accounts: members.clone(),
                };
                SetupCall::new(TIP403_REGISTRY_ADDRESS, *admin, &create)
            }
            Self::Compound(call) => SetupCall::new(TIP403_REGISTRY_ADDRESS, creator, call),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Precompile, Result,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        tip20::TIP20Token,
        tip20_factory::TIP20Factory,
        tip403_registry::{ALLOW_ALL_POLICY_ID, REJECT_ALL_POLICY_ID, TIP403Registry},
    };
    use alloy::primitives::{TxKind, U256};
    use std::collections::HashSet;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_primitives::{
        TempoAddressExt,
        test_utils::{actors, amounts},
    };

    /// Applying a setup in memory and executing its lowered calls leave the same storage, so
    /// `apply_rpc` sets up what unit tests set up.
    #[test]
    fn calls_match_apply() {
        let [admin, alice, bob, spender] = actors();
        let [minted, approved] = amounts();
        let salt = B256::random();
        let setups = || {
            let tokens = [
                TIP20Setup::path_usd(admin)
                    .with_mint(alice, minted)
                    .with_approval(alice, spender, approved),
                TIP20Setup::create("Test", "TST", admin)
                    .with_salt(salt)
                    .currency("EUR")
                    .with_issuer(bob)
                    .with_mint(bob, minted)
                    .with_approval(bob, spender, approved)
                    .with_transfer_policy(TIP403Setup::whitelist(admin).with_members([alice, bob])),
            ];
            let compound = TIP403Setup::compound(
                ALLOW_ALL_POLICY_ID,
                REJECT_ALL_POLICY_ID,
                ALLOW_ALL_POLICY_ID,
            );
            (tokens, compound)
        };
        let storage_after = |lowered: bool| {
            // The latest fork, as on a dev node: compound policies dispatch only from T2.
            let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::latest());
            storage.set_timestamp(U256::from(1));
            StorageCtx::enter(&mut storage, || -> Result<()> {
                // Genesis: pathUSD and the factory, which `calls` expects.
                TIP20Setup::path_usd(admin).apply()?;
                let (tokens, compound) = setups();
                if !lowered {
                    for token in tokens {
                        token.apply()?;
                    }
                    return compound.apply().map(drop);
                }
                for token in tokens {
                    let next_policy_id = TIP403Registry::new().policy_id_counter()?;
                    token
                        .calls(next_policy_id)
                        .1
                        .into_iter()
                        .try_for_each(execute)?;
                }
                execute(compound.call(admin))
            })
            .unwrap();
            storage
                .into_storage()
                .filter(|(_, _, value)| !value.is_zero())
                .collect::<HashSet<_>>()
        };

        assert_eq!(storage_after(false), storage_after(true));
    }

    /// Executes `call` through the target precompile's ABI dispatch.
    fn execute(SetupCall { caller, call }: SetupCall) -> Result<()> {
        let (TxKind::Call(target), calldata) = (call.to, call.input) else {
            panic!("setup calls never create");
        };
        let result = if target.is_tip20() {
            TIP20Token::from_address(target)?.call(&calldata, caller)
        } else if target == TIP20_FACTORY_ADDRESS {
            TIP20Factory::new().call(&calldata, caller)
        } else {
            assert_eq!(target, TIP403_REGISTRY_ADDRESS);
            TIP403Registry::new().call(&calldata, caller)
        };
        result.unwrap_or_else(|err| panic!("call to {target} from {caller} failed: {err:?}"));
        Ok(())
    }
}
