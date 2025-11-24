use crate::{
    Precompile, input_cost, metadata, mutate, mutate_void,
    path_usd::PathUSD,
    storage::{ContractStorage, PrecompileStorageProvider},
    tip20::{IRolesAuth, ITIP20},
    view,
};

use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};
use tempo_contracts::precompiles::{IPathUSD, TIP20Error};

impl<S: PrecompileStorageProvider> Precompile for PathUSD<'_, S> {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        let selector: [u8; 4] = if let Some(bytes) = calldata.get(..4) {
            bytes.try_into().unwrap()
        } else {
            self.token
                .storage()
                .deduct_gas(input_cost(calldata.len()))
                .map_err(|_| PrecompileError::OutOfGas)?;

            return Err(PrecompileError::Other(
                "Invalid input: missing function selector".into(),
            ));
        };

        // Post allegretto hardfork, treat pathUSD as a default TIP20 without extra permissions
        // For calls to name() or symbol(), since this contract is already deployed pre hardfork,
        // we override name/symbol to PathUSD rather than treating these calls with default TIP20 logic
        if self.token.storage().spec().is_allegretto()
            && selector != ITIP20::nameCall::SELECTOR
            && selector != ITIP20::symbolCall::SELECTOR
        {
            return self.token.call(calldata, msg_sender);
        }

        self.token
            .storage()
            .deduct_gas(input_cost(calldata.len()))
            .map_err(|_| PrecompileError::OutOfGas)?;

        let result = match selector {
            // Metadata
            ITIP20::nameCall::SELECTOR => metadata::<ITIP20::nameCall>(|| self.name()),
            ITIP20::symbolCall::SELECTOR => metadata::<ITIP20::symbolCall>(|| self.symbol()),
            ITIP20::decimalsCall::SELECTOR => metadata::<ITIP20::decimalsCall>(|| self.decimals()),
            ITIP20::totalSupplyCall::SELECTOR => {
                metadata::<ITIP20::totalSupplyCall>(|| self.total_supply())
            }
            ITIP20::currencyCall::SELECTOR => metadata::<ITIP20::currencyCall>(|| self.currency()),
            ITIP20::quoteTokenCall::SELECTOR => {
                view::<ITIP20::quoteTokenCall>(calldata, |_| self.token.quote_token())
            }
            ITIP20::pausedCall::SELECTOR => metadata::<ITIP20::pausedCall>(|| self.paused()),
            ITIP20::supplyCapCall::SELECTOR => {
                metadata::<ITIP20::supplyCapCall>(|| self.token.supply_cap())
            }
            ITIP20::transferPolicyIdCall::SELECTOR => {
                metadata::<ITIP20::transferPolicyIdCall>(|| self.token.transfer_policy_id())
            }

            // View functions
            ITIP20::balanceOfCall::SELECTOR => {
                view::<ITIP20::balanceOfCall>(calldata, |call| self.balance_of(call))
            }
            ITIP20::allowanceCall::SELECTOR => {
                view::<ITIP20::allowanceCall>(calldata, |call| self.allowance(call))
            }
            ITIP20::PAUSE_ROLECall::SELECTOR => {
                view::<ITIP20::PAUSE_ROLECall>(calldata, |_| Ok(Self::pause_role()))
            }
            ITIP20::UNPAUSE_ROLECall::SELECTOR => {
                view::<ITIP20::UNPAUSE_ROLECall>(calldata, |_| Ok(Self::unpause_role()))
            }
            ITIP20::ISSUER_ROLECall::SELECTOR => {
                view::<ITIP20::ISSUER_ROLECall>(calldata, |_| Ok(Self::issuer_role()))
            }
            ITIP20::BURN_BLOCKED_ROLECall::SELECTOR => {
                view::<ITIP20::BURN_BLOCKED_ROLECall>(calldata, |_| Ok(Self::burn_blocked_role()))
            }
            IPathUSD::TRANSFER_ROLECall::SELECTOR => {
                view::<IPathUSD::TRANSFER_ROLECall>(calldata, |_| Ok(Self::transfer_role()))
            }
            IPathUSD::RECEIVE_WITH_MEMO_ROLECall::SELECTOR => {
                view::<IPathUSD::RECEIVE_WITH_MEMO_ROLECall>(calldata, |_| {
                    Ok(Self::receive_with_memo_role())
                })
            }

            // Mutating functions that work normally
            ITIP20::approveCall::SELECTOR => {
                mutate::<ITIP20::approveCall>(calldata, msg_sender, |sender, call| {
                    self.approve(sender, call)
                })
            }
            ITIP20::mintCall::SELECTOR => {
                mutate_void::<ITIP20::mintCall>(calldata, msg_sender, |sender, call| {
                    self.mint(sender, call)
                })
            }
            ITIP20::mintWithMemoCall::SELECTOR => {
                mutate_void::<ITIP20::mintWithMemoCall>(calldata, msg_sender, |sender, call| {
                    self.token.mint_with_memo(sender, call)
                })
            }
            ITIP20::burnCall::SELECTOR => {
                mutate_void::<ITIP20::burnCall>(calldata, msg_sender, |sender, call| {
                    self.burn(sender, call)
                })
            }
            ITIP20::burnWithMemoCall::SELECTOR => {
                mutate_void::<ITIP20::burnWithMemoCall>(calldata, msg_sender, |sender, call| {
                    self.token.burn_with_memo(sender, call)
                })
            }
            ITIP20::burnBlockedCall::SELECTOR => {
                mutate_void::<ITIP20::burnBlockedCall>(calldata, msg_sender, |sender, call| {
                    self.token.burn_blocked(sender, call)
                })
            }
            ITIP20::pauseCall::SELECTOR => {
                mutate_void::<ITIP20::pauseCall>(calldata, msg_sender, |sender, call| {
                    self.pause(sender, call)
                })
            }
            ITIP20::unpauseCall::SELECTOR => {
                mutate_void::<ITIP20::unpauseCall>(calldata, msg_sender, |sender, call| {
                    self.unpause(sender, call)
                })
            }
            ITIP20::changeTransferPolicyIdCall::SELECTOR => {
                mutate_void::<ITIP20::changeTransferPolicyIdCall>(
                    calldata,
                    msg_sender,
                    |sender, call| self.token.change_transfer_policy_id(sender, call),
                )
            }
            ITIP20::setSupplyCapCall::SELECTOR => {
                mutate_void::<ITIP20::setSupplyCapCall>(calldata, msg_sender, |sender, call| {
                    self.token.set_supply_cap(sender, call)
                })
            }

            // Transfer functions that are disabled for PathUSD
            ITIP20::transferCall::SELECTOR => {
                mutate::<ITIP20::transferCall>(calldata, msg_sender, |sender, call| {
                    self.transfer(sender, call)
                })
            }
            ITIP20::transferFromCall::SELECTOR => {
                mutate::<ITIP20::transferFromCall>(calldata, msg_sender, |sender, call| {
                    self.transfer_from(sender, call)
                })
            }
            ITIP20::transferWithMemoCall::SELECTOR => {
                mutate_void::<ITIP20::transferWithMemoCall>(calldata, msg_sender, |sender, call| {
                    self.transfer_with_memo(sender, call)
                })
            }
            ITIP20::transferFromWithMemoCall::SELECTOR => {
                mutate::<ITIP20::transferFromWithMemoCall>(calldata, msg_sender, |sender, call| {
                    self.transfer_from_with_memo(sender, call)
                })
            }

            ITIP20::startRewardCall::SELECTOR => {
                mutate::<ITIP20::startRewardCall>(calldata, msg_sender, |_s, _call| {
                    Err(TIP20Error::rewards_disabled().into())
                })
            }
            ITIP20::setRewardRecipientCall::SELECTOR => {
                mutate_void::<ITIP20::setRewardRecipientCall>(calldata, msg_sender, |_s, _call| {
                    Err(TIP20Error::rewards_disabled().into())
                })
            }
            ITIP20::cancelRewardCall::SELECTOR => {
                mutate::<ITIP20::cancelRewardCall>(calldata, msg_sender, |_s, _call| {
                    Err(TIP20Error::rewards_disabled().into())
                })
            }
            ITIP20::claimRewardsCall::SELECTOR => {
                mutate::<ITIP20::claimRewardsCall>(calldata, msg_sender, |_, _| {
                    Err(TIP20Error::rewards_disabled().into())
                })
            }

            // RolesAuth functions
            IRolesAuth::hasRoleCall::SELECTOR => {
                view::<IRolesAuth::hasRoleCall>(calldata, |call| self.token.has_role(call))
            }
            IRolesAuth::getRoleAdminCall::SELECTOR => {
                view::<IRolesAuth::getRoleAdminCall>(calldata, |call| {
                    self.token.get_role_admin(call)
                })
            }
            IRolesAuth::grantRoleCall::SELECTOR => {
                mutate_void::<IRolesAuth::grantRoleCall>(calldata, msg_sender, |sender, call| {
                    self.token.grant_role(sender, call)
                })
            }
            IRolesAuth::revokeRoleCall::SELECTOR => {
                mutate_void::<IRolesAuth::revokeRoleCall>(calldata, msg_sender, |sender, call| {
                    self.token.revoke_role(sender, call)
                })
            }
            IRolesAuth::renounceRoleCall::SELECTOR => {
                mutate_void::<IRolesAuth::renounceRoleCall>(calldata, msg_sender, |sender, call| {
                    self.token.renounce_role(sender, call)
                })
            }
            IRolesAuth::setRoleAdminCall::SELECTOR => {
                mutate_void::<IRolesAuth::setRoleAdminCall>(calldata, msg_sender, |sender, call| {
                    self.token.set_role_admin(sender, call)
                })
            }

            _ => Err(PrecompileError::Other("Unknown selector".into())),
        };

        result.map(|mut res| {
            res.gas_used = self.token.storage().gas_used();
            res
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{storage::hashmap::HashMapStorageProvider, test_util::check_selector_coverage};
    use alloy::{
        primitives::{Bytes, U256},
        sol_types::SolInterface,
    };
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{
        IRolesAuth::IRolesAuthCalls, ITIP20::ITIP20Calls, TIP20Error,
    };

    #[test]
    fn path_usd_test_selector_coverage() {
        use crate::test_util::assert_full_coverage;

        let mut storage = HashMapStorageProvider::new(1);
        let mut path_usd = PathUSD::new(&mut storage);

        path_usd.initialize(Address::ZERO).unwrap();

        let itip20_unsupported =
            check_selector_coverage(&mut path_usd, ITIP20Calls::SELECTORS, "ITIP20", |s| {
                ITIP20Calls::name_by_selector(s)
            });

        let roles_unsupported = check_selector_coverage(
            &mut path_usd,
            IRolesAuthCalls::SELECTORS,
            "IRolesAuth",
            IRolesAuthCalls::name_by_selector,
        );

        assert_full_coverage([itip20_unsupported, roles_unsupported]);
    }

    #[test]
    fn test_start_reward_disabled() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = PathUSD::new(&mut storage);
        let sender = Address::from([1u8; 20]);

        token
            .initialize(sender)
            .expect("Failed to initialize token");

        let calldata = ITIP20::startRewardCall {
            amount: U256::from(1000),
            secs: 100,
        }
        .abi_encode();

        let output = token.call(&Bytes::from(calldata), sender)?;
        assert!(output.reverted);
        let expected: Bytes = TIP20Error::rewards_disabled().selector().into();
        assert_eq!(output.bytes, expected);

        Ok(())
    }

    #[test]
    fn test_set_reward_recipient_disabled() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = PathUSD::new(&mut storage);
        let sender = Address::from([1u8; 20]);
        let recipient = Address::from([2u8; 20]);

        token
            .initialize(sender)
            .expect("Failed to initialize token");

        let calldata = ITIP20::setRewardRecipientCall { recipient }.abi_encode();

        let output = token.call(&Bytes::from(calldata), sender)?;
        assert!(output.reverted);
        let expected: Bytes = TIP20Error::rewards_disabled().selector().into();
        assert_eq!(output.bytes, expected);

        Ok(())
    }

    #[test]
    fn test_cancel_reward_disabled() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = PathUSD::new(&mut storage);
        let sender = Address::from([1u8; 20]);

        token
            .initialize(sender)
            .expect("Failed to initialize token");

        let calldata = ITIP20::cancelRewardCall { id: 1 }.abi_encode();

        let output = token.call(&Bytes::from(calldata), sender)?;
        assert!(output.reverted);
        let expected: Bytes = TIP20Error::rewards_disabled().selector().into();
        assert_eq!(output.bytes, expected);

        Ok(())
    }

    #[test]
    fn test_claim_rewards_disabled() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = PathUSD::new(&mut storage);
        let sender = Address::from([1u8; 20]);

        token
            .initialize(sender)
            .expect("Failed to initialize token");

        let calldata = ITIP20::claimRewardsCall {}.abi_encode();

        let output = token.call(&Bytes::from(calldata), sender)?;
        assert!(output.reverted);
        let expected: Bytes = TIP20Error::rewards_disabled().selector().into();
        assert_eq!(output.bytes, expected);

        Ok(())
    }

    #[test]
    fn test_pre_allegretto_name_symbol() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::Moderato);
        let mut token = PathUSD::new(&mut storage);
        let sender = Address::from([1u8; 20]);

        token.initialize(sender)?;

        let name_calldata = ITIP20::nameCall {}.abi_encode();
        let name_output = token.call(&Bytes::from(name_calldata), sender)?;
        let name = ITIP20::nameCall::abi_decode_returns(&name_output.bytes)?;
        assert_eq!(name, "linkingUSD");

        let symbol_calldata = ITIP20::symbolCall {}.abi_encode();
        let symbol_output = token.call(&Bytes::from(symbol_calldata), sender)?;
        let symbol = ITIP20::symbolCall::abi_decode_returns(&symbol_output.bytes)?;
        assert_eq!(symbol, "linkingUSD");

        Ok(())
    }

    #[test]
    fn test_post_allegretto_name_symbol() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::Allegretto);
        let mut token = PathUSD::new(&mut storage);
        let sender = Address::from([1u8; 20]);

        token.initialize(sender)?;

        let name_calldata = ITIP20::nameCall {}.abi_encode();
        let name_output = token.call(&Bytes::from(name_calldata), sender)?;
        let name = ITIP20::nameCall::abi_decode_returns(&name_output.bytes)?;
        assert_eq!(name, "pathUSD");

        // Test symbol() call
        let symbol_calldata = ITIP20::symbolCall {}.abi_encode();
        let symbol_output = token.call(&Bytes::from(symbol_calldata), sender)?;
        let symbol = ITIP20::symbolCall::abi_decode_returns(&symbol_output.bytes)?;
        assert_eq!(symbol, "pathUSD");

        Ok(())
    }
}
