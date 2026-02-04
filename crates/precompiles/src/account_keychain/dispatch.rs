use super::AccountKeychain;
use crate::{Precompile, dispatch_call, input_cost, mutate_void, view};
use alloy::{primitives::Address, sol_types::SolInterface};
use revm::precompile::{PrecompileError, PrecompileResult};
use tempo_contracts::precompiles::IAccountKeychain::IAccountKeychainCalls;

impl Precompile for AccountKeychain {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        self.storage
            .deduct_gas(input_cost(calldata.len()))
            .map_err(|_| PrecompileError::OutOfGas)?;

        dispatch_call(
            calldata,
            IAccountKeychainCalls::abi_decode,
            |call| match call {
                IAccountKeychainCalls::authorizeKey(call) => {
                    mutate_void(call, msg_sender, |sender, c| self.authorize_key(sender, c))
                }
                IAccountKeychainCalls::revokeKey(call) => {
                    mutate_void(call, msg_sender, |sender, c| self.revoke_key(sender, c))
                }
                IAccountKeychainCalls::updateSpendingLimit(call) => {
                    mutate_void(call, msg_sender, |sender, c| {
                        self.update_spending_limit(sender, c)
                    })
                }
                // TIP-1011: Periodic spending limits (T2+)
                IAccountKeychainCalls::setPeriodicLimit(call) => {
                    mutate_void(call, msg_sender, |sender, c| {
                        self.set_periodic_limit(sender, c)
                    })
                }
                // TIP-1011: Destination scoping (T2+)
                IAccountKeychainCalls::setAllowedDestinations(call) => {
                    mutate_void(call, msg_sender, |sender, c| {
                        self.set_allowed_destinations(sender, c)
                    })
                }
                IAccountKeychainCalls::getKey(call) => view(call, |c| self.get_key(c)),
                IAccountKeychainCalls::getRemainingLimit(call) => {
                    view(call, |c| self.get_remaining_limit(c))
                }
                // TIP-1011: Get limit info with period data (T2+)
                IAccountKeychainCalls::getLimitInfo(call) => {
                    view(call, |c| self.get_limit_info(c))
                }
                // TIP-1011: Get allowed destinations (T2+)
                IAccountKeychainCalls::getAllowedDestinations(call) => {
                    view(call, |c| self.get_allowed_destinations(c))
                }
                IAccountKeychainCalls::getTransactionKey(call) => {
                    view(call, |c| self.get_transaction_key(c, msg_sender))
                }
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage},
    };

    #[test]
    fn test_account_keychain_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut fee_manager = AccountKeychain::new();

            let unsupported = check_selector_coverage(
                &mut fee_manager,
                IAccountKeychainCalls::SELECTORS,
                "IAccountKeychain",
                IAccountKeychainCalls::name_by_selector,
            );

            assert_full_coverage([unsupported]);

            Ok(())
        })
    }
}
