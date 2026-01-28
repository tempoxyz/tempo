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
                IAccountKeychainCalls::getKey(call) => view(call, |c| self.get_key(c)),
                IAccountKeychainCalls::getRemainingLimit(call) => {
                    view(call, |c| self.get_remaining_limit(c))
                }
                IAccountKeychainCalls::getTransactionKey(call) => {
                    view(call, |c| self.get_transaction_key(c, msg_sender))
                }
                IAccountKeychainCalls::getAllowedDestinations(call) => {
                    view(call, |c| self.get_allowed_destinations_sol(c))
                }
                // TIP-1013: Activation window functions
                IAccountKeychainCalls::getActivationWindow(call) => {
                    view(call, |c| self.get_activation_window(c))
                }
                IAccountKeychainCalls::extendActivation(call) => {
                    mutate_void(call, msg_sender, |sender, c| {
                        self.extend_activation(sender, c)
                    })
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
