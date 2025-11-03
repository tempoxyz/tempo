use super::{AccountKeychain, IAccountKeychain};
use crate::{Precompile, mutate_void, view};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};

impl<S: crate::storage::PrecompileStorageProvider> Precompile for AccountKeychain<'_, S> {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        let selector: [u8; 4] = calldata
            .get(..4)
            .ok_or_else(|| {
                PrecompileError::Other("Invalid input: missing function selector".to_string())
            })?
            .try_into()
            .unwrap();

        match selector {
            IAccountKeychain::authorizeKeyCall::SELECTOR => {
                mutate_void::<IAccountKeychain::authorizeKeyCall>(
                    calldata,
                    msg_sender,
                    |sender, call| self.authorize_key(call, &sender),
                )
            }

            IAccountKeychain::revokeKeyCall::SELECTOR => {
                mutate_void::<IAccountKeychain::revokeKeyCall>(
                    calldata,
                    msg_sender,
                    |sender, call| self.revoke_key(call, &sender),
                )
            }

            IAccountKeychain::updateSpendingLimitCall::SELECTOR => {
                mutate_void::<IAccountKeychain::updateSpendingLimitCall>(
                    calldata,
                    msg_sender,
                    |sender, call| self.update_spending_limit(call, &sender),
                )
            }

            IAccountKeychain::getKeyCall::SELECTOR => {
                view::<IAccountKeychain::getKeyCall>(calldata, |call| self.get_key(call))
            }

            IAccountKeychain::getRemainingLimitCall::SELECTOR => {
                view::<IAccountKeychain::getRemainingLimitCall>(calldata, |call| {
                    self.get_remaining_limit(call)
                })
            }

            IAccountKeychain::getTransactionKeyCall::SELECTOR => {
                view::<IAccountKeychain::getTransactionKeyCall>(calldata, |call| {
                    self.get_transaction_key(call, &msg_sender)
                })
            }

            _ => Err(PrecompileError::Other(
                "Unknown function selector".to_string(),
            )),
        }
    }
}
