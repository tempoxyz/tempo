use super::{AccountKeychain, IAccountKeychain};
use crate::{
    Precompile, input_cost, mutate_void, storage::PrecompileStorageProvider, unknown_selector, view,
};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};

impl<S: PrecompileStorageProvider> Precompile for AccountKeychain<'_, S> {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        self.storage
            .deduct_gas(input_cost(calldata.len()))
            .map_err(|_| PrecompileError::OutOfGas)?;

        let selector: [u8; 4] = calldata
            .get(..4)
            .ok_or_else(|| {
                PrecompileError::Other("Invalid input: missing function selector".into())
            })?
            .try_into()
            .unwrap();

        let result = match selector {
            IAccountKeychain::authorizeKeyCall::SELECTOR => {
                mutate_void::<IAccountKeychain::authorizeKeyCall>(
                    calldata,
                    msg_sender,
                    |sender, call| self.authorize_key(sender, call),
                )
            }

            IAccountKeychain::revokeKeyCall::SELECTOR => {
                mutate_void::<IAccountKeychain::revokeKeyCall>(
                    calldata,
                    msg_sender,
                    |sender, call| self.revoke_key(sender, call),
                )
            }

            IAccountKeychain::updateSpendingLimitCall::SELECTOR => {
                mutate_void::<IAccountKeychain::updateSpendingLimitCall>(
                    calldata,
                    msg_sender,
                    |sender, call| self.update_spending_limit(sender, call),
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
                    self.get_transaction_key(call, msg_sender)
                })
            }

            _ => unknown_selector(selector, self.storage.gas_used(), self.storage.spec()),
        };

        result.map(|mut res| {
            res.gas_used = self.storage.gas_used();
            res
        })
    }
}
