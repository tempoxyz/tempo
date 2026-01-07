use super::AccountKeychain;
use crate::{Precompile, fill_precompile_output, input_cost, mutate_void, unknown_selector, view};
use alloy::{primitives::Address, sol_types::SolInterface};
use revm::precompile::{PrecompileError, PrecompileOutput, PrecompileResult};
use tempo_contracts::precompiles::IAccountKeychain::IAccountKeychainCalls;

impl Precompile for AccountKeychain {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        self.storage
            .deduct_gas(input_cost(calldata.len()))
            .map_err(|_| PrecompileError::OutOfGas)?;

        if calldata.len() < 4 {
            return Err(PrecompileError::Other(
                "Invalid input: missing function selector".into(),
            ));
        }

        let call = match IAccountKeychainCalls::abi_decode(calldata) {
            Ok(call) => call,
            Err(alloy::sol_types::Error::UnknownSelector { selector, .. }) => {
                return unknown_selector(*selector, self.storage.gas_used())
                    .map(|res| fill_precompile_output(res, &mut self.storage));
            }
            Err(_) => {
                return Ok(fill_precompile_output(
                    PrecompileOutput::new_reverted(0, alloy::primitives::Bytes::new()),
                    &mut self.storage,
                ));
            }
        };

        let result = match call {
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
        };

        result.map(|res| fill_precompile_output(res, &mut self.storage))
    }
}
