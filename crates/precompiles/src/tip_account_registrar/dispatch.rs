use crate::{Precompile, mutate, storage::PrecompileStorageProvider};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};

use crate::tip_account_registrar::{ITipAccountRegistrar, TipAccountRegistrar};

impl<'a, S: PrecompileStorageProvider> Precompile for TipAccountRegistrar<'a, S> {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        let selector: [u8; 4] = calldata
            .get(..4)
            .ok_or_else(|| {
                PrecompileError::Other("Invalid input: missing function selector".to_string())
            })?
            .try_into()
            .unwrap();

        match selector {
            ITipAccountRegistrar::delegateToDefaultCall::SELECTOR => {
                mutate::<ITipAccountRegistrar::delegateToDefaultCall>(
                    calldata,
                    msg_sender,
                    |_, call| self.delegate_to_default(call),
                )
            }
            _ => Err(PrecompileError::Other(
                "Unknown function selector".to_string(),
            )),
        }
    }
}
