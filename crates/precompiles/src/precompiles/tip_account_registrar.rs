use crate::precompiles::{Precompile, mutate};
use alloy::{primitives::Address, sol_types::SolCall};
use reth_evm::revm::precompile::{PrecompileError, PrecompileResult};

use crate::contracts::{StorageProvider, TipAccountRegistrar, types::ITipAccountRegistrar};

impl<'a, S: StorageProvider> Precompile for TipAccountRegistrar<'a, S> {
    fn call(&mut self, calldata: &[u8], msg_sender: &Address) -> PrecompileResult {
        let selector: [u8; 4] = calldata
            .get(..4)
            .ok_or_else(|| {
                PrecompileError::Other("Invalid input: missing function selector".to_string())
            })?
            .try_into()
            .unwrap();

        match selector {
            ITipAccountRegistrar::delegateToDefaultCall::SELECTOR => {
                mutate::<ITipAccountRegistrar::delegateToDefaultCall, _>(
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
