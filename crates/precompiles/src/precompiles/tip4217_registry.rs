use crate::precompiles::{metadata, Precompile};
use alloy::{primitives::Address, sol_types::SolCall};
use reth::revm::precompile::{PrecompileError, PrecompileResult};

use crate::contracts::{storage::StorageProvider, tip4217_registry::TIP4217Registry, types::ITIP4217Registry};

impl<'a, S: StorageProvider> Precompile for TIP4217Registry<'a, S> {
    fn call(&mut self, calldata: &[u8], _msg_sender: &Address) -> PrecompileResult {
        let selector: [u8; 4] = calldata
            .get(..4)
            .ok_or_else(|| PrecompileError::Other("Invalid input: missing function selector".to_string()))?
            .try_into()
            .unwrap();

        match selector {
            ITIP4217Registry::getCurrencyDecimalsCall::SELECTOR => {
                // pure view
                let call = ITIP4217Registry::getCurrencyDecimalsCall::abi_decode(calldata)
                    .map_err(|e| PrecompileError::Other(format!("Failed to decode input: {e}")))?;
                let result = self.get_currency_decimals(call);
                Ok(reth::revm::precompile::PrecompileOutput::new(
                    super::VIEW_FUNC_GAS,
                    ITIP4217Registry::getCurrencyDecimalsCall::abi_encode_returns(&result).into(),
                ))
            }
            _ => Err(PrecompileError::Other("Unknown function selector".to_string())),
        }
    }
}
