use crate::{Precompile, view};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};

use crate::tip4217_registry::{ITIP4217Registry, TIP4217Registry};

impl Precompile for TIP4217Registry {
    fn call(&mut self, calldata: &[u8], _msg_sender: Address) -> PrecompileResult {
        let selector: [u8; 4] = calldata
            .get(..4)
            .ok_or_else(|| {
                PrecompileError::Other("Invalid input: missing function selector".to_string())
            })?
            .try_into()
            .unwrap();

        match selector {
            ITIP4217Registry::getCurrencyDecimalsCall::SELECTOR => {
                view::<ITIP4217Registry::getCurrencyDecimalsCall>(calldata, |call| {
                    Ok(self.get_currency_decimals(call))
                })
            }
            _ => Err(PrecompileError::Other(
                "Unknown function selector".to_string(),
            )),
        }
    }
}
