use crate::precompiles::{Precompile, view};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};

use crate::contracts::{nonce::NonceManager, types::INonce};

impl<S: crate::contracts::StorageProvider> Precompile for NonceManager<'_, S> {
    fn call(&mut self, calldata: &[u8], _msg_sender: &Address) -> PrecompileResult {
        let selector: [u8; 4] = calldata
            .get(..4)
            .ok_or_else(|| {
                PrecompileError::Other("Invalid input: missing function selector".to_string())
            })?
            .try_into()
            .unwrap();

        match selector {
            INonce::getNonceCall::SELECTOR => {
                let call = INonce::getNonceCall::abi_decode(calldata)
                    .map_err(|e| PrecompileError::Other(format!("Failed to decode input: {e}")))?;

                match self.get_nonce(call) {
                    Ok(nonce) => view::<INonce::getNonceCall>(calldata, |_| nonce),
                    Err(e) => Err(PrecompileError::Other(e)),
                }
            }
            INonce::getActiveNonceKeyCountCall::SELECTOR => {
                view::<INonce::getActiveNonceKeyCountCall>(calldata, |call| {
                    self.get_active_nonce_key_count(call)
                })
            }
            _ => Err(PrecompileError::Other(
                "Unknown function selector".to_string(),
            )),
        }
    }
}
