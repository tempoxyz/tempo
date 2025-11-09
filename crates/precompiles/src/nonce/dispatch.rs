use crate::{
    Precompile, input_cost, nonce::NonceManager, storage::PrecompileStorageProvider, view,
};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};

use super::INonce;

impl<S: PrecompileStorageProvider> Precompile for NonceManager<'_, S> {
    fn call(
        &mut self,
        calldata: &[u8],
        _msg_sender: Address,
        _beneficiary: Address,
    ) -> PrecompileResult {
        self.storage
            .deduct_gas(input_cost(calldata.len()))
            .map_err(|_| PrecompileError::OutOfGas)?;

        let selector: [u8; 4] = calldata
            .get(..4)
            .ok_or_else(|| {
                PrecompileError::Other("Invalid input: missing function selector".to_string())
            })?
            .try_into()
            .unwrap();

        let result = match selector {
            INonce::getNonceCall::SELECTOR => {
                view::<INonce::getNonceCall>(calldata, |call| self.get_nonce(call))
            }
            INonce::getActiveNonceKeyCountCall::SELECTOR => {
                view::<INonce::getActiveNonceKeyCountCall>(calldata, |call| {
                    self.get_active_nonce_key_count(call)
                })
            }
            _ => Err(PrecompileError::Other(
                "Unknown function selector".to_string(),
            )),
        };

        result.map(|mut res| {
            res.gas_used = self.storage.gas_used();
            res
        })
    }
}
