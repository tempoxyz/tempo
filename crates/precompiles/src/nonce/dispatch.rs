use crate::{
    Precompile, fill_precompile_output, input_cost, nonce::NonceManager, unknown_selector, view,
};
use alloy::{primitives::Address, sol_types::SolInterface};
use revm::precompile::{PrecompileError, PrecompileOutput, PrecompileResult};
use tempo_contracts::precompiles::INonce::INonceCalls;

impl Precompile for NonceManager {
    fn call(&mut self, calldata: &[u8], _msg_sender: Address) -> PrecompileResult {
        self.storage
            .deduct_gas(input_cost(calldata.len()))
            .map_err(|_| PrecompileError::OutOfGas)?;

        if calldata.len() < 4 {
            return Err(PrecompileError::Other(
                "Invalid input: missing function selector".into(),
            ));
        }

        let call = match INonceCalls::abi_decode(calldata) {
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
            INonceCalls::getNonce(call) => view(call, |c| self.get_nonce(c)),
        };

        result.map(|res| fill_precompile_output(res, &mut self.storage))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage},
    };
    use tempo_contracts::precompiles::INonce::INonceCalls;

    #[test]
    fn test_nonce_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut nonce_manager = NonceManager::new();

            let unsupported = check_selector_coverage(
                &mut nonce_manager,
                INonceCalls::SELECTORS,
                "INonce",
                INonceCalls::name_by_selector,
            );

            assert_full_coverage([unsupported]);
            Ok(())
        })
    }
}
