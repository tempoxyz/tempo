use crate::{
    Precompile, fill_precompile_output, input_cost, nonce::NonceManager, unknown_selector, view,
};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};

use super::INonce;

impl Precompile for NonceManager {
    fn call(&mut self, calldata: &[u8], _msg_sender: Address) -> PrecompileResult {
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
            INonce::getNonceCall::SELECTOR => {
                view::<INonce::getNonceCall>(calldata, |call| self.get_nonce(call))
            }
            _ => unknown_selector(selector, self.storage.gas_used(), self.storage.spec()),
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
