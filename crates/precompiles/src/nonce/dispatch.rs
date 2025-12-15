use crate::{
    Precompile, fill_precompile_output, input_cost, nonce::NonceManager,
    storage::PrecompileStorageProvider, unknown_selector, view,
};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};

use super::INonce;

impl<S: PrecompileStorageProvider> Precompile for NonceManager<'_, S> {
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
            // Deprecated post-AllegroModerato: active key count is no longer tracked
            INonce::getActiveNonceKeyCountCall::SELECTOR => {
                if self.storage.spec().is_allegro_moderato() {
                    unknown_selector(selector, self.storage.gas_used(), self.storage.spec())
                } else {
                    view::<INonce::getActiveNonceKeyCountCall>(calldata, |call| {
                        self.get_active_nonce_key_count(call)
                    })
                }
            }
            _ => unknown_selector(selector, self.storage.gas_used(), self.storage.spec()),
        };

        result.map(|res| fill_precompile_output(res, self.storage))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        storage::hashmap::HashMapStorageProvider,
        test_util::{assert_full_coverage, check_selector_coverage},
    };
    use tempo_contracts::precompiles::INonce::INonceCalls;

    #[test]
    fn nonce_test_selector_coverage() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut nonce_manager = NonceManager::new(&mut storage);

        let unsupported =
            check_selector_coverage(&mut nonce_manager, INonceCalls::SELECTORS, "INonce", |s| {
                INonceCalls::name_by_selector(s)
            });

        assert_full_coverage([unsupported]);
    }
}
