use crate::{Precompile, input_cost, mutate, storage::PrecompileStorageProvider};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};

use crate::tip_account_registrar::{ITipAccountRegistrar, TipAccountRegistrar};

impl<'a, S: PrecompileStorageProvider> Precompile for TipAccountRegistrar<'a, S> {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
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
        };

        result.map(|mut res| {
            res.gas_used = self.storage.gas_used();
            res
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        storage::hashmap::HashMapStorageProvider,
        test_util::{assert_full_coverage, check_selector_coverage},
    };
    use tempo_contracts::precompiles::ITipAccountRegistrar::ITipAccountRegistrarCalls;

    #[test]
    fn tip_account_registrar_test_selector_coverage() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut registrar = TipAccountRegistrar::new(&mut storage);

        let unsupported = check_selector_coverage(
            &mut registrar,
            ITipAccountRegistrarCalls::SELECTORS,
            "ITipAccountRegistrar",
            ITipAccountRegistrarCalls::name_by_selector,
        );

        assert_full_coverage([unsupported]);
    }
}
