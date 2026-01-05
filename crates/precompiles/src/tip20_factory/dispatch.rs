use crate::{Precompile, fill_precompile_output, input_cost, mutate, unknown_selector, view};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};

use crate::tip20_factory::{ITIP20Factory, TIP20Factory};

impl Precompile for TIP20Factory {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        self.storage
            .deduct_gas(input_cost(calldata.len()))
            .map_err(|_| PrecompileError::OutOfGas)?;

        let selector: [u8; 4] = calldata
            .get(..4)
            .ok_or_else(|| {
                PrecompileError::Other("Invalid input: missing function selector".into())
            })?
            .try_into()
            .map_err(|_| PrecompileError::Other("Invalid function selector length".into()))?;

        let result = match selector {
            ITIP20Factory::createTokenCall::SELECTOR => {
                mutate::<ITIP20Factory::createTokenCall>(calldata, msg_sender, |s, call| {
                    self.create_token(s, call)
                })
            }
            ITIP20Factory::isTIP20Call::SELECTOR => {
                view::<ITIP20Factory::isTIP20Call>(calldata, |call| self.is_tip20(call.token))
            }
            ITIP20Factory::getTokenAddressCall::SELECTOR => {
                view::<ITIP20Factory::getTokenAddressCall>(calldata, |call| {
                    self.get_token_address(call)
                })
            }
            _ => unknown_selector(selector, self.storage.gas_used()),
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
    use tempo_contracts::precompiles::ITIP20Factory::ITIP20FactoryCalls;

    #[test]
    fn tip20_factory_test_selector_coverage() {
        let mut storage = HashMapStorageProvider::new(1);

        StorageCtx::enter(&mut storage, || {
            let mut factory = TIP20Factory::new();

            let unsupported = check_selector_coverage(
                &mut factory,
                ITIP20FactoryCalls::SELECTORS,
                "ITIP20Factory",
                ITIP20FactoryCalls::name_by_selector,
            );

            assert_full_coverage([unsupported]);
        })
    }
}
