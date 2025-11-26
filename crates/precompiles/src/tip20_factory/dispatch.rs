use crate::{
    Precompile, fill_precompile_output, input_cost, mutate, tip20::is_tip20, unknown_selector, view,
};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};

use crate::{
    storage::PrecompileStorageProvider,
    tip20_factory::{ITIP20Factory, TIP20Factory},
};

impl<'a, S: PrecompileStorageProvider> Precompile for TIP20Factory<'a, S> {
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
            ITIP20Factory::tokenIdCounterCall::SELECTOR => {
                view::<ITIP20Factory::tokenIdCounterCall>(calldata, |_call| self.token_id_counter())
            }
            ITIP20Factory::createTokenCall::SELECTOR => {
                mutate::<ITIP20Factory::createTokenCall>(calldata, msg_sender, |s, call| {
                    self.create_token(s, call)
                })
            }
            ITIP20Factory::isTIP20Call::SELECTOR => {
                view::<ITIP20Factory::isTIP20Call>(calldata, |call| Ok(is_tip20(call.token)))
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
    use tempo_contracts::precompiles::ITIP20Factory::ITIP20FactoryCalls;

    #[test]
    fn tip20_factory_test_selector_coverage() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut factory = TIP20Factory::new(&mut storage);

        let unsupported = check_selector_coverage(
            &mut factory,
            ITIP20FactoryCalls::SELECTORS,
            "ITIP20Factory",
            ITIP20FactoryCalls::name_by_selector,
        );

        assert_full_coverage([unsupported]);
    }
}
