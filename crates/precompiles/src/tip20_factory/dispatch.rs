//! ABI dispatch for the [`TIP20Factory`] precompile.

use crate::{
    Precompile, charge_input_cost, dispatch_call, mutate, tip20_factory::TIP20Factory, view,
};
use alloy::{primitives::Address, sol_types::SolInterface};
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::ITIP20Factory::ITIP20FactoryCalls;

impl Precompile for TIP20Factory {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch_call(
            calldata,
            &[],
            ITIP20FactoryCalls::abi_decode,
            |call| match call {
                ITIP20FactoryCalls::createToken(call) => {
                    mutate(call, msg_sender, |s, c| self.create_token(s, c))
                }
                ITIP20FactoryCalls::isTIP20(call) => view(call, |c| self.is_tip20(c.token)),
                ITIP20FactoryCalls::getTokenAddress(call) => {
                    view(call, |c| self.get_token_address(c))
                }
            },
        )
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
