use crate::{Precompile, input_cost, mutate_void, unknown_selector};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};
use tempo_contracts::precompiles::ITIP20RewardsRegistry;

use crate::{storage::PrecompileStorageProvider, tip20_rewards_registry::TIP20RewardsRegistry};

impl<'a, S: PrecompileStorageProvider> Precompile for TIP20RewardsRegistry<'a, S> {
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
            ITIP20RewardsRegistry::finalizeStreamsCall::SELECTOR => {
                mutate_void::<ITIP20RewardsRegistry::finalizeStreamsCall>(
                    calldata,
                    msg_sender,
                    |sender, _call| self.finalize_streams(sender),
                )
            }
            _ => unknown_selector(selector, self.storage.gas_used(), self.storage.spec()),
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
    use tempo_contracts::precompiles::ITIP20RewardsRegistry::ITIP20RewardsRegistryCalls;

    #[test]
    fn tip20_rewards_registry_test_selector_coverage() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut registry = TIP20RewardsRegistry::new(&mut storage);

        let unsupported = check_selector_coverage(
            &mut registry,
            ITIP20RewardsRegistryCalls::SELECTORS,
            "ITIP20RewardsRegistry",
            ITIP20RewardsRegistryCalls::name_by_selector,
        );

        assert_full_coverage([unsupported]);
    }
}
