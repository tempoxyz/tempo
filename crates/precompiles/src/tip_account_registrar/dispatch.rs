use crate::{
    Precompile, fill_precompile_output, input_cost, mutate, storage::PrecompileStorageProvider,
    unknown_selector,
};
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
                PrecompileError::Other("Invalid input: missing function selector".into())
            })?
            .try_into()
            .unwrap();

        let result = match selector {
            // Old signature: delegateToDefault(bytes32,bytes) - only pre-Moderato
            ITipAccountRegistrar::delegateToDefault_0Call::SELECTOR => {
                if self.storage.spec().is_moderato() {
                    unknown_selector(selector, self.storage.gas_used(), self.storage.spec())
                } else {
                    mutate::<ITipAccountRegistrar::delegateToDefault_0Call>(
                        calldata,
                        msg_sender,
                        |_, call| self.delegate_to_default_v1(call),
                    )
                }
            }
            // New signature: delegateToDefault(bytes,bytes) - only post-Moderato
            ITipAccountRegistrar::delegateToDefault_1Call::SELECTOR => {
                if self.storage.spec().is_moderato() {
                    mutate::<ITipAccountRegistrar::delegateToDefault_1Call>(
                        calldata,
                        msg_sender,
                        |_, call| self.delegate_to_default_v2(call),
                    )
                } else {
                    unknown_selector(selector, self.storage.gas_used(), self.storage.spec())
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
    use crate::{storage::hashmap::HashMapStorageProvider, test_util::check_selector_coverage};
    use tempo_contracts::precompiles::ITipAccountRegistrar::ITipAccountRegistrarCalls;

    #[test]
    fn tip_account_registrar_test_selector_coverage() {
        use tempo_chainspec::hardfork::TempoHardfork;

        // Pre-Moderato: v1 signature should be supported, v2 should be unsupported
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::Adagio);
        let mut registrar = TipAccountRegistrar::new(&mut storage);

        let unsupported_pre = check_selector_coverage(
            &mut registrar,
            ITipAccountRegistrarCalls::SELECTORS,
            "ITipAccountRegistrar (pre-Moderato)",
            ITipAccountRegistrarCalls::name_by_selector,
        );

        // Expect exactly one unsupported: delegateToDefault v2 (bytes,bytes)
        assert_eq!(
            unsupported_pre.len(),
            1,
            "Expected 1 unsupported selector pre-Moderato, got {}",
            unsupported_pre.len()
        );
        assert_eq!(
            unsupported_pre[0].0,
            ITipAccountRegistrar::delegateToDefault_1Call::SELECTOR,
            "Expected delegateToDefault v2 to be unsupported pre-Moderato"
        );

        // Post-Moderato: v2 signature should be supported, v1 should be unsupported
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::Moderato);
        let mut registrar = TipAccountRegistrar::new(&mut storage);

        let unsupported_post = check_selector_coverage(
            &mut registrar,
            ITipAccountRegistrarCalls::SELECTORS,
            "ITipAccountRegistrar (post-Moderato)",
            ITipAccountRegistrarCalls::name_by_selector,
        );

        // Expect exactly one unsupported: delegateToDefault v1 (bytes32,bytes)
        assert_eq!(
            unsupported_post.len(),
            1,
            "Expected 1 unsupported selector post-Moderato, got {}",
            unsupported_post.len()
        );
        assert_eq!(
            unsupported_post[0].0,
            ITipAccountRegistrar::delegateToDefault_0Call::SELECTOR,
            "Expected delegateToDefault v1 to be unsupported post-Moderato"
        );
    }
}
