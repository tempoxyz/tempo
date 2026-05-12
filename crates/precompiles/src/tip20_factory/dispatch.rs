//! ABI dispatch for the [`TIP20Factory`] precompile.

use crate::{
    Precompile, SelectorSchedule, charge_input_cost, dispatch_call, mutate,
    tip20_factory::TIP20Factory, view,
};
use alloy::{
    primitives::Address,
    sol_types::{SolCall, SolInterface},
};
use revm::precompile::PrecompileResult;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{ITIP20Factory::ITIP20FactoryCalls, createTokenWithLogoCall};

/// Selectors added at T5: TIP-1026 Token Logo URI factory overload.
const T5_ADDED: &[[u8; 4]] = &[createTokenWithLogoCall::SELECTOR];

impl Precompile for TIP20Factory {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch_call(
            calldata,
            &[SelectorSchedule::new(TempoHardfork::T5).with_added(T5_ADDED)],
            ITIP20FactoryCalls::abi_decode,
            |call| match call {
                ITIP20FactoryCalls::createToken_0(call) => {
                    mutate(call, msg_sender, |s, c| self.create_token(s, c))
                }
                ITIP20FactoryCalls::createToken_1(call) => {
                    mutate(call, msg_sender, |s, c| self.create_token_with_logo(s, c))
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
    use alloy::{
        primitives::B256,
        sol_types::{SolCall, SolError},
    };
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{
        ITIP20Factory::ITIP20FactoryCalls, UnknownFunctionSelector,
    };

    #[test]
    fn tip20_factory_test_selector_coverage() {
        // Use T5 hardfork so T5-gated `createTokenWithLogo` selector is active.
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);

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

    #[test]
    fn test_create_token_with_logo_gated_behind_t5() -> eyre::Result<()> {
        // Pre-T5: createTokenWithLogo should return unknown selector.
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T4);
        let sender = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut factory = TIP20Factory::new();

            let calldata = createTokenWithLogoCall {
                name: "Logo".to_string(),
                symbol: "LOGO".to_string(),
                currency: "USD".to_string(),
                quoteToken: Address::ZERO,
                admin: sender,
                salt: B256::ZERO,
                logoURI: String::new(),
            }
            .abi_encode();

            let result = factory.call(&calldata, sender)?;
            assert!(result.is_revert());
            assert!(UnknownFunctionSelector::abi_decode(&result.bytes).is_ok());

            Ok(())
        })
    }
}
