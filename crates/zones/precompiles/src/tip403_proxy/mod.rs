//! Zone rules for the L1-backed Tempo TIP-403 registry.
//!
//! Other precompiles use the upstream
//! [`tempo_precompiles::tip403_registry::TIP403Registry`] implementation directly over finalized
//! L1 storage. Calls through the canonical EVM address are rejected as external calls.

use crate::execution::{CallCheck, CallRules};
use alloy_primitives::Address;
use alloy_sol_types::SolError;

alloy_sol_types::sol! {
    /// Returned when a nonzero caller accesses the registry through its EVM interface.
    #[derive(Debug, PartialEq, Eq)]
    error OnlyPrecompiles();
}

/// Restricts EVM calls to the registry.
///
/// Registry reads may fetch finalized L1 state, so allowing arbitrary simulations would let RPC
/// clients repeatedly consume operator resources. The zero address is reserved for simulations on
/// the trusted operator RPC, so that endpoint must not be exposed to untrusted callers. The public
/// redacted RPC binds every simulation to its authenticated caller and therefore cannot call it.
///
/// Other precompiles bypass this EVM adapter and invoke the TIP-403 implementation directly.
pub(crate) struct Tip403Rules;

impl CallRules for Tip403Rules {
    fn admit(&self, _data: &[u8], caller: Address) -> CallCheck {
        // Operator simulations use `address(0)`. Public RPC simulations cannot select this caller.
        if caller.is_zero() {
            return CallCheck::Continue;
        }
        CallCheck::Revert(OnlyPrecompiles {}.abi_encode().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use alloy_evm::precompiles::DynPrecompile;
    use alloy_primitives::{Bytes, U256, address};
    use alloy_sol_types::SolCall;
    use revm::precompile::{PrecompileError, PrecompileOutput};
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{ITIP403Registry, TIP403_REGISTRY_ADDRESS};
    use tempo_precompiles::{DelegateCallNotAllowed, storage::PrecompileStorageProvider};

    use crate::{
        tempo_state::slots::TEMPO_BLOCK_NUMBER,
        test_utils::{TestContext, call_precompile, test_context, test_env, test_storage_provider},
    };

    const ANCHOR: u64 = 77;
    const CALLER: Address = address!("0x0000000000000000000000000000000000000aaa");

    struct RegistryHarness {
        ctx: TestContext,
        precompile: DynPrecompile,
    }

    impl RegistryHarness {
        fn new() -> Self {
            let mut ctx = test_context();
            ctx.cfg.spec = TempoHardfork::T8;
            test_storage_provider(&mut ctx, u64::MAX, false)
                .sstore(
                    zone_primitives::constants::TEMPO_STATE_ADDRESS,
                    TEMPO_BLOCK_NUMBER,
                    U256::from(ANCHOR),
                )
                .unwrap();
            let env = test_env(&ctx);
            Self {
                ctx,
                precompile: zone_precompile!(
                    env,
                    tempo_precompiles::tip403_registry::TIP403Registry,
                    Tip403Rules
                ),
            }
        }

        fn call(&mut self, data: &[u8], gas: u64) -> Result<PrecompileOutput, PrecompileError> {
            self.call_as(data, gas, TIP403_REGISTRY_ADDRESS, TIP403_REGISTRY_ADDRESS)
        }

        fn call_as(
            &mut self,
            data: &[u8],
            gas: u64,
            target: Address,
            bytecode: Address,
        ) -> Result<PrecompileOutput, PrecompileError> {
            call_precompile(
                &mut self.ctx,
                &self.precompile,
                CALLER,
                data,
                gas,
                true,
                target,
                bytecode,
            )
        }
    }

    #[test]
    fn only_zero_address_is_admitted() {
        let data = ITIP403Registry::policyIdCounterCall {}.abi_encode();
        assert!(matches!(
            Tip403Rules.admit(&data, Address::ZERO),
            CallCheck::Continue
        ));
        for caller in [CALLER, Address::repeat_byte(0x20)] {
            assert!(matches!(
                Tip403Rules.admit(&data, caller),
                CallCheck::Revert(data) if data == OnlyPrecompiles {}.abi_encode()
            ));
        }
    }

    #[test]
    fn external_calls_revert_with_only_precompiles() -> eyre::Result<()> {
        let mut harness = RegistryHarness::new();
        let output = harness.call(
            &ITIP403Registry::policyIdCounterCall {}.abi_encode(),
            u64::MAX,
        )?;

        assert!(output.is_revert());
        assert_eq!(output.bytes, Bytes::from(OnlyPrecompiles {}.abi_encode()));
        Ok(())
    }

    #[test]
    fn delegate_calls_revert_before_execution() -> eyre::Result<()> {
        let mut harness = RegistryHarness::new();
        let call = ITIP403Registry::policyIdCounterCall {}.abi_encode();
        let output = harness.call_as(
            &call,
            u64::MAX,
            TIP403_REGISTRY_ADDRESS,
            Address::repeat_byte(0x44),
        )?;

        assert!(output.is_revert());
        assert_eq!(output.gas_used, 0);
        assert_eq!(
            output.bytes,
            Bytes::from(DelegateCallNotAllowed {}.abi_encode())
        );
        Ok(())
    }
}
