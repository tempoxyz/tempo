//! Zone read-privacy rules for the upstream Tempo NonceManager precompile.

use alloy_primitives::Address;
use alloy_sol_types::SolInterface;
use tempo_contracts::precompiles::INonce;
use tempo_precompiles::dispatch::abi_decoder_config_for_spec;

use crate::{
    execution::{CallCheck, CallRules},
    privacy::check_caller,
    storage::StorageCtx,
};

/// Zone-specific rules applied before forwarding to upstream `NonceManager`.
#[derive(Clone)]
pub(crate) struct NonceRules;

impl CallRules for NonceRules {
    fn admit(&self, data: &[u8], caller: Address) -> CallCheck {
        let Ok(call) = INonce::INonceCalls::abi_decode_with_config(
            data,
            abi_decoder_config_for_spec(StorageCtx::default().spec()),
        ) else {
            // Preserve the upstream error and gas behavior for malformed or unknown calldata.
            return CallCheck::Continue;
        };

        // Intentionally exhaustive: an upstream ABI addition must be classified here.
        match call {
            INonce::INonceCalls::getNonce(call) => check_caller(caller, &[call.account]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};
    use alloy_sol_types::{SolCall, SolError};
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_zone_contracts::Unauthorized;

    use crate::{
        storage::StorageCtx,
        test_utils::{test_context, test_storage_provider},
    };

    fn admit_at(data: &[u8], caller: Address, spec: TempoHardfork) -> CallCheck {
        let mut ctx = test_context();
        ctx.cfg.spec = spec;
        let mut storage = test_storage_provider(&mut ctx, u64::MAX, true);
        StorageCtx::enter(&mut storage, || NonceRules.admit(data, caller))
    }

    #[test]
    fn nonce_reads_allow_only_owner() {
        let owner = Address::repeat_byte(0x11);
        let sequencer = Address::repeat_byte(0x22);
        let outsider = Address::repeat_byte(0x33);
        let intermediary = Address::repeat_byte(0x44);
        let rules = NonceRules;
        let call = INonce::getNonceCall {
            account: owner,
            nonceKey: U256::ONE,
        };
        let mut ctx = test_context();
        let mut storage = test_storage_provider(&mut ctx, u64::MAX, true);

        StorageCtx::enter(&mut storage, || {
            assert!(matches!(
                rules.admit(&call.abi_encode(), owner),
                CallCheck::Continue
            ));
            for caller in [sequencer, outsider, intermediary] {
                assert!(matches!(
                    rules.admit(&call.abi_encode(), caller),
                    CallCheck::Revert(data) if data == Unauthorized {}.abi_encode()
                ));
            }
        });
    }

    #[test]
    fn t11_defers_noncanonical_address_calldata_to_upstream() {
        let owner = Address::repeat_byte(0x11);
        let outsider = Address::repeat_byte(0x22);
        let mut data = INonce::getNonceCall {
            account: owner,
            nonceKey: U256::ONE,
        }
        .abi_encode();
        data[4] = 1;

        assert!(matches!(
            admit_at(&data, outsider, TempoHardfork::T8),
            CallCheck::Revert(data) if data == Unauthorized {}.abi_encode()
        ));
        assert!(matches!(
            admit_at(&data, outsider, TempoHardfork::T11),
            CallCheck::Continue
        ));
    }
}
