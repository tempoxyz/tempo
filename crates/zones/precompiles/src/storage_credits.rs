//! Zone read-privacy rules for the upstream Tempo StorageCredits precompile.

use alloy_primitives::Address;
use alloy_sol_types::SolInterface;
use tempo_contracts::precompiles::IStorageCredits;
use tempo_precompiles::dispatch::abi_decoder_config_for_spec;

use crate::{
    execution::{CallCheck, CallRules},
    privacy::check_caller,
    storage::StorageCtx,
};

/// Zone-specific rules applied before forwarding to upstream `StorageCredits`.
#[derive(Clone)]
pub(crate) struct StorageCreditsRules;

impl CallRules for StorageCreditsRules {
    fn admit(&self, data: &[u8], caller: Address) -> CallCheck {
        let Ok(call) = IStorageCredits::IStorageCreditsCalls::abi_decode_with_config(
            data,
            abi_decoder_config_for_spec(StorageCtx::default().spec()),
        ) else {
            return CallCheck::Continue;
        };

        // Intentionally exhaustive: an upstream ABI addition must be classified here.
        match call {
            IStorageCredits::IStorageCreditsCalls::balanceOf(call) => {
                check_caller(caller, &[call.account])
            }
            IStorageCredits::IStorageCreditsCalls::modeOf(call) => {
                check_caller(caller, &[call.account])
            }
            IStorageCredits::IStorageCreditsCalls::budgetOf(call) => {
                check_caller(caller, &[call.account])
            }
            IStorageCredits::IStorageCreditsCalls::setMode(_)
            | IStorageCredits::IStorageCreditsCalls::setBudget(_) => CallCheck::Continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        StorageCtx::enter(&mut storage, || StorageCreditsRules.admit(data, caller))
    }

    #[test]
    fn account_indexed_getters_allow_only_owner() {
        let owner = Address::repeat_byte(0x11);
        let sequencer = Address::repeat_byte(0x22);
        let outsider = Address::repeat_byte(0x33);
        let rules = StorageCreditsRules;
        let mut ctx = test_context();
        let mut storage = test_storage_provider(&mut ctx, u64::MAX, true);

        StorageCtx::enter(&mut storage, || {
            for call in [
                IStorageCredits::IStorageCreditsCalls::balanceOf(IStorageCredits::balanceOfCall {
                    account: owner,
                }),
                IStorageCredits::IStorageCreditsCalls::modeOf(IStorageCredits::modeOfCall {
                    account: owner,
                }),
                IStorageCredits::IStorageCreditsCalls::budgetOf(IStorageCredits::budgetOfCall {
                    account: owner,
                }),
            ] {
                assert!(matches!(
                    rules.admit(&call.abi_encode(), owner),
                    CallCheck::Continue
                ));
                for caller in [sequencer, outsider] {
                    assert!(matches!(
                        rules.admit(&call.abi_encode(), caller),
                        CallCheck::Revert(data) if data == Unauthorized {}.abi_encode()
                    ));
                }
            }
        });
    }

    #[test]
    fn mutations_and_malformed_calldata_remain_upstream_authorized() {
        let caller = Address::repeat_byte(0x11);
        assert!(matches!(
            admit_at(
                &IStorageCredits::setBudgetCall { credits: 7 }.abi_encode(),
                caller,
                TempoHardfork::T8,
            ),
            CallCheck::Continue
        ));
        assert!(matches!(
            admit_at(
                &IStorageCredits::balanceOfCall::SELECTOR,
                caller,
                TempoHardfork::T8,
            ),
            CallCheck::Continue
        ));
    }

    #[test]
    fn t11_defers_noncanonical_address_calldata_to_upstream() {
        let owner = Address::repeat_byte(0x11);
        let outsider = Address::repeat_byte(0x22);
        let mut data = IStorageCredits::balanceOfCall { account: owner }.abi_encode();
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
