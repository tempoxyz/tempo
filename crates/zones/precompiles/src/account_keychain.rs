//! Zone read-privacy rules for the upstream Tempo AccountKeychain precompile.

use alloy_primitives::Address;
use alloy_sol_types::{SolCall, SolInterface};
use tempo_contracts::precompiles::IAccountKeychain;
use tempo_precompiles::dispatch::abi_decoder_config_for_spec;

use crate::{
    execution::{CallCheck, CallRules},
    privacy::check_caller,
    storage::StorageCtx,
};

/// Zone-specific rules applied before forwarding to upstream `AccountKeychain`.
#[derive(Clone)]
pub(crate) struct AccountKeychainRules;

const UNRESTRICTED_SELECTORS: &[[u8; 4]] = &[
    IAccountKeychain::authorizeKey_0Call::SELECTOR,
    IAccountKeychain::authorizeKey_1Call::SELECTOR,
    IAccountKeychain::authorizeKey_2Call::SELECTOR,
    IAccountKeychain::authorizeAdminKeyCall::SELECTOR,
    IAccountKeychain::burnKeyAuthorizationWitnessCall::SELECTOR,
    IAccountKeychain::revokeKeyCall::SELECTOR,
    IAccountKeychain::updateSpendingLimitCall::SELECTOR,
    IAccountKeychain::setAllowedCallsCall::SELECTOR,
    IAccountKeychain::removeAllowedCallsCall::SELECTOR,
    IAccountKeychain::getTransactionKeyCall::SELECTOR,
];

impl CallRules for AccountKeychainRules {
    fn admit(&self, data: &[u8], caller: Address) -> CallCheck {
        let spec = StorageCtx::default().spec();

        // These calls have no Zone-specific privacy policy. Defer directly to the upstream
        // dispatcher for selector scheduling and ABI decoding.
        if data.get(..4).is_some_and(|selector| {
            UNRESTRICTED_SELECTORS
                .iter()
                .any(|allowed| selector == allowed.as_slice())
        }) {
            return CallCheck::Continue;
        }

        let Ok(call) = IAccountKeychain::IAccountKeychainCalls::abi_decode_with_config(
            data,
            abi_decoder_config_for_spec(spec),
        ) else {
            // Preserve the upstream error and gas behavior for malformed or unknown calldata.
            return CallCheck::Continue;
        };

        // Intentionally exhaustive: an upstream ABI addition must be classified here.
        match call {
            IAccountKeychain::IAccountKeychainCalls::getKey(call) => {
                check_caller(caller, &[call.account])
            }
            IAccountKeychain::IAccountKeychainCalls::getRemainingLimit(call) => {
                check_caller(caller, &[call.account])
            }
            IAccountKeychain::IAccountKeychainCalls::getRemainingLimitWithPeriod(call) => {
                check_caller(caller, &[call.account])
            }
            IAccountKeychain::IAccountKeychainCalls::getAllowedCalls(call) => {
                check_caller(caller, &[call.account])
            }
            IAccountKeychain::IAccountKeychainCalls::isKeyAuthorizationWitnessBurned(call) => {
                check_caller(caller, &[call.account])
            }
            IAccountKeychain::IAccountKeychainCalls::isAdminKey(call) => {
                check_caller(caller, &[call.account])
            }
            IAccountKeychain::IAccountKeychainCalls::authorizeKey_0(_)
            | IAccountKeychain::IAccountKeychainCalls::authorizeKey_1(_)
            | IAccountKeychain::IAccountKeychainCalls::authorizeKey_2(_)
            | IAccountKeychain::IAccountKeychainCalls::authorizeAdminKey(_)
            | IAccountKeychain::IAccountKeychainCalls::burnKeyAuthorizationWitness(_)
            | IAccountKeychain::IAccountKeychainCalls::revokeKey(_)
            | IAccountKeychain::IAccountKeychainCalls::updateSpendingLimit(_)
            | IAccountKeychain::IAccountKeychainCalls::setAllowedCalls(_)
            | IAccountKeychain::IAccountKeychainCalls::removeAllowedCalls(_)
            | IAccountKeychain::IAccountKeychainCalls::getTransactionKey(_) => CallCheck::Continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256};
    use alloy_sol_types::{SolCall, SolError};
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_zone_contracts::Unauthorized;

    use crate::{
        storage::StorageCtx,
        test_utils::{test_context, test_storage_provider},
    };

    fn admit_at(
        rules: &AccountKeychainRules,
        data: &[u8],
        caller: Address,
        spec: TempoHardfork,
    ) -> CallCheck {
        let mut ctx = test_context();
        ctx.cfg.spec = spec;
        let mut storage = test_storage_provider(&mut ctx, u64::MAX, true);
        StorageCtx::enter(&mut storage, || rules.admit(data, caller))
    }

    fn assert_account_scoped<C: SolCall + Clone>(
        rules: &AccountKeychainRules,
        call: C,
        owner: Address,
        sequencer: Address,
        outsider: Address,
    ) {
        assert!(matches!(
            rules.admit(&call.abi_encode(), owner),
            CallCheck::Continue
        ));
        for caller in [sequencer, outsider] {
            assert!(matches!(
                rules.admit(&call.clone().abi_encode(), caller),
                CallCheck::Revert(data) if data == Unauthorized {}.abi_encode()
            ));
        }
    }

    #[test]
    fn account_indexed_getters_allow_only_owner() {
        let owner = Address::repeat_byte(0x11);
        let key_id = Address::repeat_byte(0x12);
        let token = Address::repeat_byte(0x13);
        let sequencer = Address::repeat_byte(0x22);
        let outsider = Address::repeat_byte(0x33);
        let rules = AccountKeychainRules;
        let mut ctx = test_context();
        let mut storage = test_storage_provider(&mut ctx, u64::MAX, true);

        StorageCtx::enter(&mut storage, || {
            assert_account_scoped(
                &rules,
                IAccountKeychain::getKeyCall {
                    account: owner,
                    keyId: key_id,
                },
                owner,
                sequencer,
                outsider,
            );
            assert_account_scoped(
                &rules,
                IAccountKeychain::getRemainingLimitCall {
                    account: owner,
                    keyId: key_id,
                    token,
                },
                owner,
                sequencer,
                outsider,
            );
            assert_account_scoped(
                &rules,
                IAccountKeychain::getRemainingLimitWithPeriodCall {
                    account: owner,
                    keyId: key_id,
                    token,
                },
                owner,
                sequencer,
                outsider,
            );
            assert_account_scoped(
                &rules,
                IAccountKeychain::getAllowedCallsCall {
                    account: owner,
                    keyId: key_id,
                },
                owner,
                sequencer,
                outsider,
            );
            assert_account_scoped(
                &rules,
                IAccountKeychain::isKeyAuthorizationWitnessBurnedCall {
                    account: owner,
                    witness: B256::repeat_byte(0x55),
                },
                owner,
                sequencer,
                outsider,
            );
            assert_account_scoped(
                &rules,
                IAccountKeychain::isAdminKeyCall {
                    account: owner,
                    keyId: key_id,
                },
                owner,
                sequencer,
                outsider,
            );
        });
    }

    #[test]
    fn caller_scoped_and_mutating_methods_remain_upstream_authorized() {
        let caller = Address::repeat_byte(0x11);
        let rules = AccountKeychainRules;

        let mut ctx = test_context();
        let mut storage = test_storage_provider(&mut ctx, u64::MAX, true);
        StorageCtx::enter(&mut storage, || {
            assert!(matches!(
                rules.admit(
                    &IAccountKeychain::getTransactionKeyCall {}.abi_encode(),
                    caller,
                ),
                CallCheck::Continue
            ));
            assert!(matches!(
                rules.admit(
                    &IAccountKeychain::revokeKeyCall {
                        keyId: Address::repeat_byte(0x22),
                    }
                    .abi_encode(),
                    caller,
                ),
                CallCheck::Continue
            ));
        });
    }

    #[test]
    fn t11_defers_noncanonical_address_calldata_to_upstream() {
        let owner = Address::repeat_byte(0x11);
        let outsider = Address::repeat_byte(0x22);
        let rules = AccountKeychainRules;
        let mut data = IAccountKeychain::getKeyCall {
            account: owner,
            keyId: Address::repeat_byte(0x33),
        }
        .abi_encode();
        data[4] = 1;

        assert!(matches!(
            admit_at(&rules, &data, outsider, TempoHardfork::T8),
            CallCheck::Revert(data) if data == Unauthorized {}.abi_encode()
        ));
        assert!(matches!(
            admit_at(&rules, &data, outsider, TempoHardfork::T11),
            CallCheck::Continue
        ));
    }

    #[test]
    fn malformed_unrestricted_calls_remain_deferred_to_upstream() {
        let rules = AccountKeychainRules;

        for data in UNRESTRICTED_SELECTORS {
            for spec in [TempoHardfork::T10, TempoHardfork::T11] {
                assert!(matches!(
                    admit_at(&rules, data, Address::ZERO, spec),
                    CallCheck::Continue
                ));
            }
        }
    }
}
