//! Zone pre-execution rules for the upstream Tempo SignatureVerifier precompile.
//!
//! `SignatureVerifier` remains the source of truth for signature verification. Before forwarding a
//! call to Tempo, `SignatureVerifierRules` applies only zone-specific checks: from T15, keychain
//! views are privacy-gated like the `AccountKeychain` getters they read through.
//!
//! Accepted calldata and callers are forwarded unchanged to Tempo.

use alloy_primitives::Address;
use alloy_sol_types::SolInterface;
use tempo_contracts::precompiles::ISignatureVerifier::ISignatureVerifierCalls;
use tempo_precompiles::dispatch::abi_decoder_config_for_spec;

use crate::{
    execution::{CallCheck, CallRules},
    privacy::check_caller,
    storage::StorageCtx,
};

/// Zone-specific rules applied before forwarding to upstream `SignatureVerifier`.
pub(crate) struct SignatureVerifierRules;

impl CallRules for SignatureVerifierRules {
    /// Apply zone privacy restrictions before upstream execution.
    fn admit(&self, data: &[u8], caller: Address) -> CallCheck {
        let spec = StorageCtx::default().spec();
        // Before T15, every call is forwarded unchanged.
        if !spec.is_t15() {
            return CallCheck::Continue;
        }
        let Ok(call) = ISignatureVerifierCalls::abi_decode_with_config(
            data,
            abi_decoder_config_for_spec(spec),
        ) else {
            // Preserve the upstream error and gas behavior for malformed or unknown calldata.
            return CallCheck::Continue;
        };

        // Intentionally exhaustive: an upstream ABI addition must be classified here.
        match call {
            // Reveal whether a key is active or admin on `account`.
            ISignatureVerifierCalls::verifyKeychain(call) => check_caller(caller, &[call.account]),
            ISignatureVerifierCalls::verifyKeychainAdmin(call) => {
                check_caller(caller, &[call.account])
            }
            // Stateless, or read only the account's public configuration commitment.
            ISignatureVerifierCalls::recover(_)
            | ISignatureVerifierCalls::verify(_)
            | ISignatureVerifierCalls::verifyConfigurableAccount(_) => CallCheck::Continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B256, Bytes};
    use alloy_sol_types::SolCall;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::ISignatureVerifier;
    use test_case::test_case;

    use crate::{
        test_utils::{test_context, test_storage_provider},
        zone_identity::ZoneIdentity,
    };

    /// Whether an outsider may call `verifyKeychain` on an org member; the member and admin always may.
    #[test_case(TempoHardfork::T14 => true)]
    #[test_case(TempoHardfork::T15 => false)]
    fn keychain_views_follow_account_read_rules_from_t15(spec: TempoHardfork) -> bool {
        let [owner, admin, outsider] = [0x11, 0x22, 0x33].map(Address::repeat_byte);
        let data = ISignatureVerifier::verifyKeychainCall {
            account: owner,
            hash: B256::ZERO,
            signature: Bytes::new(),
        }
        .abi_encode();

        let mut ctx = test_context();
        ctx.cfg.spec = spec;
        let mut storage = test_storage_provider(&mut ctx, u64::MAX, false);
        StorageCtx::enter(&mut storage, || {
            let mut identity = ZoneIdentity::new();
            let org = identity.create_org(admin, admin, admin).unwrap();
            identity.add_members(admin, org, &[owner]).unwrap();
            let admits = |caller| {
                matches!(
                    SignatureVerifierRules.admit(&data, caller),
                    CallCheck::Continue
                )
            };
            assert!(admits(owner) && admits(admin));
            admits(outsider)
        })
    }
}
