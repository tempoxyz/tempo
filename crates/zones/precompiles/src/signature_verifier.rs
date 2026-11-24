//! Zone read-privacy rules for the upstream Tempo SignatureVerifier precompile (TIP-1154).

use alloy_primitives::Address;
use alloy_sol_types::SolInterface;
use tempo_contracts::precompiles::ISignatureVerifier::ISignatureVerifierCalls;
use tempo_precompiles::dispatch::abi_decoder_config_for_spec;

use crate::{
    execution::{CallCheck, CallRules},
    privacy::check_caller,
    storage::StorageCtx,
};

/// From T15, `verifyKeychain` and `verifyKeychainAdmin` follow the `AccountKeychain` getters'
/// read rule, since both reveal whether a key is active or admin on the account in calldata: the
/// account itself, or a caller `ZoneIdentity.canRead` allows for it.
pub(crate) struct SignatureVerifierRules;

impl CallRules for SignatureVerifierRules {
    fn admit(&self, data: &[u8], caller: Address) -> CallCheck {
        let spec = StorageCtx::default().spec();
        // T14 zone blocks execute as they did when SignatureVerifier was added.
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
            ISignatureVerifierCalls::verifyKeychain(call) => check_caller(caller, &[call.account]),
            ISignatureVerifierCalls::verifyKeychainAdmin(call) => {
                check_caller(caller, &[call.account])
            }
            // Stateless, or reads only the account's configuration commitment from Tempo.
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
    use alloy_sol_types::{SolCall, SolError};
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::{precompiles::ISignatureVerifier, zones::Unauthorized};

    use crate::{
        test_utils::{test_context, test_storage_provider},
        zone_identity::ZoneIdentity,
    };

    const OWNER: Address = Address::repeat_byte(0x11);
    const OUTSIDER: Address = Address::repeat_byte(0x33);
    const REGISTRAR: Address = Address::repeat_byte(0x44);
    const ORG_ADMIN: Address = Address::repeat_byte(0x55);
    const ORG_READER: Address = Address::repeat_byte(0x66);

    fn keychain_views(account: Address) -> [Vec<u8>; 2] {
        let hash = B256::repeat_byte(0x77);
        let signature = Bytes::from_static(&[0x04]);
        [
            ISignatureVerifier::verifyKeychainCall {
                account,
                hash,
                signature: signature.clone(),
            }
            .abi_encode(),
            ISignatureVerifier::verifyKeychainAdminCall {
                account,
                hash,
                signature,
            }
            .abi_encode(),
        ]
    }

    /// Runs `f` at `spec` with `OWNER` in an org administered by `ORG_ADMIN` and read by
    /// `ORG_READER`.
    fn with_org<R>(spec: TempoHardfork, f: impl FnOnce() -> R) -> R {
        let mut ctx = test_context();
        ctx.cfg.spec = spec;
        let mut storage = test_storage_provider(&mut ctx, u64::MAX, false);
        StorageCtx::enter(&mut storage, || {
            let mut identity = ZoneIdentity::new();
            let org = identity
                .create_org(REGISTRAR, REGISTRAR, ORG_ADMIN)
                .unwrap();
            identity.add_members(ORG_ADMIN, org, &[OWNER]).unwrap();
            identity
                .set_reader(ORG_ADMIN, org, ORG_READER, true)
                .unwrap();
            f()
        })
    }

    fn is_unauthorized(check: &CallCheck) -> bool {
        matches!(check, CallCheck::Revert(data) if *data == Unauthorized {}.abi_encode())
    }

    #[test]
    fn t15_keychain_views_follow_identity_read_rules() {
        with_org(TempoHardfork::T15, || {
            for data in keychain_views(OWNER) {
                for reader in [OWNER, ORG_ADMIN, ORG_READER] {
                    assert!(matches!(
                        SignatureVerifierRules.admit(&data, reader),
                        CallCheck::Continue
                    ));
                }
                assert!(is_unauthorized(
                    &SignatureVerifierRules.admit(&data, OUTSIDER)
                ));
            }
            // An account in no org is readable only by itself.
            for data in keychain_views(OUTSIDER) {
                assert!(is_unauthorized(
                    &SignatureVerifierRules.admit(&data, ORG_ADMIN)
                ));
            }
        });
    }

    #[test]
    fn t14_keychain_views_are_unchanged() {
        with_org(TempoHardfork::T14, || {
            for data in keychain_views(OWNER) {
                assert!(matches!(
                    SignatureVerifierRules.admit(&data, OUTSIDER),
                    CallCheck::Continue
                ));
            }
        });
    }

    #[test]
    fn stateless_and_commitment_views_remain_open() {
        let hash = B256::repeat_byte(0x77);
        let signature = Bytes::from_static(&[0x01]);
        with_org(TempoHardfork::T15, || {
            for data in [
                ISignatureVerifier::recoverCall {
                    hash,
                    signature: signature.clone(),
                }
                .abi_encode(),
                ISignatureVerifier::verifyCall {
                    signer: OWNER,
                    hash,
                    signature: signature.clone(),
                }
                .abi_encode(),
                ISignatureVerifier::verifyConfigurableAccountCall {
                    account: OWNER,
                    hash,
                    signature: signature.clone(),
                }
                .abi_encode(),
                vec![0xde, 0xad],
            ] {
                assert!(matches!(
                    SignatureVerifierRules.admit(&data, OUTSIDER),
                    CallCheck::Continue
                ));
            }
        });
    }
}
