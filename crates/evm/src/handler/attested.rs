//! Attested signature (type `0x06`) checks that need block state (attested signers PoC).
//!
//! [`validate`] checks the validity window and reads the Attested Key Registry, at the
//! transaction's position in the block, before any attested P256 signature is verified in the
//! handler. Block import recovers senders, verifying a `0x06` sender signature first, which the
//! TIP allows outside pool admission. Pool admission instead derives a `0x06` sender without a
//! curve operation, runs [`validate_window`] before building the transaction environment, and
//! verifies the sender's P256 signature after the handler.

use super::TempoEvmTypes;
use crate::{TempoAaTx, TempoInvalidTransaction};
use evm2::{Evm, registry::HandlerResult};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{attested_key_registry::AttestedKeyRegistry, storage::StorageCtx};
use tempo_primitives::{
    AASigned,
    transaction::{
        ATTESTED_MAX_VALIDITY_WINDOW, AccountSignature, AttestedSignature,
        ConfigurableAccountSignature, OwnerApproval, TempoSignature,
    },
};

/// Rejects the transaction unless every attested signature it carries passes
/// [`validate_window`] at the block's timestamp and is signed by a program key that the registry
/// slot it names holds as current.
pub(crate) fn validate(
    host: &mut Evm<'_, TempoEvmTypes>,
    aa: &TempoAaTx,
    spec: TempoHardfork,
) -> HandlerResult<()> {
    let now = host.block().timestamp.saturating_to::<u64>();
    validate_window(aa.inner(), now, spec)?;
    for signature in signatures(aa.inner()) {
        let current = StorageCtx::enter_evm_without_tip1060_accounting(host, || {
            AttestedKeyRegistry::new().program_key_current(
                signature.policy_id,
                signature.slot,
                signature.program_key_x(),
                signature.program_key_y(),
            )
        })?;
        if !current {
            return Err(rejected("program key is not current").into());
        }
    }
    Ok(())
}

/// Stateless checks of every attested signature `signed` carries, as the sender signature, the
/// key authorization signature, or an owner approval of a configurable account signature in
/// either role: activation (T14 in this PoC) and `now <= valid_until <= now + 600`.
///
/// Also rejects attested owner approvals inside a keychain signature, which decoding already
/// rejects, so that a keychain signature built in memory cannot relay one either.
pub fn validate_window(
    signed: &AASigned,
    now: u64,
    spec: TempoHardfork,
) -> Result<(), TempoInvalidTransaction> {
    if signed
        .signature()
        .as_keychain()
        .and_then(|keychain| keychain.signature.as_configurable_account())
        .is_some_and(|signature| attested_approvals(signature).next().is_some())
    {
        return Err(rejected("attested approval inside a keychain signature"));
    }
    for signature in signatures(signed) {
        if !spec.is_t14() {
            return Err(rejected("not active"));
        }
        if signature.valid_until < now {
            return Err(rejected("expired"));
        }
        if signature.valid_until - now > ATTESTED_MAX_VALIDITY_WINDOW {
            return Err(rejected("valid_until too far in the future"));
        }
    }
    Ok(())
}

/// Returns the attested signatures `signed` carries outside keychain signatures.
fn signatures(signed: &AASigned) -> impl Iterator<Item = &AttestedSignature> {
    let outer = match signed.signature() {
        TempoSignature::Primitive(_) | TempoSignature::Keychain(_) => None,
        TempoSignature::Attested(signature) => Some(AccountSignatureRef::Attested(signature)),
        TempoSignature::ConfigurableAccount(signature) => {
            Some(AccountSignatureRef::Configurable(signature))
        }
    };
    let grant = signed
        .tx()
        .key_authorization
        .as_ref()
        .and_then(|auth| match &auth.signature {
            AccountSignature::Primitive(_) => None,
            AccountSignature::Attested(signature) => Some(AccountSignatureRef::Attested(signature)),
            AccountSignature::ConfigurableAccount(signature) => {
                Some(AccountSignatureRef::Configurable(signature))
            }
        });
    [outer, grant]
        .into_iter()
        .flatten()
        .flat_map(|role| match role {
            AccountSignatureRef::Attested(signature) => vec![signature],
            AccountSignatureRef::Configurable(signature) => attested_approvals(signature).collect(),
        })
}

/// A role's signature that may carry attested signatures.
enum AccountSignatureRef<'a> {
    Attested(&'a AttestedSignature),
    Configurable(&'a ConfigurableAccountSignature),
}

fn attested_approvals(
    signature: &ConfigurableAccountSignature,
) -> impl Iterator<Item = &AttestedSignature> {
    signature
        .signatures()
        .iter()
        .filter_map(OwnerApproval::as_attested)
}

fn rejected(reason: &'static str) -> TempoInvalidTransaction {
    TempoInvalidTransaction::AttestedSignatureRejected { reason }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256, B512};
    use tempo_primitives::transaction::{
        ConfigurableAccountConfig, ConfigurableAccountOwner, KeychainSignature, TempoTransaction,
    };

    const NOW: u64 = 1_800_000_000;

    /// An attested signature whose P256 signature is never verified here.
    fn attested(valid_until: u64) -> AttestedSignature {
        AttestedSignature {
            policy_id: B256::repeat_byte(0xAA),
            user_tag: B256::repeat_byte(0xBB),
            slot: 0,
            program_key: B512::repeat_byte(0x03),
            valid_until,
            signature: B512::repeat_byte(0x01),
        }
    }

    fn configurable(valid_until: u64) -> ConfigurableAccountSignature {
        let approval = attested(valid_until);
        let config = ConfigurableAccountConfig {
            salt: B256::ZERO,
            version: 0,
            threshold: 1,
            owners: vec![ConfigurableAccountOwner {
                owner: approval.address(),
                weight: 1,
            }],
        };
        let account = config.derive_account().unwrap();
        ConfigurableAccountSignature::try_new(account, config, [approval]).unwrap()
    }

    fn check(
        signature: TempoSignature,
        spec: TempoHardfork,
    ) -> Result<(), TempoInvalidTransaction> {
        validate_window(
            &TempoTransaction::default().into_signed(signature),
            NOW,
            spec,
        )
    }

    fn rejection(reason: &'static str) -> Result<(), TempoInvalidTransaction> {
        Err(rejected(reason))
    }

    #[test]
    fn window_bounds_and_activation() {
        for signature in [
            TempoSignature::Attested(attested(NOW)),
            TempoSignature::ConfigurableAccount(configurable(NOW + ATTESTED_MAX_VALIDITY_WINDOW)),
        ] {
            assert_eq!(check(signature.clone(), TempoHardfork::T14), Ok(()));
            assert_eq!(
                check(signature, TempoHardfork::T13),
                rejection("not active")
            );
        }
        assert_eq!(
            check(
                TempoSignature::Attested(attested(NOW - 1)),
                TempoHardfork::T14
            ),
            rejection("expired")
        );
        assert_eq!(
            check(
                TempoSignature::ConfigurableAccount(configurable(
                    NOW + ATTESTED_MAX_VALIDITY_WINDOW + 1
                )),
                TempoHardfork::T14
            ),
            rejection("valid_until too far in the future")
        );
    }

    #[test]
    fn keychain_cannot_relay_attested_approvals() {
        let relay = KeychainSignature::new(Address::repeat_byte(0x11), configurable(NOW));
        assert_eq!(
            check(TempoSignature::Keychain(relay), TempoHardfork::T14),
            rejection("attested approval inside a keychain signature")
        );
    }
}
