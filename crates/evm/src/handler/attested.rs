//! Attested signature (type `0x06`) checks that need block state (attested signers PoC).
//!
//! Sender recovery and key authorization recovery verify the program key's P256 signature. This
//! module adds the validity window and the Attested Key Registry read, at the transaction's
//! position in the block. The pool runs the same handler, so one check covers both.

use super::TempoEvmTypes;
use crate::{TempoAaTx, TempoInvalidTransaction};
use evm2::{Evm, registry::HandlerResult};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{attested_key_registry::AttestedKeyRegistry, storage::StorageCtx};
use tempo_primitives::transaction::{
    ATTESTED_MAX_VALIDITY_WINDOW, AccountSignature, AttestedSignature,
    ConfigurableAccountSignature, OwnerApproval, TempoSignature,
};

/// Rejects the transaction unless every attested signature it carries, as the sender signature,
/// the key authorization signature, or an owner approval of a configurable account signature in
/// either role, is within its validity window and signed by a program key the registry holds as
/// current.
///
/// Attested signatures are gated on T14 in this PoC.
pub(crate) fn validate(
    host: &mut Evm<'_, TempoEvmTypes>,
    aa: &TempoAaTx,
    spec: TempoHardfork,
) -> HandlerResult<()> {
    let outer = match aa.signature() {
        TempoSignature::Primitive(_) => None,
        TempoSignature::Attested(signature) => Some(AccountSignatureRef::Attested(signature)),
        TempoSignature::ConfigurableAccount(signature) => {
            Some(AccountSignatureRef::Configurable(signature))
        }
        TempoSignature::Keychain(keychain) => keychain
            .signature
            .as_configurable_account()
            .map(AccountSignatureRef::Configurable),
    };
    let grant = aa
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
    let signatures = [outer, grant]
        .into_iter()
        .flatten()
        .flat_map(|role| match role {
            AccountSignatureRef::Attested(signature) => vec![signature],
            AccountSignatureRef::Configurable(signature) => signature
                .signatures()
                .iter()
                .filter_map(OwnerApproval::as_attested)
                .collect(),
        });
    for signature in signatures {
        if !spec.is_t14() {
            return Err(rejected("not active").into());
        }
        let now = host.block().timestamp.saturating_to::<u64>();
        if signature.valid_until < now {
            return Err(rejected("expired").into());
        }
        if signature.valid_until - now > ATTESTED_MAX_VALIDITY_WINDOW {
            return Err(rejected("valid_until too far in the future").into());
        }
        let current = StorageCtx::enter_evm_without_tip1060_accounting(host, || {
            AttestedKeyRegistry::new().program_key_current(
                signature.policy_id,
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

/// A role's signature that may carry attested signatures.
enum AccountSignatureRef<'a> {
    Attested(&'a AttestedSignature),
    Configurable(&'a ConfigurableAccountSignature),
}

fn rejected(reason: &'static str) -> TempoInvalidTransaction {
    TempoInvalidTransaction::AttestedSignatureRejected { reason }
}
