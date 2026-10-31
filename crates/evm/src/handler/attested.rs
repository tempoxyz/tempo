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
use tempo_primitives::transaction::ATTESTED_MAX_VALIDITY_WINDOW;

/// Rejects the transaction unless every attested signature it carries, as the sender signature
/// or as the key authorization signature, is within its validity window and signed by a program
/// key the registry holds as current.
///
/// Attested signatures are gated on T14 in this PoC.
pub(crate) fn validate(
    host: &mut Evm<'_, TempoEvmTypes>,
    aa: &TempoAaTx,
    spec: TempoHardfork,
) -> HandlerResult<()> {
    let outer = aa.signature().as_attested();
    let grant = aa
        .tx()
        .key_authorization
        .as_ref()
        .and_then(|auth| auth.signature.as_attested());
    for signature in [outer, grant].into_iter().flatten() {
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

fn rejected(reason: &'static str) -> TempoInvalidTransaction {
    TempoInvalidTransaction::AttestedSignatureRejected { reason }
}
