//! Authenticate the startup tip before recovering DKG state from chain data.

use commonware_consensus::{
    Epochable as _,
    simplex::scheme::bls12381_threshold::vrf::Scheme,
    types::{Epocher as _, FixedEpocher, Height},
};
use commonware_cryptography::ed25519::PublicKey;
use commonware_parallel::Sequential;
use eyre::ensure;
use rand_core::CryptoRng;
use tempo_chainspec::NetworkIdentity;
use tracing::{info, instrument};

use super::state::State;
use crate::{alias::marshal::FinalizedTip, config::NAMESPACE};

#[instrument(skip_all, err)]
pub(super) fn verify_finalized_tip(
    rng: &mut impl CryptoRng,
    epoch_strategy: &FixedEpocher,
    binary: &NetworkIdentity,
    persisted: Option<&State>,
    tip: Option<&FinalizedTip>,
    finalized_floor: Height,
) -> eyre::Result<()> {
    let mut trusted = binary.clone();
    if let Some(state) = persisted {
        let identity = *state.output.public().public();
        if state.epoch.get() == binary.from_epoch {
            assert_eq!(
                identity, binary.identity,
                "persisted DKG network identity differs from the binary in epoch `{}`",
                state.epoch,
            );
        }
        if state.epoch.get() > binary.from_epoch {
            trusted = NetworkIdentity {
                from_epoch: state.epoch.get(),
                identity,
            };
        }
    }

    let Some(tip) = tip else {
        ensure!(
            finalized_floor.is_zero(),
            "only genesis may lack a finalized tip certificate"
        );
        return Ok(());
    };
    ensure!(
        !tip.height().is_zero(),
        "genesis must not have a finalization certificate"
    );
    ensure!(
        tip.height() >= finalized_floor,
        "finalized tip is below the finalized floor"
    );
    let epoch = epoch_strategy
        .containing(tip.height())
        .expect("epoch strategy covers all heights")
        .epoch();
    ensure!(
        tip.certificate().epoch() == epoch,
        "finalized tip certificate epoch `{}` does not match height `{}` in epoch `{epoch}`",
        tip.certificate().epoch(),
        tip.height(),
    );

    if epoch.get() < trusted.from_epoch {
        // A rotation's outgoing boundary certificate can precede the latest
        // persisted DKG identity. Historical bootstrap remains allowed; the
        // binary and persisted identities stay pinned when their epochs start.
        info!(
            tip_height = %tip.height(),
            tip_epoch = %epoch,
            identity_from_epoch = trusted.from_epoch,
            "finalized tip predates the trusted network identity; accepting historical bootstrap",
        );
        return Ok(());
    }

    // Do not use the shared scheme provider here: it may already contain
    // schemes read from the same snapshot whose tip we are authenticating.
    let scheme = Scheme::<PublicKey, _>::certificate_verifier(NAMESPACE, trusted.identity);
    ensure!(
        tip.certificate().verify(rng, &scheme, &Sequential),
        "finalized tip certificate at height `{}` in epoch `{epoch}` failed verification \
         against the trusted network identity from epoch `{}`; configure an updated network \
         identity if a full DKG rotation occurred while the node was offline",
        tip.height(),
        trusted.from_epoch,
    );
    Ok(())
}
