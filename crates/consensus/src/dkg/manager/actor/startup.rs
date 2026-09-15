//! Authenticate the startup tip before recovering DKG state from chain data.

use alloy_consensus::{BlockHeader as _, Sealable as _};
use commonware_consensus::{
    simplex::scheme::bls12381_threshold::vrf::Scheme,
    types::{Epocher as _, FixedEpocher, Height},
};
use commonware_cryptography::ed25519::PublicKey;
use commonware_parallel::Sequential;
use eyre::ensure;
use rand_core::CryptoRng;
use tempo_chainspec::NetworkIdentity;
use tempo_primitives::TempoHeader;
use tracing::{info, instrument};

use super::state::State;
use crate::{config::NAMESPACE, consensus::Digest, gossip::Certificate};

#[instrument(skip_all, err)]
pub(super) fn verify_finalized_tip(
    rng: &mut impl CryptoRng,
    epoch_strategy: &FixedEpocher,
    configured_identity: &NetworkIdentity,
    persisted: Option<&State>,
    tip: Option<(Height, &Certificate, &TempoHeader)>,
    finalized_floor: Height,
) -> eyre::Result<()> {
    let mut trusted = configured_identity.clone();
    if let Some(state) = persisted {
        let identity = *state.output.public().public();
        if state.epoch.get() == configured_identity.from_epoch {
            assert_eq!(
                identity, configured_identity.identity,
                "persisted DKG network identity differs from the configured identity in epoch `{}`",
                state.epoch,
            );
        }
        if state.epoch.get() > configured_identity.from_epoch {
            trusted = NetworkIdentity {
                from_epoch: state.epoch.get(),
                identity,
            };
        }
    }

    let Some((height, certificate, header)) = tip else {
        ensure!(
            finalized_floor.is_zero(),
            "only genesis may lack a finalized tip certificate"
        );
        return Ok(());
    };
    ensure!(
        header.number() == height.get(),
        "finalized tip header number `{}` does not match archive height `{height}`",
        header.number(),
    );
    ensure!(
        Digest(header.hash_slow()) == certificate.proposal.payload,
        "finalized tip header hash does not match certificate payload at height `{height}`",
    );
    ensure!(
        !height.is_zero(),
        "genesis must not have a finalization certificate"
    );
    ensure!(
        height >= finalized_floor,
        "finalized tip is below the finalized floor"
    );
    let epoch = epoch_strategy
        .containing(height)
        .expect("epoch strategy covers all heights")
        .epoch();

    if epoch.get() < trusted.from_epoch {
        // A rotation's outgoing boundary certificate can precede the latest
        // persisted DKG identity. Historical bootstrap remains allowed; the
        // configured and persisted identities stay pinned when their epochs start.
        info!(
            tip_height = %height,
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
        certificate.verify(rng, &scheme, &Sequential),
        "finalized tip certificate at height `{}` in epoch `{epoch}` failed verification \
         against the trusted network identity from epoch `{}`; configure an updated network \
         identity if a full DKG rotation occurred while the node was offline",
        height,
        trusted.from_epoch,
    );
    Ok(())
}
