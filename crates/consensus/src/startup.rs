//! Authenticate the startup tip and register its trusted identity before actors start.

use commonware_consensus::{
    simplex::scheme::bls12381_threshold::vrf::Scheme,
    types::{Epoch, Height},
};
use commonware_cryptography::ed25519::PublicKey;
use commonware_parallel::Sequential;
use eyre::ensure;
use rand_core::CryptoRng;
use tempo_chainspec::NetworkIdentity;
use tracing::{info, instrument};

use crate::{config::NAMESPACE, epoch::SchemeProvider, gossip::Certificate};

/// Select the newest configured or persisted identity, authenticate the tip, and register its schemes.
/// Returns the selected identity. Historical tips are accepted with the future identity pinned.
#[instrument(skip_all, err)]
pub(crate) fn verify_finalized_tip(
    rng: &mut impl CryptoRng,
    configured_identity: &NetworkIdentity,
    persisted: Option<&NetworkIdentity>,
    tip: Option<(Height, &Certificate)>,
    finalized_floor: Height,
    scheme_provider: &SchemeProvider,
) -> eyre::Result<NetworkIdentity> {
    let mut trusted = configured_identity.clone();
    if let Some(persisted) = persisted {
        if persisted.from_epoch == configured_identity.from_epoch {
            ensure!(
                persisted.identity == configured_identity.identity,
                "persisted DKG network identity differs from the configured identity in epoch `{}`",
                persisted.from_epoch,
            );
        }
        if persisted.from_epoch > configured_identity.from_epoch {
            trusted = persisted.clone();
        }
    }

    let scheme = Scheme::<PublicKey, _>::certificate_verifier(NAMESPACE, trusted.identity);
    if let Some((height, certificate)) = tip {
        ensure!(!height.is_zero(), "genesis must not have a certificate");
        ensure!(height >= finalized_floor, "tip is below the floor");

        let cert_epoch = certificate.proposal.round.epoch();
        if cert_epoch.get() < trusted.from_epoch {
            // A rotation's outgoing boundary certificate can precede the latest
            // persisted DKG identity. This means historical certs are trusted
            // by default, but all future certs must are verified against the
            // trusted identity by marshal.
            info!(
                tip_height = %height,
                tip_epoch = %cert_epoch,
                identity_from_epoch = trusted.from_epoch,
                "finalized tip predates the trusted network identity; accepting historical bootstrap",
            );
        } else {
            // Any available certs must match against the newest identity we
            // have available. Otherwise we cannot trust them.
            ensure!(
                certificate.verify(rng, &scheme, &Sequential),
                "finalized tip certificate at height `{}` in epoch `{cert_epoch}` failed verification \
                 against the trusted network identity from epoch `{}`; configure an updated network \
                 identity if a full DKG rotation occurred while the node was offline",
                height,
                trusted.from_epoch,
            );
            // IMPORTANT: we register trusted identity A for the tip cert's
            // epoch. Assume the tip is for epoch 20 but we start with a
            // manipulated finalized block registry that contains a malicious
            // identity B in outcome(epoch=19). Then pre-registering A prevents
            // installation of B (since `scheme_provider.register` rejects
            // differing identities).
            scheme_provider.register(cert_epoch, scheme.clone());
        }
    } else {
        ensure!(
            finalized_floor.is_zero(),
            "only genesis may lack a finalized tip certificate"
        );
    }
    // Pin the trusted identity even when the tip predates it or startup is at genesis.
    scheme_provider.register(Epoch::new(trusted.from_epoch), scheme);
    Ok(trusted)
}
