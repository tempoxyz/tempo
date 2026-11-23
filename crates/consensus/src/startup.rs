//! Authenticate the startup tip and register its trusted identity before actors start.

use std::cmp::Ordering;

use alloy_consensus::Sealable as _;
use alloy_primitives::B256;
use commonware_consensus::{
    simplex::scheme::bls12381_threshold::vrf::Scheme,
    types::{Epoch, Height},
};
use commonware_cryptography::ed25519::PublicKey;
use commonware_parallel::Sequential;
use eyre::{bail, ensure};
use rand_core::CryptoRng;
use tempo_chainspec::NetworkIdentity;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_primitives::TempoHeader;
use tracing::{info, instrument, warn};

use crate::{config::NAMESPACE, consensus::Digest, epoch::SchemeProvider, gossip::Certificate};

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
            if persisted.identity != configured_identity.identity {
                warn!(
                    configured_from_epoch = configured_identity.from_epoch,
                    configured_network_identity = %configured_identity.identity,
                    persisted_from_epoch = persisted.from_epoch,
                    persisted_network_identity = %persisted.identity,
                    "Persisted network identity differs from the configured network identity!!! Using the persisted identity; update the binary with the latest network identity"
                );
            }
            trusted = persisted.clone();
        }
    }

    let scheme = Scheme::<PublicKey, _>::certificate_verifier(NAMESPACE, trusted.identity);
    if let Some((height, certificate)) = tip {
        ensure!(!height.is_zero(), "genesis must not have a certificate");

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

/// Ensures a startup DKG outcome is at most one epoch past the finalized tip's epoch.
///
/// [`verify_finalized_tip`] accepts a tip older than the trusted identity without
/// verifying it. Bounding the startup outcome by that tip forces the node to cross every
/// boundary up to the identity's epoch, where the pinned identity is checked.
pub(crate) fn ensure_outcome_within_tip_epoch(
    outcome_epoch: Epoch,
    tip: Option<&Certificate>,
) -> eyre::Result<()> {
    if let Some(tip) = tip {
        let tip_epoch = tip.proposal.round.epoch();
        ensure!(
            outcome_epoch <= tip_epoch.next(),
            "startup DKG outcome is for epoch `{outcome_epoch}`, past the epoch after the \
             finalized tip's epoch `{tip_epoch}`",
        );
    }
    Ok(())
}

/// A finalized floor certificate verified against an identity the node trusts.
pub(crate) struct VerifiedFloor {
    /// Height of the certified block.
    pub(crate) height: Height,
    /// Digest of the certified block.
    pub(crate) digest: Digest,
    /// Epoch the certificate was signed in.
    pub(crate) epoch: Epoch,
    /// Identity the certificate verified against.
    pub(crate) identity: NetworkIdentity,
}

/// Verifies the finalized floor certificate against the configured or persisted identity.
///
/// Either identity is trusted, so the certificate passes if it verifies against one of them. The
/// persisted identity's `from_epoch` is the node's latest epoch rather than when the identity
/// took effect, so it does not bound which certificates it may verify. Fails when neither
/// verifies, such as for a snapshot taken before the last full DKG the binary knows about.
#[instrument(skip_all, err)]
pub(crate) fn verify_floor_certificate(
    rng: &mut impl CryptoRng,
    configured_identity: &NetworkIdentity,
    persisted: Option<&NetworkIdentity>,
    height: Height,
    certificate: &Certificate,
) -> eyre::Result<VerifiedFloor> {
    let epoch = certificate.proposal.round.epoch();
    let identity = std::iter::once(configured_identity)
        .chain(persisted)
        .find(|identity| {
            let scheme = Scheme::<PublicKey, _>::certificate_verifier(NAMESPACE, identity.identity);
            certificate.verify(&mut *rng, &scheme, &Sequential)
        });
    let Some(identity) = identity else {
        ensure!(
            persisted.is_some() || epoch.get() >= configured_identity.from_epoch,
            "finalized floor certificate at height `{height}` in epoch `{epoch}` predates the \
             trusted network identity from epoch `{}`; restore a snapshot taken at or after that \
             epoch",
            configured_identity.from_epoch,
        );
        bail!(
            "finalized floor certificate at height `{height}` in epoch `{epoch}` failed \
             verification against every trusted network identity"
        );
    };
    Ok(VerifiedFloor {
        height,
        digest: certificate.proposal.payload,
        epoch,
        identity: identity.clone(),
    })
}

/// Ensures the boundary header startup reads its DKG outcome from agrees with the verified floor.
///
/// A boundary at genesis must be the chain spec's genesis. A boundary at the floor is the
/// certified block itself. Below it, the outcome is for the floor's epoch and must carry the
/// identity its certificate verified against. The floor must not be below the boundary.
pub(crate) fn ensure_boundary_matches_floor(
    boundary: Height,
    header: &TempoHeader,
    outcome: &OnchainDkgOutcome,
    floor: Option<&VerifiedFloor>,
    genesis_hash: B256,
) -> eyre::Result<()> {
    if boundary.is_zero() {
        ensure!(
            header.hash_slow() == genesis_hash,
            "genesis header does not match the chain spec's genesis hash `{genesis_hash}`",
        );
    }
    // Marshal lacks a floor certificate only at genesis (see `alias::marshal::init`), where
    // `verify_finalized_tip` already requires a zero floor.
    let Some(floor) = floor else {
        return Ok(());
    };
    match boundary.cmp(&floor.height) {
        Ordering::Equal => ensure!(
            Digest(header.hash_slow()) == floor.digest,
            "boundary header at height `{boundary}` does not match the finalized floor certificate",
        ),
        Ordering::Less => {
            ensure!(
                outcome.epoch() == floor.epoch,
                "boundary outcome at height `{boundary}` is for epoch `{}`, but the finalized floor \
                 certificate is in epoch `{}`",
                outcome.epoch(),
                floor.epoch,
            );
            ensure!(
                *outcome.network_identity() == floor.identity.identity,
                "boundary outcome at height `{boundary}` carries a network identity other than \
                 the one the finalized floor certificate in epoch `{}` verified against",
                floor.epoch,
            );
        }
        Ordering::Greater => bail!(
            "boundary at height `{boundary}` is above the finalized floor certificate at height \
             `{}`",
            floor.height,
        ),
    }
    Ok(())
}
