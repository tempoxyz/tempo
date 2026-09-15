use std::str::FromStr;

use alloy_consensus::{BlockHeader as _, Sealable as _};
use alloy_primitives::{FixedBytes, hex};
use commonware_codec::ReadExt as _;
use commonware_consensus::{
    Epochable as _,
    simplex::scheme::bls12381_threshold::vrf::Scheme,
    types::{Epoch, Epocher as _, FixedEpocher, Height},
};
use commonware_cryptography::{
    bls12381::primitives::variant::{MinSig, Variant},
    ed25519::PublicKey,
};
use commonware_parallel::Sequential;
use eyre::{WrapErr as _, ensure};
use rand_core::CryptoRng;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_primitives::TempoHeader;
use tracing::warn;

use crate::alias::marshal::FinalizedTip;

#[derive(Debug, Clone, Copy)]
pub(crate) struct NetworkIdentity(pub <MinSig as Variant>::Public);

#[derive(Debug, thiserror::Error)]
pub(crate) enum ParseNetworkIdentityError {
    #[error("invalid hex string: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("must be a valid BLS public key: {0}")]
    InvalidPublicKey(#[from] commonware_codec::Error),
}

impl FromStr for NetworkIdentity {
    type Err = ParseNetworkIdentityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.parse::<FixedBytes<96>>()?;

        let mut bytes = bytes.as_slice();
        let key = <MinSig as Variant>::Public::read(&mut bytes)?;

        Ok(Self(key))
    }
}

/// Decode an epoch's DKG outcome only from the boundary that activates it.
pub(crate) fn decode_boundary_outcome(
    epoch_strategy: &FixedEpocher,
    header: &TempoHeader,
) -> eyre::Result<OnchainDkgOutcome> {
    let height = Height::new(header.number());
    let epoch_info = epoch_strategy
        .containing(height)
        .expect("strategy valid for all heights");
    let expected_epoch = if height.is_zero() {
        Epoch::zero()
    } else {
        ensure!(
            height == epoch_info.last(),
            "DKG outcome at height `{height}` is not at an epoch boundary"
        );
        epoch_info.epoch().next()
    };
    let outcome = OnchainDkgOutcome::read(&mut header.extra_data().as_ref())
        .wrap_err("boundary block did not contain a DKG outcome")?;
    ensure!(
        outcome.epoch() == expected_epoch,
        "boundary DKG outcome epoch `{}` does not match height-derived epoch `{expected_epoch}` at height `{height}`",
        outcome.epoch,
    );
    Ok(outcome)
}

/// Prefer only an identity persisted after a runtime DKG transition for this exact epoch.
/// A failed check against an observed identity must not fall back to the configured identity.
/// `tip` is `None` only when `header` is the genesis header.
pub(crate) fn verify_finalized_tip(
    rng: &mut impl CryptoRng,
    epoch_strategy: &FixedEpocher,
    network_identity: &tempo_chainspec::NetworkIdentity,
    observed_identity: Option<<MinSig as Variant>::Public>,
    header: &TempoHeader,
    tip: Option<&FinalizedTip>,
) -> eyre::Result<()> {
    let epoch = epoch_strategy
        .containing(Height::new(header.number()))
        .expect("strategy valid for all heights");
    // Check storage consistency even when the configured identity is newer than the tip.
    if let Some(tip) = tip {
        ensure!(
            !tip.height.is_zero() && tip.height.get() == header.number(),
            "finalized tip must match a non-genesis header: tip height `{}`, header height `{}`",
            tip.height,
            header.number(),
        );
        let certificate = &tip.certificate;
        ensure!(
            header.hash_slow() == certificate.proposal.payload.0,
            "finalized tip header and certificate digest mismatch: inconsistent local storage; finalization certificates are only archived with a matching block"
        );
        ensure!(
            certificate.epoch() == epoch.epoch(),
            "finalized tip certificate epoch `{}` does not match height-derived epoch `{}`",
            certificate.epoch(),
            epoch.epoch()
        );
    } else {
        ensure!(
            header.number() == 0,
            "finalized tip missing for non-genesis header at height `{}`",
            header.number(),
        );
    }
    if epoch.epoch().get() == network_identity.from_epoch
        && let Some(identity) = observed_identity
    {
        assert_eq!(
            identity, network_identity.identity,
            "network identity mismatch at configured activation epoch"
        );
    }
    if observed_identity.is_none() && epoch.epoch().get() < network_identity.from_epoch {
        warn!(
            height = header.number(),
            epoch = %epoch.epoch(),
            identity = %network_identity.identity,
            identity_from_epoch = network_identity.from_epoch,
            "cannot verify finalized chain state against the configured network identity; syncing will trust local execution state until the network identity's activation epoch"
        );
        return Ok(());
    }

    let identity = observed_identity.unwrap_or(network_identity.identity);
    let Some(tip) = tip else {
        let outcome = OnchainDkgOutcome::read(&mut header.extra_data().as_ref())
            .wrap_err("genesis did not contain a DKG outcome")?;
        ensure!(
            *outcome.network_identity() == identity,
            "network identity mismatch with genesis: configured {} found {}; update the binary or --consensus.network-identity and --consensus.network-identity-from-epoch",
            network_identity.identity,
            outcome.network_identity(),
        );

        return Ok(());
    };

    let scheme: Scheme<PublicKey, MinSig> =
        Scheme::certificate_verifier(crate::config::NAMESPACE, identity);
    let certificate = &tip.certificate;

    ensure!(
        certificate.verify(rng, &scheme, &Sequential),
        "finalized chain tip at epoch {} failed verification against network identity {} (runtime-observed: {}); update the binary or --consensus.network-identity and --consensus.network-identity-from-epoch",
        certificate.epoch(),
        identity,
        observed_identity.is_some(),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::follow::test_utils::{EPOCH_LENGTH, dkg_fixture, make_block, make_finalization};
    use commonware_consensus::types::Epoch;
    use commonware_runtime::{Runner as _, deterministic};

    #[test]
    fn snapshot_tip_rejects_stale_identity_even_if_old_boundary_matched() {
        deterministic::Runner::default().start(|mut context| async move {
            let old = dkg_fixture(&mut context, Epoch::zero());
            let rotated = dkg_fixture(&mut context, Epoch::new(2));
            let strategy = FixedEpocher::new(EPOCH_LENGTH);
            let block = make_block(21, None);
            let tip = FinalizedTip {
                height: Height::new(block.header().number()),
                certificate: make_finalization(&block, Epoch::new(2), &rotated.schemes),
            };
            let stale = tempo_chainspec::NetworkIdentity {
                identity: *old.outcome.network_identity(),
                from_epoch: 0,
            };
            assert!(
                verify_finalized_tip(
                    &mut context,
                    &strategy,
                    &stale,
                    None,
                    block.header(),
                    Some(&tip),
                )
                .is_err()
            );
            let updated = tempo_chainspec::NetworkIdentity {
                identity: *rotated.outcome.network_identity(),
                from_epoch: 2,
            };
            verify_finalized_tip(
                &mut context,
                &strategy,
                &updated,
                None,
                block.header(),
                Some(&tip),
            )
            .unwrap();
        });
    }

    #[test]
    fn boundary_tip_is_verified_with_outgoing_epoch_identity() {
        deterministic::Runner::default().start(|mut context| async move {
            let old = dkg_fixture(&mut context, Epoch::new(1));
            let rotated = dkg_fixture(&mut context, Epoch::new(2));
            let strategy = FixedEpocher::new(EPOCH_LENGTH);
            let block = make_block(19, Some(&rotated.outcome));
            let tip = FinalizedTip {
                height: Height::new(block.header().number()),
                certificate: make_finalization(&block, Epoch::new(1), &old.schemes),
            };
            let stale = tempo_chainspec::NetworkIdentity {
                identity: *old.outcome.network_identity(),
                from_epoch: 0,
            };
            verify_finalized_tip(
                &mut context,
                &strategy,
                &stale,
                None,
                block.header(),
                Some(&tip),
            )
            .unwrap();
            let updated = tempo_chainspec::NetworkIdentity {
                identity: *rotated.outcome.network_identity(),
                from_epoch: 2,
            };
            verify_finalized_tip(
                &mut context,
                &strategy,
                &updated,
                None,
                block.header(),
                Some(&tip),
            )
            .unwrap();
        });
    }

    #[test]
    fn snapshot_identity_matrix() {
        deterministic::Runner::default().start(|mut context| async move {
            let old = dkg_fixture(&mut context, Epoch::zero());
            let rotated = dkg_fixture(&mut context, Epoch::new(2));
            for fixture in [&old, &rotated] {
                let outcome = &fixture.outcome;
                for (identity, from_epoch) in [
                    (old.outcome.network_identity(), 0),
                    (rotated.outcome.network_identity(), 2),
                ] {
                    let configured = tempo_chainspec::NetworkIdentity {
                        identity: *identity,
                        from_epoch,
                    };
                    let strategy = FixedEpocher::new(EPOCH_LENGTH);
                    let block = if outcome.epoch == 0 {
                        make_block(0, Some(outcome))
                    } else {
                        make_block(outcome.epoch * EPOCH_LENGTH.get() + 1, None)
                    };
                    let tip = (outcome.epoch != 0).then(|| FinalizedTip {
                        height: Height::new(block.header().number()),
                        certificate: make_finalization(&block, outcome.epoch(), &fixture.schemes),
                    });
                    let result = verify_finalized_tip(
                        &mut context,
                        &strategy,
                        &configured,
                        None,
                        block.header(),
                        tip.as_ref(),
                    );
                    let should_pass =
                        outcome.epoch < from_epoch || outcome.network_identity() == identity;
                    assert_eq!(
                        result.is_ok(),
                        should_pass,
                        "epoch {}, configured from {from_epoch}",
                        outcome.epoch
                    );
                }
            }
        });
    }

    #[test]
    fn observed_identity_does_not_fall_back_to_configured_identity() {
        deterministic::Runner::default().start(|mut context| async move {
            let configured = dkg_fixture(&mut context, Epoch::zero());
            let observed = dkg_fixture(&mut context, Epoch::new(2));
            let block = make_block(21, None);
            let tip = FinalizedTip {
                height: Height::new(block.header().number()),
                certificate: make_finalization(&block, Epoch::new(2), &configured.schemes),
            };
            let result = verify_finalized_tip(
                &mut context,
                &FixedEpocher::new(EPOCH_LENGTH),
                &tempo_chainspec::NetworkIdentity {
                    from_epoch: 0,
                    identity: *configured.outcome.network_identity(),
                },
                Some(*observed.outcome.network_identity()),
                block.header(),
                Some(&tip),
            );
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("failed verification")
            );
        });
    }

    #[test]
    fn genesis_requires_an_absent_finalized_tip() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = dkg_fixture(&mut context, Epoch::zero());
            let genesis = make_block(0, Some(&fixture.outcome));
            let configured = tempo_chainspec::NetworkIdentity {
                from_epoch: 0,
                identity: *fixture.outcome.network_identity(),
            };
            let strategy = FixedEpocher::new(EPOCH_LENGTH);
            verify_finalized_tip(
                &mut context,
                &strategy,
                &configured,
                None,
                genesis.header(),
                None,
            )
            .unwrap();

            let tip = FinalizedTip {
                height: Height::zero(),
                certificate: make_finalization(&genesis, Epoch::zero(), &fixture.schemes),
            };
            assert!(
                verify_finalized_tip(
                    &mut context,
                    &strategy,
                    &configured,
                    None,
                    genesis.header(),
                    Some(&tip),
                )
                .unwrap_err()
                .to_string()
                .contains("non-genesis header")
            );
        });
    }

    #[test]
    fn older_snapshot_still_requires_consistent_tip_evidence() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = dkg_fixture(&mut context, Epoch::zero());
            let block = make_block(11, None);
            let configured = tempo_chainspec::NetworkIdentity {
                from_epoch: 2,
                identity: *fixture.outcome.network_identity(),
            };
            let strategy = FixedEpocher::new(EPOCH_LENGTH);
            assert!(
                verify_finalized_tip(
                    &mut context,
                    &strategy,
                    &configured,
                    None,
                    block.header(),
                    None
                )
                .unwrap_err()
                .to_string()
                .contains("tip missing")
            );
            let tip = FinalizedTip {
                height: Height::new(block.header().number()),
                certificate: make_finalization(&block, Epoch::zero(), &fixture.schemes),
            };
            assert!(
                verify_finalized_tip(
                    &mut context,
                    &strategy,
                    &configured,
                    None,
                    block.header(),
                    Some(&tip)
                )
                .unwrap_err()
                .to_string()
                .contains("height-derived epoch")
            );
        });
    }
}
