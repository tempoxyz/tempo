use alloy_consensus::Header;
use commonware_consensus::types::{Epoch, FixedEpocher};
use commonware_cryptography::certificate::Provider as _;
use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, deterministic};
use reth_node_core::primitives::SealedBlock;
use tempo_chainspec::NetworkIdentity;
use tempo_primitives::{Block as TempoBlock, BlockBody, TempoHeader};

use super::{Error, FinalizationVerifier};
use crate::follow::test_utils::{
    EPOCH_LENGTH, dkg_fixture, make_block, make_certified_block, make_finalization,
};

#[test_traced]
fn tracks_boundary_identity() {
    deterministic::Runner::default().start(|mut context| async move {
        let current = dkg_fixture(&mut context, Epoch::zero());
        let next = dkg_fixture(&mut context, Epoch::new(1));
        let verifier = FinalizationVerifier::new(
            NetworkIdentity {
                from_epoch: 0,
                identity: *current.outcome.network_identity(),
            },
            FixedEpocher::new(EPOCH_LENGTH),
        );

        let boundary = make_block(EPOCH_LENGTH.get() - 1, Some(&next.outcome));
        let finalization = make_finalization(&boundary, Epoch::zero(), &current.schemes);
        let certified = make_certified_block(boundary.clone(), &finalization);
        verifier
            .decode_and_verify(&mut context, &certified)
            .expect("current identity should verify the boundary");

        verifier
            .decode_dkg_outcome_and_register_boundary(boundary.header())
            .expect("boundary should install the next identity");

        let block = make_block(EPOCH_LENGTH.get(), None);
        let finalization = make_finalization(&block, Epoch::new(1), &next.schemes);
        let certified = make_certified_block(block, &finalization);
        verifier
            .decode_and_verify(&mut context, &certified)
            .expect("installed identity should verify the next epoch");
    });
}

#[test_traced]
fn rejects_boundary_epoch_that_skips_activation_without_registering_scheme() {
    deterministic::Runner::default().start(|mut context| async move {
        let configured = dkg_fixture(&mut context, Epoch::new(1));
        let forged = dkg_fixture(&mut context, Epoch::new(2));
        let verifier = FinalizationVerifier::new(
            NetworkIdentity {
                from_epoch: 1,
                identity: *configured.outcome.network_identity(),
            },
            FixedEpocher::new(EPOCH_LENGTH),
        );

        // The epoch-zero boundary must activate epoch one, even if its payload claims
        // an epoch after the configured checkpoint.
        let boundary = make_block(EPOCH_LENGTH.get() - 1, Some(&forged.outcome));
        let error = verifier
            .decode_dkg_outcome_and_register_boundary(boundary.header())
            .unwrap_err();
        assert!(error.to_string().contains("height-derived epoch `1`"));
        assert!(verifier.scheme_provider.scheme(Epoch::new(1)).is_none());
        assert!(verifier.scheme_provider.scheme(Epoch::new(2)).is_none());

        let block = make_block(2 * EPOCH_LENGTH.get(), None);
        let forged_certificate = make_finalization(&block, Epoch::new(2), &forged.schemes);
        assert!(
            verifier
                .verify_certificate(&mut context, &forged_certificate)
                .is_err()
        );
        let configured_certificate = make_finalization(&block, Epoch::new(2), &configured.schemes);
        verifier
            .verify_certificate(&mut context, &configured_certificate)
            .expect("rejected outcome must leave the configured fallback usable");
    });
}

#[test_traced]
fn boundary_outcomes_require_genesis_or_the_previous_epoch_boundary() {
    deterministic::Runner::default().start(|mut context| async move {
        let genesis = dkg_fixture(&mut context, Epoch::zero());
        let next = dkg_fixture(&mut context, Epoch::new(1));
        let verifier = FinalizationVerifier::new(
            NetworkIdentity {
                from_epoch: 0,
                identity: *genesis.outcome.network_identity(),
            },
            FixedEpocher::new(EPOCH_LENGTH),
        );

        let block = make_block(0, Some(&next.outcome));
        assert!(
            verifier
                .decode_dkg_outcome_and_register_boundary(block.header())
                .unwrap_err()
                .to_string()
                .contains("height-derived epoch `0`")
        );
        let block = make_block(EPOCH_LENGTH.get(), Some(&next.outcome));
        assert!(
            verifier
                .decode_dkg_outcome_and_register_boundary(block.header())
                .unwrap_err()
                .to_string()
                .contains("not at an epoch boundary")
        );
        assert!(verifier.scheme_provider.scheme(Epoch::new(1)).is_none());

        let block = make_block(0, Some(&genesis.outcome));
        verifier
            .decode_dkg_outcome_and_register_boundary(block.header())
            .expect("genesis activates epoch zero");
        assert_eq!(
            verifier
                .scheme_provider
                .scheme(Epoch::zero())
                .unwrap()
                .identity(),
            genesis.outcome.network_identity(),
        );
    });
}

#[test_traced]
fn rejects_epoch_mismatching_block_height() {
    deterministic::Runner::default().start(|mut context| async move {
        let fixture = dkg_fixture(&mut context, Epoch::zero());
        let verifier = FinalizationVerifier::new(
            NetworkIdentity {
                from_epoch: 0,
                identity: *fixture.outcome.network_identity(),
            },
            FixedEpocher::new(EPOCH_LENGTH),
        );

        let block = make_block(EPOCH_LENGTH.get(), None);
        let finalization = make_finalization(&block, Epoch::zero(), &fixture.schemes);
        let certified = make_certified_block(block, &finalization);
        assert!(matches!(
            verifier.decode_and_verify(&mut context, &certified),
            Err(Error::EpochMismatch {
                height,
                expected: 1,
                actual: 0,
            }) if height == EPOCH_LENGTH.get()
        ));
    });
}

#[test_traced]
fn rejects_block_body_that_does_not_match_header() {
    deterministic::Runner::default().start(|mut context| async move {
        let fixture = dkg_fixture(&mut context, Epoch::zero());
        let verifier = FinalizationVerifier::new(
            NetworkIdentity {
                from_epoch: 0,
                identity: *fixture.outcome.network_identity(),
            },
            FixedEpocher::new(EPOCH_LENGTH),
        );

        let block = make_block(1, None);
        let finalization = make_finalization(&block, Epoch::zero(), &fixture.schemes);
        let mut certified = make_certified_block(block, &finalization);
        let hash = certified.block.hash();
        certified.block = SealedBlock::new_unchecked(
            TempoBlock {
                header: TempoHeader {
                    inner: Header {
                        number: 1,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                body: BlockBody {
                    withdrawals: Some(Default::default()),
                    ..Default::default()
                },
            },
            hash,
        )
        .into();

        assert!(matches!(
            verifier.decode_and_verify(&mut context, &certified),
            Err(Error::BlockBodyMismatch(_))
        ));
    });
}

#[test_traced]
fn panics_on_activation_identity_mismatch_without_registering_scheme() {
    deterministic::Runner::default().start(|mut context| async move {
        let configured = dkg_fixture(&mut context, Epoch::new(1));
        let other = dkg_fixture(&mut context, Epoch::new(1));
        let verifier = FinalizationVerifier::new(
            NetworkIdentity {
                from_epoch: 1,
                identity: *configured.outcome.network_identity(),
            },
            FixedEpocher::new(EPOCH_LENGTH),
        );
        let boundary = make_block(EPOCH_LENGTH.get() - 1, Some(&other.outcome));
        let result = std::panic::catch_unwind(|| {
            verifier.decode_dkg_outcome_and_register_boundary(boundary.header())
        });
        assert!(
            result
                .unwrap_err()
                .downcast_ref::<String>()
                .expect("identity assertion should panic with a diagnostic")
                .contains("network identity mismatch")
        );
        assert!(verifier.scheme_provider.scheme(Epoch::new(1)).is_none());

        let boundary = make_block(EPOCH_LENGTH.get() - 1, Some(&configured.outcome));
        verifier
            .decode_dkg_outcome_and_register_boundary(boundary.header())
            .expect("matching identity should register");
        assert!(verifier.scheme_provider.scheme(Epoch::new(1)).is_some());

        // A rejected outcome must also leave an existing valid scheme intact.
        let boundary = make_block(EPOCH_LENGTH.get() - 1, Some(&other.outcome));
        assert!(
            std::panic::catch_unwind(|| {
                verifier.decode_dkg_outcome_and_register_boundary(boundary.header())
            })
            .is_err()
        );
        let block = make_block(EPOCH_LENGTH.get(), None);
        let finalization = make_finalization(&block, Epoch::new(1), &configured.schemes);
        verifier
            .decode_and_verify(&mut context, &make_certified_block(block, &finalization))
            .expect("rejected identity must not replace the valid scheme");
    });
}
