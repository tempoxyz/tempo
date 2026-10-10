use alloy_consensus::{BlockHeader as _, Header};
use commonware_consensus::types::{Epoch, FixedEpocher};
use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, deterministic};
use reth_node_core::primitives::SealedBlock;
use tempo_chainspec::NetworkIdentity;
use tempo_primitives::{Block as TempoBlock, BlockBody, TempoHeader};

use super::{Error, FinalizationVerifier};
use crate::follow::test_utils::{
    DkgFixture, EPOCH_LENGTH, dkg_fixture, make_block, make_certified_block, make_finalization,
};

#[test_traced]
fn tracks_and_authenticates_boundary_identity() {
    deterministic::Runner::default().start(|mut context| async move {
        let certified = |height, outcome, epoch, fixture: &DkgFixture| {
            let block = make_block(height, outcome);
            let certificate = make_finalization(&block, Epoch::new(epoch), &fixture.schemes);
            make_certified_block(block, &certificate)
        };
        let current = dkg_fixture(&mut context, Epoch::zero());
        let next = dkg_fixture(&mut context, Epoch::new(1));
        let verifier = |fixture: &DkgFixture| {
            FinalizationVerifier::new(
                NetworkIdentity {
                    from_epoch: 0,
                    identity: *fixture.outcome.network_identity(),
                },
                FixedEpocher::new(EPOCH_LENGTH),
            )
        };
        let rotation_verifier = verifier(&current);

        let boundary_height = EPOCH_LENGTH.get() - 1;
        let boundary = certified(boundary_height, Some(&next.outcome), 0, &current);
        rotation_verifier
            .decode_and_verify(&mut context, &boundary)
            .expect("current identity should verify the boundary");

        rotation_verifier
            .decode_dkg_outcome_and_register_boundary(boundary.block.header().extra_data().as_ref())
            .expect("boundary should install the next identity");

        let floor = certified(EPOCH_LENGTH.get(), None, 1, &next);
        rotation_verifier
            .decode_and_verify(&mut context, &floor)
            .expect("installed identity should verify the next epoch");

        // Bootstrap starts with only the static network identity, without learned schemes.
        let verifier = verifier(&next);
        let boundary = certified(boundary_height, Some(&next.outcome), 0, &next);
        let (_, certificate) = verifier
            .verify_anchor(&mut context, &floor, &boundary)
            .expect("network identity should authenticate the anchor and its boundary");
        assert_eq!(certificate.unwrap().proposal.payload.get(), boundary.digest);

        let wrong_floor = certified(EPOCH_LENGTH.get(), None, 1, &current);
        assert!(
            verifier
                .verify_anchor(&mut context, &wrong_floor, &boundary)
                .is_err(),
            "accepted invalid floor signature"
        );
        let mut wrong_epoch = next.outcome.clone();
        wrong_epoch.epoch = 2;
        let mut wrong_sharing = current.outcome.clone();
        wrong_sharing.epoch = 1;
        for (name, boundary) in [
            (
                "boundary signature",
                certified(boundary_height, Some(&next.outcome), 0, &current),
            ),
            (
                "boundary height",
                certified(boundary_height - 1, Some(&next.outcome), 0, &next),
            ),
            (
                "DKG epoch",
                certified(boundary_height, Some(&wrong_epoch), 0, &next),
            ),
            (
                "DKG sharing",
                certified(boundary_height, Some(&wrong_sharing), 0, &next),
            ),
        ] {
            assert!(
                verifier
                    .verify_anchor(&mut context, &floor, &boundary)
                    .is_err(),
                "accepted invalid {name}"
            );
        }
    });
}

#[test_traced]
fn rejects_invalid_certified_blocks() {
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
