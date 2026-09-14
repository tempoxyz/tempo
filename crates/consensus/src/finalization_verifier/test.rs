use alloy_consensus::{BlockHeader as _, Header};
use commonware_consensus::types::{Epoch, FixedEpocher};
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
            .decode_dkg_outcome_and_register_boundary(boundary.header().extra_data().as_ref())
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
