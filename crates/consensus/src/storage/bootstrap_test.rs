use commonware_consensus::types::{Epoch, FixedEpocher};
use commonware_runtime::{Runner as _, deterministic::Runner};
use tempo_chainspec::NetworkIdentity;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_node::rpc::consensus::CertifiedBlock;

use super::verify_anchor;
use crate::follow::test_utils::{
    DkgFixture, EPOCH_LENGTH, dkg_fixture, make_block, make_certified_block, make_finalization,
};

#[test]
fn bootstrap_anchor_requires_authenticated_epoch_boundary() {
    Runner::default().start(|mut context| async move {
        let trusted = dkg_fixture(&mut context, Epoch::new(1));
        let unrelated = dkg_fixture(&mut context, Epoch::new(1));
        let identity = NetworkIdentity {
            from_epoch: 0,
            identity: *trusted.outcome.network_identity(),
        };
        let floor = certified(12, None, 1, &trusted);
        let boundary = certified(9, Some(&trusted.outcome), 0, &trusted);
        let mut verify = |floor, boundary| {
            verify_anchor(
                &mut context,
                identity.clone(),
                FixedEpocher::new(EPOCH_LENGTH),
                floor,
                boundary,
            )
        };
        verify(&floor, &boundary).unwrap();

        let mut wrong_epoch = trusted.outcome.clone();
        wrong_epoch.epoch = 2;
        for (floor, boundary) in [
            (certified(12, None, 1, &unrelated), boundary.clone()),
            (
                floor.clone(),
                certified(9, Some(&trusted.outcome), 0, &unrelated),
            ),
            (
                floor.clone(),
                certified(8, Some(&trusted.outcome), 0, &trusted),
            ),
            (floor.clone(), certified(9, Some(&wrong_epoch), 0, &trusted)),
            (
                floor.clone(),
                certified(9, Some(&unrelated.outcome), 0, &trusted),
            ),
        ] {
            assert!(verify(&floor, &boundary).is_err());
        }
    });
}

fn certified(
    height: u64,
    outcome: Option<&OnchainDkgOutcome>,
    epoch: u64,
    fixture: &DkgFixture,
) -> CertifiedBlock {
    let block = make_block(height, outcome);
    let certificate = make_finalization(&block, Epoch::new(epoch), &fixture.schemes);
    make_certified_block(block, &certificate)
}
