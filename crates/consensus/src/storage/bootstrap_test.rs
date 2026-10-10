use commonware_consensus::types::{Epoch, FixedEpocher};
use commonware_runtime::{Runner as _, deterministic::Runner};
use tempo_chainspec::NetworkIdentity;
use tempo_node::rpc::consensus::CertifiedBlock;

use super::verify_anchor;
use crate::follow::test_utils::{
    DkgFixture, EPOCH_LENGTH, dkg_fixture, make_block, make_certified_block, make_finalization,
};

#[test]
fn bootstrap_anchor_requires_authenticated_epoch_boundary() {
    Runner::default().start(|mut context| async move {
        let certified = |height, outcome, epoch, fixture: &DkgFixture| {
            let block = make_block(height, outcome);
            let certificate = make_finalization(&block, Epoch::new(epoch), &fixture.schemes);
            make_certified_block(block, &certificate)
        };
        let trusted = dkg_fixture(&mut context, Epoch::new(1));
        let unrelated = dkg_fixture(&mut context, Epoch::new(1));
        let identity = NetworkIdentity {
            from_epoch: 0,
            identity: *trusted.outcome.network_identity(),
        };
        let floor = certified(12, None, 1, &trusted);
        let boundary = certified(9, Some(&trusted.outcome), 0, &trusted);
        let mut verify = |floor: &CertifiedBlock, boundary: &CertifiedBlock| {
            verify_anchor(
                &mut context,
                identity.clone(),
                FixedEpocher::new(EPOCH_LENGTH),
                floor,
                boundary,
            )
        };
        let (_, certificate) = verify(&floor, &boundary).unwrap();
        assert_eq!(certificate.unwrap().proposal.payload.get(), boundary.digest);

        let mut wrong_epoch = trusted.outcome.clone();
        wrong_epoch.epoch = 2;
        assert!(verify(&certified(12, None, 1, &unrelated), &boundary).is_err());
        for boundary in [
            certified(9, Some(&trusted.outcome), 0, &unrelated),
            certified(8, Some(&trusted.outcome), 0, &trusted),
            certified(9, Some(&wrong_epoch), 0, &trusted),
            certified(9, Some(&unrelated.outcome), 0, &trusted),
        ] {
            assert!(verify(&floor, &boundary).is_err());
        }
    });
}
