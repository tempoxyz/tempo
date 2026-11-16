use commonware_consensus::types::Epoch;
use commonware_runtime::{Runner as _, Supervisor as _, deterministic::Runner};
use test_case::test_case;

use super::*;
use crate::{
    storage::hybrid::test::utils::fresh_page_cache,
    test_utils::{dkg_fixture, make_certificate},
};

// Exercise both sides of epoch boundaries, including the end of epoch zero.
#[test_case(9, 0, 0)]
#[test_case(9, 1, 0)]
#[test_case(10, 0, 1)]
#[test_case(10, 1, 1)]
#[test_case(19, 1, 1)]
#[test_case(19, 2, 1)]
#[test_case(20, 1, 2)]
#[test_case(20, 2, 2)]
#[test_case(20, 3, 2)]
fn finalizations_archive_tip_epoch_must_match_its_height(
    height: u64,
    cert_epoch: u64,
    expected_epoch: u64,
) {
    Runner::default().start(|mut context| async move {
        let epoch_strategy = FixedEpocher::new(NZU64!(10));
        let fixture = dkg_fixture(&mut context, Epoch::zero());
        let mut archive = init_finalizations_archive(
            &context,
            "test",
            fresh_page_cache(),
            &epoch_strategy,
        )
        .await
        .unwrap();
        assert_eq!(archive.last_index(), None);

        // Keep a valid floor so rejection depends on checking the tip.
        for (height, epoch) in [(1, 0), (height, cert_epoch)] {
            let digest = Digest(alloy_primitives::B256::with_last_byte(height as u8));
            let certificate = make_certificate(digest, Epoch::new(epoch), 1, &fixture.schemes);
            archive = archive.put(height, digest, &certificate).await.unwrap();
        }
        drop(archive.sync().await.unwrap());

        let context = context.child("reopen");
        let result = init_finalizations_archive(
            &context,
            "test",
            fresh_page_cache(),
            &epoch_strategy,
        )
        .await;
        if cert_epoch == expected_epoch {
            assert_eq!(result.unwrap().last_index(), Some(height));
        } else {
            let error = result.unwrap_err().to_string();
            assert!(
                error.contains(&format!(
                    "certificate epoch `{cert_epoch}` does not match epoch `{expected_epoch}` for archive height `{height}`"
                )),
                "{error}",
            );
        }
    });
}
