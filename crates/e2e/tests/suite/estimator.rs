//! The consensus application feeds the proposal budget estimator.
//!
//! The harness pins every node's network reservation
//! (`EstimatorConfig::fixed`), but completed own proposals are still pushed
//! into the window as network samples, so counting them shows that the hooks
//! ran: `build()` records each own proposal's return, and the finalized child
//! completes the sample, whether the node built that child itself or another
//! leader did.

use std::time::{Duration, Instant};

use commonware_macros::test_traced;
use commonware_runtime::{
    Runner as _,
    deterministic::{self, Runner},
};
use futures::future::join_all;

use crate::{Setup, metrics::wait_for_height, setup_validators};

/// Runs `signers` validators until every one of them has seen height 20,
/// then checks that each completed at least one network sample.
fn every_node_completes_a_network_sample(signers: u32) {
    let _ = tempo_eyre::install();
    let setup = Setup::new(crate::VERIFICATION_MODE)
        .how_many_signers(signers)
        .epoch_length(100);
    let cfg = deterministic::Config::default()
        .with_seed(setup.seed)
        .with_timeout(Some(Duration::from_secs(60)));

    Runner::from(cfg).start(|mut context| async move {
        let (mut nodes, _execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(nodes.iter_mut().map(|node| node.start(&context))).await;
        join_all(nodes.iter().map(|node| wait_for_height(&context, node, 20))).await;

        for node in &nodes {
            let snapshot = node.estimator.snapshot(Instant::now());
            assert!(
                snapshot.network_samples >= 1,
                "node {} completed no network sample: {snapshot:?}",
                node.uid(),
            );
        }
    });
}

#[test_traced]
fn a_lone_signer_samples_the_children_it_builds() {
    // A lone signer leads every view, so the child of each of its proposals
    // is its own next build.
    every_node_completes_a_network_sample(1);
}

#[test_traced]
fn signers_sample_the_children_other_leaders_build() {
    // With four signers the child of a node's proposal usually comes from
    // another leader.
    every_node_completes_a_network_sample(4);
}
