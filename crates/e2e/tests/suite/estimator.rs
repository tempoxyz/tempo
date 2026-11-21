//! Finalized successors of own proposals produce network sampling metrics.

use std::time::Duration;

use commonware_macros::test_traced;
use commonware_runtime::{
    Runner as _,
    deterministic::{self, Runner},
};
use futures::future::join_all;

use crate::{
    Setup,
    metrics::{Metrics, wait_for_height},
    setup_validators,
};

/// Runs four validators until every one of them has seen height 20, then
/// checks that each completed at least one network sample. With four signers
/// the child of a node's proposal usually comes from another leader.
#[test_traced]
fn signers_sample_the_children_other_leaders_build() {
    let _ = tempo_eyre::install();
    let setup = Setup::new(crate::VERIFICATION_MODE)
        .how_many_signers(4)
        .epoch_length(100);
    let cfg = deterministic::Config::default()
        .with_seed(setup.seed)
        .with_timeout(Some(Duration::from_secs(60)));

    Runner::from(cfg).start(|mut context| async move {
        let (mut nodes, _execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(nodes.iter_mut().map(|node| node.start(&context))).await;
        join_all(nodes.iter().map(|node| wait_for_height(&context, node, 20))).await;

        let metrics = Metrics::from_context(&context);
        for node in &nodes {
            let samples = metrics
                .for_scope(node)
                .value::<u64>("application_network_samples_total")
                .expect("consensus application registers the network sample counter");
            assert!(
                samples >= 1,
                "node {} completed no network sample",
                node.uid()
            );
        }
    });
}
