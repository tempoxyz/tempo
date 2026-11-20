use commonware_macros::test_traced;
use commonware_runtime::{
    Runner as _,
    deterministic::{Config, Runner},
};
use futures::future::join_all;

use crate::{
    Setup,
    metrics::{assert_no_duplicate_definitions, wait_for_metrics},
    setup_validators,
};

#[test_traced]
fn no_duplicate_metrics() {
    let _ = tempo_eyre::install();

    let setup = Setup::new().how_many_signers(1).epoch_length(10);

    let cfg = Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        // Setup and run all validators.
        let (mut nodes, _execution_runtime) = setup_validators(&mut context, setup).await;

        join_all(nodes.iter_mut().map(|node| node.start(&context))).await;

        wait_for_metrics(&context, |metrics| metrics.consensus_at_epoch(2) > 0).await;

        // NOTE: useful for debugging
        // std::fs::write("metrics-dump", &all_metrics).unwrap();
        assert_no_duplicate_definitions(&context);
    })
}
