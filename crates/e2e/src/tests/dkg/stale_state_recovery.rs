//! Tests recovery from DKG state that predates the installed consensus snapshot.

use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, Storage as _, deterministic};
use futures::future::join_all;

use super::common::wait_for_validators_to_reach_epoch;
use crate::{
    Setup, connect_execution_peers, connect_execution_to_peers,
    consensus_snapshot::write_consensus_snapshot, setup_validators,
};

/// Snapshot storage partitions materialized by `write_consensus_snapshot`.
const SNAPSHOT_PARTITION_SUFFIXES: &[&str] = &[
    "finalizations-by-height-metadata",
    "finalizations-by-height-freezer-table",
    "finalizations-by-height-freezer-key",
    "finalizations-by-height-freezer-value",
    "finalizations-by-height-ordinal",
    "finalized-blocks-prunable-key",
    "finalized-blocks-prunable-value",
];

/// A validator retains its DKG journal while replacing the finalized consensus snapshot with one
/// from a later epoch. On restart, the DKG actor must rebuild its state from the snapshot boundary
/// and rejoin consensus.
#[test_traced]
fn validator_heals_dkg_state_behind_consensus_snapshot() {
    let _ = tempo_eyre::install();

    let setup = Setup::new().how_many_signers(4).epoch_length(10);
    let executor = deterministic::Runner::seeded(setup.seed);

    executor.start(|mut context| async move {
        let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;

        join_all(validators.iter_mut().map(|node| node.start(&context))).await;
        connect_execution_peers(&validators).await;

        // Ensure the validator has persisted epoch 1 DKG state before taking it offline.
        wait_for_validators_to_reach_epoch(&context, 1, validators.len() as u32).await;
        let mut stale = validators.pop().expect("setup includes validators");
        stale.stop().await;

        // Advance the remaining quorum and capture a snapshot rooted in epoch 2.
        wait_for_validators_to_reach_epoch(&context, 2, validators.len() as u32).await;
        let mut donor = validators.pop().expect("setup includes a snapshot donor");
        let execution_provider = donor.execution_provider();
        donor.stop().await;

        let target_prefix = stale.partition_prefix.clone();
        for suffix in SNAPSHOT_PARTITION_SUFFIXES {
            context
                .remove(&format!("{target_prefix}-{suffix}"), None)
                .await
                .expect("stopped validator's snapshot partition must be removable");
        }
        write_consensus_snapshot(&context, &donor, execution_provider, &target_prefix).await;

        // Reuse the donor's synced execution database with the stale validator's identity and
        // consensus partition. The DKG partitions still contain epoch 1 state, while the installed
        // snapshot starts in epoch 2.
        donor.adopt_identity_from(stale);
        donor.start(&context).await;
        connect_execution_to_peers(&donor, &validators).await;
        validators.push(donor);

        // Healing must restore a usable share and let the three online validators advance.
        wait_for_validators_to_reach_epoch(&context, 3, validators.len() as u32).await;
    });
}
