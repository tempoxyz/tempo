//! Tests for the exit-after-epoch coordinated shutdown feature.

use std::time::Duration;

use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Runner as _,
    deterministic::{Config, Runner},
};
use reth_ethereum::storage::BlockNumReader;
use tempo_commonware_node_config::SigningShare;
use tracing::info;

use crate::{Setup, setup_validators};

/// Test exit-after-epoch with share export, then restart with sync_floor.
///
/// This simulates the rolling upgrade scenario:
/// 1. Node exits after epoch 1 and exports its share
/// 2. Consensus storage is deleted (simulating breaking migration)
/// 3. Node restarts with sync_floor enabled, using exported share
/// 4. Node should resume from the execution layer's highest block
/// 5. Verify it advances at least 2 blocks into the new epoch
#[test_traced]
fn exit_after_epoch_and_restart_with_sync_floor() {
    let _ = tempo_eyre::install();

    let epoch_length = 10;
    let target_epoch = 1; // Exit after epoch 1 (blocks 10-19)

    let export_dir = tempfile::tempdir().expect("failed to create temp dir");
    let export_path = export_dir.path().join("signing_share.txt");

    info!(?export_path, "test will look for export file");

    let setup = Setup::new()
        .how_many_signers(1)
        .epoch_length(epoch_length)
        .allegretto_time(0) // Post-allegretto from genesis
        .exit_after_epoch(target_epoch, export_path.clone());

    let cfg = Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|context| async move {
        let (mut validators, _execution_runtime) = setup_validators(context.clone(), setup).await;
        let node = &mut validators[0];

        // Start the validator
        node.start().await;

        // Wait for the export file to be created
        for i in 0..120 {
            context.sleep(Duration::from_secs(1)).await;

            if export_path.exists() {
                info!(iteration = i, "export file found!");
                break;
            }

            if i % 10 == 0 {
                info!(
                    iteration = i,
                    exists = export_path.exists(),
                    "waiting for export file"
                );
            }
        }

        // Verify the export file was created
        assert!(
            export_path.exists(),
            "signing share export file should exist at {export_path:?}"
        );

        // Verify the exported file can be read as a valid signing share
        let share = SigningShare::read_from_file(&export_path)
            .expect("should be able to read exported share");
        info!("export file contains valid signing share");

        // Get the block number at exit (should be end of epoch 1 = block 19)
        let exit_block = node
            .execution()
            .provider
            .best_block_number()
            .expect("should get best block number");
        info!(exit_block, "node exited at block");

        // The exit block should be the last block of epoch 1
        let expected_exit_block = (target_epoch + 1) * epoch_length - 1; // epoch 1 ends at block 19
        assert_eq!(
            exit_block, expected_exit_block,
            "exit block should be last block of target epoch"
        );

        // Stop the node
        node.stop().await;
        info!("node stopped after exit");

        // Clear consensus storage (simulating deleting datadir/consensus)
        node.clear_consensus_storage();
        node.consensus_config_mut().share = Some(share.into_inner());
        node.consensus_config_mut().sync_floor = true;
        node.consensus_config_mut().exit.args.exit_after_epoch = None;
        node.consensus_config_mut().exit.args.exit_export_share = None;

        // Restart the node
        node.start().await;
        info!("node restarted with sync_floor");

        // Wait for the node to advance at least 2 blocks past the exit block
        let target_block = exit_block + 2;
        for i in 0..30 {
            context.sleep(Duration::from_secs(1)).await;

            let current_block = node
                .execution()
                .provider
                .best_block_number()
                .expect("should get best block number");

            if current_block >= target_block {
                break;
            }

            if i % 10 == 0 {
                info!(
                    iteration = i,
                    current_block, target_block, "waiting for block progress"
                );
            }
        }

        let final_block = node
            .execution()
            .provider
            .best_block_number()
            .expect("should get best block number");

        assert!(
            final_block >= target_block,
            "node should have advanced at least 2 blocks past exit: final={final_block}, target={target_block}"
        );
    });
}
