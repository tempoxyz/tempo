//! Tests for the exit-after-epoch coordinated shutdown feature.

use std::time::Duration;

use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Runner as _,
    deterministic::{Config, Runner},
};
use tracing::info;

use crate::{Setup, setup_validators};

#[test_traced]
fn single_validator_exits_after_epoch_and_exports_state() {
    let _ = tempo_eyre::install();

    let epoch_length = 10;
    let target_epoch = 1; // Exit after epoch 1 (blocks 10-19)

    let export_dir = tempfile::tempdir().expect("failed to create temp dir");
    let export_path = export_dir.path().join("dkg_export.json");

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

        // Start the single validator
        validators[0].start().await;

        // Wait for the export file to be created (indicates successful exit-after-epoch)
        // The node should process epoch 1 (blocks 10-19) and then export + shutdown
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
            "DKG export file should exist at {export_path:?}"
        );

        // Verify the export file contains valid JSON with expected fields
        let export_content =
            std::fs::read_to_string(&export_path).expect("should be able to read export file");
        let export: serde_json::Value =
            serde_json::from_str(&export_content).expect("export file should contain valid JSON");

        // After processing the last block of epoch 1 (block 19), the DB epoch state
        // is updated to epoch 2. The export captures this NEW epoch state.
        let expected_epoch = target_epoch + 1; // 2 (the epoch we're about to enter)
        let expected_exported_at_height = (target_epoch + 1) * epoch_length - 1; // 19 (last block of epoch 1)
        let expected_floor_height = expected_exported_at_height + 1; // 20 (first block of epoch 2)

        assert_eq!(
            export["epoch_state"]["epoch"].as_u64(),
            Some(expected_epoch),
            "export epoch_state.epoch should be {expected_epoch}"
        );
        assert_eq!(
            export["exported_at_height"].as_u64(),
            Some(expected_exported_at_height),
            "export should be at height {expected_exported_at_height}"
        );
        assert_eq!(
            export["floor_height"].as_u64(),
            Some(expected_floor_height),
            "floor_height should be {expected_floor_height}"
        );
        assert!(
            export["epoch_state"].is_object(),
            "export should contain epoch_state"
        );

        info!("test passed: export file created with valid content");
    });
}
