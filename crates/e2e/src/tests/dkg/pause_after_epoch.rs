//! Tests for the pause-after-epoch coordinated shutdown feature.

use std::time::Duration;

use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Runner as _,
    deterministic::{Config, Runner},
};
use tempo_commonware_node_config::SigningShare;
use tracing::info;

use crate::{Setup, setup_validators};

#[test_traced]
fn single_validator_pauses_after_epoch_and_exports_share() {
    let _ = tempo_eyre::install();

    let epoch_length = 10;
    let target_epoch = 1; // Pause after epoch 1 (blocks 10-19)

    let export_dir = tempfile::tempdir().expect("failed to create temp dir");
    let export_path = export_dir.path().join("signing_share.txt");

    info!(?export_path, "test will look for export file");

    let setup = Setup::new()
        .how_many_signers(1)
        .epoch_length(epoch_length)
        .allegretto_time(0) // Post-allegretto from genesis
        .pause_after_epoch(target_epoch, export_path.clone());

    let cfg = Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|context| async move {
        let (mut validators, _execution_runtime) = setup_validators(context.clone(), setup).await;

        // Start the single validator
        validators[0].start().await;

        // Wait for the export file to be created (indicates successful pause-after-epoch)
        // The node should process epoch 1 (blocks 10-19) and then export the share
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
        // (same format as --consensus.signing-share input)
        let _share = SigningShare::read_from_file(&export_path)
            .expect("should be able to read exported share");

        info!("test passed: export file contains valid signing share");
    });
}
