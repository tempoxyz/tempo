//! Tests for full DKG ceremonies triggered by `setNextFullDkgCeremony`.

use alloy::transports::http::reqwest::Url;
use commonware_macros::test_traced;
use commonware_runtime::{
    Runner as _,
    deterministic::{Config, Runner},
};
use futures::future::join_all;

use super::common::{assert_no_dkg_failures, wait_for_epoch, wait_for_outcome};
use crate::{Setup, setup_validators};

#[test_traced]
fn full_dkg_ceremony() {
    FullDkgTest {
        how_many_signers: 1,
        epoch_length: 10,
        full_dkg_epoch: 1,
    }
    .run();
}

struct FullDkgTest {
    how_many_signers: u32,
    epoch_length: u64,
    full_dkg_epoch: u64,
}

impl FullDkgTest {
    fn run(self) {
        let _ = tempo_eyre::install();

        let setup = Setup::new()
            .how_many_signers(self.how_many_signers)
            .epoch_length(self.epoch_length);

        let cfg = Config::default().with_seed(setup.seed);
        let executor = Runner::from(cfg);

        executor.start(|mut context| async move {
            let (mut validators, execution_runtime) = setup_validators(&mut context, setup).await;

            join_all(validators.iter_mut().map(|v| v.start(&context))).await;

            // Schedule full DKG for the specified epoch
            let http_url: Url = validators[0]
                .execution()
                .rpc_server_handle()
                .http_url()
                .unwrap()
                .parse()
                .unwrap();

            execution_runtime
                .set_next_full_dkg_ceremony(http_url, self.full_dkg_epoch)
                .await
                .unwrap();

            tracing::info!(full_dkg_epoch = self.full_dkg_epoch, "Scheduled full DKG");

            // Step 1: Wait for and verify the is_next_full_dkg flag in epoch N-1
            let outcome_before = wait_for_outcome(
                &context,
                &validators,
                self.full_dkg_epoch - 1,
                self.epoch_length,
            )
            .await;

            assert!(
                outcome_before.is_next_full_dkg,
                "Epoch {} outcome should have is_next_full_dkg=true",
                self.full_dkg_epoch - 1
            );
            let pubkey_before = *outcome_before.sharing().public();
            tracing::info!(?pubkey_before, "Group public key BEFORE full DKG");

            // Step 2: Wait for full DKG to complete (epoch N+1)
            wait_for_epoch(&context, self.full_dkg_epoch + 1, self.how_many_signers).await;
            assert_no_dkg_failures(&context);

            // Step 3: Verify full DKG created a NEW polynomial (different public key)
            let outcome_after_full = wait_for_outcome(
                &context,
                &validators,
                self.full_dkg_epoch,
                self.epoch_length,
            )
            .await;

            let pubkey_after_full = *outcome_after_full.sharing().public();
            tracing::info!(?pubkey_after_full, "Group public key AFTER full DKG");

            assert_ne!(
                pubkey_before, pubkey_after_full,
                "Full DKG must produce a DIFFERENT group public key"
            );
            tracing::info!("Verified: full DKG created independent polynomial");

            // Step 4: Wait for reshare (epoch N+2) and verify it PRESERVES the public key
            wait_for_epoch(&context, self.full_dkg_epoch + 2, self.how_many_signers).await;
            assert_no_dkg_failures(&context);

            let outcome_after_reshare = wait_for_outcome(
                &context,
                &validators,
                self.full_dkg_epoch + 1,
                self.epoch_length,
            )
            .await;

            assert!(
                !outcome_after_reshare.is_next_full_dkg,
                "Epoch {} should NOT have is_next_full_dkg flag",
                self.full_dkg_epoch + 1
            );

            let pubkey_after_reshare = *outcome_after_reshare.sharing().public();
            tracing::info!(?pubkey_after_reshare, "Group public key AFTER reshare");

            assert_eq!(
                pubkey_after_full, pubkey_after_reshare,
                "Reshare must PRESERVE the group public key"
            );
            tracing::info!("Verified: reshare preserved polynomial (full DKG only ran once)");
        })
    }
}
