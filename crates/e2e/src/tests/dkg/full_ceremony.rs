//! Tests for full DKG ceremonies triggered by `setNextFullDkgCeremony`.

use std::time::Duration;

use alloy::transports::http::reqwest::Url;
use commonware_codec::ReadExt as _;
use commonware_consensus::types::{Epoch, Epocher as _, FixedEpocher};
use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _,
    deterministic::{Config, Context, Runner},
};
use commonware_utils::NZU64;
use futures::future::join_all;
use reth_ethereum::provider::BlockReader as _;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;

use crate::{CONSENSUS_NODE_PREFIX, Setup, TestingNode, setup_validators};

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

        executor.start(|context| async move {
            let (mut validators, execution_runtime) =
                setup_validators(context.clone(), setup).await;

            join_all(validators.iter_mut().map(|v| v.start())).await;

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
            let outcome_before = self
                .wait_for_outcome(&context, &validators, self.full_dkg_epoch - 1)
                .await;

            assert!(
                outcome_before.is_next_full_dkg,
                "Epoch {} outcome should have is_next_full_dkg=true",
                self.full_dkg_epoch - 1
            );
            let pubkey_before = *outcome_before.sharing().public();
            tracing::info!(?pubkey_before, "Group public key BEFORE full DKG");

            // Step 2: Wait for full DKG to complete (epoch N+1)
            self.wait_for_epoch(&context, self.full_dkg_epoch + 1).await;

            // Step 3: Verify full DKG created a NEW polynomial (different public key)
            let outcome_after_full = self
                .wait_for_outcome(&context, &validators, self.full_dkg_epoch)
                .await;

            let pubkey_after_full = *outcome_after_full.sharing().public();
            tracing::info!(?pubkey_after_full, "Group public key AFTER full DKG");

            assert_ne!(
                pubkey_before, pubkey_after_full,
                "Full DKG must produce a DIFFERENT group public key"
            );
            tracing::info!("Verified: full DKG created independent polynomial");

            // Step 4: Wait for reshare (epoch N+2) and verify it PRESERVES the public key
            self.wait_for_epoch(&context, self.full_dkg_epoch + 2).await;

            let outcome_after_reshare = self
                .wait_for_outcome(&context, &validators, self.full_dkg_epoch + 1)
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

    /// Waits for and reads the DKG outcome from the last block of the given epoch.
    async fn wait_for_outcome(
        &self,
        context: &Context,
        validators: &[TestingNode<Context>],
        epoch: u64,
    ) -> OnchainDkgOutcome {
        let block_num = FixedEpocher::new(NZU64!(self.epoch_length))
            .last(Epoch::new(epoch))
            .expect("valid epoch")
            .get();

        tracing::info!(epoch, %block_num, "Waiting for DKG outcome");

        loop {
            context.sleep(Duration::from_secs(1)).await;

            if let Some(outcome) = read_outcome_from_validator(&validators[0], block_num) {
                tracing::info!(
                    epoch,
                    block_num,
                    outcome_epoch = %outcome.epoch,
                    is_next_full_dkg = outcome.is_next_full_dkg,
                    "Read DKG outcome"
                );
                return outcome;
            }
        }
    }

    /// Waits until all validators reach the target epoch.
    async fn wait_for_epoch(&self, context: &Context, target_epoch: u64) {
        tracing::info!(target_epoch, "Waiting for epoch");

        loop {
            context.sleep(Duration::from_secs(1)).await;

            if self.count_validators_at_epoch(context, target_epoch) >= self.how_many_signers {
                tracing::info!(target_epoch, "All validators reached epoch");
                return;
            }
        }
    }

    /// Counts how many validators have reached the target epoch.
    fn count_validators_at_epoch(&self, context: &Context, target_epoch: u64) -> u32 {
        let metrics = context.encode();
        let mut at_epoch = 0;

        for line in metrics.lines() {
            let Some((metric, value)) = parse_metric_line(line) else {
                continue;
            };

            // Assert no DKG failures
            if metric.ends_with("_dkg_manager_ceremony_failures_total") {
                assert_eq!(0, value, "DKG ceremony failed: {metric}");
            }

            if metric.ends_with("_epoch_manager_latest_epoch") && value >= target_epoch {
                at_epoch += 1;
            }
        }

        at_epoch
    }
}

/// Reads the DKG outcome from a block, returns None if block doesn't exist or has no outcome.
fn read_outcome_from_validator(
    validator: &TestingNode<Context>,
    block_num: u64,
) -> Option<OnchainDkgOutcome> {
    let provider = validator.execution_provider();
    let block = provider.block_by_number(block_num).ok()??;
    let extra_data = &block.header.inner.extra_data;

    if extra_data.is_empty() {
        return None;
    }

    Some(OnchainDkgOutcome::read(&mut extra_data.as_ref()).expect("valid DKG outcome"))
}

/// Parses a metric line, returning (metric_name, value) if valid.
fn parse_metric_line(line: &str) -> Option<(&str, u64)> {
    if !line.starts_with(CONSENSUS_NODE_PREFIX) {
        return None;
    }

    let mut parts = line.split_whitespace();
    let metric = parts.next()?;
    let value = parts.next()?.parse().ok()?;

    Some((metric, value))
}
