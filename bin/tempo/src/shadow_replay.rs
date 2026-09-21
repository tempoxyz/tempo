//! Historical replay over a canonical database block range.

use alloy_consensus::BlockHeader as _;
use clap::Parser;
use eyre::{ensure, eyre};
use reth_cli_commands::common::{AccessRights, EnvironmentArgs};
use reth_ethereum::tasks::Runtime;
use reth_provider::{
    BlockNumReader as _, BlockReader as _, DatabaseProviderFactory as _, ReceiptProvider as _,
    TransactionVariant, providers::BlockchainProvider,
};
use std::time::{Duration, Instant};
use tempo_chainspec::{
    hardfork::TempoHardfork,
    spec::{TempoChainSpecParser, TempoHardforks as _},
};
use tempo_node::{ReplayOutcome, ShadowReplayer, node::TempoNode};
use tracing::{info, info_span, warn};

/// Replay a canonical block range independently under candidate hardfork rules.
#[derive(Debug, Parser)]
pub struct ShadowReplay {
    #[command(flatten)]
    env: EnvironmentArgs<TempoChainSpecParser>,

    /// Inclusive first block to replay.
    #[arg(long, default_value_t = 1)]
    from: u64,

    /// Inclusive last block to replay. Defaults to the database tip.
    #[arg(long)]
    to: Option<u64>,

    /// Candidate hardfork to activate for counterfactual execution.
    #[arg(long)]
    hardfork: TempoHardfork,

    /// Exit unsuccessfully on unexplained findings or inconclusive comparisons.
    #[arg(long)]
    fail_on_findings: bool,
}

impl ShadowReplay {
    pub(crate) async fn execute(self, runtime: Runtime) -> eyre::Result<()> {
        ensure!(self.from > 0, "shadow replay cannot execute genesis block");

        let chain_spec = self.env.chain.clone();
        let environment = self.env.init::<TempoNode>(AccessRights::RO, runtime)?;
        let best_block = environment
            .provider_factory
            .database_provider_ro()?
            .best_block_number()?;
        let to = self.to.unwrap_or(best_block);
        ensure!(
            to <= best_block,
            "requested --to ({to}) is beyond database tip ({best_block})"
        );
        ensure!(
            self.from <= to,
            "--from ({}) is beyond --to ({to}), nothing to replay",
            self.from
        );

        let provider = BlockchainProvider::new(environment.provider_factory)?;
        let replayer = ShadowReplayer::new(provider.clone(), self.hardfork);
        let (mut matched, mut expected, mut inconclusive, mut findings, mut skipped) =
            (0u64, 0u64, 0u64, 0u64, 0u64);
        let started_at = Instant::now();
        let mut last_progress = started_at;

        info!(
            from = self.from,
            to,
            hardfork = %self.hardfork,
            "Starting historical shadow replay"
        );

        for number in self.from..=to {
            let block = provider
                .recovered_block(number.into(), TransactionVariant::NoHash)?
                .ok_or_else(|| eyre!("canonical block {number} not found"))?;
            if chain_spec.tempo_hardfork_at(block.timestamp()) >= self.hardfork {
                skipped += 1;
            } else {
                let receipts = provider
                    .receipts_by_block(number.into())?
                    .ok_or_else(|| eyre!("canonical receipts for block {number} not found"))?;
                let span = info_span!(
                    target: "shadow_replay",
                    "shadow_replay",
                    block_number = number,
                    block_hash = ?block.hash(),
                    hardfork = %self.hardfork,
                );
                let outcome = span.in_scope(|| replayer.replay(&block, &receipts));

                match outcome
                    .map_err(|err| eyre!("shadow replay failed at block {number}: {err}"))?
                {
                    ReplayOutcome::Match => matched += 1,
                    ReplayOutcome::Expected => expected += 1,
                    ReplayOutcome::Inconclusive => inconclusive += 1,
                    ReplayOutcome::Findings => findings += 1,
                }
            }

            if last_progress.elapsed() >= Duration::from_secs(10) {
                info!(
                    latest_block = number,
                    matched, expected, inconclusive, findings, skipped, "Shadow replay progress"
                );
                last_progress = Instant::now();
            }
        }

        info!(
            from = self.from,
            to,
            hardfork = %self.hardfork,
            matched,
            expected,
            inconclusive,
            findings,
            skipped,
            elapsed = ?started_at.elapsed(),
            "Historical shadow replay completed"
        );
        if skipped > 0 {
            warn!(
                skipped,
                "Skipped blocks where the candidate hardfork was already canonical"
            );
        }
        if self.fail_on_findings && (findings > 0 || inconclusive > 0) {
            eyre::bail!(
                "historical shadow replay needs review: {findings} blocks with unexplained differences, {inconclusive} inconclusive blocks"
            );
        }
        Ok(())
    }
}
