//! Read-only differential replay against canonical blocks and historical parent state.

use std::{
    fs::File,
    io::{BufWriter, Write},
    path::PathBuf,
    time::Instant,
};

use alloy_consensus::BlockHeader;
use clap::Parser;
use eyre::{OptionExt, WrapErr, ensure};
use reth_cli_commands::common::{AccessRights, EnvironmentArgs};
use reth_ethereum::{
    consensus::FullConsensus,
    evm::{
        primitives::{ConfigureEvm, execute::Executor},
        revm::database::StateProviderDatabase,
    },
    tasks::Runtime,
};
use reth_provider::{
    BlockNumReader, BlockReader, ChainSpecProvider, DatabaseProviderFactory, ReceiptProvider,
    TransactionVariant,
};
use reth_storage_api::{HashedPostStateProvider, StateRootProvider};
use tempo_chainspec::spec::TempoChainSpecParser;
use tempo_consensus::TempoConsensus;
use tempo_evm::{TempoEvmConfig, parallel::SpeculativeExecutor};
use tempo_node::node::TempoNode;
use tracing::info;

/// Compare sequential and speculative execution with canonical receipts and state roots.
#[derive(Debug, Parser)]
pub(crate) struct ParallelReplay {
    #[command(flatten)]
    env: EnvironmentArgs<TempoChainSpecParser>,
    /// First block to replay (inclusive). Parent state must be retained.
    #[arg(long, default_value = "1", value_parser = clap::value_parser!(u64).range(1..))]
    from: u64,
    /// Last block to replay (inclusive); defaults to the database head.
    #[arg(long)]
    to: Option<u64>,
    /// Speculative workers. Block commits still follow canonical transaction order.
    #[arg(long, default_value = "16", value_parser = clap::value_parser!(u32).range(1..))]
    threads: u32,
    /// Maximum speculative lookahead.
    #[arg(long, default_value = "128", value_parser = clap::value_parser!(u32).range(1..))]
    batch_size: u32,
    /// Optional TSV report; flushed after each successfully verified block.
    #[arg(long)]
    output: Option<PathBuf>,
}

impl ParallelReplay {
    pub(crate) async fn execute(self, runtime: Runtime) -> eyre::Result<()> {
        let environment = self.env.init::<TempoNode>(AccessRights::RO, runtime)?;
        let factory = environment.provider_factory;
        let head = factory.database_provider_ro()?.best_block_number()?;
        let to = self.to.unwrap_or(head);
        ensure!(
            self.from <= to && to <= head,
            "range must satisfy 1 <= from <= to <= head ({head})"
        );
        let chain = factory.chain_spec();
        let sequential = TempoEvmConfig::new(chain.clone());
        let speculative = sequential.clone().with_speculative_executor(
            SpeculativeExecutor::new(self.threads as usize, self.batch_size as usize)?
                .with_adaptive_backoff(false)
                .with_minimum_body_duration(std::time::Duration::ZERO),
        );
        let consensus = TempoConsensus::new(chain);
        let mut report = self
            .output
            .map(File::create)
            .transpose()?
            .map(BufWriter::new);
        if let Some(report) = &mut report {
            writeln!(
                report,
                "block\ttransactions\tgas_used\tsequential_seconds\tspeculative_seconds\tstate_root"
            )?;
        }
        let mut transactions = 0usize;
        for number in self.from..=to {
            let block = factory
                .recovered_block(number.into(), TransactionVariant::NoHash)?
                .ok_or_eyre(format!("missing canonical block {number}"))?;
            let parent = factory
                .history_by_block_number(number - 1)
                .wrap_err_with(|| format!("parent state unavailable for block {number}"))?;
            let start = Instant::now();
            let expected = sequential
                .executor(StateProviderDatabase(&parent))
                .execute(&block)
                .wrap_err_with(|| format!("sequential execution failed at block {number}"))?;
            let sequential_seconds = start.elapsed().as_secs_f64();
            let start = Instant::now();
            let actual = speculative
                .executor(StateProviderDatabase(&parent))
                .execute(&block)
                .wrap_err_with(|| format!("speculative execution failed at block {number}"))?;
            let speculative_seconds = start.elapsed().as_secs_f64();
            ensure!(
                actual.result == expected.result,
                "execution results differ at block {number}"
            );
            // Compare the complete state delta, including account deletion and code.
            ensure!(
                actual.state == expected.state,
                "state deltas differ at block {number}"
            );
            let receipts = factory
                .receipts_by_block(number.into())?
                .ok_or_eyre(format!("canonical receipts unavailable for block {number}"))?;
            ensure!(
                actual.result.receipts == receipts,
                "canonical receipts differ at block {number}"
            );
            consensus
                .validate_block_post_execution(&block, &actual.result, None)
                .wrap_err_with(|| {
                    format!("canonical gas/receipt-root validation failed at block {number}")
                })?;
            let root = parent
                .state_root(parent.hashed_post_state(&actual.state))
                .wrap_err_with(|| format!("state-root calculation failed at block {number}"))?;
            ensure!(
                root == block.header().state_root(),
                "canonical state root differs at block {number}: computed {root}"
            );
            transactions += receipts.len();
            if let Some(report) = &mut report {
                writeln!(
                    report,
                    "{number}\t{}\t{}\t{sequential_seconds:.9}\t{speculative_seconds:.9}\t{root}",
                    receipts.len(),
                    actual.result.gas_used
                )?;
                report.flush()?;
            }
            info!(number, transactions = receipts.len(), sequential_seconds, speculative_seconds, %root, "Differential replay verified");
        }
        info!(
            from = self.from,
            to, transactions, "Canonical differential replay completed"
        );
        Ok(())
    }
}
