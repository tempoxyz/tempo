//! Startup handoff that syncs frozen eras with their writer binaries before the node opens storage.

use crate::{TempoCli, eras};
use eyre::{OptionExt as _, WrapErr as _, ensure};
use reth_chainspec::EthChainSpec as _;
use reth_cli_runner::CliRunner;
use reth_ethereum::{
    cli::Commands,
    node::core::dirs::{ChainPath, DataDirPath},
    provider::providers::ReadOnlyConfig,
    tasks::Runtime,
};
use reth_provider::{BlockHashReader as _, BlockNumReader as _, ChainStateBlockReader as _};
use std::{ffi::OsString, ops::ControlFlow, sync::Arc};
use tempo_chainspec::spec::TempoChainSpec;
use tempo_metabinary::{catalog::FrozenEra, process::run_child};
use tempo_node::node::TempoNode;
use tokio::process::Command;

/// Syncs every frozen era the durable head hasn't reached, for `tempo node` with a schedule.
///
/// Returns `Break` on shutdown, else whether finality is still within the frozen eras.
pub(crate) fn prepare(cli: &TempoCli) -> eyre::Result<ControlFlow<(), bool>> {
    let Commands::Node(node) = &cli.command else {
        return Ok(ControlFlow::Continue(false));
    };
    let Some(schedule) = eras::release_schedule(&node.chain)? else {
        return Ok(ControlFlow::Continue(false));
    };
    let last = schedule
        .eras
        .last()
        .ok_or_eyre("release schedules have at least one era")?
        .checkpoint;
    let datadir = node.datadir.clone().resolve_datadir(node.chain.chain());
    let runner = CliRunner::try_default_runtime().wrap_err("failed to build history runtime")?;
    let mut progress = durable_progress(&node.chain, &datadir, &schedule.eras, runner.runtime())?;

    let debug = &node.debug;
    if node.dev.dev
        || debug.tip.is_some()
        || debug.max_block.is_some()
        || debug.terminate
        || debug.rpc_consensus_url.is_some()
        || debug.etherscan.is_some()
    {
        ensure!(
            progress.is_some_and(|(best, _)| best >= last.number),
            "--dev and --debug sync modes skip historical sync, which must first reach block {}",
            last.number
        );
        return Ok(ControlFlow::Continue(false));
    }

    let args = frozen_args(std::env::args_os().skip(1));
    for era in &schedule.eras {
        let checkpoint = era.checkpoint;
        if progress.is_some_and(|(best, _)| best >= checkpoint.number) {
            continue;
        }
        println!("Syncing {era} through block {}", checkpoint.number);
        let mut cmd = Command::new(&era.binary);
        cmd.args(&args)
            .arg("--history-sync")
            .arg(format!("--debug.tip={}", checkpoint.hash))
            .arg(format!("--debug.max-block={}", checkpoint.number))
            .arg("--debug.terminate")
            .env_remove("TEMPO_FOLLOW");
        if runner
            .block_on(run_child(&era.to_string(), cmd))?
            .is_break()
        {
            return Ok(ControlFlow::Break(()));
        }
        progress = durable_progress(&node.chain, &datadir, &schedule.eras, runner.runtime())?;
        ensure!(
            progress.map(|(best, _)| best) == Some(checkpoint.number),
            "{era} historical sync did not finish at its pinned checkpoint"
        );
    }
    let finalized = progress.map_or(0, |(_, finalized)| finalized);
    Ok(ControlFlow::Continue(finalized <= last.number))
}

/// Returns durable `(best, finalized)`, `None` if fresh, failing on mismatched checkpoints.
fn durable_progress(
    chain: &Arc<TempoChainSpec>,
    datadir: &ChainPath<DataDirPath>,
    eras: &[FrozenEra],
    runtime: Runtime,
) -> eyre::Result<Option<(u64, u64)>> {
    if !datadir.db().join("mdbx.dat").exists() {
        return Ok(None);
    }
    let config = ReadOnlyConfig::from_dirs(datadir.db(), datadir.static_files(), datadir.rocksdb());
    let factory = TempoNode::provider_factory_builder()
        .open_read_only(chain.clone(), config, runtime)
        .wrap_err("failed to open storage read-only")?;
    ensure!(
        factory.block_hash(0)? == Some(chain.genesis_hash()),
        "chain specification does not match the database genesis"
    );
    let best = factory.best_block_number()?;
    for era in eras.iter().filter(|era| era.checkpoint.number <= best) {
        ensure!(
            factory.block_hash(era.checkpoint.number)? == Some(era.checkpoint.hash),
            "historical canonical checkpoint hash mismatch"
        );
    }
    let finalized = factory
        .provider()?
        .last_finalized_block_number()?
        .unwrap_or_default();
    Ok(Some((best, finalized)))
}

/// Returns the operator's arguments without follow mode.
fn frozen_args(args: impl IntoIterator<Item = OsString>) -> Vec<OsString> {
    let mut args = args.into_iter().peekable();
    let mut kept = Vec::new();
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--follow") => {
                if args
                    .peek()
                    .is_some_and(|value| !value.to_string_lossy().starts_with('-'))
                {
                    args.next();
                }
            }
            Some("--follow.upstream-request-timeout") => {
                args.next();
            }
            Some(flag) if flag.starts_with("--follow=") || flag.starts_with("--follow.") => {}
            _ => kept.push(arg),
        }
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_args_strip_follow_mode() {
        let args = [
            "node",
            "--follow",
            "--datadir",
            "data with spaces",
            "--follow",
            "wss://rpc.presto.tempo.xyz",
            "--follow=auto",
            "--follow.nocertify",
            "--follow.upstream-request-timeout",
            "5s",
            "--follow.upstream-request-timeout=5s",
            "--follow",
            "--http",
        ]
        .map(OsString::from);
        assert_eq!(
            frozen_args(args),
            ["node", "--datadir", "data with spaces", "--http"].map(OsString::from)
        );
    }
}
