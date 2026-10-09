//! Transfer exclusive execution storage ownership from the frozen era to the live node.

use crate::{TempoCli, eras};
use alloy::eips::BlockNumHash;
use eyre::{OptionExt as _, Result, ensure};
use reth_cli_commands::common::{AccessRights, EnvironmentArgs};
use reth_cli_runner::CliRunner;
use reth_ethereum::{chainspec::EthChainSpec as _, cli::Commands, tasks::Runtime};
use reth_storage_api::{BlockHashReader as _, BlockNumReader as _, ChainStateBlockReader as _};
use std::{ffi::OsString, ops::ControlFlow};
use tempo_chainspec::spec::TempoChainSpecParser;
use tempo_metabinary::process::{shutdown_children, shutdown_signal, spawn_child};
use tempo_node::TempoNode;
use tokio::process::Command;

/// Runs the frozen writer before live components can open or execute historical storage.
/// The returned flag requests a certified consensus anchor, including after an interrupted handoff.
pub(crate) fn prepare(cli: &TempoCli) -> Result<ControlFlow<(), bool>> {
    let Commands::Node(node) = &cli.command else {
        return Ok(ControlFlow::Continue(false));
    };
    if node.dev.dev
        || node.ext.history_sync
        || node.debug.tip.is_some()
        || node.debug.max_block.is_some()
        || node.debug.terminate
        || node.debug.rpc_consensus_url.is_some()
        || node.debug.etherscan.is_some()
        || !eras::supports_release_catalog(&node.chain)
    {
        return Ok(ControlFlow::Continue(false));
    }
    let catalog = eras::release_catalog()?;
    let Some(schedule) = catalog.for_chain(node.chain.chain_id(), node.chain.genesis_hash()) else {
        return Ok(ControlFlow::Continue(false));
    };
    ensure!(
        schedule.eras.len() == 2,
        "network handoff requires one frozen era"
    );
    let era = &schedule.eras[0];
    let checkpoint = era
        .checkpoint
        .ok_or_eyre("release has no historical sync checkpoint")?;
    let environment = EnvironmentArgs {
        chain: node.chain.clone(),
        datadir: node.datadir.clone(),
        config: node.config.clone(),
        db: node.db,
        static_files: node.static_files,
        storage: node.storage,
    };
    let runner = CliRunner::try_default_runtime()?;
    let mut head = durable_head(&environment, runner.runtime(), checkpoint)?;
    runner.block_on(async {
        if head.is_none_or(|(head, _)| head.number < checkpoint.number) {
            eprintln!("Syncing {} through block {}", era.name, checkpoint.number);
            let mut child = spawn_child(
                Command::new(era.binary.as_ref().expect("validated frozen executable"))
                    .args(frozen_args(std::env::args_os().skip(1)))
                    .env_remove("TEMPO_FOLLOW")
                    .args([
                        "--history-sync".into(),
                        format!("--debug.tip={}", checkpoint.hash),
                        format!("--debug.max-block={}", checkpoint.number),
                        "--debug.terminate".into(),
                    ]),
            )?;
            let result = tokio::select! {
                status = child.wait() => status.map(Some).map_err(Into::into),
                result = shutdown_signal() => result.map(|_| None),
            };
            let shutdown = shutdown_children([("historical sync", &mut child)]).await;
            let status = result?;
            shutdown?;
            let Some(status) = status else {
                return Ok(ControlFlow::Break(()));
            };
            ensure!(status.success(), "historical sync exited with {status}");
            head = durable_head(&environment, runner.runtime(), checkpoint)?;
            let (head, _) = head.ok_or_eyre("historical sync did not initialize storage")?;
            ensure!(
                head == checkpoint,
                "historical sync did not finish at its pinned checkpoint"
            );
        }
        let (_, finalized) = head.ok_or_eyre("historical sync did not initialize storage")?;
        Ok(ControlFlow::Continue(finalized <= checkpoint.number))
    })
}

fn durable_head(
    environment: &EnvironmentArgs<TempoChainSpecParser>,
    runtime: Runtime,
    checkpoint: BlockNumHash,
) -> Result<Option<(BlockNumHash, u64)>> {
    let datadir = environment
        .datadir
        .clone()
        .resolve_datadir(environment.chain.chain());
    if !datadir.db().join("mdbx.dat").try_exists()? {
        return Ok(None);
    }
    let factory = environment
        .init::<TempoNode>(AccessRights::RO, runtime)?
        .provider_factory;
    let provider = factory.provider()?;
    ensure!(
        provider.block_hash(0)? == Some(environment.chain.genesis_hash()),
        "chain specification does not match the database genesis"
    );
    let number = provider.best_block_number()?;
    let hash = provider
        .block_hash(number)?
        .ok_or_eyre("durable execution head is missing")?;
    if number >= checkpoint.number {
        ensure!(
            provider.block_hash(checkpoint.number)? == Some(checkpoint.hash),
            "historical canonical checkpoint hash mismatch"
        );
    }
    Ok(Some((
        BlockNumHash::new(number, hash),
        provider.last_finalized_block_number()?.unwrap_or_default(),
    )))
}

fn frozen_args(args: impl IntoIterator<Item = OsString>) -> Vec<OsString> {
    let mut args = args.into_iter().peekable();
    let mut frozen = Vec::new();
    while let Some(arg) = args.next() {
        let value = arg.to_str().unwrap_or_default();
        let key = value.split('=').next().unwrap_or_default();
        if key == "--follow" || key.starts_with("--follow.") {
            if !value.contains('=')
                && (key == "--follow.upstream-request-timeout"
                    || key == "--follow"
                        && args
                            .peek()
                            .is_some_and(|arg| !arg.to_string_lossy().starts_with('-')))
            {
                args.next();
            }
        } else {
            frozen.push(arg);
        }
    }
    frozen
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_writer_keeps_operator_options_without_live_follow_targets() {
        for follow in ["--follow", "--follow=auto", "--follow ws://upstream:8546"] {
            let args = format!(
                "node {follow} --follow.nocertify --follow.upstream-request-timeout 2s --follow.experimental.certify --datadir"
            );
            let args = args
                .split_whitespace()
                .map(OsString::from)
                .chain(["data with spaces".into()]);
            assert_eq!(
                frozen_args(args),
                ["node", "--datadir", "data with spaces"].map(OsString::from)
            );
        }
    }
}
