//! Transfer exclusive execution storage ownership through the frozen eras to the live node.

use crate::{TempoCli, eras};
use eyre::{OptionExt as _, Result, ensure};
use reth_cli_commands::common::{AccessRights, EnvironmentArgs};
use reth_cli_runner::CliRunner;
use reth_ethereum::{
    chainspec::EthChainSpec as _,
    cli::Commands,
    tasks::{Runtime, RuntimeConfig},
};
use reth_storage_api::{BlockHashReader as _, BlockNumReader as _, ChainStateBlockReader as _};
use std::{ffi::OsString, num::NonZeroUsize, ops::ControlFlow};
use tempo_chainspec::spec::TempoChainSpecParser;
use tempo_metabinary::{catalog::FrozenEra, process::run_child};
use tempo_node::TempoNode;
use tokio::process::Command;

/// Runs the frozen writers in order before live components can open or execute historical storage.
/// Modes that skip the writers require storage at the last checkpoint.
/// The returned flag requests a certified consensus anchor, including after an interrupted handoff.
pub(crate) fn prepare(cli: &TempoCli) -> Result<ControlFlow<(), bool>> {
    let Commands::Node(node) = &cli.command else {
        return Ok(ControlFlow::Continue(false));
    };
    let Some(schedule) = eras::release_schedule(&node.chain)? else {
        return Ok(ControlFlow::Continue(false));
    };
    let Some(last) = schedule.eras.last().map(|era| era.checkpoint) else {
        return Ok(ControlFlow::Continue(false));
    };
    let skips_handoff = node.dev.dev
        || node.debug.tip.is_some()
        || node.debug.max_block.is_some()
        || node.debug.terminate
        || node.debug.rpc_consensus_url.is_some()
        || node.debug.etherscan.is_some();
    let environment = EnvironmentArgs {
        chain: node.chain.clone(),
        datadir: node.datadir.clone(),
        config: node.config.clone(),
        db: node.db,
        static_files: node.static_files,
        storage: node.storage,
    };
    let runner = CliRunner::try_with_runtime_config(
        RuntimeConfig::default().with_cpu_cores(NonZeroUsize::MIN),
    )?;
    runner.block_on(async {
        let mut progress = durable_progress(&environment, runner.runtime(), &schedule.eras)?;
        if skips_handoff {
            ensure!(
                progress.is_some_and(|(head, _)| head >= last.number),
                "--dev and --debug sync modes skip historical sync, which must first reach block {}",
                last.number
            );
            return Ok(ControlFlow::Continue(false));
        }
        for era in &schedule.eras {
            let checkpoint = era.checkpoint;
            if progress.is_some_and(|(head, _)| head >= checkpoint.number) {
                continue;
            }
            eprintln!("Syncing {era} through block {}", checkpoint.number);
            if run_child(
                &format!("{era} historical sync"),
                Command::new(&era.binary)
                    .args(frozen_args(std::env::args_os().skip(1)))
                    .env_remove("TEMPO_FOLLOW")
                    .arg("--history-sync")
                    .arg(format!("--debug.tip={}", checkpoint.hash))
                    .arg(format!("--debug.max-block={}", checkpoint.number))
                    .arg("--debug.terminate"),
            )
            .await?
            .is_break()
            {
                return Ok(ControlFlow::Break(()));
            }
            progress = durable_progress(&environment, runner.runtime(), &schedule.eras)?;
            let (head, _) = progress.ok_or_eyre("historical sync did not initialize storage")?;
            ensure!(
                head == checkpoint.number,
                "{era} historical sync did not finish at its pinned checkpoint"
            );
        }
        let (_, finalized) = progress.ok_or_eyre("historical sync did not initialize storage")?;
        Ok(ControlFlow::Continue(finalized <= last.number))
    })
}

fn durable_progress(
    environment: &EnvironmentArgs<TempoChainSpecParser>,
    runtime: Runtime,
    eras: &[FrozenEra],
) -> Result<Option<(u64, u64)>> {
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
    let Some(genesis) = provider.block_hash(0)? else {
        return Ok(None);
    };
    ensure!(
        genesis == environment.chain.genesis_hash(),
        "chain specification does not match the database genesis"
    );
    let number = provider.best_block_number()?;
    for checkpoint in eras
        .iter()
        .map(|era| era.checkpoint)
        .filter(|checkpoint| checkpoint.number <= number)
    {
        ensure!(
            provider.block_hash(checkpoint.number)? == Some(checkpoint.hash),
            "historical canonical checkpoint hash mismatch"
        );
    }
    Ok(Some((
        number,
        provider.last_finalized_block_number()?.unwrap_or_default(),
    )))
}

fn frozen_args(args: impl IntoIterator<Item = OsString>) -> impl Iterator<Item = OsString> {
    let mut args = args.into_iter().peekable();
    std::iter::from_fn(move || {
        loop {
            let arg = args.next()?;
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
                return Some(arg);
            }
        }
    })
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
                frozen_args(args).collect::<Vec<_>>(),
                ["node", "--datadir", "data with spaces"].map(OsString::from)
            );
        }
    }
}
