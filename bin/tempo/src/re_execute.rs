//! Re-execute frozen eras with their own workers before the live binary continues.

use crate::eras;
use alloy_consensus::BlockHeader as _;
use clap::{ArgMatches, FromArgMatches as _};
use eyre::{OptionExt as _, Result};
use reth_cli_commands::common::{AccessRights, EnvironmentArgs};
use reth_cli_runner::CliRunner;
use reth_ethereum::tasks::RuntimeConfig;
use reth_storage_api::{BlockNumReader as _, HeaderProvider as _};
use std::{ffi::OsString, num::NonZeroUsize, ops::ControlFlow};
use tempo_chainspec::spec::TempoChainSpecParser;
use tempo_metabinary::process::run_child;
use tempo_node::TempoNode;
use tokio::process::Command;

/// Marks a worker's own re-execution, so a misconfigured catalog cannot delegate it again.
const WORKER_ERA_ENV: &str = "TEMPO_RE_EXECUTE_ERA";

/// Runs the parts of a `re-execute` range owned by frozen eras in their workers, in block order.
/// Returns arguments restricting the live binary to the remaining range, or breaks if none remains.
pub(crate) fn prepare(
    matches: &ArgMatches,
    args: Vec<OsString>,
) -> Result<ControlFlow<(), Option<Vec<OsString>>>> {
    let Some(("re-execute", command)) = matches.subcommand() else {
        return Ok(ControlFlow::Continue(None));
    };
    let environment = EnvironmentArgs::<TempoChainSpecParser>::from_arg_matches(command)?;
    let schedule = match eras::release_schedule(&environment.chain)? {
        Some(schedule) if std::env::var_os(WORKER_ERA_ENV).is_none() => schedule,
        _ => return Ok(ControlFlow::Continue(None)),
    };
    let runner = CliRunner::try_with_runtime_config(
        RuntimeConfig::default().with_cpu_cores(NonZeroUsize::MIN),
    )?;
    let (best, ends) = {
        let factory = environment
            .init::<TempoNode>(AccessRights::RO, runner.runtime())?
            .provider_factory;
        let provider = factory.provider()?;
        let best = provider.best_block_number()?;
        // Each frozen era ends before the first local block of its successor.
        let ends = schedule
            .boundaries()?
            .into_iter()
            .map(|timestamp| {
                first_block_at(best, timestamp, |number| {
                    Ok(provider
                        .header_by_number(number)?
                        .ok_or_eyre("missing canonical header")?
                        .timestamp())
                })
            })
            .collect::<Result<Vec<_>>>()?;
        (best, ends)
    };

    // Reth re-executes `from..to`, clamping `to` to the best block. Genesis has no parent state.
    let to = command.get_one::<u64>("to").copied();
    let limit = to.map_or(best, |to| to.min(best));
    let start = (*command.get_one::<u64>("from").expect("defaulted")).max(1);
    let (program, args) = args.split_first().ok_or_eyre("missing program name")?;
    runner.block_on(async {
        let mut from = start;
        for (era, end) in schedule.eras.iter().zip(ends) {
            let until = end.min(limit);
            if from < until {
                eprintln!("Re-executing blocks {from}..{until} with {era}");
                let mut worker = Command::new(&era.binary);
                worker
                    .args(range_args(args, from, Some(until)))
                    .env(WORKER_ERA_ENV, era.to_string());
                if run_child(&format!("{era} re-execution"), &mut worker)
                    .await?
                    .is_break()
                {
                    return Ok(ControlFlow::Break(()));
                }
            }
            from = from.max(end);
        }
        Ok(if from == start {
            ControlFlow::Continue(None)
        } else if from < limit {
            let live = std::iter::once(program.clone()).chain(range_args(args, from, to));
            ControlFlow::Continue(Some(live.collect()))
        } else {
            ControlFlow::Break(())
        })
    })
}

/// The first block in `0..=best` whose timestamp is at least `timestamp`, or `best + 1` if none.
/// Canonical timestamps strictly increase, so this reads `O(log best)` headers.
fn first_block_at(
    best: u64,
    timestamp: u64,
    mut timestamp_of: impl FnMut(u64) -> Result<u64>,
) -> Result<u64> {
    let mut low = 0;
    let mut high = best
        .checked_add(1)
        .ok_or_eyre("best block number overflows")?;
    while low < high {
        let middle = low + (high - low) / 2;
        if timestamp_of(middle)? < timestamp {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    Ok(low)
}

/// The operator's arguments with the block range replaced.
fn range_args(args: &[OsString], from: u64, to: Option<u64>) -> Vec<OsString> {
    let mut args = args.iter();
    let mut ranged = Vec::new();
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--from" | "--to") => {
                args.next();
            }
            Some(arg) if arg.starts_with("--from=") || arg.starts_with("--to=") => {}
            _ => ranged.push(arg.clone()),
        }
    }
    ranged.push(format!("--from={from}").into());
    ranged.extend(to.map(|to| format!("--to={to}").into()));
    ranged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn era_ends_at_first_block_reaching_activation() {
        let timestamps = [0, 10, 20, 30];
        let best = timestamps.len() as u64 - 1;
        let search = |timestamp| {
            first_block_at(best, timestamp, |number| Ok(timestamps[number as usize])).unwrap()
        };
        for (activation, end) in [(1, 1), (10, 1), (11, 2), (30, 3), (31, 4)] {
            assert_eq!(search(activation), end, "activation {activation}");
        }
        let error = first_block_at(best, 15, |_| Err(eyre::eyre!("missing canonical header")));
        assert_eq!(error.unwrap_err().to_string(), "missing canonical header");
        let error = first_block_at(u64::MAX, 15, |_| Ok(0));
        assert_eq!(
            error.unwrap_err().to_string(),
            "best block number overflows"
        );
    }

    #[test]
    fn range_arguments_replace_operator_bounds() {
        let args = |args: &[&str]| args.iter().map(OsString::from).collect::<Vec<_>>();
        let operator = args(&[
            "re-execute",
            "--from",
            "0",
            "--datadir=/a b",
            "--to=200",
            "-v",
        ]);
        assert_eq!(
            range_args(&operator, 1, Some(100)),
            args(&["re-execute", "--datadir=/a b", "-v", "--from=1", "--to=100"])
        );
        assert_eq!(
            range_args(&args(&["re-execute"]), 100, None),
            args(&["re-execute", "--from=100"])
        );
    }
}
