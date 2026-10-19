//! Era-aware `tempo re-execute`: frozen ranges run in their era binaries, the rest in-process.

use alloy_consensus::BlockHeader as _;
use clap::{ArgMatches, FromArgMatches as _};
use eyre::{OptionExt as _, WrapErr as _};
use reth_cli_commands::common::{AccessRights, Environment, EnvironmentArgs};
use reth_cli_runner::CliRunner;
use reth_provider::{BlockNumReader as _, HeaderProvider as _};
use std::{ffi::OsString, ops::ControlFlow};
use tempo_chainspec::spec::TempoChainSpecParser;
use tempo_metabinary::{process::run_child, routing::first_block_at};
use tempo_node::node::TempoNode;
use tokio::process::Command;

/// Marks a frozen re-execute child, which must not delegate again.
const ERA_ENV: &str = "TEMPO_RE_EXECUTE_ERA";

/// Runs the frozen part of a `re-execute` range in era binaries.
///
/// Returns the argv for the remaining live range, `None` to run unchanged, or `Break` if done.
pub(crate) fn delegate(
    matches: &ArgMatches,
) -> eyre::Result<ControlFlow<(), Option<Vec<OsString>>>> {
    let Some(("re-execute", command)) = matches.subcommand() else {
        return Ok(ControlFlow::Continue(None));
    };
    if std::env::var_os(ERA_ENV).is_some() {
        return Ok(ControlFlow::Continue(None));
    }
    let env = EnvironmentArgs::<TempoChainSpecParser>::from_arg_matches(command)?;
    let Some(schedule) = crate::eras::release_schedule(&env.chain)? else {
        return Ok(ControlFlow::Continue(None));
    };
    let boundaries = schedule.boundaries()?;
    let from = command.get_one::<u64>("from").copied().unwrap_or(1);
    let to = command.get_one::<u64>("to").copied();

    let runner = CliRunner::try_default_runtime().wrap_err("failed to build re-execute runtime")?;
    let Environment {
        provider_factory, ..
    } = env.init::<TempoNode>(AccessRights::RO, runner.runtime())?;
    let best = provider_factory.best_block_number()?;
    let end_exclusive = best
        .checked_add(1)
        .ok_or_eyre("best block number overflows")?;
    let provider = &provider_factory;
    let mut ends = Vec::with_capacity(boundaries.len());
    for boundary in boundaries {
        ends.push(runner.block_on(first_block_at(
            0,
            end_exclusive,
            boundary,
            |number| async move {
                provider
                    .header_by_number(number)?
                    .map(|header| header.timestamp())
                    .ok_or_eyre("missing canonical header")
            },
        ))?);
    }
    drop(provider_factory);

    let args: Vec<OsString> = std::env::args_os().collect();
    let limit = to.map_or(best, |to| to.min(best));
    // Genesis has no parent state to execute on.
    let start = from.max(1);
    let mut from = start;
    for (era, end) in schedule.eras.iter().zip(ends) {
        let until = end.min(limit);
        if from < until {
            println!("Re-executing blocks {from}..{until} with {era}");
            let mut cmd = Command::new(&era.binary);
            cmd.args(range_args(&args[1..], from, Some(until)))
                .env(ERA_ENV, era.to_string());
            if runner
                .block_on(run_child(&era.to_string(), cmd))?
                .is_break()
            {
                return Ok(ControlFlow::Break(()));
            }
        }
        from = from.max(end);
    }

    if from == start {
        Ok(ControlFlow::Continue(None))
    } else if from < limit {
        let mut live = vec![args[0].clone()];
        live.extend(range_args(&args[1..], from, to));
        Ok(ControlFlow::Continue(Some(live)))
    } else {
        Ok(ControlFlow::Break(()))
    }
}

/// Replaces `--from` and `--to` in `args`, keeping the rest in order.
fn range_args(args: &[OsString], from: u64, to: Option<u64>) -> Vec<OsString> {
    let mut kept = Vec::with_capacity(args.len() + 2);
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--from" | "--to") => {
                args.next();
            }
            Some(flag) if flag.starts_with("--from=") || flag.starts_with("--to=") => {}
            _ => kept.push(arg.clone()),
        }
    }
    kept.push(format!("--from={from}").into());
    if let Some(to) = to {
        kept.push(format!("--to={to}").into());
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_args_replace_bounds() {
        let args = |line: &str| {
            line.split_whitespace()
                .map(OsString::from)
                .collect::<Vec<_>>()
        };
        let operator = args("re-execute --from 5 --chain mainnet --to=90 --num-tasks 4");
        for (args_in, to, expected) in [
            (
                &operator[..],
                Some(20),
                "re-execute --chain mainnet --num-tasks 4 --from=10 --to=20",
            ),
            (&operator[..1], None, "re-execute --from=10"),
        ] {
            assert_eq!(range_args(args_in, 10, to), args(expected));
        }
    }
}
