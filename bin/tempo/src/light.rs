//! Independent light-mode startup. Never constructs a full-node builder or execution database.

use clap::{ArgMatches, Command, parser::ValueSource};
use eyre::{OptionExt as _, WrapErr as _};
use reth_ethereum::chainspec::EthChainSpec as _;
use std::{fmt, net::SocketAddr, num::NonZeroU32, path::PathBuf, sync::Arc, time::Duration};
use tempo_chainspec::{TempoChainSpec, TempoHardfork};
use tempo_light::{
    client::Client,
    config::{Layout, Limits, Network},
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, clap::Args)]
pub(crate) struct LightArgs {
    /// Run a native read-only TIP-20 light client, without execution or validator credentials.
    #[arg(
        id = "light",
        long = "light",
        conflicts_with = "follow",
        requires = "light_upstream"
    )]
    pub enabled: bool,
    /// Untrusted HTTP(S) evidence endpoint. Repeat for availability/failover (at most eight).
    #[arg(
        long = "light.upstream",
        requires = "light",
        env = "TEMPO_LIGHT_UPSTREAM"
    )]
    pub light_upstream: Vec<String>,
    /// Separate light checkpoint storage; never an execution database.
    #[arg(id = "light_datadir", long = "light.datadir", requires = "light")]
    pub datadir: Option<PathBuf>,
    /// Local read API address. Remote bindings require --light.allow-remote.
    #[arg(
        id = "light_listen",
        long = "light.listen",
        default_value = "127.0.0.1:8645",
        requires = "light"
    )]
    pub listen: SocketAddr,
    #[arg(
        id = "light_allow_remote",
        long = "light.allow-remote",
        requires = "light"
    )]
    pub allow_remote: bool,
    #[arg(id = "light_request_timeout_ms", long = "light.request-timeout-ms", default_value_t = 3000, value_parser = clap::value_parser!(u64).range(1..=60_000), requires = "light")]
    pub request_timeout_ms: u64,
    #[arg(id = "light_read_timeout_ms", long = "light.read-timeout-ms", default_value_t = 15_000, value_parser = clap::value_parser!(u64).range(1..=300_000), requires = "light")]
    pub read_timeout_ms: u64,
    #[arg(id = "light_poll_interval_ms", long = "light.poll-interval-ms", default_value_t = 500, value_parser = clap::value_parser!(u64).range(100..=60_000), requires = "light")]
    pub poll_interval_ms: u64,
    #[arg(id = "light_read_concurrency", long = "light.read-concurrency", default_value_t = 8, value_parser = clap::value_parser!(u32).range(1..=64), requires = "light")]
    pub read_concurrency: u32,
    #[arg(
        id = "light_account_cache",
        long = "light.account-cache",
        default_value = "4096",
        requires = "light"
    )]
    pub account_cache: NonZeroU32,
    #[arg(
        id = "light_slot_cache",
        long = "light.slot-cache",
        default_value = "16384",
        requires = "light"
    )]
    pub slot_cache: NonZeroU32,
    #[arg(id = "light_transition_search", long = "light.transition-search", default_value_t = 32, value_parser = clap::value_parser!(u64).range(1..=1024), requires = "light")]
    pub transition_search: u64,
}

impl fmt::Debug for LightArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Full TempoArgs can be debug logged; endpoint URLs can contain passwords/API keys.
        f.debug_struct("LightArgs")
            .field("enabled", &self.enabled)
            .field("upstream_count", &self.light_upstream.len())
            .finish_non_exhaustive()
    }
}

/// Allow only chain selection, light flags, and top-level logging/tracing flags. Reject explicit
/// full-node options, including environment-sourced ones, rather than silently ignoring them.
pub(crate) fn validate_options(root: &Command, matches: &ArgMatches) -> eyre::Result<()> {
    let node = matches
        .subcommand_matches("node")
        .ok_or_eyre("light mode requires node command")?;
    let command = root
        .find_subcommand("node")
        .ok_or_eyre("missing node command")?;
    for id in node.ids() {
        if !matches!(
            node.value_source(id.as_str()),
            Some(ValueSource::CommandLine | ValueSource::EnvVariable)
        ) {
            continue;
        }
        let arg = command
            .get_arguments()
            .chain(root.get_arguments())
            .find(|arg| arg.get_id() == id);
        let Some(arg) = arg else {
            continue;
        }; // Implicit Clap groups are not options.
        let long = arg.get_long().unwrap_or(id.as_str());
        let global = root.get_arguments().any(|arg| arg.get_id() == id);
        if long != "chain" && long != "light" && !long.starts_with("light.") && !global {
            eyre::bail!(
                "--{long} is incompatible with --light; use only chain selection, light options, and logging/tracing options"
            );
        }
    }
    Ok(())
}

fn network(chain: &TempoChainSpec) -> eyre::Result<Network> {
    let anchor = chain.network_identity.clone().ok_or_eyre("light mode requires a configured chain network identity (use an explicitly anchored devnet genesis, not RPC discovery)")?;
    let epoch_length = chain
        .info
        .epoch_length()
        .ok_or_eyre("light mode requires configured epochLength")?;
    let extras = serde_json::to_value(&chain.genesis().config.extra_fields)?;
    let mut unsupported_layout_from = None;
    // Unknown future Tempo forks must not silently inherit this binary's layout interpretation.
    for (name, value) in extras
        .as_object()
        .ok_or_eyre("invalid chain extra fields")?
    {
        if name.starts_with('t')
            && name.ends_with("Time")
            && name.as_bytes().get(1).is_some_and(u8::is_ascii_digit)
        {
            let supported = TempoHardfork::VARIANTS.iter().any(|fork| {
                *fork as u64 <= TempoHardfork::T14 as u64
                    && fork.genesis_key() == Some(name.as_str())
            });
            if !supported && !value.is_null() {
                let timestamp = value
                    .as_u64()
                    .ok_or_eyre("unknown fork activation must be a timestamp")?;
                unsupported_layout_from =
                    Some(unsupported_layout_from.map_or(timestamp, |old: u64| old.min(timestamp)));
            }
        }
    }
    Ok(Network {
        chain_id: chain.chain().id(),
        genesis_hash: chain.genesis_hash(),
        anchor,
        epoch_length,
        layout: Layout::V1,
        unsupported_layout_from,
    })
}

pub(crate) async fn run(chain: Arc<TempoChainSpec>, args: LightArgs) -> eyre::Result<()> {
    if !args.listen.ip().is_loopback() && !args.allow_remote {
        eyre::bail!("non-loopback light API requires --light.allow-remote");
    }
    let network = network(&chain)?;
    // Parse URLs here, not in Clap: parse diagnostics must not print credential-bearing inputs.
    let urls = args
        .light_upstream
        .iter()
        .map(|url| {
            url.parse()
                .map_err(|_| eyre::eyre!("invalid light upstream URL"))
        })
        .collect::<eyre::Result<Vec<_>>>()?;
    let datadir = match args.datadir {
        Some(path) => path,
        None => {
            let home = std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .ok_or_eyre("set --light.datadir when no home directory is configured")?;
            PathBuf::from(home).join(".tempo/light").join(format!(
                "{}-{}",
                network.chain_id,
                &network.genesis_hash.to_string()[2..18]
            ))
        }
    };
    let limits = Limits {
        request_timeout: Duration::from_millis(args.request_timeout_ms),
        read_timeout: Duration::from_millis(args.read_timeout_ms),
        poll_interval: Duration::from_millis(args.poll_interval_ms),
        read_concurrency: args.read_concurrency as usize,
        account_cache: args.account_cache,
        slot_cache: args.slot_cache,
        max_transition_search: args.transition_search,
        ..Default::default()
    };
    let interval = limits.poll_interval;
    let client =
        tokio::task::spawn_blocking(move || Client::open(network, urls, datadir, limits)).await??;
    let (server, address) =
        tempo_light::server::serve(client.clone(), args.listen, args.allow_remote).await?;
    tracing::info!(%address, "TIP-20 light read API started; no execution database or validator services");
    let stop = CancellationToken::new();
    let poll_stop = stop.clone();
    let poll = tokio::spawn(async move {
        let mut timer = tokio::time::interval(interval);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! { _ = poll_stop.cancelled() => break, _ = timer.tick() => {} }
            if let Err(error) = client.refresh().await {
                tracing::warn!(kind = ?error.kind(), "light head refresh failed; accepted progress has not regressed");
            }
        }
    });
    let closed = server.clone();
    let result = tokio::select! {
        result = shutdown_signal() => result,
        _ = closed.stopped() => Err(eyre::eyre!("light read API stopped unexpectedly")),
    };
    stop.cancel();
    // Finish any critical checkpoint publication before dropping the storage lock/runtime.
    poll.await.wrap_err("light head tracking task stopped")?;
    let _ = server.stop();
    server.stopped().await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::TempoCli;
    use clap::{CommandFactory as _, FromArgMatches as _};
    use reth_ethereum::cli::Commands;

    const UPSTREAM: &str = "http://user:__light_endpoint_secret__@127.0.0.1:8545/private-api-key";

    #[test]
    fn light_starts_without_credentials_and_redacts_endpoint_debug() {
        crate::tests::init_defaults_once();
        let command = TempoCli::command();
        let matches = command
            .clone()
            .try_get_matches_from([
                "tempo",
                "node",
                "--light",
                "--light.upstream",
                UPSTREAM,
                "--chain",
                "moderato",
            ])
            .unwrap();
        validate_options(&command, &matches).unwrap();
        let cli = TempoCli::from_arg_matches(&matches).unwrap();
        let Commands::Node(node) = cli.command else {
            panic!("expected node");
        };
        assert!(!node.ext.has_consensus_engine(false));
        assert!(!node.ext.has_gossip(false));
        let debug = format!("{:?}", node.ext);
        assert!(!debug.contains("__light_endpoint_secret__"));
        assert!(!debug.contains("private-api-key"));
        network(&node.chain).unwrap().validate().unwrap();
    }

    #[test]
    fn follow_and_light_are_mutually_exclusive_and_upstream_is_required() {
        crate::tests::init_defaults_once();
        for extra in [vec!["--follow"], vec![]] {
            let mut args = vec!["tempo", "node", "--light"];
            if !extra.is_empty() {
                args.extend(["--light.upstream", UPSTREAM]);
            }
            args.extend(extra);
            assert!(TempoCli::command().try_get_matches_from(args).is_err());
        }
        assert!(
            TempoCli::command()
                .try_get_matches_from(["tempo", "node", "--light.upstream", UPSTREAM])
                .is_err()
        );
    }

    #[test]
    fn explicit_execution_validator_and_database_options_are_rejected() {
        crate::tests::init_defaults_once();
        for extra in [
            vec!["--http"],
            vec!["--dev"],
            vec!["--datadir", "/not-opened"],
            vec!["--consensus.signing-key", "/not-opened"],
            vec!["--consensus.listen-address", "127.0.0.1:8123"],
            vec!["--port", "8123"],
            vec!["--builder.parallel"],
        ] {
            let command = TempoCli::command();
            let mut args = vec!["tempo", "node", "--light", "--light.upstream", UPSTREAM];
            args.extend(extra);
            let matches = command.clone().try_get_matches_from(args).unwrap();
            assert!(validate_options(&command, &matches).is_err());
        }
    }

    #[test]
    fn ordinary_node_and_follow_defaults_do_not_require_light() {
        crate::tests::init_defaults_once();
        for args in [
            vec!["tempo", "node", "--dev"],
            vec!["tempo", "node", "--follow"],
        ] {
            let matches = TempoCli::command().try_get_matches_from(args).unwrap();
            let cli = TempoCli::from_arg_matches(&matches).unwrap();
            let Commands::Node(node) = cli.command else {
                panic!("expected node");
            };
            assert!(!node.ext.light.enabled);
        }
    }
}

async fn shutdown_signal() -> eyre::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! { result = tokio::signal::ctrl_c() => result?, _ = terminate.recv() => {} }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}
