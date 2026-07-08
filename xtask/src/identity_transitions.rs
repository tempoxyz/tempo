//! Find network identity transitions from epoch-boundary headers.

use std::{collections::HashMap, sync::Arc, time::Duration};

use alloy::{
    eips::BlockNumberOrTag,
    primitives::hex,
    providers::{Provider, ProviderBuilder},
};
use commonware_codec::{Encode as _, ReadExt as _};
use commonware_consensus::types::{Epoch, Epocher as _, FixedEpocher, Height};
use commonware_cryptography::bls12381::primitives::variant::{MinSig, Variant};
use eyre::{Context as _, OptionExt as _, eyre};
use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;
use tempo_chainspec::spec::TempoChainSpec;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;

/// Find identity transitions by walking epoch-boundary DKG outcomes.
#[derive(Debug, clap::Args)]
pub(crate) struct GetIdentityTransitions {
    /// Chain to inspect (mainnet, moderato, testnet, dev, or a genesis JSON path).
    #[arg(long, short, value_parser = tempo_chainspec::spec::chain_value_parser)]
    chain: Arc<TempoChainSpec>,

    /// RPC endpoint URL override. Required when the selected chainspec does not define a default.
    #[arg(long)]
    rpc_url: Option<String>,

    /// Epoch to start searching from. Defaults to the epoch containing the latest block.
    #[arg(long)]
    from_epoch: Option<u64>,

    /// Return all transitions back to genesis. By default only the newest transition is returned.
    #[arg(long)]
    full: bool,

    /// Suppress progress output. The final JSON output is still printed.
    #[arg(long)]
    quiet: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct IdentityTransitionResponse {
    /// Network identity of the requested epoch.
    identity: String,
    /// List of identity transitions, ordered newest to oldest.
    transitions: Vec<IdentityTransition>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct IdentityTransition {
    /// Epoch where the full DKG ceremony occurred.
    transition_epoch: u64,
    /// Hex-encoded BLS public key before the transition.
    old_identity: String,
    /// Hex-encoded BLS public key after the transition.
    new_identity: String,
}

#[derive(Clone)]
struct EpochOutcome {
    epoch: u64,
    identity: <MinSig as Variant>::Public,
}

impl GetIdentityTransitions {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let Self {
            chain,
            rpc_url,
            from_epoch,
            full,
            quiet,
        } = self;

        let epoch_length = chain
            .info
            .epoch_length()
            .ok_or_eyre("epochLength not found in chainspec")?;
        let rpc_url = rpc_url
            .or_else(|| chain.default_follow_url().map(str::to_owned))
            .ok_or_eyre(
                "selected chainspec does not define a default RPC URL; pass --rpc-url for a custom network",
            )?;

        let provider = ProviderBuilder::new()
            .connect(&rpc_url)
            .await
            .wrap_err("failed to connect to RPC")?;

        let epocher = FixedEpocher::new(epoch_length);
        let progress = SearchProgress::new(!quiet)?;
        progress.announce(format!(
            "RPC {rpc_url}; epoch length {}",
            epoch_length.get()
        ));

        let start_epoch = if let Some(epoch) = from_epoch {
            epoch
        } else {
            progress.set_message("fetching latest block to determine starting epoch");
            let latest = provider
                .get_block_by_number(BlockNumberOrTag::Latest)
                .await
                .wrap_err("failed to fetch latest block")?
                .ok_or_eyre("latest block not found")?;
            epocher
                .containing(Height::new(latest.header.number))
                .ok_or_eyre("epocher valid for all heights")?
                .epoch()
                .get()
        };

        progress.announce(format!("Starting Epoch {start_epoch}"));
        let response =
            search_transitions(&provider, &epocher, start_epoch, full, &progress).await?;

        progress.finish("transitions search complete");
        println!("{}", serde_json::to_string_pretty(&response)?);

        Ok(())
    }
}

async fn search_transitions<P: Provider + ?Sized>(
    provider: &P,
    epocher: &FixedEpocher,
    start_epoch: u64,
    full: bool,
    progress: &SearchProgress,
) -> eyre::Result<IdentityTransitionResponse> {
    let active_outcome_epoch = start_epoch.saturating_sub(1);

    let mut outcomes = OutcomeCache::new(provider, epocher);
    let mut current = outcomes.get(active_outcome_epoch).await?;

    let start_identity = current.identity;
    let start_identity = hex::encode(start_identity.encode());
    progress.announce(format!(
        "Identity at epoch {start_epoch}: {}",
        short_hex(&start_identity)
    ));

    let mut transitions = Vec::new();

    loop {
        if current.epoch == 0 {
            break;
        }

        progress.set_message(format!("Searching from epoch {}", current.epoch));

        let run_start = find_identity_run_start(&mut outcomes, &current, progress).await?;
        if run_start == 0 {
            break;
        }

        let previous = outcomes.get(run_start - 1).await?;
        let transition = outcomes.get(run_start).await?;
        let old_identity = hex::encode(previous.identity.encode());
        let new_identity = hex::encode(transition.identity.encode());

        progress.announce(format!(
            "Identity change at epoch {run_start}: {} -> {}",
            short_hex(&old_identity),
            short_hex(&new_identity)
        ));

        transitions.push(IdentityTransition {
            transition_epoch: run_start,
            old_identity,
            new_identity,
        });

        if !full {
            break;
        }

        current = previous;
    }

    Ok(IdentityTransitionResponse {
        identity: start_identity,
        transitions,
    })
}

async fn find_identity_run_start<P: Provider + ?Sized>(
    outcomes: &mut OutcomeCache<'_, P>,
    target: &EpochOutcome,
    progress: &SearchProgress,
) -> eyre::Result<u64> {
    let mut low = 0;
    let mut high = target.epoch;

    while low < high {
        let mid = low + (high - low) / 2;
        progress.set_message(format!("Checking midpoint epoch {mid}"));

        // Network identities do not repeat, so equality with the target identity
        // is false before the run starts and true from the run start onward.
        if outcomes.get(mid).await?.identity == target.identity {
            high = mid;
        } else {
            low = mid + 1;
        }
    }

    Ok(low)
}

struct OutcomeCache<'a, P: Provider + ?Sized> {
    provider: &'a P,
    epocher: &'a FixedEpocher,
    entries: HashMap<u64, EpochOutcome>,
}

impl<'a, P: Provider + ?Sized> OutcomeCache<'a, P> {
    fn new(provider: &'a P, epocher: &'a FixedEpocher) -> Self {
        Self {
            provider,
            epocher,
            entries: HashMap::new(),
        }
    }

    async fn get(&mut self, epoch: u64) -> eyre::Result<EpochOutcome> {
        if let Some(outcome) = self.entries.get(&epoch) {
            return Ok(outcome.clone());
        }

        let height = self
            .epocher
            .last(Epoch::new(epoch))
            .expect("fixed epocher is valid for all epochs")
            .get();
        let block = self
            .provider
            .get_block_by_number(BlockNumberOrTag::Number(height))
            .await
            .wrap_err_with(|| format!("failed to fetch block {height}"))?
            .ok_or_else(|| {
                eyre!("missing epoch-boundary block {height} for outcome epoch {epoch}")
            })?;

        let number = block.header.number;

        eyre::ensure!(
            number == height,
            "RPC returned block {number} while block {height} was requested"
        );

        let extra_data = &block.header.inner.extra_data;
        eyre::ensure!(
            !extra_data.is_empty(),
            "block {height} has empty extraData (not an epoch boundary?)"
        );

        let outcome = OnchainDkgOutcome::read(&mut extra_data.as_ref()).wrap_err_with(|| {
            format!("failed to parse DKG outcome from block {height} extraData")
        })?;

        let outcome = EpochOutcome {
            epoch,
            identity: *outcome.sharing().public(),
        };

        self.entries.insert(epoch, outcome.clone());
        Ok(outcome)
    }
}

fn short_hex(value: &str) -> String {
    if value.len() <= 24 {
        value.to_owned()
    } else {
        format!("{}...{}", &value[..12], &value[value.len() - 8..])
    }
}

struct SearchProgress {
    bar: Option<ProgressBar>,
}

impl SearchProgress {
    fn new(enabled: bool) -> eyre::Result<Self> {
        let bar = if enabled {
            let bar = ProgressBar::new_spinner();
            let style = ProgressStyle::with_template("{spinner:.cyan} {msg}")?
                .tick_strings(&["-", "\\", "|", "/"]);

            bar.set_style(style);
            bar.enable_steady_tick(Duration::from_millis(120));
            Some(bar)
        } else {
            None
        };

        Ok(Self { bar })
    }

    fn set_message(&self, message: impl Into<String>) {
        if let Some(bar) = &self.bar {
            bar.set_message(message.into());
        }
    }

    fn announce(&self, message: impl AsRef<str>) {
        if let Some(bar) = &self.bar {
            bar.suspend(|| eprintln!("{}", message.as_ref()));
        }
    }

    fn finish(&self, message: &'static str) {
        if let Some(bar) = &self.bar {
            bar.finish_with_message(message);
        }
    }
}
