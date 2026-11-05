//! Check every epoch-boundary DKG outcome against the validator config in the pre-state of its
//! block, as the payload builder fills it in and verifying validators check it.

use std::sync::Arc;

use alloy::{
    eips::{BlockId, BlockNumberOrTag},
    providers::{Provider, ProviderBuilder},
};
use commonware_codec::ReadExt as _;
use commonware_consensus::types::{Epoch, Epocher as _, FixedEpocher, Height};
use commonware_cryptography::ed25519::PublicKey;
use commonware_utils::ordered;
use eyre::{OptionExt as _, WrapErr as _, ensure, eyre};
use futures::{StreamExt as _, TryStreamExt as _, stream};
use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;
use tempo_chainspec::spec::TempoChainSpec;
use tempo_contracts::precompiles::{IValidatorConfigV2, VALIDATOR_CONFIG_V2_ADDRESS};
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;

/// Check that every boundary block's DKG outcome is what the builder fills in from state.
#[derive(Debug, clap::Args)]
pub(crate) struct CheckBoundaryOutcomes {
    /// Chain to inspect (mainnet, moderato, testnet, dev, or a genesis JSON path).
    #[arg(long, short, value_parser = tempo_chainspec::spec::chain_value_parser)]
    chain: Arc<TempoChainSpec>,

    /// RPC endpoint URL override. It must serve state at historical blocks.
    #[arg(long)]
    rpc_url: Option<String>,

    /// First epoch whose boundary block to check. Defaults to the first epoch whose boundary
    /// block's parent has ValidatorConfigV2 initialized.
    #[arg(long)]
    from_epoch: Option<u64>,

    /// Last epoch whose boundary block to check. Defaults to the last finished epoch.
    #[arg(long)]
    to_epoch: Option<u64>,

    /// Boundary blocks checked at the same time.
    #[arg(long, default_value_t = 16)]
    concurrency: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Report {
    from_epoch: u64,
    to_epoch: u64,
    checked: u64,
    mismatches: Vec<Mismatch>,
}

/// A boundary block whose outcome differs from the one derived from its pre-state.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Mismatch {
    epoch: u64,
    height: u64,
    reasons: Vec<String>,
}

impl CheckBoundaryOutcomes {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let Self {
            chain,
            rpc_url,
            from_epoch,
            to_epoch,
            concurrency,
        } = self;

        let epocher = FixedEpocher::new(
            chain
                .info
                .epoch_length()
                .ok_or_eyre("epochLength not found in chainspec")?,
        );
        let rpc_url = rpc_url
            .or_else(|| chain.default_follow_url().map(str::to_owned))
            .ok_or_eyre(
                "selected chainspec does not define a default RPC URL; pass --rpc-url for a custom network",
            )?;
        let provider = ProviderBuilder::new()
            .connect(&rpc_url)
            .await
            .wrap_err("failed to connect to RPC")?;

        let to_epoch = match to_epoch {
            Some(epoch) => epoch,
            None => {
                let latest = provider
                    .get_block_number()
                    .await
                    .wrap_err("failed to fetch the latest block number")?;
                let current = epocher
                    .containing(Height::new(latest))
                    .ok_or_eyre("epocher is valid for all heights")?;
                let epoch = if current.last().get() == latest {
                    current.epoch()
                } else {
                    current
                        .epoch()
                        .previous()
                        .ok_or_eyre("the chain has not finished its first epoch yet")?
                };
                epoch.get()
            }
        };
        let from_epoch = match from_epoch {
            Some(epoch) => epoch,
            None => {
                let initialized_at =
                    IValidatorConfigV2::new(VALIDATOR_CONFIG_V2_ADDRESS, &provider)
                        .getInitializedAtHeight()
                        .call()
                        .await
                        .wrap_err("failed to read when ValidatorConfigV2 was initialized")?;
                // The first boundary whose parent is at or after the initialization height.
                epocher
                    .containing(Height::new(initialized_at + 1))
                    .ok_or_eyre("epocher is valid for all heights")?
                    .epoch()
                    .get()
            }
        };
        eprintln!(
            "checking boundary blocks of epochs {from_epoch} to {to_epoch} against {rpc_url}"
        );
        ensure!(
            from_epoch <= to_epoch,
            "--from-epoch {from_epoch} is after --to-epoch {to_epoch}"
        );

        let progress = ProgressBar::new(to_epoch - from_epoch + 1).with_style(
            ProgressStyle::with_template("{bar:40} {pos}/{len} boundaries ({eta}) {msg}")
                .expect("valid template"),
        );
        let mut mismatches = stream::iter(from_epoch..=to_epoch)
            .map(|epoch| {
                let provider = &provider;
                let epocher = &epocher;
                let progress = &progress;
                async move {
                    let mismatch = check_boundary(provider, epocher, epoch).await?;
                    progress.inc(1);
                    if let Some(mismatch) = &mismatch {
                        progress.println(format!(
                            "epoch {} (block {}): {}",
                            mismatch.epoch,
                            mismatch.height,
                            mismatch.reasons.join("; ")
                        ));
                    }
                    Ok::<_, eyre::Report>(mismatch)
                }
            })
            .buffer_unordered(concurrency.max(1))
            .try_filter_map(|mismatch| async move { Ok(mismatch) })
            .try_collect::<Vec<_>>()
            .await?;
        progress.finish_and_clear();
        mismatches.sort_by_key(|mismatch| mismatch.epoch);

        let report = Report {
            from_epoch,
            to_epoch,
            checked: to_epoch - from_epoch + 1,
            mismatches,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
        ensure!(
            report.mismatches.is_empty(),
            "{} of {} boundary blocks do not match their pre-state",
            report.mismatches.len(),
            report.checked
        );
        Ok(())
    }
}

/// Checks the boundary block of `epoch`, which carries the outcome for the epoch after it,
/// against the validator config at its parent. Returns how it differs, if it does.
async fn check_boundary<P: Provider>(
    provider: &P,
    epocher: &FixedEpocher,
    epoch: u64,
) -> eyre::Result<Option<Mismatch>> {
    let height = epocher
        .last(Epoch::new(epoch))
        .expect("fixed epocher is valid for all epochs")
        .get();
    let block = provider
        .get_block_by_number(BlockNumberOrTag::Number(height))
        .await
        .wrap_err_with(|| format!("failed to fetch block {height}"))?
        .ok_or_else(|| eyre!("block {height} not found"))?;
    let extra_data = block.header.inner.extra_data.as_ref();

    let mut reasons = Vec::new();
    let proposed = OnchainDkgOutcome::read(&mut commonware_codec::Copying(extra_data))
        .wrap_err_with(|| format!("failed to decode the DKG outcome of block {height}"))?;

    let parent = BlockId::number(height - 1);
    let config = IValidatorConfigV2::new(VALIDATOR_CONFIG_V2_ADDRESS, provider);
    let is_initialized = config
        .isInitialized()
        .block(parent)
        .call()
        .await
        .wrap_err_with(|| format!("failed to read isInitialized at block {}", height - 1))?;
    if !is_initialized {
        reasons.push("ValidatorConfigV2 is not initialized at the parent".to_string());
    }
    let validators = config
        .getActiveValidators()
        .block(parent)
        .call()
        .await
        .wrap_err_with(|| format!("failed to read getActiveValidators at block {}", height - 1))?;
    let next_full_dkg_epoch = config
        .getNextNetworkIdentityRotationEpoch()
        .block(parent)
        .call()
        .await
        .wrap_err_with(|| {
            format!(
                "failed to read getNextNetworkIdentityRotationEpoch at block {}",
                height - 1
            )
        })?;

    let expected = tempo_evm::DkgCeremonyConfig {
        active_validators: validators,
        next_full_dkg_epoch,
    }
    .boundary_outcome(epoch + 1, proposed.output.clone());
    if proposed.epoch != expected.epoch {
        reasons.push(format!(
            "epoch is {}, expected {}",
            proposed.epoch, expected.epoch
        ));
    }
    if proposed.next_players != expected.next_players {
        reasons.push(format!(
            "next players are {}, expected {}",
            keys(&proposed.next_players),
            keys(&expected.next_players)
        ));
    }
    if proposed.is_next_full_dkg != expected.is_next_full_dkg {
        reasons.push(format!(
            "full DKG is {}, expected {}",
            proposed.is_next_full_dkg, expected.is_next_full_dkg
        ));
    }

    Ok((!reasons.is_empty()).then_some(Mismatch {
        epoch,
        height,
        reasons,
    }))
}

fn keys(set: &ordered::Set<PublicKey>) -> String {
    let keys = set.iter().map(ToString::to_string).collect::<Vec<_>>();
    format!("[{}]", keys.join(", "))
}
