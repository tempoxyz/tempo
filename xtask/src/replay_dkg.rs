//! Replay a DKG ceremony by fetching blocks from RPC and using dkg::observe.

use std::collections::BTreeMap;

use alloy::{
    primitives::{B256, Bytes},
    providers::{Provider, ProviderBuilder},
};
use commonware_codec::{Read as _, ReadExt as _};
use commonware_consensus::types::{Epoch, Epocher as _, FixedEpocher};
use commonware_cryptography::{
    bls12381::{
        dkg::{self, Info, SignedDealerLog},
        primitives::{sharing::Mode, variant::MinSig},
    },
    ed25519::{PrivateKey, PublicKey},
};
use commonware_parallel::Sequential;
use commonware_utils::{N3f1, NZU32, NZU64};
use eyre::{Context as _, OptionExt as _, eyre};
use futures::StreamExt as _;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;

use crate::dealer_log::{InspectableSignedDealerLog, PlayerResultType};

const CONCURRENT_BLOCK_FETCHES: usize = 4;

/// The namespace used by the DKG protocol in Tempo.
const DKG_NAMESPACE: &[u8] = b"TEMPO";

#[derive(Debug, clap::Args)]
pub(crate) struct ReplayDkg {
    /// RPC endpoint URL (http://, https://, ws://, or wss://)
    #[arg(long)]
    rpc_url: String,

    /// The epoch to replay DKG for
    #[arg(long)]
    epoch: u64,

    /// Chain spec (mainnet, testnet, moderato, dev, or path to genesis JSON)
    #[arg(long)]
    chain_spec: String,
}

#[derive(Serialize)]
struct PlayerAckReveal {
    player: String,
    result: PlayerResultType,
}

#[derive(Serialize)]
struct DealingInfo {
    block_number: u64,
    block_hash: B256,
    dealer: String,
    ack_count: usize,
    reveal_count: usize,
    too_many_reveals: bool,
    player_results: Vec<PlayerAckReveal>,
}

#[derive(Serialize)]
struct ReplayResult {
    epoch: u64,
    epoch_start_block: u64,
    epoch_end_block: u64,
    previous_epoch_boundary_block: u64,
    dealers: Vec<String>,
    players: Vec<String>,
    dealings_found: Vec<DealingInfo>,
    observe_success: bool,
    observe_error: Option<String>,
    network_identity: Option<Bytes>,
}

fn pubkey_to_hex(pk: &PublicKey) -> String {
    const_hex::encode_prefixed(pk.as_ref())
}

impl ReplayDkg {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        // Parse chainspec and get epoch length
        let chainspec = tempo_chainspec::spec::chain_value_parser(&self.chain_spec)
            .wrap_err("failed to parse chain spec")?;

        let epoch_length = chainspec
            .info
            .epoch_length()
            .ok_or_eyre("chainspec does not contain epochLength")?;

        let epocher = FixedEpocher::new(NZU64!(epoch_length));
        let target_epoch = Epoch::new(self.epoch);

        // Calculate block ranges
        let epoch_start = epocher
            .first(target_epoch)
            .ok_or_eyre("invalid epoch")?
            .get();
        let epoch_end = epocher
            .last(target_epoch)
            .ok_or_eyre("invalid epoch")?
            .get();

        // The previous epoch boundary is the last block of the previous epoch
        // which contains the DKG outcome that defines dealers/players for this epoch
        let prev_epoch = target_epoch
            .previous()
            .ok_or_eyre("cannot replay epoch 1 (no previous boundary)")?;
        let prev_boundary = epocher
            .last(prev_epoch)
            .ok_or_eyre("invalid previous epoch")?
            .get();

        eprintln!("Epoch length: {epoch_length}");
        eprintln!(
            "Epoch {} runs from block {epoch_start} to {epoch_end}",
            self.epoch
        );
        eprintln!("Reading DKG outcome from previous boundary block {prev_boundary}");

        // Connect to RPC
        let provider = ProviderBuilder::new()
            .connect(&self.rpc_url)
            .await
            .wrap_err("failed to connect to RPC")?;

        // Fetch the previous boundary block to get the DKG outcome
        let prev_boundary_block = provider
            .get_block_by_number(prev_boundary.into())
            .await
            .wrap_err("failed to fetch previous boundary block")?
            .ok_or_else(|| eyre!("previous boundary block {prev_boundary} not found"))?;

        let extra_data = &prev_boundary_block.header.inner.extra_data;
        eyre::ensure!(
            !extra_data.is_empty(),
            "previous boundary block {prev_boundary} has empty extra_data",
        );

        let prev_outcome = OnchainDkgOutcome::read(&mut extra_data.as_ref())
            .wrap_err("failed to parse DKG outcome from previous boundary block")?;

        let dealers = prev_outcome.players().clone();
        let players = prev_outcome.next_players().clone();
        let prev_polynomial = *prev_outcome.sharing().public();

        eprintln!(
            "DKG round info:\ndealers: {dealers:?}\nplayers: {players:?}\npolynomial: {prev_polynomial:?}",
        );

        // Build the Info struct for this DKG round
        // For a reshare, we pass the previous output; for full DKG, we pass None
        let previous_output = if prev_outcome.is_next_full_dkg {
            eprintln!("This is a FULL DKG ceremony (new polynomial)");
            None
        } else {
            eprintln!("This is a RESHARE ceremony");
            Some(prev_outcome.output.clone())
        };

        let info = Info::new::<N3f1>(
            DKG_NAMESPACE,
            self.epoch,
            previous_output,
            Mode::NonZeroCounter,
            dealers.clone(),
            players.clone(),
        )
        .wrap_err("failed to create DKG Info")?;

        // Iterate through blocks from midpoint to end of epoch to find dealings
        // Dealer logs start appearing at the midpoint of the epoch
        let midpoint = self.epoch * epoch_length + epoch_length / 2;
        let scan_start = midpoint - 1;

        eprintln!("Scanning blocks {scan_start} to {epoch_end}");

        let mut dealings_found = Vec::new();
        let mut logs: BTreeMap<PublicKey, dkg::DealerLog<MinSig, PublicKey>> = BTreeMap::new();

        // Fetch blocks in parallel using buffered streams
        let num_players = NZU32!(players.len() as u32);
        let block_futures = (scan_start..=epoch_end).map(|block_num| {
            let provider = &provider;
            async move {
                let block = provider
                    .get_block_by_number(block_num.into())
                    .await
                    .wrap_err_with(|| format!("failed to fetch block {block_num}"))?
                    .ok_or_else(|| eyre!("block {block_num} not found"))?;
                Ok::<_, eyre::Report>((block_num, block))
            }
        });

        let total_blocks = epoch_end - scan_start + 1;
        let progress = ProgressBar::new(total_blocks);
        progress.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} blocks ({eta})")
                .expect("valid template")
                .progress_chars("#>-"),
        );

        let mut block_stream =
            futures::stream::iter(block_futures).buffered(CONCURRENT_BLOCK_FETCHES);

        while let Some(result) = block_stream.next().await {
            let (block_num, block) = result?;
            progress.inc(1);

            let extra_data = &block.header.inner.extra_data;
            if extra_data.is_empty() {
                continue;
            }

            // Try to parse as InspectableSignedDealerLog first to get dealer info
            match InspectableSignedDealerLog::<MinSig, PrivateKey>::from_bytes(
                extra_data.as_ref(),
                num_players,
            ) {
                Ok(inspectable) => {
                    let dealer_hex = pubkey_to_hex(inspectable.dealer());
                    let ack_count = inspectable.ack_count();
                    let reveal_count = inspectable.reveal_count();
                    let too_many_reveals = inspectable.has_too_many_reveals();

                    let player_results: Vec<PlayerAckReveal> = inspectable
                        .player_results()
                        .into_iter()
                        .map(|pr| PlayerAckReveal {
                            player: pubkey_to_hex(&pr.player),
                            result: pr.result_type,
                        })
                        .collect();

                    // Now parse the original SignedDealerLog for verification
                    let signed_log = SignedDealerLog::<MinSig, PrivateKey>::read_cfg(
                        &mut extra_data.as_ref(),
                        &num_players,
                    )
                    .expect("already parsed successfully");

                    if let Some((dealer, log)) = signed_log.check(&info) {
                        progress.suspend(|| {
                            eprintln!(
                                "Block {block_num}: dealer log from {dealer} (acks: {ack_count}, reveals: {reveal_count})",
                                dealer = inspectable.dealer(),
                            );
                        });

                        dealings_found.push(DealingInfo {
                            block_number: block_num,
                            block_hash: block.header.hash,
                            dealer: dealer_hex,
                            ack_count,
                            reveal_count,
                            too_many_reveals,
                            player_results,
                        });
                        logs.insert(dealer, log);
                    } else {
                        progress.suspend(|| {
                            eprintln!(
                                "Block {block_num}: dealer log from {dealer_hex} failed verification"
                            );
                        });
                    }
                }
                Err(_) => {
                    // Not a dealer log - could be the final DKG outcome at epoch boundary
                    if block_num == epoch_end {
                        progress.suspend(|| {
                            eprintln!("Block {block_num}: epoch boundary (DKG outcome)");
                        });
                    }
                }
            }
        }

        progress.finish_and_clear();

        eprintln!("\nFound {} valid dealer logs", logs.len());

        // Call observe to replay the DKG
        let (observe_success, observe_error, network_identity) =
            match dkg::observe::<_, _, N3f1>(info, logs, &Sequential) {
                Ok(output) => {
                    eprintln!("DKG observe succeeded!");
                    let identity = Bytes::copy_from_slice(&commonware_codec::Encode::encode(
                        output.public().public(),
                    ));
                    (true, None, Some(identity))
                }
                Err(e) => {
                    eprintln!("DKG observe failed: {e:?}");
                    (false, Some(format!("{e:?}")), None)
                }
            };

        let result = ReplayResult {
            epoch: self.epoch,
            epoch_start_block: epoch_start,
            epoch_end_block: epoch_end,
            previous_epoch_boundary_block: prev_boundary,
            dealers: dealers.iter().map(pubkey_to_hex).collect(),
            players: players.iter().map(pubkey_to_hex).collect(),
            dealings_found,
            observe_success,
            observe_error,
            network_identity,
        };

        println!("{}", serde_json::to_string_pretty(&result)?);

        Ok(())
    }
}
