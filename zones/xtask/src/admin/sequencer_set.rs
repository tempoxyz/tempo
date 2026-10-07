//! Guarded one-for-one replacement of a ZonePortal sequencer member.

use std::{fmt, path::PathBuf, time::Duration};

use alloy::{
    network::primitives::ReceiptResponse as _,
    primitives::{Address, B256},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
};
use eyre::{Context as _, ensure, eyre};
use serde::Serialize;
use tempo_alloy::TempoNetwork;
use tempo_zone_contracts::ZonePortal;
use zone_p2p::ZoneManifest;

use super::{
    config::{SharedAdminArgs, format_duration, parse_nonzero_duration},
    invariants::{address_set, ensure_invariants, evaluate_base_invariants},
    secret_file::read_private_key_file,
    snapshot::{ClusterView, PortalSnapshot, read_portal_snapshot},
};

const DEFAULT_FINALITY_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const FINALITY_POLL: Duration = Duration::from_millis(500);

#[derive(Debug, clap::Parser)]
pub(crate) struct SequencerSet {
    #[command(subcommand)]
    command: SequencerSetCommand,
}

#[derive(Debug, clap::Subcommand)]
enum SequencerSetCommand {
    /// Replace exactly one member while preserving the current threshold.
    Replace(Replace),
}

impl SequencerSet {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        match self.command {
            SequencerSetCommand::Replace(command) => command.run().await,
        }
    }
}

#[derive(Debug, clap::Parser)]
struct Replace {
    #[command(flatten)]
    shared: SharedAdminArgs,

    /// Manifest that exactly describes the replacement membership and next version.
    #[arg(long)]
    next_manifest: PathBuf,

    /// Current Portal member to replace.
    #[arg(long)]
    old_member: Address,

    /// New, previously unregistered Portal member.
    #[arg(long)]
    new_member: Address,

    /// ZonePortal admin private-key file.
    #[arg(long)]
    transaction_key_file: PathBuf,

    /// Finalized sequencer-set version this transaction must replace.
    #[arg(long)]
    expected_version: u64,

    /// Submit the Portal transaction. Without this flag the command is a dry run.
    #[arg(long)]
    execute: bool,

    /// Deadline for finalized postconditions. Defaults to 5m.
    #[arg(long, value_parser = parse_nonzero_duration)]
    timeout: Option<Duration>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplaceReport {
    ok: bool,
    dry_run: bool,
    submitted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_hash: Option<B256>,
    portal: Address,
    admin: Address,
    old_member: Address,
    new_member: Address,
    leader: Address,
    threshold: u8,
    current_version: u64,
    resulting_version: u64,
    proposed_members: Vec<Address>,
    next_manifest: String,
}

impl Replace {
    async fn run(self) -> eyre::Result<()> {
        let resulting_version = self
            .expected_version
            .checked_add(1)
            .ok_or_else(|| eyre!("expected sequencer-set version cannot be incremented"))?;
        let next_manifest = ZoneManifest::read_from_file(&self.next_manifest)
            .wrap_err("failed to load next Zone manifest")?;
        let signer = read_private_key_file(&self.transaction_key_file)?;

        progress("Loading and checking the Zone...");
        let config = self.shared.load()?;
        let view =
            ClusterView::collect(config, self.shared.rpc_timeout, |message| progress(message))
                .await?;
        let proposed = validate(&view, &next_manifest, &signer, &self)?;

        progress("Simulating setSequencerSet...");
        simulate(&view, signer.address(), &proposed).await?;

        if !self.execute {
            return self.print_report(report(
                &self,
                &view.portal,
                &proposed,
                resulting_version,
                false,
                None,
            ));
        }

        progress("Rechecking all preconditions immediately before submission...");
        let latest =
            ClusterView::collect(view.config.clone(), self.shared.rpc_timeout, |message| {
                progress(message)
            })
            .await?;
        let latest_proposed = validate(&latest, &next_manifest, &signer, &self)?;
        ensure!(
            latest_proposed == proposed,
            "proposed sequencer ordering changed during the dry run; refusing to submit"
        );
        simulate(&latest, signer.address(), &latest_proposed).await?;

        progress("Submitting setSequencerSet...");
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .wallet(signer)
            .connect(&latest.config.l1_rpc_url)
            .await
            .wrap_err("failed connecting to Tempo L1 RPC")?;
        let receipt = ZonePortal::new(latest.portal.portal, &provider)
            .setSequencerSet(latest_proposed.clone(), latest.portal.threshold)
            .send_sync()
            .await
            .wrap_err("failed to send setSequencerSet")?;
        ensure!(
            receipt.status(),
            "setSequencerSet reverted (tx: {})",
            receipt.transaction_hash
        );
        let tx_hash = receipt.transaction_hash;

        let timeout = self.timeout.unwrap_or(DEFAULT_FINALITY_TIMEOUT);
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let later = read_portal_snapshot(
                &provider,
                latest.config.zone_factory,
                latest.config.zone_id,
                latest.config.portal,
            )
            .await?;
            if later.sequencer_set_version == resulting_version
                && address_set(&later.sequencers) == address_set(&latest_proposed)
                && later.threshold == latest.portal.threshold
            {
                return self.print_report(report(
                    &self,
                    &later,
                    &latest_proposed,
                    resulting_version,
                    true,
                    Some(tx_hash),
                ));
            }
            ensure!(
                later.sequencer_set_version == self.expected_version,
                "a different sequencer-set update finalized while waiting: expected version {} or {}, found {}",
                self.expected_version,
                resulting_version,
                later.sequencer_set_version
            );
            if std::time::Instant::now() >= deadline {
                return Err(eyre!(
                    "timed out after {} waiting for sequencer-set version {} to finalize",
                    format_duration(timeout),
                    resulting_version
                ));
            }
            tokio::time::sleep(FINALITY_POLL).await;
        }
    }

    fn print_report(&self, report: ReplaceReport) -> eyre::Result<()> {
        if self.shared.json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            println!(
                "{}",
                if report.submitted {
                    "Sequencer-set replacement finalized"
                } else {
                    "Sequencer-set replacement dry run passed"
                }
            );
            println!("  Portal: {}", report.portal);
            println!("  Portal admin: {}", report.admin);
            println!("  Replace: {} -> {}", report.old_member, report.new_member);
            println!("  Threshold: {} (unchanged)", report.threshold);
            println!("  Leader retained: {}", report.leader);
            println!(
                "  Version: {} -> {}",
                report.current_version, report.resulting_version
            );
            println!("  Next manifest: {}", report.next_manifest);
            println!("  Proposed members: {:?}", report.proposed_members);
            if let Some(tx_hash) = report.tx_hash {
                println!("  Transaction: {tx_hash}");
            }
        }
        Ok(())
    }
}

fn validate(
    view: &ClusterView,
    next_manifest: &ZoneManifest,
    signer: &PrivateKeySigner,
    command: &Replace,
) -> eyre::Result<Vec<Address>> {
    ensure_healthy(view)?;
    ensure!(
        view.portal.sequencer_set_version == command.expected_version,
        "expected finalized sequencer-set version {}, found {}",
        command.expected_version,
        view.portal.sequencer_set_version
    );
    ensure!(
        signer.address() == view.portal.admin,
        "transaction key derives {}, but finalized Portal admin is {}",
        signer.address(),
        view.portal.admin
    );
    ensure!(!command.old_member.is_zero(), "--old-member cannot be zero");
    ensure!(!command.new_member.is_zero(), "--new-member cannot be zero");
    ensure!(
        command.old_member != command.new_member,
        "old and new members must be distinct"
    );
    ensure!(
        view.portal.sequencers.contains(&command.old_member),
        "old member {} is not in the finalized Portal set",
        command.old_member
    );
    ensure!(
        !view.portal.sequencers.contains(&command.new_member),
        "new member {} is already in the finalized Portal set",
        command.new_member
    );

    let proposed = view
        .portal
        .sequencers
        .iter()
        .map(|member| {
            if *member == command.old_member {
                command.new_member
            } else {
                *member
            }
        })
        .collect::<Vec<_>>();
    ensure!(
        proposed.contains(&view.portal.leader),
        "replacement would remove finalized leader {}; move leadership first",
        view.portal.leader
    );
    ensure!(
        usize::from(view.portal.threshold) <= proposed.len(),
        "current threshold {} is invalid for {} proposed members",
        view.portal.threshold,
        proposed.len()
    );

    ensure!(
        command.expected_version != u64::MAX,
        "expected sequencer-set version cannot be incremented"
    );
    let manifest_members = next_manifest
        .quorum_nodes()
        .map(|(_, address)| address)
        .collect::<Vec<_>>();
    ensure!(
        address_set(&manifest_members) == address_set(&proposed),
        "next manifest quorum members {:?} do not equal proposed Portal members {:?}",
        address_set(&manifest_members),
        address_set(&proposed)
    );

    Ok(proposed)
}

async fn simulate(view: &ClusterView, admin: Address, proposed: &[Address]) -> eyre::Result<()> {
    let l1 = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect(&view.config.l1_rpc_url)
        .await
        .wrap_err("failed connecting to Tempo L1 RPC")?;
    ZonePortal::new(view.portal.portal, &l1)
        .setSequencerSet(proposed.to_vec(), view.portal.threshold)
        .from(admin)
        .call()
        .await
        .wrap_err("setSequencerSet simulation failed")?;
    Ok(())
}

fn ensure_healthy(view: &ClusterView) -> eyre::Result<()> {
    let invariants = evaluate_base_invariants(
        &view.config,
        view.manifest.as_ref(),
        &view.portal,
        &view.nodes,
        None,
        None,
        None,
    );
    ensure_invariants(
        "cluster preflight failed; refusing sequencer-set replacement",
        &invariants,
    )
}

fn report(
    command: &Replace,
    portal: &PortalSnapshot,
    proposed: &[Address],
    resulting_version: u64,
    submitted: bool,
    tx_hash: Option<B256>,
) -> ReplaceReport {
    ReplaceReport {
        ok: true,
        dry_run: !submitted,
        submitted,
        tx_hash,
        portal: portal.portal,
        admin: portal.admin,
        old_member: command.old_member,
        new_member: command.new_member,
        leader: portal.leader,
        threshold: portal.threshold,
        current_version: command.expected_version,
        resulting_version,
        proposed_members: proposed.to_vec(),
        next_manifest: command.next_manifest.display().to_string(),
    }
}

fn progress(message: impl fmt::Display) {
    eprintln!("[admin sequencer-set] {message}");
}
