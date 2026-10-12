//! Guarded `zone_setLeader` handoff.

use std::{fmt, time::Duration};

use alloy::{
    primitives::Address,
    providers::{Provider, ProviderBuilder},
};
use eyre::{Context as _, ensure, eyre};
use serde::Serialize;
use tempo_alloy::TempoNetwork;
use zone_p2p::ZoneManifest;
use zone_rpc::types::SetLeaderResponse;

use super::{
    config::{SharedAdminArgs, format_duration, parse_nonzero_duration},
    invariants::{
        address_set, eligible_relayers, evaluate_base_invariants, is_rpc_only, resolve_node,
    },
    snapshot::{ClusterView, NodeSnapshot},
};

const DEFAULT_HANDOFF_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const HANDOFF_POLL: Duration = Duration::from_millis(500);

#[derive(Debug, clap::Parser)]
pub(crate) struct Leader {
    #[command(subcommand)]
    command: LeaderCommand,
}

#[derive(Debug, clap::Subcommand)]
enum LeaderCommand {
    /// Move finalized leadership to a different promotion-ready sequencer.
    Set(LeaderSet),
}

impl Leader {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        match self.command {
            LeaderCommand::Set(command) => command.run().await,
        }
    }
}

#[derive(Debug, clap::Parser)]
struct LeaderSet {
    #[command(flatten)]
    shared: SharedAdminArgs,

    /// Target leader, as a node name or individual sequencer address; must differ from the finalized leader.
    #[arg(long)]
    target: String,

    /// Operator RPC that relays `zone_setLeader`. Optional when exactly one relayer is eligible.
    #[arg(long)]
    via: Option<String>,

    /// Submit the leadership transaction. Without this flag the command is a dry run.
    #[arg(long)]
    execute: bool,

    /// Allow only expected old/new manifest disagreements during a membership rollout.
    #[arg(long, requires = "zone_manifest")]
    rolling_membership: bool,

    /// Deadline for finalized leader agreement. Defaults to 5m.
    #[arg(long, value_parser = parse_nonzero_duration)]
    timeout: Option<Duration>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LeaderSetReport {
    ok: bool,
    dry_run: bool,
    submitted: bool,
    via: String,
    relayer: Address,
    target: Address,
    target_name: String,
    current_leader: Address,
    current_epoch: u64,
    expected_epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_hash: Option<alloy::primitives::B256>,
}

impl LeaderSet {
    async fn run(self) -> eyre::Result<()> {
        progress("Loading and validating configuration...");
        let config = self.shared.load()?;
        let view = ClusterView::collect(config, self.shared.rpc_timeout, |message| {
            progress(message);
        })
        .await?;

        progress("Evaluating cluster preflight...");
        let invariants = evaluate_base_invariants(
            &view.config,
            view.manifest.as_ref(),
            &view.portal,
            &view.nodes,
            None,
            None,
            None,
        );
        let failed = invariants
            .iter()
            .filter(|result| result.required_failed())
            .filter(|result| !self.rolling_membership || !is_expected_rolling_failure(result.name))
            .map(|result| format!("{}: {}", result.name, result.detail))
            .collect::<Vec<_>>();
        ensure!(
            failed.is_empty(),
            "cluster preflight failed; refusing leader handoff: {}",
            failed.join("; ")
        );

        let target_node = resolve_node(&view.nodes, &self.target).ok_or_else(|| {
            eyre!(
                "target `{}` does not match a reachable operator node",
                self.target
            )
        })?;
        let target_info = target_node
            .sequencer
            .as_ref()
            .ok_or_else(|| eyre!("target {} has no sequencer status", target_node.name))?;
        if self.rolling_membership {
            let manifest = view.manifest.as_ref().ok_or_else(|| {
                eyre!(
                    "--rolling-membership requires --zone-manifest with the finalized next manifest"
                )
            })?;
            let manifest_members = manifest
                .quorum_nodes()
                .map(|(_, address)| address)
                .collect::<Vec<_>>();
            ensure!(
                address_set(&manifest_members) == address_set(&view.portal.sequencers),
                "rolling manifest quorum does not match finalized Portal membership"
            );
            ensure_rolling_node_manifest(target_node, manifest, &view.portal)?;
        }
        ensure!(
            is_rpc_only(target_info) != Some(true),
            "target {} is rpc-only and cannot become leader",
            target_node.name
        );
        let target_address = target_info
            .local
            .as_ref()
            .and_then(|local| local.sequencer_address)
            .or_else(|| {
                target_info
                    .peers
                    .iter()
                    .find(|peer| peer.is_local)
                    .and_then(|peer| peer.sequencer_address)
            })
            .ok_or_else(|| {
                eyre!(
                    "target {} has no individual sequencer address",
                    target_node.name
                )
            })?;
        ensure!(
            view.portal.sequencers.contains(&target_address),
            "target {} ({target_address}) is not a registered Portal sequencer",
            target_node.name
        );
        let ready = target_info
            .readiness
            .as_ref()
            .zip(target_info.progress.as_ref())
            .is_some_and(|(readiness, progress)| {
                readiness.ready_for_promotion && progress.pending_transitions.to::<u64>() == 0
            });
        ensure!(
            ready,
            "target {} is not promotion-ready or has pending transitions",
            target_node.name
        );
        ensure_target_differs_from_finalized_leader(
            &target_node.name,
            target_address,
            view.portal.leader,
            view.portal.leader_epoch,
        )?;
        let via_node = select_via(&view.nodes, self.via.as_deref())?;
        let via_info = via_node.sequencer.as_ref().ok_or_else(|| {
            eyre!(
                "submission endpoint {} has no sequencer status",
                via_node.name
            )
        })?;
        let relayer = via_info
            .local
            .as_ref()
            .and_then(|local| local.sequencer_address)
            .ok_or_else(|| {
                eyre!(
                    "submission endpoint {} does not hold an individual relayer key",
                    via_node.name
                )
            })?;
        ensure!(
            is_rpc_only(via_info) != Some(true),
            "submission endpoint {} is rpc-only and cannot relay setLeader",
            via_node.name
        );
        ensure!(
            view.portal.sequencers.contains(&relayer),
            "submission endpoint {} relayer {} is not a finalized Portal sequencer",
            via_node.name,
            relayer
        );
        if self.rolling_membership {
            ensure_rolling_node_manifest(
                via_node,
                view.manifest
                    .as_ref()
                    .expect("rolling manifest checked above"),
                &view.portal,
            )?;
        }

        let expected_epoch = view.portal.leader_epoch.saturating_add(1);

        if !self.execute {
            let report = LeaderSetReport {
                ok: true,
                dry_run: !self.execute,
                submitted: false,
                via: via_node.name.clone(),
                relayer,
                target: target_address,
                target_name: target_node.name.clone(),
                current_leader: view.portal.leader,
                current_epoch: view.portal.leader_epoch,
                expected_epoch,
                tx_hash: None,
            };
            return self.print_report(report);
        }

        progress(format!(
            "Calling zone_setLeader on {} for target {} ({target_address})...",
            via_node.name, target_node.name
        ));
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect(&via_node.url)
            .await?;
        let response: SetLeaderResponse = provider
            .raw_request("zone_setLeader".into(), [target_address])
            .await
            .wrap_err("zone_setLeader failed")?;

        let timeout = self.timeout.unwrap_or(DEFAULT_HANDOFF_TIMEOUT);
        let deadline = std::time::Instant::now() + timeout;
        let initial_height = view.portal.zone_height;
        loop {
            let later =
                ClusterView::collect(view.config.clone(), self.shared.rpc_timeout, |message| {
                    progress(message)
                })
                .await?;
            let leader_ok = later.portal.leader == target_address
                && later.portal.leader_epoch == expected_epoch;
            let node_reports_leader = |node: &NodeSnapshot| {
                node.sequencer
                    .as_ref()
                    .and_then(|info| info.active_leader.as_ref())
                    .is_some_and(|leader| {
                        leader.sequencer_address == Some(target_address)
                            && leader.epoch.to::<u64>() == expected_epoch
                    })
            };
            let nodes_agree = if self.rolling_membership {
                later
                    .nodes
                    .iter()
                    .find(|node| node.url == target_node.url)
                    .is_some_and(node_reports_leader)
            } else {
                later.nodes.iter().all(node_reports_leader)
            };
            let progressed = later.portal.zone_height > initial_height;
            if handoff_ready(self.rolling_membership, leader_ok, nodes_agree, progressed) {
                return self.print_report(LeaderSetReport {
                    ok: true,
                    dry_run: false,
                    submitted: response.tx_hash.is_some(),
                    via: via_node.name.clone(),
                    relayer: response.relayer,
                    target: target_address,
                    target_name: target_node.name.clone(),
                    current_leader: later.portal.leader,
                    current_epoch: later.portal.leader_epoch,
                    expected_epoch,
                    tx_hash: response.tx_hash,
                });
            }
            if std::time::Instant::now() >= deadline {
                return Err(eyre!(
                    "timed out after {} waiting for leader {} at epoch {expected_epoch}",
                    format_duration(timeout),
                    target_node.name
                ));
            }
            progress(format!(
                "Waiting for finalized leader {} epoch {expected_epoch}...",
                target_node.name
            ));
            tokio::time::sleep(HANDOFF_POLL).await;
        }
    }

    fn print_report(&self, report: LeaderSetReport) -> eyre::Result<()> {
        if self.shared.json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            println!(
                "{}",
                if report.dry_run {
                    "Leader handoff dry run"
                } else if report.submitted {
                    "Leader handoff submitted"
                } else {
                    "Leader handoff completed"
                }
            );
            println!("  Target:  {} ({})", report.target_name, report.target);
            println!("  Via:     {} (relayer {})", report.via, report.relayer);
            println!(
                "  Current: {} epoch {}",
                report.current_leader, report.current_epoch
            );
            println!("  Expected epoch: {}", report.expected_epoch);
            if let Some(tx_hash) = report.tx_hash {
                println!("  Transaction: {tx_hash}");
            }
        }
        Ok(())
    }
}

fn ensure_target_differs_from_finalized_leader(
    target_name: &str,
    target: Address,
    current_leader: Address,
    current_epoch: u64,
) -> eyre::Result<()> {
    ensure!(
        current_leader != target,
        "target {target_name} ({target}) is already the finalized Portal leader at epoch {current_epoch}; choose a different, promotion-ready follower"
    );
    Ok(())
}

fn ensure_rolling_node_manifest(
    node: &NodeSnapshot,
    manifest: &ZoneManifest,
    portal: &super::snapshot::PortalSnapshot,
) -> eyre::Result<()> {
    let info = node
        .sequencer
        .as_ref()
        .ok_or_else(|| eyre!("node {} has no sequencer status", node.name))?;
    ensure!(
        info.manifest_sequencer_set_version
            .is_some_and(|version| version.to::<u64>() == portal.sequencer_set_version),
        "node {} has not loaded finalized manifest version {}",
        node.name,
        portal.sequencer_set_version
    );
    ensure!(
        info.manifest_membership_digest == Some(manifest.membership_digest()),
        "node {} has not loaded the supplied rolling manifest",
        node.name
    );
    let members = info
        .peers
        .iter()
        .filter_map(|peer| peer.sequencer_address)
        .collect::<Vec<_>>();
    ensure!(
        address_set(&members) == address_set(&portal.sequencers),
        "node {} has not loaded finalized Portal membership",
        node.name
    );
    Ok(())
}

fn handoff_ready(
    rolling_membership: bool,
    leader_ok: bool,
    nodes_agree: bool,
    progressed: bool,
) -> bool {
    leader_ok && nodes_agree && (rolling_membership || progressed)
}

fn is_expected_rolling_failure(name: &str) -> bool {
    matches!(
        name,
        "live_membership"
            | "live_topology"
            | "loaded_manifest_agreement"
            | "manifest_version"
            | "manifest_digest"
            | "manifest_node_identity"
    )
}

fn select_via<'a>(nodes: &'a [NodeSnapshot], via: Option<&str>) -> eyre::Result<&'a NodeSnapshot> {
    if let Some(via) = via {
        return resolve_node(nodes, via)
            .ok_or_else(|| eyre!("--via `{via}` does not match a reachable operator node"));
    }
    let relayers = eligible_relayers(nodes);
    match relayers.as_slice() {
        [only] => {
            progress(format!(
                "Selected unique relayer {} for zone_setLeader.",
                only.name
            ));
            Ok(*only)
        }
        [] => Err(eyre!(
            "no reachable node holds an individual relayer key; pass --via"
        )),
        _ => Err(eyre!(
            "multiple relayers are eligible ({}); pass --via",
            relayers
                .iter()
                .map(|node| node.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

fn progress(message: impl fmt::Display) {
    eprintln!("[admin leader set] {message}");
}

#[cfg(test)]
mod tests {
    use alloy::primitives::Address;

    use super::{
        ensure_target_differs_from_finalized_leader, handoff_ready, is_expected_rolling_failure,
        select_via,
    };
    use crate::admin::snapshot::{test_node_snapshot, test_sequencer_info};

    #[test]
    fn omits_via_when_exactly_one_relayer_is_eligible() {
        let leader = test_node_snapshot("node-a", test_sequencer_info(false, true));
        let rpc = test_node_snapshot("rpc", test_sequencer_info(true, false));
        let nodes = [leader, rpc];
        let selected = select_via(&nodes, None).unwrap();
        assert_eq!(selected.name, "node-a");
    }

    #[test]
    fn refuses_ambiguous_relayer_selection() {
        let a = test_node_snapshot("node-a", test_sequencer_info(false, true));
        let b = test_node_snapshot("node-b", test_sequencer_info(false, true));
        let err = select_via(&[a, b], None).unwrap_err();
        assert!(err.to_string().contains("pass --via"));
    }

    #[test]
    fn refuses_target_that_is_already_the_finalized_leader() {
        let target = Address::with_last_byte(0x11);
        let err =
            ensure_target_differs_from_finalized_leader("node-a", target, target, 42).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("node-a"));
        assert!(message.contains(&target.to_string()));
        assert!(message.contains("already the finalized Portal leader"));
        assert!(message.contains("epoch 42"));
        assert!(message.contains("different, promotion-ready follower"));
    }

    #[test]
    fn rolling_mode_relaxes_only_expected_mixed_manifest_checks() {
        assert!(is_expected_rolling_failure("live_membership"));
        assert!(is_expected_rolling_failure("manifest_node_identity"));
        assert!(!is_expected_rolling_failure("portal_leader"));
        assert!(!is_expected_rolling_failure("canonical_state"));
        assert!(!is_expected_rolling_failure("manifest_membership"));
    }

    #[test]
    fn rolling_handoff_returns_before_cluster_progress() {
        assert!(handoff_ready(true, true, true, false));
        assert!(!handoff_ready(true, true, false, false));
        assert!(!handoff_ready(true, false, true, false));
    }

    #[test]
    fn normal_handoff_still_requires_cluster_progress() {
        assert!(!handoff_ready(false, true, true, false));
        assert!(handoff_ready(false, true, true, true));
    }
}
