//! Read-only cluster health verification.

use std::{fmt, path::PathBuf, time::Duration};

use eyre::{ensure, eyre};
use serde::Serialize;

use super::{
    config::{
        ExpectedEncryptionKey, SharedAdminArgs, format_duration, parse_duration,
        parse_encryption_key, parse_nonzero_duration,
    },
    invariants::{
        CheckStatus, InvariantInputs, InvariantResult, address_set, evaluate_invariants,
        evaluate_node_ready, is_rpc_only, zone_height_invariant,
    },
    snapshot::{ClusterView, NodeSnapshot, PortalSnapshot, query_nodes},
};

const DEFAULT_WAIT_READY_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Read-only consistency and health audit for a Zone.
#[derive(Debug, clap::Parser)]
pub(crate) struct Check {
    #[command(flatten)]
    shared: SharedAdminArgs,

    /// Interval over which operator Zone progress is observed; use 0s for a snapshot only.
    #[arg(long, default_value = "5s", value_parser = parse_duration)]
    observe_for: Duration,

    /// Require the finalized Portal to have exactly this sequencer-set version.
    #[arg(long)]
    require_sequencer_set_version: Option<u64>,

    /// Require this finalized leader, expressed as a sequencer address or manifest/node name.
    #[arg(long)]
    require_leader: Option<String>,

    /// Require the active encryption public key, formatted as X:PARITY.
    #[arg(long, value_parser = parse_encryption_key)]
    require_encryption_key: Option<ExpectedEncryptionKey>,

    /// Retry the selected checks until they pass or `--timeout` elapses.
    #[arg(long)]
    wait_ready: bool,

    /// Named operator node to wait for when `--wait-ready` is set.
    #[arg(long)]
    node: Option<String>,

    /// Deadline for `--wait-ready`. Defaults to 5m.
    #[arg(long, value_parser = parse_nonzero_duration)]
    timeout: Option<Duration>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CheckReport {
    ok: bool,
    zone_id: u32,
    manifest_supplied: bool,
    #[serde(skip)]
    manifest_path: Option<PathBuf>,
    desired_topology_verified: Option<bool>,
    observe_for_ms: u64,
    portal: PortalSnapshot,
    nodes: Vec<NodeSnapshot>,
    #[serde(skip)]
    follow_up_nodes: Option<Vec<NodeSnapshot>>,
    invariants: Vec<InvariantResult>,
}

impl Check {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        if self.node.is_some() && !self.wait_ready {
            return Err(eyre!("--node requires --wait-ready"));
        }
        if self.timeout.is_some() && !self.wait_ready {
            return Err(eyre!("--timeout requires --wait-ready"));
        }
        progress("Loading and validating configuration...");
        let config = self.shared.load()?;
        progress(format!(
            "Configuration ready: Zone {}, {} operator RPC(s), snapshot timeout {}.",
            config.zone_id,
            config.nodes.len(),
            format_duration(self.shared.rpc_timeout)
        ));

        let wait_deadline = self.wait_ready.then(|| {
            std::time::Instant::now() + self.timeout.unwrap_or(DEFAULT_WAIT_READY_TIMEOUT)
        });

        let mut view;
        loop {
            view = ClusterView::collect(config.clone(), self.shared.rpc_timeout, |message| {
                progress(message);
            })
            .await?;

            progress("Evaluating consistency and safety invariants...");
            let invariants = if let Some(node_name) = self.node.as_deref() {
                evaluate_node_ready(node_name, &view.portal, &view.nodes)
            } else {
                evaluate_invariants(InvariantInputs {
                    config: &view.config,
                    manifest: view.manifest.as_ref(),
                    portal: &view.portal,
                    nodes: &view.nodes,
                    required_version: self.require_sequencer_set_version,
                    required_leader: self.require_leader.as_deref(),
                    required_key: self.require_encryption_key,
                })
            };
            let ok = invariants.iter().all(|result| !result.required_failed());
            if !self.wait_ready || ok {
                return self.finish(view, invariants, None).await;
            }

            let Some(deadline) = wait_deadline else {
                unreachable!();
            };
            if std::time::Instant::now() >= deadline {
                progress("Wait deadline elapsed before the selected checks passed.");
                return self.finish(view, invariants, None).await;
            }
            progress(format!(
                "Selected checks have not passed yet; retrying in {}...",
                format_duration(WAIT_POLL_INTERVAL)
            ));
            tokio::time::sleep(WAIT_POLL_INTERVAL).await;
        }
    }

    async fn finish(
        self,
        view: ClusterView,
        mut invariants: Vec<InvariantResult>,
        follow_up_nodes: Option<Vec<NodeSnapshot>>,
    ) -> eyre::Result<()> {
        let follow_up_nodes = if let Some(nodes) = follow_up_nodes {
            Some(nodes)
        } else if self.node.is_some() || self.observe_for.is_zero() {
            invariants.push(InvariantResult {
                name: "zone_height",
                status: CheckStatus::Skipped,
                detail: if self.node.is_some() {
                    "liveness observation skipped while waiting on a single node".to_owned()
                } else {
                    "liveness observation disabled with --observe-for 0s".to_owned()
                },
            });
            None
        } else {
            progress(format!(
                "Observing Zone progress for {}...",
                format_duration(self.observe_for)
            ));
            tokio::time::sleep(self.observe_for).await;
            progress("Observation interval complete; collecting follow-up snapshots...");
            progress(format!(
                "Querying {} operator RPC(s) for follow-up progress...",
                view.config.nodes.len()
            ));
            let later_nodes = query_nodes(&view.config.nodes, self.shared.rpc_timeout).await;
            invariants.push(zone_height_invariant(&view.nodes, &later_nodes));
            Some(later_nodes)
        };

        progress("Rendering final report...");
        let desired_topology_verified = view.manifest.as_ref().map(|_| {
            invariants.iter().all(|result| {
                !result.name.starts_with("manifest_") || result.status == CheckStatus::Pass
            })
        });
        let ok = invariants.iter().all(|result| !result.required_failed());
        let report = CheckReport {
            ok,
            zone_id: view.config.zone_id,
            manifest_supplied: view.manifest.is_some(),
            manifest_path: view.config.manifest.clone(),
            desired_topology_verified,
            observe_for_ms: self.observe_for.as_millis().try_into().unwrap_or(u64::MAX),
            portal: view.portal,
            nodes: view.nodes,
            follow_up_nodes,
            invariants,
        };

        if self.shared.json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            render_human(&report);
        }
        ensure!(report.ok, "one or more admin checks failed");
        Ok(())
    }
}

fn progress(message: impl fmt::Display) {
    eprintln!("[admin check] {message}");
}

#[derive(Debug, Clone, Copy)]
enum TableStatus {
    Pass,
    Fail,
    NotAvailable,
}

impl fmt::Display for TableStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.pad(match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::NotAvailable => "N/A",
        })
    }
}

struct NodeTableRow {
    name: String,
    height: String,
    reach: TableStatus,
    progress: TableStatus,
    identity: TableStatus,
    membership: TableStatus,
    leader: TableStatus,
    ready: TableStatus,
    key: TableStatus,
}

fn render_node_table(report: &CheckReport) {
    let portal_members = address_set(&report.portal.sequencers);
    let rows = report
        .nodes
        .iter()
        .map(|node| {
            let follow_up = report
                .follow_up_nodes
                .as_ref()
                .and_then(|nodes| nodes.iter().find(|later| later.url == node.url));
            let initial_height = node
                .sequencer
                .as_ref()
                .and_then(|info| info.progress.as_ref())
                .map(|progress| progress.zone_height.to::<u64>());
            let later_height = follow_up
                .and_then(|later| later.sequencer.as_ref())
                .and_then(|info| info.progress.as_ref())
                .map(|progress| progress.zone_height.to::<u64>());
            let initially_reachable = node.error.is_none();
            let reachable =
                initially_reachable && follow_up.is_none_or(|later| later.error.is_none());
            let status = |passed: Option<bool>| {
                if !initially_reachable {
                    TableStatus::NotAvailable
                } else if passed.unwrap_or(false) {
                    TableStatus::Pass
                } else {
                    TableStatus::Fail
                }
            };
            let height = match (
                initial_height,
                later_height,
                report.follow_up_nodes.is_some(),
            ) {
                (Some(initial), Some(later), true) => format!("{initial} -> {later}"),
                (Some(initial), _, false) => initial.to_string(),
                (Some(initial), None, true) => format!("{initial} -> ?"),
                (None, Some(later), true) => format!("? -> {later}"),
                (None, _, _) => "N/A".to_owned(),
            };
            let progress = if report.follow_up_nodes.is_none() || !reachable {
                TableStatus::NotAvailable
            } else {
                status(initial_height.zip(later_height).map(|(a, b)| b > a))
            };
            let identity = status(node.zone.as_ref().zip(node.sequencer.as_ref()).map(
                |(zone, sequencer)| {
                    zone.zone_id.to::<u32>() == report.zone_id
                        && sequencer.portal == report.portal.portal
                },
            ));
            let membership = status(node.sequencer.as_ref().map(|sequencer| {
                address_set(
                    &sequencer
                        .peers
                        .iter()
                        .filter_map(|peer| peer.sequencer_address)
                        .collect::<Vec<_>>(),
                ) == portal_members
            }));
            let leader = status(node.sequencer.as_ref().map(|sequencer| {
                sequencer.active_leader.as_ref().is_some_and(|leader| {
                    leader.sequencer_address == Some(report.portal.leader)
                        && leader.epoch.to::<u64>() == report.portal.leader_epoch
                })
            }));
            let ready = match node.sequencer.as_ref().and_then(is_rpc_only) {
                Some(true) => TableStatus::NotAvailable,
                Some(false) => status(node.sequencer.as_ref().map(|sequencer| {
                    sequencer
                        .readiness
                        .as_ref()
                        .zip(sequencer.progress.as_ref())
                        .is_some_and(|(readiness, progress)| {
                            readiness.ready_for_promotion
                                && progress.pending_transitions.to::<u64>() == 0
                        })
                })),
                None => status(None),
            };
            let key = match report.portal.encryption_key {
                None => TableStatus::NotAvailable,
                Some(active_key) => match node.sequencer.as_ref().and_then(is_rpc_only) {
                    Some(true) => TableStatus::NotAvailable,
                    Some(false) => status(node.sequencer.as_ref().map(|sequencer| {
                        sequencer.decryption_keys.as_ref().is_some_and(|keys| {
                            keys.candidates.iter().any(|candidate| {
                                candidate.x == active_key.x
                                    && candidate.y_parity == active_key.y_parity
                            }) || keys.bound.iter().any(|bound| {
                                bound.x == active_key.x && bound.y_parity == active_key.y_parity
                            })
                        })
                    })),
                    None => status(None),
                },
            };

            NodeTableRow {
                name: truncate_cell(&node.name, 24),
                height,
                reach: if reachable {
                    TableStatus::Pass
                } else {
                    TableStatus::Fail
                },
                progress,
                identity,
                membership,
                leader,
                ready,
                key,
            }
        })
        .collect::<Vec<_>>();

    let name_width = rows
        .iter()
        .map(|row| row.name.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let height_width = rows
        .iter()
        .map(|row| row.height.len())
        .max()
        .unwrap_or(6)
        .max(6);
    println!("Operator nodes");
    println!(
        "{:<name_width$}  {:<height_width$}  {:<5}  {:<8}  {:<8}  {:<10}  {:<6}  {:<5}  {:<16}",
        "Node",
        "Height",
        "Reach",
        "Progress",
        "Identity",
        "Membership",
        "Leader",
        "Ready",
        "SharedEncKey"
    );
    println!(
        "{:-<name_width$}  {:-<height_width$}  {:-<5}  {:-<8}  {:-<8}  {:-<10}  {:-<6}  {:-<5}  {:-<16}",
        "", "", "", "", "", "", "", "", ""
    );
    for row in rows {
        println!(
            "{:<name_width$}  {:<height_width$}  {:<5}  {:<8}  {:<8}  {:<10}  {:<6}  {:<5}  {:<16}",
            row.name,
            row.height,
            row.reach,
            row.progress,
            row.identity,
            row.membership,
            row.leader,
            row.ready,
            row.key
        );
    }
}

fn truncate_cell(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_owned();
    }
    value
        .chars()
        .take(max_chars.saturating_sub(3))
        .chain("...".chars())
        .collect()
}

fn render_human(report: &CheckReport) {
    println!("Zone {} admin check", report.zone_id);
    println!(
        "Portal {} at finalized Tempo block {} ({})",
        report.portal.portal,
        report.portal.finalized_block_number,
        report.portal.finalized_block_hash
    );
    println!(
        "Sequencers: {}  Threshold: {}  Version: {}",
        report.portal.sequencers.len(),
        report.portal.threshold,
        report.portal.sequencer_set_version
    );
    println!(
        "Leader: {}  Epoch: {}",
        report.portal.leader, report.portal.leader_epoch
    );
    println!(
        "Finalized L1 batch: {}  Zone height: {}",
        report.portal.withdrawal_batch_index, report.portal.zone_height
    );
    match report.portal.encryption_key {
        Some(key) => println!("Encryption key: x={} parity={}", key.x, key.y_parity),
        None => println!("Encryption key: not configured"),
    }
    if let Some(path) = report.manifest_path.as_ref() {
        println!("Desired manifest: {}", path.display());
    } else {
        println!("Desired manifest: not supplied (live consistency only)");
    }
    println!();
    render_node_table(report);
    println!();
    for invariant in &report.invariants {
        let marker = match invariant.status {
            CheckStatus::Pass => "PASS",
            CheckStatus::Fail => "FAIL",
            CheckStatus::Skipped => "SKIP",
        };
        println!("[{marker}] {:<34} {}", invariant.name, invariant.detail);
    }
    println!();
    println!(
        "Result: {}",
        if report.ok {
            "HEALTHY"
        } else {
            "CHECKS FAILED"
        }
    );
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use clap::Parser as _;

    use super::*;

    #[test]
    fn clap_accepts_emergency_cli_without_config_or_manifest() {
        let command = Check::try_parse_from([
            "check",
            "--zone-id",
            "7",
            "--l1-rpc-url",
            "https://l1.example",
            "--operator-rpc",
            "node-a=https://node-a.example",
            "--operator-rpc",
            "https://node-b.example",
            "--observe-for",
            "0s",
            "--json",
        ])
        .unwrap();
        assert_eq!(command.shared.zone_id, Some(7));
        assert_eq!(command.shared.operator_rpcs.len(), 2);
        assert_eq!(command.observe_for, Duration::ZERO);
        assert!(command.shared.zone_manifest.is_none());
        assert!(command.shared.json);
    }

    #[test]
    fn clap_accepts_wait_ready() {
        let command = Check::try_parse_from([
            "check",
            "--zone-id",
            "1",
            "--l1-rpc-url",
            "https://l1.example",
            "--operator-rpc",
            "http://127.0.0.1:1",
            "--wait-ready",
            "--node",
            "node-b",
            "--timeout",
            "5m",
        ])
        .unwrap();
        assert!(command.wait_ready);
        assert_eq!(command.node.as_deref(), Some("node-b"));
    }

    #[test]
    fn table_status_honors_column_width() {
        assert_eq!(format!("{:<8}", TableStatus::Pass), "PASS    ");
        assert_eq!(format!("{:<8}", TableStatus::Fail), "FAIL    ");
        assert_eq!(format!("{:<8}", TableStatus::NotAvailable), "N/A     ");
    }
}
