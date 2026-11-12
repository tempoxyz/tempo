//! Controlled process outages, not container termination or automatic leader failover.

use alloy::{
    primitives::Address,
    providers::Provider as _,
    rpc::types::{BlockId, BlockNumberOrTag, TransactionReceipt},
};
use antithesis_sdk::{assert_always, assert_reachable};
use eyre::{OptionExt as _, WrapErr as _};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    fs::{self, File},
    future::Future,
    io::Write as _,
    path::{Path, PathBuf},
    time::Duration,
};
use tempo_contracts::zones::ZonePortal;
use tokio::time::{Instant, timeout};

use super::{
    ADMIN_INDEX, Account, Context, POLL, Record, SEQUENCER_INDICES, handoff,
    intents::{Chain, Effect, Intent},
    is_rpc_error, random_index,
    recovery::{FinalizedCheckpoint, ReceiptProof, recover_until},
};

// Both intentional holds must finish before the supervisor's independent 180-second watchdog.
const HOLD_TIMEOUT: Duration = Duration::from_secs(150);
const PHASE_TIMEOUT: Duration = Duration::from_secs(180);
const EPISODE_TIMEOUT: Duration = Duration::from_secs(1200);

macro_rules! phase {
    ($($case:ident,)? $message:literal, $duration:expr, $work:expr) => {{
        let result = timeout($duration, $work).await
            .wrap_err(concat!($message, ": timed out")).and_then(|result| result);
        phase!(@assert $($case,)? $message, result);
        result.wrap_err($message)
    }};
    // The SDK catalogs constant messages as property IDs; details do not separate cases.
    (@assert $case:ident, $message:literal, $result:ident) => {
        match $case {
            Case::Backup => phase!(@assert concat!("Backup outage: ", $message), $result),
            Case::Leader => phase!(@assert concat!("Leader outage: ", $message), $result),
        }
    };
    (@assert $message:expr, $result:ident) => {
        assert_always!($result.is_ok(), $message,
            &json!({"error": $result.as_ref().err().map(|error| format!("{error:#}"))}))
    };
}

/// The role of the process intentionally crashed in the first phase.
#[derive(Debug, Clone, Copy, clap::ValueEnum, Serialize)]
pub(super) enum Case {
    /// Leaves the current leader running.
    Backup,
    /// Crashes the leader and explicitly hands leadership to a healthy sequencer as admin.
    Leader,
}

impl Context {
    /// Serializes a bounded outage episode; no RPC error or missing evidence counts as a skip.
    pub(super) async fn single_sequencer_outage(
        &self,
        dir: &Path,
        case: Option<Case>,
    ) -> eyre::Result<()> {
        let case = case.unwrap_or_else(|| {
            if random_index(2) == 0 {
                Case::Backup
            } else {
                Case::Leader
            }
        });
        phase!(
            case,
            "Single-sequencer outage episode finishes within the quiet window",
            EPISODE_TIMEOUT,
            async {
                let _lock = self.ledger.episode_lock(true).await?;
                self.release_outages(dir).await?;
                eyre::ensure!(
                    self.zones.len() == 4,
                    "outage requires three sequencers and one RPC-only node"
                );
                let all: Vec<_> = (0..self.zones.len()).collect();
                let members = SEQUENCER_INDICES
                    .map(|index| Ok(Account::at(index)?.address()))
                    .collect::<eyre::Result<Vec<_>>>()?;
                let (baseline, membership) = phase!(
                    case,
                    "Outage preconditions become ready",
                    PHASE_TIMEOUT,
                    async {
                        recover_until(Instant::now() + PHASE_TIMEOUT, async || {
                            if !self.reconcile_intents().await? {
                                return Ok(None);
                            }
                            let checkpoint = self.finalized_checkpoint().await?;
                            if checkpoint.hash.is_zero() {
                                return Ok(None);
                            }
                            for zone in &self.zones {
                                let block =
                                    zone.get_block_by_number(checkpoint.height.into()).await?;
                                let Some(block) = block else {
                                    return Ok(None);
                                };
                                eyre::ensure!(
                                    block.header.hash == checkpoint.hash,
                                    "zone node disagrees with the pre-outage finalized baseline"
                                );
                            }
                            let membership = self
                                .outage_membership(BlockId::hash(checkpoint.l1_hash))
                                .await?;
                            membership.validate(&members)?;
                            // A previous driver's lost reply may leave a handoff awaiting finality.
                            // Wait it out before the kill; any change DURING the outage still fails.
                            if self.outage_membership(BlockId::latest()).await? != membership {
                                return Ok(None);
                            }
                            Ok(Some((checkpoint, membership)))
                        })
                        .await
                    }
                )?;
                let leader = members
                    .iter()
                    .position(|address| *address == membership.leader)
                    .ok_or_eyre("leader is not one of the controlled sequencers")?;
                let backups: Vec<_> = (0..3).filter(|node| *node != leader).collect();
                let victim = match case {
                    Case::Backup => backups[random_index(2)],
                    Case::Leader => leader,
                };
                let active = match case {
                    Case::Backup => leader,
                    Case::Leader => backups[random_index(2)],
                };
                let mut expected = membership.clone();
                let max_tip = self.maximum_zone_tip().await?;
                let mut held = Hold::new(self, dir, victim)?;
                let outage = phase!(
                    case,
                    "Fresh settlement progresses while the first sequencer stays down",
                    HOLD_TIMEOUT,
                    async {
                        held.kill().await?;
                        held.while_down(async {
                            if matches!(case, Case::Leader) {
                                phase!(
                                    "Leader outage: Explicit admin handoff from the crashed leader finalizes",
                                    HOLD_TIMEOUT,
                                    self.outage_handoff(&membership, members[active])
                                )?;
                                expected.leader = members[active];
                                expected.epoch = expected
                                    .epoch
                                    .checked_add(1)
                                    .ok_or_eyre("leader epoch overflow")?;
                            }
                            self.outage_canary(&baseline, max_tip, active, victim, &expected)
                                .await
                        })
                        .await
                    }
                );
                let restored = phase!(
                    case,
                    "First crashed sequencer restarts",
                    PHASE_TIMEOUT,
                    held.restore()
                );
                let (settled, canary) = outage?;
                restored?;
                phase!(
                    case,
                    "Restarted sequencer catches up to the exact finalized receipt and hash",
                    PHASE_TIMEOUT,
                    async {
                        recover_until(Instant::now() + PHASE_TIMEOUT, async || {
                            Ok(self
                                .check_checkpoint(&baseline, &settled, &canary, &all)
                                .await?
                                .then_some(()))
                        })
                        .await
                    }
                )?;
                match case {
                    Case::Backup => assert_reachable!(
                        "Backup outage: A controlled sequencer restarts and catches up after outage settlement",
                        &json!({"case": case, "victim": victim, "canary": canary})
                    ),
                    Case::Leader => assert_reachable!(
                        "Leader outage: A controlled sequencer restarts and catches up after outage settlement",
                        &json!({"case": case, "victim": victim, "canary": canary})
                    ),
                }

                // With unchanged 2-of-3 membership, leader + restarted victim are the ONLY two
                // available signers. The canary is signed AFTER the other backup is reaped and its
                // height exceeds every pre-kill tip: no pre-outage block/signature can settle it.
                // A finalized checkpoint containing it therefore requires a fresh victim attestation.
                let other = (0..3)
                    .find(|node| *node != victim && *node != active)
                    .ok_or_eyre("no other backup for attestation proof")?;
                let max_tip = self.maximum_zone_tip().await?;
                let mut held = Hold::new(self, dir, other)?;
                let attestation = phase!(
                    case,
                    "Restarted victim participates in fresh settlement with the other backup down",
                    HOLD_TIMEOUT,
                    async {
                        held.kill().await?;
                        held.while_down(
                            self.outage_canary(&settled, max_tip, active, other, &expected),
                        )
                        .await
                    }
                );
                let restored = phase!(
                    case,
                    "Other backup restarts after the attestation proof",
                    PHASE_TIMEOUT,
                    held.restore()
                );
                let (fresh, second) = attestation?;
                restored?;
                phase!(
                    case,
                    "All zone nodes converge after the single-sequencer outage episode",
                    PHASE_TIMEOUT,
                    async {
                        recover_until(Instant::now() + PHASE_TIMEOUT, async || {
                            let first = self
                                .check_checkpoint(&baseline, &fresh, &canary, &all)
                                .await?;
                            let second = self
                                .check_checkpoint(&settled, &fresh, &second, &all)
                                .await?;
                            Ok((first && second).then_some(()))
                        })
                        .await
                    }
                )?;
                match case {
                    Case::Backup => assert_reachable!(
                        "Backup process outage settles and the restarted victim freshly attests",
                        &json!({"victim": victim, "fresh": fresh, "canary": second})
                    ),
                    Case::Leader => assert_reachable!(
                        "Leader process outage with explicit admin handoff settles and the restarted victim freshly attests",
                        &json!({"victim": victim, "leader": active, "fresh": fresh, "canary": second})
                    ),
                }
                println!(
                    "single-sequencer-outage: {}",
                    json!({"case": case, "victim": victim, "active_leader": active, "other_backup": other, "settled": fresh, "canary": second})
                );
                Ok(())
            }
        )
    }

    /// Releases persistent holds after cancellation. Caller owns the exclusive episode lock.
    /// A running marker is only a control acknowledgement, never evidence of RPC recovery.
    pub(super) async fn release_outages(&self, dir: &Path) -> eyre::Result<()> {
        phase!(
            "Intentional sequencer holds are released",
            PHASE_TIMEOUT,
            async {
                // Write every release before waiting, so one missing supervisor cannot strand another.
                let mut requests = Vec::new();
                for node in 0..3 {
                    let id = self.ledger.next_id()?;
                    write_request(dir, node, id, "start")?;
                    requests.push((node, id));
                }
                recover_until(Instant::now() + PHASE_TIMEOUT, async || {
                    for &(node, id) in &requests {
                        let status = match read_status(dir, node) {
                            Ok(status) => status,
                            Err(error)
                                if error.downcast_ref::<std::io::Error>().is_some_and(
                                    |error| error.kind() == std::io::ErrorKind::NotFound,
                                ) =>
                            {
                                return Ok(None);
                            }
                            Err(error) => return Err(error),
                        };
                        if status.id != id || status.state != State::Running {
                            return Ok(None);
                        }
                    }
                    Ok(Some(()))
                })
                .await
            }
        )
    }

    async fn maximum_zone_tip(&self) -> eyre::Result<u64> {
        let mut maximum = 0;
        for zone in &self.zones {
            maximum = maximum.max(zone.get_block_number().await?);
        }
        Ok(maximum)
    }

    async fn outage_membership(&self, at: BlockId) -> eyre::Result<Membership> {
        let at = if at == BlockId::latest() {
            let block = self
                .l1
                .get_block_by_number(BlockNumberOrTag::Latest)
                .await?
                .ok_or_eyre("no latest L1 membership snapshot")?;
            BlockId::hash(block.header.hash)
        } else {
            at
        };
        let portal = ZonePortal::new(self.portal, &self.l1);
        Ok(Membership {
            members: portal.sequencers_at(at).await?,
            threshold: portal.sequencerThreshold().block(at).call().await?,
            version: portal.sequencerSetVersion().block(at).call().await?,
            leader: portal.leader().block(at).call().await?,
            epoch: portal.leaderEpoch().block(at).call().await?,
        })
    }

    async fn outage_handoff(&self, prior: &Membership, target: Address) -> eyre::Result<()> {
        let admin = Account::at(ADMIN_INDEX)?;
        let _lease = self
            .ledger
            .try_lease(&admin)?
            .ok_or_eyre("outage handoff admin is busy")?;
        let request = ZonePortal::new(self.portal, &self.l1)
            .setLeader(target, prior.epoch)
            .into_transaction_request();
        let intent = self
            .prepare_intent(&admin, Chain::L1, 0, request, Effect::Leadership { target })
            .await?;
        self.ledger
            .append(&Record::HandoffRequest(handoff::Request {
                id: self.ledger.next_id()?,
                previous_leader: prior.leader,
                expected_epoch: prior.epoch,
                target,
                relayed: false,
                from_l1_block: self.l1.get_block_number().await?,
                l1_tx: Some(intent.tx),
            }))?;
        let receipt = self.outage_receipt(&intent).await?;
        eyre::ensure!(receipt.status(), "explicit outage handoff reverted");
        recover_until(Instant::now() + HOLD_TIMEOUT, async || {
            let update = self
                .canonical_handoffs()
                .await?
                .into_iter()
                .find(|event| event.l1_tx == intent.tx);
            let Some(update) = update else {
                return Ok(None);
            };
            eyre::ensure!(
                update.previous_leader == prior.leader
                    && update.new_leader == target
                    && Some(update.epoch) == prior.epoch.checked_add(1),
                "unexpected finalized outage handoff"
            );
            Ok(Some(()))
        })
        .await
    }

    async fn outage_canary(
        &self,
        baseline: &FinalizedCheckpoint,
        max_tip: u64,
        active: usize,
        down: usize,
        expected: &Membership,
    ) -> eyre::Result<(FinalizedCheckpoint, ReceiptProof)> {
        let deadline = Instant::now() + HOLD_TIMEOUT;
        let intent = recover_until(deadline, async || {
            self.prepare_recovery_canary(active).await
        })
        .await?;
        let receipt = self.outage_receipt(&intent).await?;
        let canary = ReceiptProof {
            tx: receipt.transaction_hash,
            height: receipt
                .block_number
                .ok_or_eyre("outage canary has no height")?,
            hash: receipt
                .block_hash
                .ok_or_eyre("outage canary has no block hash")?,
            success: receipt.status(),
        };
        ensure_fresh(&canary, max_tip)?;
        let live: Vec<_> = (0..self.zones.len()).filter(|node| *node != down).collect();
        let settled = recover_until(deadline, async || {
            let settled = self.finalized_checkpoint().await?;
            if settled.height < canary.height {
                return Ok(None);
            }
            eyre::ensure!(
                self.outage_membership(BlockId::hash(settled.l1_hash))
                    .await?
                    == *expected,
                "portal membership or leadership changed during outage"
            );
            eyre::ensure!(
                self.outage_membership(BlockId::latest()).await? == *expected,
                "unfinalized portal change during outage"
            );
            Ok(self
                .check_checkpoint(baseline, &settled, &canary, &live)
                .await?
                .then_some(settled))
        })
        .await?;
        Ok((settled, canary))
    }

    // Reconcile only this exact transaction on its known-live endpoint, never poll the dead node.
    async fn outage_receipt(&self, intent: &Intent) -> eyre::Result<TransactionReceipt> {
        let provider = match intent.chain {
            Chain::L1 => &self.l1,
            Chain::Zone => &self.zones[intent.node],
        };
        recover_until(Instant::now() + HOLD_TIMEOUT, async || {
            if let Some(receipt) = provider.get_transaction_receipt(intent.tx).await? {
                self.ledger.resolve_intent(intent, &receipt)?;
                return Ok(Some(receipt));
            }
            match provider.send_raw_transaction(&intent.raw).await {
                Ok(_) => {}
                Err(error) => {
                    let error = eyre::Report::from(error);
                    if !is_rpc_error(&error) {
                        return Err(error);
                    }
                    println!(
                        "outage transaction {} remains unresolved: {error:#}",
                        intent.tx
                    );
                }
            }
            Ok(None)
        })
        .await
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Membership {
    members: Vec<Address>,
    threshold: u8,
    version: u64,
    leader: Address,
    epoch: u64,
}

impl Membership {
    fn validate(&self, expected: &[Address]) -> eyre::Result<()> {
        let mut members = self.members.clone();
        members.sort();
        let mut expected = expected.to_vec();
        expected.sort();
        eyre::ensure!(
            self.threshold == 2 && members.len() == 3 && members == expected,
            "fresh attestation proof requires exactly the three controlled sequencers and threshold two"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum State {
    Running,
    Down,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct Status {
    id: u64,
    state: State,
    generation: u64,
}

// A reserved START request is armed before KILL is written. Cancellation of any await drops it.
struct Hold {
    dir: PathBuf,
    node: usize,
    kill_id: u64,
    start_id: u64,
    generation: u64,
    armed: bool,
}

impl Hold {
    fn new(ctx: &Context, dir: &Path, node: usize) -> eyre::Result<Self> {
        eyre::ensure!(
            node < 3,
            "RPC-only node cannot be a controlled outage victim"
        );
        let status = read_status(dir, node)?;
        eyre::ensure!(
            status.state == State::Running,
            "outage victim is not running before kill"
        );
        let kill_id = ctx.ledger.next_id()?;
        let start_id = ctx.ledger.next_id()?;
        eyre::ensure!(kill_id > status.id, "outage request sequence is stale");
        Ok(Self {
            dir: dir.to_path_buf(),
            node,
            kill_id,
            start_id,
            generation: status.generation,
            armed: true,
        })
    }

    async fn kill(&self) -> eyre::Result<()> {
        write_request(&self.dir, self.node, self.kill_id, "kill")?;
        recover_until(Instant::now() + Duration::from_secs(20), async || {
            let status = read_status(&self.dir, self.node)?;
            if status.id != self.kill_id {
                return Ok(None);
            }
            ensure_down(status, self.kill_id, self.generation)?;
            Ok(Some(()))
        })
        .await
    }

    async fn while_down<T>(&self, work: impl Future<Output = eyre::Result<T>>) -> eyre::Result<T> {
        let check = || {
            ensure_down(
                read_status(&self.dir, self.node)?,
                self.kill_id,
                self.generation,
            )
        };
        check()?;
        tokio::pin!(work);
        let result = loop {
            tokio::select! {
                result = &mut work => break result,
                () = tokio::time::sleep(POLL) => check()?,
            }
        };
        check()?; // Even a watchdog restart during the final RPC must invalidate the evidence.
        result
    }

    async fn restore(&mut self) -> eyre::Result<()> {
        write_request(&self.dir, self.node, self.start_id, "start")?;
        recover_until(Instant::now() + Duration::from_secs(30), async || {
            let status = read_status(&self.dir, self.node)?;
            Ok((status.id == self.start_id
                && status.state == State::Running
                && status.generation > self.generation)
                .then_some(()))
        })
        .await?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        if self.armed
            && let Err(error) = write_request(&self.dir, self.node, self.start_id, "start")
        {
            eprintln!(
                "failed releasing controlled sequencer {} on cancellation: {error:#}",
                self.node
            );
        }
    }
}

fn read_status(dir: &Path, node: usize) -> eyre::Result<Status> {
    serde_json::from_slice(
        &fs::read(dir.join(format!("zone-{node}.status")))
            .wrap_err("failed reading sequencer supervisor status")?,
    )
    .wrap_err("invalid sequencer supervisor status")
}

fn write_request(dir: &Path, node: usize, id: u64, action: &str) -> eyre::Result<()> {
    let temporary = dir.join(format!("zone-{node}.{id}.{}.tmp", std::process::id()));
    let mut file =
        File::create(&temporary).wrap_err("failed creating sequencer control request")?;
    file.write_all(&serde_json::to_vec(&json!({"id": id, "action": action}))?)?;
    file.sync_all()
        .wrap_err("failed syncing sequencer control request")?;
    fs::rename(&temporary, dir.join(format!("zone-{node}.request")))
        .wrap_err("failed publishing sequencer control request")?;
    File::open(dir)?
        .sync_all()
        .wrap_err("failed syncing control directory")
}

fn ensure_down(status: Status, id: u64, generation: u64) -> eyre::Result<()> {
    eyre::ensure!(
        status.id == id && status.state == State::Down && status.generation == generation,
        "sequencer recovered early or its controlled outage acknowledgement changed"
    );
    Ok(())
}

fn ensure_fresh(canary: &ReceiptProof, maximum_pre_kill_tip: u64) -> eyre::Result<()> {
    eyre::ensure!(canary.success, "outage canary reverted");
    eyre::ensure!(
        canary.height > maximum_pre_kill_tip,
        "outage canary can reuse pre-kill signatures"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::Ledger;
    use alloy::{
        primitives::{B256, Bloom, Bytes, keccak256},
        providers::ProviderBuilder,
        transports::mock::Asserter,
    };

    use std::collections::BTreeMap;

    #[test]
    fn outage_cases_have_independent_sdk_catalog_properties() {
        let class = module_path!().strip_suffix("::tests").unwrap();
        let entries: Vec<_> = antithesis_sdk::assert::ANTITHESIS_CATALOG
            .iter()
            .filter(|entry| entry.class == class)
            .collect();
        let actual: BTreeMap<_, _> = entries
            .iter()
            .map(|entry| {
                assert_eq!(entry.id, entry.message);
                assert!(entry.must_hit);
                (entry.id.to_owned(), entry.display_type)
            })
            .collect();
        assert_eq!(actual.len(), entries.len(), "duplicate outage property IDs");
        let mut expected = BTreeMap::new();
        for case in ["Backup", "Leader"] {
            for phase in [
                "Single-sequencer outage episode finishes within the quiet window",
                "Outage preconditions become ready",
                "Fresh settlement progresses while the first sequencer stays down",
                "First crashed sequencer restarts",
                "Restarted sequencer catches up to the exact finalized receipt and hash",
                "Restarted victim participates in fresh settlement with the other backup down",
                "Other backup restarts after the attestation proof",
                "All zone nodes converge after the single-sequencer outage episode",
            ] {
                expected.insert(format!("{case} outage: {phase}"), "Always");
            }
            expected.insert(
                format!("{case} outage: A controlled sequencer restarts and catches up after outage settlement"),
                "Reachable",
            );
        }
        expected.insert(
            "Leader outage: Explicit admin handoff from the crashed leader finalizes".to_owned(),
            "Always",
        );
        for message in [
            "Backup process outage settles and the restarted victim freshly attests",
            "Leader process outage with explicit admin handoff settles and the restarted victim freshly attests",
        ] {
            expected.insert(message.to_owned(), "Reachable");
        }
        // Cleanup is the only property shared between the two episodes and terminal checks.
        expected.insert(
            "Intentional sequencer holds are released".to_owned(),
            "Always",
        );
        assert_eq!(actual, expected);
    }

    fn status(dir: &Path, id: u64, state: &str, generation: u64) {
        fs::write(
            dir.join("zone-0.status"),
            serde_json::to_vec(&json!({"id": id, "state": state, "generation": generation}))
                .unwrap(),
        )
        .unwrap();
    }

    fn hold(dir: &Path) -> Hold {
        Hold {
            dir: dir.to_path_buf(),
            node: 0,
            kill_id: 10,
            start_id: 11,
            generation: 3,
            armed: true,
        }
    }

    #[test]
    fn watchdog_restart_stale_ack_and_changed_generation_cannot_pass() {
        assert!(
            ensure_down(
                Status {
                    id: 10,
                    state: State::Down,
                    generation: 3
                },
                10,
                3
            )
            .is_ok()
        );
        for status in [
            Status {
                id: 10,
                state: State::Running,
                generation: 4,
            },
            Status {
                id: 9,
                state: State::Down,
                generation: 3,
            },
            Status {
                id: 10,
                state: State::Down,
                generation: 4,
            },
        ] {
            assert_eq!(
                ensure_down(status, 10, 3).unwrap_err().to_string(),
                "sequencer recovered early or its controlled outage acknowledgement changed"
            );
        }
    }

    #[test]
    fn old_height_and_reverted_canary_cannot_prove_new_attestation() {
        let mut canary = ReceiptProof {
            tx: B256::repeat_byte(1),
            height: 101,
            hash: B256::repeat_byte(2),
            success: true,
        };
        assert!(ensure_fresh(&canary, 100).is_ok());
        for height in [99, 100] {
            canary.height = height;
            assert_eq!(
                ensure_fresh(&canary, 100).unwrap_err().to_string(),
                "outage canary can reuse pre-kill signatures"
            );
        }
        canary.height = 101;
        canary.success = false;
        assert_eq!(
            ensure_fresh(&canary, 100).unwrap_err().to_string(),
            "outage canary reverted"
        );
    }

    #[test]
    fn forced_signer_proof_rejects_threshold_one_extra_or_substituted_signers() {
        let addresses: Vec<_> = (1..=3).map(Address::repeat_byte).collect();
        let valid = Membership {
            members: addresses.clone(),
            threshold: 2,
            version: 1,
            leader: addresses[0],
            epoch: 1,
        };
        assert!(valid.validate(&addresses).is_ok());
        for members in [
            vec![addresses[0], addresses[1]],
            vec![addresses[0], addresses[1], Address::repeat_byte(4)],
            vec![
                addresses[0],
                addresses[1],
                addresses[2],
                Address::repeat_byte(4),
            ],
            vec![addresses[0]; 3],
        ] {
            let invalid = Membership {
                members,
                ..valid.clone()
            };
            assert_eq!(
                invalid.validate(&addresses).unwrap_err().to_string(),
                "fresh attestation proof requires exactly the three controlled sequencers and threshold two"
            );
        }
        for threshold in [0, 1, 3] {
            let invalid = Membership {
                threshold,
                ..valid.clone()
            };
            assert_eq!(
                invalid.validate(&addresses).unwrap_err().to_string(),
                "fresh attestation proof requires exactly the three controlled sequencers and threshold two"
            );
        }
        // Even restoring the same addresses after changing membership changes its monotonic version.
        assert_ne!(
            valid,
            Membership {
                version: 2,
                ..valid.clone()
            }
        );
        assert_ne!(
            valid,
            Membership {
                epoch: 2,
                ..valid.clone()
            }
        );
    }

    #[tokio::test]
    async fn last_observation_catches_watchdog_restart_during_final_rpc() {
        let dir = tempfile::tempdir().unwrap();
        status(dir.path(), 10, "down", 3);
        let held = hold(dir.path());
        let result = held
            .while_down(async {
                status(dir.path(), 10, "running", 4);
                Ok(())
            })
            .await;
        assert_eq!(
            result.unwrap_err().to_string(),
            "sequencer recovered early or its controlled outage acknowledgement changed"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn monitor_rejects_autoheal_while_rpc_never_finishes() {
        let dir = tempfile::tempdir().unwrap();
        status(dir.path(), 10, "down", 3);
        let held = hold(dir.path());
        let result = held
            .while_down(async {
                tokio::time::sleep(POLL / 2).await;
                status(dir.path(), 10, "running", 4);
                std::future::pending::<eyre::Result<()>>().await
            })
            .await;
        assert_eq!(
            result.unwrap_err().to_string(),
            "sequencer recovered early or its controlled outage acknowledgement changed"
        );
    }

    #[tokio::test]
    async fn cancellation_and_error_both_publish_new_id_start_requests() {
        let dir = tempfile::tempdir().unwrap();
        status(dir.path(), 10, "down", 3);
        let cancelled = timeout(Duration::from_millis(1), async {
            let held = hold(dir.path());
            held.while_down(std::future::pending::<eyre::Result<()>>())
                .await
        })
        .await;
        assert!(cancelled.is_err());
        let request: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.path().join("zone-0.request")).unwrap()).unwrap();
        assert_eq!(request, json!({"id": 11, "action": "start"}));
        let result: eyre::Result<()> = {
            let held = hold(dir.path());
            held.while_down(async { eyre::bail!("invalid receipt") })
                .await
        };
        assert_eq!(result.unwrap_err().to_string(), "invalid receipt");
        let request: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.path().join("zone-0.request")).unwrap()).unwrap();
        assert_eq!(request, json!({"id": 11, "action": "start"}));
    }

    #[tokio::test(start_paused = true)]
    async fn restart_requires_new_generation_not_a_stale_running_marker() {
        let dir = tempfile::tempdir().unwrap();
        status(dir.path(), 11, "running", 3);
        let mut held = hold(dir.path());
        assert_eq!(
            held.restore().await.unwrap_err().to_string(),
            "recovery observation timed out"
        );
        assert!(held.armed);
        status(dir.path(), 11, "running", 4);
        held.restore().await.unwrap();
        assert!(!held.armed);
    }

    #[tokio::test(start_paused = true)]
    async fn kill_requires_reaped_matching_ack_and_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        status(dir.path(), 9, "down", 3);
        let held = hold(dir.path());
        assert_eq!(
            held.kill().await.unwrap_err().to_string(),
            "recovery observation timed out"
        );
        status(dir.path(), 10, "down", 3);
        held.kill().await.unwrap();
        status(dir.path(), 10, "running", 4);
        assert_eq!(
            held.kill().await.unwrap_err().to_string(),
            "sequencer recovered early or its controlled outage acknowledgement changed"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn phase_timeout_and_errors_are_failures_not_skips() {
        for case in [Case::Backup, Case::Leader] {
            let result = phase!(
                case,
                "Test outage phase",
                Duration::from_secs(1),
                std::future::pending::<eyre::Result<()>>()
            );
            assert_eq!(
                format!("{:#}", result.unwrap_err()),
                "Test outage phase: Test outage phase: timed out: deadline has elapsed"
            );
            let result: eyre::Result<()> =
                phase!(case, "Test outage phase", Duration::from_secs(1), async {
                    eyre::bail!("broken proof")
                });
            assert_eq!(
                format!("{:#}", result.unwrap_err()),
                "Test outage phase: broken proof"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn exclusive_episode_blocks_handoffs_and_other_episodes_without_skipping() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::open(dir.path()).unwrap();
        let exclusive = ledger.episode_lock(true).await.unwrap();
        for other_exclusive in [true, false] {
            assert_eq!(
                ledger
                    .episode_lock(other_exclusive)
                    .await
                    .unwrap_err()
                    .to_string(),
                "recovery observation timed out"
            );
        }
        drop(exclusive);
        let first = ledger.episode_lock(false).await.unwrap();
        let second = ledger.episode_lock(false).await.unwrap();
        assert_eq!(
            ledger.episode_lock(true).await.unwrap_err().to_string(),
            "recovery observation timed out"
        );
        drop((first, second));
        assert!(ledger.episode_lock(true).await.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn canary_receipt_uses_only_live_endpoint_and_leaves_other_intents_pending() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::open(dir.path()).unwrap();
        let sender = ledger.new_account().unwrap();
        let raw = Bytes::from_static(b"outage canary signed bytes");
        let intent = Intent {
            tx: keccak256(&raw),
            raw,
            chain: Chain::Zone,
            chain_id: 123,
            sender: sender.address(),
            nonce: 0,
            node: 1,
            effect: Effect::Transfer {
                to: Address::repeat_byte(2),
                amount: 1,
            },
        };
        ledger.append(&Record::Intent(intent.clone())).unwrap();
        let mut other = intent.clone();
        other.raw = Bytes::from_static(b"unrelated signed bytes");
        other.tx = keccak256(&other.raw);
        other.nonce = 1;
        other.node = 0;
        ledger.append(&Record::Intent(other.clone())).unwrap();
        let dead = Asserter::new();
        dead.push_failure_msg("dead endpoint must not be touched");
        let l1 = Asserter::new();
        l1.push_failure_msg("unrelated L1 intents must not be reconciled");
        let live = Asserter::new();
        live.push_success(&None::<TransactionReceipt>);
        live.push_failure_msg("broadcast reply lost");
        live.push_success(
            &json!({ "type": "0x0", "status": "0x1", "cumulativeGasUsed": "0x1",
            "logs": [], "logsBloom": Bloom::ZERO, "transactionHash": intent.tx,
            "transactionIndex": "0x0", "blockHash": B256::repeat_byte(4),
            "blockNumber": "0x65", "gasUsed": "0x1", "effectiveGasPrice": "0x1",
            "from": intent.sender, "to": Address::repeat_byte(2), "contractAddress": null }),
        );
        let ctx = Context {
            ledger,
            http: Default::default(),
            l1_url: "http://l1.invalid".parse().unwrap(),
            l1: ProviderBuilder::new()
                .connect_mocked_client(l1.clone())
                .erased(),
            zone_urls: ["http://dead.invalid", "http://live.invalid"]
                .map(|url| url.parse().unwrap())
                .to_vec(),
            zones: [dead.clone(), live.clone()]
                .into_iter()
                .map(|mock| ProviderBuilder::new().connect_mocked_client(mock).erased())
                .collect(),
            portal: Address::repeat_byte(9),
        };
        let receipt = ctx.outage_receipt(&intent).await.unwrap();
        assert_eq!(receipt.transaction_hash, intent.tx);
        assert_eq!(receipt.block_number, Some(101));
        assert_eq!(dead.read_q().len(), 1);
        assert_eq!(l1.read_q().len(), 1);
        assert!(live.read_q().is_empty());
        assert_eq!(
            crate::intents::pending(&ctx.ledger.records().unwrap()).unwrap(),
            vec![other]
        );
    }

    #[test]
    fn control_json_is_atomic_strict_and_preserves_full_u64_ids() {
        let dir = tempfile::tempdir().unwrap();
        write_request(dir.path(), 0, u64::MAX, "start").unwrap();
        let request: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.path().join("zone-0.request")).unwrap()).unwrap();
        assert_eq!(request["id"].as_u64(), Some(u64::MAX));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        assert!(
            serde_json::from_str::<Status>(
                r#"{"id":1,"state":"down","generation":1,"extra":true}"#
            )
            .unwrap_err()
            .to_string()
            .contains("unknown field")
        );
        assert!(
            serde_json::from_str::<Status>(r#"{"id":1,"state":"expired","generation":1}"#)
                .unwrap_err()
                .to_string()
                .contains("unknown variant")
        );
    }
}
