//! Controlled lagging-successor and overlapping handoffs, with one clock from restart to proof.

use alloy::{providers::Provider as _, rpc::types::TransactionReceipt};
use antithesis_sdk::{assert_always, assert_reachable, assert_sometimes};
use eyre::{OptionExt as _, WrapErr as _};
use serde::Serialize;
use serde_json::json;
use std::{path::Path, time::Duration};
use tokio::time::{Instant, timeout, timeout_at};

use super::{
    Account, Context, SEQUENCER_INDICES, is_rpc_error,
    outage::Hold,
    random_index,
    recovery::{ReceiptProof, recover_until},
};

const PRECONDITION_TIMEOUT: Duration = Duration::from_secs(180);
// Includes both handoffs, and remains below the independent 180-second supervisor watchdog.
const HELD_TIMEOUT: Duration = Duration::from_secs(150);
const RECOVERY_TIMEOUT: Duration = Duration::from_secs(180);
const EPISODE_TIMEOUT: Duration = Duration::from_secs(900);

macro_rules! phase {
    ($case:ident, $message:literal, $duration:expr, $work:expr) => {{
        let result = timeout($duration, $work).await
            .wrap_err(concat!($message, ": timed out")).and_then(|result| result);
        phase!(@assert $case, $message, result);
        result.wrap_err($message)
    }};
    (@assert $case:ident, $message:literal, $result:ident) => {
        match $case {
            Case::LaggingSuccessor => assert_always!($result.is_ok(),
                concat!("Lagging successor: ", $message),
                &json!({"error": $result.as_ref().err().map(|error| format!("{error:#}"))})),
            Case::OverlappingHandoffs => assert_always!($result.is_ok(),
                concat!("Overlapping handoffs: ", $message),
                &json!({"error": $result.as_ref().err().map(|error| format!("{error:#}"))})),
        }
    };
}

/// Selects an explicit controlled episode; omission chooses using Antithesis randomness.
#[derive(Debug, Clone, Copy, clap::ValueEnum, Serialize)]
pub(super) enum Case {
    /// Crashes the successor before a durable predecessor tail and promotes it while behind.
    LaggingSuccessor,
    /// Returns A→B→A while B is still down, before the first promotion can drain.
    OverlappingHandoffs,
}

impl Context {
    /// Holds the exclusive episode lock and never clears ambiguous relay submissions.
    /// Started episodes fail on missing evidence; only unprovable prior quiescence may skip.
    pub(super) async fn handoff_campaign(
        &self,
        dir: &Path,
        case: Option<Case>,
    ) -> eyre::Result<()> {
        let case = case.unwrap_or_else(|| {
            if random_index(2) == 0 {
                Case::LaggingSuccessor
            } else {
                Case::OverlappingHandoffs
            }
        });
        let mut executed = false;
        let result = timeout(EPISODE_TIMEOUT, async {
            let _lock = self.ledger.episode_lock(true).await?;
            super::proxy::release_network_faults(dir).await?;
            self.release_outages(dir).await?;
            let drained = recover_until(Instant::now() + PRECONDITION_TIMEOUT, async || {
                let ready = self.handoffs_drained().await?;
                if !ready {
                    self.reconcile_intents().await?;
                }
                Ok(ready.then_some(()))
            }).await;
            if drained.as_ref().is_err_and(|error|
                error.downcast_ref::<tokio::time::error::Elapsed>().is_some()) {
                println!("handoff-campaign: {}", json!({"case": case, "result": "SKIPPED",
                    "reason": "prior handoff quiescence is unknown; no campaign fault injected"}));
                return Ok(());
            }
            drained?;
            let members = SEQUENCER_INDICES.map(|index| Ok(Account::at(index)?.address()))
                .collect::<eyre::Result<Vec<_>>>()?;
            let (baseline, initial) = phase!(case, "Preconditions become ready", PRECONDITION_TIMEOUT,
                self.outage_preconditions(&members))?;
            eyre::ensure!(self.zones.len() == 4, "handoff campaign requires four zone nodes");
            let leader = members.iter().position(|member| *member == initial.leader)
                .ok_or_eyre("campaign leader is not controlled")?;
            let backups: Vec<_> = (0..3).filter(|node| *node != leader).collect();
            let successor = backups[random_index(backups.len())];
            let mut held = Hold::new(self, dir, successor)?;
            executed = true;
            let fault = phase!(case, "Durable tail and journaled handoffs execute while successor stays down",
                HELD_TIMEOUT, async {
                    held.kill().await?;
                    held.while_down(async {
                        // A post-kill live leader tip bounds everything the stopped follower knew.
                        let mut ceiling = 0;
                        for (node, zone) in self.zones.iter().enumerate() {
                            if node != successor {
                                ceiling = ceiling.max(zone.get_block_number().await?);
                            }
                        }
                        let (tail, predecessor) = self.outage_canary(&baseline, ceiling, leader,
                            Some(successor), &initial).await?;
                        let inflight = recover_until(Instant::now() + HELD_TIMEOUT, async ||
                            self.prepare_recovery_canary(leader).await).await?;
                        // Submit without waiting for inclusion; a fast leader may include it
                        // before the transition. Recovery still resolves this exact intent.
                        match self.zones[leader].send_raw_transaction(&inflight.raw).await {
                            Ok(_) => {},
                            Err(error) => {
                                let error = eyre::Report::from(error);
                                if !is_rpc_error(&error) { return Err(error); }
                                println!("handoff in-flight send {} is unknown: {error:#}", inflight.tx);
                            }
                        }
                        let first = self.campaign_handoff(&initial, members[successor]).await?;
                        let mut expected = initial.clone();
                        expected.leader = first.new_leader;
                        expected.epoch = first.epoch;
                        let final_update = match case {
                            Case::LaggingSuccessor => first,
                            Case::OverlappingHandoffs => {
                                // Do not require independent progress from superseded B; recovery still
                                // preserves its historical interval if the predecessor prefix needs it.
                                let last = self.campaign_handoff(&expected, initial.leader).await?;
                                expected.leader = last.new_leader;
                                expected.epoch = last.epoch;
                                last
                            }
                        };
                        Ok((tail, predecessor, inflight, final_update, expected))
                    }).await
                });
            match case {
                Case::LaggingSuccessor => if fault.is_ok() {
                    assert_reachable!("Lagging successor: Admin promotes a successor missing the durable tail",
                        &json!({"successor": successor}));
                },
                Case::OverlappingHandoffs => if fault.is_ok() {
                    assert_reachable!("Overlapping handoffs: A to B to A finalizes before B can activate",
                        &json!({"successor": successor}));
                },
            }
            // The single recovery deadline includes the restart acknowledgement, activation,
            // pending canary, fresh canary, finality and every follower's exact prefix proof.
            let deadline = Instant::now() + RECOVERY_TIMEOUT;
            let recovered = timeout_at(deadline, async {
                let restored = held.restore().await;
                phase!(@assert case, "Successor restart is acknowledged", restored);
                let (tail, predecessor, inflight, update, expected) = match (fault, restored) {
                    (Ok(proof), Ok(())) => proof,
                    (Err(fault), Err(cleanup)) => eyre::bail!("handoff fault phase failed: {fault:#}; restart failed: {cleanup:#}"),
                    (Err(error), Ok(())) | (Ok(_), Err(error)) => return Err(error),
                };
                held.while_running(async {
                recover_until(deadline, async || {
                    Ok(self.handoff_term_ready(&update, &expected, None).await?.then_some(()))
                }).await?;
                let pending = receipt_proof(self.outage_receipt(&inflight).await?)?;
                eyre::ensure!(pending.tx == inflight.tx, "handoff in-flight receipt has wrong transaction");
                let ceiling = recover_until(deadline, async || self.maximum_zone_tip().await.map(Some)).await?;
                let active = members.iter().position(|member| *member == expected.leader)
                    .ok_or_eyre("final campaign leader is not controlled")?;
                let (settled, fresh) = self.outage_canary(&tail, ceiling, active, None, &expected).await?;
                let all: Vec<_> = (0..self.zones.len()).collect();
                recover_until(deadline, async || {
                    if !self.handoff_term_ready(&update, &expected, Some(&fresh)).await?
                        || !self.check_checkpoint(&baseline, &settled, &predecessor, &all).await?
                        || !self.check_checkpoint(&baseline, &settled, &pending, &all).await? {
                        return Ok(None);
                    }
                    Ok(Some(()))
                }).await?;
                match case {
                    Case::LaggingSuccessor => assert_reachable!(
                        "Lagging successor: Final term settles fresh work and preserves the predecessor tail on all nodes",
                        &json!({"update": update, "settled": settled, "canary": fresh})),
                    Case::OverlappingHandoffs => assert_reachable!(
                        "Overlapping handoffs: Final A term settles fresh work and preserves the predecessor tail on all nodes",
                        &json!({"update": update, "settled": settled, "canary": fresh})),
                }
                println!("handoff-campaign: {}", json!({"case": case, "result": "PASSED",
                    "final_term": update, "predecessor": predecessor, "inflight": pending,
                    "fresh": fresh, "settled": settled}));
                Ok(())
                }).await
            }).await.wrap_err("handoff recovery timed out from restart issuance")
                .and_then(|result| result);
            phase!(@assert case, "Final term makes fresh canonical progress within the restart deadline", recovered);
            recovered
        }).await.wrap_err("handoff campaign exceeded its quiet window").and_then(|result| result);
        match case {
            Case::LaggingSuccessor => assert_sometimes!(
                executed,
                "Lagging successor: Quiescence permits a controlled episode",
                &json!({"executed": executed})
            ),
            Case::OverlappingHandoffs => assert_sometimes!(
                executed,
                "Overlapping handoffs: Quiescence permits a controlled episode",
                &json!({"executed": executed})
            ),
        }
        if executed || result.is_err() {
            phase!(@assert case, "Episode completes successfully within its quiet window", result);
        }
        result
    }
}

fn receipt_proof(receipt: TransactionReceipt) -> eyre::Result<ReceiptProof> {
    eyre::ensure!(receipt.status(), "handoff in-flight canary reverted");
    Ok(ReceiptProof {
        tx: receipt.transaction_hash,
        height: receipt
            .block_number
            .ok_or_eyre("handoff in-flight canary has no height")?,
        hash: receipt
            .block_hash
            .ok_or_eyre("handoff in-flight canary has no block hash")?,
        success: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{handoff::Request, ledger::Ledger};
    use alloy::{
        primitives::{Address, B256, Bloom},
        providers::ProviderBuilder,
        transports::mock::Asserter,
    };
    use std::{collections::BTreeMap, fs};

    fn context(dir: &Path) -> Context {
        Context {
            ledger: Ledger::open(dir).unwrap(),
            http: Default::default(),
            l1_url: "http://localhost:1".parse().unwrap(),
            l1: ProviderBuilder::new()
                .connect_mocked_client(Asserter::new())
                .erased(),
            zones: (0..4)
                .map(|_| {
                    ProviderBuilder::new()
                        .connect_mocked_client(Asserter::new())
                        .erased()
                })
                .collect(),
            zone_urls: vec![],
            portal: Address::repeat_byte(9),
        }
    }

    async fn request(dir: &Path, node: usize) -> serde_json::Value {
        timeout(Duration::from_secs(2), async {
            let path = dir.join(format!("zone-{node}.request"));
            loop {
                match fs::read(&path) {
                    Ok(bytes) => return serde_json::from_slice(&bytes).unwrap(),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => panic!("{error}"),
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap()
    }

    fn status(dir: &Path, node: usize, id: u64, state: &str) {
        fs::write(
            dir.join(format!("zone-{node}.status")),
            serde_json::to_vec(&json!({"id": id, "state": state, "generation": 1})).unwrap(),
        )
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn campaign_does_not_kill_or_clear_an_unknown_prior_relay() {
        for case in [Case::LaggingSuccessor, Case::OverlappingHandoffs] {
            let dir = tempfile::tempdir().unwrap();
            let ctx = context(dir.path());
            let unknown = Request {
                id: 100,
                previous_leader: Address::repeat_byte(1),
                expected_epoch: 1,
                target: Address::repeat_byte(2),
                relayed: true,
                from_l1_block: 10,
                l1_tx: None,
            };
            ctx.ledger
                .append(&crate::Record::HandoffRequest(unknown.clone()))
                .unwrap();
            crate::proxy::initial_statuses(dir.path());
            let (result, ()) = tokio::join!(ctx.handoff_campaign(dir.path(), Some(case)), async {
                for node in 0..3 {
                    let request = request(dir.path(), node).await;
                    assert_eq!(request["action"], "start");
                    status(dir.path(), node, request["id"].as_u64().unwrap(), "running");
                }
            });
            result.unwrap();
            assert!(!ctx.handoffs_drained().await.unwrap());
            let records = ctx.ledger.records().unwrap();
            let mut expected = vec![crate::Record::HandoffRequest(unknown)];
            for node in 0..3 {
                let release = request(dir.path(), node).await;
                assert_eq!(release["action"], "start");
                expected.push(crate::Record::Sequence {
                    id: release["id"].as_u64().unwrap(),
                });
            }
            // Only release-ID reservations may follow the unchanged unknown request:
            // no transaction intents or terminal handoff records are permitted.
            assert_eq!(records, expected);
        }
    }

    #[tokio::test]
    async fn campaign_supervisor_failure_is_an_error_not_successful_skip() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = context(dir.path());
        // Network release succeeds; a non-file request destination fails supervisor control.
        crate::proxy::initial_statuses(dir.path());
        fs::create_dir(dir.path().join("zone-0.request")).unwrap();
        let error = ctx
            .handoff_campaign(dir.path(), Some(Case::LaggingSuccessor))
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "Intentional sequencer holds are released"
        );
        assert_eq!(
            error.chain().nth(1).unwrap().to_string(),
            "failed publishing sequencer control request"
        );
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::IsADirectory
        );
    }

    #[tokio::test(start_paused = true)]
    async fn campaign_phase_timeout_releases_a_real_acknowledged_hold() {
        for case in [Case::LaggingSuccessor, Case::OverlappingHandoffs] {
            let dir = tempfile::tempdir().unwrap();
            let ctx = context(dir.path());
            status(dir.path(), 0, 0, "running");
            let (result, kill_id) = tokio::join!(
                async {
                    phase!(
                        case,
                        "Test controlled handoff deadline",
                        Duration::from_secs(1),
                        async {
                            let held = Hold::new(&ctx, dir.path(), 0)?;
                            held.kill().await?;
                            held.while_down(std::future::pending::<eyre::Result<()>>())
                                .await
                        }
                    )
                },
                async {
                    let request = request(dir.path(), 0).await;
                    assert_eq!(request["action"], "kill");
                    let id = request["id"].as_u64().unwrap();
                    status(dir.path(), 0, id, "down");
                    id
                }
            );
            assert_eq!(
                format!("{:#}", result.unwrap_err()),
                "Test controlled handoff deadline: Test controlled handoff deadline: timed out: deadline has elapsed"
            );
            let release = request(dir.path(), 0).await;
            assert_eq!(release["action"], "start");
            assert!(release["id"].as_u64().unwrap() > kill_id);
        }
    }

    #[test]
    fn campaign_cases_catalog_progress_as_always_not_only_sometimes() {
        let class = module_path!().strip_suffix("::tests").unwrap();
        let entries: Vec<_> = antithesis_sdk::assert::ANTITHESIS_CATALOG
            .iter()
            .filter(|entry| entry.class == class)
            .collect();
        let actual: BTreeMap<_, _> = entries
            .iter()
            .map(|entry| (entry.message.to_owned(), entry.display_type))
            .collect();
        assert_eq!(
            actual.len(),
            entries.len(),
            "duplicate campaign property IDs"
        );
        for case in ["Lagging successor", "Overlapping handoffs"] {
            for phase in [
                "Preconditions become ready",
                "Durable tail and journaled handoffs execute while successor stays down",
                "Successor restart is acknowledged",
                "Final term makes fresh canonical progress within the restart deadline",
                "Episode completes successfully within its quiet window",
            ] {
                assert_eq!(actual.get(&format!("{case}: {phase}")), Some(&"Always"));
            }
        }
    }

    #[test]
    fn inflight_receipt_requires_success_and_exact_block_identity() {
        let value = json!({"type":"0x0", "status":"0x1", "cumulativeGasUsed":"0x1",
            "logs":[], "logsBloom":Bloom::ZERO, "transactionHash":B256::repeat_byte(1),
            "transactionIndex":"0x0", "blockHash":B256::repeat_byte(2), "blockNumber":"0x14",
            "gasUsed":"0x1", "effectiveGasPrice":"0x1", "from":Address::ZERO,
            "to":Address::repeat_byte(3), "contractAddress":null});
        assert_eq!(
            receipt_proof(serde_json::from_value(value.clone()).unwrap()).unwrap(),
            ReceiptProof {
                tx: B256::repeat_byte(1),
                height: 20,
                hash: B256::repeat_byte(2),
                success: true
            }
        );
        for (field, replacement, message) in [
            ("status", json!("0x0"), "handoff in-flight canary reverted"),
            (
                "blockNumber",
                json!(null),
                "handoff in-flight canary has no height",
            ),
            (
                "blockHash",
                json!(null),
                "handoff in-flight canary has no block hash",
            ),
        ] {
            let mut invalid = value.clone();
            invalid[field] = replacement;
            assert_eq!(
                receipt_proof(serde_json::from_value(invalid).unwrap())
                    .unwrap_err()
                    .to_string(),
                message
            );
        }
    }
}
