//! Bounded, mid-run recovery checks against a fresh finalized settlement.

use alloy::{
    primitives::B256,
    providers::Provider as _,
    rpc::types::{BlockId, BlockNumberOrTag},
};
use antithesis_sdk::assert_always;
use eyre::{OptionExt as _, WrapErr as _};
use serde::Serialize;
use serde_json::json;
use std::{future::Future, time::Duration};
use tempo_contracts::zones::{TEMPO_STATE_ADDRESS, TempoState, ZonePortal};
use tokio::time::{Instant, timeout, timeout_at};

use super::{Context, POLL, Record, intents::Outcome, is_rpc_error};

/// Leaves one minute of the serial driver's 360-second quiet window for command overhead.
const RECOVERY_TIMEOUT: Duration = Duration::from_secs(300);
/// Never substitute `latest`: a mined settlement can still be rolled back on L1.
const SETTLEMENT_TAG: BlockNumberOrTag = BlockNumberOrTag::Finalized;

impl Context {
    /// Reconciles interrupted sends, then proves a new canary settles on finalized L1 and every
    /// zone node preserves its receipt and the baseline prefix. Errors and timeout fail the check.
    pub(super) async fn recovery_probe(&self) -> eyre::Result<()> {
        bounded_check(RECOVERY_TIMEOUT, async {
            let deadline = Instant::now() + RECOVERY_TIMEOUT;
            // Restoring killed containers and links does not mean their RPC servers are ready.
            recover_until(deadline, async || {
                for zone in &self.zones {
                    zone.get_block_number().await?;
                }
                Ok(Some(()))
            })
            .await?;
            let baseline = recover_until(deadline, async || {
                let checkpoint = self.finalized_checkpoint().await?;
                if checkpoint.hash.is_zero() {
                    return Ok(None);
                }
                Ok(Some(checkpoint))
            })
            .await?;
            recover_until(deadline, async || {
                for zone in &self.zones {
                    let Some(block) = zone
                        .get_block_by_number(baseline.height.into())
                        .await?
                    else {
                        return Ok(None);
                    };
                    eyre::ensure!(block.header.hash == baseline.hash,
                        "zone node disagrees with the finalized baseline");
                }
                Ok(Some(()))
            })
            .await?;
            recover_until(deadline, async || {
                Ok(self.reconcile_intents().await?.then_some(()))
            })
            .await?;
            recover_until(deadline, async || {
                self.reconcile_handoffs().await?;
                self.check_handoff_history().await?;
                Ok(Some(()))
            })
            .await?;

            // The canary is signed and durably journaled only after the finalized baseline.
            // Cancellation leaves that exact intent for the next reconciliation, not a new send.
            let intent = recover_until(deadline, async || self.prepare_recovery_canary().await).await?;
            match self.send_intent(&intent).await {
                Ok(_) => {},
                Err(error) if is_rpc_error(&error) => {
                    println!("recovery canary {} has an unknown send result: {error:#}", intent.tx);
                }
                Err(error) => return Err(error),
            }
            let canary = recover_until(deadline, async || {
                if !self.reconcile_intents().await? {
                    println!("recovery: signed intents remain pending");
                }
                canary_outcome(&self.ledger.records()?, intent.tx)
            }).await?;
            eyre::ensure!(canary.height > baseline.height, "canary is not fresh");

            let settled = recover_until(deadline, async || {
                let settled = self.finalized_checkpoint().await?;
                if settled.height < canary.height || settled.height <= baseline.height {
                    return Ok(None);
                }
                let prefix = self.l1.get_block_by_number(baseline.l1_height.into()).await?
                    .ok_or_eyre("baseline finalized L1 block is missing")?;
                eyre::ensure!(prefix.header.hash == baseline.l1_hash, "finalized L1 baseline changed");
                let mut nodes = Vec::with_capacity(self.zones.len());
                for zone in &self.zones {
                    let prefix = zone.get_block_by_number(baseline.height.into()).await?;
                    let checkpoint = zone.get_block_by_number(settled.height.into()).await?;
                    let block = zone.get_block_by_number(canary.height.into()).await?;
                    let receipt = zone.get_transaction_receipt(canary.tx).await?;
                    let mut proof = NodeProof {
                        checkpoint_anchor: None,
                        prefix: prefix.map(|block| block.header.hash),
                        checkpoint: checkpoint.as_ref().map(|block| block.header.hash),
                        canary_block: block.as_ref().map(|block| block.header.hash),
                        receipt: receipt.map(|receipt| {
                            eyre::Ok(ReceiptProof {
                                tx: receipt.transaction_hash,
                                height: receipt.block_number.ok_or_eyre("canary receipt has no height")?,
                                hash: receipt.block_hash.ok_or_eyre("canary receipt has no block hash")?,
                                success: receipt.status(),
                            })
                        }).transpose()?,
                    };
                    for (block, is_checkpoint) in [(block, false), (checkpoint, true)] {
                        let Some(block) = block else { continue; };
                        let anchor = TempoState::new(TEMPO_STATE_ADDRESS, zone)
                            .tempoBlockNumber()
                            .block(BlockId::hash(block.header.hash))
                            .call()
                            .await?;
                        if is_checkpoint {
                            proof.checkpoint_anchor = Some(anchor);
                        }
                        eyre::ensure!(anchor <= settled.l1_height, "zone anchor is not finalized");
                        let l1_anchor = self.l1
                            .get_block_by_number(anchor.into())
                            .await?
                            .ok_or_eyre("zone block's L1 anchor is missing")?;
                        let leader = ZonePortal::new(self.portal, &self.l1)
                            .leader()
                            .block(BlockId::hash(l1_anchor.header.hash))
                            .call()
                            .await?;
                        // Eligibility is at this block's anchor, not today's leader or a
                        // superseded intermediate handoff that need never produce a block.
                        eyre::ensure!(block.header.beneficiary == leader,
                            "recovery block was not produced by its eligible leader");
                    }
                    nodes.push(proof);
                }
                let complete = checkpoint_matches(&baseline, &settled, &canary, &nodes, self.zones.len())?;
                Ok(complete.then_some(settled))
            })
            .await?;
            recover_until(deadline, async || {
                self.reconcile_handoffs().await?;
                self.check_handoff_history().await?;
                Ok(Some(()))
            })
            .await?;
            println!("recovery-probe: {}", json!({"baseline": baseline, "settled": settled, "canary": canary, "nodes": self.zones.len()}));
            Ok(())
        })
        .await
    }

    /// Reads both portal fields at the same finalized L1 block hash, never a moving tag.
    async fn finalized_checkpoint(&self) -> eyre::Result<FinalizedCheckpoint> {
        let block = self
            .l1
            .get_block_by_number(SETTLEMENT_TAG)
            .await?
            .ok_or_eyre("L1 has no finalized block")?;
        let at = BlockId::hash(block.header.hash);
        let portal = ZonePortal::new(self.portal, &self.l1);
        Ok(FinalizedCheckpoint {
            l1_height: block.header.number,
            l1_hash: block.header.hash,
            height: portal.zoneHeight().block(at).call().await?.try_into()?,
            hash: portal.blockHash().block(at).call().await?,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
struct FinalizedCheckpoint {
    l1_height: u64,
    l1_hash: B256,
    height: u64,
    hash: B256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ReceiptProof {
    tx: B256,
    height: u64,
    hash: B256,
    success: bool,
}

#[derive(Debug, Clone)]
struct NodeProof {
    checkpoint_anchor: Option<u64>,
    prefix: Option<B256>,
    checkpoint: Option<B256>,
    canary_block: Option<B256>,
    receipt: Option<ReceiptProof>,
}

/// Bounds the whole check, including sends, polling and network requests. An error or timeout
/// also fails an SDK property, even if the caller's command error handling changes later.
pub(super) async fn bounded_check(
    duration: Duration,
    check: impl Future<Output = eyre::Result<()>>,
) -> eyre::Result<()> {
    let result = timeout(duration, check)
        .await
        .wrap_err("recovery check timed out")
        .and_then(|result| result);
    assert_always!(
        result.is_ok(),
        "Recovery checks finish successfully within their deadline",
        &json!({"error": result.as_ref().err().map(|error| format!("{error:#}")), "timeout_seconds": duration.as_secs()})
    );
    result
}

/// Polls a recovery observation to a fixed deadline. Only transport failures are retryable;
/// a missing observation retries as `None`, and neither can become success at the deadline.
pub(super) async fn recover_until<T>(
    deadline: Instant,
    mut check: impl AsyncFnMut() -> eyre::Result<Option<T>>,
) -> eyre::Result<T> {
    timeout_at(deadline, async {
        loop {
            match check().await {
                Ok(Some(value)) => return Ok(value),
                Ok(None) => {}
                Err(error) if is_rpc_error(&error) => {
                    println!("recovery waiting for RPC: {error:#}")
                }
                Err(error) => return Err(error),
            }
            tokio::time::sleep(POLL).await;
        }
    })
    .await
    .wrap_err("recovery observation timed out")?
}

/// A lost reply must resolve this exact canary, not any later successful transfer.
fn canary_outcome(records: &[Record], tx: B256) -> eyre::Result<Option<ReceiptProof>> {
    for record in records {
        match record {
            Record::IntentOutcome {
                tx: recorded,
                outcome: Outcome::Confirmed { block, block_hash },
            } if *recorded == tx => {
                return Ok(Some(ReceiptProof {
                    tx,
                    height: *block,
                    hash: *block_hash,
                    success: true,
                }));
            }
            Record::IntentOutcome {
                tx: recorded,
                outcome: Outcome::Reverted { .. },
            } if *recorded == tx => eyre::bail!("recovery canary reverted"),
            _ => {}
        }
    }
    Ok(None)
}

/// Checks one common finalized checkpoint, not equality of moving latest tips. Missing blocks
/// are still catching up; contradictions of finalized history are errors rather than retries.
fn checkpoint_matches(
    baseline: &FinalizedCheckpoint,
    settled: &FinalizedCheckpoint,
    canary: &ReceiptProof,
    nodes: &[NodeProof],
    expected_nodes: usize,
) -> eyre::Result<bool> {
    eyre::ensure!(canary.success, "recovery canary reverted");
    eyre::ensure!(canary.height > baseline.height, "canary is not fresh");
    eyre::ensure!(
        settled.l1_height >= baseline.l1_height,
        "finalized L1 prefix rolled back"
    );
    if settled.height < canary.height || settled.height <= baseline.height {
        return Ok(false);
    }
    eyre::ensure!(
        !settled.hash.is_zero(),
        "finalized settlement has no block hash"
    );
    if expected_nodes == 0 || nodes.len() != expected_nodes {
        return Ok(false);
    }
    let mut complete = true;
    for node in nodes {
        if let Some(anchor) = node.checkpoint_anchor {
            eyre::ensure!(
                anchor <= settled.l1_height,
                "checkpoint anchor is not finalized"
            );
            // Old-leader catch-up at anchors below the recovery baseline is not new-term
            // progress, even if a fresh transfer happened to fit into those old anchors.
            complete &= anchor >= baseline.l1_height;
        } else {
            complete = false;
        }
        if let Some(prefix) = node.prefix {
            eyre::ensure!(prefix == baseline.hash, "baseline settled prefix changed");
        } else {
            complete = false;
        }
        if let Some(checkpoint) = node.checkpoint {
            eyre::ensure!(
                checkpoint == settled.hash,
                "node diverges from finalized checkpoint"
            );
        } else {
            complete = false;
        }
        if let Some(hash) = node.canary_block {
            eyre::ensure!(hash == canary.hash, "canary block hash changed");
        } else {
            complete = false;
        }
        if let Some(receipt) = &node.receipt {
            eyre::ensure!(receipt == canary, "canary receipt changed");
        } else {
            complete = false;
        }
    }
    Ok(complete)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (
        FinalizedCheckpoint,
        FinalizedCheckpoint,
        ReceiptProof,
        Vec<NodeProof>,
    ) {
        let baseline = FinalizedCheckpoint {
            l1_height: 100,
            l1_hash: B256::repeat_byte(1),
            height: 10,
            hash: B256::repeat_byte(2),
        };
        let settled = FinalizedCheckpoint {
            l1_height: 110,
            l1_hash: B256::repeat_byte(3),
            height: 20,
            hash: B256::repeat_byte(4),
        };
        let canary = ReceiptProof {
            tx: B256::repeat_byte(5),
            height: 15,
            hash: B256::repeat_byte(6),
            success: true,
        };
        let node = NodeProof {
            checkpoint_anchor: Some(baseline.l1_height),
            prefix: Some(baseline.hash),
            checkpoint: Some(settled.hash),
            canary_block: Some(canary.hash),
            receipt: Some(canary.clone()),
        };
        (baseline, settled, canary, vec![node; 4])
    }

    #[test]
    fn requires_fresh_finalized_checkpoint_not_old_tip_convergence() {
        let (baseline, settled, canary, nodes) = fixture();
        assert!(checkpoint_matches(&baseline, &settled, &canary, &nodes, 4).unwrap());
        assert!(!checkpoint_matches(&baseline, &baseline, &canary, &nodes, 4).unwrap());
        // The only production constructor fetches this tag and pins both calls to its hash.
        assert_eq!(SETTLEMENT_TAG, BlockNumberOrTag::Finalized);
        assert_ne!(SETTLEMENT_TAG, BlockNumberOrTag::Latest);
    }

    #[test]
    fn old_leader_catchup_cannot_replace_progress_past_the_baseline_anchor() {
        let (baseline, settled, canary, mut nodes) = fixture();
        nodes[3].checkpoint_anchor = Some(baseline.l1_height - 1);
        assert!(!checkpoint_matches(&baseline, &settled, &canary, &nodes, 4).unwrap());
        nodes[3].checkpoint_anchor = None;
        assert!(!checkpoint_matches(&baseline, &settled, &canary, &nodes, 4).unwrap());
        nodes[3].checkpoint_anchor = Some(settled.l1_height + 1);
        assert_eq!(
            checkpoint_matches(&baseline, &settled, &canary, &nodes, 4)
                .unwrap_err()
                .to_string(),
            "checkpoint anchor is not finalized"
        );
        nodes[3].checkpoint_anchor = Some(baseline.l1_height);
        assert!(checkpoint_matches(&baseline, &settled, &canary, &nodes, 4).unwrap());
    }

    #[test]
    fn every_follower_must_reach_the_checkpoint() {
        let (baseline, settled, canary, mut nodes) = fixture();
        nodes[3].checkpoint = None;
        assert!(!checkpoint_matches(&baseline, &settled, &canary, &nodes, 4).unwrap());
        nodes.pop();
        assert!(!checkpoint_matches(&baseline, &settled, &canary, &nodes, 4).unwrap());
    }

    #[test]
    fn rejects_divergence_receipt_changes_and_prefix_rollback() {
        let (baseline, settled, canary, nodes) = fixture();
        let mut changed = nodes.clone();
        changed[3].checkpoint = Some(B256::ZERO);
        assert_eq!(
            checkpoint_matches(&baseline, &settled, &canary, &changed, 4)
                .unwrap_err()
                .to_string(),
            "node diverges from finalized checkpoint"
        );
        changed = nodes.clone();
        changed[3].prefix = Some(B256::ZERO);
        assert_eq!(
            checkpoint_matches(&baseline, &settled, &canary, &changed, 4)
                .unwrap_err()
                .to_string(),
            "baseline settled prefix changed"
        );
        changed = nodes.clone();
        changed[3].receipt.as_mut().unwrap().success = false;
        assert_eq!(
            checkpoint_matches(&baseline, &settled, &canary, &changed, 4)
                .unwrap_err()
                .to_string(),
            "canary receipt changed"
        );
        changed = nodes.clone();
        changed[3].receipt.as_mut().unwrap().hash = B256::ZERO;
        assert_eq!(
            checkpoint_matches(&baseline, &settled, &canary, &changed, 4)
                .unwrap_err()
                .to_string(),
            "canary receipt changed"
        );
        changed = nodes;
        changed[3].canary_block = Some(B256::ZERO);
        assert_eq!(
            checkpoint_matches(&baseline, &settled, &canary, &changed, 4)
                .unwrap_err()
                .to_string(),
            "canary block hash changed"
        );
    }

    #[test]
    fn rejects_nonfresh_canary_and_invalid_finalized_checkpoint() {
        let (baseline, settled, canary, nodes) = fixture();
        let mut invalid = canary.clone();
        invalid.success = false;
        assert_eq!(
            checkpoint_matches(&baseline, &settled, &invalid, &nodes, 4)
                .unwrap_err()
                .to_string(),
            "recovery canary reverted"
        );
        invalid = canary.clone();
        invalid.height = baseline.height;
        assert_eq!(
            checkpoint_matches(&baseline, &settled, &invalid, &nodes, 4)
                .unwrap_err()
                .to_string(),
            "canary is not fresh"
        );
        let mut invalid = settled.clone();
        invalid.l1_height = baseline.l1_height - 1;
        assert_eq!(
            checkpoint_matches(&baseline, &invalid, &canary, &nodes, 4)
                .unwrap_err()
                .to_string(),
            "finalized L1 prefix rolled back"
        );
        invalid = settled;
        invalid.hash = B256::ZERO;
        assert_eq!(
            checkpoint_matches(&baseline, &invalid, &canary, &nodes, 4)
                .unwrap_err()
                .to_string(),
            "finalized settlement has no block hash"
        );
    }

    #[test]
    fn missing_receipt_or_prefix_never_passes() {
        let (baseline, settled, canary, nodes) = fixture();
        let mut missing = nodes.clone();
        missing[3].receipt = None;
        assert!(!checkpoint_matches(&baseline, &settled, &canary, &missing, 4).unwrap());
        missing = nodes.clone();
        missing[3].prefix = None;
        assert!(!checkpoint_matches(&baseline, &settled, &canary, &missing, 4).unwrap());
        missing = nodes;
        missing[3].canary_block = None;
        assert!(!checkpoint_matches(&baseline, &settled, &canary, &missing, 4).unwrap());
        assert!(!checkpoint_matches(&baseline, &settled, &canary, &[], 0).unwrap());
    }

    #[test]
    fn lost_reply_waits_for_the_same_canary_not_an_unrelated_success() {
        let (_, _, canary, _) = fixture();
        let mut records = vec![Record::IntentOutcome {
            tx: B256::repeat_byte(99),
            outcome: Outcome::Confirmed {
                block: canary.height,
                block_hash: canary.hash,
            },
        }];
        assert_eq!(canary_outcome(&records, canary.tx).unwrap(), None);
        records.push(Record::IntentOutcome {
            tx: canary.tx,
            outcome: Outcome::Confirmed {
                block: canary.height,
                block_hash: canary.hash,
            },
        });
        assert_eq!(
            canary_outcome(&records, canary.tx).unwrap(),
            Some(canary.clone())
        );
        records[1] = Record::IntentOutcome {
            tx: canary.tx,
            outcome: Outcome::Reverted {
                block: canary.height,
                block_hash: canary.hash,
            },
        };
        assert_eq!(
            canary_outcome(&records, canary.tx).unwrap_err().to_string(),
            "recovery canary reverted"
        );
    }

    #[tokio::test]
    async fn timeout_and_errors_fail_the_recovery_property() {
        let error = bounded_check(Duration::from_millis(1), std::future::pending())
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "recovery check timed out");
        let error = bounded_check(Duration::from_secs(1), async {
            eyre::bail!("broken history")
        })
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "broken history");
        let error = recover_until(Instant::now() + Duration::from_millis(1), async || {
            Ok::<Option<()>, eyre::Report>(None)
        })
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "recovery observation timed out");
        let error = recover_until(Instant::now() + Duration::from_secs(1), async || {
            Err::<Option<()>, _>(eyre::eyre!("invalid record"))
        })
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "invalid record");
    }
}
