//! Durable handoff intents and canonical, finalized portal leadership history.

use alloy::{
    network::AnyTransactionReceipt,
    primitives::{Address, B256, U256},
    providers::Provider as _,
    rpc::types::{BlockId, BlockNumberOrTag, Filter, Log},
    sol_types::SolEvent as _,
};
use antithesis_sdk::{assert_always, assert_reachable, assert_sometimes};
use eyre::{OptionExt as _, WrapErr as _};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use tempo_contracts::zones::{TEMPO_STATE_ADDRESS, TempoState, ZonePortal};
use tokio::time::Instant;
use zone_rpc::types::SetLeaderResponse;

use super::{
    ADMIN_INDEX, Account, BRIDGE_WAIT, Context, Record, SEQUENCER_INDICES,
    intents::{Chain, Effect},
    outage::Membership,
    poll_until, random_below, random_choice, random_index,
    recovery::{ReceiptProof, recover_until},
};

/// Maximum L1 block range in one history query.
const LOG_CHUNK: u64 = 10_000;

/// Intent persisted before either an admin send or a node relay can have an effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    /// Durable request identifier, independent of whether a transaction is ever returned.
    pub(super) id: u64,
    /// Portal leader at the pinned pre-send observation.
    pub(super) previous_leader: Address,
    /// Compare-and-set epoch for direct sends; observed finalized epoch for relays, whose node
    /// may read a newer epoch before sending.
    pub(super) expected_epoch: u64,
    /// Requested replacement sequencer.
    pub(super) target: Address,
    /// Whether a zone node, rather than the admin, submits the transaction.
    pub(super) relayed: bool,
    /// Inclusive lower bound for finding the send's L1 event after a lost reply.
    pub(super) from_l1_block: u64,
    /// Returned transaction identity. `None` means unknown, not failed; a second record with
    /// the same ID adds this evidence without matching unrelated same-target transactions.
    pub(super) l1_tx: Option<B256>,
}

/// One finalized portal event. Request attribution is deliberately not inferred from its target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Update {
    /// Canonical L1 block containing the event.
    pub(super) l1_block: u64,
    /// Block identity, so a stale observation cannot stand in for a canonical event.
    pub(super) l1_block_hash: B256,
    /// Transaction that emitted the event, including when its sender lost the RPC reply.
    pub(super) l1_tx: B256,
    /// Log position within the L1 block; with block and transaction hashes identifies the event.
    pub(super) log_index: u64,
    /// Portal fencing epoch after the transition.
    pub(super) epoch: u64,
    /// Sequencer eligible below this transition's activation anchor.
    pub(super) previous_leader: Address,
    /// Sequencer eligible starting at this transition's activation anchor.
    pub(super) new_leader: Address,
    /// Inclusive first Tempo anchor governed by `new_leader`.
    pub(super) activation_tempo_block: u64,
}

impl Context {
    /// Journals a handoff before sending it, then observes production and settlement if its
    /// term survives. A lost reply leaves an intent recoverable by `reconcile_handoffs`.
    /// `direct_only` suppresses new relays; it never clears earlier unknown submissions.
    pub(super) async fn rotate_leader(&self, direct_only: bool) -> eyre::Result<()> {
        let _episode = self.ledger.episode_lock(false).await?;
        self.reconcile_handoffs().await?;
        // Focused campaigns avoid new ambiguous relays, without clearing old unknown sends.
        let relayed = !direct_only && random_below(2) == 0;
        let admin = Account::at(ADMIN_INDEX)?;
        let _lease = if relayed {
            None
        } else {
            let Some(lease) = self.ledger.try_lease(&admin)? else {
                println!("rotate-leader: admin is busy");
                return Ok(());
            };
            Some(lease)
        };
        let snapshot = self
            .l1
            .get_block_by_number(if relayed {
                BlockNumberOrTag::Finalized
            } else {
                BlockNumberOrTag::Latest
            })
            .await?
            .ok_or_eyre("no L1 handoff snapshot")?;
        let portal = ZonePortal::new(self.portal, &self.l1);
        let block = BlockId::hash(snapshot.header.hash);
        let leader = portal.leader().block(block).call().await?;
        let epoch = portal.leaderEpoch().block(block).call().await?;
        let mut candidates = Vec::new();
        for index in SEQUENCER_INDICES {
            let sequencer = Account::at(index)?.address();
            if sequencer != leader {
                candidates.push(sequencer);
            }
        }
        let target = random_choice(candidates).ok_or_eyre("no sequencer besides the leader")?;
        let mut request = Request {
            id: self.ledger.next_id()?,
            previous_leader: leader,
            expected_epoch: epoch,
            target,
            relayed,
            from_l1_block: snapshot.header.number,
            l1_tx: None,
        };
        // The rpc-only node refuses relays; even that attempt retains its durable intent.
        let (tx, applied) = if relayed {
            self.ledger
                .append(&Record::HandoffRequest(request.clone()))?;
            let node = random_index(self.zones.len());
            // zone-rpc exposes the typed response, but no alloy client extension for this RPC.
            let response = self.zones[node]
                .raw_request::<_, SetLeaderResponse>("zone_setLeader".into(), [target])
                .await;
            let Some(tx) = request.record_relay_response(&self.ledger, response)? else {
                println!("rotate-leader: {target} already leads");
                return Ok(());
            };
            // The relay waits for a receipt, but a successful same-target no-op emits no event.
            let logs = self
                .l1
                .get_logs(
                    &Filter::new()
                        .address(self.portal)
                        .event_signature(ZonePortal::LeaderUpdated::SIGNATURE_HASH)
                        .from_block(request.from_l1_block),
                )
                .await
                .wrap_err("failed reading relayed handoff event")?;
            (tx, handoff_applied(&logs, self.portal, tx))
        } else {
            let transaction = portal.setLeader(target, epoch).into_transaction_request();
            let intent = self
                .prepare_intent(
                    &admin,
                    Chain::L1,
                    0,
                    transaction,
                    Effect::Leadership { target },
                )
                .await?;
            // An interruption before this link still leaves a drainable Leadership intent.
            request.l1_tx = Some(intent.tx);
            self.ledger
                .append(&Record::HandoffRequest(request.clone()))?;
            let receipt = self.send_intent(&intent).await?;
            let tx = receipt.transaction_hash;
            (tx, handoff_applied(receipt.inner.logs(), self.portal, tx))
        };
        drop(_lease);
        // Reverted races and same-target no-ops cannot produce a finalized handoff event.
        if !applied {
            println!("rotate-leader: {target} not applied ({tx})");
            return Ok(());
        }
        let mut update = None;
        poll_until(BRIDGE_WAIT, async || {
            update = self
                .canonical_handoffs()
                .await?
                .into_iter()
                .find(|event| event.l1_tx == tx);
            Ok(update.is_some())
        })
        .await?;
        let Some(update) = update else {
            println!("rotate-leader: {target} not finalized ({tx})");
            return Ok(());
        };
        let details = json!({ "handoff": update, "relayed": relayed });
        assert_reachable!("Zone leadership moves to another sequencer", &details);
        assert_sometimes!(relayed, "A zone node relays a leadership handoff", &details);

        let zone = self.random_zone();
        let mut produced = None;
        poll_until(BRIDGE_WAIT, async || {
            // Do not demand progress from an intermediate term superseded by another writer.
            let history = self.canonical_handoffs().await?;
            if history.last().is_some_and(|last| last.epoch > update.epoch) {
                return Ok(true);
            }
            let block = zone
                .get_block_by_number(BlockNumberOrTag::Latest)
                .await?
                .ok_or_eyre("no latest zone block")?;
            let anchor = TempoState::new(TEMPO_STATE_ADDRESS, zone)
                .tempoBlockNumber()
                .block(BlockId::hash(block.header.hash))
                .call()
                .await?;
            // An A -> B -> A handoff must not count an old A block as this term's progress.
            if block.header.beneficiary == target
                && anchor >= update.activation_tempo_block
                && leader_at_anchor(&history, anchor) == Some(target)
            {
                produced = Some(block.header.number);
            }
            Ok(produced.is_some())
        })
        .await?;
        assert_sometimes!(
            produced.is_some(),
            "New leader produces zone blocks",
            &details
        );
        let Some(height) = produced else {
            return Ok(());
        };
        let settled = poll_until(BRIDGE_WAIT, async || {
            Ok(portal.zoneHeight().call().await? >= U256::from(height))
        })
        .await?;
        assert_sometimes!(
            settled,
            "A batch settles after a leadership handoff",
            &json!({ "handoff": details, "zone_block": height })
        );
        println!(
            "rotate-leader: {leader} -> {target} at epoch {}, settled={settled}",
            update.epoch
        );
        Ok(())
    }

    /// Sends only journaled admin transactions and returns the exact finalized transition.
    /// The caller bounds this operation and holds the exclusive episode lock.
    pub(super) async fn campaign_handoff(
        &self,
        prior: &Membership,
        target: Address,
    ) -> eyre::Result<Update> {
        eyre::ensure!(target != prior.leader, "campaign handoff is a no-op");
        let admin = Account::at(ADMIN_INDEX)?;
        let _lease = self
            .ledger
            .try_lease(&admin)?
            .ok_or_eyre("campaign handoff admin is busy")?;
        let from_l1_block = self.l1.get_block_number().await?;
        let transaction = ZonePortal::new(self.portal, &self.l1)
            .setLeader(target, prior.epoch)
            .into_transaction_request();
        let intent = self
            .prepare_intent(
                &admin,
                Chain::L1,
                0,
                transaction,
                Effect::Leadership { target },
            )
            .await?;
        self.ledger.append(&Record::HandoffRequest(Request {
            id: self.ledger.next_id()?,
            previous_leader: prior.leader,
            expected_epoch: prior.epoch,
            target,
            relayed: false,
            from_l1_block,
            l1_tx: Some(intent.tx),
        }))?;
        let receipt = self.outage_receipt(&intent).await?;
        eyre::ensure!(receipt.status(), "campaign admin handoff reverted");
        recover_until(Instant::now() + BRIDGE_WAIT, async || {
            let history = self.canonical_handoffs().await?;
            validate_history(&history)?;
            let Some(update) = history.iter().find(|update| update.l1_tx == intent.tx) else {
                return Ok(None);
            };
            eyre::ensure!(
                update.previous_leader == prior.leader
                    && update.new_leader == target
                    && Some(update.epoch) == prior.epoch.checked_add(1),
                "campaign finalized handoff differs from journaled request"
            );
            Ok(Some(update.clone()))
        })
        .await
    }

    /// Requires activation on every node in the exact final term, not a stale A block in A→B→A.
    /// With a canary, checks its exact block; without one, checks tips before signing fresh work.
    /// Missing activation retries; a superseding term or contradictory canonical identity fails.
    pub(super) async fn handoff_term_ready(
        &self,
        update: &Update,
        expected: &Membership,
        canary: Option<&ReceiptProof>,
    ) -> eyre::Result<bool> {
        let history = self.canonical_handoffs().await?;
        validate_history(&history)?;
        eyre::ensure!(
            history.last() == Some(update),
            "campaign final term was superseded or its canonical event changed"
        );
        let finalized = self
            .l1
            .get_block_by_number(BlockNumberOrTag::Finalized)
            .await?
            .ok_or_eyre("campaign final term has no finalized L1 block")?;
        eyre::ensure!(
            self.outage_membership(BlockId::hash(finalized.header.hash))
                .await?
                == *expected
                && self.outage_membership(BlockId::latest()).await? == *expected,
            "campaign final membership or epoch changed"
        );
        eyre::ensure!(
            self.zones.len() == 4,
            "campaign final term requires all four nodes"
        );
        let mut ready = true;
        for zone in &self.zones {
            let number = canary.map_or(BlockNumberOrTag::Latest, |proof| proof.height.into());
            let Some(block) = zone.get_block_by_number(number).await? else {
                ready = false;
                continue;
            };
            if let Some(proof) = canary {
                eyre::ensure!(
                    block.header.hash == proof.hash && block.header.number == proof.height,
                    "campaign canary block differs from canonical proof"
                );
            }
            let anchor = TempoState::new(TEMPO_STATE_ADDRESS, zone)
                .tempoBlockNumber()
                .block(BlockId::hash(block.header.hash))
                .call()
                .await?;
            if anchor < update.activation_tempo_block {
                ready = false;
                continue;
            }
            if canary.is_some() && anchor > finalized.header.number {
                ready = false;
                continue;
            }
            let l1 = self
                .l1
                .get_block_by_number(anchor.into())
                .await?
                .ok_or_eyre("campaign canary Tempo anchor is missing")?;
            let at = BlockId::hash(l1.header.hash);
            let portal = ZonePortal::new(self.portal, &self.l1);
            eyre::ensure!(
                block.header.beneficiary == update.new_leader
                    && portal.leader().block(at).call().await? == update.new_leader
                    && portal.leaderEpoch().block(at).call().await? == update.epoch,
                "campaign block is not authorized by the final Tempo term"
            );
        }
        Ok(ready)
    }

    /// True only when every prior handoff is provably unable to change future leadership.
    /// Caller holds the exclusive episode lock; unknown relay submissions remain unresolved.
    pub(super) async fn handoffs_drained(&self) -> eyre::Result<bool> {
        let Some(hashes) = handoff_hashes(&self.ledger.records()?)? else {
            return Ok(false);
        };
        if hashes.is_empty() {
            return Ok(true);
        }
        let finalized = self
            .l1
            .get_block_by_number(BlockNumberOrTag::Finalized)
            .await?
            .ok_or_eyre("no finalized L1 block for handoff drain")?;
        for tx in hashes {
            // The L1 provider's Ethereum envelope rejects Tempo's 0x76 relay receipts.
            let Some(receipt) = self
                .l1
                .raw_request::<_, Option<AnyTransactionReceipt>>(
                    "eth_getTransactionReceipt".into(),
                    [tx],
                )
                .await?
            else {
                return Ok(false);
            };
            eyre::ensure!(
                receipt.transaction_hash == tx,
                "handoff receipt hash differs from request"
            );
            let (Some(number), Some(hash)) = (receipt.block_number, receipt.block_hash) else {
                return Ok(false);
            };
            if number > finalized.header.number {
                return Ok(false);
            }
            let Some(block) = self.l1.get_block_by_number(number.into()).await? else {
                return Ok(false);
            };
            if block.header.number != number || block.header.hash != hash {
                return Ok(false);
            }
            // Both successful no-ops and reverts are terminal, but only in the canonical chain.
        }
        let canonical = self
            .l1
            .get_block_by_number(finalized.header.number.into())
            .await?;
        Ok(canonical.is_some_and(|block| {
            block.header.number == finalized.header.number
                && block.header.hash == finalized.header.hash
        }))
    }

    /// Recovers successful sends, including ones with no returned transaction hash, by event
    /// identity. An event without a returned hash remains unattributed to any particular request.
    pub(super) async fn reconcile_handoffs(&self) -> eyre::Result<()> {
        self.canonical_handoffs().await?;
        Ok(())
    }

    /// Rescans the portal through one finalized snapshot, persists unseen events, and returns
    /// canonical L1 order (never ledger append order). Stale journal entries are not replayed.
    /// The last entry identifies the final eligible leader for recovery checks.
    pub(super) async fn canonical_handoffs(&self) -> eyre::Result<Vec<Update>> {
        let finalized = self
            .l1
            .get_block_by_number(BlockNumberOrTag::Finalized)
            .await?
            .ok_or_eyre("no finalized L1 block for handoff history")?;
        let to = finalized.header.number;
        let filter = Filter::new()
            .address(self.portal)
            .event_signature(ZonePortal::LeaderUpdated::SIGNATURE_HASH);
        let mut updates = Vec::new();
        // Include bootstrap and non-workload changes: neither a missing intent nor a lost
        // reply is evidence that a canonical leader transition did not happen.
        let mut from = 0_u64;
        loop {
            let end = to.min(
                from.checked_add(LOG_CHUNK - 1)
                    .ok_or_eyre("L1 log range overflow")?,
            );
            for log in self
                .l1
                .get_logs(&filter.clone().from_block(from).to_block(end))
                .await
                .wrap_err("failed reading finalized handoff events")?
            {
                if log.removed {
                    continue;
                }
                let event = ZonePortal::LeaderUpdated::decode_log(&log.inner)?;
                updates.push(Update {
                    l1_block: log.block_number.ok_or_eyre("handoff event has no block")?,
                    l1_block_hash: log
                        .block_hash
                        .ok_or_eyre("handoff event has no block hash")?,
                    l1_tx: log
                        .transaction_hash
                        .ok_or_eyre("handoff event has no transaction")?,
                    log_index: log.log_index.ok_or_eyre("handoff event has no log index")?,
                    epoch: event.epoch,
                    previous_leader: event.previousLeader,
                    new_leader: event.newLeader,
                    activation_tempo_block: event.activationTempoBlock,
                });
            }
            if end == to {
                break;
            }
            from = end.checked_add(1).ok_or_eyre("L1 log range overflow")?;
        }
        let still_canonical = self
            .l1
            .get_block_by_number(BlockNumberOrTag::Number(to))
            .await?
            .ok_or_eyre("finalized handoff snapshot disappeared")?;
        eyre::ensure!(
            still_canonical.header.hash == finalized.header.hash,
            "finalized handoff snapshot changed during scan"
        );
        order_history(&mut updates);
        let known: BTreeSet<_> = self
            .ledger
            .records()?
            .into_iter()
            .filter_map(|record| match record {
                Record::HandoffUpdate(update) => {
                    Some((update.l1_block_hash, update.l1_tx, update.log_index))
                }
                _ => None,
            })
            .collect();
        for update in &updates {
            if !known.contains(&(update.l1_block_hash, update.l1_tx, update.log_index)) {
                self.ledger
                    .append_once(&Record::HandoffUpdate(update.clone()))?;
            }
        }
        Ok(updates)
    }

    /// Checks finalized epoch and activation transitions, and records repeated and competing
    /// handoff coverage. Contradictions return an error as well as an Antithesis assertion;
    /// superseded intermediate terms are never required to produce a block.
    pub(super) async fn check_handoff_history(&self) -> eyre::Result<()> {
        let history = self.canonical_handoffs().await?;
        let checked = validate_history(&history);
        assert_always!(
            checked.is_ok(),
            "Finalized handoffs advance epochs and activation anchors consistently",
            &json!({ "history": history })
        );
        checked?;
        let mut requests = BTreeMap::new();
        for record in self.ledger.records()? {
            if let Record::HandoffRequest(request) = record {
                requests.insert(request.id, request);
            }
        }
        let requests: Vec<_> = requests.into_values().collect();
        for request in &requests {
            if let Some(update) = history
                .iter()
                .find(|update| Some(update.l1_tx) == request.l1_tx)
            {
                let agrees = update.new_leader == request.target
                    && update.l1_block >= request.from_l1_block
                    && (request.relayed
                        || (request.expected_epoch.checked_add(1) == Some(update.epoch)
                            && request.previous_leader == update.previous_leader));
                assert_always!(
                    agrees,
                    "Confirmed handoffs agree with their exact transaction's request",
                    &json!({ "request": request, "update": update })
                );
                eyre::ensure!(
                    agrees,
                    "confirmed handoff disagrees with request {}",
                    request.id
                );
                assert_sometimes!(
                    request.relayed,
                    "A zone node relays a leadership handoff",
                    &json!({ "request": request, "update": update })
                );
            }
        }
        assert_sometimes!(
            returns_to_previous_leader(&history),
            "Zone leadership returns A to B to A",
            &json!({ "history": history })
        );
        assert_sometimes!(
            competing_requests(&requests),
            "Submitted handoffs target different leaders at the same observed epoch",
            &json!({ "requests": requests })
        );
        Ok(())
    }
}

impl Request {
    fn record_relay_response(
        &mut self,
        ledger: &crate::ledger::Ledger,
        response: Result<SetLeaderResponse, alloy::transports::TransportError>,
    ) -> eyre::Result<Option<B256>> {
        if let Err(error) = &response {
            if relay_refused_before_submission(error) {
                ledger.append(&Record::HandoffNotSubmitted { id: self.id })?;
            } else if let Some(error) = error.as_error_resp()
                && error.code == -32603
                && let Some(hash) = error.message.strip_prefix("setLeader transaction 0x")
                && let Some(hash) = hash.strip_suffix(" reverted on L1")
                && hash.len() == 64
                && let Ok(tx) = hash.parse::<B256>()
            {
                // The node reports the mined hash, not finality; the drain still checks its receipt.
                self.l1_tx = Some(tx);
                ledger.append(&Record::HandoffRequest(self.clone()))?;
            }
        }
        let response = response?;
        eyre::ensure!(
            response.requested_leader == self.target,
            "relay response target differs from request"
        );
        if let Some(tx) = response.tx_hash {
            self.l1_tx = Some(tx);
            ledger.append(&Record::HandoffRequest(self.clone()))?;
        } else {
            eyre::ensure!(
                response.status == "alreadyActive",
                "relay returned no transaction without a definitive no-op"
            );
            ledger.append(&Record::HandoffNotSubmitted { id: self.id })?;
        }
        Ok(response.tx_hash)
    }
}

// None means at least one submission is unknowable, never that the ledger is malformed.
fn handoff_hashes(records: &[Record]) -> eyre::Result<Option<BTreeSet<B256>>> {
    let mut requests: BTreeMap<u64, &Request> = BTreeMap::new();
    let mut not_submitted = BTreeSet::new();
    let mut hashes = BTreeSet::new();
    for record in records {
        match record {
            Record::HandoffRequest(request) => {
                if let Some(prior) = requests.insert(request.id, request) {
                    eyre::ensure!(
                        Request {
                            l1_tx: request.l1_tx,
                            ..prior.clone()
                        } == *request
                            && (prior.l1_tx.is_none() || prior.l1_tx == request.l1_tx)
                            && (!not_submitted.contains(&request.id) || request.l1_tx.is_none()),
                        "conflicting handoff request history"
                    );
                }
                if let Some(tx) = request.l1_tx {
                    hashes.insert(tx);
                }
            }
            Record::HandoffNotSubmitted { id } => {
                let request = requests
                    .get(id)
                    .ok_or_eyre("handoff completion without request")?;
                eyre::ensure!(
                    request.relayed && request.l1_tx.is_none(),
                    "invalid no-submission handoff completion"
                );
                not_submitted.insert(*id);
            }
            // Mined outcomes are not finalized, and an orphan may have been replayed elsewhere.
            Record::Intent(intent) if matches!(intent.effect, Effect::Leadership { .. }) => {
                eyre::ensure!(intent.chain == Chain::L1, "leadership intent is not on L1");
                hashes.insert(intent.tx);
            }
            _ => {}
        }
    }
    Ok(requests
        .values()
        .all(|r| r.l1_tx.is_some() || not_submitted.contains(&r.id))
        .then_some(hashes))
}

// The HTTP client disables redirects and automatic retries, so a connection failure cannot
// follow an earlier submission. Lost replies and post-connect timeouts remain unknown.
fn relay_refused_before_submission(error: &alloy::transports::TransportError) -> bool {
    if let alloy::transports::TransportError::Transport(error) = error
        && let Some(error) = error.as_custom()
        && let Some(error) = error.downcast_ref::<alloy::transports::http::reqwest::Error>()
        && error.is_connect()
    {
        return true;
    }
    // These exact invalid-params responses precede signing in zone::rpc::set_leader.
    error.as_error_resp().is_some_and(|response| {
        response.code == -32602 && matches!(response.message.as_ref(),
            "zone_setLeader requires multi-sequencer mode"
            | "zone_setLeader requires a nonzero portal"
            | "zone_setLeader requires a node holding an individual secp256k1 key; this node is rpc-only"
            | "target is not a manifest member"
            | "target is not a registered portal sequencer")
    })
}

fn handoff_applied(logs: &[Log], portal: Address, tx: B256) -> bool {
    logs.iter().any(|log| {
        !log.removed
            && log.address() == portal
            && log.transaction_hash == Some(tx)
            && ZonePortal::LeaderUpdated::decode_log(&log.inner).is_ok()
    })
}

fn order_history(history: &mut Vec<Update>) {
    history.sort_by_key(|update| (update.l1_block, update.log_index));
    history.dedup();
}

fn validate_history(history: &[Update]) -> eyre::Result<()> {
    let valid = history.iter().all(|update| {
        update.epoch > 0
            && !update.new_leader.is_zero()
            && update.previous_leader != update.new_leader
            && update.activation_tempo_block == update.l1_block
    }) && history.windows(2).all(|pair| {
        pair[0].epoch.checked_add(1) == Some(pair[1].epoch)
            && pair[0].new_leader == pair[1].previous_leader
            && pair[0].activation_tempo_block < pair[1].activation_tempo_block
    });
    eyre::ensure!(valid, "invalid finalized handoff epoch/activation history");
    Ok(())
}

/// Selects the leader for an anchor, including the outgoing leader below the first activation.
/// Callers supply canonical L1-ordered events; `None` means history has no evidence for the anchor.
pub(super) fn leader_at_anchor(history: &[Update], anchor: u64) -> Option<Address> {
    history
        .iter()
        .rev()
        .find(|update| update.activation_tempo_block <= anchor)
        .map(|update| update.new_leader)
        .or_else(|| {
            history
                .first()
                .map(|update| update.previous_leader)
                .filter(|leader| !leader.is_zero())
        })
}

fn returns_to_previous_leader(history: &[Update]) -> bool {
    history.windows(2).any(|pair| {
        !pair[0].previous_leader.is_zero()
            && pair[0].previous_leader == pair[1].new_leader
            && pair[0].new_leader == pair[1].previous_leader
    })
}

fn competing_requests(requests: &[Request]) -> bool {
    requests.iter().enumerate().any(|(index, first)| {
        requests[index + 1..].iter().any(|second| {
            first.id != second.id
                && first.l1_tx.is_some()
                && second.l1_tx.is_some()
                && first.l1_tx != second.l1_tx
                && first.expected_epoch == second.expected_epoch
                && first.target != second.target
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{
        primitives::{Bloom, Bytes},
        providers::ProviderBuilder,
        rpc::types::Block,
        sol_types::SolValue as _,
        transports::mock::Asserter,
    };
    use clap::Parser as _;
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
    };

    #[derive(Clone, Copy, Debug)]
    enum RelayTransport {
        Refused,
        LostReply,
        Timeout,
        Redirect,
    }

    async fn relay_transport_fixture(mode: RelayTransport) -> (bool, bool) {
        let dir = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let zone_json = dir.path().join("zone.json");
        std::fs::write(
            &zone_json,
            json!({"portal": Address::repeat_byte(9)}).to_string(),
        )
        .unwrap();
        let args = crate::Antithesis::parse_from([
            "workload",
            "--state-dir",
            dir.path().to_str().unwrap(),
            "--zone-json",
            zone_json.to_str().unwrap(),
            "--l1-rpc-url",
            &url,
            "--zone-rpc-urls",
            &url,
            "rotate-leader",
        ]);
        let ctx = Context::init(&args).await.unwrap();
        let server = if matches!(mode, RelayTransport::Refused) {
            drop(listener);
            None
        } else {
            Some(tokio::spawn(async move {
                let (mut socket, _) =
                    tokio::time::timeout(std::time::Duration::from_secs(2), listener.accept())
                        .await
                        .unwrap()
                        .unwrap();
                let mut request = Vec::new();
                tokio::time::timeout(std::time::Duration::from_secs(2), async {
                    while !request.ends_with(b"}") {
                        assert!(request.len() < 8192);
                        assert!(socket.read_buf(&mut request).await.unwrap() > 0);
                    }
                })
                .await
                .unwrap();
                assert!(String::from_utf8_lossy(&request).contains("zone_setLeader"));
                match mode {
                    RelayTransport::Timeout => {
                        tokio::time::sleep(crate::RPC_TIMEOUT + std::time::Duration::from_secs(1))
                            .await
                    }
                    RelayTransport::Redirect => {
                        // A prior endpoint saw the request. Following this redirect to a refused
                        // connection must never turn that ambiguous outcome into NotSubmitted.
                        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
                        let destination = closed.local_addr().unwrap();
                        drop(closed);
                        socket.write_all(format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{destination}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
                    }
                    RelayTransport::LostReply => {}
                    RelayTransport::Refused => unreachable!(),
                }
            }))
        };
        let mut request = relay_request();
        ctx.ledger
            .append(&Record::HandoffRequest(request.clone()))
            .unwrap();
        let response = ctx.zones[0]
            .raw_request::<_, SetLeaderResponse>("zone_setLeader".into(), [request.target])
            .await;
        let error = response.as_ref().unwrap_err();
        let definitive = relay_refused_before_submission(error);
        assert!(
            request
                .record_relay_response(&ctx.ledger, response)
                .is_err()
        );
        let drained = handoff_hashes(&ctx.ledger.records().unwrap())
            .unwrap()
            .is_some();
        if let Some(server) = server {
            server.await.unwrap();
        }
        (definitive, drained)
    }

    #[tokio::test]
    async fn relay_connect_refusal_does_not_poison_future_episodes() {
        assert_eq!(
            relay_transport_fixture(RelayTransport::Refused).await,
            (true, true)
        );
    }

    #[tokio::test]
    async fn relay_lost_reply_and_redirect_remain_unknown() {
        for mode in [RelayTransport::LostReply, RelayTransport::Redirect] {
            assert_eq!(
                relay_transport_fixture(mode).await,
                (false, false),
                "{mode:?}"
            );
        }
    }

    #[tokio::test]
    async fn relay_post_connect_timeout_remains_unknown() {
        assert_eq!(
            relay_transport_fixture(RelayTransport::Timeout).await,
            (false, false)
        );
    }

    #[derive(Debug, Clone, Copy)]
    enum TermFault {
        None,
        PartialActivation,
        MissingFollower,
        StaleEpoch,
        Superseded,
        CanonicalMismatch,
        WrongAuthority,
        Rpc,
    }

    fn queue_campaign_membership(l1: &Asserter, expected: &Membership, epoch: u64) {
        l1.push_success(&Bytes::from(U256::from(3).abi_encode()));
        l1.push_success(&Bytes::from(
            (
                U256::from(10),
                expected
                    .members
                    .iter()
                    .map(|member| Bytes::from(member.abi_encode()))
                    .collect::<Vec<_>>(),
            )
                .abi_encode_params(),
        ));
        for value in [U256::from(expected.threshold), U256::from(expected.version)] {
            l1.push_success(&Bytes::from(value.abi_encode()));
        }
        l1.push_success(&Bytes::from(expected.leader.abi_encode()));
        l1.push_success(&Bytes::from(U256::from(epoch).abi_encode()));
    }

    // Exercises the actual RPC-backed final-term gate, not a detached boolean model.
    async fn campaign_term_fixture(fault: TermFault, fixed_canary: bool) -> eyre::Result<bool> {
        let dir = tempfile::tempdir().unwrap();
        let l1 = Asserter::new();
        let zones: Vec<_> = (0..4).map(|_| Asserter::new()).collect();
        let ctx = Context {
            ledger: crate::ledger::Ledger::open(dir.path()).unwrap(),
            l1: ProviderBuilder::new()
                .connect_mocked_client(l1.clone())
                .erased(),
            zones: zones
                .iter()
                .cloned()
                .map(|zone| ProviderBuilder::new().connect_mocked_client(zone).erased())
                .collect(),
            zone_urls: vec![],
            http: Default::default(),
            l1_url: "http://localhost:1".parse().unwrap(),
            portal: Address::repeat_byte(9),
        };
        let expected = Membership {
            members: (1..=3).map(Address::repeat_byte).collect(),
            threshold: 2,
            version: 1,
            leader: Address::repeat_byte(1),
            epoch: 3,
        };
        let final_term = update(3, 20, 2, 1);
        let mut history = vec![update(2, 10, 1, 2), final_term.clone()];
        if matches!(fault, TermFault::Superseded) {
            history.push(update(4, 30, 1, 3));
        }
        let mut finalized = Block::<B256>::default();
        finalized.header.number = 100;
        finalized.header.hash = B256::repeat_byte(100);
        l1.push_success(&finalized);
        let logs: Vec<_> = history
            .iter()
            .map(|event| Log {
                inner: alloy::primitives::Log {
                    address: ctx.portal,
                    data: ZonePortal::LeaderUpdated {
                        previousLeader: event.previous_leader,
                        newLeader: event.new_leader,
                        epoch: event.epoch,
                        activationTempoBlock: event.activation_tempo_block,
                    }
                    .encode_log_data(),
                },
                block_number: Some(event.l1_block),
                block_hash: Some(event.l1_block_hash),
                transaction_hash: Some(event.l1_tx),
                log_index: Some(event.log_index),
                ..Default::default()
            })
            .collect();
        l1.push_success(&logs);
        l1.push_success(&finalized);
        l1.push_success(&finalized);
        queue_campaign_membership(
            &l1,
            &expected,
            if matches!(fault, TermFault::StaleEpoch) {
                1
            } else {
                3
            },
        );
        l1.push_success(&finalized);
        queue_campaign_membership(&l1, &expected, 3);
        let canary = ReceiptProof {
            tx: B256::repeat_byte(6),
            height: 40,
            hash: B256::repeat_byte(40),
            success: true,
        };
        for (index, zone) in zones.iter().enumerate() {
            if index == 3 && matches!(fault, TermFault::MissingFollower) {
                zone.push_success(&None::<Block<B256>>);
                continue;
            }
            if index == 3 && matches!(fault, TermFault::Rpc) {
                zone.push_failure_msg("campaign follower RPC unavailable");
                continue;
            }
            let mut block = Block::<B256>::default();
            block.header.number = canary.height;
            block.header.hash = if index == 3 && matches!(fault, TermFault::CanonicalMismatch) {
                B256::ZERO
            } else {
                canary.hash
            };
            block.header.beneficiary = expected.leader;
            zone.push_success(&block);
            // Old A blocks are valid history, but not evidence for final A's activation.
            let anchor = if index == 3 && matches!(fault, TermFault::PartialActivation) {
                9
            } else {
                20
            };
            zone.push_success(&Bytes::from(U256::from(anchor).abi_encode()));
            if anchor >= 20 {
                l1.push_success(&finalized);
                l1.push_success(&Bytes::from(expected.leader.abi_encode()));
                let epoch = if index == 3 && matches!(fault, TermFault::WrongAuthority) {
                    1
                } else {
                    3
                };
                l1.push_success(&Bytes::from(U256::from(epoch).abi_encode()));
            }
        }
        ctx.handoff_term_ready(&final_term, &expected, fixed_canary.then_some(&canary))
            .await
    }

    #[tokio::test]
    async fn campaign_final_term_requires_every_node_and_rejects_old_a_activation() {
        for fixed in [false, true] {
            assert!(campaign_term_fixture(TermFault::None, fixed).await.unwrap());
            for fault in [TermFault::PartialActivation, TermFault::MissingFollower] {
                assert!(
                    !campaign_term_fixture(fault, fixed).await.unwrap(),
                    "{fault:?}"
                );
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn campaign_missing_activation_times_out_before_fresh_work() {
        let mut fresh_work_started = false;
        let result: eyre::Result<()> = async {
            recover_until(
                Instant::now() + std::time::Duration::from_secs(1),
                async || {
                    Ok(campaign_term_fixture(TermFault::PartialActivation, false)
                        .await?
                        .then_some(()))
                },
            )
            .await?;
            fresh_work_started = true;
            Ok(())
        }
        .await;
        assert_eq!(
            result.unwrap_err().to_string(),
            "recovery observation timed out"
        );
        assert!(!fresh_work_started);
    }

    #[tokio::test]
    async fn campaign_rejects_stale_epoch_supersession_wrong_authority_and_hash() {
        for (fault, message) in [
            (
                TermFault::StaleEpoch,
                "campaign final membership or epoch changed",
            ),
            (
                TermFault::Superseded,
                "campaign final term was superseded or its canonical event changed",
            ),
            (
                TermFault::CanonicalMismatch,
                "campaign canary block differs from canonical proof",
            ),
            (
                TermFault::WrongAuthority,
                "campaign block is not authorized by the final Tempo term",
            ),
        ] {
            assert_eq!(
                campaign_term_fixture(fault, true)
                    .await
                    .unwrap_err()
                    .to_string(),
                message
            );
        }
        assert!(
            campaign_term_fixture(TermFault::Rpc, true)
                .await
                .unwrap_err()
                .to_string()
                .contains("campaign follower RPC unavailable")
        );
    }

    fn relay_request() -> Request {
        Request {
            relayed: true,
            l1_tx: None,
            ..request(1, 2, 2)
        }
    }

    fn rpc_error(code: i64, message: &str) -> alloy::transports::TransportError {
        alloy::transports::TransportError::ErrorResp(
            serde_json::from_value(json!({"code": code, "message": message})).unwrap(),
        )
    }

    #[test]
    fn relay_completion_requires_a_definitive_no_submission_response() {
        for message in [
            "zone_setLeader requires multi-sequencer mode",
            "zone_setLeader requires a nonzero portal",
            "zone_setLeader requires a node holding an individual secp256k1 key; this node is rpc-only",
            "target is not a manifest member",
            "target is not a registered portal sequencer",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let ledger = crate::ledger::Ledger::open(dir.path()).unwrap();
            let mut request = relay_request();
            ledger
                .append(&Record::HandoffRequest(request.clone()))
                .unwrap();
            let error = request
                .record_relay_response(&ledger, Err(rpc_error(-32602, message)))
                .unwrap_err();
            assert!(error.to_string().contains(message));
            assert_eq!(
                handoff_hashes(&ledger.records().unwrap()).unwrap(),
                Some(BTreeSet::new())
            );
        }
        for (status, target, terminal) in [
            ("alreadyActive", Address::repeat_byte(2), true),
            ("submitted", Address::repeat_byte(2), false),
            ("alreadyActive", Address::repeat_byte(3), false),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let ledger = crate::ledger::Ledger::open(dir.path()).unwrap();
            let mut request = relay_request();
            ledger
                .append(&Record::HandoffRequest(request.clone()))
                .unwrap();
            let result = request.record_relay_response(
                &ledger,
                Ok(SetLeaderResponse {
                    status: status.into(),
                    tx_hash: None,
                    requested_leader: target,
                    relayer: Address::repeat_byte(4),
                }),
            );
            if terminal {
                assert_eq!(result.unwrap(), None);
            } else {
                let expected = if target == request.target {
                    "relay returned no transaction without a definitive no-op"
                } else {
                    "relay response target differs from request"
                };
                assert_eq!(result.unwrap_err().to_string(), expected);
            }
            assert_eq!(
                handoff_hashes(&ledger.records().unwrap())
                    .unwrap()
                    .is_some(),
                terminal
            );
        }
        let dir = tempfile::tempdir().unwrap();
        let ledger = crate::ledger::Ledger::open(dir.path()).unwrap();
        let mut request = relay_request();
        ledger
            .append(&Record::HandoffRequest(request.clone()))
            .unwrap();
        let tx = B256::repeat_byte(9);
        assert_eq!(
            request
                .record_relay_response(
                    &ledger,
                    Ok(SetLeaderResponse {
                        status: "submitted".into(),
                        tx_hash: Some(tx),
                        requested_leader: request.target,
                        relayer: Address::repeat_byte(4),
                    })
                )
                .unwrap(),
            Some(tx)
        );
        assert_eq!(
            handoff_hashes(&ledger.records().unwrap()).unwrap(),
            Some(BTreeSet::from([tx]))
        );
        for (code, message) in [
            (-32603, "setLeader confirmation timed out after 30 seconds"),
            (-32603, "setLeader transaction reverted on L1"),
            (-32602, "unrecognized refusal"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let ledger = crate::ledger::Ledger::open(dir.path()).unwrap();
            let mut request = relay_request();
            ledger
                .append(&Record::HandoffRequest(request.clone()))
                .unwrap();
            assert!(
                request
                    .record_relay_response(&ledger, Err(rpc_error(code, message)))
                    .unwrap_err()
                    .to_string()
                    .contains(message)
            );
            // Even a same-target finalized event cannot identify this unknown submission.
            ledger
                .append(&Record::HandoffUpdate(update(3, 20, 1, 2)))
                .unwrap();
            assert_eq!(handoff_hashes(&ledger.records().unwrap()).unwrap(), None);
        }
    }

    #[test]
    fn conflicting_handoff_history_is_not_an_inconclusive_submission() {
        let original = relay_request();
        let known = Request {
            l1_tx: Some(B256::repeat_byte(3)),
            ..original
        };
        for (records, expected) in [
            (
                vec![Record::HandoffNotSubmitted { id: 1 }],
                "handoff completion without request",
            ),
            (
                vec![
                    Record::HandoffRequest(request(1, 2, 2)),
                    Record::HandoffNotSubmitted { id: 1 },
                ],
                "invalid no-submission handoff completion",
            ),
            (
                vec![
                    Record::HandoffRequest(known.clone()),
                    Record::HandoffNotSubmitted { id: 1 },
                ],
                "invalid no-submission handoff completion",
            ),
            (
                vec![
                    Record::HandoffRequest(known.clone()),
                    Record::HandoffRequest(original.clone()),
                ],
                "conflicting handoff request history",
            ),
            (
                vec![
                    Record::HandoffRequest(original.clone()),
                    Record::HandoffRequest(Request {
                        target: Address::ZERO,
                        ..original.clone()
                    }),
                ],
                "conflicting handoff request history",
            ),
            (
                vec![
                    Record::HandoffRequest(original.clone()),
                    Record::HandoffNotSubmitted { id: 1 },
                    Record::HandoffRequest(known.clone()),
                ],
                "conflicting handoff request history",
            ),
            (
                vec![
                    Record::HandoffRequest(known.clone()),
                    Record::HandoffRequest(Request {
                        l1_tx: Some(B256::repeat_byte(4)),
                        ..known
                    }),
                ],
                "conflicting handoff request history",
            ),
        ] {
            assert_eq!(handoff_hashes(&records).unwrap_err().to_string(), expected);
        }
        assert_eq!(
            handoff_hashes(&[
                Record::HandoffRequest(original.clone()),
                Record::HandoffNotSubmitted { id: 1 },
                Record::HandoffRequest(original),
                Record::HandoffNotSubmitted { id: 1 },
            ])
            .unwrap(),
            Some(BTreeSet::new())
        );
    }

    #[tokio::test]
    async fn drain_requires_exact_canonical_finalized_receipts_even_for_reverts() {
        assert_drain_requires_exact_canonical_finalized_receipts(request(1, 2, 2), None).await;
    }

    #[tokio::test]
    async fn drain_accepts_tempo_relay_receipts_only_when_canonical_and_finalized() {
        assert_drain_requires_exact_canonical_finalized_receipts(
            Request {
                relayed: true,
                ..request(1, 2, 2)
            },
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn reverted_relay_hash_is_journaled_but_drain_still_requires_finality() {
        let tx = B256::repeat_byte(7);
        assert_drain_requires_exact_canonical_finalized_receipts(
            relay_request(),
            Some(rpc_error(
                -32603,
                &format!("setLeader transaction {tx} reverted on L1"),
            )),
        )
        .await;
    }

    #[test]
    fn ambiguous_relay_errors_do_not_recover_a_transaction_hash() {
        let tx = B256::repeat_byte(7);
        let reverted = format!("setLeader transaction {tx} reverted on L1");
        for (code, message) in [
            (-32602, reverted.clone()),
            (-32603, "setLeader transaction reverted on L1".into()),
            (-32603, "setLeader transaction 0x1234 reverted on L1".into()),
            (
                -32603,
                format!("setLeader transaction {tx}00 reverted on L1"),
            ),
            (
                -32603,
                format!("setLeader transaction 0x{} reverted on L1", "g".repeat(64)),
            ),
            (
                -32603,
                format!("setLeader transaction {} reverted on L1", "07".repeat(32)),
            ),
            (-32603, format!("unexpected {reverted}")),
            (-32603, format!("{reverted} (retry)")),
            (
                -32603,
                "setLeader confirmation timed out after 30 seconds".into(),
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let ledger = crate::ledger::Ledger::open(dir.path()).unwrap();
            let mut request = relay_request();
            ledger
                .append(&Record::HandoffRequest(request.clone()))
                .unwrap();
            let error = rpc_error(code, &message);
            let expected = error.to_string();
            assert_eq!(
                request
                    .record_relay_response(&ledger, Err(error))
                    .unwrap_err()
                    .to_string(),
                expected
            );
            assert_eq!(request.l1_tx, None);
            let records = ledger.records().unwrap();
            assert_eq!(records.len(), 1);
            assert_eq!(handoff_hashes(&records).unwrap(), None);
        }
    }

    async fn assert_drain_requires_exact_canonical_finalized_receipts(
        mut request: Request,
        relay_error: Option<alloy::transports::TransportError>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let l1 = Asserter::new();
        let ctx = Context {
            ledger: crate::ledger::Ledger::open(dir.path()).unwrap(),
            l1: ProviderBuilder::new()
                .connect_mocked_client(l1.clone())
                .erased(),
            zones: vec![],
            zone_urls: vec![],
            http: Default::default(),
            l1_url: "http://localhost:1".parse().unwrap(),
            portal: Address::repeat_byte(9),
        };
        ctx.ledger
            .append(&Record::HandoffRequest(request.clone()))
            .unwrap();
        if let Some(error) = relay_error {
            let expected = error.to_string();
            assert_eq!(
                request
                    .record_relay_response(&ctx.ledger, Err(error))
                    .unwrap_err()
                    .to_string(),
                expected,
            );
            assert_eq!(request.l1_tx, Some(B256::repeat_byte(7)));
            let records = ctx.ledger.records().unwrap();
            assert_eq!(records.len(), 2);
            assert!(
                matches!(&records[1], Record::HandoffRequest(recorded) if *recorded == request)
            );
            assert_eq!(
                handoff_hashes(&records).unwrap(),
                Some(BTreeSet::from([B256::repeat_byte(7)]))
            );
        }
        let mut finalized = Block::<B256>::default();
        finalized.header.number = 10;
        finalized.header.hash = B256::repeat_byte(10);
        let receipt = json!({"type": if request.relayed { "0x76" } else { "0x0" }, "status":"0x1", "cumulativeGasUsed":"0x1", "logs":[], "logsBloom":Bloom::ZERO,
            "transactionHash":request.l1_tx.unwrap(), "transactionIndex":"0x0", "blockHash":finalized.header.hash,
            "blockNumber":"0xa", "gasUsed":"0x1", "effectiveGasPrice":"0x1",
            "from":Address::ZERO, "to":ctx.portal, "contractAddress":null, "feePayer":Address::ZERO});
        // Not mined, RPC error, mined above finality, noncanonical block, missing block/hash,
        // wrong receipt identity and a changed pinned finalized snapshot must all block readiness.
        l1.push_success(&finalized);
        l1.push_success(&serde_json::Value::Null);
        assert!(!ctx.handoffs_drained().await.unwrap());
        l1.push_success(&finalized);
        l1.push_failure_msg("receipt RPC unavailable");
        assert!(
            ctx.handoffs_drained()
                .await
                .unwrap_err()
                .to_string()
                .contains("receipt RPC unavailable")
        );
        let mut unfinalized = receipt.clone();
        unfinalized["blockNumber"] = json!("0xb");
        l1.push_success(&finalized);
        l1.push_success(&unfinalized);
        assert!(!ctx.handoffs_drained().await.unwrap());
        let mut fork = finalized.clone();
        fork.header.hash = B256::repeat_byte(11);
        l1.push_success(&finalized);
        l1.push_success(&receipt);
        l1.push_success(&fork);
        assert!(!ctx.handoffs_drained().await.unwrap());
        let mut wrong_number = finalized.clone();
        wrong_number.header.number = 9;
        l1.push_success(&finalized);
        l1.push_success(&receipt);
        l1.push_success(&wrong_number);
        assert!(!ctx.handoffs_drained().await.unwrap());
        l1.push_success(&finalized);
        l1.push_success(&receipt);
        l1.push_success(&None::<Block<B256>>);
        assert!(!ctx.handoffs_drained().await.unwrap());
        let mut missing = receipt.clone();
        missing["blockHash"] = serde_json::Value::Null;
        l1.push_success(&finalized);
        l1.push_success(&missing);
        assert!(!ctx.handoffs_drained().await.unwrap());
        let mut wrong = receipt.clone();
        wrong["transactionHash"] = json!(B256::repeat_byte(3));
        l1.push_success(&finalized);
        l1.push_success(&wrong);
        assert_eq!(
            ctx.handoffs_drained().await.unwrap_err().to_string(),
            "handoff receipt hash differs from request"
        );
        l1.push_success(&finalized);
        l1.push_success(&receipt);
        l1.push_success(&finalized);
        l1.push_success(&fork);
        assert!(!ctx.handoffs_drained().await.unwrap());
        for status in ["0x1", "0x0"] {
            let mut receipt = receipt.clone();
            receipt["status"] = json!(status);
            l1.push_success(&finalized);
            l1.push_success(&receipt);
            l1.push_success(&finalized);
            l1.push_success(&finalized);
            assert!(ctx.handoffs_drained().await.unwrap());
        }
        assert!(l1.read_q().is_empty());
    }

    fn update(epoch: u64, activation: u64, previous: u8, new: u8) -> Update {
        Update {
            l1_block: activation,
            l1_block_hash: B256::from(U256::from(activation)),
            l1_tx: B256::from(U256::from(epoch)),
            log_index: 0,
            epoch,
            previous_leader: Address::repeat_byte(previous),
            new_leader: Address::repeat_byte(new),
            activation_tempo_block: activation,
        }
    }

    fn request(id: u64, epoch: u64, target: u8) -> Request {
        Request {
            id,
            previous_leader: Address::repeat_byte(1),
            expected_epoch: epoch,
            target: Address::repeat_byte(target),
            relayed: false,
            from_l1_block: 10,
            l1_tx: Some(B256::from(U256::from(id))),
        }
    }

    #[test]
    fn mined_handoff_requires_its_portals_event() {
        let portal = Address::repeat_byte(9);
        let tx = B256::repeat_byte(1);
        let event = ZonePortal::LeaderUpdated {
            previousLeader: Address::repeat_byte(1),
            newLeader: Address::repeat_byte(2),
            epoch: 2,
            activationTempoBlock: 10,
        };
        let mut logs = [Log {
            inner: alloy::primitives::Log {
                address: portal,
                data: event.encode_log_data(),
            },
            transaction_hash: Some(tx),
            ..Default::default()
        }];
        // Reverted receipts and successful no-ops have no matching event to wait for.
        assert!(!handoff_applied(&[], portal, tx));
        assert!(handoff_applied(&logs, portal, tx));
        assert!(!handoff_applied(&logs, portal, B256::repeat_byte(2)));
        assert!(!handoff_applied(&logs, Address::repeat_byte(8), tx));
        logs[0].removed = true;
        assert!(!handoff_applied(&logs, portal, tx));
        logs[0].removed = false;
        logs[0].inner.data = Default::default();
        assert!(!handoff_applied(&logs, portal, tx));
    }

    #[test]
    fn competing_requests_require_two_distinct_submitted_transactions() {
        let mut requests = [request(1, 2, 2), request(2, 2, 3)];
        requests[0].l1_tx = None;
        requests[1].l1_tx = None;
        assert!(!competing_requests(&requests));
        requests[0].l1_tx = Some(B256::repeat_byte(1));
        assert!(!competing_requests(&requests));
        requests[1].l1_tx = requests[0].l1_tx;
        assert!(!competing_requests(&requests));
        requests[1].l1_tx = Some(B256::repeat_byte(2));
        assert!(competing_requests(&requests));
        requests[0].l1_tx = None;
        assert!(!competing_requests(&requests));
    }

    #[test]
    fn canonical_order_is_not_append_or_epoch_order() {
        let first = update(2, 10, 1, 2);
        let second = update(3, 20, 2, 3);
        let mut history = vec![second.clone(), first.clone(), first.clone()];
        order_history(&mut history);
        assert_eq!(history, vec![first, second]);
        assert!(validate_history(&history).is_ok());
        history[1].epoch = 1;
        order_history(&mut history);
        assert_eq!(history[0].epoch, 2);
        assert_eq!(
            validate_history(&history).unwrap_err().to_string(),
            "invalid finalized handoff epoch/activation history"
        );
    }

    #[test]
    fn repeated_leader_terms_obey_inclusive_activation_boundaries() {
        let history = vec![update(2, 10, 1, 2), update(3, 20, 2, 1)];
        assert!(validate_history(&history).is_ok());
        assert!(returns_to_previous_leader(&history));
        for (anchor, leader) in [(9, 1), (10, 2), (19, 2), (20, 1), (21, 1)] {
            assert_eq!(
                leader_at_anchor(&history, anchor),
                Some(Address::repeat_byte(leader))
            );
        }
        assert_eq!(leader_at_anchor(&[], 20), None);
        assert_eq!(leader_at_anchor(&[update(1, 10, 0, 1)], 9), None);
        assert!(!returns_to_previous_leader(&[
            update(2, 10, 1, 2),
            update(3, 20, 2, 3)
        ]));
    }

    #[test]
    fn epoch_gaps_broken_links_and_same_block_handoffs_are_invalid() {
        let first = update(2, 10, 1, 2);
        for bad in [
            update(4, 20, 2, 3),
            update(3, 20, 1, 3),
            update(3, 10, 2, 3),
        ] {
            assert_eq!(
                validate_history(&[first.clone(), bad])
                    .unwrap_err()
                    .to_string(),
                "invalid finalized handoff epoch/activation history"
            );
        }
        assert_eq!(
            validate_history(&[update(2, 10, 1, 1)])
                .unwrap_err()
                .to_string(),
            "invalid finalized handoff epoch/activation history"
        );
        let mut bad = first;
        bad.activation_tempo_block = 11;
        assert_eq!(
            validate_history(&[bad]).unwrap_err().to_string(),
            "invalid finalized handoff epoch/activation history"
        );
    }

    #[test]
    fn competing_requests_are_distinct_targets_at_the_same_observed_epoch() {
        assert!(competing_requests(&[request(1, 2, 2), request(2, 2, 3)]));
        assert!(!competing_requests(&[request(1, 2, 2), request(2, 3, 3)]));
        assert!(!competing_requests(&[request(1, 2, 2), request(2, 2, 2)]));
        assert!(!competing_requests(&[request(1, 2, 2), request(1, 2, 3)]));
        // Even an unknown request for the same target does not identify the winning transaction.
        let mut intent = request(1, 2, 2);
        intent.l1_tx = None;
        let event = update(3, 20, 1, 2);
        assert_ne!(intent.l1_tx, Some(event.l1_tx));
    }
}
