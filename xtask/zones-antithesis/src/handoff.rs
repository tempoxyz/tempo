//! Durable handoff intents and canonical, finalized portal leadership history.

use alloy::{
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
use zone_rpc::types::SetLeaderResponse;

use super::{
    ADMIN_INDEX, Account, BRIDGE_WAIT, Context, RECEIPT_TIMEOUT, Record, SEQUENCER_INDICES,
    poll_until, random_below, random_choice, random_index,
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
    pub(super) async fn rotate_leader(&self) -> eyre::Result<()> {
        self.reconcile_handoffs().await?;
        let relayed = random_below(2) == 0;
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
        self.ledger
            .append(&Record::HandoffRequest(request.clone()))?;
        // The rpc-only node refuses relays; even that attempt retains its durable intent.
        let (tx, applied) = if relayed {
            let node = random_index(self.zones.len());
            // zone-rpc exposes the typed response, but no alloy client extension for this RPC.
            let response: SetLeaderResponse = self.zones[node]
                .raw_request("zone_setLeader".into(), [target])
                .await?;
            let Some(tx) = response.tx_hash else {
                println!("rotate-leader: {target} already leads");
                return Ok(());
            };
            request.l1_tx = Some(tx);
            self.ledger
                .append(&Record::HandoffRequest(request.clone()))?;
            // The relay waits for a receipt, but a successful same-target no-op emits no event.
            // Query logs because the Ethereum provider cannot decode Tempo relay receipts.
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
            let pending = ZonePortal::new(self.portal, self.wallet(&admin, &self.l1_url))
                .setLeader(target, epoch)
                .send()
                .await?;
            // Persist the hash before waiting for the receipt, not after confirmation.
            request.l1_tx = Some(*pending.tx_hash());
            self.ledger
                .append(&Record::HandoffRequest(request.clone()))?;
            let receipt = pending
                .with_timeout(Some(RECEIPT_TIMEOUT))
                .get_receipt()
                .await?;
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
