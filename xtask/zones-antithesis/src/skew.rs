//! Asymmetric handoffs with an observed pending nonce-gap pipeline, never an inferred election.

use alloy::{
    consensus::Transaction as _,
    primitives::{Address, B256, U256},
    providers::Provider as _,
    rpc::types::{BlockId, BlockNumberOrTag, Transaction},
};
use antithesis_sdk::{assert_always, assert_reachable, assert_sometimes};
use eyre::{OptionExt as _, WrapErr as _};
use serde::Serialize;
use serde_json::json;
use std::{path::Path, time::Duration};
use tempo_contracts::{
    precompiles::{ITIP20, PATH_USD_ADDRESS},
    zones::{TEMPO_STATE_ADDRESS, TempoState},
};
use tokio::time::{Instant, timeout, timeout_at};
use zone_rpc::types::SequencerInfoResponse;

use super::{
    Account, Context, SEQUENCER_INDICES, TIP20_TX_GAS,
    handoff::Update,
    intents::{Chain, Effect, Intent},
    is_rpc_error,
    ledger::Lease,
    proxy::{Fault, release_network_faults},
    random_index,
    recovery::{ReceiptProof, recover_until},
};

const PRECONDITION_TIMEOUT: Duration = Duration::from_secs(180);
const HELD_TIMEOUT: Duration = Duration::from_secs(150);
const RECOVERY_TIMEOUT: Duration = Duration::from_secs(180);
const EPISODE_TIMEOUT: Duration = Duration::from_secs(1200);
const PENDING_OBSERVATION: Duration = Duration::from_secs(10);
const PIPELINE_LENGTH: usize = 4;

/// An exact pending envelope, not merely a successful submission or an absent receipt.
#[derive(Debug, Serialize)]
struct PendingProof {
    tx: B256,
    sender: Address,
    nonce: u64,
    ingress: usize,
}

/// A zone tip pinned before reading its TempoState anchor.
#[derive(Debug, Serialize)]
struct Tip {
    height: u64,
    hash: B256,
    anchor: u64,
    producer: Address,
    observed_epoch: Option<u64>,
    applied_epoch: Option<u64>,
}

impl Context {
    /// Exercises a finalized A→B handoff while A cannot observe L1 and B cannot replicate.
    /// Missing pending-pool evidence makes exploration inconclusive, never a fabricated pass.
    pub(super) async fn asymmetric_handoff(&self, dir: &Path) -> eyre::Result<()> {
        let mut executed = false;
        let mut witnessed = false;
        let result = timeout(EPISODE_TIMEOUT, async {
            let _episode = self.ledger.episode_lock(true).await?;
            release_network_faults(dir).await?;
            self.release_outages(dir).await?;
            let drained = recover_until(Instant::now() + PRECONDITION_TIMEOUT, async || {
                if self.handoffs_drained().await? { return Ok(Some(())); }
                self.reconcile_intents().await?;
                Ok(None)
            }).await;
            if observation_expired(drained)?.is_none() {
                println!("asymmetric-handoff: prior handoff quiescence unknown; SKIPPED without faults");
                return Ok(());
            }
            eyre::ensure!(self.zones.len() == 4, "asymmetric handoff requires four zone nodes");
            let members = SEQUENCER_INDICES.map(|index| Ok(Account::at(index)?.address()))
                .collect::<eyre::Result<Vec<_>>>()?;
            let (baseline, initial) = self.outage_preconditions(&members).await?;
            let leader = members.iter().position(|member| *member == initial.leader)
                .ok_or_eyre("asymmetric handoff leader is not controlled")?;
            let backups: Vec<_> = (0..3).filter(|node| *node != leader).collect();
            let successor = backups[random_index(backups.len())];
            let other_backup = *backups.iter().find(|node| **node != successor)
                .ok_or_eyre("asymmetric handoff has no remaining backup")?;
            // The guard remains outside the held-phase future so phase errors still await heal.
            // Cancellation of the aggregate future drops it and publishes the cancellation.
            let mut gate = None;
            executed = true;
            let fault = timeout(HELD_TIMEOUT, async {
                gate = Some(Fault::apply(dir, 0, 1 << successor, Duration::from_secs(180)).await?);
                let gate = gate.as_mut().ok_or_eyre("network gate was not installed")?;
                let (tail, predecessor) = gate.while_active(async {
                    let ceiling = self.maximum_zone_tip().await?;
                    self.outage_canary(&baseline, ceiling, leader, Some(successor), &initial).await
                }).await?;
                gate.reconfigure(1 << leader, 1 << successor).await?;
                gate.while_active(async {
                    assert_reachable!("Asymmetric handoff: L1 and replication gates are independently acknowledged",
                        &json!({"old_leader": leader, "successor": successor}));
                    let before = self.skew_tip(leader).await?;
                    let (intents, lease) = recover_until(Instant::now() + HELD_TIMEOUT,
                        async || self.prepare_skew_pipeline(leader, other_backup).await).await?;
                    // Journal n before n+1 so prepare_intent's nonce floor stays intact. The head
                    // is not broadcast here; every tail send goes to an explicit ingress.
                    for intent in &intents[1..] {
                        match self.zones[intent.node].send_raw_transaction(&intent.raw).await {
                            Ok(_) => {},
                            Err(error) => {
                                let error = eyre::Report::from(error);
                                if !is_rpc_error(&error) { return Err(error); }
                                println!("skew tail {} send is unknown, not rejected: {error:#}", intent.tx);
                            }
                        }
                    }
                    let pending_before = observation_expired(recover_until(
                        Instant::now() + PENDING_OBSERVATION,
                        async || self.pending_skew_tail(&intents[1..]).await,
                    ).await)?;
                    let update = self.campaign_handoff(&initial, members[successor]).await?;
                    // campaign_handoff proves the exact finalized Portal event, deliberately
                    // without waiting for B's activation or assuming automatic leader election.
                    gate.ensure_active().await?;
                    assert_reachable!("Asymmetric handoff: Direct journaled Portal transition finalizes under both gates",
                        &json!({"update": update}));
                    let proof = observation_expired(recover_until(
                        Instant::now() + PENDING_OBSERVATION, async || {
                            let current = self.skew_tip(leader).await?;
                            let behind = self.skew_tip(successor).await?;
                            if !skew_observed(&before, &current, &behind, &predecessor, &update, initial.epoch) {
                                return Ok(None);
                            }
                            let Some(pending_after) = self.pending_skew_tail(&intents[1..]).await?
                            else { return Ok(None); };
                            gate.ensure_active().await?;
                            Ok(Some((current, behind, pending_after)))
                        },
                    ).await)?;
                    let eligible = pending_before.is_some() && proof.is_some();
                    if eligible {
                        assert_reachable!("Asymmetric handoff: Hot nonce-gap traffic remains pending across the finalized transition",
                            &json!({"update": update, "before": before, "pending_before": pending_before,
                                "after": proof, "withheld": intents[0].tx}));
                    } else {
                        println!("asymmetric-handoff: exploration INCONCLUSIVE; pending tail and independently observed leadership skew were not both observed");
                    }
                    let mut expected = initial.clone();
                    expected.leader = update.new_leader;
                    expected.epoch = update.epoch;
                    Ok((tail, predecessor, intents, lease, update, expected, eligible))
                }).await
            }).await.wrap_err("asymmetric fault phase timed out").and_then(|result| result);
            // Healing acknowledgements, old-prefix catch-up, pending work and fresh final-term
            // settlement all consume this ONE deadline, starting before release is issued.
            let deadline = Instant::now() + RECOVERY_TIMEOUT;
            let recovery = timeout_at(deadline, async {
                let healed = match gate.as_mut() {
                    Some(gate) => gate.heal().await,
                    None => release_network_faults(dir).await,
                };
                let (tail, predecessor, intents, lease, update, expected, eligible) = match (fault, healed) {
                    (Ok(proof), Ok(())) => proof,
                    (Err(fault), Err(heal)) => eyre::bail!("asymmetric phase failed: {fault:#}; heal failed: {heal:#}"),
                    (Err(error), Ok(())) | (Ok(_), Err(error)) => return Err(error),
                };
                // Pending durable intents, not an OS lock, now reserve all four nonces.
                // Reconciliation must be able to send the head, including through another node.
                drop(lease);
                recover_until(deadline, async || Ok(self.reconcile_intents().await?.then_some(()))).await?;
                let mut receipts = vec![predecessor];
                for intent in &intents {
                    let receipt = self.outage_receipt(intent).await?;
                    eyre::ensure!(receipt.status(), "hot-account skew transfer reverted");
                    eyre::ensure!(receipt.transaction_hash == intent.tx, "skew receipt hash differs from intent");
                    receipts.push(ReceiptProof { tx: receipt.transaction_hash,
                        height: receipt.block_number.ok_or_eyre("skew receipt has no height")?,
                        hash: receipt.block_hash.ok_or_eyre("skew receipt has no block hash")?, success: true });
                }
                recover_until(deadline, async || {
                    Ok(self.handoff_term_ready(&update, &expected, None).await?.then_some(()))
                }).await?;
                let ceiling = self.maximum_zone_tip().await?;
                // This is signed only after heal and exact final-term activation on all nodes.
                let (settled, fresh) = self.outage_canary(&tail, ceiling, successor, None, &expected).await?;
                receipts.push(fresh.clone());
                let all: Vec<_> = (0..self.zones.len()).collect();
                recover_until(deadline, async || {
                    if !self.handoff_term_ready(&update, &expected, Some(&fresh)).await? { return Ok(None); }
                    for receipt in &receipts {
                        if !self.check_checkpoint(&baseline, &settled, receipt, &all).await? { return Ok(None); }
                    }
                    self.reconcile_handoffs().await?;
                    self.check_handoff_history().await?;
                    Ok(Some(()))
                }).await?;
                witnessed = eligible;
                println!("asymmetric-handoff: {}", json!({"result": if eligible { "PASSED" } else { "INCONCLUSIVE" },
                    "recovery": "PASSED", "update": update, "receipts": receipts, "settled": settled}));
                Ok(())
            }).await.wrap_err("asymmetric recovery timed out from fault release").and_then(|result| result);
            assert_always!(recovery.is_ok(),
                "Asymmetric handoff: Released faults recover every exact receipt and fresh final-term settlement within one deadline",
                &json!({"error": recovery.as_ref().err().map(|error| format!("{error:#}"))}));
            recovery
        }).await.wrap_err("asymmetric episode exceeded its quiet window").and_then(|result| result);
        assert_sometimes!(
            witnessed,
            "Asymmetric handoff: An episode proves all three independent coverage witnesses",
            &json!({"executed": executed, "witnessed": witnessed})
        );
        assert_always!(
            result.is_ok(),
            "Asymmetric handoff: Episode cleans up within its aggregate deadline",
            &json!({"error": result.as_ref().err().map(|error| format!("{error:#}"))})
        );
        result
    }

    // The lease spans signing and the intentional gap. No global reconciliation is allowed
    // until the fault is released: it would broadcast the withheld durable head as well.
    async fn prepare_skew_pipeline(
        &self,
        leader: usize,
        other_backup: usize,
    ) -> eyre::Result<Option<(Vec<Intent>, Lease)>> {
        let Some((sender, _, lease)) = self.lease_zone_sender(&self.zones[leader]).await? else {
            return Ok(None);
        };
        let recipients: Vec<_> = self
            .ledger
            .accounts()?
            .into_iter()
            .map(|account| account.address())
            .filter(|address| *address != sender.address())
            .take(2)
            .collect();
        eyre::ensure!(
            !recipients.is_empty(),
            "hot pipeline requires an existing recipient"
        );
        let ingress = [leader, other_backup, 3];
        let mut intents: Vec<Intent> = Vec::with_capacity(PIPELINE_LENGTH);
        for position in 0..PIPELINE_LENGTH {
            let node = ingress[position % ingress.len()];
            let to = recipients[position % recipients.len()];
            let mut request = ITIP20::new(PATH_USD_ADDRESS, &self.zones[leader])
                .transfer(to, U256::from(1))
                .gas(TIP20_TX_GAS)
                .into_transaction_request();
            if let Some(prior) = intents.last() {
                request.nonce = Some(
                    prior
                        .nonce
                        .checked_add(1)
                        .ok_or_eyre("skew nonce overflow")?,
                );
            }
            let intent = self
                .prepare_intent(
                    &sender,
                    Chain::Zone,
                    node,
                    request,
                    Effect::Transfer { to, amount: 1 },
                )
                .await?;
            if let Some(prior) = intents.last() {
                eyre::ensure!(
                    Some(intent.nonce) == prior.nonce.checked_add(1),
                    "skew pipeline did not reserve consecutive nonces"
                );
            }
            intents.push(intent);
        }
        Ok(Some((intents, lease)))
    }

    async fn skew_tip(&self, node: usize) -> eyre::Result<Tip> {
        let zone = &self.zones[node];
        let block = zone
            .get_block_by_number(BlockNumberOrTag::Latest)
            .await?
            .ok_or_eyre("skew observation has no latest zone block")?;
        let anchor = TempoState::new(TEMPO_STATE_ADDRESS, zone)
            .tempoBlockNumber()
            .block(BlockId::hash(block.header.hash))
            .call()
            .await?;
        // An old applied anchor does not imply an old L1 view: inspect the observer's
        // epoch independently, using the existing typed node-status response.
        let view: SequencerInfoResponse =
            zone.raw_request("zone_getSequencerInfo".into(), ()).await?;
        let observed_epoch = view
            .progress
            .as_ref()
            .and_then(|progress| progress.latest_observed_leadership_epoch)
            .map(|epoch| epoch.to::<u64>());
        let applied_epoch = view
            .progress
            .as_ref()
            .and_then(|progress| progress.locally_applied_leadership_epoch)
            .map(|epoch| epoch.to::<u64>());
        Ok(Tip {
            height: block.header.number,
            hash: block.header.hash,
            anchor,
            producer: block.header.beneficiary,
            observed_epoch,
            applied_epoch,
        })
    }

    async fn pending_skew_tail(&self, tail: &[Intent]) -> eyre::Result<Option<Vec<PendingProof>>> {
        let mut proof = Vec::with_capacity(tail.len());
        for intent in tail {
            let Some(transaction) = self.zones[intent.node]
                .get_transaction_by_hash(intent.tx)
                .await?
            else {
                return Ok(None);
            };
            if !pending_matches(intent, &transaction)? {
                return Ok(None);
            }
            proof.push(PendingProof {
                tx: intent.tx,
                sender: intent.sender,
                nonce: intent.nonce,
                ingress: intent.node,
            });
        }
        Ok(Some(proof))
    }
}

fn pending_matches(intent: &Intent, transaction: &Transaction) -> eyre::Result<bool> {
    eyre::ensure!(
        *transaction.inner.tx_hash() == intent.tx
            && transaction.inner.signer() == intent.sender
            && transaction.nonce() == intent.nonce,
        "pending skew transaction differs from signed intent"
    );
    Ok(transaction.block_hash.is_none()
        && transaction.block_number.is_none()
        && transaction.transaction_index.is_none())
}

// A cached pre-transition tip must not stand in for a current observation. Call this only
// on newly fetched tips bracketed by the gate's acknowledgement checks.
fn skew_observed(
    before: &Tip,
    current: &Tip,
    successor: &Tip,
    predecessor: &ReceiptProof,
    update: &Update,
    initial_epoch: u64,
) -> bool {
    before.observed_epoch == Some(initial_epoch)
        && current.observed_epoch == Some(initial_epoch)
        && successor.observed_epoch == Some(update.epoch)
        && before.producer == update.previous_leader
        && current.producer == update.previous_leader
        && current.height >= before.height
        && current.anchor >= before.anchor
        && current.anchor < update.activation_tempo_block
        && successor.height < predecessor.height
}

fn observation_expired<T>(result: eyre::Result<T>) -> eyre::Result<Option<T>> {
    match result {
        Ok(proof) => Ok(Some(proof)),
        Err(error)
            if error
                .downcast_ref::<tokio::time::error::Elapsed>()
                .is_some() =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Record, intents::pending, ledger::Ledger};
    use alloy::{
        consensus::{
            Signed, TxEnvelope, TxLegacy,
            transaction::{Recovered, SignerRecoverable as _},
        },
        eips::eip2718::{Decodable2718 as _, Encodable2718 as _},
        primitives::{Bloom, Bytes, Signature, TxKind, keccak256},
        providers::ProviderBuilder,
        sol_types::SolValue as _,
        transports::mock::Asserter,
    };
    use std::{
        cell::Cell,
        collections::{BTreeMap, HashSet},
    };
    use tokio::{
        io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader},
        net::TcpListener,
    };

    fn pending_transaction() -> (Intent, Transaction) {
        let sender = Address::repeat_byte(1);
        let envelope = TxEnvelope::Legacy(Signed::new_unhashed(
            TxLegacy {
                nonce: 8,
                chain_id: Some(123),
                gas_price: 1,
                gas_limit: TIP20_TX_GAS,
                to: TxKind::Call(PATH_USD_ADDRESS),
                ..Default::default()
            },
            Signature::new(U256::from(1), U256::from(2), false),
        ));
        let intent = Intent {
            tx: *envelope.tx_hash(),
            raw: envelope.encoded_2718().into(),
            chain: Chain::Zone,
            chain_id: 123,
            sender,
            nonce: 8,
            node: 2,
            effect: Effect::Transfer {
                to: Address::repeat_byte(2),
                amount: 1,
            },
        };
        let transaction = Transaction {
            inner: Recovered::new_unchecked(envelope, sender),
            block_hash: None,
            block_number: None,
            transaction_index: None,
            effective_gas_price: None,
            block_timestamp: None,
        };
        (intent, transaction)
    }

    #[tokio::test]
    async fn hot_pipeline_journals_head_first_and_replays_exact_bytes_only_after_release() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let urls: Vec<alloy::transports::http::reqwest::Url> = (0..4)
            .map(|node| {
                format!("http://{}/{node}", listener.local_addr().unwrap())
                    .parse()
                    .unwrap()
            })
            .collect();
        let http = alloy::transports::http::reqwest::Client::default();
        let connect = |url: &alloy::transports::http::reqwest::Url| {
            ProviderBuilder::new()
                .connect_reqwest(http.clone(), url.clone())
                .erased()
        };
        let dir = tempfile::tempdir().unwrap();
        let ctx = Context {
            ledger: Ledger::open(dir.path()).unwrap(),
            l1: connect(&urls[0]),
            zones: urls.iter().map(connect).collect(),
            l1_url: urls[0].clone(),
            zone_urls: urls,
            http,
            portal: Address::repeat_byte(9),
        };
        for _ in 0..3 {
            ctx.ledger.new_account().unwrap();
        }
        let healing = Cell::new(false);
        let sent_head = Cell::new(false);
        let recovered = Cell::new(0);
        let work = async {
            let (intents, lease) = ctx.prepare_skew_pipeline(0, 2).await.unwrap().unwrap();
            assert_eq!(intents.len(), PIPELINE_LENGTH);
            assert_eq!(pending(&ctx.ledger.records().unwrap()).unwrap(), intents);
            let accounts = ctx.ledger.accounts().unwrap();
            assert_eq!(accounts.len(), 3, "hot pipeline must reuse recipients");
            let sender = accounts
                .iter()
                .find(|account| account.address() == intents[0].sender)
                .unwrap();
            for (offset, intent) in intents.iter().enumerate() {
                assert_eq!(intent.nonce, 7 + u64::try_from(offset).unwrap());
                assert_eq!(intent.sender, sender.address());
                assert_eq!(keccak256(&intent.raw), intent.tx);
                let mut raw = intent.raw.as_ref();
                let signed = TxEnvelope::decode_2718(&mut raw).unwrap();
                assert!(raw.is_empty());
                assert_eq!(signed.nonce(), intent.nonce);
                assert_eq!(signed.recover_signer().unwrap(), intent.sender);
                if let Effect::Transfer { to, amount } = intent.effect {
                    assert_eq!(amount, 1);
                    assert_ne!(to, sender.address());
                    assert!(accounts.iter().any(|account| account.address() == to));
                } else {
                    panic!("hot pipeline contains non-transfer intent");
                }
            }
            assert!(ctx.ledger.try_lease(sender).unwrap().is_none());
            assert_ne!(
                intents[0].node, intents[1].node,
                "nonce-gap tail needs another ingress"
            );
            for intent in &intents[1..] {
                let _ = ctx.zones[intent.node]
                    .send_raw_transaction(&intent.raw)
                    .await
                    .unwrap();
            }
            assert_eq!(
                ctx.pending_skew_tail(&intents[1..])
                    .await
                    .unwrap()
                    .unwrap()
                    .len(),
                3
            );
            assert!(
                !sent_head.get(),
                "pre-transition tail must not release head"
            );
            healing.set(true);
            drop(lease);
            assert!(
                ctx.ledger.try_lease(sender).unwrap().is_none(),
                "durable intents retain reservation"
            );
            assert!(ctx.reconcile_intents().await.unwrap());
            assert!(sent_head.get());
            assert_eq!(recovered.get(), PIPELINE_LENGTH);
            assert!(ctx.ledger.try_lease(sender).unwrap().is_some());
            for intent in &intents {
                assert_eq!(
                    ctx.ledger
                        .records()
                        .unwrap()
                        .iter()
                        .filter(|record| record.effect_hash() == Some(intent.tx))
                        .count(),
                    1
                );
            }
        };
        let server = async {
            let mut sent = HashSet::new();
            let mut replayed = HashSet::new();
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let mut reader = BufReader::new(stream);
                let mut request_line = String::new();
                reader.read_line(&mut request_line).await.unwrap();
                let node: usize = request_line
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .trim_start_matches('/')
                    .parse()
                    .unwrap();
                let mut length = None;
                loop {
                    let mut line = String::new();
                    assert_ne!(reader.read_line(&mut line).await.unwrap(), 0);
                    if line == "\r\n" {
                        break;
                    }
                    if let Some((key, value)) = line.split_once(':')
                        && key.eq_ignore_ascii_case("content-length")
                    {
                        length = Some(value.trim().parse::<usize>().unwrap());
                    }
                }
                let mut body = vec![0; length.unwrap()];
                reader.read_exact(&mut body).await.unwrap();
                let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
                let intents: Vec<_> = ctx
                    .ledger
                    .records()
                    .unwrap()
                    .into_iter()
                    .filter_map(|record| {
                        if let Record::Intent(intent) = record {
                            Some(intent)
                        } else {
                            None
                        }
                    })
                    .collect();
                let result = match request["method"].as_str().unwrap() {
                    "eth_call" => json!(Bytes::from(
                        U256::from(crate::MIN_SENDER_BALANCE).abi_encode()
                    )),
                    "eth_chainId" => json!("0x7b"),
                    "eth_getTransactionCount" => json!("0x7"),
                    "eth_gasPrice" | "eth_maxPriorityFeePerGas" => json!("0x1"),
                    "eth_feeHistory" => json!({"oldestBlock":"0xa", "baseFeePerGas":["0x1","0x1"],
                        "gasUsedRatio":[0.5], "reward":[["0x1"]]}),
                    "eth_getBlockByNumber" => {
                        let mut block = alloy::rpc::types::Block::<B256>::default();
                        block.header.number = 10;
                        block.header.base_fee_per_gas = Some(1);
                        json!(block)
                    }
                    "eth_sendRawTransaction" => {
                        let intent = intents
                            .iter()
                            .find(|intent| json!(intent.raw) == request["params"][0])
                            .expect("broadcast must use exact journaled bytes");
                        if intent.nonce == 7 {
                            assert!(healing.get(), "head was sent before fault release");
                            sent_head.set(true);
                        }
                        if healing.get() {
                            assert_ne!(node, intent.node, "recovery must try another ingress");
                            replayed.insert(intent.tx);
                        } else {
                            assert_eq!(node, intent.node);
                        }
                        sent.insert(intent.tx);
                        json!(intent.tx)
                    }
                    "eth_getTransactionByHash" => {
                        let intent = intents
                            .iter()
                            .find(|intent| json!(intent.tx) == request["params"][0])
                            .unwrap();
                        assert!(sent.contains(&intent.tx));
                        assert!(!sent_head.get());
                        let mut raw = intent.raw.as_ref();
                        let envelope = TxEnvelope::decode_2718(&mut raw).unwrap();
                        json!(Transaction {
                            inner: Recovered::new_unchecked(envelope, intent.sender),
                            block_hash: None,
                            block_number: None,
                            transaction_index: None,
                            effective_gas_price: None,
                            block_timestamp: None,
                        })
                    }
                    "eth_getTransactionReceipt" => {
                        assert!(healing.get());
                        let intent = intents
                            .iter()
                            .find(|intent| json!(intent.tx) == request["params"][0])
                            .unwrap();
                        if replayed.contains(&intent.tx) {
                            recovered.set(recovered.get() + 1);
                            json!({"type":"0x0", "status":"0x1", "cumulativeGasUsed":"0x1",
                                "logs":[], "logsBloom":Bloom::ZERO, "transactionHash":intent.tx,
                                "transactionIndex":"0x0", "blockHash":B256::repeat_byte(8),
                                "blockNumber":"0x14", "gasUsed":"0x1", "effectiveGasPrice":"0x1",
                                "from":intent.sender, "to":PATH_USD_ADDRESS, "contractAddress":null})
                        } else {
                            json!(null)
                        }
                    }
                    other => panic!("unexpected hot-pipeline RPC {other}"),
                };
                let response =
                    json!({"jsonrpc":"2.0", "id":request["id"], "result":result}).to_string();
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.len()
                );
                let mut stream = reader.into_inner();
                stream.write_all(header.as_bytes()).await.unwrap();
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        };
        timeout(Duration::from_secs(10), async {
            tokio::select! { () = work => {}, () = server => panic!("RPC fixture stopped") }
        })
        .await
        .unwrap();
    }

    #[test]
    fn pending_witness_requires_exact_unmined_transaction_not_just_a_send() {
        let (intent, transaction) = pending_transaction();
        assert!(pending_matches(&intent, &transaction).unwrap());
        for field in 0..3 {
            let mut mined = transaction.clone();
            match field {
                0 => mined.block_number = Some(10),
                1 => mined.block_hash = Some(B256::repeat_byte(3)),
                _ => mined.transaction_index = Some(0),
            }
            assert!(!pending_matches(&intent, &mined).unwrap());
        }
        for field in 0..3 {
            let mut wrong = intent.clone();
            match field {
                0 => wrong.tx = B256::repeat_byte(4),
                1 => wrong.nonce += 1,
                _ => wrong.sender = Address::repeat_byte(5),
            }
            assert_eq!(
                pending_matches(&wrong, &transaction)
                    .unwrap_err()
                    .to_string(),
                "pending skew transaction differs from signed intent"
            );
        }
    }

    fn skew_fixture() -> (Tip, Tip, Tip, ReceiptProof, Update) {
        let before = Tip {
            height: 20,
            hash: B256::repeat_byte(1),
            anchor: 30,
            producer: Address::repeat_byte(1),
            observed_epoch: Some(1),
            applied_epoch: Some(1),
        };
        let successor = Tip {
            height: 19,
            hash: B256::repeat_byte(2),
            anchor: 29,
            producer: before.producer,
            observed_epoch: Some(2),
            applied_epoch: Some(1),
        };
        let predecessor = ReceiptProof {
            tx: B256::repeat_byte(3),
            height: 21,
            hash: B256::repeat_byte(4),
            success: true,
        };
        let update = Update {
            l1_block: 33,
            l1_block_hash: B256::repeat_byte(5),
            l1_tx: B256::repeat_byte(6),
            log_index: 0,
            epoch: 2,
            previous_leader: before.producer,
            new_leader: Address::repeat_byte(2),
            activation_tempo_block: 34,
        };
        let current = Tip {
            height: 21,
            hash: predecessor.hash,
            anchor: 31,
            producer: before.producer,
            observed_epoch: Some(1),
            applied_epoch: Some(1),
        };
        (before, current, successor, predecessor, update)
    }

    #[test]
    fn stale_or_new_term_anchor_cannot_prove_old_leader_skew() {
        let (before, mut current, successor, predecessor, update) = skew_fixture();
        assert!(skew_observed(
            &before,
            &current,
            &successor,
            &predecessor,
            &update,
            1
        ));
        current.anchor = 34;
        assert!(!skew_observed(
            &before,
            &current,
            &successor,
            &predecessor,
            &update,
            1
        ));
        current.anchor = 29;
        assert!(!skew_observed(
            &before,
            &current,
            &successor,
            &predecessor,
            &update,
            1
        ));
        current.anchor = 31;
        current.producer = update.new_leader;
        assert!(!skew_observed(
            &before,
            &current,
            &successor,
            &predecessor,
            &update,
            1
        ));
        current.producer = before.producer;
        let caught_up = Tip {
            height: predecessor.height,
            ..successor
        };
        assert!(!skew_observed(
            &before,
            &current,
            &caught_up,
            &predecessor,
            &update,
            1
        ));
    }

    #[tokio::test]
    async fn node_view_reads_observed_epoch_separately_from_applied_epoch() {
        for observed in [Some(1), Some(2), None] {
            let rpc = Asserter::new();
            let zone = ProviderBuilder::new()
                .connect_mocked_client(rpc.clone())
                .erased();
            let dir = tempfile::tempdir().unwrap();
            let ctx = Context {
                ledger: Ledger::open(dir.path()).unwrap(),
                http: Default::default(),
                l1_url: "http://localhost:1".parse().unwrap(),
                l1: zone.clone(),
                zones: vec![zone],
                zone_urls: vec![],
                portal: Address::repeat_byte(9),
            };
            let mut block = alloy::rpc::types::Block::<B256>::default();
            block.header.number = 20;
            block.header.hash = B256::repeat_byte(7);
            block.header.beneficiary = Address::repeat_byte(1);
            rpc.push_success(&block);
            rpc.push_success(&Bytes::from(U256::from(30).abi_encode()));
            rpc.push_success(&json!({"mode":"multi", "portal":ctx.portal, "peers":[],
                "progress": {"zoneHeight":"0x14", "tempoBlockNumber":"0x1e",
                    "latestObservedLeadershipEpoch": observed.map(|epoch| format!("0x{epoch:x}")),
                    "locallyAppliedLeadershipEpoch":"0x1", "pendingTransitions":"0x1"}}));
            let tip = timeout(Duration::from_secs(1), ctx.skew_tip(0))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(tip.height, 20);
            assert_eq!(tip.anchor, 30);
            assert_eq!(tip.observed_epoch, observed);
            assert_eq!(tip.applied_epoch, Some(1));
            assert!(rpc.read_q().is_empty());
        }
    }

    #[test]
    fn old_applied_epoch_does_not_hide_a_newly_observed_leadership_epoch() {
        let (before, mut current, successor, predecessor, update) = skew_fixture();
        current.observed_epoch = Some(update.epoch);
        assert_eq!(current.applied_epoch, Some(1));
        assert!(current.anchor < update.activation_tempo_block);
        assert!(!skew_observed(
            &before,
            &current,
            &successor,
            &predecessor,
            &update,
            1
        ));
        current.observed_epoch = None;
        assert!(!skew_observed(
            &before,
            &current,
            &successor,
            &predecessor,
            &update,
            1
        ));
        current.observed_epoch = Some(1);
        for observed in [None, Some(1), Some(3)] {
            let behind = Tip {
                observed_epoch: observed,
                ..skew_fixture().2
            };
            assert!(!skew_observed(
                &before,
                &current,
                &behind,
                &predecessor,
                &update,
                1
            ));
        }
        assert!(skew_observed(
            &before,
            &current,
            &successor,
            &predecessor,
            &update,
            1
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn successor_observing_transition_only_after_release_leaves_episode_inconclusive() {
        let (before, current, mut successor, predecessor, update) = skew_fixture();
        successor.observed_epoch = Some(1);
        // This is the pre-release observation window. There is no second witness attempt
        // in recovery, even if B learns the epoch immediately after the gate is healed.
        let proof = observation_expired(
            recover_until(Instant::now() + PENDING_OBSERVATION, async || {
                Ok(
                    skew_observed(&before, &current, &successor, &predecessor, &update, 1)
                        .then_some(()),
                )
            })
            .await,
        )
        .unwrap();
        assert_eq!(proof, None);
        successor.observed_epoch = Some(update.epoch);
        assert!(skew_observed(
            &before,
            &current,
            &successor,
            &predecessor,
            &update,
            1
        ));
        assert_eq!(
            proof, None,
            "post-heal observations cannot retroactively award held-phase coverage"
        );
    }

    #[test]
    fn coverage_and_recovery_have_separate_catalogued_properties() {
        let class = module_path!().strip_suffix("::tests").unwrap();
        let entries: Vec<_> = antithesis_sdk::assert::ANTITHESIS_CATALOG
            .iter()
            .filter(|entry| entry.class == class)
            .collect();
        let actual: BTreeMap<_, _> = entries
            .iter()
            .map(|entry| (entry.message, entry.display_type))
            .collect();
        assert_eq!(entries.len(), actual.len(), "duplicate skew property IDs");
        for witness in [
            "Asymmetric handoff: L1 and replication gates are independently acknowledged",
            "Asymmetric handoff: Direct journaled Portal transition finalizes under both gates",
            "Asymmetric handoff: Hot nonce-gap traffic remains pending across the finalized transition",
        ] {
            assert_eq!(actual.get(witness), Some(&"Reachable"));
        }
        assert_eq!(actual.get("Asymmetric handoff: Released faults recover every exact receipt and fresh final-term settlement within one deadline"), Some(&"Always"));
        assert_eq!(
            actual.get(
                "Asymmetric handoff: An episode proves all three independent coverage witnesses"
            ),
            Some(&"Sometimes")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn unobserved_pending_tail_expires_as_inconclusive_not_a_false_pass() {
        let result = recover_until(Instant::now() + PENDING_OBSERVATION, async || {
            eyre::Ok(None::<()>)
        })
        .await;
        assert_eq!(observation_expired(result).unwrap(), None);
        assert_eq!(observation_expired(Ok(7)).unwrap(), Some(7));
        assert_eq!(
            observation_expired::<()>(Err(eyre::eyre!("contradictory receipt")))
                .unwrap_err()
                .to_string(),
            "contradictory receipt"
        );
    }
}
