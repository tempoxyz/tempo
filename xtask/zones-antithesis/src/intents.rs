//! Durable, exact-byte payment submissions. An absent receipt is never a rejection.

use alloy::{
    consensus::Transaction as _,
    eips::eip2718::Encodable2718 as _,
    primitives::{Address, B256, Bytes, U256, keccak256},
    providers::{Provider as _, ProviderBuilder},
    rpc::types::{TransactionReceipt, TransactionRequest},
};
use eyre::{OptionExt as _, WrapErr as _};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::{
    Context, RECEIPT_TIMEOUT, TIP20_TX_GAS,
    ledger::{Account, Record},
};
use tempo_contracts::{
    precompiles::{ITIP20, PATH_USD_ADDRESS},
    zones::ZonePortal,
};

/// The chain on which the signed payment executes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Chain {
    /// Tempo L1.
    L1,
    /// The zone.
    Zone,
}

/// The obligation created by successful execution, or an auxiliary payment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Effect {
    /// Encrypted deposit; its receipt supplies the queue hash and net amount.
    Deposit { to: Address, amount: u128 },
    /// Zone transfer, including every fanout child and the recovery probe.
    Transfer { to: Address, amount: u128 },
    /// Zone withdrawal, whose successful receipt obligates L1 payment.
    Withdrawal { to: Address, amount: u128 },
    /// An allowance needed before a deposit or withdrawal.
    Approval { spender: Address },
    /// Explicit admin leadership change, including rotations and controlled outages.
    Leadership { target: Address },
    /// Funding a fresh L1 depositor.
    Funding { to: Address, amount: u128 },
}

/// Persisted before the first broadcast; replay must use `raw` without rebuilding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Intent {
    /// Hash of the exact signed envelope.
    pub(crate) tx: B256,
    /// EIP-2718 encoded signed envelope, including its signature.
    pub(crate) raw: Bytes,
    /// Execution domain.
    pub(crate) chain: Chain,
    /// Chain ID embedded in the signed envelope.
    pub(crate) chain_id: u64,
    /// Signer's address.
    pub(crate) sender: Address,
    /// Signed nonce; never replace an unresolved transaction at this nonce.
    pub(crate) nonce: u64,
    /// Original zone endpoint, allowing recovery to start at a different node.
    pub(crate) node: usize,
    /// Expected effect after successful execution.
    pub(crate) effect: Effect,
}

/// Only a mined receipt can resolve an intent. Unknown has no terminal record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Outcome {
    /// Execution succeeded at this height.
    Confirmed { block: u64, block_hash: B256 },
    /// Execution reverted at this height; no payment obligation was created.
    Reverted { block: u64, block_hash: B256 },
}

impl Intent {
    /// Converts a successful receipt into the existing checks' obligation record.
    pub(crate) fn obligation(&self, receipt: &TransactionReceipt) -> eyre::Result<Option<Record>> {
        eyre::ensure!(
            receipt.transaction_hash == self.tx,
            "receipt hash differs from intent"
        );
        let block = receipt.block_number.ok_or_eyre("receipt has no block")?;
        if !receipt.status() {
            return Ok(None);
        }
        Ok(match self.effect {
            Effect::Deposit { to, .. } => {
                let made = receipt
                    .decoded_log::<ZonePortal::DepositMade>()
                    .ok_or_eyre("deposit receipt has no DepositMade log")?;
                Some(Record::Deposit {
                    l1_tx: self.tx,
                    queue_hash: made.newCurrentDepositQueueHash,
                    sender: self.sender,
                    to,
                    net_amount: made.netAmount,
                })
            }
            Effect::Transfer { to, amount } => Some(Record::Transfer {
                zone_tx: self.tx,
                zone_block: block,
                from: self.sender,
                to,
                amount,
            }),
            Effect::Withdrawal { to, amount } => Some(Record::Withdrawal {
                zone_tx: self.tx,
                zone_block: block,
                sender: self.sender,
                to,
                amount,
            }),
            Effect::Approval { .. } | Effect::Funding { .. } | Effect::Leadership { .. } => None,
        })
    }
}

/// Rebuilds unresolved state, rejecting conflicting intent hashes and nonce replacement.
pub(crate) fn pending(records: &[Record]) -> eyre::Result<Vec<Intent>> {
    let mut intents = HashMap::new();
    let mut nonces = HashSet::new();
    let mut terminal = HashMap::new();
    let mut obligations = HashSet::new();
    for record in records {
        match record {
            Record::Intent(intent) => {
                eyre::ensure!(
                    keccak256(&intent.raw) == intent.tx,
                    "intent raw bytes do not match hash"
                );
                if let Some(prior) = intents.get(&intent.tx) {
                    eyre::ensure!(*prior == intent, "conflicting duplicate intent");
                } else {
                    eyre::ensure!(
                        nonces.insert((intent.chain, intent.chain_id, intent.sender, intent.nonce)),
                        "replacement intent at an already journaled nonce"
                    );
                    intents.insert(intent.tx, intent);
                }
            }
            Record::IntentOutcome { tx, outcome } => {
                let intent = intents.get(tx).ok_or_eyre("outcome without intent")?;
                if matches!(outcome, Outcome::Confirmed { .. })
                    && matches!(
                        intent.effect,
                        Effect::Deposit { .. }
                            | Effect::Transfer { .. }
                            | Effect::Withdrawal { .. }
                    )
                {
                    eyre::ensure!(
                        obligations.contains(tx),
                        "confirmed outcome precedes obligation"
                    );
                }
                if let Some(prior) = terminal.insert(*tx, outcome) {
                    eyre::ensure!(prior == outcome, "conflicting intent outcomes");
                }
            }
            record => {
                if let Some(tx) = record.effect_hash() {
                    obligations.insert(tx);
                }
            }
        }
    }
    // Preserve journal order: fanout nonces must be replayed in submission order.
    let mut seen = HashSet::new();
    Ok(records
        .iter()
        .filter_map(|record| match record {
            Record::Intent(intent)
                if !terminal.contains_key(&intent.tx) && seen.insert(intent.tx) =>
            {
                Some(intent.clone())
            }
            _ => None,
        })
        .collect())
}

impl Context {
    /// Signs and durably records a payment before any broadcast. Caller holds the sender lease.
    pub(crate) async fn prepare_intent(
        &self,
        account: &Account,
        chain: Chain,
        node: usize,
        mut request: TransactionRequest,
        effect: Effect,
    ) -> eyre::Result<Intent> {
        let url = match chain {
            Chain::L1 => &self.l1_url,
            Chain::Zone => &self.zone_urls[node],
        };
        let provider = ProviderBuilder::new()
            .wallet(account.signer.clone())
            .connect_reqwest(self.http.clone(), url.clone());
        request.from = Some(account.address());
        let chain_id = match request.chain_id {
            Some(chain_id) => chain_id,
            None => provider.get_chain_id().await?,
        };
        request.chain_id = Some(chain_id);
        let network_nonce = if let Some(nonce) = request.nonce {
            nonce
        } else {
            provider
                .get_transaction_count(account.address())
                .pending()
                .await?
        };
        // A lagging endpoint must not make us sign a replacement for a historical nonce.
        let next_journal_nonce = self
            .ledger
            .records()?
            .iter()
            .filter_map(|record| match record {
                Record::Intent(intent)
                    if intent.chain == chain
                        && intent.chain_id == chain_id
                        && intent.sender == account.address() =>
                {
                    Some(intent.nonce)
                }
                _ => None,
            })
            .max()
            .map(|nonce| nonce.checked_add(1).ok_or_eyre("intent nonce overflow"))
            .transpose()?
            .unwrap_or(0);
        request.nonce = Some(network_nonce.max(next_journal_nonce));
        let filled = provider
            .fill(request)
            .await
            .wrap_err("failed filling durable transaction")?;
        let envelope = filled
            .as_envelope()
            .ok_or_eyre("wallet did not sign transaction")?;
        let intent = Intent {
            tx: *envelope.tx_hash(),
            raw: envelope.encoded_2718().into(),
            chain,
            chain_id: envelope
                .chain_id()
                .ok_or_eyre("signed transaction has no chain ID")?,
            sender: account.address(),
            nonce: envelope.nonce(),
            node,
            effect,
        };
        self.ledger.append(&Record::Intent(intent.clone()))?;
        Ok(intent)
    }

    /// Broadcasts the journal's exact signed bytes and records any mined outcome synchronously.
    pub(crate) async fn send_intent(&self, intent: &Intent) -> eyre::Result<TransactionReceipt> {
        let provider = match intent.chain {
            Chain::L1 => &self.l1,
            Chain::Zone => &self.zones[intent.node],
        };
        let receipt = provider
            .send_raw_transaction(&intent.raw)
            .await?
            .with_timeout(Some(RECEIPT_TIMEOUT))
            .get_receipt()
            .await?;
        self.ledger.resolve_intent(intent, &receipt)?;
        Ok(receipt)
    }

    /// One bounded pass over prior unresolved payments. Replays identical bytes at another
    /// node; returns true only when no unresolved intent remains, including concurrent writers.
    pub(crate) async fn reconcile_intents(&self) -> eyre::Result<bool> {
        for intent in pending(&self.ledger.records()?)? {
            let providers = match intent.chain {
                Chain::L1 => vec![&self.l1],
                Chain::Zone => (1..=self.zones.len())
                    .map(|offset| &self.zones[(intent.node + offset) % self.zones.len()])
                    .collect(),
            };
            for provider in providers {
                match provider.get_transaction_receipt(intent.tx).await {
                    Ok(Some(receipt)) => {
                        self.ledger.resolve_intent(&intent, &receipt)?;
                        break;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        println!("intent {} receipt remains unknown: {error}", intent.tx);
                        continue;
                    }
                }
                // Duplicate broadcasts are safe. A send error, including nonce-too-low, is
                // NOT evidence of rejection: keep the intent until a receipt is available.
                match provider.send_raw_transaction(&intent.raw).await {
                    Ok(_) => {}
                    Err(error) => println!("intent {} replay remains unknown: {error}", intent.tx),
                }
                if let Some(receipt) = provider
                    .get_transaction_receipt(intent.tx)
                    .await
                    .unwrap_or_else(|error| {
                        println!("intent {} receipt remains unknown: {error}", intent.tx);
                        None
                    })
                {
                    self.ledger.resolve_intent(&intent, &receipt)?;
                    break;
                }
            }
        }
        Ok(pending(&self.ledger.records()?)?.is_empty())
    }

    /// Signs and journals a fresh canary on the caller's selected live endpoint, releasing the
    /// lease only after its durable intent blocks reuse. None means no free funded sender.
    pub(crate) async fn prepare_recovery_canary(
        &self,
        node: usize,
    ) -> eyre::Result<Option<Intent>> {
        let Some((sender, _, _lease)) = self.lease_zone_sender(&self.zones[node]).await? else {
            return Ok(None);
        };
        let to = self.ledger.new_account()?.address();
        let request = ITIP20::new(PATH_USD_ADDRESS, &self.zones[node])
            .transfer(to, U256::from(1))
            .gas(TIP20_TX_GAS)
            .into_transaction_request();
        let intent = self
            .prepare_intent(
                &sender,
                Chain::Zone,
                node,
                request,
                Effect::Transfer { to, amount: 1 },
            )
            .await?;
        Ok(Some(intent))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::Ledger;
    use alloy::primitives::Bloom;
    use serde_json::{Value, json};
    use std::time::Duration;
    use tokio::{
        io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader},
        net::TcpListener,
    };

    async fn request(listener: &TcpListener) -> (tokio::net::TcpStream, Value) {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut length = None;
        loop {
            let mut line = String::new();
            assert_ne!(reader.read_line(&mut line).await.unwrap(), 0);
            if line == "\r\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':')
                && name.eq_ignore_ascii_case("content-length")
            {
                length = Some(value.trim().parse::<usize>().unwrap());
            }
        }
        let mut body = vec![0; length.unwrap()];
        reader.read_exact(&mut body).await.unwrap();
        (reader.into_inner(), serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn cancelled_leadership_send_and_orphan_intent_block_outage_until_finality() {
        tokio::time::timeout(Duration::from_secs(10), async {
            for linked in [false, true] {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let url: alloy::transports::http::reqwest::Url = format!("http://{}", listener.local_addr().unwrap()).parse().unwrap();
                let dir = tempfile::tempdir().unwrap();
                let http = alloy::transports::http::reqwest::Client::default();
                let ctx = Context {
                    ledger: Ledger::open(dir.path()).unwrap(),
                    l1: ProviderBuilder::new().connect_reqwest(http.clone(), url.clone()).erased(),
                    l1_url: url, zone_urls: vec![], zones: vec![], http,
                    portal: Address::repeat_byte(9),
                };
                let account = Account::at(crate::ADMIN_INDEX).unwrap();
                let target = Address::repeat_byte(2);
                let mut tx = ZonePortal::new(ctx.portal, &ctx.l1).setLeader(target, 1)
                    .gas(500_000).gas_price(1).nonce(0).into_transaction_request();
                tx.chain_id = Some(123);
                let shared = ctx.ledger.episode_lock(false).await.unwrap();
                let lease = ctx.ledger.try_lease(&account).unwrap().unwrap();
                let intent = ctx.prepare_intent(&account, Chain::L1, 0, tx,
                    Effect::Leadership { target }).await.unwrap();
                if linked {
                    ctx.ledger.append(&Record::HandoffRequest(crate::handoff::Request {
                        id: 100, previous_leader: account.address(), expected_epoch: 1, target,
                        relayed: false, from_l1_block: 1, l1_tx: Some(intent.tx),
                    })).unwrap();
                }
                let sent = if linked {
                    let (_, received) = tokio::join!(
                        async {
                            assert!(tokio::time::timeout(Duration::from_millis(100), ctx.send_intent(&intent)).await.is_err());
                        },
                        async {
                            let (stream, body) = request(&listener).await;
                            assert_eq!(body["method"], "eth_sendRawTransaction");
                            assert_eq!(body["params"][0], json!(intent.raw));
                            // Keep the accepted connection alive beyond cancellation, losing its reply.
                            tokio::time::sleep(Duration::from_millis(150)).await;
                            drop(stream);
                            true
                        }
                    );
                    received
                } else { false };
                assert_eq!(sent, linked);
                drop(lease); drop(shared);
                // Process cancellation releases locks, but not the transaction's uncertainty.
                let _exclusive = ctx.ledger.episode_lock(true).await.unwrap();
                assert!(ctx.ledger.try_lease(&account).unwrap().is_none());
                assert_eq!(pending(&ctx.ledger.records().unwrap()).unwrap(), vec![intent.clone()]);
                let l1 = alloy::transports::mock::Asserter::new();
                let ctx = Context { l1: ProviderBuilder::new().connect_mocked_client(l1.clone()).erased(), ..ctx };
                let mut block = alloy::rpc::types::Block::<B256>::default();
                block.header.number = 10; block.header.hash = B256::repeat_byte(10);
                l1.push_success(&block); l1.push_success(&Value::Null);
                assert!(!ctx.handoffs_drained().await.unwrap());
                let receipt: TransactionReceipt = serde_json::from_value(json!({"type":"0x0", "status":"0x0", "cumulativeGasUsed":"0x1", "logs":[], "logsBloom":Bloom::ZERO,
                    "transactionHash":intent.tx, "transactionIndex":"0x0", "blockHash":block.header.hash,
                    "blockNumber":"0xa", "gasUsed":"0x1", "effectiveGasPrice":"0x1",
                    "from":account.address(), "to":ctx.portal, "contractAddress":null})).unwrap();
                ctx.ledger.resolve_intent(&intent, &receipt).unwrap();
                assert!(pending(&ctx.ledger.records().unwrap()).unwrap().is_empty());
                let mut old_finalized = block.clone(); old_finalized.header.number = 9;
                l1.push_success(&old_finalized); l1.push_success(&receipt);
                assert!(!ctx.handoffs_drained().await.unwrap(), "mined IntentOutcome is not finalized");
                l1.push_success(&block); l1.push_success(&receipt); l1.push_success(&block); l1.push_success(&block);
                assert!(ctx.handoffs_drained().await.unwrap());
                assert!(l1.read_q().is_empty());
            }
        }).await.unwrap();
    }

    #[tokio::test]
    async fn lost_send_response_replays_signed_bytes_at_another_node() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let original = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let alternate = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let urls: Vec<alloy::transports::http::reqwest::Url> = [
                format!("http://{}", original.local_addr().unwrap()),
                format!("http://{}", alternate.local_addr().unwrap()),
            ].iter().map(|url| url.parse().unwrap()).collect();
            let http = alloy::transports::http::reqwest::Client::builder()
                .timeout(Duration::from_millis(250)).build().unwrap();
            let connect = |url: &alloy::transports::http::reqwest::Url| {
                ProviderBuilder::new().connect_reqwest(http.clone(), url.clone()).erased()
            };
            let dir = tempfile::tempdir().unwrap();
            let ctx = Context {
                ledger: Ledger::open(dir.path()).unwrap(), l1: connect(&urls[0]),
                zones: urls.iter().map(connect).collect(), l1_url: urls[0].clone(),
                zone_urls: urls, http, portal: Address::repeat_byte(9),
            };
            let sender = ctx.ledger.new_account().unwrap();
            let lease = ctx.ledger.try_lease(&sender).unwrap().unwrap();
            let to = ctx.ledger.new_account().unwrap().address();
            let mut tx = ITIP20::new(PATH_USD_ADDRESS, &ctx.zones[0])
                .transfer(to, U256::from(5)).gas(TIP20_TX_GAS).gas_price(1).nonce(0)
                .into_transaction_request();
            tx.chain_id = Some(123);
            let intent = ctx.prepare_intent(&sender, Chain::Zone, 0, tx,
                Effect::Transfer { to, amount: 5 }).await.unwrap();
            assert_eq!(intent.tx, keccak256(&intent.raw));
            assert_eq!(pending(&ctx.ledger.records().unwrap()).unwrap(), vec![intent.clone()]);
            let lost_reply = tokio::spawn(async move {
                let (mut stream, body) = request(&original).await;
                assert_eq!(body["method"], "eth_sendRawTransaction");
                // The server has accepted the request, but its response is lost.
                stream.shutdown().await.unwrap();
                body["params"][0].clone()
            });
            assert!(ctx.send_intent(&intent).await.is_err());
            let first_bytes = lost_reply.await.unwrap();
            assert_eq!(first_bytes, json!(intent.raw));
            drop(lease);
            assert!(ctx.ledger.try_lease(&sender).unwrap().is_none());
            assert_eq!(pending(&ctx.ledger.records().unwrap()).unwrap(), vec![intent.clone()]);

            let expected = intent.clone();
            let replay = tokio::spawn(async move {
                for step in 0..3 {
                    let (mut stream, body) = request(&alternate).await;
                    let result = if step == 1 {
                        assert_eq!(body["method"], "eth_sendRawTransaction");
                        assert_eq!(body["params"][0], first_bytes);
                        json!(expected.tx)
                    } else {
                        assert_eq!(body["method"], "eth_getTransactionReceipt");
                        assert_eq!(body["params"][0], json!(expected.tx));
                        if step == 0 { Value::Null } else {
                            json!({ "type": "0x0", "status": "0x1", "cumulativeGasUsed": "0x1",
                                "logs": [], "logsBloom": Bloom::ZERO, "transactionHash": expected.tx,
                                "transactionIndex": "0x0", "blockHash": B256::repeat_byte(4),
                                "blockNumber": "0x1", "gasUsed": "0x1", "effectiveGasPrice": "0x1",
                                "from": expected.sender, "to": PATH_USD_ADDRESS, "contractAddress": null })
                        }
                    };
                    let response = json!({"jsonrpc":"2.0", "id": body["id"], "result":result}).to_string();
                    let header = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len());
                    stream.write_all(header.as_bytes()).await.unwrap();
                    stream.write_all(response.as_bytes()).await.unwrap();
                }
            });
            assert!(ctx.reconcile_intents().await.unwrap());
            replay.await.unwrap();
            // Repeating reconciliation neither sends again nor duplicates the obligation.
            assert!(ctx.reconcile_intents().await.unwrap());
            let records = ctx.ledger.records().unwrap();
            assert_eq!(records.iter().filter(|r| r.effect_hash() == Some(intent.tx)).count(), 1);
            assert!(ctx.ledger.try_lease(&sender).unwrap().is_some());
        }).await.unwrap();
    }
}
