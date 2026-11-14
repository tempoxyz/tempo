//! An admitted authentication failure must refund without blocking the next deposit.

use alloy::primitives::{Bytes, U256};
use antithesis_sdk::{assert_always, assert_reachable, assert_sometimes};
use eyre::{OptionExt as _, WrapErr as _};
use serde_json::json;
use std::{path::Path, time::Duration};
use tempo_contracts::{
    precompiles::{ITIP20, PATH_USD_ADDRESS},
    zones::DepositPayload,
};
use tokio::time::{Instant, timeout};
use zone_precompiles::ecies::EncryptedDepositArgs;

use crate::{
    Context, NEW_DEPOSITOR_FEE_BUDGET, USD,
    intents::{Chain, DepositCase, Effect},
    recovery::recover_until,
};

const EPISODE_TIMEOUT: Duration = Duration::from_secs(1200);
const OBSERVATION_TIMEOUT: Duration = Duration::from_secs(300);

impl DepositCase {
    /// Changes only the generated tag, before calldata construction and signing.
    pub(super) fn payload(self, mut encrypted: EncryptedDepositArgs) -> DepositPayload {
        if self == Self::BadTag {
            encrypted.tag[0] ^= 1;
        }
        DepositPayload {
            ephemeralPubkeyX: encrypted.eph_pub_x,
            ephemeralPubkeyYParity: encrypted.eph_pub_y_parity,
            ciphertext: Bytes::from(encrypted.ciphertext),
            nonce: encrypted.nonce.into(),
            tag: encrypted.tag.into(),
        }
    }
}

impl Context {
    /// Runs under an exclusive lock with bounded reconciliation and preserves every unknown send.
    pub(super) async fn bad_tag_deposit(&self, dir: &Path) -> eyre::Result<()> {
        let mut executed = false;
        let result = timeout(EPISODE_TIMEOUT, async {
            let _lock = self.ledger.episode_lock(true).await?;
            crate::proxy::release_network_faults(dir).await?;
            self.release_outages(dir).await?;
            eyre::ensure!(self.zones.len() == 4, "bad-tag episode requires four zone nodes");
            let drained = recover_until(Instant::now() + OBSERVATION_TIMEOUT, async || {
                let ready = self.handoffs_drained().await?;
                if !ready { self.reconcile_intents().await?; }
                Ok(ready.then_some(()))
            }).await;
            // Prior ambiguous relay traffic is not evidence of a failure in an unstarted episode.
            if drained.as_ref().is_err_and(|error|
                error.downcast_ref::<tokio::time::error::Elapsed>().is_some()) {
                println!("bad-tag-deposit: {}", json!({"result": "SKIPPED",
                    "reason": "prior handoff quiescence is unknown; no bad-tag deposit submitted"}));
                return Ok(());
            }
            drained?;
            recover_until(Instant::now() + OBSERVATION_TIMEOUT, async || {
                Ok(self.reconcile_intents().await?.then_some(()))
            }).await?;
            // Drain historical effects without forgetting relay/nonce uncertainty.
            self.check_ledger().await?;
            let baseline = self.finalized_checkpoint().await?;
            eyre::ensure!(!baseline.hash.is_zero(), "bad-tag episode needs a settled baseline");
            let (funder, _funder_lease) = self.lease_funder()?.ok_or_eyre("no free bad-tag funder")?;
            // A fresh sender isolates the refund multiset; refund events have no queue ID.
            let sender = self.ledger.new_account()?;
            let _sender_lease = self.ledger.try_lease(&sender)?.ok_or_eyre("new depositor is busy")?;
            let amount = 10 * USD;
            let successor_amount = 11 * USD;
            let funding = amount + successor_amount + NEW_DEPOSITOR_FEE_BUDGET;
            let request = ITIP20::new(PATH_USD_ADDRESS, &self.l1)
                .transfer(sender.address(), U256::from(funding)).into_transaction_request();
            let funding = self.prepare_intent(&funder, Chain::L1, 0, request,
                Effect::Funding { to: sender.address(), amount: funding }).await?;
            eyre::ensure!(self.outage_receipt(&funding).await?.status(), "bad-tag depositor funding reverted");
            self.ensure_portal_allowance(&sender).await?;
            let bad_to = self.ledger.new_account()?.address();
            let valid_to = self.ledger.new_account()?.address();
            let bad = self.prepare_deposit(&sender, bad_to, amount, DepositCase::BadTag).await?;
            executed = true;
            assert_reachable!("Bad-tag deposit: Signed failure intent is durable before broadcast", &json!({"tx": bad.tx}));
            eyre::ensure!(self.outage_receipt(&bad).await?.status(), "bad-tag outer deposit reverted; refund path not exercised");
            // Do not wait for the bad deposit's refund before admitting the valid successor.
            let valid = self.prepare_deposit(&sender, valid_to, successor_amount, DepositCase::Ordinary).await?;
            eyre::ensure!(self.outage_receipt(&valid).await?.status(), "bad-tag valid successor reverted");
            let settled = recover_until(Instant::now() + OBSERVATION_TIMEOUT, async || {
                let settled = self.finalized_checkpoint().await?;
                Ok(self.bad_tag_evidence(&bad, &valid, &baseline, &settled).await?.then_some(settled))
            }).await?;
            // Retain the independent whole-history cohort oracle and balance checks.
            self.check_ledger().await?;
            assert_reachable!("Bad-tag deposit: Finalized refund and valid successor witnessed on all four nodes",
                &json!({"bad_tx": bad.tx, "valid_tx": valid.tx, "settled": settled}));
            println!("bad-tag-deposit: {}", json!({"result": "PASSED", "bad_tx": bad.tx, "valid_tx": valid.tx, "settled": settled}));
            Ok(())
        }).await.wrap_err("bad-tag episode timed out").and_then(|result| result);
        let details = json!({"executed": executed, "error": result.as_ref().err().map(|error| format!("{error:#}"))});
        assert_sometimes!(executed, "Bad-tag deposit episode executes", &details);
        assert_always!(
            result.is_ok(),
            "Bad-tag deposit episode finishes within its deadline",
            &details
        );
        assert_sometimes!(
            executed && result.is_ok(),
            "Bad-tag deposit episode completes",
            &details
        );
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Account,
        intents::pending,
        ledger::{Ledger, Record},
    };
    use alloy::{
        consensus::{Transaction as _, TxEnvelope, transaction::SignerRecoverable as _},
        eips::eip2718::Decodable2718 as _,
        primitives::{Address, B256, keccak256},
        providers::{Provider as _, ProviderBuilder},
        sol_types::SolCall as _,
        transports::mock::Asserter,
    };
    use zone_precompiles::ecies::{compute_ecdh_proof, decrypt_deposit, encrypt_deposit};

    #[tokio::test]
    async fn tag_only_mutation_is_signed_journaled_and_survives_cancelled_send() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let account = Account::at(8).unwrap();
            let key = account.signer.credential().clone().into();
            let public = account
                .signer
                .credential()
                .verifying_key()
                .to_encoded_point(true);
            let portal = Address::repeat_byte(9);
            let to = Address::repeat_byte(3);
            let key_index = U256::from(2);
            let encrypted = encrypt_deposit(
                &B256::from_slice(&public.as_bytes()[1..]),
                public.as_bytes()[0],
                to,
                B256::ZERO,
                account.address(),
                portal,
                key_index,
            )
            .unwrap();
            let ordinary = DepositCase::Ordinary.payload(encrypted);
            assert_eq!(
                decrypt_deposit(
                    &key,
                    &ordinary.ephemeralPubkeyX,
                    ordinary.ephemeralPubkeyYParity,
                    &ordinary.ciphertext,
                    &ordinary.nonce.0,
                    &ordinary.tag.0,
                    portal,
                    key_index,
                    account.address()
                )
                .unwrap()
                .to,
                to
            );
            let bad = DepositCase::BadTag.payload(EncryptedDepositArgs {
                eph_pub_x: ordinary.ephemeralPubkeyX,
                eph_pub_y_parity: ordinary.ephemeralPubkeyYParity,
                ciphertext: ordinary.ciphertext.to_vec(),
                nonce: ordinary.nonce.0,
                tag: ordinary.tag.0,
            });
            assert_eq!(bad.ephemeralPubkeyX, ordinary.ephemeralPubkeyX);
            assert_eq!(bad.ephemeralPubkeyYParity, ordinary.ephemeralPubkeyYParity);
            assert_eq!(bad.ciphertext, ordinary.ciphertext);
            assert_eq!(bad.ciphertext.len(), 64);
            assert_eq!(bad.nonce, ordinary.nonce);
            assert_eq!(bad.tag[0] ^ ordinary.tag[0], 1);
            assert_eq!(&bad.tag[1..], &ordinary.tag[1..]);
            assert!(
                compute_ecdh_proof(&key, &bad.ephemeralPubkeyX, bad.ephemeralPubkeyYParity)
                    .is_some()
            );
            assert!(
                decrypt_deposit(
                    &key,
                    &bad.ephemeralPubkeyX,
                    bad.ephemeralPubkeyYParity,
                    &bad.ciphertext,
                    &bad.nonce.0,
                    &bad.tag.0,
                    portal,
                    key_index,
                    account.address()
                )
                .is_none()
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap())
                .parse()
                .unwrap();
            let dir = tempfile::tempdir().unwrap();
            let http = alloy::transports::http::reqwest::Client::default();
            let mock = Asserter::new();
            let ctx = Context {
                ledger: Ledger::open(dir.path()).unwrap(),
                http,
                l1_url: url,
                l1: ProviderBuilder::new().connect_mocked_client(mock).erased(),
                zone_urls: vec![],
                zones: vec![],
                portal,
            };
            let lease = ctx.ledger.try_lease(&account).unwrap().unwrap();
            let mut tx = tempo_contracts::zones::ZonePortal::new(portal, &ctx.l1)
                .deposit(
                    PATH_USD_ADDRESS,
                    10,
                    key_index,
                    bad.clone(),
                    account.address(),
                )
                .gas(crate::DEPOSIT_TX_GAS)
                .gas_price(1)
                .nonce(7)
                .into_transaction_request();
            tx.chain_id = Some(123);
            let intent = ctx
                .prepare_intent(
                    &account,
                    Chain::L1,
                    0,
                    tx,
                    Effect::Deposit {
                        to,
                        amount: 10,
                        case: DepositCase::BadTag,
                    },
                )
                .await
                .unwrap();
            assert_eq!(keccak256(&intent.raw), intent.tx);
            let mut raw = intent.raw.as_ref();
            let signed = TxEnvelope::decode_2718(&mut raw).unwrap();
            assert!(raw.is_empty());
            assert_eq!(signed.recover_signer().unwrap(), account.address());
            let call = tempo_contracts::zones::ZonePortal::depositCall::abi_decode_validate(
                signed.input(),
            )
            .unwrap();
            assert_eq!(call.encrypted.tag, bad.tag);
            assert_eq!(call.encrypted.ciphertext, ordinary.ciphertext);
            assert_eq!(call.encrypted.ephemeralPubkeyX, ordinary.ephemeralPubkeyX);
            assert_eq!(call.keyIndex, key_index);
            assert_eq!(call.tempoRefundRecipient, account.address());
            assert_eq!(call.amount, 10);
            // A server accepts the exact bytes and never returns; cancellation must retain them.
            let connected = ProviderBuilder::new()
                .connect_reqwest(ctx.http.clone(), ctx.l1_url.clone())
                .erased();
            let ctx = Context {
                l1: connected,
                ..ctx
            };
            let (cancelled, received) = tokio::join!(
                tokio::time::timeout(Duration::from_millis(100), ctx.send_intent(&intent)),
                async {
                    let (stream, request) = crate::intents::tests::request(&listener).await;
                    assert_eq!(request["method"], "eth_sendRawTransaction");
                    assert_eq!(request["params"][0], json!(intent.raw));
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    drop(stream);
                    true
                }
            );
            assert!(cancelled.is_err());
            assert!(received);
            drop(lease);
            let reloaded = Ledger::open(dir.path()).unwrap();
            assert_eq!(
                pending(&reloaded.records().unwrap()).unwrap(),
                vec![intent.clone()]
            );
            assert!(reloaded.try_lease(&account).unwrap().is_none());
            let replay = Asserter::new();
            replay.push_success(&serde_json::Value::Null);
            replay.push_failure_msg("nonce too low");
            replay.push_success(&serde_json::Value::Null);
            let ctx = Context { l1: ProviderBuilder::new().connect_mocked_client(replay.clone()).erased(), ..ctx };
            assert!(!ctx.reconcile_intents().await.unwrap());
            assert_eq!(pending(&ctx.ledger.records().unwrap()).unwrap(), vec![intent.clone()]);
            assert!(replay.read_q().is_empty());
            let made = tempo_contracts::zones::ZonePortal::DepositMade {
                newCurrentDepositQueueHash: B256::repeat_byte(42), sender: account.address(), token: PATH_USD_ADDRESS,
                netAmount: 10, fee: 0, keyIndex: key_index, ephemeralPubkeyX: bad.ephemeralPubkeyX,
                ephemeralPubkeyYParity: bad.ephemeralPubkeyYParity, ciphertext: bad.ciphertext.clone(),
                nonce: bad.nonce, tag: bad.tag, tempoRefundRecipient: account.address(), depositNumber: 1,
            };
            let log = alloy::rpc::types::Log { inner: alloy::primitives::Log { address: portal,
                data: alloy::sol_types::SolEvent::encode_log_data(&made) }, ..Default::default() };
            let receipt: alloy::rpc::types::TransactionReceipt = serde_json::from_value(json!({
                "type":"0x0", "status":"0x1", "cumulativeGasUsed":"0x1", "logs":[log],
                "logsBloom": alloy::primitives::Bloom::ZERO, "transactionHash":intent.tx,
                "transactionIndex":"0x0", "blockHash":B256::repeat_byte(4), "blockNumber":"0x1",
                "gasUsed":"0x1", "effectiveGasPrice":"0x1", "from":account.address(), "to":portal, "contractAddress":null
            })).unwrap();
            replay.push_success(&receipt);
            assert!(ctx.reconcile_intents().await.unwrap());
            ctx.ledger.resolve_intent(&intent, &receipt).unwrap();
            assert!(ctx.reconcile_intents().await.unwrap());
            let records = ctx.ledger.records().unwrap();
            assert_eq!(records.iter().filter(|record| record.effect_hash() == Some(intent.tx)).count(), 1);
            assert!(records.contains(&Record::Deposit { l1_tx: intent.tx, queue_hash: B256::repeat_byte(42),
                sender: intent.sender, to, net_amount: 10 }));
            assert!(ctx.ledger.try_lease(&account).unwrap().is_some());
            assert!(replay.read_q().is_empty());
            let serialized = serde_json::to_string(&Record::Intent(intent.clone())).unwrap();
            assert_eq!(
                serde_json::from_str::<Record>(&serialized).unwrap(),
                Record::Intent(intent.clone())
            );
            let mut old = serde_json::to_value(&intent).unwrap();
            old["effect"]["deposit"]
                .as_object_mut()
                .unwrap()
                .remove("case");
            let old: crate::intents::Intent = serde_json::from_value(old).unwrap();
            assert_eq!(
                old.effect,
                Effect::Deposit {
                    to,
                    amount: 10,
                    case: DepositCase::Ordinary
                }
            );
        })
        .await
        .unwrap();
    }
}
