//! Independent payment oracle: signed intent amounts, receipt identities, and exact multiplicities.
//!
//! This is not a reconstruction of balances from Transfer logs. Those logs are observations to
//! compare with the intent, and the older balance/log consistency check remains complementary.

use alloy::{
    consensus::{Transaction as _, TxEnvelope, transaction::SignerRecoverable as _},
    eips::eip2718::Decodable2718 as _,
    network::{AnyTransactionReceipt, ReceiptResponse as _},
    primitives::{Address, B256, U256},
    providers::Provider as _,
    rpc::types::{BlockId, Filter, Log},
    sol_types::{SolCall as _, SolEvent as _},
};
use antithesis_sdk::assert_always;
use eyre::{OptionExt as _, WrapErr as _};
use serde::Deserialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use tempo_contracts::{
    precompiles::{ITIP20, PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS},
    zones::{IZoneInbox, IZoneOutbox, ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS, ZonePortal},
};
use tempo_primitives::transaction::calc_gas_balance_spending;

use crate::{
    Context,
    checks::logs,
    intents::{Chain, DepositCase, Effect, Intent},
    ledger::Record,
};

/// Refuse an oversized observation rather than silently checking a prefix of the history.
const MAX_EFFECTS: usize = 200_000;

type Payment = (Address, Address, U256);
type TokenPayment = (Address, Payment);
type Refund = (Address, u128);

#[derive(Debug, Clone)]
struct Deposit {
    case: DepositCase,
    id: B256,
    sender: Address,
    to: Address,
    amount: u128,
}

#[derive(Debug, Clone)]
struct Withdrawal {
    tag: B256,
    nonce: u64,
    sender: Address,
    to: Address,
    amount: u128,
}

// Membership comes from every signed payment, not only successful receipts.
#[derive(Debug, Default)]
struct Cohort {
    zone: BTreeSet<Address>,
    l1: BTreeSet<Address>,
}

impl Cohort {
    fn from_intents<'a>(intents: impl IntoIterator<Item = &'a Intent>) -> Self {
        let mut cohort = Self::default();
        for intent in intents {
            match intent.effect {
                Effect::Deposit { to, .. } => {
                    cohort.l1.insert(intent.sender);
                    cohort.zone.insert(to);
                }
                Effect::Withdrawal { to, .. } => {
                    cohort.zone.insert(intent.sender);
                    cohort.l1.insert(to);
                }
                Effect::Transfer { to, .. } => {
                    cohort.zone.extend([intent.sender, to]);
                }
                Effect::Funding { to, .. } => {
                    cohort.l1.extend([intent.sender, to]);
                }
                Effect::Approval { .. } | Effect::Leadership { .. } => {}
            }
        }
        cohort
    }
}

#[derive(Debug, Default, Clone)]
struct Observed {
    // Vectors deliberately preserve repeated events, including identical ones.
    credits: BTreeMap<B256, Vec<(Address, Address, u128)>>,
    failures: BTreeMap<B256, Vec<(Address, u128)>>,
    refunds: Vec<Refund>,
    // Delivered refunds normalized by their explicit processing-time fee.
    delivered_refunds: Vec<Refund>,
    payouts: BTreeMap<B256, Vec<(Address, u128, bool)>>,
    bounces: BTreeMap<u64, Vec<u128>>,
    returns: Vec<Refund>,
    // Delivered (not pending) refunds/returns; amounts are verified against the obligations.
    refund_payments: Vec<Refund>,
    credited_returns: Vec<Refund>,
}

impl Context {
    /// Checks receipt-backed user effects after recovery, under the caller's bounded deadline.
    /// Returns None while current receipts are missing; no unknown/reverted intent creates a
    /// success obligation. Refunds without protocol IDs are
    /// checked as whole multisets for workload senders, never paired greedily to a deposit.
    pub(crate) async fn check_effects(&self) -> eyre::Result<Option<()>> {
        let result = self.observe_effects().await;
        // RPC errors are handled by the enclosing recovery deadline, not labelled corruption.
        if result.as_ref().is_err_and(crate::is_rpc_error) || matches!(&result, Ok(None)) {
            return result;
        }
        assert_always!(
            result.is_ok(),
            "Durable payment intents have exactly their confirmed user effects",
            &json!({ "error": result.as_ref().err().map(|error| format!("{error:#}")) })
        );
        result
    }

    /// Requires canonical finalized admission, queue outcomes, delivered refund and settlement.
    /// Missing evidence retries; contradictions fail, including credit of the corrupted payload.
    pub(super) async fn bad_tag_evidence(
        &self,
        bad: &Intent,
        valid: &Intent,
        baseline: &crate::recovery::FinalizedCheckpoint,
        settled: &crate::recovery::FinalizedCheckpoint,
    ) -> eyre::Result<bool> {
        eyre::ensure!(
            self.zones.len() == 4,
            "bad-tag evidence requires four zone nodes"
        );
        eyre::ensure!(
            bad.sender == valid.sender && bad.tx != valid.tx && bad.nonce < valid.nonce,
            "bad-tag successor is not distinct and later"
        );
        let cohort = Cohort::from_intents([bad, valid]);
        let mut deposits = Vec::new();
        let mut order = Vec::new();
        let mut numbers = Vec::new();
        for (intent, expected_case) in [(bad, DepositCase::BadTag), (valid, DepositCase::Ordinary)]
        {
            let Effect::Deposit { to, amount, case } = intent.effect else {
                eyre::bail!("bad-tag episode intent is not a deposit");
            };
            eyre::ensure!(
                case == expected_case && intent.chain == Chain::L1,
                "wrong bad-tag episode case"
            );
            let Some(receipt) = self.l1.get_transaction_receipt(intent.tx).await? else {
                return Ok(false);
            };
            eyre::ensure!(
                receipt.transaction_hash == intent.tx,
                "bad-tag admission receipt has wrong hash"
            );
            let height = receipt
                .block_number
                .ok_or_eyre("deposit receipt has no height")?;
            if height > settled.l1_height {
                return Ok(false);
            }
            let canonical = self
                .l1
                .get_block_by_number(height.into())
                .await?
                .ok_or_eyre("deposit admission block missing")?;
            eyre::ensure!(
                receipt.block_hash == Some(canonical.header.hash),
                "bad-tag admission is not canonical"
            );
            eyre::ensure!(receipt.status(), "bad-tag episode outer deposit reverted");
            let events: Vec<_> = receipt
                .inner
                .logs()
                .iter()
                .filter(|log| log.address() == self.portal)
                .filter_map(|log| ZonePortal::DepositMade::decode_log(&log.inner).ok())
                .collect();
            eyre::ensure!(
                events.len() == 1,
                "bad-tag admission needs exactly one DepositMade"
            );
            let made = &events[0];
            let mut raw = intent.raw.as_ref();
            let signed = TxEnvelope::decode_2718(&mut raw)?;
            eyre::ensure!(
                raw.is_empty()
                    && signed.tx_hash() == &intent.tx
                    && signed.recover_signer()? == intent.sender
                    && signed.to() == Some(self.portal),
                "bad-tag signed envelope differs from intent"
            );
            let call = ZonePortal::depositCall::abi_decode_validate(signed.input())?;
            eyre::ensure!(
                call.token == PATH_USD_ADDRESS
                    && call.amount == amount
                    && call.tempoRefundRecipient == intent.sender
                    && made.keyIndex == call.keyIndex
                    && made.ephemeralPubkeyX == call.encrypted.ephemeralPubkeyX
                    && made.ephemeralPubkeyYParity == call.encrypted.ephemeralPubkeyYParity
                    && made.ciphertext == call.encrypted.ciphertext
                    && made.nonce == call.encrypted.nonce
                    && made.tag == call.encrypted.tag,
                "bad-tag admission payload differs from signed calldata"
            );
            numbers.push(made.depositNumber);
            eyre::ensure!(
                made.sender == intent.sender
                    && made.tempoRefundRecipient == intent.sender
                    && made.token == PATH_USD_ADDRESS
                    && made.netAmount.checked_add(made.fee) == Some(amount),
                "bad-tag admission differs from intent"
            );
            deposits.push(Deposit {
                id: made.newCurrentDepositQueueHash,
                sender: intent.sender,
                to,
                amount: made.netAmount,
                case,
            });
            order.push((
                height,
                receipt
                    .transaction_index
                    .ok_or_eyre("deposit receipt has no index")?,
            ));
        }
        eyre::ensure!(
            order[0] < order[1]
                && deposits[0].id != deposits[1].id
                && deposits[0].to != deposits[1].to,
            "bad-tag valid successor is not distinct and later"
        );
        eyre::ensure!(
            numbers[0].checked_add(1) == Some(numbers[1]),
            "valid deposit is not the next queue entry"
        );
        // This episode owns a fresh sender. Do not invent attribution when its history isn't isolated.
        let records = self.ledger.records()?;
        let sender_deposits: BTreeSet<_> = records
            .iter()
            .filter_map(|record| match record {
                Record::Intent(intent)
                    if intent.sender == bad.sender
                        && matches!(intent.effect, Effect::Deposit { .. }) =>
                {
                    Some(intent.tx)
                }
                _ => None,
            })
            .collect();
        eyre::ensure!(
            sender_deposits == BTreeSet::from([bad.tx, valid.tx]),
            "bad-tag refund sender is not isolated"
        );
        let l1_logs = logs(
            &self.l1,
            Filter::new().address(self.portal),
            settled.l1_height,
        )
        .await?;
        let l1_transfers = logs(
            &self.l1,
            Filter::new().address(PATH_USD_ADDRESS),
            settled.l1_height,
        )
        .await?;
        for log in &l1_logs {
            let Ok(refund) = ZonePortal::DepositBounceBack::decode_log(&log.inner) else {
                continue;
            };
            if refund.tempoRefundRecipient != bad.sender || refund.token != PATH_USD_ADDRESS {
                continue;
            }
            let Some(receipt) = self
                .finalized_refund_receipt(log, settled.l1_height)
                .await?
            else {
                return Ok(false);
            };
            let transfers: Vec<_> = payments(receipt.logs())
                .into_iter()
                .filter(|(from, to, _)| *from == self.portal && *to == bad.sender)
                .collect();
            eyre::ensure!(
                transfers == [(self.portal, bad.sender, U256::from(refund.amount))],
                "refund receipt does not pay the isolated recipient exactly once"
            );
        }
        for zone in &self.zones {
            let zone_logs = logs(
                zone,
                Filter::new().address(ZONE_INBOX_ADDRESS),
                settled.height,
            )
            .await?;
            let observed = observe(&zone_logs, &l1_logs)?;
            if !bad_tag_ready(&deposits, &observed)? {
                return Ok(false);
            }
            check_bridge(&cohort, &deposits, &[], &observed)?;
            let transfers = logs(
                zone,
                Filter::new().address(PATH_USD_ADDRESS),
                settled.height,
            )
            .await?;
            check_token_effects(
                &cohort,
                &deposits,
                &[],
                &observed,
                self.portal,
                &payments(&transfers),
                &payments(&l1_transfers),
            )?;
            // Both outcome receipts and their event blocks must be in the common finalized prefix.
            let mut outcome_order = Vec::new();
            for (index, deposit) in deposits.iter().enumerate() {
                let event = zone_logs
                    .iter()
                    .find(|log| {
                        if index == 0 {
                            IZoneInbox::DepositFailed::decode_log(&log.inner)
                                .is_ok_and(|event| event.depositHash == deposit.id)
                        } else {
                            IZoneInbox::DepositProcessed::decode_log(&log.inner)
                                .is_ok_and(|event| event.depositHash == deposit.id)
                        }
                    })
                    .ok_or_eyre("bad-tag episode outcome missing")?;
                let proof = crate::recovery::ReceiptProof {
                    tx: event
                        .transaction_hash
                        .ok_or_eyre("deposit outcome has no tx")?,
                    height: event
                        .block_number
                        .ok_or_eyre("deposit outcome has no block")?,
                    hash: event
                        .block_hash
                        .ok_or_eyre("deposit outcome has no block hash")?,
                    success: true,
                };
                eyre::ensure!(
                    proof.height <= settled.height,
                    "deposit outcome is beyond finalized settlement"
                );
                outcome_order.push((
                    proof.height,
                    event
                        .transaction_index
                        .ok_or_eyre("deposit outcome has no tx index")?,
                    event
                        .log_index
                        .ok_or_eyre("deposit outcome has no log index")?,
                ));
                if !self
                    .check_checkpoint(baseline, settled, &proof, &[0, 1, 2, 3])
                    .await?
                {
                    return Ok(false);
                }
            }
            eyre::ensure!(
                outcome_order[0] < outcome_order[1],
                "successor processed before bad-tag deposit"
            );
        }
        Ok(true)
    }

    // Sequencer processWithdrawals uses Tempo's 0x76 envelope, not an Ethereum receipt type.
    async fn finalized_refund_receipt(
        &self,
        log: &Log,
        finalized_height: u64,
    ) -> eyre::Result<Option<AnyTransactionReceipt>> {
        let tx = log
            .transaction_hash
            .ok_or_eyre("refund has no transaction hash")?;
        let Some(receipt) = self
            .l1
            .raw_request::<_, Option<AnyTransactionReceipt>>(
                "eth_getTransactionReceipt".into(),
                [tx],
            )
            .await?
        else {
            return Ok(None);
        };
        let height = log.block_number.ok_or_eyre("refund has no block number")?;
        let block = self
            .l1
            .get_block_by_number(height.into())
            .await?
            .ok_or_eyre("refund block missing")?;
        verify_finalized_refund(log, &receipt, finalized_height, block.header.hash)?;
        Ok(Some(receipt))
    }

    async fn observe_effects(&self) -> eyre::Result<Option<()>> {
        // L1 first: every refund/payout in this snapshot has a zone predecessor by the later
        // zone snapshot. check-ledger runs after recovery, without workload writers.
        let l1_height = self.l1.get_block_number().await?;
        let zone = &self.zones[0];
        let zone_height = zone.get_block_number().await?;
        let l1_logs = logs(&self.l1, Filter::new().address(self.portal), l1_height).await?;
        let zone_logs = logs(zone, Filter::new().address(ZONE_INBOX_ADDRESS), zone_height).await?;
        let zone_transfers =
            logs(zone, Filter::new().address(PATH_USD_ADDRESS), zone_height).await?;
        let l1_transfers =
            logs(&self.l1, Filter::new().address(PATH_USD_ADDRESS), l1_height).await?;
        let records = self.ledger.records()?;
        eyre::ensure!(records.len() <= MAX_EFFECTS, "effect journal exceeds bound");
        let cohort = Cohort::from_intents(records.iter().filter_map(|record| match record {
            Record::Intent(intent) => Some(intent),
            _ => None,
        }));
        let mut incomplete = false;
        let mut seen = BTreeSet::new();
        let mut deposits = Vec::new();
        let mut withdrawals = Vec::new();
        let mut beneficiaries = BTreeMap::new();
        for record in &records {
            let Record::Intent(intent) = record else {
                continue;
            };
            if !seen.insert(intent.tx) {
                continue;
            }
            if !matches!(
                intent.effect,
                Effect::Deposit { .. } | Effect::Transfer { .. } | Effect::Withdrawal { .. }
            ) {
                continue;
            }
            let (provider, height) = match intent.chain {
                Chain::L1 => (&self.l1, l1_height),
                Chain::Zone => (zone, zone_height),
            };
            // Keep Tempo's fee token/payer fields instead of discarding them in an Ethereum receipt.
            let receipt = provider
                .raw_request::<_, Option<AnyTransactionReceipt>>(
                    "eth_getTransactionReceipt".into(),
                    [intent.tx],
                )
                .await?;
            let receipt =
                receipt.filter(|receipt| receipt.block_number.is_some_and(|block| block <= height));
            verify_receipt(intent.tx, receipt.as_ref())?;
            let Some(receipt) = receipt else {
                incomplete = true;
                continue;
            };
            let beneficiary = match intent.chain {
                Chain::L1 => TIP_FEE_MANAGER_ADDRESS,
                Chain::Zone => {
                    let block = receipt
                        .block_hash
                        .ok_or_eyre("zone receipt has no block hash")?;
                    match beneficiaries.get(&block) {
                        Some(beneficiary) => *beneficiary,
                        None => {
                            // A volatile receipt may disappear during reexecution. Read its
                            // own block for fee evidence, without declaring that hash final.
                            let Some(receipt_block) = zone.get_block_by_hash(block).await? else {
                                return Ok(None);
                            };
                            let beneficiary = receipt_block.header.beneficiary;
                            beneficiaries.insert(block, beneficiary);
                            beneficiary
                        }
                    }
                }
            };
            let (fee_payer, mut fee_payments) = receipt_fees(&receipt, intent.chain, beneficiary)?;
            let actual = token_payments(receipt.logs());
            match intent.effect {
                Effect::Deposit { to, amount, case } if receipt.status() => {
                    let made = receipt
                        .logs()
                        .iter()
                        .filter(|log| log.address() == self.portal)
                        .filter_map(|log| ZonePortal::DepositMade::decode_log(&log.inner).ok())
                        .collect::<Vec<_>>();
                    eyre::ensure!(
                        made.len() == 1,
                        "deposit receipt must contain exactly one DepositMade: {}",
                        intent.tx
                    );
                    let made = &made[0];
                    eyre::ensure!(
                        made.sender == intent.sender
                            && made.token == PATH_USD_ADDRESS
                            && made.tempoRefundRecipient == intent.sender
                            && made.netAmount.checked_add(made.fee) == Some(amount),
                        "deposit receipt differs from gross intent: {}",
                        intent.tx
                    );
                    if made.fee != 0 {
                        let admin = ZonePortal::new(self.portal, &self.l1)
                            .admin()
                            .block(BlockId::hash(
                                receipt
                                    .block_hash
                                    .ok_or_eyre("deposit receipt has no block hash")?,
                            ))
                            .call()
                            .await?;
                        fee_payments
                            .push((PATH_USD_ADDRESS, (self.portal, admin, U256::from(made.fee))));
                    }
                    check_principal(
                        intent,
                        true,
                        self.portal,
                        fee_payer,
                        0,
                        &fee_payments,
                        &actual,
                    )?;
                    deposits.push(Deposit {
                        case,
                        id: made.newCurrentDepositQueueHash,
                        sender: intent.sender,
                        to,
                        // The bridge fee is explicit receipt evidence, not inferred from a mint.
                        amount: amount
                            .checked_sub(made.fee)
                            .ok_or_eyre("deposit fee exceeds intent")?,
                    });
                }
                Effect::Transfer { .. } => {
                    check_transfer(intent, receipt.status(), &fee_payments, &actual)?;
                }
                Effect::Withdrawal { to, amount } if receipt.status() => {
                    let requested = receipt
                        .logs()
                        .iter()
                        .filter(|log| log.address() == ZONE_OUTBOX_ADDRESS)
                        .filter_map(|log| {
                            IZoneOutbox::WithdrawalRequested::decode_log(&log.inner).ok()
                        })
                        .collect::<Vec<_>>();
                    eyre::ensure!(
                        requested.len() == 1,
                        "withdrawal receipt must contain exactly one request: {}",
                        intent.tx
                    );
                    let requested = &requested[0];
                    eyre::ensure!(
                        requested.sender == intent.sender
                            && requested.token == PATH_USD_ADDRESS
                            && requested.to == to
                            && requested.amount == amount
                            && requested.fallbackNonce != 0
                            && requested.gasLimit == 0
                            && requested.data.data.is_empty(),
                        "withdrawal request differs from intent: {}",
                        intent.tx
                    );
                    check_principal(
                        intent,
                        true,
                        self.portal,
                        fee_payer,
                        requested.fee,
                        &fee_payments,
                        &actual,
                    )?;
                    withdrawals.push(Withdrawal {
                        tag: ZonePortal::Withdrawal::sender_tag(
                            intent.sender,
                            intent.tx,
                            requested.fallbackNonce,
                        ),
                        nonce: requested.fallbackNonce,
                        sender: intent.sender,
                        to,
                        amount,
                    });
                }
                Effect::Deposit { .. } | Effect::Withdrawal { .. } => {
                    check_principal(
                        intent,
                        false,
                        self.portal,
                        fee_payer,
                        0,
                        &fee_payments,
                        &actual,
                    )?;
                }
                _ => {}
            }
        }
        // A missing current receipt is not rejection or proof that its observed effects
        // are invented. Retry the complete snapshot without granting it a success obligation.
        if incomplete {
            return Ok(None);
        }
        let observed = observe(&zone_logs, &l1_logs)?;
        check_bridge(&cohort, &deposits, &withdrawals, &observed)?;
        check_token_effects(
            &cohort,
            &deposits,
            &withdrawals,
            &observed,
            self.portal,
            &payments(&zone_transfers),
            &payments(&l1_transfers),
        )?;
        Ok(Some(()))
    }
}

fn verify_finalized_refund(
    log: &Log,
    receipt: &AnyTransactionReceipt,
    finalized_height: u64,
    canonical_hash: B256,
) -> eyre::Result<()> {
    eyre::ensure!(
        !log.removed
            && log
                .block_number
                .is_some_and(|height| height <= finalized_height)
            && log.block_hash == Some(canonical_hash)
            && receipt.block_hash == log.block_hash
            && receipt.block_number == log.block_number
            && Some(receipt.transaction_hash) == log.transaction_hash
            && receipt.transaction_index == log.transaction_index
            && log.log_index.is_some()
            && receipt.status()
            && receipt
                .logs()
                .iter()
                .filter(|event| !event.removed
                    && event.inner == log.inner
                    && event.log_index == log.log_index
                    && event.transaction_hash == log.transaction_hash
                    && event.block_hash == log.block_hash
                    && event.block_number == log.block_number
                    && event.transaction_index == log.transaction_index)
                .count()
                == 1,
        "refund is not an exact canonical finalized receipt log"
    );
    Ok(())
}

// Readiness distinguishes absent asynchronous evidence from a contradictory observed outcome.
fn bad_tag_ready(deposits: &[Deposit], observed: &Observed) -> eyre::Result<bool> {
    eyre::ensure!(deposits.len() == 2, "bad-tag episode needs two deposits");
    let bad = &deposits[0];
    let valid = &deposits[1];
    eyre::ensure!(
        !observed.credits.contains_key(&bad.id),
        "bad-tag deposit was credited: {}",
        bad.id
    );
    eyre::ensure!(
        !observed.failures.contains_key(&valid.id),
        "valid successor deposit failed: {}",
        valid.id
    );
    if !observed.failures.contains_key(&bad.id) || !observed.credits.contains_key(&valid.id) {
        return Ok(false);
    }
    let delivered: Vec<_> = observed
        .delivered_refunds
        .iter()
        .copied()
        .filter(|(sender, _)| *sender == bad.sender)
        .collect();
    if delivered.is_empty() {
        return Ok(false);
    }
    eyre::ensure!(
        delivered == [(bad.sender, bad.amount)],
        "bad-tag delivered refund differs from failed intent"
    );
    Ok(true)
}

fn verify_receipt(tx: B256, receipt: Option<&AnyTransactionReceipt>) -> eyre::Result<()> {
    if let Some(receipt) = receipt {
        eyre::ensure!(
            receipt.transaction_hash == tx,
            "receipt differs from intent hash"
        );
    }
    // IntentOutcome records MINED, not finalized, execution. Reexecution after losing a
    // volatile prefix may change its block/hash/status. Only existing checkpoint proofs can
    // assert finality; missing receipts stay unknown and create no success obligation here.
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptFees {
    #[serde(default)]
    fee_token: Option<Address>,
    fee_payer: Address,
}

fn receipt_fees(
    receipt: &AnyTransactionReceipt,
    chain: Chain,
    beneficiary: Address,
) -> eyre::Result<(Address, Vec<TokenPayment>)> {
    // Tempo RPC recovers the payer from the signed transaction. The token is receipt metadata,
    // not a default inferred from the principal token (L1 and zones resolve defaults differently).
    let metadata: ReceiptFees = receipt
        .deserialize_other()
        .wrap_err("invalid or missing receipt fee metadata")?;
    let amount = calc_gas_balance_spending(receipt.gas_used, receipt.effective_gas_price);
    let token = if !amount.is_zero() {
        Some(
            metadata
                .fee_token
                .ok_or_eyre("non-free receipt has no fee token")?,
        )
    } else if chain == Chain::L1 && receipt.gas_used == 0 && receipt.effective_gas_price != 0 {
        // Zero-gas receipts omit feeToken. L1 may still emit its final zero-fee transfer; permit
        // only that exact payer/manager/zero tuple, never a positive payment from its logs.
        metadata.fee_token.or_else(|| {
            receipt.logs().last().and_then(|log| {
                let event = ITIP20::Transfer::decode_log(&log.inner).ok()?;
                (event.from == metadata.fee_payer
                    && event.to == TIP_FEE_MANAGER_ADDRESS
                    && event.amount.is_zero())
                .then_some(log.address())
            })
        })
    } else {
        // Zero-price transactions skip fee collection; zones also omit zero-spending logs.
        None
    };
    Ok((
        metadata.fee_payer,
        token
            .map(|token| (token, (metadata.fee_payer, beneficiary, amount)))
            .into_iter()
            .collect(),
    ))
}

fn token_payments(logs: &[Log]) -> Vec<TokenPayment> {
    logs.iter()
        .filter_map(|log| {
            ITIP20::Transfer::decode_log(&log.inner)
                .ok()
                .map(|event| (log.address(), (event.from, event.to, event.amount)))
        })
        .collect()
}

fn payments(logs: &[Log]) -> Vec<Payment> {
    token_payments(logs)
        .into_iter()
        .filter_map(|(token, payment)| (token == PATH_USD_ADDRESS).then_some(payment))
        .collect()
}

fn check_transfer(
    intent: &Intent,
    success: bool,
    fee_payments: &[TokenPayment],
    actual: &[TokenPayment],
) -> eyre::Result<()> {
    let Effect::Transfer { to, amount } = intent.effect else {
        eyre::bail!("not a transfer intent")
    };
    let mut expected = Vec::new();
    if success {
        expected.push((PATH_USD_ADDRESS, (intent.sender, to, U256::from(amount))));
    }
    expected.extend_from_slice(fee_payments);
    // Reverted receipts may omit the fee log; they must never retain the user transfer.
    if !success && actual.is_empty() {
        return Ok(());
    }
    eyre::ensure!(
        counts(actual) == counts(&expected),
        "transfer effects differ from intent: {}",
        intent.tx
    );
    Ok(())
}

// Compare all receipt movements, allowing only the exact gas and bridge-fee payments
// identified by receipt gas and protocol fee evidence. No arbitrary endpoint is exempt.
fn check_principal(
    intent: &Intent,
    success: bool,
    portal: Address,
    fee_payer: Address,
    bridge_fee: u128,
    fee_payments: &[TokenPayment],
    actual: &[TokenPayment],
) -> eyre::Result<()> {
    let expected = match intent.effect {
        Effect::Deposit { amount, .. } if success => {
            vec![(intent.sender, portal, U256::from(amount))]
        }
        Effect::Withdrawal { amount, .. } if success => {
            let debits = if fee_payer == intent.sender {
                vec![(
                    intent.sender,
                    amount
                        .checked_add(bridge_fee)
                        .ok_or_eyre("withdrawal principal plus fee overflow")?,
                )]
            } else {
                let mut debits = vec![(intent.sender, amount)];
                if bridge_fee != 0 {
                    debits.push((fee_payer, bridge_fee));
                }
                debits
            };
            debits
                .into_iter()
                .flat_map(|(payer, amount)| {
                    let amount = U256::from(amount);
                    [
                        (payer, ZONE_OUTBOX_ADDRESS, amount),
                        (ZONE_OUTBOX_ADDRESS, Address::ZERO, amount),
                    ]
                })
                .collect()
        }
        Effect::Deposit { .. } | Effect::Withdrawal { .. } => vec![],
        _ => eyre::bail!("not a bridge intent"),
    };
    // Reverted receipts may omit gas logs, but may never retain any principal movement.
    if !success && actual.is_empty() {
        return Ok(());
    }
    let mut expected: Vec<_> = expected
        .into_iter()
        .map(|payment| (PATH_USD_ADDRESS, payment))
        .collect();
    expected.extend_from_slice(fee_payments);
    eyre::ensure!(
        counts(actual) == counts(&expected),
        "bridge principal movements differ from intent: {}",
        intent.tx
    );
    Ok(())
}

fn observe(zone_logs: &[Log], l1_logs: &[Log]) -> eyre::Result<Observed> {
    eyre::ensure!(
        zone_logs.len() <= MAX_EFFECTS && l1_logs.len() <= MAX_EFFECTS,
        "effect logs exceed bound"
    );
    let mut observed = Observed::default();
    for log in zone_logs {
        if let Ok(event) = IZoneInbox::DepositProcessed::decode_log(&log.inner) {
            if event.token != PATH_USD_ADDRESS {
                continue;
            }
            observed
                .credits
                .entry(event.depositHash)
                .or_default()
                .push((event.sender, event.to, event.amount));
        } else if let Ok(event) = IZoneInbox::DepositFailed::decode_log(&log.inner) {
            if event.token != PATH_USD_ADDRESS {
                continue;
            }
            observed
                .failures
                .entry(event.depositHash)
                .or_default()
                .push((event.sender, event.amount));
        } else if let Ok(event) = IZoneInbox::WithdrawalBounceBackProcessed::decode_log(&log.inner)
        {
            if event.token != PATH_USD_ADDRESS {
                continue;
            }
            observed
                .returns
                .push((event.zoneFallbackRecipient, event.amount));
            observed
                .credited_returns
                .push((event.zoneFallbackRecipient, event.amount));
        } else if let Ok(event) = IZoneInbox::WithdrawalBounceBackPending::decode_log(&log.inner) {
            if event.token != PATH_USD_ADDRESS {
                continue;
            }
            observed
                .returns
                .push((event.zoneFallbackRecipient, event.amount));
        }
    }
    for log in l1_logs {
        if let Ok(event) = ZonePortal::WithdrawalProcessed::decode_log(&log.inner) {
            if event.token != PATH_USD_ADDRESS {
                continue;
            }
            observed.payouts.entry(event.senderTag).or_default().push((
                event.to,
                event.amount,
                event.callbackSuccess,
            ));
        } else if let Ok(event) = ZonePortal::WithdrawalBounceBack::decode_log(&log.inner) {
            if event.token != PATH_USD_ADDRESS {
                continue;
            }
            observed
                .bounces
                .entry(event.fallbackNonce)
                .or_default()
                .push(event.amount);
        } else if let Ok(event) = ZonePortal::DepositBounceBack::decode_log(&log.inner) {
            if event.token != PATH_USD_ADDRESS {
                continue;
            }
            observed
                .refund_payments
                .push((event.tempoRefundRecipient, event.amount));
            observed.delivered_refunds.push((
                event.tempoRefundRecipient,
                event
                    .amount
                    .checked_add(event.bouncebackFee)
                    .ok_or_eyre("deposit refund overflow")?,
            ));
            observed.refunds.push((
                event.tempoRefundRecipient,
                event
                    .amount
                    .checked_add(event.bouncebackFee)
                    .ok_or_eyre("deposit refund overflow")?,
            ));
        } else if let Ok(event) = ZonePortal::DepositBounceBackPending::decode_log(&log.inner) {
            if event.token != PATH_USD_ADDRESS {
                continue;
            }
            observed.refunds.push((
                event.tempoRefundRecipient,
                event
                    .amount
                    .checked_add(event.bouncebackFee)
                    .ok_or_eyre("pending deposit refund overflow")?,
            ));
        }
    }
    Ok(observed)
}

fn check_bridge(
    cohort: &Cohort,
    deposits: &[Deposit],
    withdrawals: &[Withdrawal],
    observed: &Observed,
) -> eyre::Result<()> {
    eyre::ensure!(
        deposits.len() <= MAX_EFFECTS && withdrawals.len() <= MAX_EFFECTS,
        "expected effects exceed bound"
    );
    let mut expected_refunds = Vec::new();
    let mut deposit_ids = BTreeSet::new();
    for deposit in deposits {
        eyre::ensure!(
            deposit_ids.insert(deposit.id),
            "two deposits share a queue identity"
        );
        let credits = observed
            .credits
            .get(&deposit.id)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let failures = observed
            .failures
            .get(&deposit.id)
            .map(Vec::as_slice)
            .unwrap_or_default();
        eyre::ensure!(
            credits.len() + failures.len() == 1,
            "deposit needs exactly one credit or failure: {}",
            deposit.id
        );
        eyre::ensure!(
            deposit.case != DepositCase::BadTag || credits.is_empty(),
            "bad-tag deposit was credited: {}",
            deposit.id
        );
        if !credits.is_empty() {
            eyre::ensure!(
                credits == [(deposit.sender, deposit.to, deposit.amount)],
                "deposit credit differs from intent: {}",
                deposit.id
            );
        } else {
            eyre::ensure!(
                failures == [(deposit.sender, deposit.amount)],
                "deposit failure differs from intent: {}",
                deposit.id
            );
            expected_refunds.push((deposit.sender, deposit.amount));
        }
    }
    // This closed workload is the sole source of portal deposits. Include the whole refund
    // cohort (including shared funders); identical payments are counted, not consumed by value.
    // The ABI cannot prove which of two identical refunds paid which failed deposit.
    eyre::ensure!(
        observed
            .credits
            .iter()
            .all(|(id, events)| deposit_ids.contains(id)
                || events.iter().all(
                    |(sender, to, _)| !cohort.l1.contains(sender) && !cohort.zone.contains(to)
                )),
        "unattributed deposit credit in workload cohort"
    );
    eyre::ensure!(
        observed
            .failures
            .iter()
            .all(|(id, events)| deposit_ids.contains(id)
                || events.iter().all(|(sender, _)| !cohort.l1.contains(sender))),
        "unattributed deposit failure in workload cohort"
    );
    let refunds: Vec<_> = observed
        .refunds
        .iter()
        .copied()
        .filter(|(sender, _)| cohort.l1.contains(sender))
        .collect();
    eyre::ensure!(
        counts(&refunds) == counts(&expected_refunds),
        "deposit refunds differ from failed intents"
    );
    let mut expected_returns = Vec::new();
    let mut tags = BTreeSet::new();
    let mut nonces = BTreeSet::new();
    for withdrawal in withdrawals {
        eyre::ensure!(
            tags.insert(withdrawal.tag) && nonces.insert(withdrawal.nonce),
            "withdrawal identity reused"
        );
        let payouts = observed
            .payouts
            .get(&withdrawal.tag)
            .map(Vec::as_slice)
            .unwrap_or_default();
        eyre::ensure!(
            payouts.len() == 1,
            "withdrawal needs exactly one delivery result: {}",
            withdrawal.tag
        );
        let (to, amount, delivered) = payouts[0];
        eyre::ensure!(
            to == withdrawal.to && amount == withdrawal.amount,
            "withdrawal payout differs from intent: {}",
            withdrawal.tag
        );
        let bounces = observed
            .bounces
            .get(&withdrawal.nonce)
            .map(Vec::as_slice)
            .unwrap_or_default();
        if delivered {
            eyre::ensure!(
                bounces.is_empty(),
                "withdrawal both paid and bounced: {}",
                withdrawal.tag
            );
        } else {
            eyre::ensure!(
                bounces == [withdrawal.amount],
                "failed withdrawal needs exactly one bounce: {}",
                withdrawal.tag
            );
            expected_returns.push((withdrawal.sender, withdrawal.amount));
        }
    }
    eyre::ensure!(
        observed
            .payouts
            .iter()
            .all(|(tag, events)| tags.contains(tag)
                || events.iter().all(|(to, _, _)| !cohort.l1.contains(to))),
        "unattributed withdrawal payout in workload cohort"
    );
    let returns: Vec<_> = observed
        .returns
        .iter()
        .copied()
        .filter(|(sender, _)| cohort.zone.contains(sender))
        .collect();
    eyre::ensure!(
        counts(&returns) == counts(&expected_returns),
        "withdrawal returns differ from bounced intents"
    );
    Ok(())
}

// Transfer observations are checked against intent-derived principal, never used to infer it.
// Whole multisets permit two legitimate equal payments; fee/admin/genesis traffic is outside
// the user cohort. Protocol IDs above independently distinguish duplicate bridge outcomes.
fn check_token_effects(
    cohort: &Cohort,
    deposits: &[Deposit],
    withdrawals: &[Withdrawal],
    observed: &Observed,
    portal: Address,
    zone_payments: &[Payment],
    l1_payments: &[Payment],
) -> eyre::Result<()> {
    let mut expected_mints = Vec::new();
    let mut expected_payments = Vec::new();
    for deposit in deposits {
        if observed.credits.contains_key(&deposit.id) {
            expected_mints.push((Address::ZERO, deposit.to, U256::from(deposit.amount)));
        }
    }
    expected_mints.extend(
        observed
            .credited_returns
            .iter()
            .filter(|(to, _)| cohort.zone.contains(to))
            .map(|(to, amount)| (Address::ZERO, *to, U256::from(*amount))),
    );
    for withdrawal in withdrawals {
        if observed
            .payouts
            .get(&withdrawal.tag)
            .is_some_and(|events| events.as_slice() == [(withdrawal.to, withdrawal.amount, true)])
        {
            expected_payments.push((portal, withdrawal.to, U256::from(withdrawal.amount)));
        }
    }
    expected_payments.extend(
        observed
            .refund_payments
            .iter()
            .filter(|(to, _)| cohort.l1.contains(to))
            .map(|(to, amount)| (portal, *to, U256::from(*amount))),
    );
    let actual_mints: Vec<_> = zone_payments
        .iter()
        .copied()
        .filter(|(from, to, _)| from.is_zero() && cohort.zone.contains(to))
        .collect();
    let actual_payments: Vec<_> = l1_payments
        .iter()
        .copied()
        .filter(|(from, to, _)| *from == portal && cohort.l1.contains(to))
        .collect();
    eyre::ensure!(
        counts(&actual_mints) == counts(&expected_mints),
        "mint transfers differ from intended credits"
    );
    eyre::ensure!(
        counts(&actual_payments) == counts(&expected_payments),
        "portal transfers differ from intended payouts and refunds"
    );
    Ok(())
}

fn counts<T: Ord + Clone>(values: &[T]) -> BTreeMap<T, usize> {
    let mut counts = BTreeMap::new();
    for value in values {
        *counts.entry(value.clone()).or_default() += 1;
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::Ledger;
    use alloy::{
        consensus::{Receipt, ReceiptEnvelope, ReceiptWithBloom},
        primitives::{Bloom, Bytes},
        providers::ProviderBuilder,
        rpc::types::{Block, TransactionReceipt},
        transports::mock::Asserter,
    };

    fn path_payments(payments: &[Payment]) -> Vec<TokenPayment> {
        payments
            .iter()
            .copied()
            .map(|payment| (PATH_USD_ADDRESS, payment))
            .collect()
    }

    fn cohort() -> Cohort {
        let mut deposit = intent();
        deposit.effect = Effect::Deposit {
            case: DepositCase::Ordinary,
            to: Address::repeat_byte(3),
            amount: 10,
        };
        let mut withdrawal = intent();
        withdrawal.effect = Effect::Withdrawal {
            to: Address::repeat_byte(3),
            amount: 10,
        };
        Cohort::from_intents([&deposit, &withdrawal])
    }

    fn deposit() -> Deposit {
        Deposit {
            case: DepositCase::Ordinary,
            id: B256::repeat_byte(1),
            sender: Address::repeat_byte(2),
            to: Address::repeat_byte(3),
            amount: 10,
        }
    }

    fn withdrawal() -> Withdrawal {
        Withdrawal {
            tag: B256::repeat_byte(4),
            nonce: 1,
            sender: Address::repeat_byte(2),
            to: Address::repeat_byte(3),
            amount: 10,
        }
    }

    fn intent() -> Intent {
        Intent {
            tx: B256::repeat_byte(5),
            raw: Bytes::new(),
            chain: Chain::Zone,
            chain_id: 1,
            sender: Address::repeat_byte(2),
            nonce: 0,
            node: 0,
            effect: Effect::Transfer {
                to: Address::repeat_byte(3),
                amount: 10,
            },
        }
    }

    fn fee_receipt(
        gas_used: u64,
        gas_price: u128,
        token: Option<Address>,
        payer: Address,
        logs: Vec<Log>,
    ) -> AnyTransactionReceipt {
        let receipt = TransactionReceipt {
            inner: ReceiptEnvelope::Eip1559(ReceiptWithBloom::new(
                Receipt {
                    status: true.into(),
                    cumulative_gas_used: gas_used,
                    logs,
                },
                Bloom::ZERO,
            )),
            transaction_hash: intent().tx,
            transaction_index: Some(0),
            block_hash: Some(B256::repeat_byte(23)),
            block_number: Some(1),
            gas_used,
            effective_gas_price: gas_price,
            blob_gas_used: None,
            blob_gas_price: None,
            from: intent().sender,
            to: Some(Address::repeat_byte(8)),
            contract_address: None,
        };
        let mut receipt = serde_json::to_value(receipt).unwrap();
        receipt["feePayer"] = json!(payer);
        if let Some(token) = token {
            receipt["feeToken"] = json!(token);
        }
        serde_json::from_value(receipt).unwrap()
    }

    #[tokio::test]
    async fn captured_l1_deposit_receipt_checks_beta_usd_fee_and_path_usd_principal() {
        // Local asymmetric-handoff receipt: 1e9 pathUSD deposit, 354 betaUSD gas.
        let mut receipt: AnyTransactionReceipt = serde_json::from_str(r#"{"status":"0x1","cumulativeGasUsed":"0x8fa32","logs":[{"address":"0x20c0000000000000000000000000000000000000","topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef","0x00000000000000000000000023618e81e3f5cdf7f54c3d65f7fbc0abf5b21e8f","0x0000000000000000000000005ad0000000000000000000000000000000000001"],"data":"0x000000000000000000000000000000000000000000000000000000003b9aca00","blockHash":"0x33125618268d693dc0c70177b3ebf38f8df919a68b43927d24986d05a94612c4","blockNumber":"0x30","blockTimestamp":"0x6af730b8","transactionHash":"0x5548476c49682c548dae49dca48889533d9ffc020d56222235a4e6562fd0937c","transactionIndex":"0x0","logIndex":"0x0","removed":false},{"address":"0x5ad0000000000000000000000000000000000001","topics":["0x51046223e5e0abca942f13a8f3d1c8dfd59c8b6c4f3e64fc2f5bf453767a97ca","0xc01c7cf274e3f3c13c42478a6b5a519c4144e27cfef43d78c9a7861291198036","0x00000000000000000000000023618e81e3f5cdf7f54c3d65f7fbc0abf5b21e8f"],"data":"0x00000000000000000000000020c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003b9aca0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b80632aae2b206b93eafa6a39b62689a5e25d3f448840107dba7d2c41553046a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000160377717facc8792e619273d3300000000000000000000000000000000000000000e950f909a976406b977b7312689e8140000000000000000000000000000000000000000000000000000000023618e81e3f5cdf7f54c3d65f7fbc0abf5b21e8f00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000040305588951033c56afd12ed783c3873ad22dfd337ab899c713c03c68a3f4e562cf47c9e0b9d9ccbadb6a8cbc0fad38bdf1a8930ebdec2a82cb52f24d5015ed4da","blockHash":"0x33125618268d693dc0c70177b3ebf38f8df919a68b43927d24986d05a94612c4","blockNumber":"0x30","blockTimestamp":"0x6af730b8","transactionHash":"0x5548476c49682c548dae49dca48889533d9ffc020d56222235a4e6562fd0937c","transactionIndex":"0x0","logIndex":"0x1","removed":false},{"address":"0x20c0000000000000000000000000000000000001","topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef","0x00000000000000000000000023618e81e3f5cdf7f54c3d65f7fbc0abf5b21e8f","0x000000000000000000000000feec000000000000000000000000000000000000"],"data":"0x0000000000000000000000000000000000000000000000000000000000000162","blockHash":"0x33125618268d693dc0c70177b3ebf38f8df919a68b43927d24986d05a94612c4","blockNumber":"0x30","blockTimestamp":"0x6af730b8","transactionHash":"0x5548476c49682c548dae49dca48889533d9ffc020d56222235a4e6562fd0937c","transactionIndex":"0x0","logIndex":"0x2","removed":false}],"logsBloom":"0x00800000000000000000000000000000000000000000000000000000000001000000000000000000000000000100000000000200000000000000000000000000000004000000000000000008000000000008000000000000000000000400000000000000000000000000000000000000000000000000000000080010000000000000000000000000000000020020000000000000901000000040010000000000000020000000000000000000000000000000000000000000000200000010000000000002000010000400000000000000000000000000000000000000040000000080000000000000001000000000000000000000000000000000008000000000","type":"0x2","transactionHash":"0x5548476c49682c548dae49dca48889533d9ffc020d56222235a4e6562fd0937c","transactionIndex":"0x0","blockHash":"0x33125618268d693dc0c70177b3ebf38f8df919a68b43927d24986d05a94612c4","blockNumber":"0x30","gasUsed":"0x8fa32","effectiveGasPrice":"0x23c34601","from":"0x23618e81e3f5cdf7f54c3d65f7fbc0abf5b21e8f","to":"0x5ad0000000000000000000000000000000000001","contractAddress":null,"feePayer":"0x23618e81e3f5cdf7f54c3d65f7fbc0abf5b21e8f","feeToken":"0x20c0000000000000000000000000000000000001"}"#).unwrap();
        let portal = receipt.to.unwrap();
        let sender = receipt.from;
        let beta: Address = "0x20c0000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let (payer, fees) = receipt_fees(&receipt, Chain::L1, TIP_FEE_MANAGER_ADDRESS).unwrap();
        assert_eq!(payer, sender);
        assert_eq!(
            fees,
            [(beta, (sender, TIP_FEE_MANAGER_ADDRESS, U256::from(354)))]
        );
        let mut intent = intent();
        intent.tx = alloy::primitives::keccak256(&intent.raw);
        intent.sender = sender;
        intent.chain = Chain::L1;
        let recipient = Address::repeat_byte(3);
        intent.effect = Effect::Deposit {
            case: DepositCase::Ordinary,
            to: recipient,
            amount: 1_000_000_000,
        };
        // Only the identity changes to match the synthetic journal's signed-byte fixture.
        receipt.transaction_hash = intent.tx;
        let actual = token_payments(receipt.logs());
        check_principal(&intent, true, portal, payer, 0, &fees, &actual).unwrap();
        let made = receipt
            .logs()
            .iter()
            .find_map(|log| ZonePortal::DepositMade::decode_log(&log.inner).ok())
            .unwrap();
        let credit = event_log(
            IZoneInbox::DepositProcessed {
                depositHash: made.newCurrentDepositQueueHash,
                sender,
                to: recipient,
                token: PATH_USD_ADDRESS,
                amount: 1_000_000_000,
                memo: B256::ZERO,
            },
            ZONE_INBOX_ADDRESS,
        );
        let mint = event_log(
            ITIP20::Transfer {
                from: Address::ZERO,
                to: recipient,
                amount: U256::from(1_000_000_000),
            },
            PATH_USD_ADDRESS,
        );
        let l1 = Asserter::new();
        let zone = Asserter::new();
        l1.push_success(&"0x30");
        l1.push_success(
            &receipt
                .logs()
                .iter()
                .filter(|log| log.address() == portal)
                .collect::<Vec<_>>(),
        );
        l1.push_success(
            &receipt
                .logs()
                .iter()
                .filter(|log| log.address() == PATH_USD_ADDRESS)
                .collect::<Vec<_>>(),
        );
        l1.push_success(&receipt);
        zone.push_success(&"0x1");
        zone.push_success(&vec![credit]);
        zone.push_success(&vec![mint]);
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::open(dir.path()).unwrap();
        ledger.append(&Record::Intent(intent)).unwrap();
        let ctx = Context {
            ledger,
            http: Default::default(),
            l1_url: "http://l1.invalid".parse().unwrap(),
            l1: ProviderBuilder::new().connect_mocked_client(l1).erased(),
            zone_urls: vec!["http://zone.invalid".parse().unwrap()],
            zones: vec![ProviderBuilder::new().connect_mocked_client(zone).erased()],
            portal,
        };
        assert_eq!(ctx.observe_effects().await.unwrap(), Some(()));
    }

    #[test]
    fn receipt_fee_tokens_and_sponsors_preserve_all_principal_and_gas_movements() {
        let portal = Address::repeat_byte(8);
        let beta = Address::with_last_byte(1);
        let recipient = Address::repeat_byte(3);
        for kind in ["deposit", "transfer", "withdrawal"] {
            for token in [PATH_USD_ADDRESS, beta] {
                for sponsored in [false, true] {
                    for bridge_fee in [0, 3] {
                        let mut intent = intent();
                        intent.chain = if kind == "deposit" {
                            Chain::L1
                        } else {
                            Chain::Zone
                        };
                        intent.effect = match kind {
                            "deposit" => Effect::Deposit {
                                case: DepositCase::Ordinary,
                                to: recipient,
                                amount: 10,
                            },
                            "transfer" => Effect::Transfer {
                                to: recipient,
                                amount: 10,
                            },
                            _ => Effect::Withdrawal {
                                to: recipient,
                                amount: 10,
                            },
                        };
                        let payer = if sponsored {
                            Address::repeat_byte(7)
                        } else {
                            intent.sender
                        };
                        let beneficiary = if intent.chain == Chain::L1 {
                            TIP_FEE_MANAGER_ADDRESS
                        } else {
                            Address::repeat_byte(9)
                        };
                        // One unit beyond an integral fee must round up, never truncate.
                        let receipt = fee_receipt(1, 1_000_000_000_001, Some(token), payer, vec![]);
                        let (actual_payer, mut fees) =
                            receipt_fees(&receipt, intent.chain, beneficiary).unwrap();
                        assert_eq!(actual_payer, payer);
                        let gas = (token, (payer, beneficiary, U256::from(2)));
                        assert_eq!(fees, [gas]);
                        let principal = match kind {
                            "deposit" => {
                                if bridge_fee != 0 {
                                    fees.push((
                                        PATH_USD_ADDRESS,
                                        (portal, Address::repeat_byte(10), U256::from(bridge_fee)),
                                    ));
                                }
                                vec![(intent.sender, portal, U256::from(10))]
                            }
                            "transfer" => vec![(intent.sender, recipient, U256::from(10))],
                            _ if sponsored => {
                                let mut movements = vec![
                                    (intent.sender, ZONE_OUTBOX_ADDRESS, U256::from(10)),
                                    (ZONE_OUTBOX_ADDRESS, Address::ZERO, U256::from(10)),
                                ];
                                if bridge_fee != 0 {
                                    movements.extend([
                                        (payer, ZONE_OUTBOX_ADDRESS, U256::from(3)),
                                        (ZONE_OUTBOX_ADDRESS, Address::ZERO, U256::from(3)),
                                    ]);
                                }
                                movements
                            }
                            _ => vec![
                                (
                                    intent.sender,
                                    ZONE_OUTBOX_ADDRESS,
                                    U256::from(10 + bridge_fee),
                                ),
                                (
                                    ZONE_OUTBOX_ADDRESS,
                                    Address::ZERO,
                                    U256::from(10 + bridge_fee),
                                ),
                            ],
                        };
                        for success in [false, true] {
                            let fees = if success { fees.clone() } else { vec![gas] };
                            let mut good = if success {
                                path_payments(&principal)
                            } else {
                                vec![]
                            };
                            good.extend_from_slice(&fees);
                            let check = |actual: &[TokenPayment]| {
                                if kind == "transfer" {
                                    check_transfer(&intent, success, &fees, actual)
                                } else {
                                    check_principal(
                                        &intent, success, portal, payer, bridge_fee, &fees, actual,
                                    )
                                }
                            };
                            check(&good).unwrap();
                            let error = format!(
                                "{}: {}",
                                if kind == "transfer" {
                                    "transfer effects differ from intent"
                                } else {
                                    "bridge principal movements differ from intent"
                                },
                                intent.tx
                            );
                            // Exact multiplicities include both tokens, the sponsor's debit, and burns.
                            for index in 0..good.len() {
                                for mutation in 0..6 {
                                    let mut bad = good.clone();
                                    match mutation {
                                        0 => {
                                            bad.remove(index);
                                        }
                                        1 => bad.push(good[index]),
                                        2 => bad[index].1.2 += U256::from(1),
                                        3 => bad[index].0 = Address::repeat_byte(19),
                                        4 => bad[index].1.0 = Address::repeat_byte(19),
                                        _ => bad[index].1.1 = Address::repeat_byte(19),
                                    }
                                    // Preserve the existing allowance for completely logless reverts.
                                    if !success && bad.is_empty() {
                                        continue;
                                    }
                                    assert_eq!(check(&bad).unwrap_err().to_string(), error);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn fee_metadata_is_required_without_a_principal_token_fallback() {
        let payer = intent().sender;
        let beneficiary = Address::repeat_byte(9);
        let mut receipt = fee_receipt(1, 1, None, payer, vec![]);
        for chain in [Chain::L1, Chain::Zone] {
            assert_eq!(
                receipt_fees(&receipt, chain, beneficiary)
                    .unwrap_err()
                    .to_string(),
                "non-free receipt has no fee token"
            );
        }
        receipt.other_fields_mut().remove("feePayer");
        assert_eq!(
            receipt_fees(&receipt, Chain::Zone, beneficiary)
                .unwrap_err()
                .to_string(),
            "invalid or missing receipt fee metadata"
        );
        receipt
            .other_fields_mut()
            .insert("feePayer".into(), json!(payer));
        receipt
            .other_fields_mut()
            .insert("feeToken".into(), json!("invalid address"));
        assert_eq!(
            receipt_fees(&receipt, Chain::Zone, beneficiary)
                .unwrap_err()
                .to_string(),
            "invalid or missing receipt fee metadata"
        );
    }

    #[test]
    fn free_receipts_do_not_exempt_principal_or_invent_gas_transfers() {
        let intent = intent();
        let beneficiary = TIP_FEE_MANAGER_ADDRESS;
        let zero = event_log(
            ITIP20::Transfer {
                from: intent.sender,
                to: beneficiary,
                amount: U256::ZERO,
            },
            PATH_USD_ADDRESS,
        );
        for chain in [Chain::L1, Chain::Zone] {
            let receipt = fee_receipt(21_000, 0, None, intent.sender, vec![zero.clone()]);
            let (payer, fees) = receipt_fees(&receipt, chain, beneficiary).unwrap();
            assert_eq!(payer, intent.sender);
            assert!(fees.is_empty());
            let principal =
                path_payments(&[(intent.sender, Address::repeat_byte(3), U256::from(10))]);
            check_transfer(&intent, true, &fees, &principal).unwrap();
            let mut extra = principal;
            extra.extend(token_payments(receipt.logs()));
            assert_eq!(
                check_transfer(&intent, true, &fees, &extra)
                    .unwrap_err()
                    .to_string(),
                format!("transfer effects differ from intent: {}", intent.tx)
            );
        }
        // Only L1's positive-price, zero-gas case may produce a final zero-fee log.
        let receipt = fee_receipt(0, 1, None, intent.sender, vec![zero]);
        assert_eq!(
            receipt_fees(&receipt, Chain::L1, beneficiary).unwrap().1,
            path_payments(&[(intent.sender, beneficiary, U256::ZERO)])
        );
        assert!(
            receipt_fees(&receipt, Chain::Zone, beneficiary)
                .unwrap()
                .1
                .is_empty()
        );
        for (from, to, amount) in [
            (Address::repeat_byte(4), beneficiary, U256::ZERO),
            (intent.sender, Address::repeat_byte(4), U256::ZERO),
            (intent.sender, beneficiary, U256::from(1)),
        ] {
            let receipt = fee_receipt(
                0,
                1,
                None,
                intent.sender,
                vec![event_log(
                    ITIP20::Transfer { from, to, amount },
                    PATH_USD_ADDRESS,
                )],
            );
            assert!(
                receipt_fees(&receipt, Chain::L1, beneficiary)
                    .unwrap()
                    .1
                    .is_empty()
            );
        }
    }

    #[test]
    fn deposit_credit_mutations_and_refund_exclusivity() {
        let deposit = deposit();
        let mut good = Observed::default();
        good.credits.insert(
            deposit.id,
            vec![(deposit.sender, deposit.to, deposit.amount)],
        );
        check_bridge(&cohort(), std::slice::from_ref(&deposit), &[], &good).unwrap();
        for mutation in 0..5 {
            let mut bad = good.clone();
            match mutation {
                0 => bad.credits.get_mut(&deposit.id).unwrap().clear(),
                1 => bad.credits.get_mut(&deposit.id).unwrap().push((
                    deposit.sender,
                    deposit.to,
                    deposit.amount,
                )),
                2 => bad.credits.get_mut(&deposit.id).unwrap()[0].2 += 1,
                3 => {
                    bad.failures
                        .insert(deposit.id, vec![(deposit.sender, deposit.amount)]);
                }
                _ => bad.refunds.push((deposit.sender, deposit.amount)),
            }
            let error = check_bridge(&cohort(), std::slice::from_ref(&deposit), &[], &bad)
                .unwrap_err()
                .to_string();
            assert_eq!(
                error,
                match mutation {
                    0 | 1 | 3 => format!(
                        "deposit needs exactly one credit or failure: {}",
                        deposit.id
                    ),
                    2 => format!("deposit credit differs from intent: {}", deposit.id),
                    _ => "deposit refunds differ from failed intents".into(),
                }
            );
        }
    }

    #[test]
    fn bounced_deposit_refunds_are_an_exact_multiset() {
        let deposit = deposit();
        let mut observed = Observed::default();
        observed
            .failures
            .insert(deposit.id, vec![(deposit.sender, deposit.amount)]);
        for refunds in [
            vec![],
            vec![(deposit.sender, 11)],
            vec![(deposit.sender, 10); 2],
        ] {
            observed.refunds = refunds;
            assert_eq!(
                check_bridge(&cohort(), std::slice::from_ref(&deposit), &[], &observed)
                    .unwrap_err()
                    .to_string(),
                "deposit refunds differ from failed intents"
            );
        }
        observed.refunds = vec![(deposit.sender, 10)];
        check_bridge(&cohort(), &[deposit], &[], &observed).unwrap();
    }

    #[test]
    fn transfer_mutations_preserve_fee_and_intent_independence() {
        let intent = intent();
        let beneficiary = Address::repeat_byte(9);
        let payment = (intent.sender, Address::repeat_byte(3), U256::from(10));
        let fee = (intent.sender, beneficiary, U256::from(2));
        check_transfer(
            &intent,
            true,
            &path_payments(&[fee]),
            &path_payments(&[payment, fee]),
        )
        .unwrap();
        for actual in [
            vec![fee],
            vec![payment, payment, fee],
            vec![(payment.0, payment.1, U256::from(11)), fee],
        ] {
            assert_eq!(
                check_transfer(
                    &intent,
                    true,
                    &path_payments(&[fee]),
                    &path_payments(&actual)
                )
                .unwrap_err()
                .to_string(),
                format!("transfer effects differ from intent: {}", intent.tx)
            );
        }
        // A transfer to the beneficiary can equal its fee: multiplicity still distinguishes it.
        let mut collision = intent.clone();
        collision.effect = Effect::Transfer {
            to: beneficiary,
            amount: 2,
        };
        check_transfer(
            &collision,
            true,
            &path_payments(&[fee]),
            &path_payments(&[fee, fee]),
        )
        .unwrap();
        assert_eq!(
            check_transfer(
                &collision,
                true,
                &path_payments(&[fee]),
                &path_payments(&[fee])
            )
            .unwrap_err()
            .to_string(),
            format!("transfer effects differ from intent: {}", intent.tx)
        );
        check_transfer(&intent, false, &path_payments(&[fee]), &path_payments(&[])).unwrap();
        check_transfer(
            &intent,
            false,
            &path_payments(&[fee]),
            &path_payments(&[fee]),
        )
        .unwrap();
        assert_eq!(
            check_transfer(
                &intent,
                false,
                &path_payments(&[fee]),
                &path_payments(&[payment, fee])
            )
            .unwrap_err()
            .to_string(),
            format!("transfer effects differ from intent: {}", intent.tx)
        );
    }

    #[test]
    fn withdrawal_payout_mutations_use_identity_not_recipient_amount() {
        let withdrawal = withdrawal();
        let mut good = Observed::default();
        good.payouts.insert(
            withdrawal.tag,
            vec![(withdrawal.to, withdrawal.amount, true)],
        );
        check_bridge(&cohort(), &[], std::slice::from_ref(&withdrawal), &good).unwrap();
        for mutation in 0..3 {
            let mut bad = good.clone();
            match mutation {
                0 => bad.payouts.get_mut(&withdrawal.tag).unwrap().clear(),
                1 => bad.payouts.get_mut(&withdrawal.tag).unwrap().push((
                    withdrawal.to,
                    withdrawal.amount,
                    true,
                )),
                _ => bad.payouts.get_mut(&withdrawal.tag).unwrap()[0].1 += 1,
            }
            assert_eq!(
                check_bridge(&cohort(), &[], std::slice::from_ref(&withdrawal), &bad)
                    .unwrap_err()
                    .to_string(),
                match mutation {
                    0 | 1 => format!(
                        "withdrawal needs exactly one delivery result: {}",
                        withdrawal.tag
                    ),
                    _ => format!("withdrawal payout differs from intent: {}", withdrawal.tag),
                }
            );
        }
    }

    #[test]
    fn withdrawal_failure_requires_bounce_and_return_not_a_payout() {
        let withdrawal = withdrawal();
        let mut observed = Observed::default();
        observed.payouts.insert(
            withdrawal.tag,
            vec![(withdrawal.to, withdrawal.amount, false)],
        );
        assert_eq!(
            check_bridge(&cohort(), &[], std::slice::from_ref(&withdrawal), &observed)
                .unwrap_err()
                .to_string(),
            format!(
                "failed withdrawal needs exactly one bounce: {}",
                withdrawal.tag
            )
        );
        observed
            .bounces
            .insert(withdrawal.nonce, vec![withdrawal.amount]);
        assert_eq!(
            check_bridge(&cohort(), &[], std::slice::from_ref(&withdrawal), &observed)
                .unwrap_err()
                .to_string(),
            "withdrawal returns differ from bounced intents"
        );
        observed
            .returns
            .push((withdrawal.sender, withdrawal.amount));
        check_bridge(&cohort(), &[], std::slice::from_ref(&withdrawal), &observed).unwrap();
        observed.payouts.get_mut(&withdrawal.tag).unwrap()[0].2 = true;
        assert_eq!(
            check_bridge(&cohort(), &[], std::slice::from_ref(&withdrawal), &observed)
                .unwrap_err()
                .to_string(),
            format!("withdrawal both paid and bounced: {}", withdrawal.tag)
        );
    }

    #[test]
    fn unknown_is_not_rejected_or_required_to_succeed() {
        verify_receipt(B256::ZERO, None).unwrap();
        check_bridge(&cohort(), &[], &[], &Observed::default()).unwrap();
    }

    #[test]
    fn token_movements_must_match_intents_not_just_bridge_events() {
        let deposit = deposit();
        let withdrawal = withdrawal();
        let portal = Address::repeat_byte(8);
        let mut observed = Observed::default();
        observed.credits.insert(
            deposit.id,
            vec![(deposit.sender, deposit.to, deposit.amount)],
        );
        observed.payouts.insert(
            withdrawal.tag,
            vec![(withdrawal.to, withdrawal.amount, true)],
        );
        let mint = (Address::ZERO, deposit.to, U256::from(deposit.amount));
        let payout = (portal, withdrawal.to, U256::from(withdrawal.amount));
        check_token_effects(
            &cohort(),
            std::slice::from_ref(&deposit),
            std::slice::from_ref(&withdrawal),
            &observed,
            portal,
            &[mint],
            &[payout],
        )
        .unwrap();
        for mints in [
            vec![],
            vec![mint, mint],
            vec![(mint.0, mint.1, U256::from(11))],
        ] {
            assert_eq!(
                check_token_effects(
                    &cohort(),
                    std::slice::from_ref(&deposit),
                    std::slice::from_ref(&withdrawal),
                    &observed,
                    portal,
                    &mints,
                    &[payout]
                )
                .unwrap_err()
                .to_string(),
                "mint transfers differ from intended credits"
            );
        }
        for payouts in [
            vec![],
            vec![payout, payout],
            vec![(payout.0, payout.1, U256::from(11))],
        ] {
            assert_eq!(
                check_token_effects(
                    &cohort(),
                    std::slice::from_ref(&deposit),
                    std::slice::from_ref(&withdrawal),
                    &observed,
                    portal,
                    &[mint],
                    &payouts
                )
                .unwrap_err()
                .to_string(),
                "portal transfers differ from intended payouts and refunds"
            );
        }
        // An event cannot authorize its own invented payment identity.
        let mut second = withdrawal.clone();
        second.tag = B256::repeat_byte(9);
        second.nonce = 2;
        observed
            .payouts
            .insert(second.tag, vec![(withdrawal.to, withdrawal.amount, true)]);
        assert_eq!(
            check_bridge(
                &cohort(),
                std::slice::from_ref(&deposit),
                std::slice::from_ref(&withdrawal),
                &observed
            )
            .unwrap_err()
            .to_string(),
            "unattributed withdrawal payout in workload cohort"
        );
        assert_eq!(
            check_token_effects(
                &cohort(),
                std::slice::from_ref(&deposit),
                std::slice::from_ref(&withdrawal),
                &observed,
                portal,
                &[mint],
                &[payout, payout]
            )
            .unwrap_err()
            .to_string(),
            "portal transfers differ from intended payouts and refunds"
        );
        // Equal payments are legitimate only with two independently attributed intents.
        check_bridge(
            &cohort(),
            std::slice::from_ref(&deposit),
            &[withdrawal.clone(), second.clone()],
            &observed,
        )
        .unwrap();
        check_token_effects(
            &cohort(),
            std::slice::from_ref(&deposit),
            &[withdrawal.clone(), second],
            &observed,
            portal,
            &[mint],
            &[payout, payout],
        )
        .unwrap();
        observed.credits.insert(
            B256::repeat_byte(10),
            vec![(deposit.sender, deposit.to, deposit.amount)],
        );
        assert_eq!(
            check_bridge(&cohort(), std::slice::from_ref(&deposit), &[], &observed)
                .unwrap_err()
                .to_string(),
            "unattributed deposit credit in workload cohort"
        );
        assert_eq!(
            check_token_effects(
                &cohort(),
                &[deposit],
                &[withdrawal],
                &observed,
                portal,
                &[mint, mint],
                &[payout]
            )
            .unwrap_err()
            .to_string(),
            "mint transfers differ from intended credits"
        );
    }

    fn event_log<T: alloy::sol_types::SolEvent>(event: T, address: Address) -> Log {
        Log {
            inner: alloy::primitives::Log {
                address,
                data: event.encode_log_data(),
            },
            ..Default::default()
        }
    }

    #[test]
    fn decoding_preserves_duplicate_credits_and_fee_adjusted_refunds() {
        let deposit = deposit();
        let credit = event_log(
            IZoneInbox::DepositProcessed {
                depositHash: deposit.id,
                sender: deposit.sender,
                to: deposit.to,
                token: PATH_USD_ADDRESS,
                amount: deposit.amount,
                memo: B256::ZERO,
            },
            ZONE_INBOX_ADDRESS,
        );
        let doubled = observe(&[credit.clone(), credit], &[]).unwrap();
        assert_eq!(doubled.credits[&deposit.id].len(), 2);
        assert_eq!(
            check_bridge(&cohort(), std::slice::from_ref(&deposit), &[], &doubled)
                .unwrap_err()
                .to_string(),
            format!(
                "deposit needs exactly one credit or failure: {}",
                deposit.id
            )
        );
        let failed = event_log(
            IZoneInbox::DepositFailed {
                depositHash: deposit.id,
                sender: deposit.sender,
                token: PATH_USD_ADDRESS,
                amount: deposit.amount,
            },
            ZONE_INBOX_ADDRESS,
        );
        let portal = Address::repeat_byte(8);
        for pending in [false, true] {
            let refund = if pending {
                event_log(
                    ZonePortal::DepositBounceBackPending {
                        tempoRefundRecipient: deposit.sender,
                        token: PATH_USD_ADDRESS,
                        amount: 7,
                        bouncebackFee: 3,
                    },
                    portal,
                )
            } else {
                event_log(
                    ZonePortal::DepositBounceBack {
                        tempoRefundRecipient: deposit.sender,
                        token: PATH_USD_ADDRESS,
                        amount: 7,
                        bouncebackFee: 3,
                    },
                    portal,
                )
            };
            let observed = observe(std::slice::from_ref(&failed), &[refund]).unwrap();
            check_bridge(&cohort(), std::slice::from_ref(&deposit), &[], &observed).unwrap();
            let transfers = if pending {
                vec![]
            } else {
                vec![(portal, deposit.sender, U256::from(7))]
            };
            check_token_effects(
                &cohort(),
                std::slice::from_ref(&deposit),
                &[],
                &observed,
                portal,
                &[],
                &transfers,
            )
            .unwrap();
        }
    }

    #[test]
    fn refund_overflow_is_not_a_valid_effect_and_unrelated_tokens_are_ignored() {
        let portal = Address::repeat_byte(8);
        let overflow = event_log(
            ZonePortal::DepositBounceBack {
                tempoRefundRecipient: Address::repeat_byte(2),
                token: PATH_USD_ADDRESS,
                amount: u128::MAX,
                bouncebackFee: 1,
            },
            portal,
        );
        assert_eq!(
            observe(&[], &[overflow]).unwrap_err().to_string(),
            "deposit refund overflow"
        );
        let other = event_log(
            ZonePortal::DepositBounceBack {
                tempoRefundRecipient: Address::repeat_byte(2),
                token: Address::repeat_byte(7),
                amount: 7,
                bouncebackFee: 3,
            },
            portal,
        );
        assert!(observe(&[], &[other]).unwrap().refunds.is_empty());
    }
    #[test]
    fn bridge_principal_debit_and_burn_mutations() {
        let mut intent = intent();
        let portal = Address::repeat_byte(8);
        for withdrawal in [false, true] {
            intent.effect = if withdrawal {
                Effect::Withdrawal {
                    to: Address::repeat_byte(3),
                    amount: 10,
                }
            } else {
                Effect::Deposit {
                    case: DepositCase::Ordinary,
                    to: Address::repeat_byte(3),
                    amount: 10,
                }
            };
            let fee = if withdrawal { 3 } else { 0 };
            let expected = if withdrawal {
                vec![
                    (intent.sender, ZONE_OUTBOX_ADDRESS, U256::from(13)),
                    (ZONE_OUTBOX_ADDRESS, Address::ZERO, U256::from(13)),
                ]
            } else {
                vec![(intent.sender, portal, U256::from(10))]
            };
            check_principal(
                &intent,
                true,
                portal,
                intent.sender,
                fee,
                &path_payments(&[]),
                &path_payments(&expected),
            )
            .unwrap();
            check_principal(
                &intent,
                false,
                portal,
                intent.sender,
                0,
                &path_payments(&[]),
                &path_payments(&[]),
            )
            .unwrap();
            for index in 0..expected.len() {
                for mutation in 0..3 {
                    let mut bad = expected.clone();
                    match mutation {
                        0 => {
                            bad.remove(index);
                        }
                        1 => bad.push(expected[index]),
                        _ => bad[index].2 += U256::from(1),
                    }
                    assert_eq!(
                        check_principal(
                            &intent,
                            true,
                            portal,
                            intent.sender,
                            fee,
                            &path_payments(&[]),
                            &path_payments(&bad)
                        )
                        .unwrap_err()
                        .to_string(),
                        format!(
                            "bridge principal movements differ from intent: {}",
                            intent.tx
                        )
                    );
                }
            }
            assert_eq!(
                check_principal(
                    &intent,
                    false,
                    portal,
                    intent.sender,
                    0,
                    &path_payments(&[]),
                    &path_payments(&expected)
                )
                .unwrap_err()
                .to_string(),
                format!(
                    "bridge principal movements differ from intent: {}",
                    intent.tx
                )
            );
        }
    }

    #[test]
    fn bridge_receipts_reject_extra_principal_and_duplicate_fee_movements() {
        let portal = Address::repeat_byte(8);
        let beneficiary = Address::repeat_byte(9);
        let admin = Address::repeat_byte(10);
        let stranger = Address::repeat_byte(11);
        for withdrawal in [false, true] {
            let mut intent = intent();
            intent.effect = if withdrawal {
                Effect::Withdrawal {
                    to: stranger,
                    amount: 10,
                }
            } else {
                Effect::Deposit {
                    case: DepositCase::Ordinary,
                    to: stranger,
                    amount: 10,
                }
            };
            let gas = (
                intent.sender,
                if withdrawal {
                    beneficiary
                } else {
                    TIP_FEE_MANAGER_ADDRESS
                },
                U256::from(2),
            );
            let bridge_fee = (portal, admin, U256::from(3));
            let mut fees = vec![gas];
            if !withdrawal {
                fees.push(bridge_fee);
            }
            let principal = if withdrawal {
                vec![
                    (intent.sender, ZONE_OUTBOX_ADDRESS, U256::from(13)),
                    (ZONE_OUTBOX_ADDRESS, Address::ZERO, U256::from(13)),
                ]
            } else {
                vec![(intent.sender, portal, U256::from(10))]
            };
            for success in [false, true] {
                let allowed_fees = if success { fees.clone() } else { vec![gas] };
                let mut good = if success { principal.clone() } else { vec![] };
                good.extend_from_slice(&allowed_fees);
                check_principal(
                    &intent,
                    success,
                    portal,
                    intent.sender,
                    3,
                    &path_payments(&allowed_fees),
                    &path_payments(&good),
                )
                .unwrap();
                for extra in [
                    (intent.sender, stranger, U256::from(1)),
                    (stranger, intent.sender, U256::from(1)),
                    gas,
                    bridge_fee,
                ] {
                    let mut bad = good.clone();
                    bad.push(extra);
                    assert_eq!(
                        check_principal(
                            &intent,
                            success,
                            portal,
                            intent.sender,
                            3,
                            &path_payments(&allowed_fees),
                            &path_payments(&bad)
                        )
                        .unwrap_err()
                        .to_string(),
                        format!(
                            "bridge principal movements differ from intent: {}",
                            intent.tx
                        ),
                    );
                }
                let mut wrong_gas = good.clone();
                let fee_index = if success { principal.len() } else { 0 };
                wrong_gas[fee_index].2 += U256::from(1);
                assert_eq!(
                    check_principal(
                        &intent,
                        success,
                        portal,
                        intent.sender,
                        3,
                        &path_payments(&allowed_fees),
                        &path_payments(&wrong_gas)
                    )
                    .unwrap_err()
                    .to_string(),
                    format!(
                        "bridge principal movements differ from intent: {}",
                        intent.tx
                    ),
                );
            }
        }
    }

    #[tokio::test]
    async fn reverted_fresh_recipients_stay_in_cohort_but_missing_receipts_retry() {
        for deposit in [true, false] {
            for missing in ["none", "receipt", "block"] {
                if deposit && missing == "block" {
                    continue;
                }
                let mut intent = intent();
                intent.tx = alloy::primitives::keccak256(&intent.raw);
                let recipient = Address::repeat_byte(21);
                intent.chain = if deposit { Chain::L1 } else { Chain::Zone };
                intent.effect = if deposit {
                    Effect::Deposit {
                        case: DepositCase::Ordinary,
                        to: recipient,
                        amount: 10,
                    }
                } else {
                    Effect::Withdrawal {
                        to: recipient,
                        amount: 10,
                    }
                };
                let portal = Address::repeat_byte(8);
                let mut zone_logs = Vec::new();
                let mut l1_logs = Vec::new();
                let mut zone_transfers = Vec::new();
                let mut l1_transfers = Vec::new();
                if deposit {
                    zone_logs.push(event_log(
                        IZoneInbox::DepositProcessed {
                            depositHash: B256::repeat_byte(22),
                            sender: intent.sender,
                            to: recipient,
                            token: PATH_USD_ADDRESS,
                            amount: 10,
                            memo: B256::ZERO,
                        },
                        ZONE_INBOX_ADDRESS,
                    ));
                    zone_transfers.push(event_log(
                        ITIP20::Transfer {
                            from: Address::ZERO,
                            to: recipient,
                            amount: U256::from(10),
                        },
                        PATH_USD_ADDRESS,
                    ));
                } else {
                    l1_logs.push(event_log(
                        ZonePortal::WithdrawalProcessed {
                            to: recipient,
                            senderTag: B256::repeat_byte(22),
                            token: PATH_USD_ADDRESS,
                            amount: 10,
                            callbackSuccess: true,
                        },
                        portal,
                    ));
                    l1_transfers.push(event_log(
                        ITIP20::Transfer {
                            from: portal,
                            to: recipient,
                            amount: U256::from(10),
                        },
                        PATH_USD_ADDRESS,
                    ));
                }
                let receipt: Option<TransactionReceipt> =
                    (missing != "receipt").then(|| TransactionReceipt {
                        inner: ReceiptEnvelope::Legacy(ReceiptWithBloom::new(
                            Receipt {
                                status: false.into(),
                                cumulative_gas_used: 1,
                                logs: vec![],
                            },
                            Bloom::ZERO,
                        )),
                        transaction_hash: intent.tx,
                        transaction_index: Some(0),
                        block_hash: Some(B256::repeat_byte(23)),
                        block_number: Some(1),
                        gas_used: 1,
                        effective_gas_price: 1,
                        blob_gas_used: None,
                        blob_gas_price: None,
                        from: intent.sender,
                        to: Some(portal),
                        contract_address: None,
                    });
                let receipt = receipt.map(|receipt| {
                    let mut receipt = serde_json::to_value(receipt).unwrap();
                    receipt["feeToken"] = json!(PATH_USD_ADDRESS);
                    receipt["feePayer"] = json!(intent.sender);
                    receipt
                });
                let l1 = Asserter::new();
                let zone = Asserter::new();
                l1.push_success(&"0x1");
                l1.push_success(&l1_logs);
                l1.push_success(&l1_transfers);
                zone.push_success(&"0x1");
                zone.push_success(&zone_logs);
                zone.push_success(&zone_transfers);
                if deposit {
                    l1.push_success(&receipt);
                } else {
                    zone.push_success(&receipt);
                    if missing == "block" {
                        zone.push_success(&None::<Block<B256>>);
                    } else if missing != "receipt" {
                        let mut block = Block::<B256>::default();
                        block.header.beneficiary = Address::repeat_byte(9);
                        zone.push_success(&block);
                    }
                }
                let dir = tempfile::tempdir().unwrap();
                let ledger = Ledger::open(dir.path()).unwrap();
                ledger.append(&Record::Intent(intent)).unwrap();
                let ctx = Context {
                    ledger,
                    http: Default::default(),
                    l1_url: "http://l1.invalid".parse().unwrap(),
                    l1: ProviderBuilder::new().connect_mocked_client(l1).erased(),
                    zone_urls: vec!["http://zone.invalid".parse().unwrap()],
                    zones: vec![ProviderBuilder::new().connect_mocked_client(zone).erased()],
                    portal,
                };
                let observed = ctx.observe_effects().await;
                if missing != "none" {
                    assert_eq!(
                        observed.unwrap(),
                        None,
                        "unknown must not become rejection or success"
                    );
                } else {
                    assert_eq!(
                        observed.unwrap_err().to_string(),
                        if deposit {
                            "unattributed deposit credit in workload cohort"
                        } else {
                            "unattributed withdrawal payout in workload cohort"
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn all_payment_intents_track_refunds_returns_and_unlogged_mints() {
        let mut intent = intent();
        let fresh = Address::repeat_byte(21);
        let portal = Address::repeat_byte(8);
        for effect in [
            Effect::Deposit {
                case: DepositCase::Ordinary,
                to: fresh,
                amount: 10,
            },
            Effect::Withdrawal {
                to: fresh,
                amount: 10,
            },
            Effect::Transfer {
                to: fresh,
                amount: 10,
            },
            Effect::Funding {
                to: fresh,
                amount: 10,
            },
        ] {
            intent.effect = effect;
            let cohort = Cohort::from_intents([&intent]);
            check_bridge(&cohort, &[], &[], &Observed::default()).unwrap();
            let (zone, l1) = if matches!(
                intent.effect,
                Effect::Deposit { .. } | Effect::Transfer { .. }
            ) {
                (vec![(Address::ZERO, fresh, U256::from(10))], vec![])
            } else {
                (vec![], vec![(portal, fresh, U256::from(10))])
            };
            assert_eq!(
                check_token_effects(&cohort, &[], &[], &Observed::default(), portal, &zone, &l1)
                    .unwrap_err()
                    .to_string(),
                if zone.is_empty() {
                    "portal transfers differ from intended payouts and refunds"
                } else {
                    "mint transfers differ from intended credits"
                },
            );
        }
        intent.effect = Effect::Deposit {
            case: DepositCase::Ordinary,
            to: fresh,
            amount: 10,
        };
        let cohort = Cohort::from_intents([&intent]);
        let mut observed = Observed::default();
        observed.refunds.push((intent.sender, 10));
        assert_eq!(
            check_bridge(&cohort, &[], &[], &observed)
                .unwrap_err()
                .to_string(),
            "deposit refunds differ from failed intents"
        );
        intent.effect = Effect::Withdrawal {
            to: fresh,
            amount: 10,
        };
        let cohort = Cohort::from_intents([&intent]);
        observed = Observed::default();
        observed.returns.push((intent.sender, 10));
        assert_eq!(
            check_bridge(&cohort, &[], &[], &observed)
                .unwrap_err()
                .to_string(),
            "withdrawal returns differ from bounced intents"
        );
    }
    #[tokio::test]
    async fn bad_tag_full_history_oracle_rejects_wrong_outcomes_and_refunds() {
        for mutation in [
            "none",
            "ordinary_credit",
            "bad_credit",
            "missing_refund",
            "duplicate_refund",
            "wrong_recipient",
            "wrong_amount",
            "wrong_fee",
            "pending",
            "missing_failure",
            "duplicate_failure",
            "wrong_queue",
            "missing_successor",
            "failed_successor",
            "wrong_token",
            "wrong_transfer",
            "bad_mint",
        ] {
            let portal = Address::repeat_byte(8);
            let mut bad = intent();
            bad.raw = Bytes::from_static(b"bad-tag oracle signed fixture");
            bad.tx = alloy::primitives::keccak256(&bad.raw);
            bad.chain = Chain::L1;
            bad.effect = Effect::Deposit {
                to: Address::repeat_byte(3),
                amount: 12,
                case: if mutation == "ordinary_credit" {
                    DepositCase::Ordinary
                } else {
                    DepositCase::BadTag
                },
            };
            let mut valid = bad.clone();
            valid.raw = Bytes::from_static(b"valid successor oracle signed fixture");
            valid.tx = alloy::primitives::keccak256(&valid.raw);
            valid.nonce += 1;
            valid.effect = Effect::Deposit {
                to: Address::repeat_byte(4),
                amount: 11,
                case: DepositCase::Ordinary,
            };
            let bad_deposit = Deposit {
                case: DepositCase::BadTag,
                ..deposit()
            };
            let valid_deposit = Deposit {
                id: B256::repeat_byte(6),
                sender: bad.sender,
                to: Address::repeat_byte(4),
                amount: 11,
                case: DepositCase::Ordinary,
            };
            let failed = event_log(
                IZoneInbox::DepositFailed {
                    depositHash: bad_deposit.id,
                    sender: bad.sender,
                    token: PATH_USD_ADDRESS,
                    amount: 10,
                },
                ZONE_INBOX_ADDRESS,
            );
            let credit = event_log(
                IZoneInbox::DepositProcessed {
                    depositHash: valid_deposit.id,
                    sender: valid.sender,
                    to: valid_deposit.to,
                    token: PATH_USD_ADDRESS,
                    amount: 11,
                    memo: B256::ZERO,
                },
                ZONE_INBOX_ADDRESS,
            );
            let mut zone_logs = vec![failed.clone(), credit];
            let mut l1_logs = vec![event_log(
                ZonePortal::DepositBounceBack {
                    tempoRefundRecipient: bad.sender,
                    token: PATH_USD_ADDRESS,
                    amount: 7,
                    bouncebackFee: 3,
                },
                portal,
            )];
            let mut zone_transfers = vec![event_log(
                ITIP20::Transfer {
                    from: Address::ZERO,
                    to: valid_deposit.to,
                    amount: U256::from(11),
                },
                PATH_USD_ADDRESS,
            )];
            let mut l1_transfers = vec![event_log(
                ITIP20::Transfer {
                    from: portal,
                    to: bad.sender,
                    amount: U256::from(7),
                },
                PATH_USD_ADDRESS,
            )];
            match mutation {
                "bad_credit" | "ordinary_credit" => {
                    zone_logs[0] = event_log(
                        IZoneInbox::DepositProcessed {
                            depositHash: bad_deposit.id,
                            sender: bad.sender,
                            to: bad_deposit.to,
                            token: PATH_USD_ADDRESS,
                            amount: 10,
                            memo: B256::ZERO,
                        },
                        ZONE_INBOX_ADDRESS,
                    );
                    l1_logs.clear();
                    l1_transfers.clear();
                    zone_transfers.push(event_log(
                        ITIP20::Transfer {
                            from: Address::ZERO,
                            to: bad_deposit.to,
                            amount: U256::from(10),
                        },
                        PATH_USD_ADDRESS,
                    ));
                }
                "missing_refund" => {
                    l1_logs.clear();
                    l1_transfers.clear();
                }
                "duplicate_refund" => {
                    l1_logs.push(l1_logs[0].clone());
                    l1_transfers.push(l1_transfers[0].clone());
                }
                "wrong_recipient" | "wrong_amount" | "wrong_fee" | "wrong_token" => {
                    l1_logs[0] = event_log(
                        ZonePortal::DepositBounceBack {
                            tempoRefundRecipient: if mutation == "wrong_recipient" {
                                Address::repeat_byte(99)
                            } else {
                                bad.sender
                            },
                            token: if mutation == "wrong_token" {
                                Address::repeat_byte(99)
                            } else {
                                PATH_USD_ADDRESS
                            },
                            amount: if mutation == "wrong_amount" { 8 } else { 7 },
                            bouncebackFee: if mutation == "wrong_fee" { 4 } else { 3 },
                        },
                        portal,
                    );
                }
                "pending" => {
                    l1_logs[0] = event_log(
                        ZonePortal::DepositBounceBackPending {
                            tempoRefundRecipient: bad.sender,
                            token: PATH_USD_ADDRESS,
                            amount: 7,
                            bouncebackFee: 3,
                        },
                        portal,
                    );
                    l1_transfers.clear();
                }
                "missing_failure" => {
                    zone_logs.remove(0);
                }
                "duplicate_failure" => zone_logs.push(failed),
                "wrong_queue" => {
                    zone_logs[0] = event_log(
                        IZoneInbox::DepositFailed {
                            depositHash: B256::repeat_byte(99),
                            sender: bad.sender,
                            token: PATH_USD_ADDRESS,
                            amount: 10,
                        },
                        ZONE_INBOX_ADDRESS,
                    );
                }
                "missing_successor" => {
                    zone_logs.pop();
                    zone_transfers.clear();
                }
                "failed_successor" => {
                    zone_logs[1] = event_log(
                        IZoneInbox::DepositFailed {
                            depositHash: valid_deposit.id,
                            sender: valid.sender,
                            token: PATH_USD_ADDRESS,
                            amount: 11,
                        },
                        ZONE_INBOX_ADDRESS,
                    );
                }
                "wrong_transfer" => {
                    l1_transfers[0] = event_log(
                        ITIP20::Transfer {
                            from: portal,
                            to: bad.sender,
                            amount: U256::from(8),
                        },
                        PATH_USD_ADDRESS,
                    );
                }
                "bad_mint" => zone_transfers.push(event_log(
                    ITIP20::Transfer {
                        from: Address::ZERO,
                        to: bad_deposit.to,
                        amount: U256::from(10),
                    },
                    PATH_USD_ADDRESS,
                )),
                _ => {}
            }
            let observed = observe(&zone_logs, &l1_logs).unwrap();
            if mutation == "none" {
                assert!(
                    bad_tag_ready(&[bad_deposit.clone(), valid_deposit.clone()], &observed)
                        .unwrap()
                );
            }
            if matches!(
                mutation,
                "pending" | "missing_successor" | "missing_failure" | "missing_refund"
            ) {
                assert!(
                    !bad_tag_ready(&[bad_deposit.clone(), valid_deposit.clone()], &observed)
                        .unwrap()
                );
            }
            if mutation == "failed_successor" {
                assert_eq!(
                    bad_tag_ready(&[bad_deposit.clone(), valid_deposit.clone()], &observed)
                        .unwrap_err()
                        .to_string(),
                    format!("valid successor deposit failed: {}", valid_deposit.id)
                );
            }
            let l1 = Asserter::new();
            let zone = Asserter::new();
            l1.push_success(&"0x1");
            l1.push_success(&l1_logs);
            l1.push_success(&l1_transfers);
            zone.push_success(&"0x1");
            zone.push_success(&zone_logs);
            zone.push_success(&zone_transfers);
            for (intent, deposit, fee) in [(&bad, &bad_deposit, 2), (&valid, &valid_deposit, 0)] {
                let made = event_log(
                    ZonePortal::DepositMade {
                        newCurrentDepositQueueHash: deposit.id,
                        sender: intent.sender,
                        token: PATH_USD_ADDRESS,
                        netAmount: deposit.amount,
                        fee,
                        keyIndex: U256::ZERO,
                        ephemeralPubkeyX: B256::ZERO,
                        ephemeralPubkeyYParity: 2,
                        ciphertext: Bytes::new(),
                        nonce: Default::default(),
                        tag: Default::default(),
                        tempoRefundRecipient: intent.sender,
                        depositNumber: intent.nonce + 1,
                    },
                    portal,
                );
                let mut receipt_logs = vec![
                    made,
                    event_log(
                        ITIP20::Transfer {
                            from: intent.sender,
                            to: portal,
                            amount: U256::from(deposit.amount + fee),
                        },
                        PATH_USD_ADDRESS,
                    ),
                ];
                if fee != 0 {
                    receipt_logs.push(event_log(
                        ITIP20::Transfer {
                            from: portal,
                            to: Address::repeat_byte(55),
                            amount: U256::from(fee),
                        },
                        PATH_USD_ADDRESS,
                    ));
                }
                let mut receipt = fee_receipt(0, 0, None, intent.sender, receipt_logs);
                receipt.transaction_hash = intent.tx;
                l1.push_success(&receipt);
                if fee != 0 {
                    l1.push_success(&alloy::primitives::Bytes::from(
                        Address::repeat_byte(55).into_word().to_vec(),
                    ));
                }
            }
            let dir = tempfile::tempdir().unwrap();
            let ledger = Ledger::open(dir.path()).unwrap();
            ledger.append(&Record::Intent(bad)).unwrap();
            ledger.append(&Record::Intent(valid)).unwrap();
            let ctx = Context {
                ledger,
                http: Default::default(),
                l1_url: "http://l1.invalid".parse().unwrap(),
                l1: ProviderBuilder::new()
                    .connect_mocked_client(l1.clone())
                    .erased(),
                zone_urls: vec!["http://zone.invalid".parse().unwrap()],
                zones: vec![
                    ProviderBuilder::new()
                        .connect_mocked_client(zone.clone())
                        .erased(),
                ],
                portal,
            };
            let result = ctx.observe_effects().await;
            let expected = match mutation {
                "none" | "ordinary_credit" | "pending" => None,
                "bad_credit" => Some(format!("bad-tag deposit was credited: {}", bad_deposit.id)),
                "missing_failure" | "duplicate_failure" | "wrong_queue" => Some(format!(
                    "deposit needs exactly one credit or failure: {}",
                    bad_deposit.id
                )),
                "missing_successor" => Some(format!(
                    "deposit needs exactly one credit or failure: {}",
                    valid_deposit.id
                )),
                "wrong_transfer" => {
                    Some("portal transfers differ from intended payouts and refunds".to_owned())
                }
                "bad_mint" => Some("mint transfers differ from intended credits".to_owned()),
                _ => Some("deposit refunds differ from failed intents".to_owned()),
            };
            if let Some(expected) = expected {
                assert_eq!(result.unwrap_err().to_string(), expected, "{mutation}");
            } else {
                assert_eq!(result.unwrap(), Some(()), "{mutation}");
            }
            assert!(l1.read_q().is_empty(), "{mutation}");
            assert!(zone.read_q().is_empty(), "{mutation}");
        }
    }
    #[test]
    fn refund_requires_exact_canonical_finalized_receipt_log() {
        let mut log = event_log(
            ZonePortal::DepositBounceBack {
                tempoRefundRecipient: Address::repeat_byte(2),
                token: PATH_USD_ADDRESS,
                amount: 7,
                bouncebackFee: 3,
            },
            Address::repeat_byte(8),
        );
        log.block_number = Some(1);
        log.block_hash = Some(B256::repeat_byte(23));
        log.transaction_hash = Some(intent().tx);
        log.transaction_index = Some(0);
        log.log_index = Some(1);
        let receipt = fee_receipt(0, 0, None, intent().sender, vec![log.clone()]);
        verify_finalized_refund(&log, &receipt, 1, B256::repeat_byte(23)).unwrap();
        for mutation in 0..7 {
            let mut wrong = log.clone();
            match mutation {
                0 => wrong.removed = true,
                1 => wrong.block_hash = Some(B256::ZERO),
                2 => wrong.block_number = Some(2),
                3 => wrong.transaction_hash = Some(B256::ZERO),
                4 => wrong.transaction_index = Some(1),
                5 => wrong.log_index = None,
                _ => wrong.log_index = Some(3),
            }
            assert_eq!(
                verify_finalized_refund(&wrong, &receipt, 1, B256::repeat_byte(23))
                    .unwrap_err()
                    .to_string(),
                "refund is not an exact canonical finalized receipt log"
            );
        }
        assert_eq!(
            verify_finalized_refund(&log, &receipt, 0, B256::repeat_byte(23))
                .unwrap_err()
                .to_string(),
            "refund is not an exact canonical finalized receipt log"
        );
    }
    #[tokio::test]
    async fn process_withdrawals_tempo_receipt_uses_the_finalized_refund_boundary() {
        let portal = Address::repeat_byte(8);
        let sender = intent().sender;
        let mut refund = event_log(
            ZonePortal::DepositBounceBack {
                tempoRefundRecipient: sender,
                token: PATH_USD_ADDRESS,
                amount: 7,
                bouncebackFee: 3,
            },
            portal,
        );
        refund.block_number = Some(1);
        refund.block_hash = Some(B256::repeat_byte(23));
        refund.transaction_hash = Some(intent().tx);
        refund.transaction_index = Some(0);
        refund.log_index = Some(1);
        let mut payment = event_log(
            ITIP20::Transfer {
                from: portal,
                to: sender,
                amount: U256::from(7),
            },
            PATH_USD_ADDRESS,
        );
        payment.block_number = refund.block_number;
        payment.block_hash = refund.block_hash;
        payment.transaction_hash = refund.transaction_hash;
        payment.transaction_index = refund.transaction_index;
        payment.log_index = Some(0);
        let mut wire = serde_json::to_value(fee_receipt(
            0,
            0,
            None,
            sender,
            vec![payment, refund.clone()],
        ))
        .unwrap();
        // A sequencer's processWithdrawals is sent as a Tempo transaction with nonce key 2.
        // Returning its real receipt envelope here fails an Ethereum-only provider decoder.
        wire["type"] = json!("0x76");
        let mut block = Block::<B256>::default();
        block.header.number = 1;
        block.header.hash = B256::repeat_byte(23);
        let l1 = Asserter::new();
        let dir = tempfile::tempdir().unwrap();
        let ctx = Context {
            ledger: Ledger::open(dir.path()).unwrap(),
            http: Default::default(),
            l1_url: "http://l1.invalid".parse().unwrap(),
            l1: ProviderBuilder::new()
                .connect_mocked_client(l1.clone())
                .erased(),
            zone_urls: vec![],
            zones: vec![],
            portal,
        };
        for mutation in [
            "none",
            "removed",
            "wrong_hash",
            "unfinalized",
            "duplicate_log",
        ] {
            let mut log = refund.clone();
            let mut receipt = wire.clone();
            match mutation {
                "removed" => log.removed = true,
                "wrong_hash" => receipt["blockHash"] = json!(B256::ZERO),
                "duplicate_log" => receipt["logs"].as_array_mut().unwrap().push(json!(refund)),
                _ => {}
            }
            l1.push_success(&receipt);
            l1.push_success(&block);
            let result = ctx
                .finalized_refund_receipt(&log, if mutation == "unfinalized" { 0 } else { 1 })
                .await;
            if mutation == "none" {
                let receipt = result.unwrap().unwrap();
                assert_eq!(receipt.transaction_hash, intent().tx);
                assert!(receipt.status());
                assert_eq!(
                    payments(receipt.logs()),
                    vec![(portal, sender, U256::from(7))]
                );
            } else {
                assert_eq!(
                    result.unwrap_err().to_string(),
                    "refund is not an exact canonical finalized receipt log"
                );
            }
            assert!(l1.read_q().is_empty(), "{mutation}");
        }
        l1.push_success(&serde_json::Value::Null);
        assert!(
            ctx.finalized_refund_receipt(&refund, 1)
                .await
                .unwrap()
                .is_none()
        );
        assert!(l1.read_q().is_empty());
    }
}
