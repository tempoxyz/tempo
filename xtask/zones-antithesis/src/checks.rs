//! Check commands: properties that hold during faults, after they stop, and after a fault-free run.

use alloy::{
    primitives::{Address, B256, U256},
    providers::{DynProvider, Provider},
    rpc::types::{BlockId, BlockNumberOrTag, Filter, Log, TransactionReceipt},
    sol_types::SolEvent,
};
use antithesis_sdk::{assert_always, assert_sometimes};
use eyre::WrapErr as _;
use futures::{StreamExt as _, TryStreamExt as _, stream};
use serde_json::json;
use std::{collections::BTreeMap, time::Duration};
use tempo_contracts::{
    precompiles::{ITIP20, PATH_USD_ADDRESS},
    zones::{
        IZoneInbox, IZoneOutbox, TEMPO_STATE_ADDRESS, TempoState, ZONE_INBOX_ADDRESS,
        ZONE_OUTBOX_ADDRESS, ZonePortal,
    },
};

use super::{
    Context, Record,
    intents::pending,
    is_rpc_error, random_below,
    recovery::{bounded_check, recover_until},
    shuffled,
};

/// How long `check-settled` waits for the system to recover once faults stop.
const SETTLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Accounts and transactions `check-consistency` samples per run.
const SAMPLE: usize = 16;
/// Blocks per `eth_getLogs` request.
const LOG_CHUNK: u64 = 10_000;
/// Concurrent balance reads in `check-ledger`.
const BALANCE_READS: usize = 32;

impl Context {
    pub(super) async fn check_consistency(&self) -> eyre::Result<()> {
        match async {
            self.reconcile_handoffs().await?;
            self.check_handoff_history().await
        }
        .await
        {
            Err(error) if is_rpc_error(&error) => {
                println!("check-consistency: handoff history unavailable: {error:#}");
            }
            result => result?,
        }

        // A zone block must come from the sequencer the portal names leader at the Tempo block
        // the zone block anchors to: a handoff takes effect at its activation block. Checked at
        // each node's tip, where a handoff shows first, and at one earlier block. A node that
        // faults make unreachable is skipped.
        let portal = ZonePortal::new(self.portal, &self.l1);
        for (url, zone) in self.zone_urls.iter().zip(&self.zones) {
            let checked: eyre::Result<()> = async {
                let tip = zone.get_block_number().await?;
                // Genesis has no producer.
                if tip == 0 {
                    return Ok(());
                }
                for number in [tip, random_below(tip) + 1] {
                    let Some(block) = zone
                        .get_block_by_number(BlockNumberOrTag::Number(number))
                        .await?
                    else {
                        continue;
                    };
                    let anchor = TempoState::new(TEMPO_STATE_ADDRESS, zone)
                        .tempoBlockNumber()
                        .block(BlockId::hash(block.header.hash))
                        .call()
                        .await?;
                    let leader = portal
                        .leader()
                        .block(BlockId::number(anchor))
                        .call()
                        .await?;
                    assert_always!(
                        block.header.beneficiary == leader,
                        "Zone blocks come from the leader of their Tempo anchor",
                        &json!({
                            "node": url.as_str(),
                            "height": number,
                            "hash": block.header.hash,
                            "producer": block.header.beneficiary,
                            "tempo_anchor": anchor,
                            "leader": leader,
                        })
                    );
                }
                Ok(())
            }
            .await;
            match checked {
                Err(error) if is_rpc_error(&error) => {
                    println!("check-consistency: producer check skipped {url}: {error:#}");
                }
                result => result?,
            }
        }

        // L1 can be paused or partitioned while faults run, like the zone nodes skipped below.
        let (height, hash) = match self.settled_block().await {
            Ok(settled) => settled,
            Err(error) if is_rpc_error(&error) => {
                println!("check-consistency: L1 unavailable: {error:#}");
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        // Until the first batch settles the portal holds no zone block hash to compare against.
        if hash.is_zero() {
            println!("check-consistency: nothing settled yet");
            return Ok(());
        }
        let records = self.ledger.records()?;
        let accounts: Vec<Address> = shuffled(self.ledger.accounts()?)
            .into_iter()
            .take(SAMPLE)
            .map(|account| account.address())
            .collect();
        let settled_txs: Vec<(B256, u64)> = shuffled(
            records
                .iter()
                .filter_map(|record| match *record {
                    Record::Transfer {
                        zone_tx,
                        zone_block,
                        ..
                    }
                    | Record::Withdrawal {
                        zone_tx,
                        zone_block,
                        ..
                    } if zone_block <= height => Some((zone_tx, zone_block)),
                    _ => None,
                })
                .collect(),
        )
        .into_iter()
        .take(SAMPLE)
        .collect();

        // Nodes that are down, partitioned or still behind the settled height are skipped: this
        // runs while faults are injected.
        let mut balances: BTreeMap<Address, BTreeMap<String, U256>> = BTreeMap::new();
        for (url, zone) in self.zone_urls.iter().zip(&self.zones) {
            let Ok(Some(block)) = zone
                .get_block_by_number(BlockNumberOrTag::Number(height))
                .await
            else {
                continue;
            };
            let details = json!({
                "node": url.as_str(),
                "height": height,
                "settled_hash": hash,
                "node_hash": block.header.hash,
            });
            assert_always!(
                block.header.hash == hash,
                "Zone nodes agree with the block settled on L1",
                &details
            );
            for &account in &accounts {
                if let Ok(balance) = ITIP20::new(PATH_USD_ADDRESS, zone)
                    .balanceOf(account)
                    .from(account)
                    .block(BlockId::number(height))
                    .call()
                    .await
                {
                    balances
                        .entry(account)
                        .or_default()
                        .insert(url.to_string(), balance);
                }
            }
            for &(tx, zone_block) in &settled_txs {
                let Ok(receipt) = zone.get_transaction_receipt(tx).await else {
                    continue;
                };
                assert_always!(
                    receipt.as_ref().is_some_and(
                        |receipt| receipt.status() && receipt.block_number == Some(zone_block)
                    ),
                    "Settled workload transactions stay final",
                    &json!({
                        "node": url.as_str(),
                        "tx": tx,
                        "recorded_block": zone_block,
                        "receipt_block": receipt.as_ref().and_then(|receipt| receipt.block_number),
                        "status": receipt.as_ref().map(|receipt| receipt.status()),
                    })
                );
            }
        }
        for (account, by_node) in &balances {
            let mut values = by_node.values();
            let first = values.next();
            assert_always!(
                values.all(|value| Some(value) == first),
                "Zone nodes agree on balances at the settled block",
                &json!({ "account": account, "height": height, "balances": by_node })
            );
        }
        assert_sometimes!(
            height > 0,
            "A zone batch settles on L1",
            &json!({ "height": height })
        );
        println!("check-consistency: settled height {height}");
        Ok(())
    }

    pub(super) async fn check_settled(&self) -> eyre::Result<()> {
        let mut state = None;
        let result = bounded_check(SETTLE_TIMEOUT, async {
            let deadline = tokio::time::Instant::now() + SETTLE_TIMEOUT;
            recover_until(deadline, async || {
                // A killed driver's signed send remains an obligation even without a receipt.
                // Reconciliation replays identical bytes; timeout/cancellation cannot forget it.
                if !self.reconcile_intents().await? {
                    return Ok(None);
                }
                self.reconcile_handoffs().await?;
                self.check_handoff_history().await?;
                // Take an immutable obligation snapshot after reconciliation. A concurrent
                // driver's new intent cannot slip into it and be silently ignored below.
                let records = self.ledger.records()?;
                if !pending(&records)?.is_empty() {
                    return Ok(None);
                }
                let current = self.settlement(records).await?;
                let settled = current.is_settled();
                state = Some(current);
                Ok(settled.then_some(()))
            })
            .await
        })
        .await;
        // Retain the last complete observation even if a later RPC or the deadline interrupts
        // recovery. Missing observations must not fabricate passing settlement properties.
        if let Some(state) = state {
            assert_always!(
                state.unsettled_deposits.is_empty(),
                "Every confirmed deposit is credited or bounced back",
                &json!({ "missing": state.unsettled_deposits })
            );
            assert_always!(
                state.unpaid_withdrawals.is_empty(),
                "Every confirmed withdrawal is paid or returned",
                &json!({ "missing": state.unpaid_withdrawals })
            );
            assert_always!(
                state.converged,
                "Zone nodes converge once faults stop",
                &json!({ "tips": state.tips })
            );
            println!(
                "check-settled: {} deposits and {} withdrawals unsettled, converged={}",
                state.unsettled_deposits.len(),
                state.unpaid_withdrawals.len(),
                state.converged
            );
        }
        result
    }

    pub(super) async fn check_ledger(&self) -> eyre::Result<()> {
        self.check_settled().await?;
        bounded_check(SETTLE_TIMEOUT, async {
            recover_until(tokio::time::Instant::now() + SETTLE_TIMEOUT, async || {
                self.check_effects().await
            })
            .await
        })
        .await?;
        let zone = &self.zones[0];
        let height = zone.get_block_number().await?;
        let mut from_logs: BTreeMap<Address, U256> = BTreeMap::new();
        for log in logs(zone, Filter::new().address(PATH_USD_ADDRESS), height).await? {
            let Ok(transfer) = ITIP20::Transfer::decode_log(&log.inner) else {
                continue;
            };
            if !transfer.from.is_zero() {
                let balance = from_logs.entry(transfer.from).or_default();
                *balance = balance.checked_sub(transfer.amount).ok_or_else(|| {
                    eyre::eyre!("Transfer logs overdraw {} at {log:?}", transfer.from)
                })?;
            }
            *from_logs.entry(transfer.to).or_default() += transfer.amount;
        }
        let accounts = self.ledger.accounts()?;
        let mismatches: Vec<_> = stream::iter(accounts.iter().map(|account| account.address()))
            .map(|account| async move {
                let balance = ITIP20::new(PATH_USD_ADDRESS, zone)
                    .balanceOf(account)
                    .from(account)
                    .block(BlockId::number(height))
                    .call()
                    .await
                    .wrap_err_with(|| format!("failed reading the balance of {account}"))?;
                eyre::Ok((account, balance))
            })
            .buffer_unordered(BALANCE_READS)
            .try_filter_map(|(account, balance)| {
                let logged = from_logs.get(&account).copied().unwrap_or_default();
                async move {
                    Ok((balance != logged)
                        .then(|| json!({ "account": account, "state": balance, "logs": logged })))
                }
            })
            .try_collect()
            .await?;
        assert_always!(
            mismatches.is_empty(),
            "Zone balances match the zone's Transfer logs",
            &json!({ "height": height, "accounts": accounts.len(), "mismatches": mismatches })
        );
        println!(
            "check-ledger: {} accounts at height {height}, {} mismatches",
            accounts.len(),
            mismatches.len()
        );
        Ok(())
    }

    /// The zone height and block hash the portal last settled, read at one L1 block.
    async fn settled_block(&self) -> eyre::Result<(u64, B256)> {
        let at = BlockId::number(self.l1.get_block_number().await?);
        let portal = ZonePortal::new(self.portal, &self.l1);
        let height = portal.zoneHeight().block(at).call().await?;
        let hash = portal.blockHash().block(at).call().await?;
        Ok((height.try_into()?, hash))
    }

    /// What is still in flight: confirmed deposits the zone has not processed, confirmed
    /// withdrawals L1 has not paid, and whether every zone node has the highest tip any reports.
    /// `records` is a reconciled snapshot; parallel drivers need not stop writing the journal.
    async fn settlement(&self, records: Vec<Record>) -> eyre::Result<Settlement> {
        let mut tips = BTreeMap::new();
        for (url, zone) in self.zone_urls.iter().zip(&self.zones) {
            let block = zone
                .get_block_by_number(BlockNumberOrTag::Latest)
                .await?
                .ok_or_else(|| eyre::eyre!("{url} has no latest block"))?;
            tips.insert(url.to_string(), (block.header.number, block.header.hash));
        }
        // Every node must reach the highest tip any node reported, and agree on it. That height
        // is past every block a node has, so also past every workload transaction and every
        // deposit credit the checks below read from one node.
        let highest = tips
            .values()
            .map(|(number, _)| *number)
            .max()
            .unwrap_or_default();
        let mut hashes_at_highest = Vec::new();
        for zone in &self.zones {
            hashes_at_highest.push(
                zone.get_block_by_number(BlockNumberOrTag::Number(highest))
                    .await?
                    .map(|block| block.header.hash),
            );
        }
        let converged = hashes_at_highest
            .windows(2)
            .all(|pair| pair[0].is_some() && pair[0] == pair[1]);

        let zone = &self.zones[0];
        let zone_height = zone.get_block_number().await?;
        // Inbox outcomes by deposit queue hash, which identifies one deposit.
        let mut credited: BTreeMap<B256, Vec<(Address, Address, u128)>> = BTreeMap::new();
        let mut bounced: BTreeMap<B256, Vec<(Address, u128)>> = BTreeMap::new();
        let mut returned = BTreeMap::new();
        for log in logs(zone, Filter::new().address(ZONE_INBOX_ADDRESS), zone_height).await? {
            if let Ok(event) = IZoneInbox::DepositProcessed::decode_log(&log.inner) {
                credited.entry(event.depositHash).or_default().push((
                    event.sender,
                    event.to,
                    event.amount,
                ));
            } else if let Ok(event) = IZoneInbox::DepositFailed::decode_log(&log.inner) {
                bounced
                    .entry(event.depositHash)
                    .or_default()
                    .push((event.sender, event.amount));
            } else if let Ok(event) =
                IZoneInbox::WithdrawalBounceBackProcessed::decode_log(&log.inner)
            {
                *returned
                    .entry((event.zoneFallbackRecipient, event.amount))
                    .or_default() += 1usize;
            } else if let Ok(event) =
                IZoneInbox::WithdrawalBounceBackPending::decode_log(&log.inner)
            {
                *returned
                    .entry((event.zoneFallbackRecipient, event.amount))
                    .or_default() += 1usize;
            }
        }
        let l1_height = self.l1.get_block_number().await?;
        let mut deliveries: BTreeMap<B256, Vec<(Address, u128, bool)>> = BTreeMap::new();
        // A rejected deposit is only settled once L1 refunds it, paid out or parked for claiming.
        // Keyed by refund recipient and the amount before the bounce-back fee.
        let mut refunded: BTreeMap<(Address, u128), usize> = BTreeMap::new();
        for log in logs(&self.l1, Filter::new().address(self.portal), l1_height).await? {
            // A failed delivery also emits WithdrawalProcessed, with callbackSuccess false, and
            // bounces the funds back to the zone instead of paying `to`.
            if let Ok(event) = ZonePortal::WithdrawalProcessed::decode_log(&log.inner) {
                if event.token == PATH_USD_ADDRESS {
                    deliveries.entry(event.senderTag).or_default().push((
                        event.to,
                        event.amount,
                        event.callbackSuccess,
                    ));
                }
            } else if let Ok(event) = ZonePortal::DepositBounceBack::decode_log(&log.inner) {
                *refunded
                    .entry((
                        event.tempoRefundRecipient,
                        event
                            .amount
                            .checked_add(event.bouncebackFee)
                            .ok_or_else(|| eyre::eyre!("deposit refund overflow"))?,
                    ))
                    .or_default() += 1;
            } else if let Ok(event) = ZonePortal::DepositBounceBackPending::decode_log(&log.inner) {
                *refunded
                    .entry((
                        event.tempoRefundRecipient,
                        event
                            .amount
                            .checked_add(event.bouncebackFee)
                            .ok_or_else(|| eyre::eyre!("deposit refund overflow"))?,
                    ))
                    .or_default() += 1;
            }
        }

        // Nodes may agree on a common rollback; a confirmed transaction's block is a floor.
        let last_zone_block = records
            .iter()
            .filter_map(|record| match record {
                Record::Transfer { zone_block, .. } | Record::Withdrawal { zone_block, .. } => {
                    Some(*zone_block)
                }
                _ => None,
            })
            .max()
            .unwrap_or_default();
        let converged = converged && highest >= last_zone_block;
        let mut unsettled_deposits = Vec::new();
        let mut unpaid_withdrawals = Vec::new();
        for record in records {
            match record {
                Record::Deposit {
                    queue_hash,
                    sender,
                    to,
                    net_amount,
                    ..
                } => {
                    // Drivers name the sender as the deposit's refund recipient. L1 refunds
                    // carry no deposit identity, so they are matched by recipient and amount.
                    let settled = credited
                        .get(&queue_hash)
                        .is_some_and(|credits| credits.as_slice() == [(sender, to, net_amount)])
                        && !bounced.contains_key(&queue_hash)
                        || (!credited.contains_key(&queue_hash)
                            && bounced.get(&queue_hash).is_some_and(|failures| {
                                failures.as_slice() == [(sender, net_amount)]
                            })
                            && take(&mut refunded, (sender, net_amount)));
                    if !settled {
                        unsettled_deposits.push(record);
                    }
                }
                Record::Withdrawal { zone_tx, .. } => {
                    let settled = if deliveries.is_empty() {
                        false
                    } else if let Some(receipt) = zone.get_transaction_receipt(zone_tx).await? {
                        withdrawal_settled(&record, &receipt, &mut deliveries, &mut returned)
                    } else {
                        false
                    };
                    if !settled {
                        unpaid_withdrawals.push(record);
                    }
                }
                _ => {}
            }
        }
        Ok(Settlement {
            unsettled_deposits,
            unpaid_withdrawals,
            converged,
            tips,
        })
    }
}

// A successful delivery and a failed one can have identical recipient/amount. Consume
// either only after binding its tag to this exact withdrawal receipt.
fn withdrawal_settled(
    record: &Record,
    receipt: &TransactionReceipt,
    deliveries: &mut BTreeMap<B256, Vec<(Address, u128, bool)>>,
    returned: &mut BTreeMap<(Address, u128), usize>,
) -> bool {
    let Record::Withdrawal {
        zone_tx,
        sender,
        to,
        amount,
        ..
    } = *record
    else {
        return false;
    };
    if receipt.transaction_hash != zone_tx || !receipt.status() {
        return false;
    }
    let requests: Vec<_> = receipt
        .inner
        .logs()
        .iter()
        .filter(|log| log.address() == ZONE_OUTBOX_ADDRESS)
        .filter_map(|log| IZoneOutbox::WithdrawalRequested::decode_log(&log.inner).ok())
        .collect();
    let [request] = requests.as_slice() else {
        return false;
    };
    if request.sender != sender
        || request.to != to
        || request.amount != amount
        || request.token != PATH_USD_ADDRESS
        || request.fallbackNonce == 0
    {
        return false;
    }
    let tag = ZonePortal::Withdrawal::sender_tag(sender, zone_tx, request.fallbackNonce);
    let Some(events) = deliveries.get(&tag) else {
        return false;
    };
    let settled = match events.as_slice() {
        [(recipient, value, delivered)] if *recipient == to && *value == amount => {
            *delivered || take(returned, (sender, amount))
        }
        _ => false,
    };
    if settled {
        deliveries.remove(&tag);
    }
    settled
}

/// See [`Context::settlement`].
#[derive(Debug)]
struct Settlement {
    unsettled_deposits: Vec<Record>,
    unpaid_withdrawals: Vec<Record>,
    converged: bool,
    tips: BTreeMap<String, (u64, B256)>,
}

impl Settlement {
    fn is_settled(&self) -> bool {
        self.unsettled_deposits.is_empty() && self.unpaid_withdrawals.is_empty() && self.converged
    }
}

/// Consumes one occurrence of `key`, returning whether there was one.
fn take<K: Ord>(counts: &mut BTreeMap<K, usize>, key: K) -> bool {
    match counts.get_mut(&key) {
        Some(count) if *count > 0 => {
            *count -= 1;
            true
        }
        _ => false,
    }
}

/// Every log matching `filter` in blocks `0..=to`, in [`LOG_CHUNK`]-block requests.
pub(crate) async fn logs(
    provider: &DynProvider,
    filter: Filter,
    to: u64,
) -> eyre::Result<Vec<Log>> {
    let mut logs = Vec::new();
    let mut from = 0;
    while from <= to {
        let end = to.min(from + LOG_CHUNK - 1);
        eyre::ensure!(logs.len() <= 200_000, "effect logs exceed bound");
        logs.extend(
            provider
                .get_logs(&filter.clone().from_block(from).to_block(end))
                .await
                .wrap_err_with(|| format!("failed reading logs in {from}..={end}"))?,
        );
        eyre::ensure!(logs.len() <= 200_000, "effect logs exceed bound");
        from = end
            .checked_add(1)
            .ok_or_else(|| eyre::eyre!("log height overflow"))?;
    }
    Ok(logs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{POLL, ledger::Ledger};
    use alloy::{
        consensus::{Receipt, ReceiptEnvelope, ReceiptWithBloom},
        primitives::{Bloom, Bytes},
        providers::ProviderBuilder,
        rpc::types::Block,
        transports::mock::Asserter,
    };
    use serde_json::Value;
    use std::{env, fs};
    use tokio::{process::Command, runtime::Builder, time::Instant};

    fn queue_observation(l1: &Asserter, zones: &[Asserter; 2], diverged: bool) {
        let mut block = Block::<B256>::default();
        block.header.number = 1;
        block.header.hash = B256::repeat_byte(1);
        // Reconciliation and history validation each read one pinned L1 history snapshot.
        for _ in 0..2 {
            l1.push_success(&block);
            l1.push_success(&Vec::<Log>::new());
            l1.push_success(&block);
        }
        for (index, zone) in zones.iter().enumerate() {
            block.header.hash = B256::repeat_byte(if diverged && index == 1 { 2 } else { 1 });
            zone.push_success(&block);
            zone.push_success(&block);
        }
        zones[0].push_success(&"0x1");
        zones[0].push_success(&Vec::<Log>::new());
        l1.push_success(&"0x1");
        l1.push_success(&Vec::<Log>::new());
    }

    // The SDK initializes once per process. A subprocess isolates its output and assertion
    // deduplication without mutating the test runner's environment or changing production code.
    #[test]
    fn settlement_report_fixture() {
        let Ok(case) = env::var("TEMPO_SETTLEMENT_TEST_CASE") else {
            return;
        };
        Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap()
            .block_on(async {
                let dir = tempfile::tempdir().unwrap();
                let ledger = Ledger::open(dir.path()).unwrap();
                if matches!(case.as_str(), "deposit" | "terminal_error") {
                    ledger
                        .append(&Record::Deposit {
                            l1_tx: B256::repeat_byte(3),
                            queue_hash: B256::repeat_byte(4),
                            sender: Address::repeat_byte(5),
                            to: Address::repeat_byte(6),
                            net_amount: 7,
                        })
                        .unwrap();
                }
                if case == "withdrawal" {
                    ledger
                        .append(&Record::Withdrawal {
                            zone_tx: B256::repeat_byte(8),
                            zone_block: 1,
                            sender: Address::repeat_byte(5),
                            to: Address::repeat_byte(6),
                            amount: 9,
                        })
                        .unwrap();
                }
                let l1 = Asserter::new();
                let zones = [Asserter::new(), Asserter::new()];
                if case != "unobserved" {
                    queue_observation(
                        &l1,
                        &zones,
                        matches!(case.as_str(), "divergence" | "recovers"),
                    );
                }
                if case == "recovers" {
                    queue_observation(&l1, &zones, false);
                } else if case == "terminal_error" {
                    l1.push_success(&None::<Block<B256>>);
                }
                // Later RPC errors must not erase the last complete observation.
                for _ in 0..=SETTLE_TIMEOUT.as_millis() / POLL.as_millis() {
                    l1.push_failure_msg("RPC unavailable");
                }
                let ctx = Context {
                    ledger,
                    http: Default::default(),
                    l1_url: "http://l1.invalid".parse().unwrap(),
                    l1: ProviderBuilder::new().connect_mocked_client(l1).erased(),
                    zone_urls: ["http://zone-0.invalid/", "http://zone-1.invalid/"]
                        .map(|url| url.parse().unwrap())
                        .to_vec(),
                    zones: zones
                        .into_iter()
                        .map(|zone| ProviderBuilder::new().connect_mocked_client(zone).erased())
                        .collect(),
                    portal: Address::repeat_byte(10),
                };
                let started = Instant::now();
                let result = ctx.check_settled().await;
                if matches!(case.as_str(), "settled" | "recovers") {
                    result.unwrap();
                    assert!(started.elapsed() < SETTLE_TIMEOUT);
                } else if case == "terminal_error" {
                    assert_eq!(
                        result.unwrap_err().to_string(),
                        "no finalized L1 block for handoff history"
                    );
                } else {
                    assert_eq!(
                        result.unwrap_err().to_string(),
                        "recovery observation timed out"
                    );
                    assert_eq!(started.elapsed(), SETTLE_TIMEOUT);
                }
            });
    }

    #[tokio::test]
    async fn settlement_reports_specific_failures_and_preserves_diagnostics() {
        let names = [
            "Every confirmed deposit is credited or bounced back",
            "Every confirmed withdrawal is paid or returned",
            "Zone nodes converge once faults stop",
        ];
        for case in [
            "deposit",
            "withdrawal",
            "divergence",
            "terminal_error",
            "unobserved",
            "settled",
            "recovers",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let output_path = dir.path().join("assertions.jsonl");
            let output = tokio::time::timeout(
                Duration::from_secs(20),
                Command::new(env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "checks::tests::settlement_report_fixture",
                        "--nocapture",
                    ])
                    .env("TEMPO_SETTLEMENT_TEST_CASE", case)
                    .env("ANTITHESIS_SDK_LOCAL_OUTPUT", &output_path)
                    .kill_on_drop(true)
                    .output(),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(
                output.status.success(),
                "{case}: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let events: Vec<Value> = fs::read_to_string(&output_path)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str::<Value>(line).unwrap())
                .filter_map(|mut event| event.get_mut("antithesis_assert").map(Value::take))
                .filter(|event| event["hit"] == true)
                .collect();
            let deadline = events
                .iter()
                .find(|event| {
                    event["message"] == "Recovery checks finish successfully within their deadline"
                })
                .unwrap();
            assert_eq!(
                deadline["condition"],
                matches!(case, "settled" | "recovers"),
                "{case}"
            );
            for (index, name) in names.iter().enumerate() {
                let event = events.iter().find(|event| event["message"] == *name);
                if case == "unobserved" {
                    assert!(event.is_none(), "no observations must not pass {name}");
                    continue;
                }
                let event = event.unwrap_or_else(|| panic!("{case}: missing assertion {name}"));
                let failed = match index {
                    0 => matches!(case, "deposit" | "terminal_error"),
                    1 => case == "withdrawal",
                    2 => case == "divergence",
                    _ => unreachable!(),
                };
                assert_eq!(event["condition"], !failed, "{case}: {name}");
                if index < 2 {
                    let missing = event["details"]["missing"].as_array().unwrap();
                    assert_eq!(missing.len(), usize::from(failed));
                    if failed && index == 0 {
                        assert_eq!(
                            missing[0]["deposit"]["queue_hash"],
                            json!(B256::repeat_byte(4))
                        );
                    } else if failed {
                        assert_eq!(
                            missing[0]["withdrawal"]["zone_tx"],
                            json!(B256::repeat_byte(8))
                        );
                    }
                } else {
                    let tips = &event["details"]["tips"];
                    assert_eq!(
                        tips["http://zone-0.invalid/"][1],
                        json!(B256::repeat_byte(1))
                    );
                    assert_eq!(
                        tips["http://zone-1.invalid/"][1],
                        json!(B256::repeat_byte(if failed { 2 } else { 1 }))
                    );
                }
            }
        }
    }

    fn withdrawal_fixture(index: u8, sender: Address) -> (Record, TransactionReceipt, B256) {
        let tx = B256::repeat_byte(index);
        let to = Address::repeat_byte(6);
        let event = IZoneOutbox::WithdrawalRequested {
            withdrawalIndex: u64::from(index),
            sender,
            token: PATH_USD_ADDRESS,
            to,
            amount: 9,
            fee: 1,
            memo: B256::ZERO,
            gasLimit: 0,
            fallbackNonce: u64::from(index),
            data: Bytes::new(),
            revealTo: Bytes::new(),
        };
        let log = Log {
            inner: alloy::primitives::Log {
                address: ZONE_OUTBOX_ADDRESS,
                data: event.encode_log_data(),
            },
            ..Default::default()
        };
        let receipt = TransactionReceipt {
            inner: ReceiptEnvelope::Legacy(ReceiptWithBloom::new(
                Receipt {
                    status: true.into(),
                    cumulative_gas_used: 1,
                    logs: vec![log],
                },
                Bloom::ZERO,
            )),
            transaction_hash: tx,
            transaction_index: Some(0),
            block_hash: Some(B256::repeat_byte(1)),
            block_number: Some(1),
            gas_used: 1,
            effective_gas_price: 1,
            blob_gas_used: None,
            blob_gas_price: None,
            from: sender,
            to: Some(ZONE_OUTBOX_ADDRESS),
            contract_address: None,
        };
        (
            Record::Withdrawal {
                zone_tx: tx,
                zone_block: 1,
                sender,
                to,
                amount: 9,
            },
            receipt,
            ZonePortal::Withdrawal::sender_tag(sender, tx, u64::from(index)),
        )
    }

    #[tokio::test]
    async fn equal_value_paid_and_bounced_withdrawals_settle_in_either_order() {
        for reverse in [false, true] {
            for pending in [false, true] {
                for same_sender in [false, true] {
                    let sender = Address::repeat_byte(5);
                    let other = if same_sender {
                        sender
                    } else {
                        Address::repeat_byte(7)
                    };
                    let first = withdrawal_fixture(1, sender);
                    let second = withdrawal_fixture(2, other);
                    let portal = Address::repeat_byte(10);
                    let return_data = if pending {
                        IZoneInbox::WithdrawalBounceBackPending {
                            zoneFallbackRecipient: sender,
                            token: PATH_USD_ADDRESS,
                            amount: 9,
                        }
                        .encode_log_data()
                    } else {
                        IZoneInbox::WithdrawalBounceBackProcessed {
                            zoneFallbackRecipient: sender,
                            token: PATH_USD_ADDRESS,
                            amount: 9,
                        }
                        .encode_log_data()
                    };
                    let returned = Log {
                        inner: alloy::primitives::Log {
                            address: ZONE_INBOX_ADDRESS,
                            data: return_data,
                        },
                        ..Default::default()
                    };
                    let deliveries: Vec<Log> = [(first.2, false), (second.2, true)]
                        .into_iter()
                        .map(|(tag, success)| Log {
                            inner: alloy::primitives::Log {
                                address: portal,
                                data: ZonePortal::WithdrawalProcessed {
                                    to: Address::repeat_byte(6),
                                    senderTag: tag,
                                    token: PATH_USD_ADDRESS,
                                    amount: 9,
                                    callbackSuccess: success,
                                }
                                .encode_log_data(),
                            },
                            ..Default::default()
                        })
                        .collect();
                    let ordered = if reverse {
                        [second, first]
                    } else {
                        [first, second]
                    };
                    let mut block = Block::<B256>::default();
                    block.header.number = 1;
                    block.header.hash = B256::repeat_byte(1);
                    let l1 = Asserter::new();
                    let zones = [Asserter::new(), Asserter::new()];
                    for zone in &zones {
                        zone.push_success(&block);
                        zone.push_success(&block);
                    }
                    zones[0].push_success(&"0x1");
                    zones[0].push_success(&vec![returned]);
                    for (_, receipt, _) in &ordered {
                        zones[0].push_success(receipt);
                    }
                    l1.push_success(&"0x1");
                    l1.push_success(&deliveries);
                    let dir = tempfile::tempdir().unwrap();
                    let ctx = Context {
                        ledger: Ledger::open(dir.path()).unwrap(),
                        http: Default::default(),
                        l1_url: "http://l1.invalid".parse().unwrap(),
                        l1: ProviderBuilder::new().connect_mocked_client(l1).erased(),
                        zone_urls: ["http://zone-0.invalid", "http://zone-1.invalid"]
                            .map(|url| url.parse().unwrap())
                            .to_vec(),
                        zones: zones
                            .into_iter()
                            .map(|zone| ProviderBuilder::new().connect_mocked_client(zone).erased())
                            .collect(),
                        portal,
                    };
                    let state = ctx
                        .settlement(ordered.into_iter().map(|(record, _, _)| record).collect())
                        .await
                        .unwrap();
                    assert!(
                        state.is_settled(),
                        "reverse={reverse}, pending={pending}, same_sender={same_sender}: {:?}",
                        state.unpaid_withdrawals
                    );
                }
            }
        }
    }

    #[test]
    fn withdrawal_delivery_requires_exact_receipt_single_event_and_return() {
        let sender = Address::repeat_byte(5);
        let (record, receipt, tag) = withdrawal_fixture(1, sender);
        let event = (Address::repeat_byte(6), 9, false);
        let mut deliveries = BTreeMap::from([(tag, vec![event])]);
        let mut returned = BTreeMap::from([((sender, 9), 1)]);
        let mut wrong_receipt = receipt.clone();
        wrong_receipt.transaction_hash = B256::repeat_byte(99);
        assert!(!withdrawal_settled(
            &record,
            &wrong_receipt,
            &mut deliveries,
            &mut returned
        ));
        deliveries.get_mut(&tag).unwrap().push(event);
        assert!(!withdrawal_settled(
            &record,
            &receipt,
            &mut deliveries,
            &mut returned
        ));
        assert_eq!(deliveries.get_mut(&tag).unwrap().pop(), Some(event));
        assert!(!withdrawal_settled(
            &record,
            &receipt,
            &mut deliveries,
            &mut BTreeMap::new()
        ));
        assert!(withdrawal_settled(
            &record,
            &receipt,
            &mut deliveries,
            &mut returned
        ));
        assert_eq!(returned[&(sender, 9)], 0);
        assert!(!withdrawal_settled(
            &record,
            &receipt,
            &mut deliveries,
            &mut returned
        ));
    }
}
