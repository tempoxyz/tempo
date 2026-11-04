//! Check commands: properties that hold during faults, after they stop, and after a fault-free run.

use alloy::{
    primitives::{Address, B256, U256},
    providers::{DynProvider, Provider},
    rpc::types::{BlockId, BlockNumberOrTag, Filter, Log},
    sol_types::SolEvent,
};
use antithesis_sdk::{assert_always, assert_sometimes};
use eyre::WrapErr as _;
use futures::{StreamExt as _, TryStreamExt as _, stream};
use serde_json::json;
use std::{collections::BTreeMap, time::Duration};
use tempo_contracts::{
    precompiles::ITIP20,
    zones::{IZoneInbox, ZONE_INBOX_ADDRESS, ZonePortal},
};
use tempo_precompiles::PATH_USD_ADDRESS;

use super::{Context, Record, poll_until, shuffled};

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
        let (height, hash) = self.settled_block().await?;
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
        poll_until(SETTLE_TIMEOUT, async || {
            let current = self.settlement().await?;
            let done = current.is_settled();
            state = Some(current);
            Ok(done)
        })
        .await?;
        let state =
            state.ok_or_else(|| eyre::eyre!("no zone node answered within {SETTLE_TIMEOUT:?}"))?;
        assert_always!(
            state.unsettled_deposits.is_empty(),
            "Every confirmed deposit is credited or bounced back",
            &json!({ "missing": state.unsettled_deposits })
        );
        assert_always!(
            state.unpaid_withdrawals.is_empty(),
            "Every confirmed withdrawal is paid on L1",
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
        Ok(())
    }

    pub(super) async fn check_ledger(&self) -> eyre::Result<()> {
        self.check_settled().await?;
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
    async fn settlement(&self) -> eyre::Result<Settlement> {
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
        let mut credited: BTreeMap<(Address, Address, u128), usize> = BTreeMap::new();
        let mut bounced: BTreeMap<(Address, u128), usize> = BTreeMap::new();
        for log in logs(zone, Filter::new().address(ZONE_INBOX_ADDRESS), zone_height).await? {
            if let Ok(event) = IZoneInbox::DepositProcessed::decode_log(&log.inner) {
                *credited
                    .entry((event.sender, event.to, event.amount))
                    .or_default() += 1;
            } else if let Ok(event) = IZoneInbox::DepositFailed::decode_log(&log.inner) {
                *bounced.entry((event.sender, event.amount)).or_default() += 1;
            }
        }
        let l1_height = self.l1.get_block_number().await?;
        let mut paid: BTreeMap<(Address, u128), usize> = BTreeMap::new();
        // A rejected deposit is only settled once L1 refunds it, paid out or parked for claiming.
        // Keyed by refund recipient and the amount before the bounce-back fee.
        let mut refunded: BTreeMap<(Address, u128), usize> = BTreeMap::new();
        for log in logs(&self.l1, Filter::new().address(self.portal), l1_height).await? {
            // A failed delivery also emits WithdrawalProcessed, with callbackSuccess false, and
            // bounces the funds back to the zone instead of paying `to`.
            if let Ok(event) = ZonePortal::WithdrawalProcessed::decode_log(&log.inner)
                && event.callbackSuccess
            {
                *paid.entry((event.to, event.amount)).or_default() += 1;
            } else if let Ok(event) = ZonePortal::DepositBounceBack::decode_log(&log.inner) {
                *refunded
                    .entry((
                        event.tempoRefundRecipient,
                        event.amount + event.bouncebackFee,
                    ))
                    .or_default() += 1;
            } else if let Ok(event) = ZonePortal::DepositBounceBackPending::decode_log(&log.inner) {
                *refunded
                    .entry((
                        event.tempoRefundRecipient,
                        event.amount + event.bouncebackFee,
                    ))
                    .or_default() += 1;
            }
        }

        let records = self.ledger.records()?;
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
                    sender,
                    to,
                    net_amount,
                    ..
                } => {
                    // Drivers name the sender as the deposit's refund recipient.
                    let settled = take(&mut credited, (sender, to, net_amount))
                        || (take(&mut bounced, (sender, net_amount))
                            && take(&mut refunded, (sender, net_amount)));
                    if !settled {
                        unsettled_deposits.push(record);
                    }
                }
                Record::Withdrawal { to, amount, .. } => {
                    if !take(&mut paid, (to, amount)) {
                        unpaid_withdrawals.push(record);
                    }
                }
                Record::Account { .. } | Record::Transfer { .. } => {}
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
async fn logs(provider: &DynProvider, filter: Filter, to: u64) -> eyre::Result<Vec<Log>> {
    let mut logs = Vec::new();
    let mut from = 0;
    while from <= to {
        let end = to.min(from + LOG_CHUNK - 1);
        logs.extend(
            provider
                .get_logs(&filter.clone().from_block(from).to_block(end))
                .await
                .wrap_err_with(|| format!("failed reading logs in {from}..={end}"))?,
        );
        from = end + 1;
    }
    Ok(logs)
}
