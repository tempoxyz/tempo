//! Antithesis test commands for the zone test environment in `zones/antithesis`.
//!
//! Each subcommand is one test command: drivers send deposits, withdrawals and TIP-20 transfers
//! between accounts the workload keeps creating, so the L1 and zone tries grow during a run, and
//! checks assert what must hold under faults and after recovery. Commands share state through the
//! [`Ledger`] in the workload container.

use alloy::{
    eips::Encodable2718 as _,
    primitives::{Address, B256, Bytes, I256, TxKind, U256},
    providers::{
        DynProvider, PendingTransactionBuilder, PendingTransactionError, Provider, ProviderBuilder,
    },
    rpc::types::{BlockId, Filter, TransactionReceipt},
    signers::{SignerSync as _, local::PrivateKeySigner},
    sol_types::{SolCall as _, SolEvent as _},
    transports::{TransportError, http::reqwest},
};
use antithesis_sdk::{
    assert_always, assert_sometimes, assert_sometimes_greater_than, random::get_random,
};
use eyre::{OptionExt as _, WrapErr as _, eyre};
use serde_json::json;
use std::{collections::BTreeSet, path::PathBuf, time::Duration};
use tempo_contracts::{
    precompiles::ITIP20,
    zones::{
        DepositPayload, IZoneInbox, IZoneOutbox, ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS,
        ZonePortal,
    },
};
use tempo_precompiles::PATH_USD_ADDRESS;
use tempo_primitives::{
    TempoTransaction,
    transaction::{Call, calc_gas_balance_spending},
};
use zone_precompiles::ecies::encrypt_deposit;

use ledger::{Account, Lease, Ledger, Record};

mod checks;
mod collide;
mod ledger;
mod proofs;

/// Dev accounts 8..=19 of the test mnemonic fund deposits. 0 administers the portal and 5..=7
/// are the sequencers, which pay their own settlement gas.
const FUNDER_INDICES: std::ops::RangeInclusive<u32> = 8..=19;
/// pathUSD has 6 decimals.
const USD: u128 = 1_000_000;
/// Zone accounts `first-seed` funds so transfers and withdrawals can start right away.
const SEED_ACCOUNTS: usize = 8;
const SEED_AMOUNT: u128 = 1_000 * USD;
/// What a new L1 depositor receives on top of its deposit, for L1 fees.
const NEW_DEPOSITOR_FEE_BUDGET: u128 = 10 * USD;
/// Below this zone balance an account is not picked as a sender, so fees always fit.
const MIN_SENDER_BALANCE: u128 = USD;
/// Gas limit for zone TIP-20 calls. Fixed so a failing call is mined and shows as reverted.
const TIP20_TX_GAS: u64 = 500_000;
/// Gas limit for `ZonePortal.deposit`. Fixed so a deposit the portal's caps reject is mined
/// and shows as reverted, instead of failing gas estimation.
const DEPOSIT_TX_GAS: u64 = 2_000_000;
/// Gas limit for `ZoneOutbox.requestWithdrawal`.
const WITHDRAWAL_TX_GAS: u64 = 10_000_000;
/// Bound on each RPC request, so a paused or partitioned node fails the call instead of hanging.
const RPC_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound on waiting for a transaction's receipt.
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(60);
/// How long a driver watches for its deposit or withdrawal to land on the other chain.
const BRIDGE_WAIT: Duration = Duration::from_secs(90);
const POLL: Duration = Duration::from_millis(500);
/// Most senders one burst leases.
const BURST_SENDERS: u128 = 16;
/// Most approvals one batched Tempo transaction carries.
const BATCH_APPROVALS: u128 = 32;
/// Gas a batched approval transaction gets on top of its calls.
const BATCH_BASE_GAS: u64 = 100_000;
/// Gas each call of a batched approval transaction gets.
const BATCH_CALL_GAS: u64 = 400_000;
/// Hot spenders each owner approves, so repeated approvals overwrite and clear earlier ones.
const APPROVAL_SPENDERS: u64 = 64;
/// All spenders an owner may approve: approvals outside the hot set keep adding new allowance
/// slots, so the token's storage trie keeps growing deeper.
const APPROVAL_SPENDERS_WIDE: u64 = 4096;
/// How many leased-account candidates a driver tries before giving up for this run.
const SENDER_CANDIDATES: usize = 16;
/// Transfers one fanout keeps pending at once. A follower forwards a sender's transactions to the
/// leader in bursts of at most four per peer, so a larger chunk sent to a follower never reaches
/// the leader.
const FANOUT_CHUNK: u128 = 4;

/// Antithesis test commands; see `zones/antithesis/README.md`.
#[derive(Debug, clap::Parser)]
pub(crate) struct Antithesis {
    /// Tempo L1 HTTP RPC URL.
    #[arg(long, env = "L1_RPC_URL", default_value = "http://10.20.0.10:8545")]
    l1_rpc_url: reqwest::Url,

    /// HTTP RPC URLs of every zone node. Drivers send to a random one; checks compare all.
    #[arg(
        long,
        env = "ZONE_RPC_URLS",
        value_delimiter = ',',
        default_value = "http://10.20.0.11:8545,http://10.20.0.12:8545,http://10.20.0.13:8545,http://10.20.0.20:8545"
    )]
    zone_rpc_urls: Vec<reqwest::Url>,

    /// The `zone.json` that `create-zone` wrote, for the portal address.
    #[arg(long, env = "ZONE_JSON", default_value = "/shared/zone.json")]
    zone_json: PathBuf,

    /// Directory holding the workload ledger and account leases.
    #[arg(long, env = "WORKLOAD_STATE_DIR", default_value = "/state")]
    state_dir: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Approves the portal for every funder and funds the first zone accounts.
    Seed,
    /// Deposits from a funder or a new L1 account to a new or existing zone account.
    Deposit,
    /// Transfers pathUSD inside the zone to a new or existing account.
    Transfer,
    /// Withdraws from the zone to a new or existing L1 address.
    Withdraw,
    /// Funds a batch of new zone accounts from one sender.
    Fanout,
    /// Sends a sender's whole balance to another account, deleting its balance slot.
    Sweep,
    /// Sets, changes and clears a batch of allowances, inserting, updating and deleting slots.
    Approve,
    /// Sends transfers from many senders at once, so they land in the same blocks.
    Burst,
    /// Sets allowances whose storage-trie keys share a long prefix, or rewrites earlier ones.
    Collide,
    /// Checks that state proofs verify against the block's state root and that nodes agree.
    CheckProofs,
    /// Checks that zone nodes agree with L1 settlement while faults run.
    CheckConsistency,
    /// Checks that zone nodes never hold different blocks at a height or replace one.
    CheckForks,
    /// After faults stop: every confirmed deposit and withdrawal lands and nodes converge.
    CheckSettled,
    /// After a fault-free completion: `check-settled`, then each account's zone balance equals
    /// the transfers its zone logs record.
    CheckLedger,
}

impl Antithesis {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        antithesis_sdk::antithesis_init();
        let ctx = Context::init(&self).await?;
        let driver = match self.command {
            Command::Seed => return ctx.seed().await,
            Command::CheckConsistency => return ctx.check_consistency().await,
            Command::CheckForks => return ctx.check_forks().await,
            Command::CheckSettled => return ctx.check_settled().await,
            Command::CheckLedger => return ctx.check_ledger().await,
            Command::CheckProofs => return ctx.check_proofs().await,
            Command::Deposit => ctx.deposit().await,
            Command::Transfer => ctx.transfer().await,
            Command::Withdraw => ctx.withdraw().await,
            Command::Fanout => ctx.fanout().await,
            Command::Sweep => ctx.sweep().await,
            Command::Approve => ctx.approve().await,
            Command::Burst => ctx.burst().await,
            Command::Collide => ctx.collide().await,
        };
        // Under faults, or on a node that lags the sequencer, a send can be rejected (nonce too
        // low) or never confirm. Drivers record only confirmed operations, so such an RPC error
        // ends the run without failing the command. Any other error still fails it.
        match driver {
            Err(error) if is_rpc_error(&error) => {
                println!("driver gave up: {error:#}");
                Ok(())
            }
            result => result,
        }
    }
}

/// Connections and state every command uses.
struct Context {
    ledger: Ledger,
    http: reqwest::Client,
    l1_url: reqwest::Url,
    l1: DynProvider,
    zone_urls: Vec<reqwest::Url>,
    zones: Vec<DynProvider>,
    portal: Address,
}

impl Context {
    async fn init(args: &Antithesis) -> eyre::Result<Self> {
        eyre::ensure!(!args.zone_rpc_urls.is_empty(), "no zone RPC URLs");
        let zone_json: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&args.zone_json)
                .wrap_err_with(|| format!("failed reading {}", args.zone_json.display()))?,
        )?;
        let portal = zone_json["portal"]
            .as_str()
            .ok_or_eyre("zone.json has no portal")?
            .parse()?;
        let http = reqwest::Client::builder().timeout(RPC_TIMEOUT).build()?;
        let connect = |url: &reqwest::Url| {
            ProviderBuilder::new()
                .connect_reqwest(http.clone(), url.clone())
                .erased()
        };
        Ok(Self {
            ledger: Ledger::open(&args.state_dir)?,
            l1: connect(&args.l1_rpc_url),
            zones: args.zone_rpc_urls.iter().map(connect).collect(),
            l1_url: args.l1_rpc_url.clone(),
            zone_urls: args.zone_rpc_urls.clone(),
            http,
            portal,
        })
    }

    async fn seed(&self) -> eyre::Result<()> {
        futures::future::try_join_all(
            FUNDER_INDICES
                .map(async |index| self.ensure_portal_allowance(&Account::at(index)?).await),
        )
        .await?;
        let funder = Account::at(*FUNDER_INDICES.start())?;
        let zone = self.random_zone();
        let mut pending = Vec::with_capacity(SEED_ACCOUNTS);
        for _ in 0..SEED_ACCOUNTS {
            let account = self.ledger.new_account()?;
            let from_block = zone.get_block_number().await?;
            let deposit = self
                .send_deposit(&funder, account.address(), SEED_AMOUNT)
                .await?
                .ok_or_else(|| eyre!("seed deposit to {} reverted", account.address()))?;
            pending.push((deposit, from_block));
        }
        for (deposit, from_block) in pending {
            let outcome = self
                .wait_deposit_outcome(zone, &deposit, from_block)
                .await?;
            eyre::ensure!(
                outcome == Some(DepositOutcome::Credited),
                "seed deposit {deposit:?} was not credited within {BRIDGE_WAIT:?}: {outcome:?}"
            );
        }
        println!("seed: funded {SEED_ACCOUNTS} zone accounts");
        Ok(())
    }

    async fn deposit(&self) -> eyre::Result<()> {
        let amount = random_between(USD, 50 * USD);
        // A quarter of deposits come from a new L1 account, growing the L1 trie as well.
        let new_depositor = random_below(4) == 0;
        let (sender, _lease) = if new_depositor {
            let Some((funder, _funder_lease)) = self.lease_funder()? else {
                return Ok(());
            };
            let depositor = self.ledger.new_account()?;
            let lease = self
                .ledger
                .try_lease(&depositor)?
                .ok_or_eyre("a new account is already leased")?;
            let receipt = ITIP20::new(PATH_USD_ADDRESS, self.wallet(&funder, &self.l1_url))
                .transfer(
                    depositor.address(),
                    U256::from(amount + NEW_DEPOSITOR_FEE_BUDGET),
                )
                .send()
                .await?
                .with_timeout(Some(RECEIPT_TIMEOUT))
                .get_receipt()
                .await?;
            eyre::ensure!(receipt.status(), "funding new L1 depositor reverted");
            self.ensure_portal_allowance(&depositor).await?;
            (depositor, lease)
        } else {
            let Some(funder) = self.lease_funder()? else {
                return Ok(());
            };
            funder
        };

        let (to, new_recipient) = self.pick_recipient(sender.address())?;
        let zone = self.random_zone();
        let from_block = zone.get_block_number().await?;
        let Some(deposit) = self.send_deposit(&sender, to, amount).await? else {
            // Deposits revert legitimately when the portal's unprocessed-deposit cap is reached
            // because faults stall the zone.
            println!("deposit: reverted");
            return Ok(());
        };
        let outcome = self
            .wait_deposit_outcome(zone, &deposit, from_block)
            .await?;
        let credited = outcome == Some(DepositOutcome::Credited);
        assert_sometimes!(
            credited,
            "Deposit is credited on the zone",
            &json!({ "deposit": deposit })
        );
        assert_sometimes!(
            credited && new_recipient,
            "Deposit creates a new zone account",
            &json!({ "deposit": deposit })
        );
        assert_sometimes!(
            credited && new_depositor,
            "Deposit from a new L1 account is credited",
            &json!({ "deposit": deposit })
        );
        println!("deposit: {deposit:?} {outcome:?}");
        Ok(())
    }

    async fn transfer(&self) -> eyre::Result<()> {
        let node = random_index(self.zones.len());
        let Some((sender, balance, _lease)) = self.lease_zone_sender(&self.zones[node]).await?
        else {
            return Ok(());
        };
        let (to, new_recipient) = self.pick_recipient(sender.address())?;
        let amount = random_between(1, balance / 4);
        let url = &self.zone_urls[node];
        let zone = self.wallet(&sender, url);
        let gas_price = zone.get_gas_price().await?;
        let receipt = ITIP20::new(PATH_USD_ADDRESS, &zone)
            .transfer(to, U256::from(amount))
            .gas(TIP20_TX_GAS)
            .gas_price(gas_price)
            .send()
            .await?
            .with_timeout(Some(RECEIPT_TIMEOUT))
            .get_receipt()
            .await?;
        let details = json!({
            "tx": receipt.transaction_hash,
            "from": sender.address(),
            "to": to,
            "amount": amount.to_string(),
            "balance": balance.to_string(),
        });
        // The fee comes out of the same pathUSD balance, so a funded transfer needs both.
        let max_fee: u128 = calc_gas_balance_spending(TIP20_TX_GAS, gas_price).try_into()?;
        let funded_revert = !receipt.status()
            && self
                .covered_before(&zone, &receipt, sender.address(), amount + max_fee)
                .await?;
        assert_always!(!funded_revert, "Funded zone transfer succeeds", &details);
        if !receipt.status() {
            return Ok(());
        }
        let zone_block = receipt.block_number.ok_or_eyre("receipt has no block")?;
        self.ledger.append(&Record::Transfer {
            zone_tx: receipt.transaction_hash,
            zone_block,
            from: sender.address(),
            to,
            amount,
        })?;
        if new_recipient {
            // Nothing else can spend from a new account before it holds a balance, so the
            // credit must be visible at the transfer's block.
            let credited = ITIP20::new(PATH_USD_ADDRESS, &zone)
                .balanceOf(to)
                .from(to)
                .block(BlockId::number(zone_block))
                .call()
                .await?;
            assert_always!(
                credited >= U256::from(amount),
                "Transfer to a new zone account credits it",
                &details
            );
        }
        assert_sometimes!(
            new_recipient,
            "Transfer creates a new zone account",
            &details
        );
        println!("transfer: {amount} {} -> {to}", sender.address());
        Ok(())
    }

    /// Leases up to BURST_SENDERS senders on one node and sends their transfers at once, so many
    /// independent transactions land in the same few blocks. About half the senders empty their
    /// whole balance in one transfer, deleting their balance slot, while the others each send up
    /// to FANOUT_CHUNK transfers, sometimes to an emptying sender, so slots are deleted and
    /// recreated in the same blocks.
    async fn burst(&self) -> eyre::Result<()> {
        let node = random_index(self.zones.len());
        let url = &self.zone_urls[node];
        let mut senders = Vec::new();
        for _ in 0..random_between(2, BURST_SENDERS) {
            match self.lease_zone_sender(&self.zones[node]).await? {
                Some(leased) => senders.push(leased),
                None => break,
            }
        }
        if senders.is_empty() {
            return Ok(());
        }
        let gas_price = self.zones[node].get_gas_price().await?;
        let max_fee: u128 = calc_gas_balance_spending(TIP20_TX_GAS, gas_price).try_into()?;
        let emptying: Vec<bool> = senders.iter().map(|_| random_below(2) == 0).collect();
        let emptied: Vec<Address> = senders
            .iter()
            .zip(&emptying)
            .filter(|(_, empties)| **empties)
            .map(|((sender, _, _), _)| sender.address())
            .collect();
        let mut pending = Vec::new();
        for ((sender, balance, _), empties) in senders.iter().zip(&emptying) {
            let zone = self.wallet(sender, url);
            let mut nonce = zone
                .get_transaction_count(sender.address())
                .pending()
                .await?;
            let token = ITIP20::new(PATH_USD_ADDRESS, &zone);
            if *empties {
                let Some(to) = self.random_existing_account(Some(sender.address()))? else {
                    continue;
                };
                let to = to.address();
                // The fee is charged on gas used, so leaving exactly the estimated fee empties
                // the account when the estimate holds.
                let gas = token
                    .transfer(to, U256::from(1))
                    .gas_price(gas_price)
                    .estimate_gas()
                    .await?;
                let fee: u128 = calc_gas_balance_spending(gas, gas_price).try_into()?;
                let Some(amount) = balance.checked_sub(fee).filter(|amount| *amount > 0) else {
                    continue;
                };
                let tx = token
                    .transfer(to, U256::from(amount))
                    .gas(gas)
                    .gas_price(gas_price)
                    .nonce(nonce)
                    .send()
                    .await?;
                pending.push((zone.clone(), sender.address(), to, amount, fee, tx));
                continue;
            }
            let count = random_between(1, FANOUT_CHUNK);
            let amount = (balance / 4) / count;
            if amount == 0 {
                continue;
            }
            for _ in 0..count {
                let to = match random_choice(emptied.clone()) {
                    Some(to) if to != sender.address() && random_below(3) == 0 => to,
                    _ => self.pick_recipient(sender.address())?.0,
                };
                let tx = token
                    .transfer(to, U256::from(amount))
                    .gas(TIP20_TX_GAS)
                    .gas_price(gas_price)
                    .nonce(nonce)
                    .send()
                    .await?;
                nonce += 1;
                pending.push((zone.clone(), sender.address(), to, amount, max_fee, tx));
            }
        }
        let mut blocks = BTreeSet::new();
        let mut emptied_in = Vec::new();
        let mut credited_in = Vec::new();
        let sent = pending.len();
        for (zone, from, to, amount, fee, tx) in pending {
            let receipt = tx.with_timeout(Some(RECEIPT_TIMEOUT)).get_receipt().await?;
            let funded_revert = !receipt.status()
                && self
                    .covered_before(&zone, &receipt, from, amount + fee)
                    .await?;
            assert_always!(
                !funded_revert,
                "Funded zone transfer succeeds",
                &json!({ "tx": receipt.transaction_hash, "from": from, "to": to })
            );
            if !receipt.status() {
                continue;
            }
            let zone_block = receipt.block_number.ok_or_eyre("receipt has no block")?;
            blocks.insert(zone_block);
            if emptied.contains(&from) {
                emptied_in.push((from, zone_block));
            }
            if emptied.contains(&to) {
                credited_in.push((to, zone_block));
            }
            self.ledger.append(&Record::Transfer {
                zone_tx: receipt.transaction_hash,
                zone_block,
                from,
                to,
                amount,
            })?;
        }
        let refilled = emptied_in
            .iter()
            .filter(|emptied| credited_in.contains(emptied))
            .count();
        assert_sometimes!(
            sent >= 16 && blocks.len() <= 2,
            "A burst lands 16 or more transfers in at most two blocks",
            &json!({ "senders": senders.len(), "sent": sent, "blocks": blocks })
        );
        assert_sometimes!(
            refilled > 0,
            "A burst empties and credits the same account in one block",
            &json!({ "emptied": emptied_in, "credited": credited_in })
        );
        println!(
            "burst: {sent} transfers from {} senders in {} blocks, {} emptied, {refilled} refilled",
            senders.len(),
            blocks.len(),
            emptied_in.len()
        );
        Ok(())
    }

    async fn withdraw(&self) -> eyre::Result<()> {
        let node = random_index(self.zones.len());
        let Some((sender, balance, _lease)) = self.lease_zone_sender(&self.zones[node]).await?
        else {
            return Ok(());
        };
        // Half of withdrawals pay a new L1 address, growing the L1 trie.
        let new_recipient = random_below(2) == 0;
        let to = if new_recipient {
            self.ledger.new_account()?.address()
        } else {
            self.random_existing_account(None)?
                .map_or(sender.address(), |account| account.address())
        };
        let url = &self.zone_urls[node];
        let zone = self.wallet(&sender, url);
        let outbox = IZoneOutbox::new(ZONE_OUTBOX_ADDRESS, &zone);
        let fee = outbox.calculateWithdrawalFee(0).call().await?;
        let Some(amount) = (balance / 4).checked_sub(fee).filter(|amount| *amount > 0) else {
            return Ok(());
        };
        let amount = random_between(1, amount);
        let gas_price = zone.get_gas_price().await?;
        let token = ITIP20::new(PATH_USD_ADDRESS, &zone);
        if token
            .allowance(sender.address(), ZONE_OUTBOX_ADDRESS)
            .call()
            .await?
            < U256::from(amount + fee)
        {
            let receipt = token
                .approve(ZONE_OUTBOX_ADDRESS, U256::MAX)
                .gas(TIP20_TX_GAS)
                .gas_price(gas_price)
                .send()
                .await?
                .with_timeout(Some(RECEIPT_TIMEOUT))
                .get_receipt()
                .await?;
            assert_always!(
                receipt.status(),
                "Funded zone approval succeeds",
                &json!({ "tx": receipt.transaction_hash, "owner": sender.address() })
            );
            if !receipt.status() {
                return Ok(());
            }
        }
        let l1_from_block = self.l1.get_block_number().await?;
        let receipt = outbox
            .requestWithdrawal(
                PATH_USD_ADDRESS,
                to,
                amount,
                B256::ZERO,
                0,
                sender.address(),
                Bytes::new(),
                Bytes::new(),
            )
            .gas(WITHDRAWAL_TX_GAS)
            .gas_price(gas_price)
            .send()
            .await?
            .with_timeout(Some(RECEIPT_TIMEOUT))
            .get_receipt()
            .await?;
        if !receipt.status() {
            // The sequencer's per-block withdrawal cap can reject a funded request.
            println!("withdraw: reverted {}", receipt.transaction_hash);
            return Ok(());
        }
        let withdrawal = Record::Withdrawal {
            zone_tx: receipt.transaction_hash,
            zone_block: receipt.block_number.ok_or_eyre("receipt has no block")?,
            sender: sender.address(),
            to,
            amount,
        };
        self.ledger.append(&withdrawal)?;
        let paid = self.wait_withdrawal_paid(to, amount, l1_from_block).await?;
        assert_sometimes!(
            paid,
            "Withdrawal is paid on L1",
            &json!({ "withdrawal": withdrawal })
        );
        assert_sometimes!(
            paid && new_recipient,
            "Withdrawal pays a new L1 address",
            &json!({ "withdrawal": withdrawal })
        );
        println!("withdraw: {withdrawal:?} paid={paid}");
        Ok(())
    }

    async fn fanout(&self) -> eyre::Result<()> {
        let node = random_index(self.zones.len());
        let Some((sender, balance, _lease)) = self.lease_zone_sender(&self.zones[node]).await?
        else {
            return Ok(());
        };
        let url = &self.zone_urls[node];
        let zone = self.wallet(&sender, url);
        let gas_price = zone.get_gas_price().await?;
        // The fee comes out of the same pathUSD balance, so a funded transfer needs both.
        let max_fee: u128 = calc_gas_balance_spending(TIP20_TX_GAS, gas_price).try_into()?;
        // Fees stay within half the balance and transfers take a quarter, so the batch always
        // fits what the sender holds.
        let count = random_between(50, 200).min((balance / 2) / max_fee.max(1));
        if count == 0 {
            return Ok(());
        }
        let amount = (balance / 4) / count;
        if amount == 0 {
            return Ok(());
        }
        let mut nonce = zone
            .get_transaction_count(sender.address())
            .pending()
            .await?;
        let token = ITIP20::new(PATH_USD_ADDRESS, &zone);
        // Only FANOUT_CHUNK transfers are pending at once, so the batch goes out
        // in chunks, each confirmed before the next.
        let mut remaining = count;
        // Half the time the transfers go out as the calls of Tempo transactions, up to
        // BATCH_APPROVALS per transaction, so one block creates many balance slots.
        if random_below(2) == 0 {
            while remaining > 0 {
                let calls = remaining.min(BATCH_APPROVALS);
                remaining -= calls;
                if !self
                    .fanout_batch(&zone, &sender, gas_price, calls, amount, nonce)
                    .await?
                {
                    break;
                }
                nonce += 1;
            }
        }
        while remaining > 0 {
            let chunk = remaining.min(FANOUT_CHUNK);
            remaining -= chunk;
            let mut pending: Vec<(Address, PendingTransactionBuilder<_>)> = Vec::new();
            for _ in 0..chunk {
                let to = self.ledger.new_sink_account()?.address();
                let tx = token
                    .transfer(to, U256::from(amount))
                    .gas(TIP20_TX_GAS)
                    .gas_price(gas_price)
                    .nonce(nonce)
                    .send()
                    .await?;
                nonce += 1;
                pending.push((to, tx));
            }
            for (to, tx) in pending {
                let receipt = tx.with_timeout(Some(RECEIPT_TIMEOUT)).get_receipt().await?;
                let zone_block = receipt.block_number.ok_or_eyre("receipt has no block")?;
                let funded_revert = !receipt.status()
                    && self
                        .covered_before(&zone, &receipt, sender.address(), amount + max_fee)
                        .await?;
                assert_always!(
                    !funded_revert,
                    "Funded zone transfer succeeds",
                    &json!({ "tx": receipt.transaction_hash, "from": sender.address(), "to": to })
                );
                if receipt.status() {
                    self.ledger.append(&Record::Transfer {
                        zone_tx: receipt.transaction_hash,
                        zone_block,
                        from: sender.address(),
                        to,
                        amount,
                    })?;
                }
            }
        }
        let accounts = self.ledger.accounts()?.len();
        assert_sometimes_greater_than!(
            accounts,
            1_000,
            "Workload creates more than 1000 accounts",
            &json!({ "accounts": accounts })
        );
        assert_sometimes_greater_than!(
            accounts,
            10_000,
            "Workload creates more than 10000 accounts",
            &json!({ "accounts": accounts })
        );
        println!(
            "fanout: {count} new accounts from {}, {accounts} total",
            sender.address()
        );
        Ok(())
    }

    /// Sends a batch of approvals from one sender to spenders drawn from a fixed per-sender set,
    /// so allowance slots in pathUSD's storage trie are created, overwritten and, for zero
    /// amounts, deleted, many per block. Afterwards every touched allowance must read back as the
    /// last amount set.
    async fn approve(&self) -> eyre::Result<()> {
        let node = random_index(self.zones.len());
        let Some((sender, balance, _lease)) = self.lease_zone_sender(&self.zones[node]).await?
        else {
            return Ok(());
        };
        let url = &self.zone_urls[node];
        let zone = self.wallet(&sender, url);
        let gas_price = zone.get_gas_price().await?;
        let max_fee: u128 = calc_gas_balance_spending(TIP20_TX_GAS, gas_price).try_into()?;
        // Fees stay within half the balance.
        let count = random_between(8, 64).min((balance / 2) / max_fee.max(1));
        if count == 0 {
            return Ok(());
        }
        let token = ITIP20::new(PATH_USD_ADDRESS, &zone);
        let mut nonce = zone
            .get_transaction_count(sender.address())
            .pending()
            .await?;
        // The last amount each spender was given, and the block of the last approval.
        let mut expected: Vec<(Address, U256)> = Vec::new();
        let mut last_block = None;
        let mut remaining = count;
        // Half the time the approvals go out as calls of one Tempo transaction, so a single
        // block writes many slots of the same storage trie at once.
        if random_below(2) == 0 {
            remaining = 0;
            let calls = count.min(BATCH_APPROVALS);
            if let Some((batch, block)) = self
                .approve_batch(&zone, &sender, balance, gas_price, calls, nonce)
                .await?
            {
                expected = batch;
                last_block = Some(block);
            }
            nonce += 1;
        }
        while remaining > 0 {
            let chunk = remaining.min(FANOUT_CHUNK);
            remaining -= chunk;
            let mut pending: Vec<(Address, U256, PendingTransactionBuilder<_>)> = Vec::new();
            for _ in 0..chunk {
                let spender = random_spender(sender.address());
                // A third of approvals clear the allowance, deleting its slot.
                let amount = if random_below(3) == 0 {
                    U256::ZERO
                } else {
                    U256::from(random_between(1, u128::from(u64::MAX)))
                };
                let tx = token
                    .approve(spender, amount)
                    .gas(TIP20_TX_GAS)
                    .gas_price(gas_price)
                    .nonce(nonce)
                    .send()
                    .await?;
                nonce += 1;
                pending.push((spender, amount, tx));
            }
            for (spender, amount, tx) in pending {
                let receipt = tx.with_timeout(Some(RECEIPT_TIMEOUT)).get_receipt().await?;
                let funded_revert = !receipt.status()
                    && self
                        .covered_before(&zone, &receipt, sender.address(), max_fee)
                        .await?;
                assert_always!(
                    !funded_revert,
                    "Funded zone approval succeeds",
                    &json!({ "tx": receipt.transaction_hash, "owner": sender.address() })
                );
                if receipt.status() {
                    expected.retain(|(seen, _)| *seen != spender);
                    expected.push((spender, amount));
                }
                last_block = receipt.block_number.max(last_block);
            }
        }
        let Some(block) = last_block else {
            return Ok(());
        };
        // Sends an earlier command gave up on can still land after this command's last one, in
        // the same block, and overwrite its allowances: then the block's end state is theirs.
        let nonce_after = zone
            .get_transaction_count(sender.address())
            .block_id(BlockId::number(block))
            .await?;
        if nonce_after > nonce {
            println!(
                "approve: later sends from {} landed in block {block}, skipping readback",
                sender.address()
            );
            return Ok(());
        }
        let cleared = expected
            .iter()
            .filter(|(_, amount)| amount.is_zero())
            .count();
        for (spender, amount) in &expected {
            let read = token
                .allowance(sender.address(), *spender)
                .block(BlockId::number(block))
                .call()
                .await?;
            assert_always!(
                read == *amount,
                "Zone allowance reads back the last approved amount",
                &json!({
                    "owner": sender.address(),
                    "spender": spender,
                    "approved": amount,
                    "read": read,
                    "block": block,
                })
            );
        }
        assert_sometimes!(
            cleared > 0 && cleared < expected.len(),
            "Approval batch both sets and clears allowances",
            &json!({ "owner": sender.address(), "spenders": expected.len(), "cleared": cleared })
        );
        println!(
            "approve: {count} approvals to {} spenders ({cleared} cleared) from {}",
            expected.len(),
            sender.address()
        );
        Ok(())
    }

    /// Sends `calls` transfers of `amount` to new sink accounts from `sender` as the calls of
    /// one Tempo transaction at `nonce`, and records them. Returns whether it landed.
    async fn fanout_batch(
        &self,
        zone: &DynProvider,
        sender: &Account,
        gas_price: u128,
        calls: u128,
        amount: u128,
        nonce: u64,
    ) -> eyre::Result<bool> {
        let recipients = (0..calls)
            .map(|_| Ok(self.ledger.new_sink_account()?.address()))
            .collect::<eyre::Result<Vec<Address>>>()?;
        let calls = recipients
            .iter()
            .map(|to| Call {
                to: TxKind::Call(PATH_USD_ADDRESS),
                value: U256::ZERO,
                input: ITIP20::transferCall {
                    to: *to,
                    amount: U256::from(amount),
                }
                .abi_encode()
                .into(),
            })
            .collect();
        let Some((hash, block, status)) = self
            .send_calls(zone, sender, gas_price, calls, nonce)
            .await?
        else {
            return Ok(false);
        };
        assert_sometimes!(
            status,
            "Batched zone transfers succeed",
            &json!({ "tx": hash, "from": sender.address(), "calls": recipients.len() })
        );
        if !status {
            println!("fanout: batch {hash} reverted");
            return Ok(false);
        }
        for to in recipients {
            self.ledger.append(&Record::Transfer {
                zone_tx: hash,
                zone_block: block,
                from: sender.address(),
                to,
                amount,
            })?;
        }
        Ok(true)
    }

    /// Signs and sends `calls` from `sender` as one Tempo transaction at `nonce` and waits for
    /// its receipt. Returns its hash, block and status, or `None` when it was not confirmed
    /// within the timeout.
    async fn send_calls(
        &self,
        zone: &DynProvider,
        sender: &Account,
        gas_price: u128,
        calls: Vec<Call>,
        nonce: u64,
    ) -> eyre::Result<Option<(B256, u64, bool)>> {
        let tx = TempoTransaction {
            chain_id: zone.get_chain_id().await?,
            max_fee_per_gas: gas_price,
            max_priority_fee_per_gas: gas_price,
            gas_limit: BATCH_BASE_GAS + BATCH_CALL_GAS * calls.len() as u64,
            calls,
            nonce,
            ..Default::default()
        };
        let signature = sender.signer.sign_hash_sync(&tx.signature_hash())?;
        let encoded = tx.into_signed(signature.into()).encoded_2718();
        let hash = *zone.send_raw_transaction(&encoded).await?.tx_hash();
        let mut receipt = None;
        poll_until(RECEIPT_TIMEOUT, async || {
            receipt = zone
                .raw_request::<_, Option<serde_json::Value>>(
                    "eth_getTransactionReceipt".into(),
                    (hash,),
                )
                .await?;
            Ok(receipt.is_some())
        })
        .await?;
        let Some(receipt) = receipt else {
            println!("batch {hash} not confirmed within the timeout");
            return Ok(None);
        };
        let status = receipt["status"].as_str() == Some("0x1");
        let block = receipt["blockNumber"]
            .as_str()
            .and_then(|number| u64::from_str_radix(number.trim_start_matches("0x"), 16).ok())
            .ok_or_eyre("batch receipt has no block")?;
        Ok(Some((hash, block, status)))
    }

    /// Sends `calls` approvals from `sender` as the calls of one Tempo transaction at `nonce`.
    /// Returns the last amount each spender was given and the block it landed in, or `None`
    /// when it reverted or the batch does not fit half the balance.
    async fn approve_batch(
        &self,
        zone: &DynProvider,
        sender: &Account,
        balance: u128,
        gas_price: u128,
        calls: u128,
        nonce: u64,
    ) -> eyre::Result<Option<(Vec<(Address, U256)>, u64)>> {
        let mut calls = calls;
        let gas_limit = |calls: u128| BATCH_BASE_GAS + BATCH_CALL_GAS * calls as u64;
        while calls > 1
            && calc_gas_balance_spending(gas_limit(calls), gas_price) > U256::from(balance / 2)
        {
            calls /= 2;
        }
        let gas_limit = gas_limit(calls);
        let max_fee: u128 = calc_gas_balance_spending(gas_limit, gas_price).try_into()?;
        if max_fee > balance / 2 {
            return Ok(None);
        }
        let approvals: Vec<(Address, U256)> = (0..calls)
            .map(|_| {
                let spender = random_spender(sender.address());
                let amount = if random_below(3) == 0 {
                    U256::ZERO
                } else {
                    U256::from(random_between(1, u128::from(u64::MAX)))
                };
                (spender, amount)
            })
            .collect();
        let tx = TempoTransaction {
            chain_id: zone.get_chain_id().await?,
            max_fee_per_gas: gas_price,
            max_priority_fee_per_gas: gas_price,
            gas_limit,
            calls: approvals
                .iter()
                .map(|(spender, amount)| Call {
                    to: TxKind::Call(PATH_USD_ADDRESS),
                    value: U256::ZERO,
                    input: ITIP20::approveCall {
                        spender: *spender,
                        amount: *amount,
                    }
                    .abi_encode()
                    .into(),
                })
                .collect(),
            nonce,
            ..Default::default()
        };
        let signature = sender.signer.sign_hash_sync(&tx.signature_hash())?;
        let encoded = tx.into_signed(signature.into()).encoded_2718();
        let hash = *zone.send_raw_transaction(&encoded).await?.tx_hash();
        // Tempo transaction receipts are read raw: only their status and block matter here.
        let mut receipt = None;
        poll_until(RECEIPT_TIMEOUT, async || {
            receipt = zone
                .raw_request::<_, Option<serde_json::Value>>(
                    "eth_getTransactionReceipt".into(),
                    (hash,),
                )
                .await?;
            Ok(receipt.is_some())
        })
        .await?;
        // Under faults the batch may stay pending past the timeout, like any other send.
        let Some(receipt) = receipt else {
            println!("approve: batch {hash} not confirmed within the timeout");
            return Ok(None);
        };
        let status = receipt["status"].as_str() == Some("0x1");
        let block = receipt["blockNumber"]
            .as_str()
            .and_then(|number| u64::from_str_radix(number.trim_start_matches("0x"), 16).ok())
            .ok_or_eyre("batch approval receipt has no block")?;
        assert_sometimes!(
            status,
            "Batched zone approvals succeed",
            &json!({ "tx": hash, "owner": sender.address(), "calls": calls })
        );
        if !status {
            println!("approve: batch {hash} of {calls} reverted");
            return Ok(None);
        }
        let mut expected: Vec<(Address, U256)> = Vec::new();
        for (spender, amount) in approvals {
            expected.retain(|(seen, _)| *seen != spender);
            expected.push((spender, amount));
        }
        println!("approve: batch of {calls} calls in block {block}");
        Ok(Some((expected, block)))
    }

    /// Empties one sender into another account, so its pathUSD balance slot is deleted from the
    /// storage trie, and the recipient's slot changes.
    async fn sweep(&self) -> eyre::Result<()> {
        let node = random_index(self.zones.len());
        let Some((sender, balance, _lease)) = self.lease_zone_sender(&self.zones[node]).await?
        else {
            return Ok(());
        };
        let Some(to) = self.random_existing_account(Some(sender.address()))? else {
            return Ok(());
        };
        let to = to.address();
        let url = &self.zone_urls[node];
        let zone = self.wallet(&sender, url);
        let gas_price = zone.get_gas_price().await?;
        let token = ITIP20::new(PATH_USD_ADDRESS, &zone);
        // The fee is charged on gas used, so leaving exactly the estimated fee empties the
        // account when the estimate holds.
        let gas = token
            .transfer(to, U256::from(1))
            .gas_price(gas_price)
            .estimate_gas()
            .await?;
        let fee: u128 = calc_gas_balance_spending(gas, gas_price).try_into()?;
        let Some(amount) = balance.checked_sub(fee).filter(|amount| *amount > 0) else {
            return Ok(());
        };
        let receipt = token
            .transfer(to, U256::from(amount))
            .gas(gas)
            .gas_price(gas_price)
            .send()
            .await?
            .with_timeout(Some(RECEIPT_TIMEOUT))
            .get_receipt()
            .await?;
        let zone_block = receipt.block_number.ok_or_eyre("receipt has no block")?;
        let funded_revert = !receipt.status()
            && self
                .covered_before(&zone, &receipt, sender.address(), amount + fee)
                .await?;
        assert_always!(
            !funded_revert,
            "Funded zone transfer succeeds",
            &json!({ "tx": receipt.transaction_hash, "from": sender.address(), "to": to })
        );
        if !receipt.status() {
            return Ok(());
        }
        self.ledger.append(&Record::Transfer {
            zone_tx: receipt.transaction_hash,
            zone_block,
            from: sender.address(),
            to,
            amount,
        })?;
        let left = token
            .balanceOf(sender.address())
            .from(sender.address())
            .block(BlockId::number(zone_block))
            .call()
            .await?;
        assert_sometimes!(
            left.is_zero(),
            "Sweep empties a zone account",
            &json!({ "tx": receipt.transaction_hash, "from": sender.address(), "left": left })
        );
        println!(
            "sweep: {amount} from {} to {to}, {left} left",
            sender.address()
        );
        Ok(())
    }

    /// Sends an encrypted deposit and returns its record once the L1 receipt confirms it, or
    /// `None` when it reverted.
    async fn send_deposit(
        &self,
        sender: &Account,
        to: Address,
        amount: u128,
    ) -> eyre::Result<Option<Record>> {
        let l1 = self.wallet(sender, &self.l1_url);
        let portal = ZonePortal::new(self.portal, &l1);
        let (key, key_index) = portal.encryption_key().await?;
        let parity = key
            .normalized_y_parity()
            .ok_or_else(|| eyre!("unexpected encryption key yParity {:#x}", key.yParity))?;
        let encrypted = encrypt_deposit(
            &key.x,
            parity,
            to,
            B256::ZERO,
            sender.address(),
            self.portal,
            key_index,
        )
        .ok_or_eyre("ECIES encryption failed")?;
        let payload = DepositPayload {
            ephemeralPubkeyX: encrypted.eph_pub_x,
            ephemeralPubkeyYParity: encrypted.eph_pub_y_parity,
            ciphertext: Bytes::from(encrypted.ciphertext),
            nonce: encrypted.nonce.into(),
            tag: encrypted.tag.into(),
        };
        let receipt = portal
            .deposit(
                PATH_USD_ADDRESS,
                amount,
                key_index,
                payload,
                sender.address(),
            )
            .gas(DEPOSIT_TX_GAS)
            .send()
            .await?
            .with_timeout(Some(RECEIPT_TIMEOUT))
            .get_receipt()
            .await?;
        if !receipt.status() {
            return Ok(None);
        }
        let made = receipt
            .decoded_log::<ZonePortal::DepositMade>()
            .ok_or_eyre("deposit receipt has no DepositMade log")?;
        let record = Record::Deposit {
            l1_tx: receipt.transaction_hash,
            queue_hash: made.newCurrentDepositQueueHash,
            sender: sender.address(),
            to,
            net_amount: made.netAmount,
        };
        self.ledger.append(&record)?;
        Ok(Some(record))
    }

    /// Approves the portal to spend `account`'s L1 pathUSD, unless it already may.
    async fn ensure_portal_allowance(&self, account: &Account) -> eyre::Result<()> {
        let token = ITIP20::new(PATH_USD_ADDRESS, self.wallet(account, &self.l1_url));
        if token
            .allowance(account.address(), self.portal)
            .call()
            .await?
            >= U256::from(u128::MAX)
        {
            return Ok(());
        }
        let receipt = token
            .approve(self.portal, U256::MAX)
            .send()
            .await?
            .with_timeout(Some(RECEIPT_TIMEOUT))
            .get_receipt()
            .await?;
        eyre::ensure!(
            receipt.status(),
            "portal approval for {} reverted",
            account.address()
        );
        Ok(())
    }

    /// Polls `zone` from `from_block` until the inbox credits or bounces `deposit`, matched by
    /// its queue hash. Returns `None` if neither happens within [`BRIDGE_WAIT`].
    async fn wait_deposit_outcome(
        &self,
        zone: &DynProvider,
        deposit: &Record,
        from_block: u64,
    ) -> eyre::Result<Option<DepositOutcome>> {
        let Record::Deposit { queue_hash, .. } = *deposit else {
            eyre::bail!("not a deposit: {deposit:?}");
        };
        let filter = Filter::new()
            .address(ZONE_INBOX_ADDRESS)
            .event_signature(vec![
                IZoneInbox::DepositProcessed::SIGNATURE_HASH,
                IZoneInbox::DepositFailed::SIGNATURE_HASH,
            ])
            .topic1(queue_hash)
            .from_block(from_block);
        let mut outcome = None;
        poll_until(BRIDGE_WAIT, async || {
            outcome = zone
                .get_logs(&filter)
                .await?
                .iter()
                .find_map(|log| match log.topic0() {
                    Some(&IZoneInbox::DepositProcessed::SIGNATURE_HASH) => {
                        Some(DepositOutcome::Credited)
                    }
                    Some(&IZoneInbox::DepositFailed::SIGNATURE_HASH) => {
                        Some(DepositOutcome::Bounced)
                    }
                    _ => None,
                });
            Ok(outcome.is_some())
        })
        .await?;
        Ok(outcome)
    }

    /// Polls L1 from `from_block` until the portal pays `amount` to `to`. Returns `false` if
    /// it does not within [`BRIDGE_WAIT`].
    async fn wait_withdrawal_paid(
        &self,
        to: Address,
        amount: u128,
        from_block: u64,
    ) -> eyre::Result<bool> {
        let filter = Filter::new()
            .address(self.portal)
            .event_signature(ZonePortal::WithdrawalProcessed::SIGNATURE_HASH)
            .topic1(to.into_word())
            .from_block(from_block);
        poll_until(BRIDGE_WAIT, async || {
            Ok(self.l1.get_logs(&filter).await?.iter().any(|log| {
                ZonePortal::WithdrawalProcessed::decode_log(&log.inner)
                    .is_ok_and(|event| event.amount == amount && event.callbackSuccess)
            }))
        })
        .await
    }

    /// Leases a random funder, or returns `None` when every funder is busy.
    fn lease_funder(&self) -> eyre::Result<Option<(Account, Lease)>> {
        let funders: Vec<u32> = FUNDER_INDICES.collect();
        for index in shuffled(funders) {
            let funder = Account::at(index)?;
            if let Some(lease) = self.ledger.try_lease(&funder)? {
                return Ok(Some((funder, lease)));
            }
        }
        println!("all funders are busy");
        Ok(None)
    }

    /// Leases a random workload account whose balance on `zone` can pay for a send. Returns
    /// `None` when no candidate is free and funded. The balance only sizes the send: `zone` may
    /// lag behind the account's last spends, so callers send to the same node and judge a revert
    /// with [`Self::covered_before`].
    async fn lease_zone_sender(
        &self,
        zone: &DynProvider,
    ) -> eyre::Result<Option<(Account, u128, Lease)>> {
        for account in shuffled(self.ledger.sender_accounts()?)
            .into_iter()
            .take(SENDER_CANDIDATES)
        {
            let Some(lease) = self.ledger.try_lease(&account)? else {
                continue;
            };
            let balance: u128 = ITIP20::new(PATH_USD_ADDRESS, zone)
                .balanceOf(account.address())
                .from(account.address())
                .call()
                .await?
                .try_into()?;
            if balance >= MIN_SENDER_BALANCE {
                return Ok(Some((account, balance, lease)));
            }
        }
        println!("no free funded zone sender");
        Ok(None)
    }

    /// Whether `sender` held at least `required` on `zone` just before the reverted `receipt`
    /// ran, so the revert cannot be blamed on a stale balance read. That is its balance at the
    /// parent block less what its earlier transactions in the same block spent, which includes
    /// sends from earlier commands that gave up waiting for their receipts.
    async fn covered_before(
        &self,
        zone: &DynProvider,
        receipt: &TransactionReceipt,
        sender: Address,
        required: u128,
    ) -> eyre::Result<bool> {
        let block = receipt.block_number.ok_or_eyre("receipt has no block")?;
        let index = receipt
            .transaction_index
            .ok_or_eyre("receipt has no transaction index")?;
        let parent = block
            .checked_sub(1)
            .ok_or_eyre("transaction mined in genesis")?;
        let balance = ITIP20::new(PATH_USD_ADDRESS, zone)
            .balanceOf(sender)
            .from(sender)
            .block(BlockId::number(parent))
            .call()
            .await?;
        let receipts = zone
            .get_block_receipts(BlockId::number(block))
            .await?
            .ok_or_eyre("block receipts not found")?;
        let mut balance = I256::try_from(balance)?;
        for earlier in receipts.iter().filter(|earlier| {
            earlier.from == sender && earlier.transaction_index.is_some_and(|i| i < index)
        }) {
            let mut paid_fee = false;
            for log in earlier.inner.logs() {
                if log.address() != PATH_USD_ADDRESS {
                    continue;
                }
                let Ok(transfer) = ITIP20::Transfer::decode_log(&log.inner) else {
                    continue;
                };
                if transfer.from == sender {
                    balance -= I256::try_from(transfer.amount)?;
                    paid_fee = true;
                }
                if transfer.to == sender {
                    balance += I256::try_from(transfer.amount)?;
                }
            }
            // A reverted transaction keeps no logs but still pays its fee.
            if !paid_fee {
                let fee = calc_gas_balance_spending(earlier.gas_used, earlier.effective_gas_price);
                balance -= I256::try_from(fee)?;
            }
        }
        Ok(balance >= I256::try_from(required)?)
    }

    /// Picks a recipient other than `sender`: a new account half of the time, otherwise an
    /// existing one. Returns the address and whether it is new.
    fn pick_recipient(&self, sender: Address) -> eyre::Result<(Address, bool)> {
        if random_below(2) == 0 {
            return Ok((self.ledger.new_account()?.address(), true));
        }
        match self.random_existing_account(Some(sender))? {
            Some(account) => Ok((account.address(), false)),
            None => Ok((self.ledger.new_account()?.address(), true)),
        }
    }

    fn random_existing_account(&self, except: Option<Address>) -> eyre::Result<Option<Account>> {
        let accounts: Vec<Account> = self
            .ledger
            .accounts()?
            .into_iter()
            .filter(|account| Some(account.address()) != except)
            .collect();
        Ok(random_choice(accounts))
    }

    fn random_zone(&self) -> &DynProvider {
        &self.zones[random_index(self.zones.len())]
    }

    fn wallet(&self, account: &Account, url: &reqwest::Url) -> DynProvider {
        wallet_provider(&self.http, account.signer.clone(), url)
    }
}

fn wallet_provider(
    http: &reqwest::Client,
    signer: PrivateKeySigner,
    url: &reqwest::Url,
) -> DynProvider {
    ProviderBuilder::new()
        .wallet(signer)
        .connect_reqwest(http.clone(), url.clone())
        .erased()
}

/// How the zone inbox settled a deposit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DepositOutcome {
    /// Minted to the recipient.
    Credited,
    /// Rejected and queued as a bounce-back to the refund recipient on L1.
    Bounced,
}

/// Whether `error` comes from an RPC call or a receipt wait rather than from a driver's own
/// checks: a transport failure, an error response such as nonce too low, or a receipt timeout.
fn is_rpc_error(error: &eyre::Report) -> bool {
    error.chain().any(|cause| {
        cause.is::<TransportError>()
            || cause.is::<PendingTransactionError>()
            || matches!(
                cause.downcast_ref::<alloy::contract::Error>(),
                Some(alloy::contract::Error::TransportError(_))
            )
    })
}

/// Polls `check` every [`POLL`] until it returns `true` or `timeout` passes. RPC errors count
/// as not yet, since faults make nodes unavailable for a while.
async fn poll_until(
    timeout: Duration,
    mut check: impl AsyncFnMut() -> eyre::Result<bool>,
) -> eyre::Result<bool> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match check().await {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(error) => println!("poll: {error:#}"),
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(false);
        }
        tokio::time::sleep(POLL).await;
    }
}

/// A spender of `owner`: from the hot set half the time, otherwise from the wide set.
fn random_spender(owner: Address) -> Address {
    let bound = if random_below(2) == 0 {
        APPROVAL_SPENDERS
    } else {
        APPROVAL_SPENDERS_WIDE
    };
    approval_spender(owner, random_below(bound))
}

/// Spender `index` of `owner`'s approval set: a fixed address no key controls.
fn approval_spender(owner: Address, index: u64) -> Address {
    let mut preimage = owner.to_vec();
    preimage.extend_from_slice(&index.to_be_bytes());
    Address::from_word(alloy::primitives::keccak256(preimage))
}

/// A random value in `0..bound` from the Antithesis randomness source, so every choice the
/// workload makes is one Antithesis can steer and replay.
fn random_below(bound: u64) -> u64 {
    get_random() % bound.max(1)
}

fn random_between(low: u128, high: u128) -> u128 {
    if high <= low {
        return low;
    }
    low + u128::from(get_random()) % (high - low + 1)
}

fn random_index(len: usize) -> usize {
    usize::try_from(random_below(len as u64)).expect("index below a usize length")
}

fn random_choice<T>(mut items: Vec<T>) -> Option<T> {
    if items.is_empty() {
        return None;
    }
    let index = random_index(items.len());
    Some(items.swap_remove(index))
}

fn shuffled<T>(mut items: Vec<T>) -> Vec<T> {
    for i in (1..items.len()).rev() {
        items.swap(i, random_index(i + 1));
    }
    items
}
