//! Antithesis test commands for the zone test environment in `zones/antithesis`.
//!
//! Each subcommand is one test command: drivers send deposits, withdrawals and TIP-20 transfers
//! between accounts the workload keeps creating, so the L1 and zone tries grow during a run, and
//! checks assert what must hold under faults and after recovery. Commands share state through the
//! [`Ledger`] in the workload container.

use alloy::{
    primitives::{Address, B256, Bytes, U256},
    providers::{DynProvider, PendingTransactionBuilder, Provider, ProviderBuilder},
    rpc::types::{BlockId, Filter, TransactionReceipt},
    signers::local::PrivateKeySigner,
    sol_types::SolEvent as _,
    transports::http::reqwest,
};
use antithesis_sdk::{
    assert_always, assert_sometimes, assert_sometimes_greater_than, random::get_random,
};
use eyre::{OptionExt as _, WrapErr as _, eyre};
use serde_json::json;
use std::{collections::BTreeMap, path::PathBuf, time::Duration};
use tempo_contracts::{
    precompiles::ITIP20,
    zones::{
        DepositPayload, IZoneInbox, IZoneOutbox, ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS,
        ZonePortal,
    },
};
use tempo_precompiles::PATH_USD_ADDRESS;
use tempo_primitives::transaction::calc_gas_balance_spending;
use zone_precompiles::ecies::encrypt_deposit;

use ledger::{Account, Lease, Ledger, Record};

mod checks;
mod ledger;

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
/// How many leased-account candidates a driver tries before giving up for this run.
const SENDER_CANDIDATES: usize = 16;

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
    /// Checks that zone nodes agree with L1 settlement while faults run.
    CheckConsistency,
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
        match self.command {
            Command::Seed => ctx.seed().await,
            Command::Deposit => ctx.deposit().await,
            Command::Transfer => ctx.transfer().await,
            Command::Withdraw => ctx.withdraw().await,
            Command::Fanout => ctx.fanout().await,
            Command::CheckConsistency => ctx.check_consistency().await,
            Command::CheckSettled => ctx.check_settled().await,
            Command::CheckLedger => ctx.check_ledger().await,
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
            eyre::ensure!(
                self.wait_deposit_credited(zone, &deposit, from_block)
                    .await?,
                "seed deposit {deposit:?} was not credited within {BRIDGE_WAIT:?}"
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
        let credited = self
            .wait_deposit_credited(zone, &deposit, from_block)
            .await?;
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
        println!("deposit: {deposit:?} credited={credited}");
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
        let count = random_between(5, 20);
        let amount = (balance / 4) / count;
        if amount == 0 {
            return Ok(());
        }
        let url = &self.zone_urls[node];
        let zone = self.wallet(&sender, url);
        let gas_price = zone.get_gas_price().await?;
        let mut nonce = zone
            .get_transaction_count(sender.address())
            .pending()
            .await?;
        let token = ITIP20::new(PATH_USD_ADDRESS, &zone);
        let mut pending: Vec<(Address, PendingTransactionBuilder<_>)> = Vec::new();
        for _ in 0..count {
            let to = self.ledger.new_account()?.address();
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
        // What this command's earlier transfers spent in each block, which a later revert in the
        // same block had to leave room for.
        let mut spent_in_block: BTreeMap<u64, u128> = BTreeMap::new();
        // The fee comes out of the same pathUSD balance, so a funded transfer needs both.
        let max_fee: u128 = calc_gas_balance_spending(TIP20_TX_GAS, gas_price).try_into()?;
        for (to, tx) in pending {
            let receipt = tx.with_timeout(Some(RECEIPT_TIMEOUT)).get_receipt().await?;
            let zone_block = receipt.block_number.ok_or_eyre("receipt has no block")?;
            let spent = spent_in_block.entry(zone_block).or_default();
            let funded_revert = !receipt.status()
                && self
                    .covered_before(&zone, &receipt, sender.address(), *spent + amount + max_fee)
                    .await?;
            assert_always!(
                !funded_revert,
                "Funded zone transfer succeeds",
                &json!({ "tx": receipt.transaction_hash, "from": sender.address(), "to": to })
            );
            if receipt.status() {
                *spent += amount + max_fee;
                self.ledger.append(&Record::Transfer {
                    zone_tx: receipt.transaction_hash,
                    zone_block,
                    from: sender.address(),
                    to,
                    amount,
                })?;
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

    /// Polls `zone` from `from_block` until `deposit` is credited or bounced back. Returns
    /// `false` if neither happens within [`BRIDGE_WAIT`].
    async fn wait_deposit_credited(
        &self,
        zone: &DynProvider,
        deposit: &Record,
        from_block: u64,
    ) -> eyre::Result<bool> {
        let Record::Deposit {
            sender,
            to,
            net_amount,
            ..
        } = *deposit
        else {
            eyre::bail!("not a deposit: {deposit:?}");
        };
        let processed = Filter::new()
            .address(ZONE_INBOX_ADDRESS)
            .event_signature(IZoneInbox::DepositProcessed::SIGNATURE_HASH)
            .topic2(sender.into_word())
            .topic3(to.into_word())
            .from_block(from_block);
        let failed = Filter::new()
            .address(ZONE_INBOX_ADDRESS)
            .event_signature(IZoneInbox::DepositFailed::SIGNATURE_HASH)
            .topic2(sender.into_word())
            .from_block(from_block);
        poll_until(BRIDGE_WAIT, async || {
            let credited = zone.get_logs(&processed).await?.iter().any(|log| {
                IZoneInbox::DepositProcessed::decode_log(&log.inner)
                    .is_ok_and(|event| event.amount == net_amount)
            });
            let bounced = zone.get_logs(&failed).await?.iter().any(|log| {
                IZoneInbox::DepositFailed::decode_log(&log.inner)
                    .is_ok_and(|event| event.amount == net_amount)
            });
            Ok(credited || bounced)
        })
        .await
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
        for account in shuffled(self.ledger.accounts()?)
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

    /// Whether `sender` held at least `required` on `zone` just before the block that mined the
    /// reverted `receipt`, so the revert cannot be blamed on a stale balance read.
    async fn covered_before(
        &self,
        zone: &DynProvider,
        receipt: &TransactionReceipt,
        sender: Address,
        required: u128,
    ) -> eyre::Result<bool> {
        let block = receipt.block_number.ok_or_eyre("receipt has no block")?;
        let parent = block
            .checked_sub(1)
            .ok_or_eyre("transaction mined in genesis")?;
        let balance = ITIP20::new(PATH_USD_ADDRESS, zone)
            .balanceOf(sender)
            .from(sender)
            .block(BlockId::number(parent))
            .call()
            .await?;
        Ok(balance >= U256::from(required))
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
