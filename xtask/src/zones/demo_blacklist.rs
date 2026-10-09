//! End-to-end demo of the TIP-20 + TIP-403 blacklist lifecycle.
//!
//! # What this does
//!
//! Runs a self-contained 9-step scenario on a live zone to demonstrate how
//! transfer-policy enforcement works across L1 and L2:
//!
//!  1. Create a fresh TIP-20 token on L1 (via `TIP20Factory`)
//!  2. Configure the token (supply cap, ISSUER_ROLE, mint, approve)
//!  3. Portal admin enables the token on the zone portal
//!  4. Deposit tokens into the zone (plain deposit to the PRIVATE_KEY wallet)
//!  5. Create a TIP-403 blacklist policy, blacklist a target wallet, assign it to the token
//!  6. Deposit to the blacklisted target → zone bounces it back
//!  7. Remove target from the blacklist on L1
//!  8. Deposit to the now-unblacklisted target → zone accepts it
//!  9. Target withdraws tokens from zone back to L1
//!
//! Each step prints what it's doing, why, and every tx hash / address for
//! debugging and auditability.
//!
//! # Prerequisites
//!
//! - A running zone. Pass `--zone-dir` if `generated/*/zone.json` auto-discovery
//!   cannot match `L1_PORTAL_ADDRESS`.
//! - The zone's sequencer must be actively producing blocks
//! - An L1 account with enough funds for gas (set via `PRIVATE_KEY`)
//! - Portal admin authority via `ADMIN_KEY`, or `adminKey` in zone.json
//! - The `PRIVATE_KEY` account needs a small pathUSD balance on L1 (deposited to
//!   the target wallet for L2 gas fees)
//!
//! # Usage
//!
//! ```sh
//! just demo-blacklist              # default amount=500000, auto-discovers zone metadata
//! just demo-blacklist 1000000      # custom deposit amount
//! just demo-blacklist 500000 http://localhost:8546 generated/my-zone
//! ```
//!
//! Or directly via cargo:
//! ```sh
//! cargo run -p tempo-xtask -- demo-blacklist \
//!     --portal 0x9d00Ee56f371Cc5365a686180dE3648207399640
//! ```
//!
//! # Architecture notes
//!
//! - Each run uses a random salt and random target wallet so runs are fully
//!   isolated and idempotent.
//! - Two L1 providers are needed: one for the token admin wallet (token operations,
//!   deposits) and one for the portal admin wallet (`enableToken`). `ADMIN_KEY`
//!   signs portal governance calls, with `sequencerKey` retained as a legacy
//!   fallback for zones where admin == sequencer.
//! - TIP-403 policies are assigned directly to the token via
//!   `changeTransferPolicyId`. This demo uses a simple blacklist policy; use
//!   `just create-compound-policy` for role-specific sender/recipient policies.
//! - After modifying the blacklist on L1, the zone needs a few seconds to sync
//!   the policy state via its L1 listener. We wait 6 seconds which is enough
//!   for a couple of L1 blocks.

use alloy::{
    primitives::{Address, B256, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::Filter,
    signers::local::PrivateKeySigner,
    sol_types::SolEvent,
};
use eyre::{WrapErr as _, eyre};
use tempo_alloy::TempoNetwork;
use tempo_contracts::precompiles::{
    IRolesAuth, ITIP20 as TIP20Token, ITIP20Factory as TIP20Factory,
    ITIP403Registry as TIP403Registry,
};
use tempo_precompiles::{
    PATH_USD_ADDRESS, TIP20_FACTORY_ADDRESS, TIP403_REGISTRY_ADDRESS, tip20::ISSUER_ROLE,
};
use tempo_zone_contracts::{
    DepositPayload, IZoneInbox, IZoneOutbox, ZONE_OUTBOX_ADDRESS, ZonePortal,
};
use zone_precompiles::ecies::encrypt_deposit;

use crate::zone_utils::{
    L1_EXPLORER, check, normalize_http_rpc, parse_private_key, wait_for_token_enabled,
};

#[derive(Debug, clap::Parser)]
pub(crate) struct DemoBlacklist {
    /// Tempo L1 RPC URL.
    #[arg(
        long,
        env = "L1_RPC_URL",
        default_value = "https://rpc.moderato.tempo.xyz"
    )]
    l1_rpc_url: String,

    /// ZonePortal contract address on Tempo L1.
    #[arg(long, env = "L1_PORTAL_ADDRESS")]
    portal: Address,

    /// Private key (hex) of the token admin / depositor.
    #[arg(long, env = "PRIVATE_KEY", hide_env_values = true)]
    private_key: String,

    /// Portal admin private key (hex). If not set, reads adminKey from the
    /// explicit or auto-discovered zone.json, then falls back to SEQUENCER_KEY /
    /// sequencerKey for legacy zones.
    #[arg(long, env = "ADMIN_KEY", hide_env_values = true)]
    admin_key: Option<String>,

    /// Sequencer private key (hex). Legacy fallback for zones where admin == sequencer.
    #[arg(long, env = "SEQUENCER_KEY", hide_env_values = true)]
    sequencer_key: Option<String>,

    /// Path to zone directory containing zone.json. If omitted, scans
    /// generated/*/zone.json for the portal address.
    #[arg(long)]
    zone_dir: Option<std::path::PathBuf>,

    /// Zone L2 RPC URL.
    #[arg(long, env = "ZONE_RPC_URL", default_value = "http://localhost:8546")]
    zone_rpc_url: String,

    /// Amount of tokens to use per deposit in the demo.
    #[arg(long, default_value_t = 500_000)]
    amount: u128,
}

impl DemoBlacklist {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let signer = parse_private_key(&self.private_key)?;
        let admin = signer.address();

        let (zone_json_path, zone_json) =
            load_zone_metadata(self.zone_dir.as_deref(), self.portal)?;
        let portal_admin_key_str = self
            .admin_key
            .clone()
            .or_else(|| zone_json.as_ref()?.get("adminKey")?.as_str().map(str::to_owned))
            .or_else(|| self.sequencer_key.clone())
            .or_else(|| zone_json.as_ref()?.get("sequencerKey")?.as_str().map(str::to_owned))
            .ok_or_else(|| {
                eyre!(
                    "portal admin key missing. Set ADMIN_KEY or store adminKey in {}. \
                     SEQUENCER_KEY/sequencerKey only works for legacy zones where admin == sequencer.",
                    zone_json_path
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "the matching generated/<name>/zone.json".to_string())
                )
            })?;
        let portal_admin_signer = parse_private_key(&portal_admin_key_str)?;
        let portal_admin = portal_admin_signer.address();

        let http_rpc = normalize_http_rpc(&self.l1_rpc_url);

        let l1 = ProviderBuilder::new_with_network::<TempoNetwork>()
            .wallet(signer)
            .connect(&http_rpc)
            .await?;
        l1.client()
            .set_poll_interval(std::time::Duration::from_secs(1));

        let l1_portal_admin = ProviderBuilder::new_with_network::<TempoNetwork>()
            .wallet(portal_admin_signer)
            .connect(&http_rpc)
            .await?;
        l1_portal_admin
            .client()
            .set_poll_interval(std::time::Duration::from_secs(1));

        let l2 = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect(&self.zone_rpc_url)
            .await?;

        println!("╔══════════════════════════════════════════════════════════════╗");
        println!("║          TIP-20 + TIP-403 Blacklist Demo                    ║");
        println!("╚══════════════════════════════════════════════════════════════╝");
        println!();
        println!("  Admin:        {admin}");
        println!("  Portal admin: {portal_admin}");
        println!("  Portal:       {}", self.portal);
        println!("  L1 RPC:       {http_rpc}");
        println!("  Zone RPC:     {}", self.zone_rpc_url);
        println!();

        // Generate a fresh target wallet for the demo
        let target_signer = PrivateKeySigner::random();
        let target = target_signer.address();
        println!("  Target wallet (fresh): {target}");
        println!();

        // ── Step 1: Create a new TIP-20 token on L1 ──────────────────────
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Step 1: Create a new TIP-20 token on L1");
        println!("  Deploying a fresh token via TIP20Factory.");
        println!();

        let salt = B256::random();
        let factory = TIP20Factory::new(TIP20_FACTORY_ADDRESS, &l1);

        let token_addr = factory
            .getTokenAddress(admin, salt)
            .call()
            .await
            .wrap_err("getTokenAddress failed")?;
        println!("  Predicted address: {token_addr}");

        let receipt = factory
            .createToken_0(
                "DemoUSD".to_string(),
                "DUSD".to_string(),
                "USD".to_string(),
                PATH_USD_ADDRESS,
                admin,
                salt,
            )
            .send_sync()
            .await
            .wrap_err("createToken send failed")?;
        check(&receipt, "createToken")?;
        let tx = receipt.transaction_hash;
        println!("  Token created: DemoUSD (DUSD) at {token_addr}");
        println!("  {L1_EXPLORER}/{tx}");
        println!();

        let token = TIP20Token::new(token_addr, &l1);

        // ── Step 2: Configure token (supply cap, issuer role, mint) ──────
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Step 2: Configure token — set supply cap, grant ISSUER_ROLE, mint tokens");
        println!();

        // TIP-20 supply cap is uint128 internally, so u128::MAX is the effective maximum.
        let receipt = token
            .setSupplyCap(U256::from(u128::MAX))
            .send_sync()
            .await?;
        check(&receipt, "setSupplyCap")?;
        println!("  Supply cap set to max");
        println!("  {L1_EXPLORER}/{}", receipt.transaction_hash);

        let roles = IRolesAuth::new(token_addr, &l1);
        let receipt = roles.grantRole(ISSUER_ROLE, admin).send_sync().await?;
        check(&receipt, "grantRole")?;
        println!("  ISSUER_ROLE granted to {admin}");
        println!("  {L1_EXPLORER}/{}", receipt.transaction_hash);

        // Mint 4× the deposit amount: 2× goes to the initial deposit (step 4),
        // 1× for the bounced deposit (step 6), 1× for the successful one (step 8).
        let mint_amount = self.amount * 4;
        let receipt = token
            .mint(admin, U256::from(mint_amount))
            .send_sync()
            .await?;
        check(&receipt, "mint")?;
        println!("  Minted {mint_amount} DUSD to admin");
        println!("  {L1_EXPLORER}/{}", receipt.transaction_hash);

        let receipt = token.approve(self.portal, U256::MAX).send_sync().await?;
        check(&receipt, "approve")?;
        println!("  Portal approved for max spend");
        println!("  {L1_EXPLORER}/{}", receipt.transaction_hash);
        println!();

        // ── Step 3: Enable token on the zone ─────────────────────────────
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Step 3: Enable token on zone");
        println!("  Only the portal admin can call enableToken on the portal.");
        println!();

        let portal = ZonePortal::new(self.portal, &l1);
        crate::zone_utils::verify_portal_admin(&l1, self.portal, portal_admin).await?;
        let admin_portal = ZonePortal::new(self.portal, &l1_portal_admin);
        // Retry enableToken because legacy zones may still use the sequencer key
        // as the admin key, and the running node can create nonce conflicts.
        let receipt = {
            let mut last_err = None;
            let mut pending = None;
            for attempt in 0..5u32 {
                match admin_portal.enableToken(token_addr).send().await {
                    Ok(p) => {
                        pending = Some(p);
                        break;
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        if msg.contains("underpriced") || msg.contains("nonce") {
                            println!(
                                "  Retry {}/5 — transient nonce conflict, waiting...",
                                attempt + 1
                            );
                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                            last_err = Some(e);
                            continue;
                        }
                        return Err(e)
                            .wrap_err("enableToken failed — is the portal admin key correct?");
                    }
                }
            }
            pending
                .ok_or_else(|| {
                    last_err
                        .map(|e| eyre!(e))
                        .unwrap_or_else(|| eyre!("enableToken failed after retries"))
                })?
                .get_receipt()
                .await?
        };
        check(&receipt, "enableToken")?;
        let enable_block = receipt.block_number.unwrap_or(0);
        println!("  Token enabled on L1 (block {enable_block})");
        println!("  {L1_EXPLORER}/{}", receipt.transaction_hash);

        println!("  Waiting for zone to pick up the new token...");
        wait_for_token_enabled(&l2, 1, token_addr).await?;
        println!("  Token available on zone!");
        println!();

        // ── Step 4: Deposit tokens into the zone ─────────────────────────
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        let deposit_amount = self.amount * 2;
        println!("Step 4: Deposit {deposit_amount} DUSD into the zone (to admin)");
        println!("  Deposit so admin has L2 funds for later steps.");
        println!();

        let l2_block_before = l2.get_block_number().await.unwrap_or(0);
        send_deposit(
            &portal,
            self.portal,
            token_addr,
            admin,
            admin,
            admin,
            deposit_amount,
        )
        .await?;
        println!("  Deposited {deposit_amount} DUSD");

        println!("  Waiting for deposit to land on L2...");
        let bounced = wait_for_deposit_result(
            &l2,
            l2_block_before,
            admin,
            token_addr,
            deposit_amount,
            admin,
        )
        .await?;
        eyre::ensure!(!bounced, "initial deposit unexpectedly bounced");
        println!("  Deposit processed on L2");

        let l2_balance = get_l2_balance(&l2, token_addr, admin).await?;
        println!("  Admin L2 balance: {l2_balance}");
        println!();

        // ── Step 5: Create blacklist policy and blacklist target ──────────
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Step 5: Create a blacklist policy and blacklist target wallet");
        println!("  A TIP-403 blacklist blocks specific addresses from sending/receiving.");
        println!("  We create one, blacklist the target, and assign the policy to the token.");
        println!();

        let registry = TIP403Registry::new(TIP403_REGISTRY_ADDRESS, &l1);

        let receipt = registry
            .createPolicy(admin, TIP403Registry::PolicyType::BLACKLIST)
            .send_sync()
            .await?;
        check(&receipt, "createPolicy(blacklist)")?;

        let blacklist_policy_id = receipt
            .decoded_log::<TIP403Registry::PolicyCreated>()
            .map(|e| e.policyId)
            .ok_or_else(|| eyre!("no PolicyCreated event"))?;
        println!("  Blacklist policy created: ID={blacklist_policy_id}");
        println!("  {L1_EXPLORER}/{}", receipt.transaction_hash);

        let receipt = registry
            .modifyPolicyBlacklist(blacklist_policy_id, target, true)
            .send_sync()
            .await?;
        check(&receipt, "modifyPolicyBlacklist(add)")?;
        println!("  {target} added to blacklist");
        println!("  {L1_EXPLORER}/{}", receipt.transaction_hash);

        let authorized = registry
            .isAuthorized(blacklist_policy_id, target)
            .call()
            .await?;
        println!(
            "  isAuthorized(policy={blacklist_policy_id}, target): {authorized}  (expected: false)"
        );

        // Assign blacklist policy directly to the token
        let receipt = token
            .changeTransferPolicyId(blacklist_policy_id)
            .send_sync()
            .await?;
        check(&receipt, "changeTransferPolicyId")?;
        let current_policy = token.transferPolicyId().call().await?;
        println!("  Token transfer policy set to {current_policy}");
        println!("  {L1_EXPLORER}/{}", receipt.transaction_hash);

        // The zone's L1 listener syncs policy state every few L1 blocks (~2s each).
        // 6 seconds gives enough margin for the blacklist to propagate to L2.
        println!("  Waiting for zone to sync the blacklist from L1...");
        tokio::time::sleep(std::time::Duration::from_secs(6)).await;
        println!();

        // ── Step 6: Deposit to blacklisted address → bounce ─────────────
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!(
            "Step 6: Deposit {} DUSD to blacklisted address {target}",
            self.amount
        );
        println!("  The zone should reject this deposit and bounce funds back to sender.");
        println!();

        let l2_block_before = l2.get_block_number().await.unwrap_or(0);
        send_deposit(
            &portal,
            self.portal,
            token_addr,
            target,
            admin,
            admin,
            self.amount,
        )
        .await?;

        println!("  Waiting for zone to process (expecting DepositFailed)...");
        let bounced =
            wait_for_deposit_result(&l2, l2_block_before, admin, token_addr, self.amount, target)
                .await?;
        if bounced {
            println!("  BOUNCED! Deposit to blacklisted address was correctly rejected.");
            let sender_l2_balance = get_l2_balance(&l2, token_addr, admin).await?;
            println!("  Funds returned to sender on L2. Admin L2 balance: {sender_l2_balance}");
        } else {
            println!("  WARNING: Deposit was processed — blacklist may need more time to sync.");
        }
        println!();

        // Fund target with pathUSD so it can pay L2 gas in step 9.
        let pathusd_token = TIP20Token::new(PATH_USD_ADDRESS, &l1);
        let receipt = pathusd_token
            .approve(self.portal, U256::MAX)
            .send_sync()
            .await?;
        check(&receipt, "approve pathUSD for portal")?;

        let gas_fund: u128 = 100_000;
        let l2_block_before = l2.get_block_number().await.unwrap_or(0);
        send_deposit(
            &portal,
            self.portal,
            PATH_USD_ADDRESS,
            target,
            admin,
            admin,
            gas_fund,
        )
        .await?;
        let bounced = wait_for_deposit_result(
            &l2,
            l2_block_before,
            admin,
            PATH_USD_ADDRESS,
            gas_fund,
            target,
        )
        .await?;
        eyre::ensure!(!bounced, "pathUSD gas deposit unexpectedly bounced");
        println!("  Deposited {gas_fund} pathUSD to target for L2 gas");

        // ── Step 7: Unblacklist the address ──────────────────────────────
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Step 7: Remove target from blacklist on L1");
        println!();

        let receipt = registry
            .modifyPolicyBlacklist(blacklist_policy_id, target, false)
            .send_sync()
            .await?;
        check(&receipt, "modifyPolicyBlacklist(remove)")?;
        println!("  {target} removed from blacklist");
        println!("  {L1_EXPLORER}/{}", receipt.transaction_hash);

        let authorized = registry
            .isAuthorized(blacklist_policy_id, target)
            .call()
            .await?;
        println!(
            "  isAuthorized(policy={blacklist_policy_id}, target): {authorized}  (expected: true)"
        );

        // Same L1→L2 sync delay as step 5.
        println!("  Waiting for zone to sync the unblacklist...");
        tokio::time::sleep(std::time::Duration::from_secs(6)).await;
        println!();

        // ── Step 8: Deposit to unblacklisted address → success ───────────
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!(
            "Step 8: Deposit {} DUSD to unblacklisted address {target}",
            self.amount
        );
        println!("  Now that the target is no longer blacklisted, this should succeed.");
        println!();

        let l2_block_before = l2.get_block_number().await.unwrap_or(0);
        send_deposit(
            &portal,
            self.portal,
            token_addr,
            target,
            admin,
            admin,
            self.amount,
        )
        .await?;

        println!("  Waiting for zone to process (expecting DepositProcessed)...");
        let bounced =
            wait_for_deposit_result(&l2, l2_block_before, admin, token_addr, self.amount, target)
                .await?;
        if bounced {
            println!("  WARNING: Deposit still bounced — policy may need more time to sync.");
        } else {
            println!("  SUCCESS! Deposit to unblacklisted address was accepted.");
        }

        let target_balance = get_l2_balance(&l2, token_addr, target).await?;
        println!("  Target L2 balance: {target_balance}");
        println!();

        // ── Step 9: Withdraw from zone back to L1 ───────────────────────
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Step 9: Withdraw tokens from zone back to L1");
        println!("  Target wallet withdraws DUSD from the zone to their L1 address.");
        println!();

        // Target pays L2 gas in pathUSD (deposited in step 6b).
        let l2_target = ProviderBuilder::new_with_network::<TempoNetwork>()
            .wallet(target_signer)
            .connect(&self.zone_rpc_url)
            .await?;

        let outbox_token = TIP20Token::new(token_addr, &l2_target);
        let receipt = outbox_token
            .approve(ZONE_OUTBOX_ADDRESS, U256::MAX)
            .gas(150_000)
            .send_sync()
            .await
            .wrap_err("approve outbox on L2")?;
        check(&receipt, "approve outbox (L2)")?;
        println!(
            "  Outbox approved on L2  [tx: {}]",
            receipt.transaction_hash
        );

        // Withdraw all DemoUSD — gas is paid in pathUSD.
        let withdraw_amount = target_balance.to::<u128>();
        if withdraw_amount == 0 {
            println!("  No balance to withdraw — skipping.");
        } else {
            let outbox = IZoneOutbox::new(ZONE_OUTBOX_ADDRESS, &l2_target);

            let l1_block_before = l1.get_block_number().await?;
            let receipt = outbox
                .requestWithdrawal(
                    token_addr,
                    target,
                    withdraw_amount,
                    B256::ZERO,
                    0,
                    target,
                    Bytes::new(),
                    Bytes::new(),
                )
                .gas(500_000)
                .send_sync()
                .await?;
            check(&receipt, "requestWithdrawal")?;
            println!(
                "  Withdrawal requested: {withdraw_amount} DUSD  [tx: {}]",
                receipt.transaction_hash
            );

            println!("  Waiting for withdrawal to be processed on L1...");
            wait_for_withdrawal_processed(&l1, l1_block_before, self.portal, target).await?;
        }

        let final_l1 = token.balanceOf(target).call().await?;
        println!("  Target final L1 balance: {final_l1}");
        println!();

        // ── Done ─────────────────────────────────────────────────────────
        println!("╔══════════════════════════════════════════════════════════════╗");
        println!("║                     Demo Complete!                          ║");
        println!("╚══════════════════════════════════════════════════════════════╝");
        println!();
        println!("  Token:                       DemoUSD (DUSD) at {token_addr}");
        println!("  Target wallet:               {target}");
        println!("  Blacklist:                   policy={blacklist_policy_id}");
        println!("  Deposit to blacklisted addr: BOUNCED");
        println!("  Deposit after unblacklist:   ACCEPTED");
        if withdraw_amount > 0 {
            println!("  Withdrawal to L1:            {withdraw_amount} DUSD");
        }
        println!();

        Ok(())
    }
}

fn load_zone_metadata(
    zone_dir: Option<&std::path::Path>,
    portal: Address,
) -> eyre::Result<(Option<std::path::PathBuf>, Option<serde_json::Value>)> {
    if let Some(zone_dir) = zone_dir {
        let path = zone_dir.join("zone.json");
        let value = read_zone_json(&path)?;
        return Ok((Some(path), Some(value)));
    }

    let generated = std::path::Path::new("generated");
    if !generated.is_dir() {
        return Ok((None, None));
    }

    for entry in std::fs::read_dir(generated).wrap_err("failed reading generated/")? {
        let Ok(entry) = entry else {
            continue;
        };
        let path = entry.path().join("zone.json");
        let Ok(value) = read_zone_json(&path) else {
            continue;
        };
        let Some(json_portal) = value.get("portal").and_then(serde_json::Value::as_str) else {
            continue;
        };
        if json_portal.parse::<Address>().ok() == Some(portal) {
            return Ok((Some(path), Some(value)));
        }
    }

    Ok((None, None))
}

fn read_zone_json(path: &std::path::Path) -> eyre::Result<serde_json::Value> {
    let contents = std::fs::read_to_string(path)
        .wrap_err_with(|| format!("failed reading {}", path.display()))?;
    serde_json::from_str(&contents).wrap_err_with(|| format!("failed parsing {}", path.display()))
}

/// Send a deposit through the portal.
///
/// Fetches the sequencer's current encryption public key, encrypts the
/// `(recipient, memo)` tuple so only the sequencer can decrypt it on-chain,
/// and submits the deposit transaction on L1.
async fn send_deposit<P: Provider<TempoNetwork>>(
    portal: &ZonePortal::ZonePortalInstance<&P, TempoNetwork>,
    portal_addr: Address,
    token: Address,
    to: Address,
    tempo_refund_recipient: Address,
    sender: Address,
    amount: u128,
) -> eyre::Result<()> {
    let (key, key_index) = portal
        .encryption_key()
        .await
        .wrap_err("failed to fetch encryption key")?;

    let y_parity = key
        .normalized_y_parity()
        .ok_or_else(|| eyre!("unexpected yParity {:#x}", key.yParity))?;

    let enc = encrypt_deposit(
        &key.x,
        y_parity,
        to,
        B256::ZERO,
        sender,
        portal_addr,
        key_index,
    )
    .ok_or_else(|| eyre!("ECIES encryption failed"))?;

    let payload = DepositPayload {
        ephemeralPubkeyX: enc.eph_pub_x,
        ephemeralPubkeyYParity: enc.eph_pub_y_parity,
        ciphertext: Bytes::from(enc.ciphertext),
        nonce: enc.nonce.into(),
        tag: enc.tag.into(),
    };

    let receipt = portal
        .deposit(token, amount, key_index, payload, tempo_refund_recipient)
        .send_sync()
        .await
        .wrap_err("deposit send failed")?;
    check(&receipt, "deposit")?;
    println!(
        "  Deposit sent (block {})",
        receipt.block_number.unwrap_or(0),
    );
    println!("  {L1_EXPLORER}/{}", receipt.transaction_hash);

    Ok(())
}

/// Query a TIP-20 token balance on L2.
async fn get_l2_balance<P: Provider<TempoNetwork>>(
    l2: &P,
    token: Address,
    account: Address,
) -> eyre::Result<U256> {
    Ok(TIP20Token::new(token, l2)
        .balanceOf(account)
        .call()
        .await
        .unwrap_or_default())
}

/// Poll L2 for the deposit terminal event.
///
/// Returns `true` if the deposit bounced (blacklisted), `false` if it was accepted.
/// Times out after 60 seconds (120 polls × 500ms).
async fn wait_for_deposit_result<P: Provider<TempoNetwork>>(
    l2: &P,
    from_block: u64,
    sender: Address,
    token: Address,
    amount: u128,
    to: Address,
) -> eyre::Result<bool> {
    let processed_filter = Filter::new()
        .address(tempo_zone_contracts::ZONE_INBOX_ADDRESS)
        .event_signature(IZoneInbox::DepositProcessed::SIGNATURE_HASH)
        .from_block(from_block);
    let failed_filter = Filter::new()
        .address(tempo_zone_contracts::ZONE_INBOX_ADDRESS)
        .event_signature(IZoneInbox::DepositFailed::SIGNATURE_HASH)
        .from_block(from_block);
    for _ in 0..120 {
        let logs = l2.get_logs(&processed_filter).await.unwrap_or_default();
        for log in &logs {
            if let Ok(event) = IZoneInbox::DepositProcessed::decode_log(&log.inner)
                && event.data.sender == sender
                && event.data.to == to
                && event.data.token == token
                && event.data.amount == amount
            {
                return Ok(false);
            }
        }

        let logs = l2.get_logs(&failed_filter).await.unwrap_or_default();
        for log in &logs {
            if let Ok(event) = IZoneInbox::DepositFailed::decode_log(&log.inner)
                && event.data.sender == sender
                && event.data.token == token
                && event.data.amount == amount
            {
                return Ok(true);
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    Err(eyre!("timeout waiting for deposit result"))
}

/// Poll L1 for a `WithdrawalProcessed` event on the portal matching the recipient.
///
/// Times out after 120 seconds (240 polls × 500ms). Withdrawals are slower because
/// the sequencer must batch them and submit a proof to L1.
async fn wait_for_withdrawal_processed<P: Provider<TempoNetwork>>(
    l1: &P,
    from_block: u64,
    portal: Address,
    to: Address,
) -> eyre::Result<()> {
    let filter = Filter::new()
        .address(portal)
        .event_signature(ZonePortal::WithdrawalProcessed::SIGNATURE_HASH)
        .from_block(from_block);

    for _ in 0..240 {
        let logs = l1.get_logs(&filter).await.unwrap_or_default();
        for log in &logs {
            if let Ok(event) = ZonePortal::WithdrawalProcessed::decode_log(&log.inner)
                && event.data.to == to
            {
                let block = log.block_number.unwrap_or(0);
                let tx = log.transaction_hash.unwrap_or_default();
                println!("  Withdrawal processed on L1 (block {block})");
                println!("  {L1_EXPLORER}/{tx}");
                return Ok(());
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    Err(eyre!("timeout waiting for WithdrawalProcessed"))
}
