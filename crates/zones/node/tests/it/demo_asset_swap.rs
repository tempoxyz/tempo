//! Multi-asset zone deposit and withdrawal.

use crate::utils::{L1TestNode, ZoneAccount, ZoneTestNode, spawn_sequencer};
use alloy::{
    primitives::{B256, U256},
    providers::Provider,
};

/// Longer timeout for real L1 tests.
const L1_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Multi-asset deposit + withdrawal:
///
/// 1. Start L1 dev node.
/// 2. Create AlphaUSD and BetaUSD on L1.
/// 3. Deploy zone, enable both tokens.
/// 4. Start zone node (tokens auto-initialized via `TokenEnabled` events from L1).
/// 5. Alice deposits AlphaUSD and BetaUSD.
/// 6. Spawn sequencer, withdraw both tokens.
/// 7. Verify L1 withdrawals and L2 balance decreases.
///
/// ```text
///  L1 (AlphaUSD + BetaUSD)            Zone L2
///   |--- deposit AlphaUSD ----------->|  ✓ AlphaUSD minted
///   |--- deposit BetaUSD ------------>|  ✓ BetaUSD minted
///   |<-- withdraw AlphaUSD -----------|  ✓ AlphaUSD burned
///   |<-- withdraw BetaUSD ------------|  ✓ BetaUSD burned
/// ```
///
/// NOTE: Requires `forge build` in `crates/contracts/` for shared runtime artifacts.
#[tokio::test(flavor = "multi_thread")]
async fn test_multiasset_deposit_and_withdraw() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // --- Step 1: Start L1 ---
    let l1 = L1TestNode::start().await?;

    // --- Step 2: Create two TIP-20 tokens on L1 ---
    let alpha_salt = B256::with_last_byte(100);
    let beta_salt = B256::with_last_byte(101);

    let l1_alpha = l1.create_tip20("AlphaUSD", "aUSD", alpha_salt).await?;
    let l1_beta = l1.create_tip20("BetaUSD", "bUSD", beta_salt).await?;

    let mint_amount: u128 = 100_000_000; // 100 tokens (6 decimals)
    l1.mint_tip20(l1_alpha, l1.dev_address(), mint_amount)
        .await?;
    l1.mint_tip20(l1_beta, l1.dev_address(), mint_amount)
        .await?;

    // --- Step 3: Deploy zone and start zone node ---
    let portal_address = l1.deploy_zone().await?;
    let zone = ZoneTestNode::start_from_l1(l1.http_url(), l1.ws_url(), portal_address).await?;

    // --- Step 4: Enable both tokens on the portal ---
    // Must happen AFTER zone startup so the zone's L1 subscriber picks up the
    // TokenEnabled events from live blocks.
    l1.enable_token_on_portal(portal_address, l1_alpha).await?;
    l1.enable_token_on_portal(portal_address, l1_beta).await?;
    let enable_block = l1.provider().get_block_number().await?;

    // Wait for the zone to finalize past the enableToken blocks
    zone.wait_for_l2_tempo_finalized(enable_block, L1_TIMEOUT)
        .await?;

    // L1 and L2 token addresses are the same by design
    let l2_alpha = l1_alpha;
    let l2_beta = l1_beta;

    // --- Step 5: Alice deposits both tokens ---
    let mut account = ZoneAccount::from_l1_and_zone(&l1, &zone, portal_address);
    let alpha_deposit: u128 = 1_000_000; // 1 AlphaUSD
    let beta_deposit: u128 = 2_000_000; // 2 BetaUSD

    // Fund Alice on L1
    l1.fund_user(account.address(), 10_000_000).await?; // pathUSD for gas
    l1.fund_user_token(l1_alpha, account.address(), alpha_deposit * 2)
        .await?;
    l1.fund_user_token(l1_beta, account.address(), beta_deposit * 2)
        .await?;

    // Deposit pathUSD for L2 gas
    account.deposit(5_000_000, L1_TIMEOUT, &zone).await?;

    // Deposit AlphaUSD
    let alpha_minted = account
        .deposit_token(l1_alpha, l2_alpha, alpha_deposit, L1_TIMEOUT, &zone)
        .await?;
    assert_eq!(
        alpha_minted,
        U256::from(alpha_deposit),
        "AlphaUSD minted should equal deposit"
    );

    // Deposit BetaUSD
    let beta_minted = account
        .deposit_token(l1_beta, l2_beta, beta_deposit, L1_TIMEOUT, &zone)
        .await?;
    assert_eq!(
        beta_minted,
        U256::from(beta_deposit),
        "BetaUSD minted should equal deposit"
    );

    // --- Step 6: Spawn zone sequencer (batch submitter + withdrawal processor) ---
    let _sequencer_handle = spawn_sequencer(&l1, &zone, portal_address, l1.dev_signer()).await;
    let withdrawal_timeout = std::time::Duration::from_secs(60);

    // Withdraw AlphaUSD
    let alpha_withdrawal: u128 = 500_000; // 0.5 AlphaUSD
    let alpha_balance_before = l1.balance_of(l1_alpha, account.address()).await?;
    account.withdraw_token(l2_alpha, alpha_withdrawal).await?;

    l1.wait_for_withdrawal_on_l1_token(
        portal_address,
        l1_alpha,
        account.address(),
        alpha_balance_before,
        alpha_withdrawal,
        withdrawal_timeout,
    )
    .await?;

    // Withdraw BetaUSD
    let beta_withdrawal: u128 = 1_000_000; // 1 BetaUSD
    let beta_balance_before = l1.balance_of(l1_beta, account.address()).await?;
    account.withdraw_token(l2_beta, beta_withdrawal).await?;

    l1.wait_for_withdrawal_on_l1_token(
        portal_address,
        l1_beta,
        account.address(),
        beta_balance_before,
        beta_withdrawal,
        withdrawal_timeout,
    )
    .await?;

    // --- Step 7: Verify L2 balances decreased ---
    let final_alpha = zone.balance_of(l2_alpha, account.address()).await?;
    assert!(
        final_alpha <= U256::from(alpha_deposit - alpha_withdrawal),
        "L2 AlphaUSD should decrease after withdrawal (got {final_alpha})"
    );

    let final_beta = zone.balance_of(l2_beta, account.address()).await?;
    assert!(
        final_beta <= U256::from(beta_deposit - beta_withdrawal),
        "L2 BetaUSD should decrease after withdrawal (got {final_beta})"
    );

    Ok(())
}
