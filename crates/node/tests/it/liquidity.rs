use alloy::{primitives::U256, providers::ProviderBuilder, signers::local::MnemonicBuilder};
use tempo_precompiles::DEFAULT_FEE_TOKEN;

/// Test block building when FeeAMM pool has insufficient liquidity for payment transactions
#[tokio::test(flavor = "multi_thread")]
async fn test_block_building_insufficient_fee_amm_liquidity() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = crate::utils::TestNodeBuilder::new()
        .build_http_only()
        .await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
        .index(0)?
        .build()?;
    let sender_address = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    // Setup payment token
    let payment_token = crate::utils::setup_test_token(provider.clone(), sender_address).await?;
    let payment_token_addr = *payment_token.address();

    // Get validator token address (USDC from genesis)
    use tempo_precompiles::{TIP_FEE_MANAGER_ADDRESS, contracts::types::ITIPFeeAMM};
    let validator_token_addr = DEFAULT_FEE_TOKEN;

    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());
    let validator_token =
        tempo_precompiles::contracts::types::ITIP20::new(validator_token_addr, provider.clone());

    let liquidity_amount = U256::from(10_000_000);

    println!("Setting up FeeAMM pool with initial liquidity...");

    // Mint validator tokens for liquidity
    validator_token
        .mint(sender_address, liquidity_amount)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Mint payment tokens for liquidity
    payment_token
        .mint(sender_address, liquidity_amount)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Create pool by minting liquidity
    fee_amm
        .mint(
            payment_token_addr,
            validator_token_addr,
            liquidity_amount,
            liquidity_amount,
            sender_address,
        )
        .send()
        .await?
        .get_receipt()
        .await?;

    println!("FeeAMM pool created. Now draining liquidity...");

    // Get user's LP token balance
    use tempo_precompiles::contracts::tip_fee_manager::amm::PoolKey;
    let pool_key = PoolKey::new(payment_token_addr, validator_token_addr);
    let pool_id = pool_key.get_id();

    let lp_balance = fee_amm
        .liquidityBalances(pool_id, sender_address)
        .call()
        .await?;
    println!("User LP balance: {lp_balance}");

    // Burn all liquidity to drain the pool
    fee_amm
        .burn(
            payment_token_addr,
            validator_token_addr,
            lp_balance,
            sender_address,
        )
        .send()
        .await?
        .get_receipt()
        .await?;

    println!("Pool drained. Verifying insufficient liquidity...");

    let pool = fee_amm.pools(pool_id).call().await?;
    println!(
        "Pool reserves - user_token: {}, validator_token: {}",
        pool.reserveUserToken, pool.reserveValidatorToken
    );

    // Mint payment tokens for transaction fees (while still using USDC for fees)
    let additional_tokens = U256::from(100_000_000_000_000u64);
    payment_token
        .mint(sender_address, additional_tokens)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Now set the user's fee token to our custom payment token (not USDC)
    // This ensures subsequent transactions will require a swap through the drained FeeAMM
    println!("Setting user's fee token preference...");
    use tempo_precompiles::contracts::types::IFeeManager;
    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());
    fee_manager
        .setUserToken(payment_token_addr)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Now try to send payment transactions that require fee swaps
    // With insufficient liquidity, these should be excluded from blocks
    let num_payment_txs = 5;
    println!("Sending {num_payment_txs} payment transactions that require fee swaps...");

    let mut transactions_included = 0;
    let mut transactions_timed_out = 0;

    for i in 0..num_payment_txs {
        let transfer = payment_token.transfer(sender_address, U256::from((i + 1) as u64));
        match transfer.send().await {
            Ok(pending_tx) => {
                let tx_num = i + 1;
                println!("Transaction {tx_num} sent, waiting for receipt...");
                match tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    pending_tx.get_receipt(),
                )
                .await
                {
                    Ok(Ok(receipt)) => {
                        let status = receipt.status();
                        println!("Transaction {tx_num} included with status: {status:?}");
                        transactions_included += 1;
                    }
                    Ok(Err(e)) => {
                        println!("Transaction {tx_num} receipt error: {e}");
                    }
                    Err(_) => {
                        println!("Transaction {tx_num} timed out waiting for receipt");
                        transactions_timed_out += 1;
                        break; // Stop trying if we timeout
                    }
                }
            }
            Err(e) => {
                let tx_num = i + 1;
                println!("Transaction {tx_num} failed to send: {e}");
            }
        }
    }

    println!("Transactions included: {transactions_included}, timed out: {transactions_timed_out}");

    // Verify that transactions requiring unavailable liquidity were NOT included
    assert_eq!(
        transactions_included, 0,
        "Transactions requiring unavailable liquidity should be excluded from blocks"
    );
    assert!(
        transactions_timed_out > 0,
        "At least one transaction should have timed out (indicating it was excluded)"
    );

    println!("Test completed: block building continued without stalling");

    Ok(())
}
