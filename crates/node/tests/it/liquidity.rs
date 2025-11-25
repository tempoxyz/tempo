use alloy::{
    primitives::U256,
    providers::{Provider, ProviderBuilder},
    signers::local::MnemonicBuilder,
    sol_types::SolCall,
};
use alloy_eips::Encodable2718;
use alloy_network::TxSignerSync;
use tempo_contracts::precompiles::{IFeeManager::setUserTokenCall, ITIP20};
use tempo_precompiles::DEFAULT_FEE_TOKEN_POST_ALLEGRETTO;
use tempo_primitives::TxFeeToken;

use crate::utils::setup_test_token_pre_allegretto;

/// Test block building when FeeAMM pool has insufficient liquidity for payment transactions
/// Note: This test runs without allegretto to use the old balanced `mint` function
#[tokio::test(flavor = "multi_thread")]
async fn test_block_building_insufficient_fee_amm_liquidity() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Run without allegretto to use the old `mint` function that creates balanced pools
    let setup = crate::utils::TestNodeBuilder::new()
        .build_http_only()
        .await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
        .index(0)?
        .build()?;
    let sender_address = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet.clone())
        .connect_http(http_url);

    // Setup payment token using pre-allegretto createToken_0
    let payment_token = setup_test_token_pre_allegretto(provider.clone(), sender_address).await?;
    let payment_token_addr = *payment_token.address();

    // Get validator token address (USDC from genesis)
    use tempo_contracts::precompiles::ITIPFeeAMM;
    use tempo_precompiles::TIP_FEE_MANAGER_ADDRESS;
    let validator_token_addr = DEFAULT_FEE_TOKEN_POST_ALLEGRETTO;

    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());
    let validator_token = ITIP20::new(validator_token_addr, provider.clone());

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

    // Create pool by minting liquidity with both tokens (balanced pool)
    // This requires pre-Moderato spec since mint is disabled post-Moderato
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
    use tempo_precompiles::tip_fee_manager::amm::PoolKey;
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
    let mut tx = TxFeeToken {
        fee_token: Some(DEFAULT_FEE_TOKEN_POST_ALLEGRETTO),
        to: TIP_FEE_MANAGER_ADDRESS.into(),
        input: setUserTokenCall {
            token: payment_token_addr,
        }
        .abi_encode()
        .into(),
        chain_id: provider.get_chain_id().await?,
        max_fee_per_gas: provider.get_gas_price().await?,
        max_priority_fee_per_gas: provider.get_gas_price().await?,
        nonce: provider.get_transaction_count(sender_address).await?,
        gas_limit: 100000,
        ..Default::default()
    };
    let signature = wallet.sign_transaction_sync(&mut tx).unwrap();
    let tx = tx.into_signed(signature);
    provider
        .send_raw_transaction(&tx.encoded_2718())
        .await?
        .watch()
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
