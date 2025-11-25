use alloy::{
    primitives::U256,
    providers::{Provider, ProviderBuilder},
    signers::local::MnemonicBuilder,
    sol_types::SolCall,
};
use alloy_eips::Encodable2718;
use alloy_network::TxSignerSync;
use tempo_contracts::precompiles::IFeeManager::setUserTokenCall;
use tempo_precompiles::DEFAULT_FEE_TOKEN_POST_ALLEGRETTO;
use tempo_primitives::TxFeeToken;

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
    let provider = ProviderBuilder::new()
        .wallet(wallet.clone())
        .connect_http(http_url);

    use tempo_precompiles::TIP_FEE_MANAGER_ADDRESS;

    // Create a fee token that has NO liquidity pool with the validator's token
    // This ensures any swap attempt will fail due to missing pool
    let no_pool_token = crate::utils::setup_test_token(provider.clone(), sender_address).await?;
    let no_pool_token_addr = *no_pool_token.address();

    println!("Created fee token with no liquidity pool: {no_pool_token_addr}");

    // Mint tokens to the sender so they can "pay" fees
    let token_amount = U256::from(100_000_000_000_000u64);
    no_pool_token
        .mint(sender_address, token_amount)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Set the user's fee token to our token that has no pool
    // This ensures subsequent transactions will require a swap through a non-existent pool
    println!("Setting user's fee token to token with no liquidity pool...");
    let mut tx = TxFeeToken {
        fee_token: Some(DEFAULT_FEE_TOKEN_POST_ALLEGRETTO),
        to: TIP_FEE_MANAGER_ADDRESS.into(),
        input: setUserTokenCall {
            token: no_pool_token_addr,
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

    // Now try to send transactions that require fee swaps through non-existent pool
    // With no liquidity pool, these should be excluded from blocks
    let num_payment_txs = 5;
    println!(
        "Sending {num_payment_txs} transactions that require fee swaps through missing pool..."
    );

    let mut transactions_included = 0;
    let mut transactions_timed_out = 0;

    for i in 0..num_payment_txs {
        let transfer = no_pool_token.transfer(sender_address, U256::from((i + 1) as u64));
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
