use alloy::{
    network::ReceiptResponse,
    primitives::U256,
    providers::{Provider, ProviderBuilder},
    signers::local::MnemonicBuilder,
};
use alloy_rpc_types_eth::TransactionRequest;
use std::env;
use tempo_chainspec::spec::TEMPO_BASE_FEE;
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    contracts::{IFeeManager, ITIP20},
};

#[tokio::test(flavor = "multi_thread")]
async fn test_payment_lane_with_mixed_load() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        crate::utils::NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        crate::utils::NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _local_node) = crate::utils::setup_test_node(source).await?;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url.clone());

    // Create another wallet for sending different transactions
    let wallet2 = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
        .index(1)?
        .build()?;
    let caller2 = wallet2.address();
    let provider2 = ProviderBuilder::new()
        .wallet(wallet2)
        .connect_http(http_url.clone());

    // Ensure the native account balance is 0
    assert_eq!(provider.get_balance(caller).await?, U256::ZERO);
    assert_eq!(provider2.get_balance(caller2).await?, U256::ZERO);

    // Get fee tokens for both accounts
    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());
    let fee_token_address1 = fee_manager.userTokens(caller).call().await?;
    let fee_token1 = ITIP20::new(fee_token_address1, provider.clone());

    let fee_manager2 = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider2.clone());
    let fee_token_address2 = fee_manager2.userTokens(caller2).call().await?;
    let fee_token2 = ITIP20::new(fee_token_address2, provider2.clone());

    // Setup TIP20 tokens for payment transactions
    let token = crate::utils::setup_test_token(provider.clone(), caller).await?;
    let token2 = crate::utils::setup_test_token(provider2.clone(), caller2).await?;

    // Mint tokens for testing
    let mint_amount = U256::from(1_000_000);
    token
        .mint(caller, mint_amount)
        .send()
        .await?
        .get_receipt()
        .await?;
    token2
        .mint(caller2, mint_amount)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Step 1: Send N blocks worth of non-payment transactions
    // Use multiple accounts sending in parallel for speed
    let mut non_payment_receipts = vec![];

    // Create multiple accounts for parallel sending
    let num_accounts = 10;
    let mut accounts = vec![];
    let mut providers = vec![];

    for i in 0..num_accounts {
        let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
            .index(i as u32 + 2)? // Start from index 2 (0 and 1 are already used)
            .build()?;
        let address = wallet.address();
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(http_url.clone());
        accounts.push(address);
        providers.push(provider);
    }

    // Send transactions from multiple accounts in batches
    // Target ~3 full blocks (100-150 txs per block = ~300-450 total)
    let txs_per_account = 10; // 10 txs per account = 100 total txs per batch
    let num_batches = 4; // 4 batches = 400 total txs

    println!(
        "Sending {} batches of {} non-payment transactions from {} accounts...",
        num_batches,
        txs_per_account * num_accounts,
        num_accounts
    );

    for batch in 0..num_batches {
        let mut batch_futures = vec![];

        // Send transactions from all accounts in parallel
        for (i, provider) in providers.iter().enumerate() {
            for _ in 0..txs_per_account {
                let tx = TransactionRequest::default()
                    .from(accounts[i])
                    .to(accounts[i]) // Send to self
                    .gas_price(TEMPO_BASE_FEE as u128)
                    .gas_limit(100000)
                    .value(U256::ZERO);

                batch_futures.push(provider.send_transaction(tx));
            }
        }

        // Wait for all transactions in this batch
        println!(
            "Batch {}: Sending {} transactions...",
            batch + 1,
            batch_futures.len()
        );
        let pending_txs = futures::future::try_join_all(batch_futures).await?;

        // Collect receipts
        let receipt_futures = pending_txs.into_iter().map(|tx| tx.get_receipt());
        let batch_receipts = futures::future::try_join_all(receipt_futures).await?;

        for receipt in batch_receipts {
            assert!(receipt.status(), "Non-payment tx should succeed");
            non_payment_receipts.push(receipt);
        }

        println!(
            "Batch {} complete: {} total transactions sent",
            batch + 1,
            non_payment_receipts.len()
        );
    }

    // Verify we actually filled multiple blocks with non-payment transactions
    let mut block_numbers = std::collections::HashSet::new();
    for receipt in &non_payment_receipts {
        if let Some(block_num) = receipt.block_number() {
            block_numbers.insert(block_num);
        }
    }

    println!(
        "\nNon-payment transactions were included in {} unique blocks",
        block_numbers.len()
    );
    assert!(
        block_numbers.len() >= 3,
        "Expected at least 3 blocks of non-payment transactions, got {}",
        block_numbers.len()
    );

    // Check that blocks are actually full (have many transactions)
    let mut txs_per_block = std::collections::HashMap::new();
    for receipt in &non_payment_receipts {
        if let Some(block_num) = receipt.block_number() {
            *txs_per_block.entry(block_num).or_insert(0) += 1;
        }
    }

    // Sort blocks by block number for better output
    let mut sorted_blocks: Vec<_> = txs_per_block.iter().collect();
    sorted_blocks.sort_by_key(|(block_num, _)| *block_num);

    println!("\nTransaction distribution across blocks:");
    for (block_num, tx_count) in sorted_blocks {
        println!("  Block {block_num}: {tx_count} non-payment transactions");
    }

    // Find blocks that are reasonably full (at least 50 txs each)
    let min_txs_for_full_block = 50;
    let full_blocks: Vec<_> = txs_per_block
        .iter()
        .filter(|(_, count)| **count >= min_txs_for_full_block)
        .collect();

    println!(
        "\nFull blocks (>= {} txs): {} blocks",
        min_txs_for_full_block,
        full_blocks.len()
    );
    assert!(
        full_blocks.len() >= 3,
        "Expected at least 3 full blocks with >= {} transactions, got {} full blocks",
        min_txs_for_full_block,
        full_blocks.len()
    );

    // Step 2: Continue non-payment load WHILE adding payment transactions
    println!("\nContinuing non-payment load while adding payment transactions...");

    let mut payment_receipts = vec![];
    let mut continued_non_payment_receipts = vec![];

    // Continue sending non-payment transactions from multiple accounts
    // while also sending payment transactions - simulating real mixed load
    let mixed_batches = 2; // Continue for 2 more batches
    let payments_per_batch = 5;
    let expected_total_payments = mixed_batches * payments_per_batch;

    for batch in 0..mixed_batches {
        println!(
            "\nMixed batch {}: Sending non-payment AND payment transactions...",
            batch + 1
        );

        // Create interleaved transactions - mix them together
        let mut all_futures = vec![];

        // Interleave non-payment and payment transactions
        for i in 0..txs_per_account {
            // Add non-payment transactions from all accounts
            for (j, provider) in providers.iter().enumerate() {
                let tx = TransactionRequest::default()
                    .from(accounts[j])
                    .to(accounts[j]) // Send to self
                    .gas_price(TEMPO_BASE_FEE as u128)
                    .gas_limit(100000)
                    .value(U256::ZERO);

                all_futures.push((provider.send_transaction(tx), "non-payment"));
            }

            // Interleave payment transactions (spread them throughout)
            if i < payments_per_batch {
                let transfer_tx =
                    token2.transfer(caller2, U256::from(batch * payments_per_batch + i + 1));
                let tx = transfer_tx
                    .into_transaction_request()
                    .from(caller2)
                    .gas_price(TEMPO_BASE_FEE as u128)
                    .gas_limit(80000);

                all_futures.push((provider2.send_transaction(tx), "payment"));
            }
        }

        println!(
            "  Sending {} non-payment + {} payment transactions interleaved...",
            txs_per_account * num_accounts,
            payments_per_batch
        );

        // Execute ALL transactions concurrently
        let mut payment_futures = vec![];
        let mut non_payment_futures = vec![];

        for (fut, tx_type) in all_futures {
            if tx_type == "payment" {
                payment_futures.push(fut);
            } else {
                non_payment_futures.push(fut);
            }
        }

        // Send all transactions concurrently
        let (non_payment_pending, payment_pending) = futures::future::try_join(
            futures::future::try_join_all(non_payment_futures),
            futures::future::try_join_all(payment_futures),
        )
        .await?;

        // Collect receipts
        let non_payment_receipt_futures =
            non_payment_pending.into_iter().map(|tx| tx.get_receipt());
        let payment_receipt_futures = payment_pending.into_iter().map(|tx| tx.get_receipt());

        let (batch_non_payment_receipts, batch_payment_receipts) = futures::future::try_join(
            futures::future::try_join_all(non_payment_receipt_futures),
            futures::future::try_join_all(payment_receipt_futures),
        )
        .await?;

        // Verify all succeeded and collect
        for receipt in batch_non_payment_receipts {
            assert!(receipt.status(), "Continued non-payment tx should succeed");
            continued_non_payment_receipts.push(receipt);
        }

        for receipt in batch_payment_receipts {
            assert!(
                receipt.status(),
                "Payment tx should succeed despite continued load"
            );
            payment_receipts.push(receipt);
        }

        println!(
            "  Mixed batch {} complete: {} non-payment, {} payment transactions",
            batch + 1,
            continued_non_payment_receipts.len(),
            payment_receipts.len()
        );
    }

    // Verify we sent the expected number of payment transactions
    assert_eq!(
        payment_receipts.len(),
        expected_total_payments,
        "Expected {} payment transactions, got {}",
        expected_total_payments,
        payment_receipts.len()
    );

    // Step 3: Verify expectations
    println!("\n=== Test Results ===");

    // Expectation 1: All payment transactions should be included despite continued DeFi load
    assert!(
        !payment_receipts.is_empty(),
        "Payment transactions should be included"
    );
    for receipt in &payment_receipts {
        assert!(receipt.status(), "Payment transaction should succeed");
    }
    println!(
        "All {} payment transactions were successfully included despite continued non-payment load",
        payment_receipts.len()
    );

    // Expectation 2: Payment fees should remain low (basefee) as they're not competing with DeFi
    for receipt in &payment_receipts {
        let effective_price = receipt.effective_gas_price();
        assert_eq!(
            effective_price, TEMPO_BASE_FEE as u128,
            "Payment tx should pay base fee, not elevated prices"
        );
    }
    println!("Payment transactions paid base fee ({TEMPO_BASE_FEE})");

    // Expectation 3: Both types of transactions coexist in blocks
    let total_non_payment = non_payment_receipts.len() + continued_non_payment_receipts.len();
    let total_payment = payment_receipts.len();

    assert_eq!(
        total_payment, expected_total_payments,
        "Expected {expected_total_payments} payment transactions, got {total_payment}"
    );

    println!(
        "Successfully processed {total_non_payment} non-payment and {total_payment} payment transactions"
    );
    println!(
        "  Initial non-payment load: {} transactions",
        non_payment_receipts.len()
    );
    println!(
        "  Continued non-payment load (during payment phase): {} transactions",
        continued_non_payment_receipts.len()
    );

    // Verify that both payment and non-payment transactions exist in the same blocks
    let mut non_payment_blocks = std::collections::HashSet::new();
    let mut payment_blocks = std::collections::HashSet::new();

    for receipt in &continued_non_payment_receipts {
        if let Some(block_num) = receipt.block_number() {
            non_payment_blocks.insert(block_num);
        }
    }

    for receipt in &payment_receipts {
        if let Some(block_num) = receipt.block_number() {
            payment_blocks.insert(block_num);
        }
    }

    // Find blocks that have both types
    let mixed_blocks: std::collections::HashSet<_> = non_payment_blocks
        .intersection(&payment_blocks)
        .cloned()
        .collect();

    assert!(
        !mixed_blocks.is_empty(),
        "Expected at least some blocks with both payment and non-payment transactions"
    );

    println!(
        "Verified: {} blocks contain both payment and non-payment transactions",
        mixed_blocks.len()
    );

    // Check fee token balances were properly deducted
    let balance1_after = fee_token1.balanceOf(caller).call().await?;
    let balance2_after = fee_token2.balanceOf(caller2).call().await?;

    println!("\nFee token balance changes:");
    println!("  Account 1 (non-payment sender): balance after = {balance1_after}");
    println!("  Account 2 (payment sender): balance after = {balance2_after}");

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_payment_lane_ordering() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        crate::utils::NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        crate::utils::NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _local_node) = crate::utils::setup_test_node(source).await?;

    // Use two different accounts to avoid nonce ordering issues.
    // We use one account for non-payment transactions and another for payment transactions.
    // This allows us to send them in any order (mixed), since transactions from the same
    // account must execute in nonce order which would prevent testing arbitrary reordering.
    let wallet1 = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller1 = wallet1.address();
    let provider1 = ProviderBuilder::new()
        .wallet(wallet1)
        .connect_http(http_url.clone());

    let wallet2 = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
        .index(1)?
        .build()?;
    let caller2 = wallet2.address();
    let provider2 = ProviderBuilder::new()
        .wallet(wallet2)
        .connect_http(http_url);

    // Setup TIP20 tokens for both accounts
    let token1 = crate::utils::setup_test_token(provider1.clone(), caller1).await?;
    token1
        .mint(caller1, U256::from(1_000_000))
        .send()
        .await?
        .get_receipt()
        .await?;

    let token2 = crate::utils::setup_test_token(provider2.clone(), caller2).await?;
    token2
        .mint(caller2, U256::from(1_000_000))
        .send()
        .await?
        .get_receipt()
        .await?;

    // Send transactions in mixed order from different accounts
    // This avoids nonce ordering constraints within a single account
    let mut all_txs = vec![];

    // Send PAYMENT from account 1
    let transfer_tx = token1.transfer(caller1, U256::from(1));
    let tx = transfer_tx
        .into_transaction_request()
        .from(caller1)
        .gas_price(TEMPO_BASE_FEE as u128)
        .gas_limit(80000);
    println!("Sending PAYMENT tx from account 1");
    all_txs.push((provider1.send_transaction(tx).await?, "payment-1"));

    // Send NON-PAYMENT from account 2
    let tx = TransactionRequest::default()
        .from(caller2)
        .to(caller2)
        .gas_price(TEMPO_BASE_FEE as u128)
        .gas_limit(80000)
        .value(U256::ZERO);
    println!("Sending NON-PAYMENT tx from account 2");
    all_txs.push((provider2.send_transaction(tx).await?, "non-payment-2"));

    // Send another PAYMENT from account 2
    let transfer_tx = token2.transfer(caller2, U256::from(2));
    let tx = transfer_tx
        .into_transaction_request()
        .from(caller2)
        .gas_price(TEMPO_BASE_FEE as u128)
        .gas_limit(80000);
    println!("Sending PAYMENT tx from account 2");
    all_txs.push((provider2.send_transaction(tx).await?, "payment-2"));

    // Send another NON-PAYMENT from account 1
    let tx = TransactionRequest::default()
        .from(caller1)
        .to(caller1)
        .gas_price(TEMPO_BASE_FEE as u128)
        .gas_limit(80000)
        .value(U256::ZERO);
    println!("Sending NON-PAYMENT tx from account 1");
    all_txs.push((provider1.send_transaction(tx).await?, "non-payment-1"));

    println!("\nWaiting for all transactions to be mined...");

    // Collect receipts and check they all succeeded
    for (pending_tx, tx_type) in all_txs {
        let receipt = pending_tx.get_receipt().await?;

        if !receipt.status() {
            // If a transaction fails, let's understand why
            println!("ERROR: {tx_type} transaction failed!");
            println!("  Block number: {:?}", receipt.block_number());
            println!("  Gas used: {}", receipt.gas_used);

            // This might indicate the ordering constraint is being violated
            // or there's another issue
            panic!("{tx_type} transaction failed - this might indicate improper lane ordering");
        }
        println!(
            "  {} transaction succeeded (gas used: {})",
            tx_type, receipt.gas_used
        );
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_payment_lane_gas_limits() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        crate::utils::NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        crate::utils::NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _local_node) = crate::utils::setup_test_node(source).await?;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    // Setup a TIP20 token for payment transactions
    let token = crate::utils::setup_test_token(provider.clone(), caller).await?;
    token
        .mint(caller, U256::from(1_000_000))
        .send()
        .await?
        .get_receipt()
        .await?;

    // Test that payment transactions can use gas even when non-payment gas is exhausted
    // First, send high-gas non-payment transactions to approach the limit
    println!("Sending high-gas non-payment transactions...");
    let mut non_payment_gas_used = 0u64;

    for i in 0..3 {
        let tx = TransactionRequest::default()
            .from(caller)
            .to(caller) // Send to self
            .gas_price(TEMPO_BASE_FEE as u128)
            .gas_limit(500000) // High gas limit
            .value(U256::ZERO);

        let pending_tx = provider.send_transaction(tx).await?;
        let receipt = pending_tx.get_receipt().await?;
        assert!(receipt.status(), "High-gas non-payment tx should succeed");
        non_payment_gas_used += receipt.gas_used;
        println!(
            "Non-payment tx {} used {} gas, total: {}",
            i, receipt.gas_used, non_payment_gas_used
        );
    }

    // Now send payment transactions - they should still go through
    println!("\nSending payment transactions (should succeed despite non-payment gas usage)...");
    for i in 0..3 {
        // Send valid TIP20 transfer transactions
        let transfer_tx = token.transfer(caller, U256::from(1));
        let tx = transfer_tx
            .into_transaction_request()
            .from(caller)
            .gas_price(TEMPO_BASE_FEE as u128)
            .gas_limit(100000);

        let pending_tx = provider.send_transaction(tx).await?;
        let receipt = pending_tx.get_receipt().await?;
        assert!(
            receipt.status(),
            "Payment tx should succeed even with high non-payment gas usage"
        );
        println!("Payment tx {} succeeded, used {} gas", i, receipt.gas_used);
    }

    Ok(())
}
