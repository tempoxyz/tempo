use alloy::{
    consensus::Transaction,
    network::{EthereumWallet, TransactionBuilder},
    primitives::U256,
    providers::{Provider, ProviderBuilder},
    signers::local::MnemonicBuilder,
    sol_types::SolEvent,
};
use alloy_eips::eip2718::Encodable2718;
use alloy_network::Ethereum;
use alloy_primitives::Bytes;
use alloy_rpc_types_eth::TransactionRequest;
use reth_e2e_test_utils::transaction::TransactionTestContext;
use tempo_node::node::TempoNode;
use tempo_precompiles::{
    LINKING_USD_ADDRESS, TIP20_FACTORY_ADDRESS,
    contracts::{
        ITIP20, ITIP20Factory, tip20::ISSUER_ROLE, token_id_to_address, types::IRolesAuth,
    },
};
use tempo_primitives::TempoTxEnvelope;

/// Helper to setup a test token by manually injecting transactions and advancing blocks
async fn setup_token_manual<P>(
    node: &mut reth_e2e_test_utils::NodeHelperType<TempoNode>,
    provider: &P,
    sender: &alloy::signers::local::PrivateKeySigner,
    chain_id: u64,
) -> eyre::Result<ITIP20::ITIP20Instance<P>>
where
    P: Provider + Clone,
{
    let factory = ITIP20Factory::new(TIP20_FACTORY_ADDRESS, provider.clone());
    let sender_address = sender.address();
    let signer = EthereumWallet::from(sender.clone());

    // Helper to sign and encode a transaction
    let sign_and_encode = |mut tx_req: TransactionRequest, nonce: u64| {
        let signer_clone = signer.clone();
        async move {
            tx_req.nonce = Some(nonce);
            tx_req.chain_id = Some(chain_id);
            tx_req.gas = tx_req.gas.or(Some(200_000));
            tx_req.max_fee_per_gas = tx_req.max_fee_per_gas.or(Some(20e9 as u128));
            tx_req.max_priority_fee_per_gas =
                tx_req.max_priority_fee_per_gas.or(Some(20e9 as u128));

            let signed =
                <TransactionRequest as TransactionBuilder<Ethereum>>::build(tx_req, &signer_clone)
                    .await?;
            Ok::<Bytes, eyre::Error>(signed.encoded_2718().into())
        }
    };

    // Create token
    let create_tx = factory.createToken(
        "Test".to_string(),
        "TEST".to_string(),
        "USD".to_string(),
        LINKING_USD_ADDRESS,
        sender_address,
    );
    let create_bytes = sign_and_encode(create_tx.into_transaction_request(), 0).await?;
    node.rpc.inject_tx(create_bytes).await?;
    node.advance_block().await?;

    // Get token address from logs
    let latest_block = provider.get_block_number().await?;
    let receipts = provider
        .get_block_receipts(latest_block.into())
        .await?
        .unwrap();
    let token_create_receipt = receipts
        .iter()
        .find(|r| !r.inner.logs().is_empty())
        .ok_or_else(|| eyre::eyre!("No receipt with logs found"))?;
    let event =
        ITIP20Factory::TokenCreated::decode_log(&token_create_receipt.inner.logs()[0].inner)?;
    let token_addr = token_id_to_address(event.tokenId.to());

    // Grant issuer role
    let roles = IRolesAuth::new(token_addr, provider.clone());
    let grant_tx = roles.grantRole(*ISSUER_ROLE, sender_address);
    let grant_bytes = sign_and_encode(grant_tx.into_transaction_request(), 1).await?;
    node.rpc.inject_tx(grant_bytes).await?;
    node.advance_block().await?;

    // Mint tokens
    let token = ITIP20::ITIP20Instance::new(token_addr, provider.clone());
    let mint_tx = token.mint(sender_address, U256::from(1_000_000));
    let mint_bytes = sign_and_encode(mint_tx.into_transaction_request(), 2).await?;
    node.rpc.inject_tx(mint_bytes).await?;
    node.advance_block().await?;

    Ok(token)
}

/// Helper to extract user transactions (non-system transactions)
fn extract_user_txs(all_transactions: Vec<TempoTxEnvelope>) -> Vec<TempoTxEnvelope> {
    all_transactions
        .into_iter()
        .filter(|tx| tx.gas_limit() > 0)
        .collect()
}

/// Helper to inject non-payment transactions from multiple wallets
async fn inject_non_payment_txs(
    node: &mut reth_e2e_test_utils::NodeHelperType<TempoNode>,
    chain_id: u64,
    count: usize,
    start_index: u32,
) -> eyre::Result<()> {
    for i in 0..count {
        let wallet_signer = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
            .index(start_index + i as u32)?
            .build()?;
        let raw_tx = TransactionTestContext::transfer_tx_bytes(chain_id, wallet_signer).await;
        node.rpc.inject_tx(raw_tx).await?;
    }
    Ok(())
}

/// Helper to inject payment transactions from a single sender
async fn inject_payment_txs_from_sender<P>(
    node: &mut reth_e2e_test_utils::NodeHelperType<TempoNode>,
    provider: &P,
    sender: &alloy::signers::local::PrivateKeySigner,
    token: &ITIP20::ITIP20Instance<P>,
    chain_id: u64,
    count: usize,
) -> eyre::Result<()>
where
    P: Provider + Clone,
{
    let current_nonce = provider.get_transaction_count(sender.address()).await?;
    let signer = EthereumWallet::from(sender.clone());

    for i in 0..count {
        let transfer_tx = token.transfer(sender.address(), U256::from((i + 1) as u64));
        let mut tx_request = transfer_tx.into_transaction_request();
        tx_request.nonce = Some(current_nonce + i as u64);
        tx_request.chain_id = Some(chain_id);
        tx_request.gas = Some(100_000);
        tx_request.max_fee_per_gas = Some(20e9 as u128);
        tx_request.max_priority_fee_per_gas = Some(20e9 as u128);

        let signed_tx =
            <TransactionRequest as TransactionBuilder<Ethereum>>::build(tx_request, &signer)
                .await?;
        let tx_bytes: Bytes = signed_tx.encoded_2718().into();
        node.rpc.inject_tx(tx_bytes).await?;
    }
    Ok(())
}

/// Helper to count payment and non-payment transactions
fn count_transaction_types(transactions: &[TempoTxEnvelope]) -> (usize, usize) {
    let payment_count = transactions.iter().filter(|tx| tx.is_payment()).count();
    let non_payment_count = transactions.iter().filter(|tx| !tx.is_payment()).count();
    (payment_count, non_payment_count)
}

/// Test with only a few mixed payment and non-payment transactions
#[tokio::test(flavor = "multi_thread")]
async fn test_block_building_few_mixed_txs() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = crate::utils::TestNodeBuilder::new()
        .build_with_node_access()
        .await?;

    let payment_sender = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
        .index(0)?
        .build()?;
    let payment_wallet = EthereumWallet::from(payment_sender.clone());

    let http_url = setup.node.rpc_url();
    let provider = ProviderBuilder::new()
        .wallet(payment_wallet.clone())
        .connect_http(http_url.clone());

    let chain_id = provider.get_chain_id().await?;

    let payment_token =
        setup_token_manual(&mut setup.node, &provider, &payment_sender, chain_id).await?;

    // Inject a few mixed transactions
    let num_payment_txs: usize = 3;
    let num_non_payment_txs: usize = 3;

    println!(
        "Injecting {num_payment_txs} payment and {num_non_payment_txs} non-payment transactions into pool..."
    );

    // Inject non-payment transactions
    inject_non_payment_txs(&mut setup.node, chain_id, num_non_payment_txs, 10).await?;

    // Inject payment transactions
    inject_payment_txs_from_sender(
        &mut setup.node,
        &provider,
        &payment_sender,
        &payment_token,
        chain_id,
        num_payment_txs,
    )
    .await?;

    println!("Building block with few mixed transactions...");
    let payload = setup.node.advance_block().await?;

    let block = payload.block();
    let all_transactions: Vec<_> = block.body().transactions().cloned().collect();
    let user_txs = extract_user_txs(all_transactions.clone());

    println!(
        "Block built with {} total transactions, {} user transactions",
        all_transactions.len(),
        user_txs.len()
    );

    // Verify all transactions fit in one block (few transactions scenario)
    assert_eq!(
        user_txs.len(),
        num_payment_txs + num_non_payment_txs,
        "Block should contain all transactions when there are only a few"
    );

    // Count transaction types
    let (payment_count, non_payment_count) = count_transaction_types(&user_txs);

    println!(
        "Block contains {payment_count} payment and {non_payment_count} non-payment transactions"
    );

    assert_eq!(
        payment_count, num_payment_txs,
        "Should have all payment transactions"
    );
    assert_eq!(
        non_payment_count, num_non_payment_txs,
        "Should have all non-payment transactions"
    );

    Ok(())
}

/// Test with only payment transactions
#[tokio::test(flavor = "multi_thread")]
async fn test_block_building_only_payment_txs() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = crate::utils::TestNodeBuilder::new()
        .build_with_node_access()
        .await?;

    let payment_sender = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
        .index(0)?
        .build()?;
    let payment_wallet = EthereumWallet::from(payment_sender.clone());

    let http_url = setup.node.rpc_url();
    let provider = ProviderBuilder::new()
        .wallet(payment_wallet.clone())
        .connect_http(http_url.clone());

    let chain_id = provider.get_chain_id().await?;

    // Setup payment token
    let payment_token =
        setup_token_manual(&mut setup.node, &provider, &payment_sender, chain_id).await?;

    let num_payment_txs: usize = 10;
    println!("Injecting {num_payment_txs} payment transactions into pool...");

    // Inject only payment transactions
    inject_payment_txs_from_sender(
        &mut setup.node,
        &provider,
        &payment_sender,
        &payment_token,
        chain_id,
        num_payment_txs,
    )
    .await?;

    println!("Building block...");
    let payload = setup.node.advance_block().await?;

    let block = payload.block();
    let all_transactions: Vec<_> = block.body().transactions().cloned().collect();
    let user_txs = extract_user_txs(all_transactions.clone());

    println!(
        "Block built with {} total transactions, {} user transactions",
        all_transactions.len(),
        user_txs.len()
    );

    assert_eq!(
        user_txs.len(),
        num_payment_txs,
        "Block should contain all payment transactions"
    );

    for tx in &user_txs {
        assert!(
            tx.is_payment(),
            "All transactions should be payment transactions"
        );
    }

    Ok(())
}

/// Test with only non-payment transactions
#[tokio::test(flavor = "multi_thread")]
async fn test_block_building_only_non_payment_txs() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = crate::utils::TestNodeBuilder::new()
        .build_with_node_access()
        .await?;

    let http_url = setup.node.rpc_url();
    let provider = ProviderBuilder::new().connect_http(http_url.clone());

    let chain_id = provider.get_chain_id().await?;

    let num_non_payment_txs: usize = 10;

    println!("Injecting {num_non_payment_txs} non-payment transactions into pool...");

    // Use reth_e2e_test_utils Wallet for funded accounts
    use reth_e2e_test_utils::wallet::Wallet;
    let wallets = Wallet::new(num_non_payment_txs)
        .with_chain_id(chain_id)
        .wallet_gen();
    for wallet_signer in wallets {
        let raw_tx = TransactionTestContext::transfer_tx_bytes(chain_id, wallet_signer).await;
        setup.node.rpc.inject_tx(raw_tx).await?;
    }

    println!("Building block...");
    let payload = setup.node.advance_block().await?;

    let block = payload.block();
    let all_transactions: Vec<_> = block.body().transactions().cloned().collect();
    let user_txs = extract_user_txs(all_transactions.clone());

    println!(
        "Block built with {} total transactions, {} user transactions",
        all_transactions.len(),
        user_txs.len()
    );

    assert_eq!(
        user_txs.len(),
        num_non_payment_txs,
        "Block should contain all non-payment transactions"
    );

    for tx in &user_txs {
        assert!(
            !tx.is_payment(),
            "All transactions should be non-payment transactions"
        );
    }

    Ok(())
}

/// Test with more transactions than fit in a single block
#[tokio::test(flavor = "multi_thread")]
async fn test_block_building_more_txs_than_fit() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Use lower gas limit to ensure transactions overflow to multiple blocks
    let mut setup = crate::utils::TestNodeBuilder::new()
        .with_gas_limit("0xf4240") // 1,000,000 gas
        .build_with_node_access()
        .await?;

    let http_url = setup.node.rpc_url();
    let provider = ProviderBuilder::new().connect_http(http_url.clone());

    let chain_id = provider.get_chain_id().await?;

    // Create many transactions to test handling of large transaction pools
    // Use multiple payment senders to avoid per-account in-flight limit
    let num_payment_senders: usize = 30; // Use 30 different wallets for payment txs
    let payment_txs_per_sender: usize = 10; // Each sends 10 txs (within in-flight limit)
    let num_payment_txs = num_payment_senders * payment_txs_per_sender;
    let num_non_payment_txs: usize = 30;

    println!(
        "Injecting {num_payment_txs} payment and {num_non_payment_txs} non-payment transactions into pool..."
    );

    // Setup payment tokens for multiple senders
    let mut payment_senders = Vec::new();
    let mut payment_tokens = Vec::new();

    for sender_idx in 0..num_payment_senders {
        let sender = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
            .index(sender_idx as u32)?
            .build()?;

        let sender_provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(sender.clone()))
            .connect_http(http_url.clone());

        let token =
            setup_token_manual(&mut setup.node, &sender_provider, &sender, chain_id).await?;

        payment_senders.push(sender);
        payment_tokens.push(token);
    }

    // Inject payment transactions from multiple senders
    for (sender, token) in payment_senders.iter().zip(payment_tokens.iter()) {
        let sender_provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(sender.clone()))
            .connect_http(http_url.clone());

        inject_payment_txs_from_sender(
            &mut setup.node,
            &sender_provider,
            sender,
            token,
            chain_id,
            payment_txs_per_sender,
        )
        .await?;
    }

    // Inject non-payment transactions
    // Start from index 30 to avoid collision with payment senders (0-29)
    inject_non_payment_txs(&mut setup.node, chain_id, num_non_payment_txs, 30).await?;

    // Build first block - should be full
    println!("Building first block...");
    let first_payload = setup.node.advance_block().await?;
    let first_block = first_payload.block();
    let first_all_txs: Vec<_> = first_block.body().transactions().cloned().collect();
    let first_user_txs = extract_user_txs(first_all_txs.clone());

    println!(
        "First block: {} total transactions, {} user transactions",
        first_all_txs.len(),
        first_user_txs.len()
    );

    // Count transaction types in first block
    let (first_payment_count, first_non_payment_count) = count_transaction_types(&first_user_txs);

    println!(
        "First block: {first_payment_count} payment, {first_non_payment_count} non-payment transactions"
    );

    // Keep building blocks until all transactions are processed
    let mut all_blocks_user_txs = vec![first_user_txs];
    let mut block_num = 2;

    loop {
        println!("Building block {block_num}...");
        let payload = setup.node.advance_block().await?;
        let block = payload.block();
        let all_txs: Vec<_> = block.body().transactions().cloned().collect();
        let user_txs = extract_user_txs(all_txs.clone());

        println!(
            "Block {}: {} total transactions, {} user transactions",
            block_num,
            all_txs.len(),
            user_txs.len()
        );

        if user_txs.is_empty() {
            break;
        }

        let (payment_count, non_payment_count) = count_transaction_types(&user_txs);
        println!(
            "Block {block_num}: {payment_count} payment, {non_payment_count} non-payment transactions"
        );

        all_blocks_user_txs.push(user_txs);
        block_num += 1;
    }

    // Calculate total transactions across all blocks
    let total_user_txs: usize = all_blocks_user_txs.iter().map(|txs| txs.len()).sum();
    println!(
        "Total user transactions across {} blocks: {total_user_txs}",
        all_blocks_user_txs.len()
    );

    // Verify we actually had overflow (not all fit in first block)
    assert!(
        all_blocks_user_txs.len() > 1,
        "Should have overflow to multiple blocks"
    );

    // Verify all injected transactions were included
    assert_eq!(
        total_user_txs,
        num_payment_txs + num_non_payment_txs,
        "All injected transactions should be included across blocks"
    );

    Ok(())
}
