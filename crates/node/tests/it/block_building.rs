use crate::utils::{TestNodeBuilder, with_t1_fees};
use alloy::{
    consensus::Transaction,
    primitives::{Address, B256, U256, aliases::U96},
    providers::Provider,
    sol_types::SolEvent,
};
use alloy_network::ReceiptResponse;
use alloy_primitives::Bytes;
use alloy_rpc_types_eth::TransactionRequest;
use reth_e2e_test_utils::wallet::{TestAccount, Wallet};
use reth_node_api::BuiltPayload;
use tempo_contracts::precompiles::{
    IFeeManager, IRolesAuth, ITIP20, ITIP20ChannelReserve, ITIP20Factory, ITIPFeeAMM,
};
use tempo_node::node::TempoNode;
use tempo_precompiles::{
    PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS, TIP20_CHANNEL_RESERVE_ADDRESS,
    TIP20_FACTORY_ADDRESS, tip_fee_manager::amm::compute_amount_out, tip20::ISSUER_ROLE,
};
use tempo_primitives::{TempoTxEnvelope, transaction::calc_gas_balance_spending};

/// Helper to setup a test token by manually injecting transactions and advancing blocks
async fn setup_token_manual<P>(
    node: &mut reth_e2e_test_utils::NodeHelperType<TempoNode>,
    provider: &P,
    sender: &mut TestAccount,
) -> eyre::Result<ITIP20::ITIP20Instance<P>>
where
    P: Provider + Clone,
{
    setup_token_manual_with_quote(node, provider, sender, PATH_USD_ADDRESS).await
}

async fn setup_token_manual_with_quote<P>(
    node: &mut reth_e2e_test_utils::NodeHelperType<TempoNode>,
    provider: &P,
    sender: &mut TestAccount,
    quote_token: Address,
) -> eyre::Result<ITIP20::ITIP20Instance<P>>
where
    P: Provider + Clone,
{
    let factory = ITIP20Factory::new(TIP20_FACTORY_ADDRESS, provider.clone());
    let sender_address = sender.address();

    // Create token
    let salt = B256::random();
    let create_tx = factory.createToken_0(
        "Test".to_string(),
        "TEST".to_string(),
        "USD".to_string(),
        quote_token,
        sender_address,
        salt,
    );
    let create_bytes = sign_tx(sender, create_tx.into_transaction_request()).await;
    node.inject_and_advance(create_bytes).await?;

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
        ITIP20Factory::TokenCreated::decode_log(&token_create_receipt.inner.logs()[1].inner)?;
    let token_addr = event.token;

    // Grant issuer role
    let roles = IRolesAuth::new(token_addr, provider.clone());
    let grant_tx = roles.grantRole(ISSUER_ROLE, sender_address);
    let grant_bytes = sign_tx(sender, grant_tx.into_transaction_request()).await;
    node.inject_and_advance(grant_bytes).await?;

    // Mint tokens
    let token = ITIP20::ITIP20Instance::new(token_addr, provider.clone());
    let mint_tx = token.mint(sender_address, U256::from(1_000_000));
    let mint_bytes = sign_tx(sender, mint_tx.into_transaction_request()).await;
    node.inject_and_advance(mint_bytes).await?;

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
    let wallet = Wallet::default().with_chain_id(chain_id);
    for i in 0..count as u32 {
        let tx = TransactionRequest::default()
            .to(Address::ZERO)
            .gas_limit(2_000_000);
        let tx_bytes = sign_tx(&mut wallet.account(start_index + i), tx).await;
        node.rpc.inject_tx(tx_bytes).await?;
    }
    Ok(())
}

/// Helper to inject payment transactions from a single sender
async fn inject_payment_txs_from_sender<P>(
    node: &mut reth_e2e_test_utils::NodeHelperType<TempoNode>,
    sender: &mut TestAccount,
    token: &ITIP20::ITIP20Instance<P>,
    count: usize,
) -> eyre::Result<()>
where
    P: Provider + Clone,
{
    for i in 0..count {
        let tx = token
            .transfer(sender.address(), U256::from((i + 1) as u64))
            .into_transaction_request()
            .gas_limit(1_000_000);
        let tx_bytes = sign_tx(sender, tx).await;
        node.rpc.inject_tx(tx_bytes).await?;
    }
    Ok(())
}

/// Signs `tx` with T1 base fees and, unless it sets one, a 5M gas limit, returning the encoded
/// transaction.
async fn sign_tx(sender: &mut TestAccount, mut tx: TransactionRequest) -> Bytes {
    tx.gas.get_or_insert(5_000_000);
    sender.sign_tx_bytes(with_t1_fees(tx)).await
}

/// Helper to count payment and non-payment transactions
fn count_transaction_types(transactions: &[TempoTxEnvelope]) -> (usize, usize) {
    let payment_count = transactions.iter().filter(|tx| tx.is_payment_v2()).count();
    (payment_count, transactions.len() - payment_count)
}

/// Test with only a few mixed payment and non-payment transactions
#[tokio::test(flavor = "multi_thread")]
async fn test_block_building_few_mixed_txs() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = crate::utils::TestNodeBuilder::new()
        .build_with_node_access()
        .await?;

    let provider = setup.node.rpc_provider();

    let chain_id = provider.get_chain_id().await?;
    let mut payment_sender = Wallet::default().with_chain_id(chain_id).account(0);

    let payment_token = setup_token_manual(&mut setup.node, &provider, &mut payment_sender).await?;

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
        &mut payment_sender,
        &payment_token,
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

    let provider = setup.node.rpc_provider();

    let chain_id = provider.get_chain_id().await?;
    let mut payment_sender = Wallet::default().with_chain_id(chain_id).account(0);

    // Setup payment token
    let payment_token = setup_token_manual(&mut setup.node, &provider, &mut payment_sender).await?;

    let num_payment_txs: usize = 10;
    println!("Injecting {num_payment_txs} payment transactions into pool...");

    // Inject only payment transactions
    inject_payment_txs_from_sender(
        &mut setup.node,
        &mut payment_sender,
        &payment_token,
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
            tx.is_payment_v2(),
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

    let provider = setup.node.rpc_provider();

    let chain_id = provider.get_chain_id().await?;

    let num_non_payment_txs: usize = 10;

    println!("Injecting {num_non_payment_txs} non-payment transactions into pool...");

    inject_non_payment_txs(&mut setup.node, chain_id, num_non_payment_txs, 0).await?;

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
            !tx.is_payment_v2(),
            "All transactions should be non-payment transactions"
        );
    }

    Ok(())
}

/// Test with more transactions than fit in a single block
#[tokio::test(flavor = "multi_thread")]
async fn test_block_building_more_txs_than_fit() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Use a gas limit high enough for token setup (~5M per token) but low enough
    // to cause overflow when many transactions are injected.
    // With T1 gas costs, we need at least 5M for token creation.
    // 15M allows setup but forces overflow when 330 transactions are submitted.
    let mut setup = crate::utils::TestNodeBuilder::new()
        .with_gas_limit("0xE4E1C0") // 15,000,000 gas
        .build_with_node_access()
        .await?;

    let provider = setup.node.rpc_provider();

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

    let wallet = Wallet::default().with_chain_id(chain_id);
    for sender_idx in 0..num_payment_senders {
        let mut sender = wallet.account(sender_idx as u32);
        let token = setup_token_manual(&mut setup.node, &provider, &mut sender).await?;

        payment_senders.push(sender);
        payment_tokens.push(token);
    }

    // Inject payment transactions from multiple senders
    for (sender, token) in payment_senders.iter_mut().zip(payment_tokens.iter()) {
        inject_payment_txs_from_sender(&mut setup.node, sender, token, payment_txs_per_sender)
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

/// Verifies that the payload builder's fee score accounts for the AMM haircut
/// when a transaction pays in a token different from the validator's preferred token.
#[tokio::test(flavor = "multi_thread")]
async fn test_payload_fees_account_for_amm_haircut() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = crate::utils::TestNodeBuilder::new()
        .build_with_node_access()
        .await?;

    let user_provider = setup.node.rpc_provider();
    let chain_id = user_provider.get_chain_id().await?;
    let mut user = Wallet::default().with_chain_id(chain_id).account(1);
    let user_address = user.address();

    let fee_beneficiary = Address::ZERO;

    // Create a two-hop fee route: user_fee_token -> hop_fee_token -> PATH_USD.
    let hop_fee_token =
        setup_token_manual_with_quote(&mut setup.node, &user_provider, &mut user, PATH_USD_ADDRESS)
            .await?;
    let user_fee_token = setup_token_manual_with_quote(
        &mut setup.node,
        &user_provider,
        &mut user,
        *hop_fee_token.address(),
    )
    .await?;

    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, user_provider.clone());
    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, user_provider.clone());

    // Seed AMM liquidity for user_token <-> hop_token <-> PATH_USD.
    let liquidity = U256::from(500_000u64);
    let mint_tx = sign_tx(
        &mut user,
        fee_amm
            .mint(
                *user_fee_token.address(),
                *hop_fee_token.address(),
                liquidity,
                user_address,
            )
            .into_transaction_request(),
    )
    .await;
    setup.node.inject_and_advance(mint_tx).await?;
    let mint_tx = sign_tx(
        &mut user,
        fee_amm
            .mint(
                *hop_fee_token.address(),
                PATH_USD_ADDRESS,
                liquidity,
                user_address,
            )
            .into_transaction_request(),
    )
    .await;
    setup.node.inject_and_advance(mint_tx).await?;

    // Set the user's fee token preference to the custom token
    let set_user_token_tx = sign_tx(
        &mut user,
        fee_manager
            .setUserToken(*user_fee_token.address())
            .into_transaction_request(),
    )
    .await;
    setup.node.inject_and_advance(set_user_token_tx).await?;

    // Record collected fees before the attack block
    let collected_before = fee_manager
        .collectedFees(fee_beneficiary, PATH_USD_ADDRESS)
        .call()
        .await?;

    // Submit a transaction that pays fees in user_fee_token and settles through the two-hop route.
    let attack_tx = sign_tx(
        &mut user,
        ITIP20::new(PATH_USD_ADDRESS, user_provider.clone())
            .transfer(Address::random(), U256::from(1))
            .into_transaction_request(),
    )
    .await;

    // Build and commit the block
    let (attack_tx_hash, payload) = setup.node.inject_and_advance(attack_tx).await?;
    let payload_fees = payload.fees();

    let attack_receipt = user_provider
        .get_transaction_receipt(attack_tx_hash)
        .await?
        .expect("attack tx receipt must exist");
    let nominal_spending = calc_gas_balance_spending(
        attack_receipt.gas_used,
        attack_receipt.effective_gas_price(),
    );
    let one_hop_post_swap = compute_amount_out(nominal_spending)?;
    let expected_post_swap = compute_amount_out(one_hop_post_swap)?;

    // Verify collected fees reflect the haircut
    let collected_after = fee_manager
        .collectedFees(fee_beneficiary, PATH_USD_ADDRESS)
        .call()
        .await?;
    let collected_delta = collected_after - collected_before;

    assert!(
        collected_delta < one_hop_post_swap,
        "two-hop validator accrual ({collected_delta}) should be less than one-hop accrual ({one_hop_post_swap})"
    );
    // The payload fee score must not exceed the actual validator revenue
    assert!(
        payload_fees <= nominal_spending,
        "payload fees ({payload_fees}) should not exceed nominal spending ({nominal_spending})"
    );
    assert_eq!(
        collected_delta, expected_post_swap,
        "validator accrual should reflect AMM haircut"
    );
    assert_eq!(
        payload_fees, collected_delta,
        "payload fee score should match actual validator revenue"
    );

    Ok(())
}

/// Fund `user` with PATH_USD.
async fn fund_path_usd(
    node: &mut reth_e2e_test_utils::NodeHelperType<TempoNode>,
    funder: &mut TestAccount,
    user: Address,
) -> eyre::Result<()> {
    let token = ITIP20::new(PATH_USD_ADDRESS, node.rpc_provider());

    let transfer_tx = sign_tx(
        funder,
        token
            .transfer(user, U256::from(20_000_000u64))
            .into_transaction_request(),
    )
    .await;
    node.inject_and_advance(transfer_tx).await?;

    Ok(())
}

/// Decode the first `ChannelOpened` event from the latest block.
async fn decode_channel_opened(
    node: &reth_e2e_test_utils::NodeHelperType<TempoNode>,
) -> eyre::Result<ITIP20ChannelReserve::ChannelOpened> {
    let provider = node.rpc_provider();
    let latest = provider.get_block_number().await?;
    let receipts = provider.get_block_receipts(latest.into()).await?.unwrap();
    receipts
        .iter()
        .flat_map(|r| r.inner.logs())
        .find_map(|log| ITIP20ChannelReserve::ChannelOpened::decode_log(&log.inner).ok())
        .map(|log| log.data)
        .ok_or_else(|| eyre::eyre!("ChannelOpened event not found"))
}

fn descriptor_from(
    e: &ITIP20ChannelReserve::ChannelOpened,
) -> ITIP20ChannelReserve::ChannelDescriptor {
    ITIP20ChannelReserve::ChannelDescriptor {
        payer: e.payer,
        payee: e.payee,
        operator: e.operator,
        token: e.token,
        salt: e.salt,
        authorizedSigner: e.authorizedSigner,
        expiringNonceHash: e.expiringNonceHash,
    }
}

/// Inject reserve txs: `open` (payment), `topUp` (payment), `requestClose` (payment).
/// `open` is committed in its own block so subsequent calls find the channel; only `topUp` and
/// `requestClose` remain in the pool for the caller to drain/count.
async fn inject_reserve_payment_txs(
    node: &mut reth_e2e_test_utils::NodeHelperType<TempoNode>,
    sender: &mut TestAccount,
) -> eyre::Result<()> {
    let reserve = ITIP20ChannelReserve::new(TIP20_CHANNEL_RESERVE_ADDRESS, node.rpc_provider());

    // open (payment)
    let open_tx = sign_tx(
        sender,
        reserve
            .open(
                Address::random(),
                Address::ZERO,
                PATH_USD_ADDRESS,
                U96::from(1_000u64),
                B256::random(),
                Address::ZERO,
            )
            .into_transaction_request(),
    )
    .await;
    node.inject_and_advance(open_tx).await?;

    let opened = decode_channel_opened(node).await?;
    let desc = descriptor_from(&opened);

    // topUp (payment)
    let top_up_tx = sign_tx(
        sender,
        reserve
            .topUp(desc.clone(), U96::from(500u64))
            .into_transaction_request(),
    )
    .await;
    node.rpc.inject_tx(top_up_tx).await?;

    // requestClose (payment)
    let request_close_tx = sign_tx(
        sender,
        reserve.requestClose(desc).into_transaction_request(),
    )
    .await;
    node.rpc.inject_tx(request_close_tx).await?;

    Ok(())
}

/// Queued reserve payment calls (`topUp`, `requestClose`) are classified as payment_v2 after an
/// already-committed `open` creates the channel.
#[tokio::test(flavor = "multi_thread")]
async fn test_block_building_channel_reserve_payment_v2() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    let provider = setup.node.rpc_provider();
    let chain_id = provider.get_chain_id().await?;
    let wallet = Wallet::default().with_chain_id(chain_id);
    let mut funder = wallet.account(0);
    let mut payer = wallet.account(1);

    fund_path_usd(&mut setup.node, &mut funder, payer.address()).await?;

    inject_reserve_payment_txs(&mut setup.node, &mut payer).await?;

    // Drain pool — topUp + requestClose may already have been consumed by the dev-mode block timer.
    let mut all_user_txs = Vec::new();
    loop {
        let payload = setup.node.advance_block().await?;
        let user = extract_user_txs(payload.block().body().transactions().cloned().collect());
        if user.is_empty() {
            break;
        }
        all_user_txs.extend(user);
    }
    let (payment, non_payment) = count_transaction_types(&all_user_txs);
    assert_eq!(payment, 2);
    assert_eq!(non_payment, 0);

    Ok(())
}

/// Mixed TIP-20 transfers + channel reserve payments + plain txs are classified by `is_payment_v2`.
#[tokio::test(flavor = "multi_thread")]
async fn test_block_building_mixed_tip20_and_reserve_payments() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    let tip20_provider = setup.node.rpc_provider();
    let chain_id = tip20_provider.get_chain_id().await?;
    let wallet = Wallet::default().with_chain_id(chain_id);
    let mut funder = wallet.account(0);
    let mut tip20_sender = wallet.account(1);
    let mut reserve_sender = wallet.account(2);

    let payment_token =
        setup_token_manual(&mut setup.node, &tip20_provider, &mut tip20_sender).await?;

    fund_path_usd(&mut setup.node, &mut funder, reserve_sender.address()).await?;

    // open is committed in its own setup block; topUp + requestClose are queued as payment txs.
    inject_reserve_payment_txs(&mut setup.node, &mut reserve_sender).await?;

    // Inject after reserve setup so they're still in the pool for the drain loop 3 TIP-20 transfers
    inject_payment_txs_from_sender(&mut setup.node, &mut tip20_sender, &payment_token, 3).await?;
    // 3 self-sends (non-payment)
    inject_non_payment_txs(&mut setup.node, chain_id, 3, 10).await?;

    // Drain pool
    let mut all_user_txs = Vec::new();
    loop {
        let payload = setup.node.advance_block().await?;
        let user = extract_user_txs(payload.block().body().transactions().cloned().collect());
        if user.is_empty() {
            break;
        }
        all_user_txs.extend(user);
    }

    let (payment, non_payment) = count_transaction_types(&all_user_txs);
    assert_eq!(payment, 5);
    assert_eq!(non_payment, 3);

    Ok(())
}
