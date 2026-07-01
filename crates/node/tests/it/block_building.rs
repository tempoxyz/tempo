use crate::utils::{TEST_MNEMONIC, TestNodeBuilder};
use alloy::{
    consensus::{SignableTransaction, Transaction, TxEip1559, TxEnvelope},
    network::{EthereumWallet, NetworkTransactionBuilder},
    primitives::{Address, B256, U256, aliases::U96},
    providers::{Provider, ProviderBuilder},
    signers::local::{MnemonicBuilder, PrivateKeySigner},
    sol_types::{SolCall, SolEvent},
};
use alloy_eips::eip2718::Encodable2718;
use alloy_network::{Ethereum, ReceiptResponse, TxSignerSync};
use alloy_primitives::Bytes;
use alloy_rpc_types_eth::TransactionRequest;
use commonware_codec::Encode;
use commonware_cryptography::{Signer as _, ed25519::PrivateKey as Ed25519PrivateKey};
use reth_node_api::BuiltPayload;
use std::net::{IpAddr, SocketAddr};
use tempo_chainspec::{features::highest_supported_feature_head, spec::TEMPO_T1_BASE_FEE};
use tempo_contracts::precompiles::{
    IFeatureRegistry, IFeeManager, IRolesAuth, ITIP20, ITIP20ChannelReserve, ITIP20Factory,
    ITIPFeeAMM, IValidatorConfigV2,
};
use tempo_node::node::TempoNode;
use tempo_payload_types::{TempoBuiltPayload, TempoPayloadAttributes};
use tempo_precompiles::{
    FEATURE_REGISTRY_ADDRESS, PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
    TIP20_CHANNEL_RESERVE_ADDRESS, TIP20_FACTORY_ADDRESS, VALIDATOR_CONFIG_V2_ADDRESS,
    tip_fee_manager::amm::compute_amount_out, tip20::ISSUER_ROLE,
    validator_config_v2::VALIDATOR_NS_ADD,
};
use tempo_primitives::{
    TempoConsensusContext, TempoTxEnvelope, ed25519::PublicKey,
    transaction::calc_gas_balance_spending,
};
use tempo_validator_config::ValidatorConfig;

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
    setup_token_manual_with_quote_and_nonce(node, provider, sender, chain_id, PATH_USD_ADDRESS, 0)
        .await
}

async fn setup_token_manual_with_quote_and_nonce<P>(
    node: &mut reth_e2e_test_utils::NodeHelperType<TempoNode>,
    provider: &P,
    sender: &alloy::signers::local::PrivateKeySigner,
    chain_id: u64,
    quote_token: Address,
    nonce_start: u64,
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
            tx_req.gas = tx_req.gas.or(Some(5_000_000));
            tx_req.max_fee_per_gas = tx_req.max_fee_per_gas.or(Some(TEMPO_T1_BASE_FEE as u128));
            tx_req.max_priority_fee_per_gas = tx_req
                .max_priority_fee_per_gas
                .or(Some(TEMPO_T1_BASE_FEE as u128));

            let signed = <TransactionRequest as NetworkTransactionBuilder<Ethereum>>::build(
                tx_req,
                &signer_clone,
            )
            .await?;
            Ok::<Bytes, eyre::Error>(signed.encoded_2718().into())
        }
    };

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
    let create_bytes = sign_and_encode(create_tx.into_transaction_request(), nonce_start).await?;
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
        ITIP20Factory::TokenCreated::decode_log(&token_create_receipt.inner.logs()[1].inner)?;
    let token_addr = event.token;

    // Grant issuer role
    let roles = IRolesAuth::new(token_addr, provider.clone());
    let grant_tx = roles.grantRole(*ISSUER_ROLE, sender_address);
    let grant_bytes = sign_and_encode(grant_tx.into_transaction_request(), nonce_start + 1).await?;
    node.rpc.inject_tx(grant_bytes).await?;
    node.advance_block().await?;

    // Mint tokens
    let token = ITIP20::ITIP20Instance::new(token_addr, provider.clone());
    let mint_tx = token.mint(sender_address, U256::from(1_000_000));
    let mint_bytes = sign_and_encode(mint_tx.into_transaction_request(), nonce_start + 2).await?;
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

fn feature_readiness_reports(
    payload: &TempoBuiltPayload,
) -> eyre::Result<Vec<IFeatureRegistry::reportFeatureReadinessCall>> {
    let mut reports = Vec::new();
    for tx in payload.block().body().transactions() {
        if tx.is_system_tx() && tx.to() == Some(FEATURE_REGISTRY_ADDRESS) {
            reports.push(IFeatureRegistry::reportFeatureReadinessCall::abi_decode(
                tx.input(),
            )?);
        }
    }
    Ok(reports)
}

async fn advance_block_with_proposer(
    node: &mut reth_e2e_test_utils::NodeHelperType<TempoNode>,
    public_key: B256,
) -> eyre::Result<TempoBuiltPayload> {
    node.payload.timestamp += 1;
    let consensus_context = Some(TempoConsensusContext {
        epoch: 0,
        view: 0,
        parent_view: 0,
        proposer: PublicKey::try_from(public_key)
            .expect("active validator public key must be valid"),
    });
    let attrs = TempoPayloadAttributes::new(
        Some(public_key),
        node.payload.timestamp,
        0,
        Bytes::new(),
        consensus_context,
        Vec::new,
    );
    let payload_id = node
        .inner
        .add_ons_handle
        .beacon_engine_handle
        .fork_choice_updated(node.current_forkchoice_state()?, Some(attrs.clone()))
        .await?
        .payload_id
        .ok_or_else(|| eyre::eyre!("payload id missing"))?;

    node.payload.expect_attr_event(attrs).await?;
    node.payload.wait_for_built_payload(payload_id).await;
    let payload = node.payload.expect_built_payload().await?;
    node.submit_payload(payload.clone()).await?;
    node.update_forkchoice(payload.block().hash(), payload.block().hash())
        .await?;

    Ok(payload)
}

fn sign_add_validator_args(
    chain_id: u64,
    private_key: &Ed25519PrivateKey,
    validator: Address,
    public_key: B256,
    ingress: SocketAddr,
    egress: IpAddr,
    fee_recipient: Address,
) -> Vec<u8> {
    let message = ValidatorConfig {
        chain_id,
        validator_address: validator,
        public_key,
        ingress,
        egress,
    }
    .add_validator_message_hash(fee_recipient);

    private_key
        .sign(VALIDATOR_NS_ADD, message.as_slice())
        .encode()
        .to_vec()
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
        let mut tx = TxEip1559 {
            chain_id,
            gas_limit: 2_000_000,
            to: Address::ZERO.into(),
            max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
            max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
            ..Default::default()
        };
        let signature = wallet_signer.sign_transaction_sync(&mut tx).unwrap();

        node.rpc
            .inject_tx(
                TxEnvelope::Eip1559(tx.into_signed(signature))
                    .encoded_2718()
                    .into(),
            )
            .await?;
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
        tx_request.gas = Some(1_000_000);
        tx_request.max_fee_per_gas = Some(TEMPO_T1_BASE_FEE as u128);
        tx_request.max_priority_fee_per_gas = Some(TEMPO_T1_BASE_FEE as u128);

        let signed_tx =
            <TransactionRequest as NetworkTransactionBuilder<Ethereum>>::build(tx_request, &signer)
                .await?;
        let tx_bytes: Bytes = signed_tx.encoded_2718().into();
        node.rpc.inject_tx(tx_bytes).await?;
    }
    Ok(())
}

async fn sign_and_inject(
    node: &mut reth_e2e_test_utils::NodeHelperType<TempoNode>,
    signer: &alloy::signers::local::PrivateKeySigner,
    chain_id: u64,
    mut tx_request: TransactionRequest,
    nonce: u64,
) -> eyre::Result<B256> {
    let signer_wallet = EthereumWallet::from(signer.clone());
    tx_request.nonce = Some(nonce);
    tx_request.chain_id = Some(chain_id);
    tx_request.gas = tx_request.gas.or(Some(5_000_000));
    tx_request.max_fee_per_gas = tx_request
        .max_fee_per_gas
        .or(Some(TEMPO_T1_BASE_FEE as u128));
    tx_request.max_priority_fee_per_gas = tx_request
        .max_priority_fee_per_gas
        .or(Some(TEMPO_T1_BASE_FEE as u128));

    let signed_tx = <TransactionRequest as NetworkTransactionBuilder<Ethereum>>::build(
        tx_request,
        &signer_wallet,
    )
    .await?;
    let tx_hash = *signed_tx.tx_hash();
    let tx_bytes: Bytes = signed_tx.encoded_2718().into();
    node.rpc.inject_tx(tx_bytes).await?;
    Ok(tx_hash)
}

/// Helper to count payment and non-payment transactions
fn count_transaction_types(transactions: &[TempoTxEnvelope]) -> (usize, usize) {
    let payment_count = transactions.iter().filter(|tx| tx.is_payment_v2()).count();
    (payment_count, transactions.len() - payment_count)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_block_building_reports_scheduled_feature_readiness_once() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let validator_private_key = Ed25519PrivateKey::from_seed(0);
    let validator_public_key = B256::from_slice(&validator_private_key.public_key().encode());
    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    let owner = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(owner.clone()))
        .connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;
    let validator_config = IValidatorConfigV2::new(VALIDATOR_CONFIG_V2_ADDRESS, provider.clone());

    let ingress: SocketAddr = "127.0.0.1:9000".parse()?;
    let egress: IpAddr = "127.0.0.1".parse()?;
    let pending = validator_config
        .addValidator(
            owner.address(),
            validator_public_key,
            ingress.to_string(),
            egress.to_string(),
            owner.address(),
            sign_add_validator_args(
                chain_id,
                &validator_private_key,
                owner.address(),
                validator_public_key,
                ingress,
                egress,
                owner.address(),
            )
            .into(),
        )
        .gas(5_000_000)
        .send()
        .await?;
    setup.node.advance_block().await?;
    assert!(pending.get_receipt().await?.status());

    let validator = validator_config
        .validatorByPublicKey(validator_public_key)
        .call()
        .await?;
    assert_eq!(validator.deactivatedAtHeight, 0);

    let feature_registry = IFeatureRegistry::new(FEATURE_REGISTRY_ADDRESS, provider.clone());
    let expected_feature_head = highest_supported_feature_head();
    assert_ne!(expected_feature_head, B256::ZERO);

    let pending = feature_registry
        .scheduleFeatureHead(expected_feature_head, 1)
        .gas(5_000_000)
        .send()
        .await?;
    setup.node.advance_block().await?;
    assert!(pending.get_receipt().await?.status());

    let scheduled = feature_registry.scheduledFeatureHead().call().await?;
    assert_eq!(scheduled.featureHead, expected_feature_head);
    assert_eq!(scheduled.activationEpoch, 1);
    assert!(
        !feature_registry
            .validatorConfirmedScheduledFeatureReadiness(validator.publicKey)
            .call()
            .await?
    );

    inject_non_payment_txs(&mut setup.node, chain_id, 1, 42).await?;

    let first_payload = advance_block_with_proposer(&mut setup.node, validator.publicKey).await?;
    let mut first_transactions = first_payload.block().body().transactions();
    let first_tx = first_transactions
        .next()
        .ok_or_else(|| eyre::eyre!("payload should contain readiness report"))?;
    assert!(first_tx.is_system_tx());
    assert_eq!(first_tx.to(), Some(FEATURE_REGISTRY_ADDRESS));
    assert!(first_transactions.any(|tx| tx.gas_limit() > 0));

    let reports = feature_readiness_reports(&first_payload)?;
    assert_eq!(reports.len(), 1);
    assert!(reports[0].ready);
    assert!(
        feature_registry
            .validatorConfirmedScheduledFeatureReadiness(validator.publicKey)
            .call()
            .await?
    );

    let second_payload = advance_block_with_proposer(&mut setup.node, validator.publicKey).await?;
    assert!(feature_readiness_reports(&second_payload)?.is_empty());

    Ok(())
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
        let raw_tx = {
            let mut tx = TxEip1559 {
                chain_id,
                gas_limit: 2_000_000,
                to: Address::ZERO.into(),
                max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
                max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
                ..Default::default()
            };
            let signature = wallet_signer.sign_transaction_sync(&mut tx).unwrap();
            TxEnvelope::Eip1559(tx.into_signed(signature))
                .encoded_2718()
                .into()
        };
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

/// Verifies that the payload builder's fee score accounts for the AMM haircut
/// when a transaction pays in a token different from the validator's preferred token.
#[tokio::test(flavor = "multi_thread")]
async fn test_payload_fees_account_for_amm_haircut() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = crate::utils::TestNodeBuilder::new()
        .build_with_node_access()
        .await?;

    let user_signer = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
        .index(1)?
        .build()?;
    let user_address = user_signer.address();
    let user_provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(user_signer.clone()))
        .connect_http(setup.node.rpc_url());
    let chain_id = user_provider.get_chain_id().await?;

    let fee_beneficiary = Address::ZERO;

    // Create a two-hop fee route: user_fee_token -> hop_fee_token -> PATH_USD.
    let mut nonce = 0u64;
    let hop_fee_token = setup_token_manual_with_quote_and_nonce(
        &mut setup.node,
        &user_provider,
        &user_signer,
        chain_id,
        PATH_USD_ADDRESS,
        nonce,
    )
    .await?;
    nonce += 3; // setup_token_manual uses 3 txs (create, grantRole, mint)
    let user_fee_token = setup_token_manual_with_quote_and_nonce(
        &mut setup.node,
        &user_provider,
        &user_signer,
        chain_id,
        *hop_fee_token.address(),
        nonce,
    )
    .await?;
    nonce += 3;

    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, user_provider.clone());
    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, user_provider.clone());

    // Seed AMM liquidity for user_token <-> hop_token <-> PATH_USD.
    let liquidity = U256::from(500_000u64);
    sign_and_inject(
        &mut setup.node,
        &user_signer,
        chain_id,
        fee_amm
            .mint(
                *user_fee_token.address(),
                *hop_fee_token.address(),
                liquidity,
                user_address,
            )
            .into_transaction_request(),
        nonce,
    )
    .await?;
    nonce += 1;
    setup.node.advance_block().await?;
    sign_and_inject(
        &mut setup.node,
        &user_signer,
        chain_id,
        fee_amm
            .mint(
                *hop_fee_token.address(),
                PATH_USD_ADDRESS,
                liquidity,
                user_address,
            )
            .into_transaction_request(),
        nonce,
    )
    .await?;
    nonce += 1;
    setup.node.advance_block().await?;

    // Set the user's fee token preference to the custom token
    sign_and_inject(
        &mut setup.node,
        &user_signer,
        chain_id,
        fee_manager
            .setUserToken(*user_fee_token.address())
            .into_transaction_request(),
        nonce,
    )
    .await?;
    nonce += 1;
    setup.node.advance_block().await?;

    // Record collected fees before the attack block
    let collected_before = fee_manager
        .collectedFees(fee_beneficiary, PATH_USD_ADDRESS)
        .call()
        .await?;

    // Submit a transaction that pays fees in user_fee_token and settles through the two-hop route.
    let attack_tx_hash = sign_and_inject(
        &mut setup.node,
        &user_signer,
        chain_id,
        ITIP20::new(PATH_USD_ADDRESS, user_provider.clone())
            .transfer(Address::random(), U256::from(1))
            .into_transaction_request(),
        nonce,
    )
    .await?;

    // Build and commit the block
    let payload = setup.node.advance_block().await?;
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
    funder: &PrivateKeySigner,
    user: &PrivateKeySigner,
    chain_id: u64,
    funder_nonce: u64,
) -> eyre::Result<()> {
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(funder.clone()))
        .connect_http(node.rpc_url());
    let token = ITIP20::new(PATH_USD_ADDRESS, provider);

    sign_and_inject(
        node,
        funder,
        chain_id,
        token
            .transfer(user.address(), U256::from(20_000_000u64))
            .into_transaction_request(),
        funder_nonce,
    )
    .await?;
    node.advance_block().await?;

    Ok(())
}

/// Decode the first `ChannelOpened` event from the latest block.
async fn decode_channel_opened(
    node: &reth_e2e_test_utils::NodeHelperType<TempoNode>,
) -> eyre::Result<ITIP20ChannelReserve::ChannelOpened> {
    let provider = ProviderBuilder::new().connect_http(node.rpc_url());
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
    sender: &PrivateKeySigner,
    chain_id: u64,
    start_nonce: u64,
) -> eyre::Result<()> {
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(sender.clone()))
        .connect_http(node.rpc_url());
    let reserve = ITIP20ChannelReserve::new(TIP20_CHANNEL_RESERVE_ADDRESS, provider);

    // open (payment)
    sign_and_inject(
        node,
        sender,
        chain_id,
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
        start_nonce,
    )
    .await?;
    node.advance_block().await?;

    let opened = decode_channel_opened(node).await?;
    let desc = descriptor_from(&opened);

    // topUp (payment)
    sign_and_inject(
        node,
        sender,
        chain_id,
        reserve
            .topUp(desc.clone(), U96::from(500u64))
            .into_transaction_request(),
        start_nonce + 1,
    )
    .await?;

    // requestClose (payment)
    sign_and_inject(
        node,
        sender,
        chain_id,
        reserve.requestClose(desc).into_transaction_request(),
        start_nonce + 2,
    )
    .await?;

    Ok(())
}

/// Queued reserve payment calls (`topUp`, `requestClose`) are classified as payment_v2 after an
/// already-committed `open` creates the channel.
#[tokio::test(flavor = "multi_thread")]
async fn test_block_building_channel_reserve_payment_v2() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    let funder = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(0)?
        .build()?;
    let payer = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(1)?
        .build()?;

    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(payer.clone()))
        .connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    fund_path_usd(&mut setup.node, &funder, &payer, chain_id, 0).await?;

    let payer_nonce = provider.get_transaction_count(payer.address()).await?;
    inject_reserve_payment_txs(&mut setup.node, &payer, chain_id, payer_nonce).await?;

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
    let funder = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(0)?
        .build()?;
    let tip20_sender = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(1)?
        .build()?;
    let reserve_sender = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(2)?
        .build()?;

    let tip20_provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(tip20_sender.clone()))
        .connect_http(setup.node.rpc_url());
    let chain_id = tip20_provider.get_chain_id().await?;

    let payment_token =
        setup_token_manual(&mut setup.node, &tip20_provider, &tip20_sender, chain_id).await?;

    let funder_nonce = ProviderBuilder::new()
        .wallet(EthereumWallet::from(funder.clone()))
        .connect_http(setup.node.rpc_url())
        .get_transaction_count(funder.address())
        .await?;
    fund_path_usd(
        &mut setup.node,
        &funder,
        &reserve_sender,
        chain_id,
        funder_nonce,
    )
    .await?;

    // open is committed in its own setup block; topUp + requestClose are queued as payment txs.
    let reserve_nonce = ProviderBuilder::new()
        .wallet(EthereumWallet::from(reserve_sender.clone()))
        .connect_http(setup.node.rpc_url())
        .get_transaction_count(reserve_sender.address())
        .await?;
    inject_reserve_payment_txs(&mut setup.node, &reserve_sender, chain_id, reserve_nonce).await?;

    // Inject after reserve setup so they're still in the pool for the drain loop 3 TIP-20 transfers
    inject_payment_txs_from_sender(
        &mut setup.node,
        &tip20_provider,
        &tip20_sender,
        &payment_token,
        chain_id,
        3,
    )
    .await?;
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
