use crate::utils::{TestNodeBuilder, setup_test_token};
use alloy::{
    consensus::Transaction,
    network::ReceiptResponse,
    providers::{Provider, ProviderBuilder, WalletProvider},
    signers::{
        SignerSync,
        local::{MnemonicBuilder, PrivateKeySigner},
    },
    sol_types::SolEvent,
};
use alloy_eips::{BlockId, Encodable2718};
use alloy_network::{AnyReceiptEnvelope, EthereumWallet};
use alloy_primitives::{Address, Signature, U256, address};
use alloy_rpc_types_eth::TransactionRequest;
use tempo_alloy::rpc::TempoTransactionReceipt;
use tempo_contracts::precompiles::{
    IFeeManager, ITIP20, ITIP403Registry,
    ITIPFeeAMM::{self},
};
use tempo_precompiles::{PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS, TIP403_REGISTRY_ADDRESS};
use tempo_primitives::{
    TempoTransaction, TempoTxEnvelope,
    transaction::{calc_gas_balance_spending, tempo_transaction::Call},
};

#[tokio::test(flavor = "multi_thread")]
async fn test_set_user_token() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let user_address = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    // Create test tokens
    let user_token = setup_test_token(provider.clone(), user_address).await?;
    let validator_token = ITIP20::new(PATH_USD_ADDRESS, &provider);
    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

    user_token
        .mint(user_address, U256::from(1e10))
        .send()
        .await?
        .watch()
        .await?;

    // Verify default user token matches the genesis-created AlphaUSD (reserved address)
    let expected_default_token = address!("20C0000000000000000000000000000000000001");
    assert_eq!(
        fee_manager.userTokens(user_address).call().await?,
        expected_default_token
    );

    let validator = provider
        .get_block(BlockId::latest())
        .await?
        .unwrap()
        .header
        .beneficiary;

    let validator_balance_before = validator_token.balanceOf(validator).call().await?;

    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

    // Track collected fees before this transaction
    let collected_fees_before = fee_manager
        .collectedFees(validator, *validator_token.address())
        .call()
        .await?;

    let pending_tx = fee_amm
        .mint(
            *user_token.address(),
            *validator_token.address(),
            U256::from(1e8),
            user_address,
        )
        .send()
        .await?;
    let receipt = pending_tx.get_receipt().await?;
    assert!(receipt.status());

    let expected_cost = calc_gas_balance_spending(receipt.gas_used, receipt.effective_gas_price);

    // Fees accumulate in collected_fees and require distributeFees() call
    let collected_fees_after = fee_manager
        .collectedFees(validator, *validator_token.address())
        .call()
        .await?;
    let fees_from_this_tx = collected_fees_after - collected_fees_before;
    assert_eq!(
        fees_from_this_tx,
        expected_cost * U256::from(9970) / U256::from(10000)
    );

    // Distribute fees to validator (this distributes ALL accumulated fees for this token)
    fee_manager
        .distributeFees(validator, *validator_token.address())
        .send()
        .await?
        .watch()
        .await?;

    let validator_balance_after = validator_token.balanceOf(validator).call().await?;
    // Validator receives all accumulated fees, not just from this tx
    assert!(validator_balance_after > validator_balance_before);

    let set_receipt = fee_manager
        .setUserToken(*user_token.address())
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(set_receipt.status());

    let current_token = fee_manager.userTokens(user_address).call().await?;
    assert_eq!(current_token, *user_token.address());

    // Fees from setUserToken tx also accumulated
    fee_manager
        .distributeFees(validator, *validator_token.address())
        .send()
        .await?
        .watch()
        .await?;
    assert!(validator_token.balanceOf(validator).call().await? > validator_balance_after);

    // Send a dummy transaction and verify fee was paid in the newly configured user_token
    let user_balance_before = user_token.balanceOf(user_address).call().await?;
    let collected_fees_before = fee_manager
        .collectedFees(validator, *validator_token.address())
        .call()
        .await?;

    let pending_tx = provider
        .send_transaction(TransactionRequest::default().to(Address::random()))
        .await?;
    let tx_hash = *pending_tx.tx_hash();
    let receipt = pending_tx.get_receipt().await?;
    assert!(receipt.status());

    // Verify fee was paid in user_token (max_fee deducted from user)
    let user_balance_after = user_token.balanceOf(user_address).call().await?;
    let tx = provider.get_transaction_by_hash(tx_hash).await?.unwrap();
    let expected_max_fee =
        calc_gas_balance_spending(tx.inner.gas_limit(), receipt.effective_gas_price);
    assert_eq!(user_balance_before - user_balance_after, expected_max_fee);

    // Verify collected fees increased (after swap at 0.9970 rate)
    let collected_fees_after = fee_manager
        .collectedFees(validator, *validator_token.address())
        .call()
        .await?;
    assert_eq!(
        collected_fees_after - collected_fees_before,
        expected_max_fee * U256::from(9970) / U256::from(10000)
    );

    // Distribute fees before checking validator balance
    let validator_balance_before = validator_token.balanceOf(validator).call().await?;
    fee_manager
        .distributeFees(validator, *validator_token.address())
        .send()
        .await?
        .watch()
        .await?;
    let validator_balance_after = validator_token.balanceOf(validator).call().await?;

    assert!(validator_balance_after > validator_balance_before);

    // Ensure that the user can set the fee token back to pathUSD
    let set_receipt = fee_manager
        .setUserToken(PATH_USD_ADDRESS)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(set_receipt.status());

    let current_token = fee_manager.userTokens(user_address).call().await?;
    assert_eq!(current_token, PATH_USD_ADDRESS);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_set_validator_token() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let validator_address = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let validator_token = setup_test_token(provider.clone(), validator_address).await?;
    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider);

    let initial_token = fee_manager
        .validatorTokens(validator_address)
        .call()
        .await?;
    assert_eq!(initial_token, PATH_USD_ADDRESS);

    let set_receipt = fee_manager
        .setValidatorToken(*validator_token.address())
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(set_receipt.status());

    let current_token = fee_manager
        .validatorTokens(validator_address)
        .call()
        .await?;
    assert_eq!(current_token, *validator_token.address());

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_fee_token_tx() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let signers = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
        .into_iter()
        .take(2)
        .collect::<Result<Vec<_>, _>>()?;

    let mut wallet = EthereumWallet::new(signers[0].clone());
    wallet.register_signer(signers[1].clone());

    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);
    let user_address = provider.default_signer_address();

    let user_token = setup_test_token(provider.clone(), user_address).await?;
    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

    let fees = provider.estimate_eip1559_fees().await?;

    let send_fee_token_tx = || async {
        let tx = TempoTransaction {
            chain_id: provider.get_chain_id().await?,
            nonce: provider.get_transaction_count(user_address).await?,
            fee_token: Some(*user_token.address()),
            max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
            max_fee_per_gas: fees.max_fee_per_gas,
            gas_limit: 1_000_000,
            calls: vec![Call {
                to: Address::ZERO.into(),
                value: U256::ZERO,
                input: alloy_primitives::Bytes::new(),
            }],
            ..Default::default()
        };

        let signature = signers[0].sign_hash_sync(&tx.signature_hash()).unwrap();
        let envelope: TempoTxEnvelope = tx.into_signed(signature.into()).into();
        provider
            .send_raw_transaction(&envelope.encoded_2718())
            .await
    };

    let res = send_fee_token_tx().await;
    assert!(
        res.err()
            .is_some_and(|e| e.to_string().contains("insufficient funds"))
    );

    for signer in &signers {
        assert!(
            user_token
                .mint(signer.address(), U256::from(1e18))
                .send()
                .await?
                .get_receipt()
                .await?
                .status()
        );
    }

    assert!(
        fee_amm
            .mint(
                *user_token.address(),
                PATH_USD_ADDRESS,
                U256::from(1e18),
                signers[1].address(),
            )
            .from(signers[1].address())
            .send()
            .await?
            .get_receipt()
            .await?
            .status()
    );

    let tx_hash = send_fee_token_tx().await?.watch().await?;
    let receipt = provider
        .client()
        .request::<_, AnyReceiptEnvelope>("eth_getTransactionReceipt", (tx_hash,))
        .await?;

    assert!(receipt.status());

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_fee_payer_tx() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let fee_payer = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let user = PrivateKeySigner::random();

    let provider = ProviderBuilder::new().connect_http(http_url);
    let fees = provider.estimate_eip1559_fees().await?;

    let mut tx = TempoTransaction {
        chain_id: provider.get_chain_id().await?,
        nonce: provider.get_transaction_count(user.address()).await?,
        max_priority_fee_per_gas: fees.max_fee_per_gas,
        max_fee_per_gas: fees.max_fee_per_gas,
        gas_limit: 1_000_000,
        calls: vec![Call {
            to: Address::ZERO.into(),
            value: U256::ZERO,
            input: alloy_primitives::Bytes::new(),
        }],
        // Placeholder so `skip_fee_token = true` when computing signature_hash
        fee_payer_signature: Some(Signature::new(
            Default::default(),
            Default::default(),
            false,
        )),
        ..Default::default()
    };

    let sig_hash = tx.signature_hash();
    let user_signature = user.sign_hash_sync(&sig_hash).unwrap();
    assert!(
        user_signature
            .recover_address_from_prehash(&sig_hash)
            .unwrap()
            == user.address()
    );
    let fee_payer_signature = fee_payer
        .sign_hash_sync(&tx.fee_payer_signature_hash(user.address()))
        .unwrap();

    tx.fee_payer_signature = Some(fee_payer_signature);

    let tx: TempoTxEnvelope = tx.into_signed(user_signature.into()).into();

    // Query the fee payer's actual fee token from the FeeManager
    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &provider);
    let fee_payer_token = fee_manager.userTokens(fee_payer.address()).call().await?;

    assert!(
        ITIP20::new(fee_payer_token, &provider)
            .balanceOf(user.address())
            .call()
            .await?
            .is_zero()
    );

    let balance_before = ITIP20::new(fee_payer_token, provider.clone())
        .balanceOf(fee_payer.address())
        .call()
        .await?;

    let tx_hash = provider
        .send_raw_transaction(&tx.encoded_2718())
        .await?
        .watch()
        .await?;

    let receipt = provider
        .raw_request::<_, TempoTransactionReceipt>("eth_getTransactionReceipt".into(), (tx_hash,))
        .await?;

    assert!(receipt.status());

    let balance_after = ITIP20::new(fee_payer_token, &provider)
        .balanceOf(fee_payer.address())
        .call()
        .await?;

    assert_eq!(
        balance_after,
        balance_before - calc_gas_balance_spending(receipt.gas_used, receipt.effective_gas_price())
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_fee_payer_transfer_whitelist_pre_t1c() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let genesis_str = include_str!("../assets/test-genesis.json");
    let mut genesis: serde_json::Value = serde_json::from_str(genesis_str)?;
    genesis["config"].as_object_mut().unwrap().remove("t1cTime");
    genesis["config"].as_object_mut().unwrap().remove("t2Time");

    let setup = TestNodeBuilder::new()
        .with_genesis(serde_json::to_string(&genesis)?)
        .build_http_only()
        .await?;

    let admin = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let admin_addr = admin.address();
    let fee_payer_signer = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
        .index(1)?
        .build()?;
    let fee_payer_addr = fee_payer_signer.address();
    let provider = ProviderBuilder::new()
        .wallet(admin.clone())
        .connect_http(setup.http_url.clone());

    // Create a token where admin has DEFAULT_ADMIN_ROLE
    let admin_token = setup_test_token(provider.clone(), admin_addr).await?;
    let token_addr = *admin_token.address();
    admin_token
        .mint(admin_addr, U256::from(1e18 as u64))
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    admin_token
        .mint(fee_payer_addr, U256::from(1e18 as u64))
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Provide AMM liquidity so admin_token can be swapped to PATH_USD for fee settlement
    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());
    fee_amm
        .mint(
            token_addr,
            PATH_USD_ADDRESS,
            U256::from(1e17 as u64),
            admin_addr,
        )
        .send()
        .await?
        .get_receipt()
        .await?;

    // Set fee_payer's fee preference to admin_token
    let fee_payer_provider = ProviderBuilder::new()
        .wallet(fee_payer_signer.clone())
        .connect_http(setup.http_url.clone());
    let fee_manager_fp = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, fee_payer_provider.clone());
    fee_manager_fp
        .setUserToken(token_addr)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Create whitelist policy: whitelist fee_payer only (FeeManager not whitelisted pre-T1C)
    let registry = ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, provider.clone());
    let policy_receipt = registry
        .createPolicy(admin_addr, ITIP403Registry::PolicyType::WHITELIST)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;

    let policy_id = policy_receipt
        .logs()
        .iter()
        .filter_map(|log| ITIP403Registry::PolicyCreated::decode_log(&log.inner).ok())
        .next()
        .expect("PolicyCreated event should be emitted")
        .policyId;

    registry
        .modifyPolicyWhitelist(policy_id, fee_payer_addr, true)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;

    let admin_token_contract = ITIP20::new(token_addr, &provider);
    let receipt = admin_token_contract
        .changeTransferPolicyId(policy_id)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "changeTransferPolicyId should succeed");

    // Pre-T1C: tx should succeed without whitelisting the FeeManager
    let tx = TransactionRequest::default()
        .to(Address::ZERO)
        .value(U256::ZERO);
    let receipt = fee_payer_provider
        .send_transaction(tx)
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status());

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_fee_payer_transfer_whitelist_post_t1c() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;

    let admin = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let admin_addr = admin.address();
    let fee_payer_signer = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
        .index(1)?
        .build()?;
    let fee_payer_addr = fee_payer_signer.address();
    let provider = ProviderBuilder::new()
        .wallet(admin.clone())
        .connect_http(setup.http_url.clone());

    // Create a token where admin has DEFAULT_ADMIN_ROLE (unlike PATH_USD whose
    // genesis admin is the coinbase address, not the test mnemonic).
    let admin_token = setup_test_token(provider.clone(), admin_addr).await?;
    let token_addr = *admin_token.address();
    admin_token
        .mint(admin_addr, U256::from(1e18 as u64))
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    admin_token
        .mint(fee_payer_addr, U256::from(1e18 as u64))
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Provide AMM liquidity so admin_token can be swapped to PATH_USD for fee settlement
    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());
    fee_amm
        .mint(
            token_addr,
            PATH_USD_ADDRESS,
            U256::from(1e17 as u64),
            admin_addr,
        )
        .send()
        .await?
        .get_receipt()
        .await?;

    // Set fee_payer's fee preference to admin_token BEFORE applying restrictive policy
    let fee_payer_provider = ProviderBuilder::new()
        .wallet(fee_payer_signer.clone())
        .connect_http(setup.http_url.clone());
    let fee_manager_fp = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, fee_payer_provider.clone());
    fee_manager_fp
        .setUserToken(token_addr)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Create whitelist policy on admin_token: whitelist fee_payer but NOT FeeManager
    let registry = ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, provider.clone());
    let policy_receipt = registry
        .createPolicy(admin_addr, ITIP403Registry::PolicyType::WHITELIST)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;

    let policy_id = policy_receipt
        .logs()
        .iter()
        .filter_map(|log| ITIP403Registry::PolicyCreated::decode_log(&log.inner).ok())
        .next()
        .expect("PolicyCreated event should be emitted")
        .policyId;

    registry
        .modifyPolicyWhitelist(policy_id, fee_payer_addr, true)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;

    let admin_token_contract = ITIP20::new(token_addr, &provider);
    let receipt = admin_token_contract
        .changeTransferPolicyId(policy_id)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "changeTransferPolicyId should succeed");

    // T1C requires both sender and FeeManager whitelisted — fee_payer is whitelisted
    // but FeeManager is not, so the tx should be rejected at the pool level.
    let tx = TransactionRequest::default()
        .to(Address::ZERO)
        .value(U256::ZERO);
    let result = fee_payer_provider.send_transaction(tx).await;
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("blacklisted"),
        "expected blacklisted fee payer error, got: {err}"
    );

    // Whitelist FeeManager — now fee_payer's tx should go through
    registry
        .modifyPolicyWhitelist(policy_id, TIP_FEE_MANAGER_ADDRESS, true)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Re-fetch nonce from chain since the rejected tx above desynchronized
    // the provider's internal nonce tracker.
    let nonce = fee_payer_provider
        .get_transaction_count(fee_payer_addr)
        .await?;
    let tx = TransactionRequest::default()
        .to(Address::ZERO)
        .value(U256::ZERO)
        .nonce(nonce);
    let receipt = fee_payer_provider
        .send_transaction(tx)
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status());

    Ok(())
}
