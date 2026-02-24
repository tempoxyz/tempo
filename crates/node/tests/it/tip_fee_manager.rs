use crate::utils::{TestNodeBuilder, setup_test_token};
use alloy::{
    consensus::Transaction,
    network::ReceiptResponse,
    primitives::{B256, Bytes},
    providers::{Provider, ProviderBuilder, WalletProvider},
    signers::{
        SignerSync,
        local::{MnemonicBuilder, PrivateKeySigner},
    },
    sol_types::SolCall,
};
use alloy_eips::{BlockId, Encodable2718};
use alloy_network::{AnyReceiptEnvelope, EthereumWallet};
use alloy_primitives::{Address, Signature, U256, address};
use alloy_rpc_types_eth::TransactionRequest;
use tempo_alloy::rpc::TempoTransactionReceipt;
use tempo_contracts::{
    CREATEX_ADDRESS, CreateX,
    precompiles::{
        IFeeManager, ITIP20,
        ITIPFeeAMM::{self},
    },
};
use tempo_precompiles::{PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS};
use tempo_primitives::{
    TempoTransaction, TempoTxEnvelope,
    transaction::{calc_gas_balance_spending, tempo_transaction::Call},
};

/// Builds init code for a helper contract that calls `getFeeToken()` twice on the
/// FeeManager precompile and stores the results in storage slots 0 and 1.
///
/// This allows integration tests to verify the fee token value observed during
/// real transaction execution by reading the contract's storage after the tx.
fn build_fee_token_checker_init_code() -> Bytes {
    let selector = IFeeManager::getFeeTokenCall::SELECTOR;
    let fm_addr = TIP_FEE_MANAGER_ADDRESS;

    let mut runtime = Vec::new();

    // Call getFeeToken() twice, storing results at slots 0 and 1
    for slot in 0u8..2u8 {
        // PUSH4 <selector>
        runtime.push(0x63);
        runtime.extend_from_slice(&selector);
        // PUSH1 0x00, MSTORE — selector right-aligned at memory[0:32]
        runtime.extend_from_slice(&[0x60, 0x00, 0x52]);
        // STATICCALL(gas, addr, argsOffset=28, argsSize=4, retOffset=32, retSize=32)
        runtime.extend_from_slice(&[0x60, 0x20, 0x60, 0x20, 0x60, 0x04, 0x60, 0x1c]);
        // PUSH20 <fee_manager_address>
        runtime.push(0x73);
        runtime.extend_from_slice(fm_addr.as_slice());
        // GAS, STATICCALL, POP success
        runtime.extend_from_slice(&[0x5a, 0xfa, 0x50]);
        // MLOAD(0x20) — load result, SSTORE at slot
        runtime.extend_from_slice(&[0x60, 0x20, 0x51, 0x60, slot, 0x55]);
    }

    // STOP
    runtime.push(0x00);

    let runtime_len = runtime.len() as u8;

    // Init code: CODECOPY runtime to memory and RETURN it
    let init_prefix_len = 11u8;
    let mut init = Vec::with_capacity(init_prefix_len as usize + runtime.len());
    init.extend_from_slice(&[
        0x60,
        runtime_len, // PUSH1 <runtime_len>
        0x80,        // DUP1
        0x60,
        init_prefix_len, // PUSH1 <init_prefix_len>
        0x60,
        0x00, // PUSH1 0x00
        0x39, // CODECOPY
        0x60,
        0x00, // PUSH1 0x00
        0xf3, // RETURN
    ]);
    debug_assert_eq!(init.len(), init_prefix_len as usize);

    init.extend(runtime);
    Bytes::from(init)
}

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

/// TIP-1007: getFeeToken() is callable via eth_call (static call safety) and
/// returns the resolved fee token. The handler runs during eth_call in this
/// node implementation, so the fee token is set in transient storage.
#[tokio::test(flavor = "multi_thread")]
async fn test_get_fee_token_eth_call() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let user_address = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(setup.http_url);

    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

    // The handler runs during eth_call, so getFeeToken() returns the user's resolved
    // fee token rather than address(0). This is because eth_call goes through the
    // full handler pipeline including validate_against_state_and_deduct_caller.
    let fee_token = fee_manager.getFeeToken().call().await?;
    let user_fee_token = fee_manager.userTokens(user_address).call().await?;
    assert_eq!(
        fee_token, user_fee_token,
        "getFeeToken() via eth_call must return the resolved fee token"
    );

    Ok(())
}

/// TIP-1007: getFeeToken() returns the correct fee token during real transaction
/// execution, is consistent across multiple calls within the same tx, and
/// transient storage is properly cleared between transactions.
#[tokio::test(flavor = "multi_thread")]
async fn test_get_fee_token_during_execution() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let user_address = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(setup.http_url);

    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());
    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

    // Query the user's default fee token
    let default_fee_token = fee_manager.userTokens(user_address).call().await?;
    assert!(
        !default_fee_token.is_zero(),
        "user should have a default fee token"
    );

    // --- Deploy helper contract via CreateX ---
    let init_code = build_fee_token_checker_init_code();
    let createx = CreateX::new(CREATEX_ADDRESS, &provider);
    let checker = createx
        .deployCreate(init_code.clone())
        .gas(5_000_000)
        .call()
        .await?
        .0
        .into();
    createx
        .deployCreate(init_code)
        .gas(5_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;

    // --- Test 1: basic functionality with default fee token ---
    let receipt = provider
        .send_transaction(
            TransactionRequest::default()
                .to(checker)
                .gas_limit(1_000_000),
        )
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "helper call failed");

    let result_0 = provider.get_storage_at(checker, U256::ZERO).await?;
    let fee_token_0 = Address::from_word(B256::from(result_0));
    assert_eq!(
        fee_token_0, default_fee_token,
        "getFeeToken() must return the user's fee token during execution"
    );

    // --- Test 2: consistency — second call in same tx returns same value ---
    let result_1 = provider.get_storage_at(checker, U256::from(1)).await?;
    let fee_token_1 = Address::from_word(B256::from(result_1));
    assert_eq!(
        fee_token_0, fee_token_1,
        "getFeeToken() must return consistent value across calls within same tx"
    );

    // --- Test 3: different fee token + transient storage clearing ---
    let custom_token = setup_test_token(provider.clone(), user_address).await?;
    custom_token
        .mint(user_address, U256::from(1e18 as u64))
        .send()
        .await?
        .get_receipt()
        .await?;

    fee_amm
        .mint(
            *custom_token.address(),
            PATH_USD_ADDRESS,
            U256::from(1e8 as u64),
            user_address,
        )
        .send()
        .await?
        .get_receipt()
        .await?;

    fee_manager
        .setUserToken(*custom_token.address())
        .send()
        .await?
        .get_receipt()
        .await?;

    // Call helper again — should now see the custom fee token
    let receipt = provider
        .send_transaction(
            TransactionRequest::default()
                .to(checker)
                .gas_limit(1_000_000),
        )
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "helper call with custom token failed");

    let result_0 = provider.get_storage_at(checker, U256::ZERO).await?;
    let custom_fee_token = Address::from_word(B256::from(result_0));
    assert_eq!(
        custom_fee_token,
        *custom_token.address(),
        "getFeeToken() must return the custom fee token after preference change"
    );

    // Verify consistency for custom token
    let result_1 = provider.get_storage_at(checker, U256::from(1)).await?;
    let custom_fee_token_1 = Address::from_word(B256::from(result_1));
    assert_eq!(
        custom_fee_token, custom_fee_token_1,
        "getFeeToken() must return consistent value with custom token"
    );

    // Verify transient clearing: custom token != default token from previous tx
    assert_ne!(
        custom_fee_token, default_fee_token,
        "transient storage must be cleared between transactions"
    );

    Ok(())
}
