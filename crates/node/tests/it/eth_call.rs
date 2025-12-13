use crate::utils::{TestNodeBuilder, setup_test_token};
use alloy::{
    primitives::{Address, B256, Bytes, U256},
    providers::{Provider, ProviderBuilder, ext::TraceApi},
    rpc::types::{
        Filter, TransactionRequest,
        trace::parity::{ChangedType, Delta},
    },
    signers::local::MnemonicBuilder,
    sol_types::{SolCall, SolError, SolEvent},
};
use alloy_eips::BlockId;
use alloy_rpc_types_eth::TransactionInput;
use reth_evm::revm::interpreter::instructions::utility::IntoU256;
use tempo_chainspec::spec::TEMPO_BASE_FEE;
use tempo_contracts::precompiles::{
    IFeeManager,
    ITIP20::{self, transferCall},
    ITIPFeeAMM, UnknownFunctionSelector,
};
use tempo_precompiles::{
    PATH_USD_ADDRESS, TIP_ACCOUNT_REGISTRAR,
    tip20::{self, TIP20Token},
};

#[tokio::test(flavor = "multi_thread")]
async fn test_eth_call() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new()
        .allegretto_activated()
        .build_http_only()
        .await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    // Setup test token
    let token = setup_test_token(provider.clone(), caller).await?;

    // First, mint some tokens to the caller for testing
    // Use u128 range since supply cap is u128::MAX with allegretto
    let mint_amount = U256::from(rand::random::<u128>());
    token
        .mint(caller, mint_amount)
        .gas_price(TEMPO_BASE_FEE as u128)
        .gas(300_000)
        .send()
        .await?
        .get_receipt()
        .await?;

    let recipient = Address::random();
    let calldata = token.transfer(recipient, mint_amount).calldata().clone();
    let tx = TransactionRequest::default()
        .to(*token.address())
        .gas_price(0)
        .input(TransactionInput::new(calldata));

    let res = provider.call(tx).await?;
    let success = transferCall::abi_decode_returns(&res)?;
    assert!(success);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_eth_trace_call() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new()
        .allegretto_activated()
        .build_http_only()
        .await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    // Setup test token
    let token = setup_test_token(provider.clone(), caller).await?;
    let token_id = tip20::address_to_token_id_unchecked(*token.address());

    // First, mint some tokens to the caller for testing
    // Use u128 range since supply cap is u128::MAX with allegretto
    let mint_amount = U256::from(rand::random::<u128>());
    token
        .mint(caller, mint_amount)
        .gas_price(TEMPO_BASE_FEE as u128)
        .gas(300_000)
        .send()
        .await?
        .get_receipt()
        .await?;

    let recipient = Address::random();
    let calldata = token.transfer(recipient, mint_amount).calldata().clone();
    let tx = TransactionRequest::default()
        .from(caller)
        .to(*token.address())
        .input(TransactionInput::new(calldata));

    let res = provider.call(tx.clone()).await?;
    let success = transferCall::abi_decode_returns(&res)?;
    assert!(success);

    let trace_res = provider.trace_call(&tx).state_diff().await?;

    let success = transferCall::abi_decode_returns(&trace_res.output)?;
    assert!(success);

    let state_diff = trace_res.state_diff.expect("Could not get state diff");
    let caller_diff = state_diff.get(&caller).expect("Could not get caller diff");
    assert!(caller_diff.nonce.is_changed());
    assert!(caller_diff.balance.is_unchanged());
    assert!(caller_diff.code.is_unchanged());
    assert!(caller_diff.storage.is_empty());

    let token_diff = state_diff
        .get(token.address())
        .expect("Could not get token diff");

    assert!(token_diff.balance.is_unchanged());
    assert!(token_diff.code.is_unchanged());
    assert!(token_diff.nonce.is_unchanged());

    let token_storage_diff = token_diff.storage.clone();
    // Assert sender token balance has changed
    let slot = TIP20Token::new(token_id).balances.at(caller).slot();
    let sender_balance = token_storage_diff
        .get(&B256::from(slot))
        .expect("Could not get recipient balance delta");

    assert!(sender_balance.is_changed());

    let Delta::Changed(ChangedType { from, to }) = sender_balance else {
        panic!("Unexpected delta");
    };
    assert_eq!(from.into_u256(), mint_amount);
    assert_eq!(to.into_u256(), U256::ZERO);

    // Assert recipient token balance is changed
    let slot = TIP20Token::new(token_id).balances.at(recipient).slot();
    let recipient_balance = token_storage_diff
        .get(&B256::from(slot))
        .expect("Could not get recipient balance delta");
    assert!(recipient_balance.is_changed());

    let Delta::Changed(ChangedType { from, to }) = recipient_balance else {
        panic!("Unexpected delta");
    };
    assert_eq!(from.into_u256(), U256::ZERO);
    assert_eq!(to.into_u256(), mint_amount);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_eth_get_logs() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new()
        .allegretto_activated()
        .build_http_only()
        .await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    // Setup test token
    let token = setup_test_token(provider.clone(), caller).await?;

    // Use u128 range since supply cap is u128::MAX with allegretto
    let mint_amount = U256::from(rand::random::<u128>());
    let mint_receipt = token
        .mint(caller, mint_amount)
        .gas_price(TEMPO_BASE_FEE as u128)
        .gas(300_000)
        .send()
        .await?
        .get_receipt()
        .await?;

    let recipient = Address::random();
    token
        .transfer(recipient, mint_amount)
        .gas_price(TEMPO_BASE_FEE as u128)
        .gas(300_000)
        .send()
        .await?
        .get_receipt()
        .await?;

    let filter = Filter::new()
        .address(*token.address())
        .from_block(mint_receipt.block_number.unwrap());
    let logs = provider.get_logs(&filter).await?;
    assert_eq!(logs.len(), 3);

    // NOTE: this currently reflects the event emission from the reference contract. Double check
    // this is the expected behavior
    let transfer_event = ITIP20::Transfer::decode_log(&logs[0].inner)?;
    assert_eq!(transfer_event.from, Address::ZERO);
    assert_eq!(transfer_event.to, caller);
    assert_eq!(transfer_event.amount, mint_amount);

    let mint_event = ITIP20::Mint::decode_log(&logs[1].inner)?;
    assert_eq!(mint_event.to, caller);
    assert_eq!(mint_event.amount, mint_amount);

    let transfer_event = ITIP20::Transfer::decode_log(&logs[2].inner)?;
    assert_eq!(transfer_event.from, caller);
    assert_eq!(transfer_event.to, recipient);
    assert_eq!(transfer_event.amount, mint_amount);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_eth_estimate_gas() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new()
        .allegretto_activated()
        .build_http_only()
        .await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let token = setup_test_token(provider.clone(), caller).await?;
    let calldata = token.mint(caller, U256::from(1000)).calldata().clone();
    let tx = TransactionRequest::default()
        .to(*token.address())
        .input(calldata.into());

    let gas = provider.estimate_gas(tx.clone()).await?;
    // gas estimation is calldata dependent, but should be consistent with same calldata
    assert_eq!(gas, 109051);

    // ensure we can successfully send the tx with that gas
    let receipt = provider
        .send_transaction(tx.gas_limit(gas))
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.gas_used <= gas);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_eth_estimate_gas_different_fee_tokens() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new()
        .allegretto_activated()
        .build_http_only()
        .await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let user_address = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    // Get beneficiary (validator) from latest block
    let block = provider
        .get_block(BlockId::latest())
        .await?
        .expect("Could not get latest block");
    let validator_address = block.header.beneficiary;
    assert!(!validator_address.is_zero());

    // Create different fee tokens for user and validator
    let user_fee_token = setup_test_token(provider.clone(), user_address).await?;

    let mint_amount = U256::from(u128::MAX);
    user_fee_token
        .mint(user_address, mint_amount)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Setup fee manager to configure different tokens
    let fee_manager =
        IFeeManager::new(tempo_precompiles::TIP_FEE_MANAGER_ADDRESS, provider.clone());

    // Supply liquidity to enable fee token swapping
    let validator_token_address = PATH_USD_ADDRESS;

    let fee_amm = ITIPFeeAMM::new(tempo_precompiles::TIP_FEE_MANAGER_ADDRESS, provider.clone());

    // Provide liquidity for the fee token pair
    // Use mintWithValidatorToken as mint is disabled post-Moderato
    let liquidity_amount = U256::from(u32::MAX);
    fee_amm
        .mintWithValidatorToken(
            *user_fee_token.address(),
            validator_token_address,
            liquidity_amount,
            user_address,
        )
        .send()
        .await?
        .get_receipt()
        .await?;

    // Set different fee tokens for user and validator
    // Note that the validator defaults to the PathUSD
    fee_manager
        .setUserToken(*user_fee_token.address())
        .send()
        .await?
        .get_receipt()
        .await?;

    // Verify the tokens are set correctly
    let user_token = fee_manager.userTokens(user_address).call().await?;
    let validator_token = fee_manager
        .validatorTokens(validator_address)
        .call()
        .await?;

    assert_eq!(user_token, *user_fee_token.address());
    assert_eq!(validator_token, validator_token_address);
    assert_ne!(user_token, validator_token_address);

    // Create a test transaction to estimate gas for
    let recipient = Address::random();
    let calldata = user_fee_token
        .transfer(recipient, U256::ONE)
        .calldata()
        .clone();
    let tx = TransactionRequest::default()
        .from(user_address)
        .to(*user_fee_token.address())
        .input(TransactionInput::new(calldata));

    // Estimate gas when user fee token differs from validator fee token
    let gas = provider.estimate_gas(tx.clone()).await?;

    // NOTE: this test is flaky, with gas sometimes returning as 75513 and other times as 75515.
    // Updating to assert gas > 0 as this test is only checking if gas estimation succeeds when
    // the user fee token differs from the validator fee token
    assert!(gas > 0);

    // Verify we can execute the transaction with the estimated gas
    let receipt = provider
        .send_transaction(tx.gas_limit(gas))
        .await?
        .get_receipt()
        .await?;

    assert!(receipt.status());
    assert!(receipt.gas_used <= gas);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_unknown_selector_error_via_rpc() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Note: This test uses moderato genesis (without allegretto) to test older behavior
    let setup = TestNodeBuilder::new()
        .with_genesis(include_str!("../assets/test-genesis-moderato.json").to_string())
        .build_http_only()
        .await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    // Call with an unknown function selector (0x12345678)
    let unknown_selector = [0x12u8, 0x34, 0x56, 0x78];
    let mut calldata = unknown_selector.to_vec();
    // Add some dummy data
    calldata.extend_from_slice(&[0u8; 64]);

    let tx = TransactionRequest::default()
        .to(TIP_ACCOUNT_REGISTRAR)
        .input(TransactionInput::new(Bytes::from(calldata)));

    // The call should fail with UnknownFunctionSelector error
    let result = provider.call(tx).await;

    assert!(
        result.is_err(),
        "Call should have failed with unknown selector"
    );

    let err = result.unwrap_err();

    // Get the error response payload
    let error_payload = err.as_error_resp();
    assert!(
        error_payload.is_some(),
        "Should have error response payload"
    );

    let payload = error_payload.unwrap();
    assert!(payload.data.is_some(), "Should have error data");

    // Deserialize the error data as Bytes
    let error_bytes: Bytes = serde_json::from_str(payload.data.as_ref().unwrap().get())
        .expect("Failed to deserialize error data as bytes");

    // Decode UnknownFunctionSelector from the error data
    let decoded_error = UnknownFunctionSelector::abi_decode(&error_bytes);
    assert!(
        decoded_error.is_ok(),
        "Error should be decodable as UnknownFunctionSelector"
    );

    // Verify it contains the correct selector
    let error = decoded_error.unwrap();
    assert_eq!(
        error.selector, unknown_selector,
        "Error should contain the correct unknown selector"
    );

    Ok(())
}
