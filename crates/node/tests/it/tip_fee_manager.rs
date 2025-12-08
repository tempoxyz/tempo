use crate::utils::{TestNodeBuilder, setup_test_token, setup_test_token_pre_allegretto};
use alloy::{
    providers::{Provider, ProviderBuilder},
    signers::local::MnemonicBuilder,
};
use alloy_eips::BlockId;
use alloy_primitives::{Address, U256};
use alloy_rpc_types_eth::TransactionRequest;
use tempo_contracts::precompiles::{
    IFeeManager, ITIP20,
    ITIPFeeAMM::{self},
};
use tempo_precompiles::{PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS, tip20::token_id_to_address};
use tempo_primitives::transaction::calc_gas_balance_spending;

#[tokio::test(flavor = "multi_thread")]
async fn test_set_user_token() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new()
        .allegro_moderato_activated()
        .build_http_only()
        .await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let user_address = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    // Use pre-allegretto token creation since test uses moderato genesis
    let user_token = setup_test_token_pre_allegretto(provider.clone(), user_address).await?;
    let validator_token = ITIP20::new(PATH_USD_ADDRESS, &provider);
    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

    user_token
        .mint(user_address, U256::from(1e10))
        .send()
        .await?
        .watch()
        .await?;

    // Initial token should be predeployed token
    assert_eq!(
        fee_manager.userTokens(user_address).call().await?,
        token_id_to_address(1)
    );

    let validator = provider
        .get_block(BlockId::latest())
        .await?
        .unwrap()
        .header
        .beneficiary;

    let validator_balance_before = validator_token.balanceOf(validator).call().await?;

    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

    let receipt = fee_amm
        .mintWithValidatorToken(
            *user_token.address(),
            *validator_token.address(),
            U256::from(1e8),
            user_address,
        )
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status());

    let expected_cost = calc_gas_balance_spending(receipt.gas_used, receipt.effective_gas_price);

    let validator_balance_after = validator_token.balanceOf(validator).call().await?;
    assert_eq!(
        validator_balance_after,
        validator_balance_before + expected_cost * U256::from(9970) / U256::from(10000)
    );

    let set_receipt = fee_manager
        .setUserToken(*user_token.address())
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(set_receipt.status());

    let current_token = fee_manager.userTokens(user_address).call().await?;
    assert_eq!(current_token, *user_token.address());

    assert!(validator_token.balanceOf(validator).call().await? > validator_balance_after);

    // send a dummy transaction
    let receipt = provider
        .send_transaction(TransactionRequest::default().to(Address::random()))
        .await?
        .get_receipt()
        .await?;

    // Assert transaction fee was paid in the newly configured token.
    assert!(receipt.logs().last().unwrap().address() == *user_token.address());

    // Ensure the validator was paid for it (or wasn't due to pre-moderato bug)
    let validator_balance_before = validator_token
        .balanceOf(validator)
        .block((receipt.block_number.unwrap() - 1).into())
        .call()
        .await?;
    let validator_balance_after = validator_token.balanceOf(validator).call().await?;

    assert!(validator_balance_after > validator_balance_before);

    // Ensure that the user can set the fee token back to pathUSD post allegro moderato
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

    let setup = TestNodeBuilder::new()
        .allegretto_activated()
        .build_http_only()
        .await?;
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
    // Initial token should be PathUSD (token_id 0)
    assert_eq!(initial_token, token_id_to_address(0));

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
