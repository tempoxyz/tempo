use crate::utils::{setup_test_node, setup_test_token};
use alloy::{
    providers::ProviderBuilder,
    signers::local::{MnemonicBuilder, coins_bip39::English},
};
use std::env;
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    contracts::{token_id_to_address, types::IFeeManager},
};

#[tokio::test(flavor = "multi_thread")]
async fn test_set_user_token() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        crate::utils::NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        crate::utils::NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _local_node) = setup_test_node(source).await?;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let user_address = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let user_token = setup_test_token(provider.clone(), user_address).await?;
    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider);

    let initial_token = fee_manager.userTokens(user_address).call().await?;
    // Initial token should be predeployed token
    assert_eq!(initial_token, token_id_to_address(0));

    let set_receipt = fee_manager
        .setUserToken(*user_token.address())
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(set_receipt.status());

    let current_token = fee_manager.userTokens(user_address).call().await?;
    assert_eq!(current_token, *user_token.address());

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_set_validator_token() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        crate::utils::NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        crate::utils::NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _local_node) = setup_test_node(source).await?;

    let wallet = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .build()?;
    let validator_address = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let validator_token = setup_test_token(provider.clone(), validator_address).await?;
    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider);

    let initial_token = fee_manager
        .validatorTokens(validator_address)
        .call()
        .await?;
    // Initial token should be predeployed token
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
