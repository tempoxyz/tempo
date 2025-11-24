use alloy::{
    primitives::U256,
    providers::{Provider, ProviderBuilder},
    signers::local::MnemonicBuilder,
    sol_types::SolEvent,
};
use alloy_primitives::Address;
use std::env;
use tempo_chainspec::spec::TEMPO_BASE_FEE;
use tempo_contracts::precompiles::{ITIP20, ITIP20Factory};
use tempo_precompiles::{PATH_USD_ADDRESS, TIP20_FACTORY_ADDRESS, tip20::token_id_to_address};

#[tokio::test(flavor = "multi_thread")]
async fn test_create_token() -> eyre::Result<()> {
    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        crate::utils::NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        crate::utils::NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _local_node) = crate::utils::setup_test_node(source).await?;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let factory = ITIP20Factory::new(TIP20_FACTORY_ADDRESS, provider.clone());

    let initial_token_id = factory.tokenIdCounter().call().await?;
    let name = "Test".to_string();
    let symbol = "TEST".to_string();
    let currency = "USD".to_string();

    // Ensure the native account balance is zero
    let balance = provider.get_account_info(caller).await?.balance;
    assert_eq!(balance, U256::ZERO);
    let receipt = factory
        .createToken(
            "Test".to_string(),
            "TEST".to_string(),
            "USD".to_string(),
            PATH_USD_ADDRESS,
            caller,
            Address::ZERO,
        )
        .gas_price(TEMPO_BASE_FEE as u128)
        .gas(300_000)
        .send()
        .await?
        .get_receipt()
        .await?;

    let event = ITIP20Factory::TokenCreated::decode_log(&receipt.logs()[0].inner).unwrap();
    assert_eq!(event.tokenId, initial_token_id);
    assert_eq!(event.address, TIP20_FACTORY_ADDRESS);
    assert_eq!(event.name, "Test");
    assert_eq!(event.symbol, "TEST");
    assert_eq!(event.currency, "USD");
    assert_eq!(event.admin, caller);

    let token_id = factory.tokenIdCounter().call().await?;
    assert_eq!(token_id, initial_token_id + U256::ONE);

    let token_addr = token_id_to_address(event.tokenId.to());
    let token = ITIP20::new(token_addr, provider);
    assert_eq!(token.name().call().await?, name);
    assert_eq!(token.symbol().call().await?, symbol);
    assert_eq!(token.decimals().call().await?, 6);
    assert_eq!(token.currency().call().await?, currency);
    assert_eq!(token.supplyCap().call().await?, U256::MAX);
    assert_eq!(token.transferPolicyId().call().await?, 1);

    Ok(())
}
