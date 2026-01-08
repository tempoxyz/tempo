use alloy::{
    primitives::{B256, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::MnemonicBuilder,
    sol_types::SolEvent,
};
use tempo_chainspec::spec::TEMPO_BASE_FEE;
use tempo_contracts::precompiles::{ITIP20, ITIP20Factory};
use tempo_precompiles::{PATH_USD_ADDRESS, TIP20_FACTORY_ADDRESS, tip20::is_tip20_prefix};

#[tokio::test(flavor = "multi_thread")]
async fn test_create_token() -> eyre::Result<()> {
    let setup = crate::utils::TestNodeBuilder::new()
        .build_http_only()
        .await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let factory = ITIP20Factory::new(TIP20_FACTORY_ADDRESS, provider.clone());

    let name = "Test".to_string();
    let symbol = "TEST".to_string();
    let currency = "USD".to_string();
    let salt = B256::random();

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
            salt,
        )
        .gas_price(TEMPO_BASE_FEE as u128)
        .gas(300_000)
        .send()
        .await?
        .get_receipt()
        .await?;

    let event = ITIP20Factory::TokenCreated::decode_log(&receipt.logs()[1].inner).unwrap();
    assert_eq!(event.address, TIP20_FACTORY_ADDRESS);
    assert_eq!(event.name, "Test");
    assert_eq!(event.symbol, "TEST");
    assert_eq!(event.currency, "USD");
    assert_eq!(event.admin, caller);
    assert_eq!(event.salt, salt);

    // Verify the token address has TIP20 prefix
    assert!(
        is_tip20_prefix(event.token),
        "Token should have TIP20 prefix"
    );

    let token = ITIP20::new(event.token, provider);
    assert_eq!(token.name().call().await?, name);
    assert_eq!(token.symbol().call().await?, symbol);
    assert_eq!(token.decimals().call().await?, 6);
    assert_eq!(token.currency().call().await?, currency);
    // Supply cap is u128::MAX
    assert_eq!(token.supplyCap().call().await?, U256::from(u128::MAX));
    assert_eq!(token.transferPolicyId().call().await?, 1);

    Ok(())
}

/// isTIP20 should check both prefix and code deployment
#[tokio::test(flavor = "multi_thread")]
async fn test_is_tip20_checks_code_deployment() -> eyre::Result<()> {
    let setup = crate::utils::TestNodeBuilder::new()
        .build_http_only()
        .await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let factory = ITIP20Factory::new(TIP20_FACTORY_ADDRESS, provider.clone());

    // Create an address with valid TIP20 prefix but no code deployed
    // Using a fake address that has the prefix but was never created
    let mut fake_tip20_bytes = [0u8; 20];
    fake_tip20_bytes[..12].copy_from_slice(&[0x20, 0xC0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    fake_tip20_bytes[12..].copy_from_slice(&[0xFF; 8]); // Random suffix
    let non_existent_tip20_addr = alloy::primitives::Address::from(fake_tip20_bytes);

    // Verify this address has valid TIP20 prefix
    assert!(
        is_tip20_prefix(non_existent_tip20_addr),
        "Address should have valid TIP20 prefix"
    );

    // isTIP20 should return false because no code is deployed
    let is_tip20 = factory.isTIP20(non_existent_tip20_addr).call().await?;
    assert!(
        !is_tip20,
        "isTIP20 should return false for address with no deployed code"
    );

    // Verify that a valid TIP20 (PATH_USD) returns true
    let path_usd_is_tip20 = factory.isTIP20(PATH_USD_ADDRESS).call().await?;
    assert!(path_usd_is_tip20, "PATH_USD should be a valid TIP20");

    Ok(())
}
