use alloy::{
    primitives::U256,
    providers::{Provider, ProviderBuilder},
    signers::local::MnemonicBuilder,
    sol_types::SolEvent,
};
use tempo_chainspec::spec::TEMPO_BASE_FEE;
use tempo_contracts::precompiles::{ITIP20, ITIP20Factory};
use tempo_precompiles::{PATH_USD_ADDRESS, TIP20_FACTORY_ADDRESS, tip20::token_id_to_address};

#[tokio::test(flavor = "multi_thread")]
async fn test_create_token() -> eyre::Result<()> {
    let setup = crate::utils::TestNodeBuilder::new()
        .allegretto_activated()
        .build_http_only()
        .await?;
    let http_url = setup.http_url;

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
    // Supply cap is u128::MAX post-allegretto
    assert_eq!(token.supplyCap().call().await?, U256::from(u128::MAX));
    assert_eq!(token.transferPolicyId().call().await?, 1);

    Ok(())
}

/// Post-AllegroModerato: isTIP20 should check both prefix and tokenIdCounter
#[tokio::test(flavor = "multi_thread")]
async fn test_is_tip20_checks_token_id_counter_post_allegro_moderato() -> eyre::Result<()> {
    let setup = crate::utils::TestNodeBuilder::new()
        .allegro_moderato_activated()
        .build_http_only()
        .await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let factory = ITIP20Factory::new(TIP20_FACTORY_ADDRESS, provider.clone());

    let token_id_counter: u64 = factory.tokenIdCounter().call().await?.to();

    // Create an address with valid TIP20 prefix but token ID >= tokenIdCounter
    let non_existent_token_id = token_id_counter + 100;
    let non_existent_tip20_addr = token_id_to_address(non_existent_token_id);

    // Verify this address has valid TIP20 prefix
    assert!(
        non_existent_tip20_addr
            .as_slice()
            .starts_with(&[0x20, 0xC0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        "Address should have valid TIP20 prefix"
    );

    // isTIP20 should return false because token ID >= tokenIdCounter
    let is_tip20 = factory.isTIP20(non_existent_tip20_addr).call().await?;
    assert!(
        !is_tip20,
        "isTIP20 should return false for non-existent token ID {non_existent_token_id} (>= counter {token_id_counter})"
    );

    // Verify that a valid TIP20 (PATH_USD) returns true
    let path_usd_is_tip20 = factory.isTIP20(PATH_USD_ADDRESS).call().await?;
    assert!(path_usd_is_tip20, "PATH_USD should be a valid TIP20");

    Ok(())
}

/// Pre-AllegroModerato: isTIP20 should only check the prefix for backwards compatibility
#[tokio::test(flavor = "multi_thread")]
async fn test_is_tip20_only_checks_prefix_pre_allegro_moderato() -> eyre::Result<()> {
    let setup = crate::utils::TestNodeBuilder::new()
        .allegretto_activated()
        .build_http_only()
        .await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let factory = ITIP20Factory::new(TIP20_FACTORY_ADDRESS, provider.clone());

    let token_id_counter: u64 = factory.tokenIdCounter().call().await?.to();

    // Create an address with valid TIP20 prefix but token ID >= tokenIdCounter
    let non_existent_token_id = token_id_counter + 100;
    let non_existent_tip20_addr = token_id_to_address(non_existent_token_id);

    // Pre-AllegroModerato: isTIP20 should return true (only checks prefix)
    let is_tip20 = factory.isTIP20(non_existent_tip20_addr).call().await?;
    assert!(
        is_tip20,
        "Pre-AllegroModerato: isTIP20 should return true for valid prefix (token ID {non_existent_token_id})"
    );

    // Verify that a valid TIP20 (PATH_USD) still returns true
    let path_usd_is_tip20 = factory.isTIP20(PATH_USD_ADDRESS).call().await?;
    assert!(path_usd_is_tip20, "PATH_USD should be a valid TIP20");

    Ok(())
}
