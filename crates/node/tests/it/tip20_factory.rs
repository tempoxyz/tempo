use alloy::providers::ProviderBuilder;
use reth_e2e_test_utils::wallet::test_signer;
use tempo_contracts::precompiles::ITIP20Factory;
use tempo_precompiles::{PATH_USD_ADDRESS, TIP20_FACTORY_ADDRESS};
use tempo_primitives::TempoAddressExt;

/// isTIP20 should check both prefix and code deployment
#[tokio::test(flavor = "multi_thread")]
async fn test_is_tip20_checks_code_deployment() -> eyre::Result<()> {
    let setup = crate::utils::TestNodeBuilder::new()
        .build_http_only()
        .await?;
    let http_url = setup.http_url;

    let wallet = test_signer(0);
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
        non_existent_tip20_addr.is_tip20(),
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
