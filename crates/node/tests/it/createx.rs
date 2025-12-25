use crate::utils::{TEST_MNEMONIC, TestNodeBuilder};
use alloy::{
    primitives::Bytes,
    providers::{Provider, ProviderBuilder},
    signers::local::MnemonicBuilder,
};
use tempo_chainspec::spec::TEMPO_BASE_FEE;
use tempo_contracts::{CREATEX_ADDRESS, CreateX};

#[tokio::test(flavor = "multi_thread")]
async fn test_createx() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new()
        .allegro_moderato_activated()
        .build_http_only()
        .await?;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(setup.http_url);

    // Simple contract: PUSH1 0x2a PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN (returns 42)
    let init_code =
        Bytes::from_static(&[0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3]);

    let createx = CreateX::new(CREATEX_ADDRESS, &provider);

    // Get deployed address from simulated call
    let deployed_address = createx
        .deployCreate(init_code.clone())
        .gas_price(TEMPO_BASE_FEE as u128)
        .gas(500_000)
        .call()
        .await?
        .0;

    // Send the actual transaction
    createx
        .deployCreate(init_code)
        .gas_price(TEMPO_BASE_FEE as u128)
        .gas(500_000)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Verify deployed contract has the expected runtime code
    // The init code stores 0x2a at memory[0] and returns 32 bytes
    let deployed_code = provider.get_code_at(deployed_address.into()).await?;
    let mut expected = [0u8; 32];
    expected[31] = 0x2a;
    assert_eq!(deployed_code.as_ref(), &expected);

    // Verify CreateX bytecode was fixed after block execution
    let code_after = provider.get_code_at(CREATEX_ADDRESS).await?;
    let hash_after = alloy::primitives::keccak256(&code_after);
    assert_eq!(
        hash_after,
        tempo_contracts::contracts::CREATEX_BYTECODE_HASH,
        "CreateX bytecode should be fixed"
    );

    Ok(())
}
