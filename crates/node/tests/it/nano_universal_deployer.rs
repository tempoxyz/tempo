use crate::utils::{TEST_MNEMONIC, TestNodeBuilder};
use alloy::{
    primitives::{Bytes, TxKind},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::MnemonicBuilder,
};
use alloy_primitives::{keccak256, B256};
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_contracts::{NANO_UNIVERSAL_DEPLOYER_ADDRESS, NanoUniversalDeployer};

// Simple contract: PUSH1 0x2a PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN (returns 42)
const INIT_CODE: &[u8] = &[0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];

#[tokio::test(flavor = "multi_thread")]
async fn test_nano_universal_deployer_is_deployed_at_t5() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let sender = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(setup.http_url);

    // Trigger block production so the T5 boundary code runs (which deploys NanoUniversalDeployer).
    // Any tx to the address works; the block's pre-execution deploys the contract first.
    provider
        .send_transaction(TransactionRequest {
            from: Some(sender),
            to: Some(TxKind::Call(NANO_UNIVERSAL_DEPLOYER_ADDRESS)),
            input: alloy::rpc::types::TransactionInput::new(Bytes::from_static(INIT_CODE)),
            gas_price: Some(TEMPO_T1_BASE_FEE as u128),
            gas: Some(1_000_000),
            ..Default::default()
        })
        .await?
        .get_receipt()
        .await?;

    let code = provider.get_code_at(NANO_UNIVERSAL_DEPLOYER_ADDRESS).await?;
    assert!(
        !code.is_empty(),
        "NanoUniversalDeployer must be deployed at T5 boundary"
    );
    assert_eq!(
        code.as_ref(),
        NanoUniversalDeployer::DEPLOYED_BYTECODE.as_ref(),
        "NanoUniversalDeployer bytecode must match"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_nano_universal_deployer_create_address() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let sender = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(setup.http_url);

    // NanoUniversalDeployer uses CREATE2 with a hardcoded salt of zero. Calldata is just
    // the init code — no salt prefix. The deployed address is deterministic:
    //   keccak256(0xff ++ deployer ++ 0x00..00 ++ keccak256(initCode))[12..]
    let expected_addr = NANO_UNIVERSAL_DEPLOYER_ADDRESS.create2(B256::ZERO, keccak256(INIT_CODE));

    let receipt = provider
        .send_transaction(TransactionRequest {
            from: Some(sender),
            to: Some(TxKind::Call(NANO_UNIVERSAL_DEPLOYER_ADDRESS)),
            input: alloy::rpc::types::TransactionInput::new(Bytes::from_static(INIT_CODE)),
            gas_price: Some(TEMPO_T1_BASE_FEE as u128),
            gas: Some(1_000_000),
            ..Default::default()
        })
        .await?
        .get_receipt()
        .await?;

    assert!(receipt.status(), "deploy tx must succeed");

    // The init code stores 0x2a at memory[0] and returns 32 bytes.
    let deployed_code = provider.get_code_at(expected_addr).await?;
    let mut expected_code = [0u8; 32];
    expected_code[31] = 0x2a;
    assert_eq!(
        deployed_code.as_ref(),
        &expected_code,
        "contract deployed via NanoUniversalDeployer must land at CREATE2 address with expected code"
    );

    Ok(())
}
