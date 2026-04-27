use crate::utils::{TEST_MNEMONIC, TestNodeBuilder};
use alloy::{
    primitives::{Address, B256, Bytes},
    providers::{Provider, ProviderBuilder},
    signers::local::MnemonicBuilder,
};
use alloy_primitives::keccak256;
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_contracts::{ERC2470_SINGLETON_DEPLOYER_ADDRESS, ERC2470SingletonDeployer};

// Simple contract: PUSH1 0x2a PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN (returns 42)
const INIT_CODE: &[u8] = &[0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];

/// Compute the CREATE2 address ERC2470 will deploy to:
///   keccak256(0xff ++ factory ++ salt ++ keccak256(initCode))[12..]
///
/// This is deterministic — identical to querying Ethereum mainnet with:
///   cast call 0xce0042B868300000d44A59004Da54A005ffdcf9f \
///     "deploy(bytes,bytes32)(address)" <initCode> 0x00..00 \
///     --rpc-url $ETH_RPC_URL
fn expected_address(salt: B256) -> Address {
    ERC2470_SINGLETON_DEPLOYER_ADDRESS.create2(salt, keccak256(INIT_CODE))
}

#[tokio::test(flavor = "multi_thread")]
async fn test_erc2470_is_deployed_at_t5() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(setup.http_url);

    let deployer = ERC2470SingletonDeployer::new(ERC2470_SINGLETON_DEPLOYER_ADDRESS, &provider);

    // Trigger block production so the T5 boundary code runs (which deploys ERC2470).
    // Use a no-op call to the factory with dummy args — it will revert (no contract yet),
    // but the block still gets produced and apply_pre_execution_changes still runs.
    // Use a dummy deploy_call with gas to force a block.
    deployer
        .deploy_call(Bytes::new(), B256::ZERO)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;

    let code = provider.get_code_at(ERC2470_SINGLETON_DEPLOYER_ADDRESS).await?;
    assert!(
        !code.is_empty(),
        "ERC2470SingletonDeployer must be deployed at T5 boundary"
    );
    assert_eq!(
        code.as_ref(),
        ERC2470SingletonDeployer::DEPLOYED_BYTECODE.as_ref(),
        "ERC2470SingletonDeployer bytecode must match"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_erc2470_deploy_matches_mainnet_create2_address() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(setup.http_url);

    let salt = B256::ZERO;
    let init_code = Bytes::from_static(INIT_CODE);

    let deployer = ERC2470SingletonDeployer::new(ERC2470_SINGLETON_DEPLOYER_ADDRESS, &provider);

    // First produce a block to trigger T5 boundary deployment of ERC2470.
    deployer
        .deploy_call(Bytes::new(), B256::ZERO)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Simulate the call to get the would-be deployed address — same result as
    // `cast call 0xce0042... "deploy(bytes,bytes32)(address)" <initCode> 0x00..00`
    // against Ethereum mainnet (deterministic CREATE2, no state dependency).
    let simulated_addr = Address(
        deployer
            .deploy_call(init_code.clone(), salt)
            .gas_price(TEMPO_T1_BASE_FEE as u128)
            .gas(5_000_000)
            .call()
            .await?
            .0,
    );

    assert_eq!(
        simulated_addr,
        expected_address(salt),
        "simulated deploy address must match local CREATE2 computation"
    );

    // Actually deploy.
    deployer
        .deploy_call(init_code, salt)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(5_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Verify the contract landed at the expected address with the expected runtime code.
    // The init code stores 0x2a at memory[0] and returns 32 bytes.
    let deployed_code = provider.get_code_at(simulated_addr).await?;
    let mut expected_code = [0u8; 32];
    expected_code[31] = 0x2a;
    assert_eq!(deployed_code.as_ref(), &expected_code);

    Ok(())
}
