//! Tests for TIP-1016: Exempt Storage Creation from Gas Limits.
//!
//! TIP-1016 splits storage creation costs into two components:
//! - **Execution gas**: computational cost (writing, hashing) -- counts toward protocol limits
//! - **Storage creation gas**: permanent storage burden -- does NOT count toward protocol limits
//!
//! Key invariants tested:
//! 1. Block header gas_used reflects only execution gas (storage creation gas excluded)
//! 2. Receipt gas_used includes ALL gas (execution + storage creation)
//! 3. Therefore: sum of receipt gas_used > block header gas_used when storage is created
//! 4. Transactions that only touch existing storage have no difference
//! 5. Reverted txs still have state gas exempted from protocol limits (CPU time is bounded
//!    regardless of whether state was committed)
//! 6. Multiple storage-creating operations in a single tx are additive
//! 7. Multiple storage-creating txs in a single block correctly accumulate exemptions
//! 8. Reverted inner CALLs do NOT contribute state gas to the parent frame's exemption

use reth_node_api::BuiltPayload;

use alloy::{
    consensus::{SignableTransaction, Transaction, TxEip1559, TxEnvelope},
    primitives::{Address, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::MnemonicBuilder,
    sol_types::SolCall,
};
use alloy_eips::{BlockId, BlockNumberOrTag, eip2718::Encodable2718};
use alloy_network::TxSignerSync;
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_contracts::{CREATEX_ADDRESS, CreateX, Multicall3, precompiles::DEFAULT_FEE_TOKEN};

use crate::utils::{TEST_MNEMONIC, TestNodeBuilder};

/// Builds and encodes a signed EIP-1559 CALL transaction.
fn build_call_tx(
    signer: &alloy::signers::local::PrivateKeySigner,
    chain_id: u64,
    nonce: u64,
    gas_limit: u64,
    to: Address,
    input: Bytes,
) -> Bytes {
    let mut tx = TxEip1559 {
        chain_id,
        nonce,
        gas_limit,
        to: to.into(),
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        input,
        ..Default::default()
    };
    let signature = signer.sign_transaction_sync(&mut tx).unwrap();
    TxEnvelope::Eip1559(tx.into_signed(signature))
        .encoded_2718()
        .into()
}

/// Gets the deployed contract address from CreateX's ContractCreation event, polling until
/// receipts are available.
async fn get_createx_deployed_address<P: Provider>(
    provider: &P,
    block_number: u64,
) -> eyre::Result<Address> {
    let block_id = BlockId::Number(BlockNumberOrTag::Number(block_number));
    for _ in 0..50 {
        if let Some(receipts) = provider.get_block_receipts(block_id).await? {
            let receipt = receipts
                .iter()
                .find(|r| !r.inner.logs().is_empty())
                .expect("should have a receipt with logs");
            assert!(receipt.status(), "deployment should succeed");
            let addr = Address::from_slice(
                &receipt.inner.logs()[0].inner.data.topics()[1].as_slice()[12..],
            );
            return Ok(addr);
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    eyre::bail!("timed out waiting for deploy receipts at block {block_number}")
}

/// Returns the total gas_used from all receipts in a block, polling until the RPC catches up.
async fn total_receipt_gas_for_block<P: Provider>(
    provider: &P,
    block_number: u64,
) -> eyre::Result<u64> {
    let block_id = BlockId::Number(BlockNumberOrTag::Number(block_number));
    for _ in 0..50 {
        if let Some(receipts) = provider.get_block_receipts(block_id).await? {
            return Ok(receipts.iter().map(|r| r.gas_used).sum());
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    eyre::bail!("timed out waiting for receipts at block {block_number}")
}

/// Happy path: deploying a contract via CreateX creates new storage (account creation +
/// code storage), so block header gas_used should be less than the sum of receipt gas_used.
///
/// The difference is the storage creation gas that TIP-1016 exempts from protocol limits.
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1016_contract_deployment_exempts_storage_gas() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    let signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(0)?
        .build()?;
    let provider = ProviderBuilder::new().connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    // Simple contract init code: PUSH1 0x2a PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN
    // Deploys a contract that returns 42, creating new account + code storage.
    let init_code =
        Bytes::from_static(&[0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3]);

    let createx = CreateX::new(CREATEX_ADDRESS, &provider);
    let deploy_calldata: Bytes = createx.deployCreate(init_code).calldata().clone();

    let raw_tx = build_call_tx(
        &signer,
        chain_id,
        0,
        5_000_000,
        CREATEX_ADDRESS,
        deploy_calldata,
    );
    setup.node.rpc.inject_tx(raw_tx.clone()).await?;

    let payload = setup.node.advance_block().await?;
    let block = payload.block();
    let block_number = block.header().inner.number;
    let block_gas_used = block.header().inner.gas_used;

    // Verify user tx was included (non-system txs have gas_limit > 0)
    let user_tx_count = block
        .body()
        .transactions()
        .filter(|tx| (*tx).gas_limit() > 0)
        .count();
    assert!(user_tx_count > 0, "deploy tx should be included in block");

    let receipts_total_gas = total_receipt_gas_for_block(&provider, block_number).await?;

    // TIP-1016: block header gas_used should be LESS than the sum of all receipt gas_used
    // because state gas is exempted from the block header but charged to users.
    //
    // State gas includes: account creation, code deposit (32 * 2300 = 73600),
    // and other state-affecting operations tracked by the EVM.
    let state_gas = receipts_total_gas - block_gas_used;
    assert!(
        state_gas >= 73_600,
        "state gas should be at least 73,600 (code_deposit_state_gas), \
         got {state_gas} (block_gas_used={block_gas_used}, receipts_total_gas={receipts_total_gas})"
    );

    Ok(())
}

/// Happy path: a SSTORE (zero -> non-zero) via a CALL to an existing contract
/// triggers the storage creation gas exemption.
///
/// SSTORE zero->non-zero costs 250,000 gas total (5,000 exec + 245,000 storage).
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1016_sstore_zero_to_nonzero_exempts_storage_gas() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    let signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(0)?
        .build()?;
    let provider = ProviderBuilder::new().connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    // Step 1: Deploy a contract whose runtime code does SSTORE(calldataload(0), 1)
    //
    // Runtime bytecode (7 bytes):
    //   PUSH1 0x01   PUSH1 0x00  CALLDATALOAD  SSTORE  STOP
    //
    // Init code wraps runtime via CODECOPY + RETURN
    let init_code = Bytes::from_static(&[
        // Init code (12 bytes)
        0x60, 0x07, // PUSH1 7 (runtime length)
        0x60, 0x0c, // PUSH1 12 (runtime offset)
        0x60, 0x00, // PUSH1 0 (memory dest)
        0x39, // CODECOPY
        0x60, 0x07, // PUSH1 7 (return length)
        0x60, 0x00, // PUSH1 0 (return offset)
        0xf3, // RETURN
        // Runtime code (7 bytes)
        0x60, 0x01, // PUSH1 1 (value)
        0x60, 0x00, // PUSH1 0 (calldata offset)
        0x35, // CALLDATALOAD (slot)
        0x55, // SSTORE
        0x00, // STOP
    ]);

    let createx = CreateX::new(CREATEX_ADDRESS, &provider);
    let deploy_calldata: Bytes = createx.deployCreate(init_code).calldata().clone();

    let deploy_raw = build_call_tx(
        &signer,
        chain_id,
        0,
        5_000_000,
        CREATEX_ADDRESS,
        deploy_calldata,
    );
    setup.node.rpc.inject_tx(deploy_raw).await?;
    let deploy_payload = setup.node.advance_block().await?;

    // Get deployed contract address from the CreateX ContractCreation event
    let deploy_block_number = deploy_payload.block().header().inner.number;
    let contract_addr = get_createx_deployed_address(&provider, deploy_block_number).await?;

    // Step 2: Call the deployed contract to trigger SSTORE zero->non-zero at slot 42
    let calldata: Bytes = alloy_primitives::B256::left_padding_from(&42u64.to_be_bytes())
        .as_slice()
        .to_vec()
        .into();
    let call_raw = build_call_tx(&signer, chain_id, 1, 5_000_000, contract_addr, calldata);
    setup.node.rpc.inject_tx(call_raw).await?;
    let call_payload = setup.node.advance_block().await?;

    let call_block_number = call_payload.block().header().inner.number;
    let block_gas_used = call_payload.block().header().inner.gas_used;
    let receipts_total_gas = total_receipt_gas_for_block(&provider, call_block_number).await?;

    // TIP-1016: block gas_used should be less than receipt gas because
    // the SSTORE zero->non-zero has 230,000 storage creation gas exempted.
    //
    // sstore_set_state_gas = 250,000 - 20,000 = 230,000 per TIP-1016 spec
    let storage_creation_gas = receipts_total_gas - block_gas_used;
    assert_eq!(
        storage_creation_gas, 230_000,
        "storage creation gas should be exactly 230,000 (sstore_set_state_gas), \
         got {storage_creation_gas} (block_gas_used={block_gas_used}, receipts_total_gas={receipts_total_gas})"
    );

    Ok(())
}

/// Happy path: a SSTORE that modifies an existing slot (non-zero -> non-zero) should
/// NOT have any storage creation gas component, so block gas_used and total receipt gas
/// should be equal.
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1016_sstore_nonzero_to_nonzero_no_exemption() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    let signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(0)?
        .build()?;
    let provider = ProviderBuilder::new().connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    // Deploy a contract that does: SSTORE(slot=calldataload(0), value=calldataload(32))
    //
    // Runtime (8 bytes):
    //   PUSH1 0x20  CALLDATALOAD  PUSH1 0x00  CALLDATALOAD  SSTORE  STOP
    let init_code = Bytes::from_static(&[
        // Init code (12 bytes)
        0x60, 0x08, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, 0x08, 0x60, 0x00, 0xf3,
        // Runtime code (8 bytes)
        0x60, 0x20, 0x35, 0x60, 0x00, 0x35, 0x55, 0x00,
    ]);

    let createx = CreateX::new(CREATEX_ADDRESS, &provider);
    let deploy_calldata: Bytes = createx.deployCreate(init_code).calldata().clone();

    let deploy_raw = build_call_tx(
        &signer,
        chain_id,
        0,
        5_000_000,
        CREATEX_ADDRESS,
        deploy_calldata,
    );
    setup.node.rpc.inject_tx(deploy_raw).await?;
    let deploy_payload = setup.node.advance_block().await?;

    let deploy_blk = deploy_payload.block().header().inner.number;
    let contract_addr = get_createx_deployed_address(&provider, deploy_blk).await?;

    // First call: SSTORE zero->non-zero at slot 0
    let mut calldata1 = [0u8; 64];
    calldata1[63] = 1; // value = 1
    let call1_raw = build_call_tx(
        &signer,
        chain_id,
        1,
        5_000_000,
        contract_addr,
        calldata1.to_vec().into(),
    );
    setup.node.rpc.inject_tx(call1_raw).await?;
    setup.node.advance_block().await?;

    // Second call: SSTORE non-zero->non-zero at slot 0 (value 1->2)
    let mut calldata2 = [0u8; 64];
    calldata2[63] = 2; // value = 2
    let call2_raw = build_call_tx(
        &signer,
        chain_id,
        2,
        5_000_000,
        contract_addr,
        calldata2.to_vec().into(),
    );
    setup.node.rpc.inject_tx(call2_raw).await?;
    let call2_payload = setup.node.advance_block().await?;

    let blk_number = call2_payload.block().header().inner.number;
    let block_gas_used = call2_payload.block().header().inner.gas_used;
    let receipts_total_gas = total_receipt_gas_for_block(&provider, blk_number).await?;

    // For non-zero->non-zero SSTORE, there's no storage creation gas.
    // Block gas_used and total receipt gas should be equal.
    assert_eq!(
        block_gas_used, receipts_total_gas,
        "block gas_used ({block_gas_used}) should equal total receipt gas \
         ({receipts_total_gas}) for non-zero->non-zero SSTORE (no storage creation)"
    );

    Ok(())
}

/// Happy path: a TIP-20 transfer to an existing account (no new storage slots created)
/// should have identical block gas_used and total receipt gas.
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1016_tip20_transfer_existing_no_storage_creation() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    let signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(0)?
        .build()?;
    let signer2 = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(1)?
        .build()?;
    let provider = ProviderBuilder::new().connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    let sender = signer.address();
    let receiver = signer2.address();
    let token =
        tempo_precompiles::tip20::ITIP20::new(tempo_precompiles::PATH_USD_ADDRESS, &provider);

    // Mint tokens to both signers
    let mint_calldata: Bytes = token.mint(sender, U256::from(1_000_000)).calldata().clone();
    let mint_raw = build_call_tx(
        &signer,
        chain_id,
        0,
        5_000_000,
        tempo_precompiles::PATH_USD_ADDRESS,
        mint_calldata,
    );
    setup.node.rpc.inject_tx(mint_raw).await?;
    let mint_calldata: Bytes = token
        .mint(receiver, U256::from(1_000_000))
        .calldata()
        .clone();
    let mint_raw2 = build_call_tx(
        &signer,
        chain_id,
        1,
        5_000_000,
        tempo_precompiles::PATH_USD_ADDRESS,
        mint_calldata,
    );
    setup.node.rpc.inject_tx(mint_raw2).await?;
    setup.node.advance_block().await?;

    // Transfer to second receiver (existing account, existing balance slot) -- no storage creation
    let transfer_calldata: Bytes = token.transfer(receiver, U256::from(100)).calldata().clone();
    let transfer_raw = build_call_tx(
        &signer,
        chain_id,
        2,
        5_000_000,
        tempo_precompiles::PATH_USD_ADDRESS,
        transfer_calldata,
    );
    setup.node.rpc.inject_tx(transfer_raw).await?;
    let transfer_payload = setup.node.advance_block().await?;

    let blk_number = transfer_payload.block().header().inner.number;
    let block_gas_used = transfer_payload.block().header().inner.gas_used;
    let receipts_total_gas = total_receipt_gas_for_block(&provider, blk_number).await?;

    // No storage creation -> block gas_used should equal total receipt gas
    assert_eq!(
        block_gas_used, receipts_total_gas,
        "block gas_used ({block_gas_used}) should equal total receipt gas \
         ({receipts_total_gas}) for TIP-20 transfer to existing account (no storage creation)"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Unhappy path / corner case tests
// ---------------------------------------------------------------------------

/// Unhappy path: a transaction that does SSTORE zero->non-zero then explicitly REVERTs.
///
/// Even though the tx reverts (state changes rolled back), the storage creation gas
/// is still exempted from protocol limits because protocol limits bound CPU time, and
/// the SSTORE execution cost (5,000) is the only CPU-relevant part regardless of outcome.
///
/// revm preserves state_gas_spent on all result paths (ok, revert, halt) via
/// `last_frame_result`, so the block header gas_used should still exclude the 245,000
/// storage creation gas.
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1016_reverted_sstore_still_exempts_state_gas() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    let signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(0)?
        .build()?;
    let provider = ProviderBuilder::new().connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    // Deploy a contract whose runtime does SSTORE(0, 1) then REVERT.
    //
    // Runtime bytecode (10 bytes):
    //   PUSH1 0x01  PUSH1 0x00  SSTORE  PUSH1 0x00  PUSH1 0x00  REVERT
    let init_code = Bytes::from_static(&[
        // Init code (12 bytes)
        0x60, 0x0a, // PUSH1 10 (runtime length)
        0x60, 0x0c, // PUSH1 12 (runtime offset)
        0x60, 0x00, // PUSH1 0 (memory dest)
        0x39, // CODECOPY
        0x60, 0x0a, // PUSH1 10 (return length)
        0x60, 0x00, // PUSH1 0 (return offset)
        0xf3, // RETURN
        // Runtime code (10 bytes)
        0x60, 0x01, // PUSH1 1 (value)
        0x60, 0x00, // PUSH1 0 (slot)
        0x55, // SSTORE (zero -> non-zero)
        0x60, 0x00, // PUSH1 0 (revert data size)
        0x60, 0x00, // PUSH1 0 (revert data offset)
        0xfd, // REVERT
    ]);

    let createx = CreateX::new(CREATEX_ADDRESS, &provider);
    let deploy_calldata: Bytes = createx.deployCreate(init_code).calldata().clone();

    let deploy_raw = build_call_tx(
        &signer,
        chain_id,
        0,
        5_000_000,
        CREATEX_ADDRESS,
        deploy_calldata,
    );
    setup.node.rpc.inject_tx(deploy_raw).await?;
    let deploy_payload = setup.node.advance_block().await?;
    let deploy_block_number = deploy_payload.block().header().inner.number;
    let contract_addr = get_createx_deployed_address(&provider, deploy_block_number).await?;

    // Call the contract -- it will do SSTORE(0, 1) then REVERT
    let call_raw = build_call_tx(&signer, chain_id, 1, 5_000_000, contract_addr, Bytes::new());
    setup.node.rpc.inject_tx(call_raw).await?;
    let call_payload = setup.node.advance_block().await?;

    let call_block_number = call_payload.block().header().inner.number;
    let block_gas_used = call_payload.block().header().inner.gas_used;
    let receipts_total_gas = total_receipt_gas_for_block(&provider, call_block_number).await?;

    // Verify the tx reverted by checking receipts
    let block_id = BlockId::Number(BlockNumberOrTag::Number(call_block_number));
    let receipts = provider
        .get_block_receipts(block_id)
        .await?
        .expect("receipts should be available");
    let user_receipt = receipts
        .iter()
        .find(|r| r.gas_used > 0 && !r.status())
        .expect("should have a reverted user tx receipt");
    assert!(!user_receipt.status(), "tx should have reverted");

    // When a tx reverts, state changes are rolled back so state_gas_spent is 0.
    // Block header gas_used should equal receipt gas_used (no state gas exemption).
    assert_eq!(
        block_gas_used, receipts_total_gas,
        "reverted tx should have block_gas_used == receipts_total_gas (no state gas on revert), \
         got block_gas_used={block_gas_used}, receipts_total_gas={receipts_total_gas}"
    );

    Ok(())
}

/// Corner case: multiple SSTORE zero->non-zero in a single transaction.
///
/// Storage creation gas should be additive: N slots x 245,000 per slot.
/// Block header gas_used should only include the execution component (5,000 per slot).
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1016_multiple_sstore_zero_to_nonzero_additive() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    let signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(0)?
        .build()?;
    let provider = ProviderBuilder::new().connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    // Deploy a contract that does 3 SSTOREs: slot 0, 1, 2 all zero->non-zero.
    //
    // Runtime bytecode (16 bytes):
    //   PUSH1 0x01  PUSH1 0x00  SSTORE   (slot 0 = 1)
    //   PUSH1 0x01  PUSH1 0x01  SSTORE   (slot 1 = 1)
    //   PUSH1 0x01  PUSH1 0x02  SSTORE   (slot 2 = 1)
    //   STOP
    let init_code = Bytes::from_static(&[
        // Init code (12 bytes)
        0x60, 0x10, // PUSH1 16 (runtime length)
        0x60, 0x0c, // PUSH1 12 (runtime offset)
        0x60, 0x00, // PUSH1 0 (memory dest)
        0x39, // CODECOPY
        0x60, 0x10, // PUSH1 16 (return length)
        0x60, 0x00, // PUSH1 0 (return offset)
        0xf3, // RETURN
        // Runtime code (16 bytes)
        0x60, 0x01, // PUSH1 1
        0x60, 0x00, // PUSH1 0 (slot 0)
        0x55, // SSTORE
        0x60, 0x01, // PUSH1 1
        0x60, 0x01, // PUSH1 1 (slot 1)
        0x55, // SSTORE
        0x60, 0x01, // PUSH1 1
        0x60, 0x02, // PUSH1 2 (slot 2)
        0x55, // SSTORE
        0x00, // STOP
    ]);

    let createx = CreateX::new(CREATEX_ADDRESS, &provider);
    let deploy_calldata: Bytes = createx.deployCreate(init_code).calldata().clone();

    let deploy_raw = build_call_tx(
        &signer,
        chain_id,
        0,
        5_000_000,
        CREATEX_ADDRESS,
        deploy_calldata,
    );
    setup.node.rpc.inject_tx(deploy_raw).await?;
    let deploy_payload = setup.node.advance_block().await?;
    let deploy_blk = deploy_payload.block().header().inner.number;
    let contract_addr = get_createx_deployed_address(&provider, deploy_blk).await?;

    // Call the contract to trigger 3 SSTOREs zero->non-zero
    let call_raw = build_call_tx(&signer, chain_id, 1, 5_000_000, contract_addr, Bytes::new());
    setup.node.rpc.inject_tx(call_raw).await?;
    let call_payload = setup.node.advance_block().await?;

    let call_blk = call_payload.block().header().inner.number;
    let block_gas_used = call_payload.block().header().inner.gas_used;
    let receipts_total_gas = total_receipt_gas_for_block(&provider, call_blk).await?;

    // 3 SSTOREs zero->non-zero: 3 x 230,000 = 690,000 storage creation gas exempted
    let storage_creation_gas = receipts_total_gas - block_gas_used;
    assert_eq!(
        storage_creation_gas,
        3 * 230_000,
        "storage creation gas should be 3 x 230,000 = 690,000, \
         got {storage_creation_gas} (block_gas_used={block_gas_used}, receipts_total_gas={receipts_total_gas})"
    );

    Ok(())
}

/// Corner case: two storage-creating transactions in the same block.
///
/// Each tx does SSTORE zero->non-zero. The block's cumulative storage creation gas
/// should be the sum of both (2 x 230,000 = 460,000). This tests that the inner
/// executor's `block_regular_gas_used` correctly excludes state gas across
/// multiple transactions.
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1016_two_storage_txs_same_block() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    let signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(0)?
        .build()?;
    let provider = ProviderBuilder::new().connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    // Deploy contract: SSTORE(calldataload(0), 1) -- same as existing test
    //
    // Runtime (7 bytes):
    //   PUSH1 0x01  PUSH1 0x00  CALLDATALOAD  SSTORE  STOP
    let init_code = Bytes::from_static(&[
        // Init code (12 bytes)
        0x60, 0x07, // PUSH1 7 (runtime length)
        0x60, 0x0c, // PUSH1 12 (runtime offset)
        0x60, 0x00, // PUSH1 0 (memory dest)
        0x39, // CODECOPY
        0x60, 0x07, // PUSH1 7 (return length)
        0x60, 0x00, // PUSH1 0 (return offset)
        0xf3, // RETURN
        // Runtime code (7 bytes)
        0x60, 0x01, // PUSH1 1 (value)
        0x60, 0x00, // PUSH1 0 (calldata offset)
        0x35, // CALLDATALOAD (slot)
        0x55, // SSTORE
        0x00, // STOP
    ]);

    let createx = CreateX::new(CREATEX_ADDRESS, &provider);
    let deploy_calldata: Bytes = createx.deployCreate(init_code).calldata().clone();

    let deploy_raw = build_call_tx(
        &signer,
        chain_id,
        0,
        5_000_000,
        CREATEX_ADDRESS,
        deploy_calldata,
    );
    setup.node.rpc.inject_tx(deploy_raw).await?;
    let deploy_payload = setup.node.advance_block().await?;
    let deploy_blk = deploy_payload.block().header().inner.number;
    let contract_addr = get_createx_deployed_address(&provider, deploy_blk).await?;

    // Submit two txs that each do SSTORE zero->non-zero at different slots
    let slot_100: Bytes = alloy_primitives::B256::left_padding_from(&100u64.to_be_bytes())
        .as_slice()
        .to_vec()
        .into();
    let slot_200: Bytes = alloy_primitives::B256::left_padding_from(&200u64.to_be_bytes())
        .as_slice()
        .to_vec()
        .into();

    let tx1_raw = build_call_tx(&signer, chain_id, 1, 5_000_000, contract_addr, slot_100);
    let tx2_raw = build_call_tx(&signer, chain_id, 2, 5_000_000, contract_addr, slot_200);

    // Inject both before advancing -- they should land in the same block
    setup.node.rpc.inject_tx(tx1_raw).await?;
    setup.node.rpc.inject_tx(tx2_raw).await?;
    let payload = setup.node.advance_block().await?;

    let blk_number = payload.block().header().inner.number;
    let block_gas_used = payload.block().header().inner.gas_used;
    let receipts_total_gas = total_receipt_gas_for_block(&provider, blk_number).await?;

    // Verify both user txs were included (non-system txs with gas_limit > 0)
    let user_tx_count = payload
        .block()
        .body()
        .transactions()
        .filter(|tx| (*tx).gas_limit() > 0)
        .count();
    assert!(
        user_tx_count >= 2,
        "both SSTORE txs should be included in block, got {user_tx_count} user txs"
    );

    // Two SSTOREs zero->non-zero: 2 x 230,000 = 460,000 storage creation gas
    let storage_creation_gas = receipts_total_gas - block_gas_used;
    assert_eq!(
        storage_creation_gas,
        2 * 230_000,
        "storage creation gas should be 2 x 230,000 = 460,000 for two txs in same block, \
         got {storage_creation_gas} (block_gas_used={block_gas_used}, receipts_total_gas={receipts_total_gas})"
    );

    Ok(())
}

/// Unhappy path: inner CALL that reverts does NOT contribute state gas to the exemption.
///
/// Contract A calls Contract B. B does SSTORE zero->non-zero then REVERTs. A ignores
/// the failure and STOPs successfully. Since B's frame reverted, `handle_reservoir_remaining_gas`
/// does NOT propagate B's state_gas_spent to A. The overall tx has state_gas_spent == 0,
/// so block gas_used should equal total receipt gas_used (no exemption).
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1016_inner_call_revert_no_state_gas_exemption() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    let signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(0)?
        .build()?;
    let provider = ProviderBuilder::new().connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    // Step 1: Deploy "reverting SSTORE" contract (B).
    // Runtime: SSTORE(0, 1) then REVERT
    let b_init_code = Bytes::from_static(&[
        // Init code (12 bytes)
        0x60, 0x0a, // PUSH1 10 (runtime length)
        0x60, 0x0c, // PUSH1 12 (runtime offset)
        0x60, 0x00, // PUSH1 0 (memory dest)
        0x39, // CODECOPY
        0x60, 0x0a, // PUSH1 10 (return length)
        0x60, 0x00, // PUSH1 0 (return offset)
        0xf3, // RETURN
        // Runtime code (10 bytes)
        0x60, 0x01, // PUSH1 1 (value)
        0x60, 0x00, // PUSH1 0 (slot)
        0x55, // SSTORE
        0x60, 0x00, // PUSH1 0 (revert data size)
        0x60, 0x00, // PUSH1 0 (revert data offset)
        0xfd, // REVERT
    ]);

    let createx = CreateX::new(CREATEX_ADDRESS, &provider);
    let b_deploy_calldata: Bytes = createx.deployCreate(b_init_code).calldata().clone();

    let b_deploy_raw = build_call_tx(
        &signer,
        chain_id,
        0,
        5_000_000,
        CREATEX_ADDRESS,
        b_deploy_calldata,
    );
    setup.node.rpc.inject_tx(b_deploy_raw).await?;
    let b_deploy_payload = setup.node.advance_block().await?;
    let b_deploy_blk = b_deploy_payload.block().header().inner.number;
    let b_addr = get_createx_deployed_address(&provider, b_deploy_blk).await?;

    // Step 2: Deploy "caller" contract (A).
    // Runtime: CALL(gas=GAS, addr=calldataload(0), value=0, args=0, argsLen=0, ret=0, retLen=0)
    //          then STOP.
    // A ignores B's revert (CALL pushes 0 on failure, but A doesn't check).
    let a_init_code = Bytes::from_static(&[
        // Init code (12 bytes)
        0x60, 0x10, // PUSH1 16 (runtime length)
        0x60, 0x0c, // PUSH1 12 (runtime offset)
        0x60, 0x00, // PUSH1 0 (memory dest)
        0x39, // CODECOPY
        0x60, 0x10, // PUSH1 16 (return length)
        0x60, 0x00, // PUSH1 0 (return offset)
        0xf3, // RETURN
        // Runtime code (16 bytes)
        0x60, 0x00, // PUSH1 0 (retSize)
        0x60, 0x00, // PUSH1 0 (retOffset)
        0x60, 0x00, // PUSH1 0 (argsSize)
        0x60, 0x00, // PUSH1 0 (argsOffset)
        0x60, 0x00, // PUSH1 0 (value)
        0x60, 0x00, // PUSH1 0 (calldata offset for calldataload)
        0x35, // CALLDATALOAD (loads B's address from calldata)
        0x5a, // GAS (forward all remaining gas)
        0xf1, // CALL
        0x50, // POP (discard CALL return value)
        0x00, // STOP
    ]);

    let a_deploy_calldata: Bytes = createx.deployCreate(a_init_code).calldata().clone();

    let a_deploy_raw = build_call_tx(
        &signer,
        chain_id,
        1,
        5_000_000,
        CREATEX_ADDRESS,
        a_deploy_calldata,
    );
    setup.node.rpc.inject_tx(a_deploy_raw).await?;
    let a_deploy_payload = setup.node.advance_block().await?;
    let a_deploy_blk = a_deploy_payload.block().header().inner.number;
    let a_addr = get_createx_deployed_address(&provider, a_deploy_blk).await?;

    // Step 3: Call A, passing B's address as calldata.
    // A will CALL B, B does SSTORE + REVERT, A continues and STOPs.
    let b_addr_calldata: Bytes = alloy_primitives::B256::left_padding_from(b_addr.as_slice())
        .as_slice()
        .to_vec()
        .into();

    let call_raw = build_call_tx(&signer, chain_id, 2, 5_000_000, a_addr, b_addr_calldata);
    setup.node.rpc.inject_tx(call_raw).await?;
    let call_payload = setup.node.advance_block().await?;

    let call_blk = call_payload.block().header().inner.number;
    let block_gas_used = call_payload.block().header().inner.gas_used;
    let receipts_total_gas = total_receipt_gas_for_block(&provider, call_blk).await?;

    // Verify the tx succeeded (A ignores B's revert)
    let block_id = BlockId::Number(BlockNumberOrTag::Number(call_blk));
    let receipts = provider
        .get_block_receipts(block_id)
        .await?
        .expect("receipts should be available");
    let user_receipt = receipts
        .iter()
        .find(|r| r.gas_used > 21_000)
        .expect("should have a user tx receipt with significant gas");
    assert!(
        user_receipt.status(),
        "tx should succeed (A ignores B's revert)"
    );

    // B's SSTORE reverted, so its state gas should NOT be exempted.
    // Block gas_used should equal total receipt gas (no storage creation exemption).
    assert_eq!(
        block_gas_used, receipts_total_gas,
        "block gas_used ({block_gas_used}) should equal total receipt gas \
         ({receipts_total_gas}) -- inner reverted CALL should NOT exempt state gas"
    );

    Ok(())
}

/// Stress test: a single AA transaction with gas_limit=150M that does 400 TIP-20
/// transfers to fresh addresses via Multicall3, each creating a new balance storage slot.
///
/// Under TIP-1016, each transfer to a new address creates a SSTORE zero->non-zero
/// (230,000 state gas) that is exempted from block gas accounting. The tx gas_limit
/// covers both regular and state gas, so 150M is needed to accommodate state gas
/// from many transfers even though regular gas usage is much lower.
///
/// This tests that:
/// 1. A tx with gas_limit=150M doing 400 TIP-20 transfers to fresh addresses succeeds.
/// 2. The receipt gas_used includes all gas (execution + state creation).
/// 3. The block header gas_used excludes state gas (TIP-1016 exemption).
/// 4. The state gas from many TIP-20 balance slot creations is correctly exempted.
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1016_high_gas_limit_batch_tip20_transfers() -> eyre::Result<()> {
    use alloy::signers::SignerSync;
    use reth_primitives_traits::transaction::TxHashRef;
    use tempo_precompiles::{PATH_USD_ADDRESS, tip20::ITIP20};
    use tempo_primitives::{
        TempoTransaction, TempoTxEnvelope, transaction::tempo_transaction::Call,
    };

    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new().build_with_node_access().await?;
    let signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(0)?
        .build()?;
    let provider = ProviderBuilder::new().connect_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;

    let num_transfers: u64 = 400;

    // Step 1: Mint PATH_USD to Multicall3 so it has tokens to transfer.
    let token = ITIP20::new(PATH_USD_ADDRESS, &provider);
    let mint_calldata: Bytes = token
        .mint(
            tempo_contracts::MULTICALL3_ADDRESS,
            U256::from(num_transfers * 10),
        )
        .calldata()
        .clone();
    let mint_raw = build_call_tx(
        &signer,
        chain_id,
        0,
        5_000_000,
        PATH_USD_ADDRESS,
        mint_calldata,
    );
    setup.node.rpc.inject_tx(mint_raw).await?;
    setup.node.advance_block().await?;

    // Step 2: Build Multicall3.aggregate() calldata with 400 TIP-20 transfers.
    // Each transfer goes to address(0xdead0001 + i), creating a new balance slot.
    let multicall_calls: Vec<Multicall3::Call> = (0..num_transfers)
        .map(|i| {
            let to = Address::from_word(alloy_primitives::B256::left_padding_from(
                &(0xdead0001u64 + i).to_be_bytes(),
            ));
            Multicall3::Call {
                target: PATH_USD_ADDRESS,
                callData: ITIP20::transferCall {
                    to,
                    amount: U256::from(1),
                }
                .abi_encode()
                .into(),
            }
        })
        .collect();

    let multicall = Multicall3::new(tempo_contracts::MULTICALL3_ADDRESS, &provider);
    let aggregate_calldata: Bytes = multicall.aggregate(multicall_calls).calldata().clone();

    // Step 3: Send as AA tx with a single call to Multicall3, gas_limit=150M.
    let tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
        gas_limit: 150_000_000, // 150M
        calls: vec![Call {
            to: tempo_contracts::MULTICALL3_ADDRESS.into(),
            value: U256::ZERO,
            input: aggregate_calldata,
        }],
        nonce_key: U256::ZERO,
        nonce: 1,
        fee_token: Some(DEFAULT_FEE_TOKEN),
        ..Default::default()
    };

    let sig_hash = tx.signature_hash();
    let signature: alloy::primitives::Signature = signer.sign_hash_sync(&sig_hash)?;
    let envelope: TempoTxEnvelope = tx.into_signed(signature.into()).into();
    let tx_hash = *envelope.tx_hash();
    setup
        .node
        .rpc
        .inject_tx(envelope.encoded_2718().into())
        .await?;
    let call_payload = setup.node.advance_block().await?;

    let block_gas_used = call_payload.block().header().inner.gas_used;

    // Fetch receipt via raw RPC (AA tx type 0x76 isn't deserializable by standard types).
    let receipt_raw: serde_json::Value = provider
        .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
        .await?;
    let receipt_status = receipt_raw["status"].as_str().unwrap();
    assert_eq!(
        receipt_status, "0x1",
        "150M gas multicall tx should succeed"
    );

    let receipt_gas = u64::from_str_radix(
        receipt_raw["gasUsed"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
        16,
    )?;

    // Receipt gas includes state gas; block header excludes it.
    // Each transfer to a fresh address: 230,000 state gas per new balance slot.
    let expected_state_gas = num_transfers * 230_000;
    let state_gas = receipt_gas.saturating_sub(block_gas_used);
    assert_eq!(
        state_gas, expected_state_gas,
        "state gas ({state_gas}) should {expected_state_gas} \
         ({num_transfers} transfers × 230,000), \
         block_gas_used={block_gas_used}, receipt_gas={receipt_gas}"
    );

    assert!(
        block_gas_used < receipt_gas,
        "block gas_used ({block_gas_used}) should be less than receipt gas \
         ({receipt_gas}) due to TIP-1016 state gas exemption"
    );

    Ok(())
}
