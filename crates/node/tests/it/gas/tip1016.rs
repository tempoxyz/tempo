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
//! 5. Reverted txs roll back their state gas, so header and receipts agree
//! 6. Multiple storage-creating operations in a single tx are additive
//! 7. Multiple storage-creating txs in a single block correctly accumulate exemptions
//! 8. Reverted inner CALLs do NOT contribute state gas to the parent frame's exemption
//!
//! Every test follows the same shape: optional setup (deploy a contract, mint TIP-20),
//! then send the tx(s) under test into one block via [`Tip1016Node::run_block`] and
//! assert on the returned [`BlockGas`] (status, receipt gas, block gas, state gas).

use alloy::{
    primitives::{Address, B256, Bytes, TxKind, U256, keccak256},
    providers::{DynProvider, Provider, ProviderBuilder},
    signers::{SignerSync, local::PrivateKeySigner},
    sol_types::SolCall,
};
use alloy_eips::Encodable2718;
use reth_node_api::BuiltPayload;
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_contracts::{
    CREATEX_ADDRESS, CreateX, MULTICALL3_ADDRESS, Multicall3, precompiles::DEFAULT_FEE_TOKEN,
};
use tempo_precompiles::{PATH_USD_ADDRESS, tip20::ITIP20};
use tempo_primitives::{TempoTransaction, TempoTxEnvelope, transaction::tempo_transaction::Call};

use super::helpers::{build_call_tx, build_create_tx, test_signer};
use crate::utils::{SingleNodeSetup, TestNodeBuilder};

/// Gas limit used for every non-batch test transaction.
const TX_GAS_LIMIT: u64 = 5_000_000;

/// SSTORE zero->non-zero state gas (STORAGE_CREDIT_VALUE / sstore_set_state_gas).
const SSTORE_SET_STATE_GAS: u64 = 245_000;

// ---------------------------------------------------------------------------
// Runtime bytecode used by the tests (deployed via `Tip1016Node::deploy_runtime`)
// ---------------------------------------------------------------------------

/// Runtime: `SSTORE(calldataload(0), 1); STOP` -- writes 1 to the slot given in calldata.
const RT_SSTORE_SLOT_FROM_CALLDATA: &[u8] = &[
    0x60, 0x01, // PUSH1 1 (value)
    0x60, 0x00, // PUSH1 0 (calldata offset)
    0x35, // CALLDATALOAD (slot)
    0x55, // SSTORE
    0x00, // STOP
];

/// Runtime: `SSTORE(calldataload(0), calldataload(32)); STOP` -- calldata is (slot, value).
const RT_SSTORE_SLOT_AND_VALUE_FROM_CALLDATA: &[u8] = &[
    0x60, 0x20, // PUSH1 32 (calldata offset)
    0x35, // CALLDATALOAD (value)
    0x60, 0x00, // PUSH1 0 (calldata offset)
    0x35, // CALLDATALOAD (slot)
    0x55, // SSTORE
    0x00, // STOP
];

/// Runtime: `SSTORE(0, 1); REVERT(0, 0)` -- creates a slot, then reverts.
const RT_SSTORE_THEN_REVERT: &[u8] = &[
    0x60, 0x01, // PUSH1 1 (value)
    0x60, 0x00, // PUSH1 0 (slot)
    0x55, // SSTORE (zero -> non-zero)
    0x60, 0x00, // PUSH1 0 (revert data size)
    0x60, 0x00, // PUSH1 0 (revert data offset)
    0xfd, // REVERT
];

/// Runtime: `SSTORE(0, 1); SSTORE(1, 1); SSTORE(2, 1); STOP`.
const RT_THREE_SSTORES: &[u8] = &[
    0x60, 0x01, 0x60, 0x00, 0x55, // SSTORE(0, 1)
    0x60, 0x01, 0x60, 0x01, 0x55, // SSTORE(1, 1)
    0x60, 0x01, 0x60, 0x02, 0x55, // SSTORE(2, 1)
    0x00, // STOP
];

/// Runtime: `CALL(GAS, calldataload(0), 0, 0, 0, 0, 0); POP; STOP` -- calls the address
/// given in calldata, forwarding all gas, and ignores the call's success flag.
const RT_CALL_ADDR_FROM_CALLDATA: &[u8] = &[
    0x60, 0x00, // PUSH1 0 (retSize)
    0x60, 0x00, // PUSH1 0 (retOffset)
    0x60, 0x00, // PUSH1 0 (argsSize)
    0x60, 0x00, // PUSH1 0 (argsOffset)
    0x60, 0x00, // PUSH1 0 (value)
    0x60, 0x00, // PUSH1 0 (calldata offset)
    0x35, // CALLDATALOAD (target address)
    0x5a, // GAS (forward all remaining gas)
    0xf1, // CALL
    0x50, // POP (discard CALL success flag)
    0x00, // STOP
];

/// Initcode: `MSTORE(0, 42); RETURN(0, 32)` -- deploys a 32-byte runtime.
const INITCODE_RETURN_42_WORD: &[u8] = &[
    0x60, 0x2a, // PUSH1 42
    0x60, 0x00, // PUSH1 0
    0x52, // MSTORE
    0x60, 0x20, // PUSH1 32
    0x60, 0x00, // PUSH1 0
    0xf3, // RETURN
];

/// Initcode: `REVERT(0, 0)` -- deploys nothing.
const INITCODE_REVERT: &[u8] = &[0x60, 0x00, 0x60, 0x00, 0xfd];

/// Wraps runtime bytecode in minimal init code that CODECOPYs it into memory and returns it.
fn initcode_for_runtime(runtime: &[u8]) -> Bytes {
    let len = u8::try_from(runtime.len()).expect("runtime must fit in a PUSH1");
    let mut code = vec![
        0x60, len, // PUSH1 <len> (runtime length)
        0x60, 0x0c, // PUSH1 12 (runtime offset in initcode)
        0x60, 0x00, // PUSH1 0 (memory dest)
        0x39, // CODECOPY
        0x60, len, // PUSH1 <len> (return length)
        0x60, 0x00, // PUSH1 0 (return offset)
        0xf3, // RETURN
    ];
    code.extend_from_slice(runtime);
    code.into()
}

/// ABI-style calldata: each `u64` becomes one left-padded 32-byte word.
fn words(values: &[u64]) -> Bytes {
    values
        .iter()
        .flat_map(|v| B256::left_padding_from(&v.to_be_bytes()).0)
        .collect::<Vec<u8>>()
        .into()
}

/// A single left-padded 32-byte word holding an address.
fn address_word(address: Address) -> Bytes {
    B256::left_padding_from(address.as_slice()).as_slice().to_vec().into()
}

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

/// Gas outcome of one injected transaction.
struct TxGas {
    gas_used: u64,
    success: bool,
}

/// Gas accounting of a mined block: header gas, total receipt gas, and the
/// injected txs' individual receipts. `receipts_total - block_gas_used` is the
/// TIP-1016 state gas the block exempted.
struct BlockGas {
    block_gas_used: u64,
    receipts_total_gas: u64,
    txs: Vec<TxGas>,
}

impl BlockGas {
    fn state_gas(&self) -> u64 {
        self.receipts_total_gas
            .checked_sub(self.block_gas_used)
            .expect("total receipt gas must be >= block header gas_used")
    }

    #[track_caller]
    fn assert_success(&self) -> &Self {
        for (i, tx) in self.txs.iter().enumerate() {
            assert!(tx.success, "tx {i} should have succeeded");
        }
        self
    }

    #[track_caller]
    fn assert_reverted(&self) -> &Self {
        for (i, tx) in self.txs.iter().enumerate() {
            assert!(!tx.success, "tx {i} should have reverted");
        }
        self
    }

    /// Asserts the state gas exempted from the block header (receipts total minus header).
    #[track_caller]
    fn assert_state_gas(&self, expected: u64) -> &Self {
        assert_eq!(
            self.state_gas(),
            expected,
            "state gas exemption mismatch (block_gas_used={}, receipts_total_gas={})",
            self.block_gas_used,
            self.receipts_total_gas,
        );
        self
    }

    /// Asserts the block header gas_used exactly.
    #[track_caller]
    fn assert_block_gas(&self, expected: u64) -> &Self {
        assert_eq!(
            self.block_gas_used, expected,
            "block header gas_used mismatch (receipts_total_gas={})",
            self.receipts_total_gas,
        );
        self
    }

    /// Asserts the single injected tx's receipt gas_used exactly.
    #[track_caller]
    fn assert_receipt_gas(&self, expected: u64) -> &Self {
        assert_eq!(self.txs.len(), 1, "expected exactly one injected tx");
        assert_eq!(
            self.txs[0].gas_used, expected,
            "receipt gas_used mismatch (block_gas_used={})",
            self.block_gas_used,
        );
        self
    }
}

/// One test node plus a funded signer, with helpers for the shared TIP-1016
/// test pattern: setup steps (deploy / mint), then measure one block.
struct Tip1016Node {
    setup: SingleNodeSetup,
    provider: DynProvider,
    signer: PrivateKeySigner,
    chain_id: u64,
    nonce: u64,
}

impl Tip1016Node {
    async fn new() -> eyre::Result<Self> {
        reth_tracing::init_test_tracing();
        let setup = TestNodeBuilder::new().build_with_node_access().await?;
        let signer = test_signer(0)?;
        let provider = ProviderBuilder::new()
            .connect_http(setup.node.rpc_url())
            .erased();
        let chain_id = provider.get_chain_id().await?;
        Ok(Self {
            setup,
            provider,
            signer,
            chain_id,
            nonce: 0,
        })
    }

    fn address(&self) -> Address {
        self.signer.address()
    }

    fn next_nonce(&mut self) -> u64 {
        let nonce = self.nonce;
        self.nonce += 1;
        nonce
    }

    /// Builds a signed EIP-1559 CALL tx from the harness signer.
    fn call_tx(&mut self, to: Address, input: Bytes) -> Bytes {
        let nonce = self.next_nonce();
        build_call_tx(&self.signer, self.chain_id, nonce, TX_GAS_LIMIT, to, input)
    }

    /// Builds a signed EIP-1559 CREATE tx from the harness signer.
    fn create_tx(&mut self, initcode: Bytes) -> Bytes {
        let nonce = self.next_nonce();
        build_create_tx(&self.signer, self.chain_id, nonce, TX_GAS_LIMIT, initcode)
    }

    /// Builds a signed AA batch tx (protocol nonce, default fee token).
    fn batch_tx(&mut self, gas_limit: u64, calls: Vec<Call>) -> eyre::Result<Bytes> {
        let tx = TempoTransaction {
            chain_id: self.chain_id,
            max_priority_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
            max_fee_per_gas: TEMPO_T1_BASE_FEE as u128,
            gas_limit,
            calls,
            nonce_key: U256::ZERO,
            nonce: self.next_nonce(),
            fee_token: Some(DEFAULT_FEE_TOKEN),
            ..Default::default()
        };
        let signature = self.signer.sign_hash_sync(&tx.signature_hash())?;
        let envelope: TempoTxEnvelope = tx.into_signed(signature.into()).into();
        Ok(envelope.encoded_2718().into())
    }

    /// Injects the given raw txs, mines one block, and returns its gas accounting.
    ///
    /// Receipts are fetched via raw JSON-RPC (AA tx type 0x76 isn't deserializable
    /// by standard alloy types) and each injected tx is verified to have landed in
    /// the mined block.
    async fn run_block(&mut self, txs: Vec<Bytes>) -> eyre::Result<BlockGas> {
        eyre::ensure!(!txs.is_empty(), "run_block needs at least one tx");
        let mut hashes = Vec::with_capacity(txs.len());
        for tx in txs {
            hashes.push(keccak256(&tx));
            self.setup.node.rpc.inject_tx(tx).await?;
        }
        let payload = self.setup.node.advance_block().await?;
        let header = &payload.block().header().inner;
        let (block_number, block_gas_used) = (header.number, header.gas_used);

        let mut tx_gas = Vec::with_capacity(hashes.len());
        for hash in hashes {
            let receipt = self.raw_receipt(hash).await?;
            let receipt_block = hex_u64(&receipt, "blockNumber")?;
            eyre::ensure!(
                receipt_block == block_number,
                "tx {hash} landed in block {receipt_block}, expected {block_number}"
            );
            tx_gas.push(TxGas {
                gas_used: hex_u64(&receipt, "gasUsed")?,
                success: receipt["status"] == "0x1",
            });
        }

        Ok(BlockGas {
            block_gas_used,
            receipts_total_gas: self.block_receipts_total(block_number).await?,
            txs: tx_gas,
        })
    }

    /// Runs a setup tx in its own block and asserts it succeeded.
    async fn setup_call(&mut self, to: Address, input: Bytes) -> eyre::Result<()> {
        let tx = self.call_tx(to, input);
        self.run_block(vec![tx]).await?.assert_success();
        Ok(())
    }

    /// Mints PATH_USD to `to` in its own block. Also used with the harness signer
    /// as recipient to establish the sender account, keeping the nonce-0
    /// account-creation cost (25,000 regular + 225,000 state gas) out of later txs.
    async fn mint(&mut self, to: Address, amount: u64) -> eyre::Result<()> {
        let calldata = ITIP20::mintCall {
            to,
            amount: U256::from(amount),
        }
        .abi_encode()
        .into();
        self.setup_call(PATH_USD_ADDRESS, calldata).await
    }

    /// Deploys runtime bytecode via CreateX in its own block; returns the address.
    async fn deploy_runtime(&mut self, runtime: &[u8]) -> eyre::Result<Address> {
        let deploy_calldata: Bytes = CreateX::deployCreateCall {
            initCode: initcode_for_runtime(runtime),
        }
        .abi_encode()
        .into();
        let tx = self.call_tx(CREATEX_ADDRESS, deploy_calldata);
        let hash = keccak256(&tx);
        self.run_block(vec![tx]).await?.assert_success();

        // Deployed address is topic 1 of CreateX's ContractCreation event.
        let receipt = self.raw_receipt(hash).await?;
        let topic = receipt["logs"][0]["topics"][1]
            .as_str()
            .ok_or_else(|| eyre::eyre!("deploy receipt missing ContractCreation topic"))?;
        Ok(Address::from_word(topic.parse()?))
    }

    /// Fetches a receipt as raw JSON, polling until the RPC catches up.
    async fn raw_receipt(&self, tx_hash: B256) -> eyre::Result<serde_json::Value> {
        for _ in 0..50 {
            let receipt: Option<serde_json::Value> = self
                .provider
                .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
                .await?;
            if let Some(receipt) = receipt {
                return Ok(receipt);
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        eyre::bail!("timed out waiting for receipt {tx_hash}");
    }

    /// Returns the total gas_used over all receipts in a block (including system txs).
    async fn block_receipts_total(&self, block_number: u64) -> eyre::Result<u64> {
        for _ in 0..50 {
            let receipts: Option<Vec<serde_json::Value>> = self
                .provider
                .raw_request("eth_getBlockReceipts".into(), [format!("0x{block_number:x}")])
                .await?;
            if let Some(receipts) = receipts {
                return receipts.iter().map(|r| hex_u64(r, "gasUsed")).sum();
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        eyre::bail!("timed out waiting for receipts at block {block_number}");
    }
}

fn hex_u64(receipt: &serde_json::Value, field: &str) -> eyre::Result<u64> {
    let value = receipt[field]
        .as_str()
        .ok_or_else(|| eyre::eyre!("receipt missing {field} field"))?;
    Ok(u64::from_str_radix(value.trim_start_matches("0x"), 16)?)
}

// ---------------------------------------------------------------------------
// Happy path tests
// ---------------------------------------------------------------------------

/// Happy path: deploying a contract via CreateX creates new storage (account creation +
/// code storage), so block header gas_used should be less than the sum of receipt gas_used.
///
/// The difference is the storage creation gas that TIP-1016 exempts from protocol limits.
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1016_contract_deployment_exempts_storage_gas() -> eyre::Result<()> {
    let mut node = Tip1016Node::new().await?;

    let deploy_calldata: Bytes = CreateX::deployCreateCall {
        initCode: Bytes::from_static(INITCODE_RETURN_42_WORD),
    }
    .abi_encode()
    .into();
    let tx = node.call_tx(CREATEX_ADDRESS, deploy_calldata);
    let gas = node.run_block(vec![tx]).await?;

    // TIP-1016 state gas (permanent storage burden), exempt from the block header:
    //   468,000  CREATE contract metadata (create_state_gas)
    //    73,600  code deposit: 32 bytes * 2,300 (code_deposit_state_gas)
    //   225,000  sender account creation, tx nonce == 0 (new_account_state_gas intrinsic)
    const EXPECTED_STATE_GAS: u64 = 468_000 + 73_600 + 225_000; // 766,600

    // Execution (regular) gas, the only component counted in the block header:
    // 21,000 intrinsic + calldata + CreateX dispatch + 32,000 CREATE regular
    // + 32 * 200 code-deposit regular + 25,000 nonce-0 account-creation regular.
    const EXPECTED_EXECUTION_GAS: u64 = 87_023;

    // Block header gas_used reflects only execution gas: state gas is exempted
    // from protocol limits but still charged to the user via the receipt.
    // There is no floor gas or refund, so state gas is a simple subtraction.
    gas.assert_success()
        .assert_block_gas(EXPECTED_EXECUTION_GAS)
        .assert_state_gas(EXPECTED_STATE_GAS);
    Ok(())
}

/// Happy path: a SSTORE (zero -> non-zero) via a CALL to an existing contract
/// triggers the storage creation gas exemption.
///
/// Under the TIP-1060 credit model the creditable portion is STORAGE_CREDIT_VALUE
/// (245,000), charged as state gas by the storage-credit hook (sstore_set_state_gas).
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1016_sstore_zero_to_nonzero_exempts_storage_gas() -> eyre::Result<()> {
    let mut node = Tip1016Node::new().await?;
    let contract = node.deploy_runtime(RT_SSTORE_SLOT_FROM_CALLDATA).await?;

    let tx = node.call_tx(contract, words(&[42]));
    node.run_block(vec![tx])
        .await?
        .assert_success()
        .assert_state_gas(SSTORE_SET_STATE_GAS);
    Ok(())
}

/// Happy path: a SSTORE that modifies an existing slot (non-zero -> non-zero) should
/// NOT have any storage creation gas component, so block gas_used and total receipt gas
/// should be equal.
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1016_sstore_nonzero_to_nonzero_no_exemption() -> eyre::Result<()> {
    let mut node = Tip1016Node::new().await?;
    let contract = node
        .deploy_runtime(RT_SSTORE_SLOT_AND_VALUE_FROM_CALLDATA)
        .await?;

    // Warm-up: SSTORE zero -> non-zero at slot 0.
    node.setup_call(contract, words(&[0, 1])).await?;

    // Measured: SSTORE non-zero -> non-zero at slot 0 (value 1 -> 2).
    let tx = node.call_tx(contract, words(&[0, 2]));
    node.run_block(vec![tx])
        .await?
        .assert_success()
        .assert_state_gas(0);
    Ok(())
}

/// Happy path: a TIP-20 transfer to an existing account (no new storage slots created)
/// should have identical block gas_used and total receipt gas.
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1016_tip20_transfer_existing_no_storage_creation() -> eyre::Result<()> {
    let mut node = Tip1016Node::new().await?;
    let sender = node.address();
    let receiver = test_signer(1)?.address();

    // Mint to both so the receiver's balance slot already exists.
    node.mint(sender, 1_000_000).await?;
    node.mint(receiver, 1_000_000).await?;

    let transfer_calldata = ITIP20::transferCall {
        to: receiver,
        amount: U256::from(100),
    }
    .abi_encode()
    .into();
    let tx = node.call_tx(PATH_USD_ADDRESS, transfer_calldata);
    node.run_block(vec![tx])
        .await?
        .assert_success()
        .assert_state_gas(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Unhappy path / corner case tests
// ---------------------------------------------------------------------------

/// Unhappy path: a transaction that does SSTORE zero->non-zero then explicitly REVERTs.
///
/// When a tx reverts, state changes are rolled back so state_gas_spent is 0.
/// Block header gas_used should equal receipt gas_used (no state gas exemption).
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1016_reverted_sstore_still_exempts_state_gas() -> eyre::Result<()> {
    let mut node = Tip1016Node::new().await?;
    let contract = node.deploy_runtime(RT_SSTORE_THEN_REVERT).await?;

    let tx = node.call_tx(contract, Bytes::new());
    node.run_block(vec![tx])
        .await?
        .assert_reverted()
        .assert_state_gas(0);
    Ok(())
}

/// Corner case: multiple SSTORE zero->non-zero in a single transaction.
///
/// Storage creation gas should be additive: N slots x 245,000 per slot.
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1016_multiple_sstore_zero_to_nonzero_additive() -> eyre::Result<()> {
    let mut node = Tip1016Node::new().await?;
    let contract = node.deploy_runtime(RT_THREE_SSTORES).await?;

    let tx = node.call_tx(contract, Bytes::new());
    node.run_block(vec![tx])
        .await?
        .assert_success()
        .assert_state_gas(3 * SSTORE_SET_STATE_GAS);
    Ok(())
}

/// Corner case: two storage-creating transactions in the same block.
///
/// Each tx does SSTORE zero->non-zero. The block's cumulative storage creation gas
/// should be the sum of both. This tests that the inner executor's
/// `block_regular_gas_used` correctly excludes state gas across multiple transactions.
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1016_two_storage_txs_same_block() -> eyre::Result<()> {
    let mut node = Tip1016Node::new().await?;
    let contract = node.deploy_runtime(RT_SSTORE_SLOT_FROM_CALLDATA).await?;

    let tx1 = node.call_tx(contract, words(&[100]));
    let tx2 = node.call_tx(contract, words(&[200]));
    node.run_block(vec![tx1, tx2])
        .await?
        .assert_success()
        .assert_state_gas(2 * SSTORE_SET_STATE_GAS);
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
    let mut node = Tip1016Node::new().await?;
    let reverting_sstore = node.deploy_runtime(RT_SSTORE_THEN_REVERT).await?;
    let caller = node.deploy_runtime(RT_CALL_ADDR_FROM_CALLDATA).await?;

    let tx = node.call_tx(caller, address_word(reverting_sstore));
    node.run_block(vec![tx])
        .await?
        .assert_success() // caller ignores the inner revert
        .assert_state_gas(0);
    Ok(())
}

/// Unhappy path (TIP-1016 / EIP-8037): a top-level CREATE transaction whose
/// initcode reverts must not consume `create_state_gas`.
///
/// Tempo charges the CREATE state gas at the intrinsic phase (EIP-2780 stays
/// disabled) and marks the first frame as charged, so `last_frame_result`
/// refunds it via `FrameResult::refundable_state_gas` when nothing deploys.
/// The receipt therefore pays execution gas only, and -- since the revert
/// rolled back all state -- the block header matches the receipts exactly.
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1016_reverting_create_tx_refunds_create_state_gas() -> eyre::Result<()> {
    let mut node = Tip1016Node::new().await?;

    // Establish the sender account first so the nonce-0 account-creation cost
    // (25,000 regular + 225,000 state gas) stays out of the CREATE tx below.
    let sender = node.address();
    node.mint(sender, 1_000_000).await?;

    let tx = node.create_tx(Bytes::from_static(INITCODE_REVERT));

    // Execution gas only -- the 468,000 create_state_gas charged at the
    // intrinsic phase was refunded because the initcode deployed nothing:
    //   21,000 base intrinsic
    //   32,000 CREATE regular
    //       56 calldata (3 non-zero bytes * 16 + 2 zero bytes * 4)
    //        2 initcode word cost (1 word)
    //        6 initcode execution (PUSH1 + PUSH1 + REVERT)
    const EXPECTED_GAS: u64 = 21_000 + 32_000 + 56 + 2 + 6;

    node.run_block(vec![tx])
        .await?
        .assert_reverted()
        .assert_receipt_gas(EXPECTED_GAS)
        .assert_state_gas(0);
    Ok(())
}

/// Unhappy path (TIP-1016 / EIP-8037): an AA batch whose first call is a
/// reverting CREATE must not consume `create_state_gas` either.
///
/// The batch executes each call through the same `execute_single_call_with`
/// path as a single-call tx, so the per-call `last_frame_result` refunds the
/// intrinsic CREATE state gas charge when the initcode reverts. The second
/// call never runs: the batch reverts atomically on the first failure.
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1016_batch_reverting_create_refunds_create_state_gas() -> eyre::Result<()> {
    let mut node = Tip1016Node::new().await?;

    // Establish the sender account first so the nonce-0 account-creation cost
    // stays out of the batch tx below.
    let sender = node.address();
    node.mint(sender, 1_000_000).await?;

    // Batch: reverting CREATE first (the only position a CREATE is allowed
    // in), then a TIP-20 transfer that never runs because the batch reverts
    // atomically on the CREATE failure.
    let tx = node.batch_tx(
        TX_GAS_LIMIT,
        vec![
            Call {
                to: TxKind::Create,
                value: U256::ZERO,
                input: Bytes::from_static(INITCODE_REVERT),
            },
            Call {
                to: PATH_USD_ADDRESS.into(),
                value: U256::ZERO,
                input: ITIP20::transferCall {
                    to: Address::repeat_byte(0x42),
                    amount: U256::from(1),
                }
                .abi_encode()
                .into(),
            },
        ],
    )?;

    // The intrinsic create_state_gas charge (468,000) must have been refunded:
    // the receipt pays the AA intrinsic cost plus the CREATE execution only.
    //   21,000 base intrinsic
    //   32,000 CREATE regular
    //       56 first-call calldata (initcode: 3 non-zero bytes * 16 + 2 zero bytes * 4)
    //        2 initcode word cost (1 word)
    //        6 initcode execution (PUSH1 + PUSH1 + REVERT)
    //    3,172 AA overhead (second call's calldata + AA intrinsic costs)
    const EXPECTED_GAS: u64 = 56_236;

    node.run_block(vec![tx])
        .await?
        .assert_reverted()
        .assert_receipt_gas(EXPECTED_GAS)
        .assert_state_gas(0);
    Ok(())
}

/// Stress test: a single AA transaction with gas_limit=150M that does 400 TIP-20
/// transfers to fresh addresses via Multicall3, each creating a new balance storage slot.
///
/// Under TIP-1016, each transfer to a new address creates a SSTORE zero->non-zero
/// (245,000 state gas) that is exempted from block gas accounting. The tx gas_limit
/// covers both regular and state gas, so 150M is needed to accommodate state gas
/// from many transfers even though regular gas usage is much lower.
#[tokio::test(flavor = "multi_thread")]
async fn test_tip1016_high_gas_limit_batch_tip20_transfers() -> eyre::Result<()> {
    let mut node = Tip1016Node::new().await?;

    let num_transfers: u64 = 400;

    // Mint PATH_USD to Multicall3 so it has tokens to transfer.
    node.mint(MULTICALL3_ADDRESS, num_transfers * 10).await?;

    // Multicall3.aggregate() with 400 TIP-20 transfers, each to a fresh
    // address(0xdead0001 + i), creating a new balance slot.
    let multicall_calls: Vec<Multicall3::Call> = (0..num_transfers)
        .map(|i| Multicall3::Call {
            target: PATH_USD_ADDRESS,
            callData: ITIP20::transferCall {
                to: Address::from_word(B256::left_padding_from(&(0xdead0001u64 + i).to_be_bytes())),
                amount: U256::from(1),
            }
            .abi_encode()
            .into(),
        })
        .collect();
    let aggregate_calldata: Bytes = Multicall3::aggregateCall {
        calls: multicall_calls,
    }
    .abi_encode()
    .into();

    let tx = node.batch_tx(
        150_000_000,
        vec![Call {
            to: MULTICALL3_ADDRESS.into(),
            value: U256::ZERO,
            input: aggregate_calldata,
        }],
    )?;

    node.run_block(vec![tx])
        .await?
        .assert_success()
        .assert_state_gas(num_transfers * SSTORE_SET_STATE_GAS);
    Ok(())
}
