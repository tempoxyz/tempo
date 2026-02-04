//! Execution engine for test vectors.
//!
//! Wraps TempoBlockExecutor to execute transactions from test vectors.

use crate::database::VectorDatabase;
use crate::vector::{BlockContext, TestVector, Transaction};
use alloy_consensus::{Signed, TxEip1559, TxEip2930, TxLegacy};
use alloy_evm::eth::EthBlockExecutionCtx;
use alloy_evm::{EvmEnv, FromRecoveredTx};
use alloy_primitives::{Address, B256, Bytes, Signature, TxKind, U256};
use reth_chainspec::EthChainSpec;
use reth_revm::State;
use reth_revm::context::BlockEnv;
use revm::ExecuteEvm;
use revm::context_interface::result::ExecutionResult;
use revm::{Context, MainContext};
use std::collections::HashMap;
use std::sync::Arc;
use tempo_chainspec::TempoChainSpec;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_chainspec::spec::MODERATO;
use tempo_evm::{TempoBlockEnv, TempoBlockExecutionCtx};
use tempo_primitives::TempoTxEnvelope;
use tempo_primitives::TempoTxType;
use tempo_primitives::transaction::tt_signed::AASigned;
use tempo_primitives::transaction::{PrimitiveSignature, TempoSignature, TempoTransaction};
use tempo_revm::TempoEvm;
use tempo_revm::TempoTxEnv;

/// Result of executing a single transaction
#[derive(Debug, Clone)]
pub struct TxExecutionResult {
    /// Whether the transaction succeeded
    pub success: bool,
    /// Gas used by this transaction
    pub gas_used: u64,
    /// Cumulative gas used up to and including this transaction
    pub cumulative_gas_used: u64,
    /// Return data (output bytes)
    pub return_data: Bytes,
    /// Logs emitted
    pub logs: Vec<Log>,
    /// Revert reason if failed
    pub revert_reason: Option<String>,
}

/// A log emitted during execution
#[derive(Debug, Clone)]
pub struct Log {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
}

impl From<alloy_primitives::Log> for Log {
    fn from(log: alloy_primitives::Log) -> Self {
        Self {
            address: log.address,
            topics: log.topics().to_vec(),
            data: log.data.data,
        }
    }
}

/// Result of executing all transactions in a vector
#[derive(Debug)]
pub struct ExecutionResult_ {
    /// Per-transaction results
    pub tx_results: Vec<TxExecutionResult>,
    /// Total gas used by all transactions
    pub total_gas_used: u64,
}

/// Decode revert reason from EVM output bytes.
/// Handles Error(string) selector 0x08c379a0 and Panic(uint256) selector 0x4e487b71.
fn decode_revert_reason(output: &Bytes) -> Option<String> {
    if output.len() < 4 {
        return None;
    }

    let selector = &output[..4];

    // Error(string) selector
    if selector == [0x08, 0xc3, 0x79, 0xa0] && output.len() >= 68 {
        // ABI decode: skip selector (4) + offset (32) + length (32), read string
        let len = u64::from_be_bytes(output[36..44].try_into().ok()?) as usize;
        if output.len() >= 68 + len {
            return String::from_utf8(output[68..68 + len].to_vec()).ok();
        }
    }

    // Panic(uint256) selector
    if selector == [0x4e, 0x48, 0x7b, 0x71] && output.len() >= 36 {
        let code = U256::from_be_slice(&output[4..36]);
        return Some(format!("Panic({code})"));
    }

    None
}

/// Executor for test vectors
pub struct VectorExecutor {
    chainspec: Arc<TempoChainSpec>,
}

impl VectorExecutor {
    /// Create a new executor with the given chain spec
    pub fn new(chainspec: Arc<TempoChainSpec>) -> Self {
        Self { chainspec }
    }

    /// Create an executor with the default test chain spec (Moderato)
    pub fn with_test_chainspec() -> Self {
        let chainspec = Arc::new(TempoChainSpec::from_genesis(MODERATO.genesis().clone()));
        Self::new(chainspec)
    }

    /// Execute a test vector and return results
    pub fn execute(
        &self,
        vector: &TestVector,
        db: &mut VectorDatabase,
    ) -> eyre::Result<ExecutionResult_> {
        // 1. Build State wrapper around the CacheDB
        let mut state = State::builder()
            .with_database(&mut db.db)
            .with_bundle_update()
            .build();

        // 2. Build TempoBlockExecutionCtx
        let eth_ctx = EthBlockExecutionCtx {
            parent_hash: B256::ZERO,
            parent_beacon_block_root: Some(B256::ZERO),
            ommers: &[],
            withdrawals: None,
            extra_data: Bytes::new(),
            tx_count_hint: Some(vector.transactions.len()),
        };

        let _ctx = TempoBlockExecutionCtx {
            inner: eth_ctx,
            general_gas_limit: vector.block.gas_limit,
            shared_gas_limit: 0, // No subblocks for precompile tests
            validator_set: None, // Skip subblock validation
            subblock_fee_recipients: HashMap::new(),
        };

        let mut tx_results = Vec::new();
        let mut cumulative_gas_used = 0u64;

        // For each transaction, build and execute
        for tx_def in &vector.transactions {
            let chain_id = self.chainspec.chain().id();
            let (envelope, sender) = self.build_transaction(tx_def, chain_id)?;

            // Execute the transaction using the EVM directly
            let result = self.execute_single_tx(&envelope, sender, &mut state, &vector.block)?;

            cumulative_gas_used += result.gas_used;
            let mut result_with_cumulative = result;
            result_with_cumulative.cumulative_gas_used = cumulative_gas_used;

            tx_results.push(result_with_cumulative);
        }

        Ok(ExecutionResult_ {
            tx_results,
            total_gas_used: cumulative_gas_used,
        })
    }

    /// Execute a single transaction and return the result
    fn execute_single_tx<DB>(
        &self,
        envelope: &TempoTxEnvelope,
        sender: Address,
        state: &mut State<DB>,
        block: &BlockContext,
    ) -> eyre::Result<TxExecutionResult>
    where
        DB: revm::Database + std::fmt::Debug,
        DB::Error: std::error::Error + Send + Sync + 'static,
    {
        // Build transaction environment from the envelope and sender
        let tx_env = TempoTxEnv::from_recovered_tx(envelope, sender);

        // Build EVM environment for this block
        let evm_env = self.build_evm_env(block);

        // Build context for tempo_revm::TempoEvm
        let mut cfg_env = evm_env.cfg_env;
        cfg_env.chain_id = self.chainspec.chain().id();

        let ctx = Context::mainnet()
            .with_db(state)
            .with_block(evm_env.block_env)
            .with_cfg(cfg_env)
            .with_tx(Default::default());

        // Create a fresh TempoEvm for this transaction
        let mut evm = TempoEvm::new(ctx, ());

        // Execute the transaction (transact_one sets the tx_env internally)
        let result = evm
            .transact_one(tx_env)
            .map_err(|e| eyre::eyre!("EVM error: {:?}", e))?;

        // Convert the execution result to TxExecutionResult
        match result {
            ExecutionResult::Success {
                gas_used,
                output,
                logs,
                ..
            } => {
                let return_data = match output {
                    revm::context_interface::result::Output::Call(data) => data,
                    revm::context_interface::result::Output::Create(data, _) => data,
                };
                Ok(TxExecutionResult {
                    success: true,
                    gas_used,
                    cumulative_gas_used: 0, // Set by caller
                    return_data,
                    logs: logs.into_iter().map(Log::from).collect(),
                    revert_reason: None,
                })
            }
            ExecutionResult::Revert { gas_used, output } => {
                let revert_reason = decode_revert_reason(&output);
                Ok(TxExecutionResult {
                    success: false,
                    gas_used,
                    cumulative_gas_used: 0, // Set by caller
                    return_data: output,
                    logs: vec![],
                    revert_reason,
                })
            }
            ExecutionResult::Halt { reason, gas_used } => Ok(TxExecutionResult {
                success: false,
                gas_used,
                cumulative_gas_used: 0, // Set by caller
                return_data: Bytes::new(),
                logs: vec![],
                revert_reason: Some(format!("{reason:?}")),
            }),
        }
    }

    /// Build EVM environment from block context
    fn build_evm_env(&self, block: &BlockContext) -> EvmEnv<TempoHardfork, TempoBlockEnv> {
        EvmEnv {
            block_env: TempoBlockEnv {
                inner: BlockEnv {
                    number: U256::from(block.number),
                    beneficiary: block.coinbase,
                    timestamp: U256::from(block.timestamp),
                    gas_limit: block.gas_limit,
                    basefee: block.basefee.try_into().unwrap_or(u64::MAX),
                    prevrandao: Some(block.prevrandao),
                    ..Default::default()
                },
                timestamp_millis_part: u64::from(block.timestamp_millis_part),
            },
            cfg_env: Default::default(),
        }
    }

    /// Convert a vector Transaction to a recoverable transaction envelope
    fn build_transaction(
        &self,
        tx: &Transaction,
        chain_id: u64,
    ) -> eyre::Result<(TempoTxEnvelope, Address)> {
        let nonce = tx.nonce.unwrap_or(0);
        let to = match tx.to {
            Some(addr) => TxKind::Call(addr),
            None => TxKind::Create,
        };

        let envelope = match tx.tx_type {
            TempoTxType::Legacy => {
                let legacy_tx = TxLegacy {
                    chain_id: Some(chain_id),
                    nonce,
                    gas_limit: tx.gas_limit,
                    gas_price: tx.max_fee_per_gas.try_into().unwrap_or(u128::MAX),
                    to,
                    value: tx.value,
                    input: tx.input.clone(),
                };
                let signed =
                    Signed::new_unchecked(legacy_tx, Signature::test_signature(), B256::ZERO);
                TempoTxEnvelope::Legacy(signed)
            }

            TempoTxType::Eip2930 => {
                let eip2930_tx = TxEip2930 {
                    chain_id,
                    nonce,
                    gas_limit: tx.gas_limit,
                    gas_price: tx.max_fee_per_gas.try_into().unwrap_or(u128::MAX),
                    to,
                    value: tx.value,
                    input: tx.input.clone(),
                    access_list: Default::default(),
                };
                let signed =
                    Signed::new_unchecked(eip2930_tx, Signature::test_signature(), B256::ZERO);
                TempoTxEnvelope::Eip2930(signed)
            }

            TempoTxType::Eip1559 => {
                let eip1559_tx = TxEip1559 {
                    chain_id,
                    nonce,
                    gas_limit: tx.gas_limit,
                    max_fee_per_gas: tx.max_fee_per_gas.try_into().unwrap_or(u128::MAX),
                    max_priority_fee_per_gas: tx
                        .max_priority_fee_per_gas
                        .try_into()
                        .unwrap_or(u128::MAX),
                    to,
                    value: tx.value,
                    input: tx.input.clone(),
                    access_list: Default::default(),
                };
                let signed =
                    Signed::new_unchecked(eip1559_tx, Signature::test_signature(), B256::ZERO);
                TempoTxEnvelope::Eip1559(signed)
            }

            TempoTxType::AA => {
                // Build calls from the vector
                let calls: Vec<tempo_primitives::transaction::Call> = if tx.calls.is_empty() {
                    // Fallback: use to/value/input as a single call
                    vec![tempo_primitives::transaction::Call {
                        to,
                        value: tx.value,
                        input: tx.input.clone(),
                    }]
                } else {
                    tx.calls
                        .iter()
                        .map(|c| tempo_primitives::transaction::Call {
                            to: match c.to {
                                Some(addr) => TxKind::Call(addr),
                                None => TxKind::Create,
                            },
                            value: c.value,
                            input: c.input.clone(),
                        })
                        .collect()
                };

                let tempo_tx = TempoTransaction {
                    chain_id,
                    nonce,
                    nonce_key: tx.nonce_key,
                    gas_limit: tx.gas_limit,
                    max_fee_per_gas: tx.max_fee_per_gas.try_into().unwrap_or(u128::MAX),
                    max_priority_fee_per_gas: tx
                        .max_priority_fee_per_gas
                        .try_into()
                        .unwrap_or(u128::MAX),
                    calls,
                    fee_token: tx.fee_token,
                    valid_before: tx.valid_before,
                    valid_after: tx.valid_after,
                    access_list: Default::default(),
                    fee_payer_signature: None,
                    key_authorization: None,
                    tempo_authorization_list: vec![],
                };

                // Use test secp256k1 signature for AA transactions
                let aa_signed = AASigned::new_unhashed(
                    tempo_tx,
                    TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                        Signature::test_signature(),
                    )),
                );
                TempoTxEnvelope::AA(aa_signed)
            }

            TempoTxType::Eip7702 => {
                return Err(eyre::eyre!("EIP-7702 transactions not yet supported"));
            }
        };

        Ok((envelope, tx.from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vector::Call as VectorCall;

    fn make_base_tx() -> Transaction {
        Transaction {
            tx_type: TempoTxType::Eip1559,
            from: Address::repeat_byte(0x11),
            to: Some(Address::repeat_byte(0x22)),
            value: U256::from(1000),
            input: Bytes::from(vec![0x01, 0x02, 0x03]),
            gas_limit: 100_000,
            max_fee_per_gas: U256::from(20_000_000_000u64),
            max_priority_fee_per_gas: U256::from(1_000_000_000u64),
            nonce: Some(5),
            calls: vec![],
            nonce_key: U256::ZERO,
            fee_token: None,
            valid_before: None,
            valid_after: None,
        }
    }

    #[test]
    fn test_executor_creation() {
        let executor = VectorExecutor::with_test_chainspec();
        assert!(Arc::strong_count(&executor.chainspec) >= 1);
    }

    #[test]
    fn test_build_evm_env() {
        let executor = VectorExecutor::with_test_chainspec();
        let block = BlockContext {
            number: 1000,
            timestamp: 1700000000,
            timestamp_millis_part: 500,
            basefee: U256::from(1_000_000_000u64),
            gas_limit: 30_000_000,
            coinbase: Address::ZERO,
            prevrandao: B256::ZERO,
        };

        let env = executor.build_evm_env(&block);

        assert_eq!(env.block_env.inner.number, U256::from(1000));
        assert_eq!(env.block_env.inner.timestamp, U256::from(1700000000u64));
        assert_eq!(env.block_env.timestamp_millis_part, 500);
        assert_eq!(env.block_env.inner.gas_limit, 30_000_000);
    }

    #[test]
    fn test_build_legacy_transaction() {
        let executor = VectorExecutor::with_test_chainspec();
        let mut tx = make_base_tx();
        tx.tx_type = TempoTxType::Legacy;

        let chain_id = executor.chainspec.chain().id();
        let (envelope, sender) = executor.build_transaction(&tx, chain_id).unwrap();

        assert_eq!(sender, Address::repeat_byte(0x11));
        assert!(matches!(envelope, TempoTxEnvelope::Legacy(_)));

        if let TempoTxEnvelope::Legacy(signed) = &envelope {
            assert_eq!(signed.tx().gas_limit, 100_000);
            assert_eq!(signed.tx().nonce, 5);
        }
    }

    #[test]
    fn test_build_eip2930_transaction() {
        let executor = VectorExecutor::with_test_chainspec();
        let mut tx = make_base_tx();
        tx.tx_type = TempoTxType::Eip2930;

        let chain_id = executor.chainspec.chain().id();
        let (envelope, sender) = executor.build_transaction(&tx, chain_id).unwrap();

        assert_eq!(sender, Address::repeat_byte(0x11));
        assert!(matches!(envelope, TempoTxEnvelope::Eip2930(_)));

        if let TempoTxEnvelope::Eip2930(signed) = &envelope {
            assert_eq!(signed.tx().gas_limit, 100_000);
            assert_eq!(signed.tx().nonce, 5);
        }
    }

    #[test]
    fn test_build_eip1559_transaction() {
        let executor = VectorExecutor::with_test_chainspec();
        let tx = make_base_tx();

        let chain_id = executor.chainspec.chain().id();
        let (envelope, sender) = executor.build_transaction(&tx, chain_id).unwrap();

        assert_eq!(sender, Address::repeat_byte(0x11));
        assert!(matches!(envelope, TempoTxEnvelope::Eip1559(_)));

        if let TempoTxEnvelope::Eip1559(signed) = &envelope {
            assert_eq!(signed.tx().gas_limit, 100_000);
            assert_eq!(signed.tx().value, U256::from(1000));
            assert_eq!(signed.tx().nonce, 5);
        }
    }

    #[test]
    fn test_build_tempo_transaction_single_call() {
        let executor = VectorExecutor::with_test_chainspec();
        let mut tx = make_base_tx();
        tx.tx_type = TempoTxType::AA;
        tx.nonce_key = U256::from(1);
        tx.fee_token = Some(Address::repeat_byte(0x33));

        let chain_id = executor.chainspec.chain().id();
        let (envelope, sender) = executor.build_transaction(&tx, chain_id).unwrap();

        assert_eq!(sender, Address::repeat_byte(0x11));
        assert!(matches!(envelope, TempoTxEnvelope::AA(_)));

        if let TempoTxEnvelope::AA(aa_signed) = &envelope {
            let tempo_tx = aa_signed.tx();
            assert_eq!(tempo_tx.gas_limit, 100_000);
            assert_eq!(tempo_tx.nonce, 5);
            assert_eq!(tempo_tx.nonce_key, U256::from(1));
            assert_eq!(tempo_tx.fee_token, Some(Address::repeat_byte(0x33)));
            assert_eq!(tempo_tx.calls.len(), 1);
            assert_eq!(tempo_tx.calls[0].value, U256::from(1000));
        }
    }

    #[test]
    fn test_build_tempo_transaction_multi_call() {
        let executor = VectorExecutor::with_test_chainspec();
        let mut tx = make_base_tx();
        tx.tx_type = TempoTxType::AA;
        tx.calls = vec![
            VectorCall {
                to: Some(Address::repeat_byte(0xaa)),
                value: U256::from(100),
                input: Bytes::from(vec![0x01]),
            },
            VectorCall {
                to: Some(Address::repeat_byte(0xbb)),
                value: U256::from(200),
                input: Bytes::from(vec![0x02]),
            },
        ];

        let chain_id = executor.chainspec.chain().id();
        let (envelope, _sender) = executor.build_transaction(&tx, chain_id).unwrap();

        if let TempoTxEnvelope::AA(aa_signed) = &envelope {
            let tempo_tx = aa_signed.tx();
            assert_eq!(tempo_tx.calls.len(), 2);
            assert_eq!(tempo_tx.calls[0].value, U256::from(100));
            assert_eq!(tempo_tx.calls[1].value, U256::from(200));
        } else {
            panic!("Expected AA transaction");
        }
    }

    #[test]
    fn test_build_eip7702_transaction_unsupported() {
        let executor = VectorExecutor::with_test_chainspec();
        let mut tx = make_base_tx();
        tx.tx_type = TempoTxType::Eip7702;

        let chain_id = executor.chainspec.chain().id();
        let result = executor.build_transaction(&tx, chain_id);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("EIP-7702"));
    }
}
