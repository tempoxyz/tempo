use crate::{TempoEvmConfig, context::TempoBlockExecutionCtx};
use alloy_consensus::{BlockBody, BlockHeader, EMPTY_OMMER_ROOT_HASH, Header, TxReceipt, proofs};
use alloy_eips::{eip4895::Withdrawals, merge::BEACON_NONCE};
use alloy_evm::block::BlockExecutionError;
use alloy_primitives::{B256, Bloom};
use rayon::{ThreadPool, prelude::*};
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_evm::execute::{BlockAssembler, BlockAssemblerInput};
use reth_revm::context::Block as _;
use std::sync::Arc;
use tempo_chainspec::TempoChainSpec;
use tempo_primitives::{Block, TempoHeader, TempoReceipt, TempoTxEnvelope};

/// Assembler for Tempo blocks.
#[derive(Debug, Clone)]
pub struct TempoBlockAssembler {
    chain_spec: Arc<TempoChainSpec>,
    pub(crate) pool: Option<Arc<ThreadPool>>,
}

impl TempoBlockAssembler {
    pub fn new(chain_spec: Arc<TempoChainSpec>) -> Self {
        Self {
            chain_spec,
            pool: None,
        }
    }
}

/// Keep indexed receipt order while computing independent blooms concurrently.
/// The block bloom is the union of those same blooms, avoiding a second hash of
/// every log address and topic. Small blocks avoid worker scheduling overhead.
fn calculate_roots(
    transactions: &[TempoTxEnvelope],
    receipts: &[TempoReceipt],
    pool: Option<&ThreadPool>,
) -> (B256, B256, Bloom) {
    let receipt_roots = |parallel: bool| {
        let receipts = if parallel {
            receipts
                .par_iter()
                .map(TxReceipt::with_bloom_ref)
                .collect::<Vec<_>>()
        } else {
            receipts
                .iter()
                .map(TxReceipt::with_bloom_ref)
                .collect::<Vec<_>>()
        };
        let bloom = receipts
            .iter()
            .fold(Bloom::ZERO, |bloom, receipt| bloom | receipt.logs_bloom);
        (proofs::calculate_receipt_root(&receipts), bloom)
    };
    let (transactions_root, (receipts_root, bloom)) = match pool {
        Some(pool) if transactions.len() >= 128 && pool.current_num_threads() > 1 => {
            pool.install(|| {
                rayon::join(
                    || proofs::calculate_transaction_root(transactions),
                    || receipt_roots(true),
                )
            })
        }
        _ => (
            proofs::calculate_transaction_root(transactions),
            receipt_roots(false),
        ),
    };
    (transactions_root, receipts_root, bloom)
}

impl BlockAssembler<TempoEvmConfig> for TempoBlockAssembler {
    type Block = Block;

    fn assemble_block(
        &self,
        input: BlockAssemblerInput<'_, '_, TempoEvmConfig, TempoHeader>,
    ) -> Result<Self::Block, BlockExecutionError> {
        let BlockAssemblerInput {
            evm_env,
            execution_ctx:
                TempoBlockExecutionCtx {
                    inner: ctx,
                    general_gas_limit,
                    shared_gas_limit,
                    consensus_context,
                    ..
                },
            parent,
            transactions,
            output,
            state_root,
            ..
        } = input;

        let timestamp = evm_env.block_env.timestamp().saturating_to();
        let (transactions_root, receipts_root, logs_bloom) =
            calculate_roots(&transactions, &output.receipts, self.pool.as_deref());

        // Preserve EthBlockAssembler's fork-dependent header and body fields.
        // Differential assembly tests below compare the complete upstream block.
        let withdrawals = self
            .chain_spec
            .is_shanghai_active_at_timestamp(timestamp)
            .then(|| Withdrawals::new(ctx.withdrawals.map(|w| w.into_owned()).unwrap_or_default()));
        let withdrawals_root = withdrawals
            .as_deref()
            .map(|w| proofs::calculate_withdrawals_root(w));
        let requests_hash = self
            .chain_spec
            .is_prague_active_at_timestamp(timestamp)
            .then(|| output.requests.requests_hash());
        let mut excess_blob_gas = None;
        let mut block_blob_gas_used = None;
        if self.chain_spec.is_cancun_active_at_timestamp(timestamp) {
            block_blob_gas_used = Some(output.blob_gas_used);
            excess_blob_gas = if self
                .chain_spec
                .is_cancun_active_at_timestamp(parent.timestamp())
            {
                parent.maybe_next_block_excess_blob_gas(
                    self.chain_spec.blob_params_at_timestamp(timestamp),
                )
            } else {
                Some(
                    alloy_eips::eip7840::BlobParams::cancun()
                        .next_block_excess_blob_gas_osaka(0, 0, 0),
                )
            };
        }
        let inner = Header {
            parent_hash: ctx.parent_hash,
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
            beneficiary: evm_env.block_env.beneficiary(),
            state_root,
            transactions_root,
            receipts_root,
            withdrawals_root,
            logs_bloom,
            timestamp,
            mix_hash: evm_env.block_env.prevrandao().unwrap_or_default(),
            nonce: BEACON_NONCE.into(),
            base_fee_per_gas: Some(evm_env.block_env.basefee()),
            number: evm_env.block_env.number().saturating_to(),
            gas_limit: evm_env.block_env.gas_limit(),
            difficulty: evm_env.block_env.difficulty(),
            gas_used: output.gas_used,
            extra_data: ctx.extra_data,
            parent_beacon_block_root: ctx.parent_beacon_block_root,
            blob_gas_used: block_blob_gas_used,
            excess_blob_gas,
            requests_hash,
            block_access_list_hash: None,
            slot_number: None,
        };
        Ok(Block {
            header: TempoHeader {
                inner,
                general_gas_limit,
                timestamp_millis_part: evm_env.block_env.timestamp_millis_part,
                shared_gas_limit,
                consensus_context,
            },
            body: BlockBody {
                transactions,
                ommers: Default::default(),
                withdrawals,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Signed, TxLegacy};
    use alloy_evm::{EvmEnv, block::BlockExecutionResult, eth::EthBlockExecutionCtx};
    use alloy_primitives::{Address, B256, Bytes, Signature, TxKind, U256};
    use reth_chainspec::EthChainSpec;
    use reth_evm::execute::BlockAssembler;
    use reth_primitives_traits::SealedHeader;
    use reth_storage_api::noop::NoopProvider;
    use revm::{context::BlockEnv, database::BundleState};
    use std::collections::HashMap;
    use tempo_chainspec::spec::MODERATO;
    use tempo_primitives::{
        TempoHeader, TempoPrimitives, TempoReceipt, TempoTxEnvelope, TempoTxType,
    };
    use tempo_revm::TempoBlockEnv;

    fn create_legacy_tx() -> TempoTxEnvelope {
        let tx = TxLegacy {
            chain_id: Some(1),
            nonce: 0,
            gas_price: 1,
            gas_limit: 21000,
            to: TxKind::Call(Address::ZERO),
            value: U256::ZERO,
            input: Bytes::new(),
        };
        TempoTxEnvelope::Legacy(Signed::new_unhashed(tx, Signature::test_signature()))
    }

    fn create_test_receipt(gas_used: u64) -> TempoReceipt {
        TempoReceipt {
            tx_type: TempoTxType::Legacy,
            success: true,
            cumulative_gas_used: gas_used,
            logs: vec![],
        }
    }

    #[test]
    fn test_assemble_block() {
        let chainspec = Arc::new(TempoChainSpec::from_genesis(MODERATO.genesis().clone()));
        let assembler = TempoBlockAssembler::new(chainspec.clone());

        let block_number = 1u64;
        let timestamp = 1000u64;
        let timestamp_millis_part = 500u64;
        let gas_limit = 30_000_000u64;
        let general_gas_limit = 10_000_000u64;
        let shared_gas_limit = 10_000_000u64;

        let evm_env = EvmEnv {
            block_env: TempoBlockEnv {
                inner: BlockEnv {
                    number: U256::from(block_number),
                    timestamp: U256::from(timestamp),
                    beneficiary: Address::repeat_byte(0x01),
                    basefee: 1,
                    gas_limit,
                    ..Default::default()
                },
                timestamp_millis_part,
            },
            ..Default::default()
        };

        let parent_header = TempoHeader {
            inner: alloy_consensus::Header {
                number: 0,
                timestamp: 0,
                gas_limit,
                ..Default::default()
            },
            general_gas_limit,
            timestamp_millis_part: 0,
            shared_gas_limit,
            ..Default::default()
        };
        let parent = SealedHeader::seal_slow(parent_header);

        let execution_ctx = TempoBlockExecutionCtx {
            transactions: &[],
            inner: EthBlockExecutionCtx {
                parent_hash: parent.hash(),
                parent_beacon_block_root: Some(B256::ZERO),
                ommers: &[],
                withdrawals: None,
                extra_data: Bytes::new(),
                tx_count_hint: None,
            },
            general_gas_limit,
            shared_gas_limit,
            validator_set: None,
            consensus_context: None,
            subblock_fee_recipients: HashMap::new(),
        };

        let tx = create_legacy_tx();
        let transactions = vec![tx];

        let receipt = create_test_receipt(21000);
        let output = BlockExecutionResult {
            receipts: vec![receipt],
            requests: Default::default(),
            gas_used: 21000,
            blob_gas_used: 0,
        };

        let bundle_state = BundleState::default();
        let state_provider = NoopProvider::<TempoChainSpec, TempoPrimitives>::new(chainspec);
        let state_root = B256::ZERO;

        let input = BlockAssemblerInput::<TempoEvmConfig, TempoHeader>::new(
            evm_env,
            execution_ctx,
            &parent,
            transactions,
            &output,
            &bundle_state,
            &state_provider,
            state_root,
        );

        let block = assembler
            .assemble_block(input)
            .expect("should assemble block");

        // Verify block header fields
        assert_eq!(block.header.inner.number, block_number);
        assert_eq!(block.header.inner.timestamp, timestamp);
        assert_eq!(block.header.inner.gas_used, 21000);
        assert_eq!(block.header.inner.gas_limit, gas_limit);
        assert_eq!(block.header.inner.parent_hash, parent.hash());
        assert_eq!(block.header.inner.beneficiary, Address::repeat_byte(0x01));
        assert_eq!(block.header.inner.state_root, state_root);

        // Verify Tempo-specific header fields
        assert_eq!(block.header.general_gas_limit, general_gas_limit);
        assert_eq!(block.header.shared_gas_limit, shared_gas_limit);
        assert_eq!(block.header.timestamp_millis_part, timestamp_millis_part);

        // Verify body
        assert_eq!(block.body.transactions.len(), 1);

        // Verify consensus context is None when not provided
        assert!(block.header.consensus_context.is_none());
    }

    #[test]
    fn test_assemble_block_with_consensus_context() {
        let chainspec = Arc::new(TempoChainSpec::from_genesis(MODERATO.genesis().clone()));
        let assembler = TempoBlockAssembler::new(chainspec.clone());

        let gas_limit = 30_000_000u64;
        let general_gas_limit = 10_000_000u64;
        let shared_gas_limit = 10_000_000u64;

        let ctx = tempo_primitives::TempoConsensusContext {
            epoch: 1,
            view: 5,
            proposer: tempo_primitives::ed25519::PublicKey::from_seed([0xab; 32]),
            parent_view: 4,
        };

        let evm_env = EvmEnv {
            block_env: TempoBlockEnv {
                inner: BlockEnv {
                    number: U256::from(1),
                    timestamp: U256::from(1000),
                    beneficiary: Address::repeat_byte(0x01),
                    basefee: 1,
                    gas_limit,
                    ..Default::default()
                },
                timestamp_millis_part: 0,
            },
            ..Default::default()
        };

        let parent_header = TempoHeader {
            inner: alloy_consensus::Header {
                gas_limit,
                ..Default::default()
            },
            general_gas_limit,
            shared_gas_limit,
            ..Default::default()
        };
        let parent = SealedHeader::seal_slow(parent_header);

        let execution_ctx = TempoBlockExecutionCtx {
            transactions: &[],
            inner: EthBlockExecutionCtx {
                parent_hash: parent.hash(),
                parent_beacon_block_root: Some(B256::ZERO),
                ommers: &[],
                withdrawals: None,
                extra_data: Bytes::new(),
                tx_count_hint: None,
            },
            general_gas_limit,
            shared_gas_limit,
            validator_set: None,
            consensus_context: Some(ctx),
            subblock_fee_recipients: HashMap::new(),
        };

        let transactions = vec![create_legacy_tx()];
        let output = BlockExecutionResult {
            receipts: vec![create_test_receipt(21000)],
            requests: Default::default(),
            gas_used: 21000,
            blob_gas_used: 0,
        };

        let bundle_state = BundleState::default();
        let state_provider = NoopProvider::<TempoChainSpec, TempoPrimitives>::new(chainspec);

        let input = BlockAssemblerInput::<TempoEvmConfig, TempoHeader>::new(
            evm_env,
            execution_ctx,
            &parent,
            transactions,
            &output,
            &bundle_state,
            &state_provider,
            B256::ZERO,
        );

        let block = assembler
            .assemble_block(input)
            .expect("should assemble block");

        assert_eq!(block.header.consensus_context, Some(ctx));
    }

    fn generated_assembly_data(count: usize) -> (Vec<TempoTxEnvelope>, Vec<TempoReceipt>) {
        use alloy_consensus::TxEip1559;
        use alloy_primitives::Log;
        use tempo_primitives::{AASigned, TempoSignature, TempoTransaction};
        let transactions = (0..count)
            .map(|i| match i % 3 {
                0 => TempoTxEnvelope::Legacy(Signed::new_unhashed(
                    TxLegacy {
                        nonce: i as u64,
                        input: vec![i as u8; i % 128].into(),
                        ..Default::default()
                    },
                    Signature::test_signature(),
                )),
                1 => TempoTxEnvelope::Eip1559(Signed::new_unhashed(
                    TxEip1559 {
                        nonce: i as u64,
                        input: vec![i as u8; i % 128].into(),
                        ..Default::default()
                    },
                    Signature::test_signature(),
                )),
                _ => TempoTxEnvelope::AA(AASigned::new_unhashed(
                    TempoTransaction {
                        nonce: i as u64,
                        nonce_key: U256::from(i + 1),
                        ..Default::default()
                    },
                    TempoSignature::default(),
                )),
            })
            .collect::<Vec<_>>();
        let receipts = transactions
            .iter()
            .enumerate()
            .map(|(i, tx)| TempoReceipt {
                tx_type: tx.tx_type(),
                success: i % 7 != 0,
                cumulative_gas_used: (i as u64 + 1) * 21_000,
                logs: (0..i % 4)
                    .map(|j| {
                        Log::new_unchecked(
                            Address::from_word(B256::from(U256::from(i + j))),
                            (0..(i + j) % 5)
                                .map(|k| B256::from(U256::from(i * 7 + k)))
                                .collect(),
                            vec![j as u8; i % 97].into(),
                        )
                    })
                    .collect(),
            })
            .collect();
        (transactions, receipts)
    }

    #[test]
    fn assembly_matches_upstream_across_forks_and_worker_counts() {
        use crate::{TempoEvmFactory, TempoReceiptBuilder, parallel::SpeculativeExecutor};
        use alloy_eips::{eip4895::Withdrawal, eip7685::Requests};
        use alloy_evm::eth::EthBlockExecutorFactory;
        use reth_chainspec::{EthereumHardfork, ForkCondition};
        use reth_evm_ethereum::EthBlockAssembler;
        let mut chainspec = TempoChainSpec::moderato();
        for (fork, timestamp) in [
            (EthereumHardfork::Shanghai, 100),
            (EthereumHardfork::Cancun, 200),
            (EthereumHardfork::Prague, 300),
            (EthereumHardfork::Osaka, 400),
        ] {
            chainspec
                .inner
                .hardforks
                .insert(fork, ForkCondition::Timestamp(timestamp));
        }
        let chainspec = Arc::new(chainspec);
        let reference = EthBlockAssembler::new(chainspec.clone());
        let state_provider =
            NoopProvider::<TempoChainSpec, TempoPrimitives>::new(chainspec.clone());
        let bundle = BundleState::default();
        for workers in [0, 1, 4] {
            let mut config = TempoEvmConfig::new(chainspec.clone());
            if workers > 0 {
                config = config
                    .with_speculative_executor(SpeculativeExecutor::new(workers, 128).unwrap());
                assert!(config.block_assembler.pool.is_some());
            }
            for count in [0, 1, 127, 128, 129, 257] {
                let (transactions, receipts) = generated_assembly_data(count);
                let output = BlockExecutionResult {
                    receipts,
                    requests: Requests::new(vec![
                        Bytes::from_static(&[0, 1, 2]),
                        Bytes::from_static(&[1, 3]),
                    ]),
                    gas_used: count as u64 * 21_000,
                    blob_gas_used: 131_072,
                };
                for timestamp in [99u64, 100, 199, 200, 201, 299, 300, 399, 400, 401] {
                    let parent = SealedHeader::seal_slow(TempoHeader {
                        inner: alloy_consensus::Header {
                            number: 10,
                            timestamp: timestamp - 1,
                            gas_limit: 100_000_000,
                            gas_used: 45_000_000,
                            blob_gas_used: (timestamp > 200).then_some(131_072),
                            excess_blob_gas: (timestamp > 200).then_some(262_144),
                            ..Default::default()
                        },
                        ..Default::default()
                    });
                    let eth_parent = SealedHeader::new_unhashed(parent.clone().into_header().inner);
                    let evm_env = EvmEnv {
                        block_env: TempoBlockEnv {
                            inner: BlockEnv {
                                number: U256::from(11),
                                timestamp: U256::from(timestamp),
                                beneficiary: Address::repeat_byte(0x17),
                                basefee: 123,
                                gas_limit: 100_000_000,
                                prevrandao: Some(B256::repeat_byte(0x29)),
                                difficulty: U256::from(42),
                                ..Default::default()
                            },
                            timestamp_millis_part: 777,
                        },
                        ..Default::default()
                    };
                    let inner = EthBlockExecutionCtx {
                        parent_hash: parent.hash(),
                        parent_beacon_block_root: Some(B256::repeat_byte(0x42)),
                        ommers: &[],
                        withdrawals: Some(std::borrow::Cow::Owned(vec![Withdrawal {
                            index: 1,
                            validator_index: 3,
                            address: Address::repeat_byte(0x31),
                            amount: 55,
                        }])),
                        extra_data: Bytes::from_static(b"assembly-differential"),
                        tx_count_hint: Some(count),
                    };
                    let consensus_context = tempo_primitives::TempoConsensusContext {
                        epoch: 9,
                        view: 13,
                        proposer: tempo_primitives::ed25519::PublicKey::from_seed([0xab; 32]),
                        parent_view: 12,
                    };
                    let ctx = TempoBlockExecutionCtx {
                        transactions: &[],
                        inner: inner.clone(),
                        general_gas_limit: 50_000_000,
                        shared_gas_limit: 10_000_000,
                        validator_set: None,
                        consensus_context: Some(consensus_context),
                        subblock_fee_recipients: HashMap::new(),
                    };
                    let expected = reference
                        .assemble_block(BlockAssemblerInput::<
                            EthBlockExecutorFactory<
                                TempoReceiptBuilder,
                                TempoChainSpec,
                                TempoEvmFactory,
                            >,
                        >::new(
                            evm_env.clone(),
                            inner,
                            &eth_parent,
                            transactions.clone(),
                            &output,
                            &bundle,
                            &state_provider,
                            B256::repeat_byte(0x51),
                        ))
                        .unwrap();
                    let actual = config
                        .block_assembler
                        .assemble_block(BlockAssemblerInput::<TempoEvmConfig, TempoHeader>::new(
                            evm_env,
                            ctx,
                            &parent,
                            transactions.clone(),
                            &output,
                            &bundle,
                            &state_provider,
                            B256::repeat_byte(0x51),
                        ))
                        .unwrap();
                    assert_eq!(actual.header.general_gas_limit, 50_000_000);
                    assert_eq!(actual.header.shared_gas_limit, 10_000_000);
                    assert_eq!(actual.header.timestamp_millis_part, 777);
                    assert_eq!(actual.header.consensus_context, Some(consensus_context));
                    assert_eq!(
                        actual.map_header(|h| h.inner),
                        expected,
                        "workers={workers}, count={count}, timestamp={timestamp}"
                    );
                }
            }
        }
    }

    #[test]
    #[ignore = "release-mode block assembly benchmark"]
    fn assembly_roots_throughput() {
        use std::time::Instant;
        for count in [10_000, 25_000, 50_000] {
            let (transactions, receipts) = generated_assembly_data(count);
            let reference = || {
                (
                    proofs::calculate_transaction_root(&transactions),
                    proofs::calculate_receipt_root(
                        &receipts
                            .iter()
                            .map(TxReceipt::with_bloom_ref)
                            .collect::<Vec<_>>(),
                    ),
                    reth_primitives_traits::logs_bloom(receipts.iter().flat_map(|r| &r.logs)),
                )
            };
            let expected = reference();
            for workers in [0, 16, 32] {
                let pool = (workers > 0).then(|| {
                    rayon::ThreadPoolBuilder::new()
                        .num_threads(workers)
                        .build()
                        .unwrap()
                });
                for repeat in 0..3 {
                    let before = Instant::now();
                    let original = reference();
                    let original_seconds = before.elapsed().as_secs_f64();
                    assert_eq!(original, expected);
                    let before = Instant::now();
                    let actual = calculate_roots(&transactions, &receipts, pool.as_ref());
                    let seconds = before.elapsed().as_secs_f64();
                    assert_eq!(actual, expected);
                    println!(
                        "assembly\t{count}\t{workers}\t{repeat}\t{original_seconds:.9}\t{seconds:.9}"
                    );
                }
            }
        }
    }
}
