use alloy_consensus::{Signed, TxLegacy};
use alloy_primitives::{Address, B256, U256};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use reth_basic_payload_builder::{BuildArguments, PayloadConfig};
use reth_chainspec::ChainSpecProvider;
use reth_db::{DatabaseEnv, open_db_read_only};
use reth_ethereum::EthereumNode;
use reth_node_builder::NodeTypesWithDBAdapter;
use reth_payload_builder::PayloadBuilder;
use reth_payload_primitives::EthPayloadBuilderAttributes;
use reth_primitives_traits::{SealedHeader, Recovered};
use reth_provider::{StaticFileProvider, providers::StaticFileWriter};
use reth_revm::CachedReads;
use std::sync::Arc;
use tempfile::TempDir;
use tempo_chainspec::TempoChainSpec;
use tempo_evm::TempoEvmConfig;
use tempo_payload_builder::TempoPayloadBuilder;
use tempo_payload_types::TempoPayloadBuilderAttributes;
use tempo_primitives::{TempoTxEnvelope, transaction::envelope::TEMPO_SYSTEM_TX_SIGNATURE};
use tempo_transaction_pool::TempoTransactionPool;

// Mock provider for benchmarks
#[derive(Debug, Clone)]
struct MockProvider {
    chain_spec: Arc<TempoChainSpec>,
}

impl MockProvider {
    fn new() -> Self {
        Self {
            chain_spec: Arc::new(TempoChainSpec::default()),
        }
    }
}

impl ChainSpecProvider for MockProvider {
    type ChainSpec = TempoChainSpec;

    fn chain_spec(&self) -> Arc<Self::ChainSpec> {
        self.chain_spec.clone()
    }
}

impl StateProviderFactory for MockProvider {
    type StateProvider = NoopStateProvider;

    fn state_by_block_hash(
        &self,
        _block_hash: B256,
    ) -> reth_storage_api::ProviderResult<Self::StateProvider> {
        Ok(NoopStateProvider::default())
    }

    fn latest(&self) -> reth_storage_api::ProviderResult<Self::StateProvider> {
        Ok(NoopStateProvider::default())
    }

    fn state_by_block_number_or_tag(
        &self,
        _number_or_tag: reth_primitives_traits::BlockNumberOrTag,
    ) -> reth_storage_api::ProviderResult<Self::StateProvider> {
        Ok(NoopStateProvider::default())
    }
}

// Mock transaction iterator for big blocks
struct MockBigBlockTransactions {
    transactions: VecDeque<Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
}

impl MockBigBlockTransactions {
    fn new(tx_count: usize, data_size_per_tx: usize) -> Self {
        let mut transactions = VecDeque::new();
        
        for i in 0..tx_count {
            // Create large calldata
            let large_data = vec![0u8; data_size_per_tx];
            
            let tx = TempoTxEnvelope::Legacy(Signed::new_unhashed(
                TxLegacy {
                    chain_id: Some(1),
                    nonce: i as u64,
                    gas_price: 20_000_000_000u128, // 20 gwei
                    gas_limit: 100_000,
                    to: Some(Address::random()),
                    value: U256::from(1000),
                    input: large_data.into(),
                },
                TEMPO_SYSTEM_TX_SIGNATURE,
            ));
            
            let recovered_tx = Recovered::new_unchecked(
                tx.clone(),
                Address::random(),
            );
            
            let pooled_tx = TempoPooledTransaction::new(recovered_tx, U256::from(20_000_000_000u128));
            let valid_tx = Arc::new(ValidPoolTransaction::new(pooled_tx, 0));
            
            transactions.push_back(valid_tx);
        }
        
        Self { transactions }
    }
}

impl reth_transaction_pool::BestTransactions for MockBigBlockTransactions {
    type Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>;

    fn next(&mut self) -> Option<Self::Item> {
        self.transactions.pop_front()
    }

    fn mark_invalid(
        &mut self,
        _tx: &Self::Item,
        _error: reth_transaction_pool::error::InvalidPoolTransactionError,
    ) {
        // For benchmarks, we don't need to handle this
    }
}

fn create_mock_header(block_number: u64) -> Header {
    Header {
        parent_hash: B256::random(),
        ommers_hash: B256::ZERO,
        beneficiary: Address::random(),
        state_root: B256::random(),
        transactions_root: B256::random(),
        receipts_root: B256::random(),
        withdrawals_root: Some(B256::random()),
        logs_bloom: Default::default(),
        difficulty: U256::ZERO,
        number: block_number,
        gas_limit: 30_000_000u64,
        gas_used: 0,
        timestamp: 1234567890,
        mix_hash: B256::random(),
        nonce: 0,
        base_fee_per_gas: Some(1_000_000_000u64), // 1 gwei
        blob_gas_used: Some(0),
        excess_blob_gas: Some(0),
        parent_beacon_block_root: Some(B256::random()),
        requests_root: Some(B256::random()),
    }
}

fn bench_build_payload_big_blocks(c: &mut Criterion) {
    let mut group = c.benchmark_group("build_payload_big_blocks");
    
    // Test scenarios: (tx_count, data_size_per_tx in KB)
    let scenarios = vec![
        (10, 1024),   // 10 txs with 1KB each
        (50, 2048),   // 50 txs with 2KB each  
        (20, 10240),  // 20 txs with 10KB each
        (10, 51200),  // 10 txs with 50KB each
        (5, 102400),  // 5 txs with 100KB each
    ];
    
    for &(tx_count, data_size) in &scenarios {
        let provider = MockProvider::new();
        let pool = TempoTransactionPool::new(provider.clone(), Default::default());
        let evm_config = TempoEvmConfig::default();
        let builder = TempoPayloadBuilder::new(pool, provider.clone(), evm_config);
        
        group.bench_with_input(
            BenchmarkId::new("big_block", format!("{}tx_{}KB", tx_count, data_size / 1024)),
            &(tx_count, data_size),
            |b, &(tx_count, data_size)| {
                b.iter(|| {
                    let parent_header = create_mock_header(100);
                    
                    let attributes = TempoPayloadBuilderAttributes::new(
                        reth_payload_primitives::PayloadId::new([1u8; 8]),
                        parent_header.hash(),
                        1234567890u64,
                        B256::random(),
                        Address::random(),
                        None,
                        false,
                        Vec::new(),
                    );
                    
                    let config = PayloadConfig {
                        parent_header: Arc::new(parent_header),
                        attributes,
                    };
                    
                    let args = BuildArguments::new(
                        CachedReads::default(),
                        config,
                        Default::default(),
                        Default::default(),
                    );
                    
                    // Create mock transactions with big data
                    let mock_txs = MockBigBlockTransactions::new(tx_count, data_size);
                    
                    // Call build_payload with our big block transactions
                    let result = builder.build_payload(black_box(args), |_attrs| black_box(mock_txs));
                    
                    black_box(result);
                });
            },
        );
    }
    
    group.finish();
}

criterion_group!(benches, bench_build_payload_big_blocks);
criterion_main!(benches);