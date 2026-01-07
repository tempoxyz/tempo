use std::{collections::HashMap, sync::Arc};

use alloy_evm::{Database, EvmEnv};
use alloy_primitives::{Address, B256, Bytes};
use reth_chainspec::EthChainSpec;
use reth_revm::{State, context::BlockEnv};
use revm::{database::EmptyDB, inspector::NoOpInspector};
use tempo_chainspec::{TempoChainSpec, spec::ANDANTINO};
use tempo_revm::TempoBlockEnv;

use crate::{TempoBlockExecutionCtx, block::TempoBlockExecutor, evm::TempoEvm};
use alloy_evm::eth::EthBlockExecutionCtx;
use alloy_primitives::U256;
use tempo_primitives::subblock::PartialValidatorKey;

pub fn test_chainspec() -> Arc<TempoChainSpec> {
    Arc::new(TempoChainSpec::from_genesis(ANDANTINO.genesis().clone()))
}

pub fn test_evm<DB: Database>(db: DB) -> TempoEvm<DB, NoOpInspector> {
    test_evm_with_basefee(db, 1)
}

pub fn test_evm_with_basefee<DB: Database>(db: DB, basefee: u64) -> TempoEvm<DB, NoOpInspector> {
    TempoEvm::new(
        db,
        EvmEnv {
            block_env: TempoBlockEnv {
                inner: BlockEnv {
                    basefee,
                    gas_limit: 30_000_000,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        },
    )
}

pub struct TestExecutorBuilder {
    pub block_number: u64,
    pub parent_hash: B256,
    pub general_gas_limit: u64,
    pub shared_gas_limit: u64,
    pub validator_set: Option<Vec<B256>>,
    pub parent_beacon_block_root: Option<B256>,
    pub subblock_fee_recipients: HashMap<PartialValidatorKey, Address>,
}

impl Default for TestExecutorBuilder {
    fn default() -> Self {
        Self {
            block_number: 1,
            parent_hash: B256::ZERO,
            general_gas_limit: 10_000_000,
            shared_gas_limit: 10_000_000,
            validator_set: None,
            parent_beacon_block_root: None,
            subblock_fee_recipients: HashMap::new(),
        }
    }
}

impl TestExecutorBuilder {
    pub fn with_validator_set(mut self, validators: Vec<B256>) -> Self {
        self.validator_set = Some(validators);
        self
    }

    pub fn with_shared_gas_limit(mut self, limit: u64) -> Self {
        self.shared_gas_limit = limit;
        self
    }

    pub fn with_general_gas_limit(mut self, limit: u64) -> Self {
        self.general_gas_limit = limit;
        self
    }

    pub fn with_parent_beacon_block_root(mut self, root: B256) -> Self {
        self.parent_beacon_block_root = Some(root);
        self
    }

    pub fn build<'a>(
        self,
        db: &'a mut State<EmptyDB>,
        chainspec: &'a Arc<TempoChainSpec>,
    ) -> TempoBlockExecutor<'a, EmptyDB, NoOpInspector> {
        let evm = TempoEvm::new(
            db,
            EvmEnv {
                block_env: TempoBlockEnv {
                    inner: BlockEnv {
                        number: U256::from(self.block_number),
                        basefee: 1,
                        gas_limit: 30_000_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        );

        let ctx = TempoBlockExecutionCtx {
            inner: EthBlockExecutionCtx {
                parent_hash: self.parent_hash,
                parent_beacon_block_root: self.parent_beacon_block_root,
                ommers: &[],
                withdrawals: None,
                extra_data: Bytes::new(),
            },
            general_gas_limit: self.general_gas_limit,
            shared_gas_limit: self.shared_gas_limit,
            validator_set: self.validator_set,
            subblock_fee_recipients: self.subblock_fee_recipients,
        };

        TempoBlockExecutor::new(evm, ctx, chainspec)
    }
}
