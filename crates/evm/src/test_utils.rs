use std::{collections::HashMap, sync::Arc};

use alloy_evm::{Database, EvmEnv};
use alloy_primitives::{Address, B256, Bytes};
use reth_chainspec::EthChainSpec;
use reth_revm::{State, context::BlockEnv};
use revm::{database::EmptyDB, inspector::NoOpInspector};
use tempo_chainspec::{TempoChainSpec, spec::MODERATO};
use tempo_revm::TempoBlockEnv;

use crate::{TempoBlockExecutionCtx, block::TempoBlockExecutor, evm::TempoEvm};
use alloy_evm::eth::EthBlockExecutionCtx;
use alloy_primitives::U256;
use tempo_primitives::subblock::PartialValidatorKey;

pub(crate) fn test_chainspec() -> Arc<TempoChainSpec> {
    Arc::new(TempoChainSpec::from_genesis(MODERATO.genesis().clone()))
}

pub(crate) fn test_evm<DB: Database>(db: DB) -> TempoEvm<DB, NoOpInspector> {
    test_evm_with_basefee(db, 1)
}

pub(crate) fn test_evm_with_basefee<DB: Database>(
    db: DB,
    basefee: u64,
) -> TempoEvm<DB, NoOpInspector> {
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

use crate::block::BlockSection;
use tempo_primitives::TempoTxEnvelope;

pub(crate) struct TestExecutorBuilder {
    pub(crate) block_number: u64,
    pub(crate) parent_hash: B256,
    pub(crate) general_gas_limit: u64,
    pub(crate) shared_gas_limit: u64,
    pub(crate) validator_set: Option<Vec<B256>>,
    pub(crate) parent_beacon_block_root: Option<B256>,
    pub(crate) subblock_fee_recipients: HashMap<PartialValidatorKey, Address>,
    // Test state to seed into the executor after creation
    pub(crate) initial_section: Option<BlockSection>,
    pub(crate) initial_seen_subblocks: Vec<(PartialValidatorKey, Vec<TempoTxEnvelope>)>,
    pub(crate) initial_incentive_gas_used: u64,
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
            initial_section: None,
            initial_seen_subblocks: Vec::new(),
            initial_incentive_gas_used: 0,
        }
    }
}

impl TestExecutorBuilder {
    pub(crate) fn with_validator_set(mut self, validators: Vec<B256>) -> Self {
        self.validator_set = Some(validators);
        self
    }

    pub(crate) fn with_shared_gas_limit(mut self, limit: u64) -> Self {
        self.shared_gas_limit = limit;
        self
    }

    pub(crate) fn with_general_gas_limit(mut self, limit: u64) -> Self {
        self.general_gas_limit = limit;
        self
    }

    pub(crate) fn with_parent_beacon_block_root(mut self, root: B256) -> Self {
        self.parent_beacon_block_root = Some(root);
        self
    }

    /// Set the initial block section for the executor (for testing section transitions).
    pub(crate) fn with_section(mut self, section: BlockSection) -> Self {
        self.initial_section = Some(section);
        self
    }

    /// Add a seen subblock to the executor (for testing shared gas validation).
    pub(crate) fn with_seen_subblock(
        mut self,
        proposer: PartialValidatorKey,
        txs: Vec<TempoTxEnvelope>,
    ) -> Self {
        self.initial_seen_subblocks.push((proposer, txs));
        self
    }

    /// Set the initial incentive gas used (for testing gas limit validation).
    pub(crate) fn with_incentive_gas_used(mut self, gas: u64) -> Self {
        self.initial_incentive_gas_used = gas;
        self
    }

    pub(crate) fn build<'a>(
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
                tx_count_hint: None,
            },
            general_gas_limit: self.general_gas_limit,
            shared_gas_limit: self.shared_gas_limit,
            validator_set: self.validator_set,
            subblock_fee_recipients: self.subblock_fee_recipients,
        };

        let mut executor = TempoBlockExecutor::new(evm, ctx, chainspec);

        // Apply test-specific initial state
        if let Some(section) = self.initial_section {
            executor.set_section_for_test(section);
        }
        for (proposer, txs) in self.initial_seen_subblocks {
            executor.add_seen_subblock_for_test(proposer, txs);
        }
        if self.initial_incentive_gas_used > 0 {
            executor.set_incentive_gas_used_for_test(self.initial_incentive_gas_used);
        }

        executor
    }
}
