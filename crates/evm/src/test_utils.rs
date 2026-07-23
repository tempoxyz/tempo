use crate::{
    TempoBlockEnv, TempoBlockExecutionCtx, TempoBlockExecutor, TempoBlockExt, TempoEvm,
    TempoEvmConfig, TempoEvmEnv, block::BlockSection,
};
use alloy_primitives::{Address, B256, Bytes, U256};
use evm2::{EvmFeatures, SpecId, evm::DynDatabase};
use reth_chainspec::EthChainSpec;
use reth_evm::BlockExecutorFactory;
use reth_evm_ethereum::EthBlockExecutionCtx;
use std::{collections::HashMap, num::NonZeroU64, sync::Arc};
use tempo_chainspec::{TempoChainSpec, TempoHardfork, spec::MODERATO};
use tempo_primitives::{TempoTxEnvelope, subblock::PartialValidatorKey};

pub(crate) fn test_chainspec() -> Arc<TempoChainSpec> {
    Arc::new(TempoChainSpec::from_genesis(MODERATO.genesis().clone()))
}

pub(crate) struct TestExecutorBuilder {
    pub(crate) block_number: u64,
    pub(crate) epoch_length: NonZeroU64,
    pub(crate) parent_hash: B256,
    pub(crate) general_gas_limit: u64,
    pub(crate) shared_gas_limit: u64,
    pub(crate) validator_set: Option<Vec<B256>>,
    pub(crate) parent_beacon_block_root: Option<B256>,
    pub(crate) subblock_fee_recipients: HashMap<PartialValidatorKey, Address>,
    pub(crate) amsterdam_eip8037_enabled: bool,
    pub(crate) spec: TempoHardfork,
    pub(crate) extra_data: Bytes,
    pub(crate) initial_section: Option<BlockSection>,
    pub(crate) initial_seen_subblocks: Vec<(PartialValidatorKey, Vec<TempoTxEnvelope>)>,
    pub(crate) initial_incentive_gas_used: u64,
}

impl Default for TestExecutorBuilder {
    fn default() -> Self {
        Self {
            block_number: 1,
            epoch_length: NonZeroU64::MIN,
            parent_hash: B256::ZERO,
            general_gas_limit: 10_000_000,
            shared_gas_limit: 10_000_000,
            validator_set: None,
            parent_beacon_block_root: None,
            subblock_fee_recipients: HashMap::new(),
            amsterdam_eip8037_enabled: false,
            spec: TempoHardfork::default(),
            extra_data: Bytes::new(),
            initial_section: None,
            initial_seen_subblocks: Vec::new(),
            initial_incentive_gas_used: 0,
        }
    }
}

impl TestExecutorBuilder {
    pub(crate) fn with_block_number(mut self, block_number: u64) -> Self {
        self.block_number = block_number;
        self
    }

    pub(crate) fn with_epoch_length(mut self, epoch_length: u64) -> Self {
        self.epoch_length = NonZeroU64::new(epoch_length).expect("epoch length must be non-zero");
        self
    }

    pub(crate) fn with_extra_data(mut self, extra_data: Bytes) -> Self {
        self.extra_data = extra_data;
        self
    }

    pub(crate) fn with_spec(mut self, spec: TempoHardfork) -> Self {
        self.spec = spec;
        self
    }

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

    pub(crate) fn with_amsterdam_eip8037_enabled(mut self, enabled: bool) -> Self {
        self.amsterdam_eip8037_enabled = enabled;
        self
    }

    pub(crate) fn with_section(mut self, section: BlockSection) -> Self {
        self.initial_section = Some(section);
        self
    }

    pub(crate) fn with_seen_subblock(
        mut self,
        proposer: PartialValidatorKey,
        txs: Vec<TempoTxEnvelope>,
    ) -> Self {
        self.initial_seen_subblocks.push((proposer, txs));
        self
    }

    pub(crate) fn with_incentive_gas_used(mut self, gas: u64) -> Self {
        self.initial_incentive_gas_used = gas;
        self
    }

    fn evm<'a>(
        &self,
        database: impl DynDatabase + 'a,
        chainspec: &Arc<TempoChainSpec>,
    ) -> TempoEvm<'a> {
        let spec = SpecId::OSAKA;
        let mut version =
            tempo_chainspec::gas_params::version(spec, self.spec, self.amsterdam_eip8037_enabled);
        version.chain_id = chainspec.chain().id();
        version.features.remove(EvmFeatures::BALANCE_CHECK);
        version.features.remove(EvmFeatures::BALANCE_TOP_UP);
        TempoEvmConfig::new(chainspec.clone()).evm_with_env(
            database,
            TempoEvmEnv {
                tempo_spec: self.spec,
                version,
                block: TempoBlockEnv {
                    number: U256::from(self.block_number),
                    gas_limit: U256::from(30_000_000),
                    basefee: U256::ONE,
                    ext: TempoBlockExt {
                        epoch_length: self.epoch_length,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            },
        )
    }

    pub(crate) fn build<'a>(
        self,
        database: impl DynDatabase + 'a,
        chainspec: &'a Arc<TempoChainSpec>,
    ) -> TempoBlockExecutor<'a> {
        let evm = self.evm(database, chainspec);
        let ctx = TempoBlockExecutionCtx {
            inner: EthBlockExecutionCtx {
                parent_hash: self.parent_hash,
                parent_beacon_block_root: self.parent_beacon_block_root,
                ommers: &[],
                withdrawals: None,
                extra_data: self.extra_data,
                tx_count_hint: None,
                slot_number: None,
            },
            general_gas_limit: self.general_gas_limit,
            shared_gas_limit: self.shared_gas_limit,
            validator_set: self.validator_set,
            consensus_context: None,
            subblock_fee_recipients: self.subblock_fee_recipients,
        };
        let mut executor = TempoBlockExecutor::new(evm, ctx, chainspec);
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
