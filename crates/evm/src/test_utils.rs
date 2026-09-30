use std::{num::NonZeroU64, sync::Arc};

use crate::{
    TempoBlockEnv, TempoBlockExecutionCtx, TempoBlockExecutor, TempoBlockExt, TempoEvmConfig,
    TempoEvmEnv, block::BlockSection,
};
use alloy_primitives::{B256, Bytes, U256};
use evm2::{EvmFeatures, SpecId, evm::DynDatabase};
use reth_chainspec::EthChainSpec;
use reth_evm::BlockExecutorFactory;
use reth_evm_ethereum::EthBlockExecutionCtx;
use tempo_chainspec::{TempoChainSpec, TempoHardfork, spec::MODERATO};

pub(crate) fn test_chainspec() -> Arc<TempoChainSpec> {
    Arc::new(TempoChainSpec::from_genesis(MODERATO.genesis().clone()))
}

pub(crate) struct TestExecutorBuilder {
    pub(crate) block_number: u64,
    pub(crate) epoch_length: NonZeroU64,
    pub(crate) parent_hash: B256,
    pub(crate) general_gas_limit: u64,
    pub(crate) shared_gas_limit: u64,
    pub(crate) parent_beacon_block_root: Option<B256>,
    /// Enables the Amsterdam EIP-8037 feature to gate TIP-1016 behavior in tests.
    pub(crate) amsterdam_eip8037_enabled: bool,
    pub(crate) spec: TempoHardfork,
    pub(crate) extra_data: Bytes,
    // Test state to seed into the executor after creation
    pub(crate) initial_section: Option<BlockSection>,
}

impl Default for TestExecutorBuilder {
    fn default() -> Self {
        Self {
            block_number: 1,
            epoch_length: NonZeroU64::MIN,
            parent_hash: B256::ZERO,
            general_gas_limit: 10_000_000,
            shared_gas_limit: 10_000_000,
            parent_beacon_block_root: None,
            amsterdam_eip8037_enabled: false,
            spec: TempoHardfork::default(),
            extra_data: Bytes::new(),
            initial_section: None,
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

    pub(crate) fn with_general_gas_limit(mut self, limit: u64) -> Self {
        self.general_gas_limit = limit;
        self
    }

    pub(crate) fn with_parent_beacon_block_root(mut self, root: B256) -> Self {
        self.parent_beacon_block_root = Some(root);
        self
    }

    /// Toggles the Amsterdam EIP-8037 feature, which gates TIP-1016 (state gas split)
    /// behavior independently of the T4 hardfork.
    pub(crate) fn with_amsterdam_eip8037_enabled(mut self, enabled: bool) -> Self {
        self.amsterdam_eip8037_enabled = enabled;
        self
    }

    /// Set the initial block section for the executor (for testing section transitions).
    pub(crate) fn with_section(mut self, section: BlockSection) -> Self {
        self.initial_section = Some(section);
        self
    }

    pub(crate) fn build<'a>(
        self,
        database: impl DynDatabase + 'a,
        chainspec: &'a Arc<TempoChainSpec>,
    ) -> TempoBlockExecutor<'a> {
        let spec = SpecId::OSAKA;
        let mut version =
            tempo_chainspec::gas_params::version(spec, self.spec, self.amsterdam_eip8037_enabled);
        version.chain_id = chainspec.chain().id();
        version.features.remove(EvmFeatures::BALANCE_CHECK);
        version.features.remove(EvmFeatures::BALANCE_TOP_UP);
        let evm = TempoEvmConfig::new(chainspec.clone()).evm_with_env(
            database,
            TempoEvmEnv {
                spec: self.spec,
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
        );

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
            consensus_context: None,
        };

        let mut executor = TempoBlockExecutor::new(evm, ctx, chainspec);

        // Apply test-specific initial state
        if let Some(section) = self.initial_section {
            executor.set_section_for_test(section);
        }

        executor
    }
}
