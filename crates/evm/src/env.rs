//! Resolved Tempo EVM environment.

use crate::TempoEvmTypes;
use evm2::{Version, env::BlockEnv};
use tempo_chainspec::hardfork::TempoHardfork;

/// Fully resolved Tempo execution environment: the active hardfork, its runtime configuration and
/// the block environment.
#[derive(Debug, Clone)]
pub struct TempoEvmEnv {
    /// Active Tempo hardfork.
    pub spec: TempoHardfork,
    /// Runtime configuration for the active hardfork.
    pub version: Version,
    /// EVM block environment.
    pub block: BlockEnv<TempoEvmTypes>,
}

impl TempoEvmEnv {
    /// Creates an environment with the default runtime configuration of `spec` for `chain_id`.
    pub fn new(spec: TempoHardfork, block: BlockEnv<TempoEvmTypes>, chain_id: u64) -> Self {
        let mut version = Version::new(spec.into());
        version.chain_id = chain_id;
        Self {
            spec,
            version,
            block,
        }
    }

    /// Creates an environment with a preconfigured runtime configuration.
    pub const fn new_with_version(
        spec: TempoHardfork,
        block: BlockEnv<TempoEvmTypes>,
        version: Version,
    ) -> Self {
        Self {
            spec,
            version,
            block,
        }
    }
}

impl Default for TempoEvmEnv {
    fn default() -> Self {
        let spec = TempoHardfork::default();
        Self {
            spec,
            version: Version::new(spec.into()),
            block: Default::default(),
        }
    }
}

impl AsRef<BlockEnv<TempoEvmTypes>> for TempoEvmEnv {
    fn as_ref(&self) -> &BlockEnv<TempoEvmTypes> {
        &self.block
    }
}

#[cfg(feature = "reth")]
impl reth_evm::EvmEnv for TempoEvmEnv {
    type EvmTypes = TempoEvmTypes;

    fn spec_id(&self) -> TempoHardfork {
        self.spec
    }

    fn chain_id(&self) -> u64 {
        self.version.chain_id
    }

    fn block_env(&self) -> &BlockEnv<TempoEvmTypes> {
        &self.block
    }

    fn block_env_mut(&mut self) -> &mut BlockEnv<TempoEvmTypes> {
        &mut self.block
    }

    fn version(&self) -> &Version {
        &self.version
    }

    fn version_mut(&mut self) -> &mut Version {
        &mut self.version
    }

    fn block_base_fee(&self) -> u64 {
        self.block.basefee.saturating_to()
    }

    fn block_blob_base_fee(&self) -> u64 {
        self.block.blob_basefee.saturating_to()
    }

    fn transaction_validation_limits(&self) -> reth_evm::EvmTransactionValidationLimits {
        let tx_gas_limit_cap = if self.version.feature(evm2::EvmFeatures::EIP8037)
            || self.version.tx_gas_limit_cap == u64::MAX
        {
            0
        } else {
            self.version.tx_gas_limit_cap
        };

        reth_evm::EvmTransactionValidationLimits {
            max_initcode_size: self.version.max_initcode_size,
            tx_gas_limit_cap,
        }
    }

    fn transaction_validation_gas_rules(&self) -> reth_evm::EvmTransactionValidationGasRules {
        reth_evm::EvmTransactionValidationGasRules {
            version: self.version,
        }
    }

    fn uses_separate_block_gas(&self) -> bool {
        self.version.feature(evm2::EvmFeatures::EIP8037)
    }

    fn regular_gas_limit_cap(&self) -> u64 {
        self.version.tx_gas_limit_cap
    }

    fn with_nonce_check_disabled(mut self) -> Self {
        self.version.features.remove(evm2::EvmFeatures::NONCE_CHECK);
        self
    }

    fn with_balance_check_disabled(mut self) -> Self {
        self.version
            .features
            .remove(evm2::EvmFeatures::BALANCE_CHECK);
        self
    }
}
