use std::collections::HashMap;

use alloy_evm::eth::EthBlockExecutionCtx;
use alloy_primitives::{Address, B256};
use reth_evm::NextBlockEnvAttributes;
use tempo_primitives::subblock::PartialValidatorKey;

/// Execution context for Tempo block.
#[derive(Debug, Clone, derive_more::Deref)]
pub struct TempoBlockExecutionCtx<'a> {
    /// Inner [`EthBlockExecutionCtx`].
    #[deref]
    pub inner: EthBlockExecutionCtx<'a>,
    /// Non-payment gas limit for the block.
    pub general_gas_limit: u64,
    /// Shared gas limit for the block.
    pub shared_gas_limit: u64,
    /// Validator set for the block.
    ///
    /// Only set for un-finalized blocks coming from consensus layer.
    ///
    /// When this is set to `None`, no validation of subblock signatures is performed.
    /// Make sure to always set this field when executing blocks from untrusted sources
    pub validator_set: Option<Vec<B256>>,
    /// Mapping from a subblock validator public key to the fee recipient configured.
    ///
    /// Used to provide EVM with the fee recipient context when executing subblock transactions.
    pub subblock_fee_recipients: HashMap<PartialValidatorKey, Address>,
}

/// Context required for next block environment.
#[derive(Debug, Clone, derive_more::Deref)]
pub struct TempoNextBlockEnvAttributes {
    /// Inner [`NextBlockEnvAttributes`].
    #[deref]
    pub inner: NextBlockEnvAttributes,
    /// Non-payment gas limit for the block.
    pub general_gas_limit: u64,
    /// Shared gas limit for the block.
    pub shared_gas_limit: u64,
    /// Milliseconds portion of the timestamp.
    pub timestamp_millis_part: u64,
    /// Mapping from a subblock validator public key to the fee recipient configured.
    pub subblock_fee_recipients: HashMap<PartialValidatorKey, Address>,
}

#[cfg(feature = "rpc")]
impl reth_rpc_eth_api::helpers::pending_block::BuildPendingEnv<tempo_primitives::TempoHeader>
    for TempoNextBlockEnvAttributes
{
    fn build_pending_env(parent: &crate::SealedHeader<tempo_primitives::TempoHeader>) -> Self {
        use alloy_consensus::BlockHeader as _;

        let shared_gas_limit = parent.gas_limit() / tempo_consensus::TEMPO_SHARED_GAS_DIVISOR;
        let general_gas_limit =
            (parent.gas_limit() - shared_gas_limit) / tempo_consensus::TEMPO_GENERAL_GAS_DIVISOR;

        Self {
            inner: NextBlockEnvAttributes::build_pending_env(parent),
            general_gas_limit,
            shared_gas_limit,
            timestamp_millis_part: parent.timestamp_millis_part,
            subblock_fee_recipients: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_primitives_traits::SealedHeader;
    use reth_rpc_eth_api::helpers::pending_block::BuildPendingEnv;
    use tempo_primitives::TempoHeader;

    #[test]
    fn test_build_pending_env() {
        let gas_limit = 30_000_000u64;
        let timestamp_millis_part = 500u64;

        let parent_header = TempoHeader {
            inner: alloy_consensus::Header {
                number: 10,
                timestamp: 1000,
                gas_limit,
                ..Default::default()
            },
            general_gas_limit: 10_000_000,
            timestamp_millis_part,
            shared_gas_limit: 3_000_000,
        };
        let parent = SealedHeader::seal_slow(parent_header);
        let pending_env = TempoNextBlockEnvAttributes::build_pending_env(&parent);

        // Verify gas limits are computed correctly
        let expected_shared_gas_limit = gas_limit / tempo_consensus::TEMPO_SHARED_GAS_DIVISOR;
        assert_eq!(pending_env.shared_gas_limit, expected_shared_gas_limit);

        // general_gas_limit = (gas_limit - shared_gas_limit) / TEMPO_GENERAL_GAS_DIVISOR
        let expected_general_gas_limit =
            (gas_limit - expected_shared_gas_limit) / tempo_consensus::TEMPO_GENERAL_GAS_DIVISOR;
        assert_eq!(pending_env.general_gas_limit, expected_general_gas_limit);

        // Verify timestamp_millis_part is carried from parent
        assert_eq!(pending_env.timestamp_millis_part, timestamp_millis_part);

        // Verify subblock_fee_recipients is empty by default
        assert!(pending_env.subblock_fee_recipients.is_empty());
    }
}
