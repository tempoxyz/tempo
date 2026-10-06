use alloy_evm::eth::EthBlockExecutionCtx;
use reth_evm::NextBlockEnvAttributes;
use tempo_primitives::TempoConsensusContext;

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
    /// Consensus metadata for the block. `None` for pre-fork blocks.
    pub consensus_context: Option<TempoConsensusContext>,
    /// Expected replay-state commitment when validating an existing block.
    pub expiring_nonce_root: Option<alloy_primitives::B256>,
    /// Hash of the block being validated, absent while building a new block.
    pub block_hash: Option<alloy_primitives::B256>,
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
    /// Consensus context
    pub consensus_context: Option<TempoConsensusContext>,
}

#[cfg(feature = "rpc")]
impl reth_rpc_eth_api::helpers::pending_block::BuildPendingEnv<tempo_primitives::TempoHeader>
    for TempoNextBlockEnvAttributes
{
    fn build_pending_env(
        parent: &crate::SealedHeader<tempo_primitives::TempoHeader>,
        block_overrides: Option<&alloy_rpc_types_eth::BlockOverrides>,
    ) -> Self {
        let mut inner = NextBlockEnvAttributes::build_pending_env(parent, block_overrides);
        // Reth applies RPC block overrides after creating the EVM environment.
        // Replay protection must expire entries at the simulated time as well.
        if let Some(timestamp) = block_overrides.and_then(|overrides| overrides.time) {
            inner.timestamp = timestamp;
        }
        Self {
            inner,
            general_gas_limit: parent.general_gas_limit,
            shared_gas_limit: parent.shared_gas_limit,
            timestamp_millis_part: parent.timestamp_millis_part,
            consensus_context: None,
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
    fn test_build_pending_env_uses_parent_values() {
        // Pending env uses parent's values directly since pending blocks are disabled
        let gas_limit = 500_000_000u64;
        let timestamp_millis_part = 500u64;
        let general_gas_limit = 30_000_000u64;
        let shared_gas_limit = 250_000_000u64;
        let parent_header = TempoHeader {
            inner: alloy_consensus::Header {
                number: 10,
                timestamp: 1000,
                gas_limit,
                ..Default::default()
            },
            general_gas_limit,
            timestamp_millis_part,
            shared_gas_limit,
            ..Default::default()
        };
        let parent = SealedHeader::seal_slow(parent_header);
        let pending_env = TempoNextBlockEnvAttributes::build_pending_env(&parent, None);

        // Verify values are copied directly from parent
        assert_eq!(pending_env.general_gas_limit, general_gas_limit);
        assert_eq!(pending_env.shared_gas_limit, shared_gas_limit);
        assert_eq!(pending_env.timestamp_millis_part, timestamp_millis_part);
    }

    #[test]
    fn pending_nonce_state_uses_the_simulation_timestamp() {
        let parent = SealedHeader::seal_slow(TempoHeader {
            inner: alloy_consensus::Header {
                timestamp: 1000,
                ..Default::default()
            },
            ..Default::default()
        });
        let overrides = alloy_rpc_types_eth::BlockOverrides {
            time: Some(1001),
            ..Default::default()
        };
        let attributes = TempoNextBlockEnvAttributes::build_pending_env(&parent, Some(&overrides));
        assert_eq!(attributes.timestamp, 1001);
    }
}
