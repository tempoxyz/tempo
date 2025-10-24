use reth_evm::{NextBlockEnvAttributes, eth::EthBlockExecutionCtx};

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
        }
    }
}
