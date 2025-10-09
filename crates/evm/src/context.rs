use reth_evm::{NextBlockEnvAttributes, eth::EthBlockExecutionCtx};
#[cfg(feature = "rpc")]
use tempo_primitives::TempoHeader;

/// Execution context for Tempo block.
#[derive(Debug, Clone, derive_more::Deref)]
pub struct TempoBlockExecutionCtx<'a> {
    /// Inner [`EthBlockExecutionCtx`].
    #[deref]
    pub inner: EthBlockExecutionCtx<'a>,
    /// Non-payment gas limit for the block.
    pub general_gas_limit: u64,
}

/// Context required for next block environment.
#[derive(Debug, Clone, derive_more::Deref)]
pub struct TempoNextBlockEnvAttributes {
    /// Inner [`NextBlockEnvAttributes`].
    #[deref]
    pub inner: NextBlockEnvAttributes,
    /// Non-payment gas limit for the block.
    pub general_gas_limit: u64,
}

#[cfg(feature = "rpc")]
impl reth_rpc_eth_api::helpers::pending_block::BuildPendingEnv<TempoHeader>
    for TempoNextBlockEnvAttributes
{
    fn build_pending_env(parent: &crate::SealedHeader<TempoHeader>) -> Self {
        use alloy_consensus::BlockHeader as _;

        Self {
            inner: NextBlockEnvAttributes::build_pending_env(parent),
            general_gas_limit: parent.gas_limit() / tempo_consensus::TEMPO_GENERAL_GAS_DIVISOR,
        }
    }
}
