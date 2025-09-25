use reth_evm::{NextBlockEnvAttributes, eth::EthBlockExecutionCtx};

/// Execution context for Tempo block.
#[derive(Debug, Clone, derive_more::Deref)]
pub struct TempoBlockExecutionCtx<'a> {
    /// Inner [`EthBlockExecutionCtx`].
    #[deref]
    pub inner: EthBlockExecutionCtx<'a>,
    /// Non-payment gas limit for the block.
    pub non_payment_gas_limit: u64,
}

/// Context required for next block environment.
#[derive(Debug, Clone, derive_more::Deref)]
pub struct TempoNextBlockEnvAttributes {
    /// Inner [`NextBlockEnvAttributes`].
    #[deref]
    pub inner: NextBlockEnvAttributes,
    /// Non-payment gas limit for the block.
    pub non_payment_gas_limit: u64,
}

#[cfg(feature = "rpc")]
impl reth_rpc_eth_api::helpers::pending_block::BuildPendingEnv<alloy_consensus::Header>
    for TempoNextBlockEnvAttributes
{
    fn build_pending_env(parent: &crate::SealedHeader) -> Self {
        Self {
            inner: NextBlockEnvAttributes::build_pending_env(parent),
            non_payment_gas_limit: parent.gas_limit
                / tempo_consensus::TEMPO_NON_PAYMENT_GAS_DIVISOR,
        }
    }
}
