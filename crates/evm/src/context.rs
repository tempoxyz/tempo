use std::collections::HashMap;

use alloy_evm::eth::EthBlockExecutionCtx;
use alloy_primitives::{Address, B256};
use reth_evm::NextBlockEnvAttributes;
use tempo_contracts::precompiles::TIP_FEE_MANAGER_ADDRESS;
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
        // Use parent's values directly since pending block building is disabled for Tempo
        // (PendingBlockKind::None) - blocks require consensus data that RPC doesn't have.
        let mut inner = NextBlockEnvAttributes::build_pending_env(parent);

        // Use TIP_FEE_MANAGER_ADDRESS as a sentinel fee recipient so the EVM resolves the
        // default fee token (PathUSD) for RPC simulations (eth_call, eth_estimateGas).
        // This address can never be the sender of a transaction, so its validatorTokens
        // mapping is guaranteed to be zero, which falls back to DEFAULT_FEE_TOKEN.
        // NOTE: Address::ZERO cannot be used because genesis maps it to the "DONOTUSE" token.
        inner.suggested_fee_recipient = TIP_FEE_MANAGER_ADDRESS;

        Self {
            inner,
            general_gas_limit: parent.general_gas_limit,
            shared_gas_limit: parent.shared_gas_limit,
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
        };
        let parent = SealedHeader::seal_slow(parent_header);
        let pending_env = TempoNextBlockEnvAttributes::build_pending_env(&parent);

        // Verify values are copied directly from parent
        assert_eq!(pending_env.general_gas_limit, general_gas_limit);
        assert_eq!(pending_env.shared_gas_limit, shared_gas_limit);
        assert_eq!(pending_env.timestamp_millis_part, timestamp_millis_part);
        assert!(pending_env.subblock_fee_recipients.is_empty());
        assert_eq!(
            pending_env.inner.suggested_fee_recipient, TIP_FEE_MANAGER_ADDRESS,
            "pending env uses TIP_FEE_MANAGER_ADDRESS so RPC resolves default fee token"
        );
    }
}
