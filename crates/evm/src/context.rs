use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::ExpiringNonceEntry;
use alloy_evm::eth::EthBlockExecutionCtx;
use alloy_primitives::{Address, B256};
use reth_evm::NextBlockEnvAttributes;
use tempo_primitives::{TempoConsensusContext, subblock::PartialValidatorKey};

/// Replay entries committed while constructing one local payload.
///
/// The block builder clones the execution context before creating the executor, so this overlay
/// provides a direct handoff to the assembler without storing unsealed payloads in global replay
/// history.
#[derive(Debug, Clone, Default)]
pub struct ExpiringNonceBlockOverlay {
    entries: Arc<Mutex<Vec<ExpiringNonceEntry>>>,
}

impl ExpiringNonceBlockOverlay {
    /// Publishes the entries committed by the block executor.
    pub(crate) fn publish(&self, entries: Vec<ExpiringNonceEntry>) {
        *self
            .entries
            .lock()
            .expect("expiring nonce block overlay lock poisoned") = entries;
    }

    /// Takes the committed entries when assembling the sealed block.
    pub(crate) fn take(&self) -> Vec<ExpiringNonceEntry> {
        std::mem::take(
            &mut *self
                .entries
                .lock()
                .expect("expiring nonce block overlay lock poisoned"),
        )
    }

    /// Benchmark-only access to the block overlay handoff.
    #[cfg(feature = "bench")]
    #[doc(hidden)]
    pub fn bench_publish(&self, entries: Vec<ExpiringNonceEntry>) {
        self.publish(entries);
    }

    /// Benchmark-only access to the block overlay handoff.
    #[cfg(feature = "bench")]
    #[doc(hidden)]
    pub fn bench_take(&self) -> Vec<ExpiringNonceEntry> {
        self.take()
    }
}

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
    /// Consensus metadata for the block. `None` for pre-fork blocks.
    pub consensus_context: Option<TempoConsensusContext>,
    /// Mapping from a subblock validator public key to the fee recipient configured.
    ///
    /// Used to provide EVM with the fee recipient context when executing subblock transactions.
    pub subblock_fee_recipients: HashMap<PartialValidatorKey, Address>,
    /// Hash of the block being executed, when it is already sealed.
    ///
    /// Payload construction leaves this unset and records replay history when the built block is
    /// later imported.
    pub block_hash: Option<B256>,
    /// Per-build handoff for expiring nonce entries committed by the executor.
    pub expiring_nonce_overlay: ExpiringNonceBlockOverlay,
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
    /// Mapping from a subblock validator public key to the fee recipient configured.
    pub subblock_fee_recipients: HashMap<PartialValidatorKey, Address>,
}

#[cfg(feature = "rpc")]
impl reth_rpc_eth_api::helpers::pending_block::BuildPendingEnv<tempo_primitives::TempoHeader>
    for TempoNextBlockEnvAttributes
{
    fn build_pending_env(
        parent: &crate::SealedHeader<tempo_primitives::TempoHeader>,
        block_overrides: Option<&alloy_rpc_types_eth::BlockOverrides>,
    ) -> Self {
        Self {
            inner: NextBlockEnvAttributes::build_pending_env(parent, block_overrides),
            general_gas_limit: parent.general_gas_limit,
            shared_gas_limit: parent.shared_gas_limit,
            timestamp_millis_part: parent.timestamp_millis_part,
            consensus_context: None,
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
            ..Default::default()
        };
        let parent = SealedHeader::seal_slow(parent_header);
        let pending_env = TempoNextBlockEnvAttributes::build_pending_env(&parent, None);

        // Verify values are copied directly from parent
        assert_eq!(pending_env.general_gas_limit, general_gas_limit);
        assert_eq!(pending_env.shared_gas_limit, shared_gas_limit);
        assert_eq!(pending_env.timestamp_millis_part, timestamp_millis_part);
        assert!(pending_env.subblock_fee_recipients.is_empty());
    }

    #[test]
    fn block_overlay_hands_entries_to_assembler_once() {
        let overlay = ExpiringNonceBlockOverlay::default();
        let entry = ExpiringNonceEntry {
            replay_id: B256::repeat_byte(1),
            valid_before: 300,
        };

        overlay.publish(vec![entry]);

        assert_eq!(overlay.take(), vec![entry]);
        assert!(overlay.take().is_empty());
    }
}
