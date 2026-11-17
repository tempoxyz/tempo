//! The zone head that survives a crash.

use reth_stages_types::StageId;
use reth_storage_api::{BlockNumReader, StageCheckpointReader, errors::provider::ProviderResult};

/// Reads the highest zone block this node still holds after a crash.
///
/// [`BlockNumReader::last_block_number`] reads the static-file tip, which reth writes before it
/// commits the MDBX transaction for the same blocks. A block at that tip can still be lost if the
/// process dies before the commit lands, and the node then rebuilds the height with a different
/// hash. The `Finish` stage checkpoint is written inside that MDBX transaction, and its
/// `partial_state_trie` frontier is the height reth unwinds to on restart, so only blocks at or
/// below it may be signed, served to peers or settled.
///
/// Implemented for every provider that can read block numbers and stage checkpoints.
/// A database without a `Finish` checkpoint reports genesis, so callers fail closed.
pub trait DurableBlockReader: BlockNumReader + StageCheckpointReader {
    /// Returns the highest block that survives a crash.
    fn durable_block_number(&self) -> ProviderResult<u64> {
        let frontier = self
            .get_stage_checkpoint(StageId::Finish)?
            .map_or(0, |checkpoint| {
                checkpoint
                    .finish_stage_checkpoint()
                    .and_then(|finish| finish.partial_state_trie())
                    .unwrap_or(checkpoint.block_number)
            });
        Ok(frontier.min(self.last_block_number()?))
    }
}

impl<P: BlockNumReader + StageCheckpointReader + ?Sized> DurableBlockReader for P {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use reth_provider::test_utils::MockEthProvider;
    use reth_stages_types::{FinishCheckpoint, StageCheckpoint};
    use tempo_primitives::{Block, TempoHeader, TempoPrimitives};

    fn provider_with_tip(tip: u64) -> MockEthProvider<TempoPrimitives> {
        let provider = MockEthProvider::<TempoPrimitives>::new();
        for number in 0..=tip {
            let mut header = TempoHeader::default();
            header.inner.number = number;
            provider.add_block(
                B256::with_last_byte(number as u8 + 1),
                Block {
                    header,
                    body: Default::default(),
                },
            );
        }
        provider
    }

    #[test]
    fn missing_checkpoint_reports_genesis() {
        assert_eq!(provider_with_tip(5).durable_block_number().unwrap(), 0);
    }

    #[test]
    fn static_file_tip_ahead_of_commit_is_not_durable() {
        let provider = provider_with_tip(5);
        provider.add_stage_checkpoint(StageId::Finish, StageCheckpoint::new(4));
        assert_eq!(provider.durable_block_number().unwrap(), 4);
    }

    #[test]
    fn partial_state_trie_frontier_bounds_the_durable_tip() {
        let provider = provider_with_tip(5);
        provider.add_stage_checkpoint(
            StageId::Finish,
            StageCheckpoint::new(5).with_finish_stage_checkpoint(FinishCheckpoint {
                partial_state_trie: Some(3),
            }),
        );
        assert_eq!(provider.durable_block_number().unwrap(), 3);
    }

    #[test]
    fn committed_tip_is_durable() {
        let provider = provider_with_tip(5);
        provider.add_stage_checkpoint(StageId::Finish, StageCheckpoint::new(5));
        assert_eq!(provider.durable_block_number().unwrap(), 5);
    }
}
