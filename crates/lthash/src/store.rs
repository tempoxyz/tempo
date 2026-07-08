//! The two-tier accumulator store.

use crate::{
    accumulator::LthashAccumulator, error::LthashError, overlay::LthashAccumulatorOverlay, tables,
};
use alloy_consensus::BlockHeader as _;
use alloy_eips::eip1898::BlockNumHash;
use alloy_primitives::B256;
use reth_chain_state::ExecutedBlock;
use reth_db_api::{
    cursor::{DbCursorRO, DbCursorRW},
    transaction::{DbTx, DbTxMut},
};
use reth_errors::{ProviderError, ProviderResult};
use reth_primitives_traits::NodePrimitives;
use reth_prune_types::PruneMode;
use reth_storage_api::{DBProvider, DatabaseProviderFactory};
use tracing::{debug, warn};

/// Configuration for the [`LthashStore`].
#[derive(Debug, Clone, Copy)]
pub struct LthashStoreConfig {
    /// Retention policy for persisted accumulator rows, pruned as batches are persisted.
    /// `None` keeps every row.
    pub retention: Option<PruneMode>,
}

impl LthashStoreConfig {
    /// Default number of blocks of persisted accumulators to keep.
    ///
    /// Rows are only ever read to resolve the parent of a block entering the engine, so the
    /// window just needs to comfortably cover the persistence depth plus any reorg margin;
    /// at 2 KiB per row this default caps the table around 200 MiB.
    pub const DEFAULT_RETENTION_DISTANCE: u64 = 100_000;
}

impl Default for LthashStoreConfig {
    fn default() -> Self {
        Self {
            retention: Some(PruneMode::Distance(Self::DEFAULT_RETENTION_DISTANCE)),
        }
    }
}

/// Lthash accumulators of recent and persisted blocks.
///
/// Two tiers behind one interface, mirroring reth's in-memory tree over its canonical tables:
/// an in-memory overlay holds the accumulators of blocks that are validated but not yet
/// persisted, keyed by the state root they hash to so sibling blocks from forks coexist; the
/// [`tables::LthashAccumulators`] table holds one row per persisted canonical height, verified
/// against the parent root on read.
///
/// The state-root task [`record`](Self::record)s results into the overlay, parent resolution
/// goes through [`resolve_parent`](Self::resolve_parent), and the persistence hook calls
/// [`persist`](Self::persist) and [`unwind`](Self::unwind) inside the same transaction that
/// saves or removes the blocks themselves.
#[derive(Debug, Default)]
pub struct LthashStore {
    overlay: LthashAccumulatorOverlay,
    config: LthashStoreConfig,
}

impl LthashStore {
    /// Creates a store with the given configuration.
    pub fn new(config: LthashStoreConfig) -> Self {
        Self {
            overlay: LthashAccumulatorOverlay::default(),
            config,
        }
    }

    /// Records an accumulator under the state root it hashes to.
    pub(crate) fn record(&self, state_root: B256, number: u64, accumulator: LthashAccumulator) {
        self.overlay.insert(state_root, number, accumulator);
    }

    /// Resolves the accumulator whose checksum is the parent block's state root: from the
    /// overlay for recent blocks, from the [`tables::LthashAccumulators`] table for persisted
    /// ones.
    ///
    /// The overlay and the table key accumulators by the root they hash to, so a stored entry
    /// is self-certifying: if the lookup matches the parent root, it is the right accumulator
    /// no matter which fork or code path produced it.
    ///
    /// A parent with no recorded accumulator starts from an empty one, with a warning; see
    /// the TODO on the fallback.
    pub(crate) fn resolve_parent<P>(
        &self,
        provider: &P,
        parent_state_root: B256,
        parent_number: u64,
    ) -> ProviderResult<LthashAccumulator>
    where
        P: DatabaseProviderFactory,
    {
        if let Some(accumulator) = self.overlay.lookup(parent_state_root) {
            return Ok(accumulator);
        }

        let provider = provider.database_provider_ro()?;
        if let Some(value) = provider
            .tx_ref()
            .get::<tables::LthashAccumulators>(parent_number)?
        {
            match tables::decode_accumulator_row(&value) {
                Some((root, bytes)) if root == parent_state_root => {
                    if let Some(accumulator) = LthashAccumulator::from_bytes(bytes) {
                        return Ok(accumulator);
                    }
                }
                Some((root, _)) => {
                    // The canonical row at this height hashes to a different root: the
                    // parent was reorged out after persistence. There is no recovery path
                    // without historical accumulators, so surface an error.
                    return Err(ProviderError::other(LthashError::AccumulatorRootMismatch {
                        parent_state_root,
                        stored_root: root,
                        number: parent_number,
                    }));
                }
                None => {}
            }
            return Err(ProviderError::other(LthashError::AccumulatorCorrupt {
                number: parent_number,
            }));
        }

        // TODO(lthash): benchmarking-only fallback. Starting from an empty accumulator
        // yields roots that are consistent across a fleet whose nodes all start unseeded
        // at the same height, but they are NOT sound commitments to state — and a node
        // joining later with an empty accumulator forks the network. The production path
        // per TIP-1078 "Migration" is:
        //   1. rebuild the accumulator from canonical hashed state at a base block and
        //      persist it as the anchor row (also the recovery path for backfill, snap
        //      sync, and reorg desync);
        //   2. shadow-maintain the accumulator during pre-fork import while MPT remains
        //      the consensus root;
        //   3. make a missing parent accumulator a hard error again — a node without it
        //      must not validate or produce fork blocks.
        // Genesis-active chains additionally need the genesis alloc folded into a seed
        // row at table initialization; commit f9767cb0c carried a working seed_genesis
        // implementation before it was removed in favour of this fallback.
        warn!(
            target: "tempo::lthash",
            ?parent_state_root,
            parent_number,
            "no lthash accumulator for parent, starting from an empty one; roots are not \
             sound state commitments (benchmarking mode)"
        );
        Ok(LthashAccumulator::zero())
    }

    /// Flushes the accumulators of a persisted block batch into the table, prunes table rows
    /// that fell out of the retention window, and prunes the overlay one batch late, so
    /// overlay readers never race the database commit.
    ///
    /// Must run inside the same transaction that saves the blocks, so a row commits
    /// atomically with its block.
    pub(crate) fn persist<N, Tx>(&self, tx: &Tx, blocks: &[ExecutedBlock<N>]) -> ProviderResult<()>
    where
        N: NodePrimitives,
        Tx: DbTxMut,
    {
        let Some(highest) = blocks
            .iter()
            .map(|b| b.recovered_block().num_hash().number)
            .max()
        else {
            return Ok(());
        };
        for block in blocks {
            let num_hash = block.recovered_block().num_hash();
            let state_root = block.recovered_block().header().state_root();
            let Some(bytes) = self.overlay.accumulator_bytes(state_root) else {
                // Expected for blocks validated before the strategy was installed. A gap
                // here otherwise means children of this block cannot resolve their parent
                // accumulator once it leaves the overlay.
                debug!(
                    target: "tempo::lthash",
                    number = num_hash.number,
                    hash = ?num_hash.hash,
                    "no lthash accumulator to persist"
                );
                continue;
            };
            let value = tables::encode_accumulator_row(state_root, &bytes);
            tx.put::<tables::LthashAccumulators>(num_hash.number, value)?;
        }
        if let Some(prune_mode) = self.config.retention {
            self.prune_rows(tx, prune_mode, highest)?;
        }
        self.overlay.on_batch_persisted(highest);
        Ok(())
    }

    /// Deletes table rows outside the retention window for the given tip.
    ///
    /// Rows are height-ordered and deleted oldest-first, so each call pays only for the rows
    /// that expired since the previous batch.
    fn prune_rows<Tx: DbTxMut>(
        &self,
        tx: &Tx,
        prune_mode: PruneMode,
        tip: u64,
    ) -> ProviderResult<usize> {
        let mut cursor = tx.cursor_write::<tables::LthashAccumulators>()?;
        let mut pruned = 0;
        let mut entry = cursor.first()?;
        while let Some((number, _)) = entry {
            if !prune_mode.should_prune(number, tip) {
                break;
            }
            cursor.delete_current()?;
            pruned += 1;
            entry = cursor.next()?;
        }
        Ok(pruned)
    }

    /// Deletes the rows of blocks leaving the database on unwind, in the same transaction,
    /// so stale rows cannot shadow the new chain.
    pub(crate) fn unwind<Tx: DbTxMut>(
        &self,
        tx: &Tx,
        blocks: &[BlockNumHash],
    ) -> ProviderResult<()> {
        for block in blocks {
            tx.delete::<tables::LthashAccumulators>(block.number, None)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_db_api::database::Database;

    fn row(byte: u8) -> Vec<u8> {
        tables::encode_accumulator_row(
            B256::repeat_byte(byte),
            &LthashAccumulator::zero().to_bytes(),
        )
    }

    #[test]
    fn prune_rows_keeps_the_retention_window() {
        let dir = tempfile::tempdir().unwrap();
        let db = reth_db::mdbx::init_db_for::<_, tables::Tables>(
            dir.path(),
            reth_db::mdbx::DatabaseArguments::new(Default::default()),
        )
        .unwrap();
        let store = LthashStore::new(LthashStoreConfig {
            retention: Some(PruneMode::Distance(2)),
        });

        let tx = db.tx_mut().unwrap();
        for number in 1..=5u64 {
            tx.put::<tables::LthashAccumulators>(number, row(number as u8))
                .unwrap();
        }

        // Distance(2) at tip 5 prunes rows strictly below 5 - 2 = 3.
        assert_eq!(store.prune_rows(&tx, PruneMode::Distance(2), 5).unwrap(), 2);
        for number in 1..=2u64 {
            assert!(
                tx.get::<tables::LthashAccumulators>(number)
                    .unwrap()
                    .is_none()
            );
        }
        for number in 3..=5u64 {
            assert!(
                tx.get::<tables::LthashAccumulators>(number)
                    .unwrap()
                    .is_some()
            );
        }

        // A second pass at the same tip finds nothing left to prune.
        assert_eq!(store.prune_rows(&tx, PruneMode::Distance(2), 5).unwrap(), 0);

        // A distance larger than the tip never prunes.
        assert_eq!(
            store.prune_rows(&tx, PruneMode::Distance(10), 5).unwrap(),
            0
        );
        tx.commit().unwrap();
    }
}
