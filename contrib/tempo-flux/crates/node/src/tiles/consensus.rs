use flux::{
    spine::{DCacheRead, SpineAdapter},
    tile::Tile,
};
use tempo_flux_primitives::{Block, BuildRequest, Executed, Finalized, Hash};

use crate::{now_ns, spine::NodeSpine};

/// Single-validator dev consensus: one block per slot, finalized as soon as
/// it executes. The message flow matches what a BFT engine needs (propose,
/// verify via execution, finalize), so the engine can replace this tile
/// without touching the others.
pub struct ConsensusTile {
    pub block_time_ns: u64,
    pub max_txs: u32,
    height: u64,
    head: Hash,
    next_slot_ns: u64,
    inflight: Option<Block>,
    requested_ns: u64,
}

impl ConsensusTile {
    pub fn new(block_time_ms: u64, max_txs: u32) -> Self {
        Self {
            block_time_ns: block_time_ms * 1_000_000,
            max_txs,
            height: 0,
            head: [0; 32],
            next_slot_ns: 0,
            inflight: None,
            requested_ns: 0,
        }
    }
}

impl Tile<NodeSpine> for ConsensusTile {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<NodeSpine>) {
        let inflight = &mut self.inflight;
        adapter.consume_with_dcache::<Block, (), _, _>(
            |_, _| (),
            |res, _| {
                if let DCacheRead::Ok((b, ())) | DCacheRead::NoRef(b) = res {
                    *inflight = Some(b);
                }
            },
        );

        let mut executed = None;
        adapter.consume(|e: Executed, _| executed = Some(e));
        if let (Some(e), Some(b)) = (executed, self.inflight) {
            if e.height == b.height && e.hash == b.hash {
                if e.valid {
                    self.height = b.height;
                    self.head = b.hash;
                    adapter.produce(Finalized {
                        height: b.height,
                        hash: b.hash,
                        state_root: e.state_root,
                        tx_count: b.tx_count,
                        oldest_ingress_ns: b.oldest_ingress_ns,
                    });
                }
                self.inflight = None;
            }
        }

        let now = now_ns();
        // A request sent before the builder attached, or a block whose body or
        // diff was lost on the spine, is never answered; propose again.
        let unanswered =
            self.inflight.is_some() && now - self.requested_ns > 20 * self.block_time_ns;
        if unanswered {
            self.inflight = None;
        }
        if self.inflight.is_none() && now >= self.next_slot_ns {
            self.requested_ns = now;
            self.next_slot_ns = now + self.block_time_ns;
            // Mark the slot as taken until the block comes back.
            self.inflight = Some(Block {
                height: u64::MAX,
                ..Default::default()
            });
            tracing::debug!(height = self.height + 1, "build request");
            adapter.produce(BuildRequest {
                height: self.height + 1,
                parent: self.head,
                timestamp_ms: now / 1_000_000,
                max_txs: self.max_txs,
            });
        }
    }
}
