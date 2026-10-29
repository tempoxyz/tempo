use flux::{spine::SpineAdapter, tile::Tile};
use tempo_flux_primitives::RawTx;

use crate::{now_ns, spine::NodeSpine};

/// Stand-in for p2p and RPC ingress: replays presigned transactions at a
/// fixed rate.
pub struct LoadgenTile {
    pub txs: Vec<Vec<u8>>,
    pub tps: u64,
    sent: usize,
    start_ns: u64,
}

impl LoadgenTile {
    pub fn new(txs: Vec<Vec<u8>>, tps: u64) -> Self {
        Self {
            txs,
            tps,
            sent: 0,
            start_ns: 0,
        }
    }
}

impl Tile<NodeSpine> for LoadgenTile {
    fn try_init(&mut self, _adapter: &mut SpineAdapter<NodeSpine>) -> bool {
        self.start_ns = now_ns();
        true
    }

    fn loop_body(&mut self, adapter: &mut SpineAdapter<NodeSpine>) {
        if self.sent >= self.txs.len() {
            return;
        }
        let now = now_ns();
        let due = ((now - self.start_ns) as u128 * self.tps as u128 / 1_000_000_000) as usize;
        let due = due.min(self.txs.len());
        while self.sent < due {
            let tx = &self.txs[self.sent];
            let _ = adapter.produce_with_dcache(
                RawTx { ingress_ns: now },
                Some((tx.len(), |buf: &mut [u8]| buf.copy_from_slice(tx))),
            );
            self.sent += 1;
        }
    }
}
