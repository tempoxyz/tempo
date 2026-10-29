use std::collections::BTreeMap;

use flux::{
    spine::{DCacheRead, SpineAdapter},
    tile::Tile,
};
use rustc_hash::FxHashMap;
use tempo_flux_primitives::{Address, Block, BuildRequest, Hash, ValidTx, body};

use crate::spine::NodeSpine;

struct PendingTx {
    hash: Hash,
    ingress_ns: u64,
    bytes: Vec<u8>,
}

/// Holds the pending pool and assembles blocks when consensus asks.
#[derive(Default)]
pub struct BuilderTile {
    by_sender: FxHashMap<Address, BTreeMap<u64, PendingTx>>,
    next_nonce: FxHashMap<Address, u64>,
    pooled: usize,
    picked: Vec<(Address, u64)>,
}

impl BuilderTile {
    fn insert(&mut self, tx: ValidTx, bytes: &[u8]) {
        let base = self.next_nonce.get(&tx.sender).copied().unwrap_or(0);
        if tx.nonce < base {
            return;
        }
        let slot = self.by_sender.entry(tx.sender).or_default();
        if slot
            .insert(
                tx.nonce,
                PendingTx {
                    hash: tx.hash,
                    ingress_ns: tx.ingress_ns,
                    bytes: bytes.to_vec(),
                },
            )
            .is_none()
        {
            self.pooled += 1;
        }
    }

    fn build(&mut self, req: BuildRequest, adapter: &mut SpineAdapter<NodeSpine>) {
        tracing::debug!(req.height, pooled = self.pooled, "building");
        self.picked.clear();
        let max = req.max_txs as usize;
        for (sender, txs) in &self.by_sender {
            let mut nonce = self.next_nonce.get(sender).copied().unwrap_or(0);
            while self.picked.len() < max && txs.contains_key(&nonce) {
                self.picked.push((*sender, nonce));
                nonce += 1;
            }
            if self.picked.len() >= max {
                break;
            }
        }

        let mut oldest = u64::MAX;
        let mut hasher = alloy_primitives::Keccak256::new();
        hasher.update(req.height.to_be_bytes());
        hasher.update(req.parent);
        let txs: Vec<(&Address, &PendingTx)> = self
            .picked
            .iter()
            .map(|(s, n)| (s, &self.by_sender[s][n]))
            .collect();
        for (_, tx) in &txs {
            hasher.update(tx.hash);
            oldest = oldest.min(tx.ingress_ns);
        }
        let block = Block {
            height: req.height,
            parent: req.parent,
            hash: hasher.finalize().0,
            timestamp_ms: req.timestamp_ms,
            tx_count: txs.len() as u32,
            oldest_ingress_ns: if txs.is_empty() { 0 } else { oldest },
        };
        let len = body::encoded_len(txs.iter().map(|(s, t)| (*s, t.bytes.as_slice())));
        let payload = (len > 0).then_some((len, |buf: &mut [u8]| {
            body::write(buf, txs.iter().map(|(s, t)| (*s, t.bytes.as_slice())));
        }));
        adapter
            .produce_with_dcache(block, payload)
            .expect("block body fits the dcache");

        for (sender, nonce) in &self.picked {
            if let Some(txs) = self.by_sender.get_mut(sender) {
                txs.remove(nonce);
                if txs.is_empty() {
                    self.by_sender.remove(sender);
                }
            }
            self.next_nonce.insert(*sender, nonce + 1);
            self.pooled -= 1;
        }
    }
}

impl Tile<NodeSpine> for BuilderTile {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<NodeSpine>) {
        let mut incoming: Vec<(ValidTx, Vec<u8>)> = Vec::new();
        adapter.consume_with_dcache::<ValidTx, Vec<u8>, _, _>(
            |_, bytes| bytes.to_vec(),
            |res, _| match res {
                DCacheRead::Ok((tx, bytes)) => incoming.push((tx, bytes)),
                other => {
                    let lost = matches!(other, DCacheRead::SpedPast);
                    tracing::warn!(sped_past = lost, "builder dropped a pooled tx");
                }
            },
        );
        for (tx, bytes) in incoming {
            self.insert(tx, &bytes);
        }

        let mut req = None;
        adapter.consume(|r: BuildRequest, _| req = Some(r));
        if let Some(r) = req {
            self.build(r, adapter);
        }
    }
}
