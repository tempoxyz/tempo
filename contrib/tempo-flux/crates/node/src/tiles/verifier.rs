use alloy_consensus::{
    Transaction,
    transaction::{SignerRecoverable, TxHashRef},
};
use alloy_eips::eip2718::Decodable2718;
use flux::{
    spine::{DCacheRead, SpineAdapter, SpineProducers},
    tile::Tile,
};
use tempo_flux_primitives::{RawTx, ValidTx};
use tempo_primitives::TempoTxEnvelope;

use crate::spine::NodeSpine;

const GROUP: &str = "verifier";

pub static DROPPED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Decodes Tempo transactions (including 0x76 AA with secp256k1, P256 and
/// WebAuthn signatures) and recovers their senders. Verifier tiles share the
/// `RawTx` queue as one collaborative group, so recovery scales with cores.
#[derive(Default)]
pub struct VerifierTile {
    pub index: usize,
    pub rejected: u64,
}

impl Tile<NodeSpine> for VerifierTile {
    fn on_attach(&mut self, adapter: &mut SpineAdapter<NodeSpine>) {
        adapter.set_collaborative_group_dcache::<RawTx>(GROUP);
    }

    fn loop_body(&mut self, adapter: &mut SpineAdapter<NodeSpine>) {
        let mut rejected = 0;
        while adapter.consume_with_dcache_collaborative::<RawTx, (), _, _>(
            |raw, mut bytes, producers| {
                let encoded = bytes;
                let Ok(tx) = TempoTxEnvelope::decode_2718(&mut bytes) else {
                    rejected += 1;
                    return;
                };
                let Ok(sender) = tx.recover_signer() else {
                    rejected += 1;
                    return;
                };
                let valid = ValidTx {
                    hash: tx.tx_hash().0,
                    sender: sender.0.0,
                    nonce: tx.nonce(),
                    priority_fee: tx.max_priority_fee_per_gas().unwrap_or_default() as u64,
                    ingress_ns: raw.ingress_ns,
                };
                let _ = producers.produce_with_dcache(
                    valid,
                    Some((encoded.len(), |buf: &mut [u8]| buf.copy_from_slice(encoded))),
                );
            },
            |res, _| {
                if !matches!(res, DCacheRead::Ok(_)) {
                    tracing::warn!("verifier dropped a raw tx");
                    DROPPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            },
        ) {}
        self.rejected += rejected;
    }

    fn name(&self) -> flux::tile::TileName {
        flux::tile::TileName::from_str_truncate(&format!("verifier-{}", self.index))
    }
}
