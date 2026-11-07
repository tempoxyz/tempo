pub mod spine;
pub mod tempo;
pub mod tiles;
pub mod trie;

pub fn now_ns() -> u64 {
    flux_timing::Nanos::now().0
}

pub fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = alloy_primitives::Keccak256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().0
}
