//! Expiry burst and snapshot destruction costs. Shared cases retain a parent
//! snapshot, as normal block execution does; unique cases own the last reference.
use alloy_primitives::{B256, keccak256};
use std::{hint::black_box, time::Instant};
use tempo_expiring_nonces::ExpiringNonceState;

fn percentile(values: &mut [f64], percentile: usize) -> f64 {
    values.sort_by(f64::total_cmp);
    values[(values.len() * percentile / 100).min(values.len() - 1)]
}

fn main() {
    let repetitions = std::env::var("TEMPO_NONCE_LIFECYCLE_REPEATS")
        .map_or(8, |value| value.parse::<usize>().unwrap());
    assert!(repetitions > 0);
    let ids: Vec<B256> = (0..300_000u64)
        .map(|id| keccak256(id.to_be_bytes()))
        .collect();
    for live in [30_000, 100_000, 300_000] {
        for expired in [live / 10, live * 9 / 10, live] {
            for shared in [false, true] {
                let mut advance = Vec::new();
                let mut destroy = Vec::new();
                let mut roots = Vec::new();
                for _ in 0..repetitions {
                    let mut state = ExpiringNonceState::default();
                    state.advance(1000).unwrap();
                    for (index, id) in ids[..live].iter().enumerate() {
                        state
                            .insert(
                                *id,
                                if index < expired { 1010 } else { 1300 },
                                300,
                                3_000_000,
                            )
                            .unwrap();
                    }
                    let parent = shared.then(|| state.clone());
                    let start = Instant::now();
                    state.advance(1010).unwrap();
                    advance.push(start.elapsed().as_secs_f64() * 1000.0);
                    assert_eq!(state.len(), live - expired);
                    let start = Instant::now();
                    black_box(state.root());
                    roots.push(start.elapsed().as_secs_f64() * 1000.0);
                    let start = Instant::now();
                    drop(state);
                    drop(parent);
                    destroy.push(start.elapsed().as_secs_f64() * 1000.0);
                }
                println!(
                    "{{\"live\":{live},\"expired\":{expired},\"shared\":{shared},\"repeats\":{repetitions},\"advance_p50_ms\":{:.6},\"advance_p99_ms\":{:.6},\"drop_p50_ms\":{:.6},\"root_p50_ms\":{:.6}}}",
                    percentile(&mut advance, 50),
                    percentile(&mut advance, 99),
                    percentile(&mut destroy, 50),
                    percentile(&mut roots, 50)
                );
            }
        }
    }
}
