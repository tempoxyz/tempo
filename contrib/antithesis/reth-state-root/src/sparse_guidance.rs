//! Local-neighbourhood coverage for the Docker-only sparse-trie arena hook.

use std::{
    hint::black_box,
    sync::atomic::{AtomicU64, Ordering},
};

static COUNTERS: [AtomicU64; ARM_COUNT] = [const { AtomicU64::new(0) }; ARM_COUNT];
macro_rules! coverage_arm {
    ($name:ident, $index:literal) => {
        #[inline(never)]
        fn $name(observation: &Observation) {
            // A different address and immediate in every body prevent identical-code folding.
            let counter = black_box(&COUNTERS[$index]);
            let previous = counter.fetch_or(1, Ordering::Relaxed);
            black_box(($index, previous));
            if previous == 0 {
                observation.first_hit($index);
            }
        }
    };
}

include!("sparse_buckets_generated.rs");

struct Observation {
    branch_path_len: usize,
    state_mask: u16,
    revealed_mask: u16,
    leaf_mask: u16,
    proof_target: u8,
    proof_parent: bool,
}

impl Observation {
    fn valid(&self) -> bool {
        self.branch_path_len < 64 &&
            self.revealed_mask & !self.state_mask == 0 &&
            self.leaf_mask & !self.revealed_mask == 0
    }

    fn first_hit(&self, index: usize) {
        // At most ARM_COUNT lines per process, even for arbitrarily many observations.
        if !cfg!(test) {
            eprintln!(
                "sparse_proof_bucket_v1 id={index} depth={} target={} parent={} state={} revealed={} leaf={}",
                self.branch_path_len, self.proof_target, u8::from(self.proof_parent),
                self.state_mask, self.revealed_mask, self.leaf_mask
            );
        }
    }
}

fn depth_bucket(depth: usize) -> u8 {
    match depth {
        0 => 0,
        1 => 1,
        2..=4 => 2,
        5..=8 => 3,
        9..=16 => 4,
        17..=32 => 5,
        _ => 6,
    }
}

fn local_index(observation: &Observation, target: u8) -> usize {
    let mut pattern = 0;
    // No wrapping: out-of-range positions are absent; target nibble remains a dimension.
    for (slot, delta) in [-2i16, -1, 1, 2].into_iter().enumerate() {
        let nibble = i16::from(target) + delta;
        let kind = if !(0..16).contains(&nibble) {
            0
        } else {
            let bit = 1u16 << nibble;
            if observation.state_mask & bit == 0 {
                0
            } else if observation.revealed_mask & bit == 0 {
                1
            } else if observation.leaf_mask & bit == 0 {
                2
            } else {
                3
            }
        };
        pattern |= kind << (slot * 2);
    }
    LOCAL_START +
        (usize::from(depth_bucket(observation.branch_path_len)) * 16 + usize::from(target)) * 256 +
        pattern
}

/// Observes a blinded proof target at sparse-trie proof emission, never at the caller/model.
///
/// Masks describe its local revealed logical parent. A blinded root has no parent and
/// passes zero masks/depth/target; it hits a separate bounded control, not the local bank.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn antithesis_sparse_proof_target(
    branch_path_len: usize,
    has_parent: bool,
    target: u8,
    state_mask: u16,
    revealed_mask: u16,
    leaf_mask: u16,
) {
    let observation = Observation {
        branch_path_len,
        state_mask,
        revealed_mask,
        leaf_mask,
        proof_target: target,
        proof_parent: has_parent,
    };
    if !has_parent {
        if (branch_path_len, target, state_mask, revealed_mask, leaf_mask) == (0, 0, 0, 0, 0) {
            ARMS[NO_PARENT](&observation);
        } else {
            ARMS[INVALID_PROOF](&observation);
        }
        return;
    }
    if !observation.valid() ||
        target >= 16 ||
        state_mask & (1 << target) == 0 ||
        revealed_mask & (1 << target) != 0
    {
        ARMS[INVALID_PROOF](&observation);
        return;
    }
    ARMS[local_index(&observation, target)](&observation);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn generated_mapping_and_proof_controls() {
        // This is the only test that mutates counters, keeping parallel tests independent.
        let observation = Observation {
            branch_path_len: 0,
            state_mask: 0,
            revealed_mask: 0,
            leaf_mask: 0,
            proof_target: 0,
            proof_parent: true,
        };
        assert_eq!(ARMS.len(), 28674);
        assert_eq!(ARMS.iter().map(|f| *f as usize).collect::<HashSet<_>>().len(), ARM_COUNT);
        assert_eq!(ARM_NAMES.iter().collect::<HashSet<_>>().len(), ARM_COUNT);
        assert!(ARM_NAMES[..NO_PARENT].iter().all(|name| name.starts_with("local_")));
        assert_eq!(&ARM_NAMES[NO_PARENT..], &["proof_no_parent", "invalid_proof"]);
        for (index, arm) in ARMS.iter().enumerate() {
            arm(&observation);
            assert_eq!(COUNTERS[index].load(Ordering::Relaxed), 1);
            if index + 1 < ARM_COUNT {
                assert_eq!(COUNTERS[index + 1].load(Ordering::Relaxed), 0);
            }
        }
        for counter in &COUNTERS {
            counter.store(0, Ordering::Relaxed);
        }
        // Controls reject inconsistent parent data, non-blinded targets and invalid subsets.
        for args in [
            (64, true, 5, 32, 0, 0),
            (1, true, 16, 32, 0, 0),
            (1, true, 5, 0, 0, 0),
            (1, true, 5, 32, 32, 0),
            (1, true, 5, 32, 1, 0),
            (1, true, 5, 32, 0, 1),
            (1, false, 0, 0, 0, 0),
        ] {
            let (depth, parent, target, state, revealed, leaf) = args;
            antithesis_sparse_proof_target(depth, parent, target, state, revealed, leaf);
        }
        assert_eq!(COUNTERS[INVALID_PROOF].load(Ordering::Relaxed), 1);
        antithesis_sparse_proof_target(0, false, 0, 0, 0, 0);
        assert_eq!(COUNTERS[NO_PARENT].load(Ordering::Relaxed), 1);
        antithesis_sparse_proof_target(0, true, 5, 1 << 5, 0, 0);
        assert_eq!(COUNTERS[5 * 256].load(Ordering::Relaxed), 1);
        assert_eq!(
            COUNTERS.iter().filter(|counter| counter.load(Ordering::Relaxed) != 0).count(),
            3
        );
    }

    #[test]
    fn exhaustive_local_mapping_and_boundary_padding() {
        for (depth, raw_depth) in [0, 1, 2, 5, 9, 17, 33].into_iter().enumerate() {
            for target in 0..16u8 {
                for assignment in 0..256usize {
                    let mut o = Observation {
                        branch_path_len: raw_depth,
                        state_mask: 1 << target,
                        revealed_mask: 0,
                        leaf_mask: 0,
                        proof_target: target,
                        proof_parent: true,
                    };
                    let mut padded_pattern = 0;
                    for (slot, position) in [
                        i32::from(target) - 2,
                        i32::from(target) - 1,
                        i32::from(target) + 1,
                        i32::from(target) + 2,
                    ]
                    .into_iter()
                    .enumerate()
                    {
                        if !(0..16).contains(&position) {
                            continue;
                        }
                        let kind = (assignment >> (slot * 2)) & 3;
                        padded_pattern |= kind << (slot * 2);
                        if kind > 0 {
                            o.state_mask |= 1 << position;
                        }
                        if kind > 1 {
                            o.revealed_mask |= 1 << position;
                        }
                        if kind > 2 {
                            o.leaf_mask |= 1 << position;
                        }
                    }
                    assert_eq!(
                        local_index(&o, target),
                        LOCAL_START + (depth * 16 + usize::from(target)) * 256 + padded_pattern
                    );
                    // Remote positions must never influence local neighbors.
                    for remote in 0..16i32 {
                        if (remote - i32::from(target)).abs() > 2 {
                            o.state_mask ^= 1 << remote;
                            o.revealed_mask = 0;
                            o.leaf_mask = 0;
                            // Compare with independently reconstructed state-only base-4 code.
                            let expected: usize = [-2i32, -1, 1, 2]
                                .into_iter()
                                .enumerate()
                                .map(|(slot, delta)| {
                                    let bit = i32::from(target) + delta;
                                    if (0..16).contains(&bit) && o.state_mask & (1 << bit) != 0 {
                                        1 << (slot * 2)
                                    } else {
                                        0
                                    }
                                })
                                .sum();
                            assert_eq!(
                                local_index(&o, target),
                                LOCAL_START + (depth * 16 + usize::from(target)) * 256 + expected
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn depth_ladder_boundaries() {
        for depth in 0..64 {
            let expected = [0..=0, 1..=1, 2..=4, 5..=8, 9..=16, 17..=32, 33..=63]
                .iter()
                .position(|range| range.contains(&depth))
                .unwrap();
            assert_eq!(usize::from(depth_bucket(depth)), expected);
        }
    }
}
