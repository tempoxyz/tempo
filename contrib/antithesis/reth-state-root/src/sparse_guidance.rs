//! Finite coverage ladders for the Docker-only sparse-trie arena hook.

use std::{
    hint::black_box,
    sync::atomic::{AtomicU64, Ordering},
};

static COUNTERS: [AtomicU64; ARM_COUNT] = [const { AtomicU64::new(0) }; ARM_COUNT];
static OBSERVATIONS: AtomicU64 = AtomicU64::new(0);
static LOGGED_COUNTS: AtomicU64 = AtomicU64::new(0);

// Index the finite exact-triple bank without scanning all 1,120 triples at every request.
const SANDWICH_INDEX: [[[usize; 16]; 16]; 16] = {
    let mut table = [[[usize::MAX; 16]; 16]; 16];
    let mut rank = 0;
    let mut i = 0;
    while i < 16 {
        let mut j = 0;
        while j < 16 {
            let mut k = 0;
            while k < 16 {
                if (i < j && j < k) || (k < j && j < i) {
                    table[i][j][k] = rank;
                    rank += 1;
                }
                k += 1;
            }
            j += 1;
        }
        i += 1;
    }
    table
};

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
    is_root: bool,
    state_mask: u16,
    revealed_mask: u16,
    leaf_mask: u16,
    proof_target: Option<u8>,
    proof_parent: bool,
}

impl Observation {
    fn masks(&self) -> [u16; 5] {
        [
            self.state_mask,
            self.revealed_mask,
            self.leaf_mask,
            self.state_mask & !self.revealed_mask,
            self.revealed_mask & !self.leaf_mask,
        ]
    }

    fn valid(&self) -> bool {
        self.branch_path_len < 64 &&
            self.is_root == (self.branch_path_len == 0) &&
            self.revealed_mask & !self.state_mask == 0 &&
            self.leaf_mask & !self.revealed_mask == 0
    }

    fn first_hit(&self, index: usize) {
        // At most ARM_COUNT lines per process, even for arbitrarily many observations.
        if !cfg!(test) {
            if let Some(target) = self.proof_target {
                eprintln!(
                    "sparse_proof_bucket_v1 id={index} depth={} target={target} parent={} state={} revealed={} leaf={}",
                    self.branch_path_len, u8::from(self.proof_parent), self.state_mask, self.revealed_mask, self.leaf_mask
                );
                return;
            }
            eprintln!(
                "sparse_bucket_v1 id={index} depth={} root={} state={} revealed={} leaf={}",
                self.branch_path_len,
                u8::from(self.is_root),
                self.state_mask,
                self.revealed_mask,
                self.leaf_mask
            );
        }
    }
}

fn count_bucket(mask: u16) -> u8 {
    match mask.count_ones() {
        0 => 0,
        1 => 1,
        2..=4 => 2,
        5..=8 => 3,
        _ => 4,
    }
}

fn shape_bucket(mask: u16) -> u8 {
    match mask {
        0 => 0,
        u16::MAX => 4,
        _ if mask.is_power_of_two() => 1,
        _ => {
            let shifted = u32::from(mask) >> mask.trailing_zeros();
            if shifted & (shifted + 1) == 0 {
                2
            } else {
                3
            }
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

/// Receives one dirty branch at RLP encoding in the Docker-patched Reth arena.
///
/// State means occupied children; revealed means arena-backed; leaf means a revealed
/// leaf, including lower-subtrie leaf roots. All masks use nibble positions.
#[unsafe(no_mangle)]
pub extern "C" fn antithesis_sparse_branch_shape(
    branch_path_len: usize,
    is_root: bool,
    state_mask: u16,
    revealed_mask: u16,
    leaf_mask: u16,
) {
    let observation = Observation {
        branch_path_len,
        is_root,
        state_mask,
        revealed_mask,
        leaf_mask,
        proof_target: None,
        proof_parent: true,
    };
    if !observation.valid() {
        coverage_invalid_observation(&observation);
        return;
    }
    let count = OBSERVATIONS.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    if count.is_power_of_two() && !cfg!(test) {
        let bit = 1u64 << count.trailing_zeros();
        if LOGGED_COUNTS.fetch_or(bit, Ordering::Relaxed) & bit == 0 {
            eprintln!("sparse_observations_v1 count={count}");
        }
    }
    dispatch(&observation);
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
/// passes zero masks/depth/target; it hits a separate bounded control, not either bank.
#[unsafe(no_mangle)]
pub extern "C" fn antithesis_sparse_proof_target(
    branch_path_len: usize,
    has_parent: bool,
    target: u8,
    state_mask: u16,
    revealed_mask: u16,
    leaf_mask: u16,
) {
    let observation = Observation {
        branch_path_len,
        is_root: branch_path_len == 0,
        state_mask,
        revealed_mask,
        leaf_mask,
        proof_target: Some(target),
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
    let depth = usize::from(depth_bucket(branch_path_len));
    for j in 0..16 {
        if revealed_mask & (1 << j) == 0 {
            continue;
        }
        for k in 0..16 {
            if state_mask & !revealed_mask & (1 << k) == 0 {
                continue;
            }
            let rank = SANDWICH_INDEX[usize::from(target)][j][k];
            if rank != usize::MAX {
                let leaf = usize::from(leaf_mask & (1 << j) != 0);
                ARMS[SANDWICH_START + (depth * 1120 + rank) * 2 + leaf](&observation);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn exhaustive_mask_classification() {
        for mask in 0..=u16::MAX {
            let bits: Vec<_> = (0..16).filter(|bit| mask & (1 << bit) != 0).collect();
            let count = bits.len();
            let expected_count = match count {
                0 => 0,
                1 => 1,
                2..=4 => 2,
                5..=8 => 3,
                _ => 4,
            };
            let expected_shape = match count {
                0 => 0,
                1 => 1,
                16 => 4,
                _ if bits.windows(2).all(|pair| pair[1] == pair[0] + 1) => 2,
                _ => 3,
            };
            assert_eq!(count_bucket(mask), expected_count, "{mask:04x}");
            assert_eq!(shape_bucket(mask), expected_shape, "{mask:04x}");
        }
    }

    #[test]
    fn generated_mapping_relationships_and_all_arms() {
        // This is the only test that mutates counters, keeping parallel tests independent.
        let observation = Observation {
            branch_path_len: 0,
            is_root: true,
            state_mask: 0,
            revealed_mask: 0,
            leaf_mask: 0,
            proof_target: None,
            proof_parent: true,
        };
        assert_eq!(ARMS.len(), 44898);
        assert_eq!(ARMS.iter().map(|f| *f as usize).collect::<HashSet<_>>().len(), ARM_COUNT);
        assert_eq!(ARM_NAMES.iter().collect::<HashSet<_>>().len(), ARM_COUNT);
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
        // Every valid subset triple on eight positions, translated to both halves of the
        // nibble space (4^8 assignments). Full sixteen-position patterns cover large counts.
        for assignment in 0..65536u32 {
            for offset in [0, 8] {
                let (mut state, mut revealed, mut leaf) = (0, 0, 0);
                for bit in 0..8 {
                    let kind = (assignment >> (bit * 2)) & 3;
                    if kind >= 1 {
                        state |= 1 << (bit + offset);
                    }
                    if kind >= 2 {
                        revealed |= 1 << (bit + offset);
                    }
                    if kind == 3 {
                        leaf |= 1 << (bit + offset);
                    }
                }
                let o = Observation {
                    branch_path_len: 4,
                    is_root: false,
                    state_mask: state,
                    revealed_mask: revealed,
                    leaf_mask: leaf,
                    proof_target: None,
                    proof_parent: true,
                };
                assert!(o.valid());
                let masks = o.masks();
                assert_eq!(masks[3] & masks[4], 0);
                assert_eq!(masks[3] | masks[4] | leaf, state);
                dispatch(&o);
            }
        }
        // Exhaust every sixteen-bit mask for each relationship and every depth.
        for mask in 0..=u16::MAX {
            for (state, revealed, leaf) in [
                (mask, 0, 0),
                (mask, mask, 0),
                (mask, mask, mask),
                (u16::MAX, mask, 0),
                (u16::MAX, u16::MAX, mask),
            ] {
                for depth in [0, 1, 2, 5, 9, 17, 33, 63] {
                    let o = Observation {
                        branch_path_len: depth,
                        is_root: depth == 0,
                        state_mask: state,
                        revealed_mask: revealed,
                        leaf_mask: leaf,
                        proof_target: None,
                        proof_parent: true,
                    };
                    assert!(o.valid());
                    dispatch(&o);
                }
            }
        }
        // Exercise all ordered count triples and disjoint relationship count pairs.
        for state in 0..=16 {
            for revealed in 0..=state {
                for leaf in 0..=revealed {
                    let mask = |n| ((1u32 << n) - 1u32) as u16;
                    for depth in [0, 1] {
                        dispatch(&Observation {
                            branch_path_len: depth,
                            is_root: depth == 0,
                            state_mask: mask(state),
                            revealed_mask: mask(revealed),
                            leaf_mask: mask(leaf),
                            proof_target: None,
                            proof_parent: true,
                        });
                    }
                }
            }
        }
        assert_eq!(COUNTERS[ENCODER_COUNT - 1].load(Ordering::Relaxed), 0);
        for (index, counter) in COUNTERS[..ENCODER_COUNT - 1].iter().enumerate() {
            assert!(
                counter.load(Ordering::Relaxed) > 0,
                "Unreached generated arm {}",
                ARM_NAMES[index]
            );
        }
        for (depth, root, state, revealed, leaf) in [
            (64, false, 0, 0, 0),
            (0, false, 0, 0, 0),
            (1, true, 0, 0, 0),
            (1, false, 0, 1, 0),
            (1, false, 1, 0, 1),
        ] {
            antithesis_sparse_branch_shape(depth, root, state, revealed, leaf);
        }
        assert_eq!(COUNTERS[ENCODER_COUNT - 1].load(Ordering::Relaxed), 1);
        // Exact ordered target/revealed/blinded triples in both directions, both leaf states.
        let mut rank = 0;
        for i in 0..16u8 {
            for j in 0..16u8 {
                for k in 0..16u8 {
                    let between = (i < j && j < k) || (k < j && j < i);
                    if !between {
                        continue;
                    }
                    assert_eq!(
                        SANDWICH_INDEX[usize::from(i)][usize::from(j)][usize::from(k)],
                        rank
                    );
                    for (depth, raw_depth) in [0, 1, 2, 5, 9, 17, 33].into_iter().enumerate() {
                        for leaf in 0..2 {
                            let index = SANDWICH_START + (depth * 1120 + rank) * 2 + leaf;
                            assert_eq!(COUNTERS[index].load(Ordering::Relaxed), 0);
                            antithesis_sparse_proof_target(
                                raw_depth,
                                true,
                                i,
                                (1 << i) | (1 << j) | (1 << k),
                                1 << j,
                                if leaf == 1 { 1 << j } else { 0 },
                            );
                            assert_eq!(COUNTERS[index].load(Ordering::Relaxed), 1);
                        }
                    }
                    rank += 1;
                }
            }
        }
        assert_eq!(rank, 1120);
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
    }

    #[test]
    fn exhaustive_local_mapping_and_boundary_padding() {
        for (depth, raw_depth) in [0, 1, 2, 5, 9, 17, 33].into_iter().enumerate() {
            for target in 0..16u8 {
                for assignment in 0..256usize {
                    let mut o = Observation {
                        branch_path_len: raw_depth,
                        is_root: raw_depth == 0,
                        state_mask: 1 << target,
                        revealed_mask: 0,
                        leaf_mask: 0,
                        proof_target: Some(target),
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
