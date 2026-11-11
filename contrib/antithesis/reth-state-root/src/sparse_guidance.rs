//! Finite coverage ladders for the Docker-only sparse-trie arena hook.

use std::{
    hint::black_box,
    sync::atomic::{AtomicU64, Ordering},
};

static COUNTERS: [AtomicU64; ARM_COUNT] = [const { AtomicU64::new(0) }; ARM_COUNT];
static OBSERVATIONS: AtomicU64 = AtomicU64::new(0);
static LOGGED_COUNTS: AtomicU64 = AtomicU64::new(0);

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
    let observation =
        Observation { branch_path_len, is_root, state_mask, revealed_mask, leaf_mask };
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
        };
        assert_eq!(ARMS.len(), 544);
        assert_eq!(ARMS.iter().map(|f| *f as usize).collect::<HashSet<_>>().len(), ARM_COUNT);
        assert_eq!(ARM_NAMES.iter().collect::<HashSet<_>>().len(), ARM_COUNT);
        for (index, arm) in ARMS.iter().enumerate() {
            arm(&observation);
            for (slot, counter) in COUNTERS.iter().enumerate() {
                assert_eq!(counter.load(Ordering::Relaxed), u64::from(slot <= index));
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
                        });
                    }
                }
            }
        }
        assert_eq!(COUNTERS[ARM_COUNT - 1].load(Ordering::Relaxed), 0);
        for (index, counter) in COUNTERS[..ARM_COUNT - 1].iter().enumerate() {
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
        assert_eq!(COUNTERS[ARM_COUNT - 1].load(Ordering::Relaxed), 1);
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
