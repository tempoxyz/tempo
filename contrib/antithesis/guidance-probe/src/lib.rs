//! Pure state/label logic; no SDK assertions or instrumentation.

/// A bijection of 0..64, deliberately unrelated to state depth/order.
pub const LABELS: [&str; 64] = [
    "13", "38", "1d", "02", "27", "0c", "31", "16", "3b", "20", "05", "2a", "0f", "34", "19", "3e",
    "23", "08", "2d", "12", "37", "1c", "01", "26", "0b", "30", "15", "3a", "1f", "04", "29", "0e",
    "33", "18", "3d", "22", "07", "2c", "11", "36", "1b", "00", "25", "0a", "2f", "14", "39", "1e",
    "03", "28", "0d", "32", "17", "3c", "21", "06", "2b", "10", "35", "1a", "3f", "24", "09", "2e",
];

/// For uniform draw, advance with probability 3/4, otherwise reset. Cap at 63.
/// `state` must be in 0..64. Release disassembly checks guard the branchless design.
#[inline(never)]
pub fn transition(state: u8, draw: u64) -> u8 {
    let capped = state + u8::from(state < 63);
    capped * u8::from((draw & 3) != 0)
}

/// State machine whose mode changes only the emitted label, never its transitions.
#[derive(Clone, Copy, Debug)]
pub struct Probe {
    state: u8,
    label_mask: u8,
}

impl Probe {
    /// Starts at state zero; resolve `dynamic` once before setup completes.
    /// Constant mode always returns the state-zero label.
    pub fn new(dynamic: bool) -> Self {
        Self {
            state: 0,
            label_mask: 63 * u8::from(dynamic),
        }
    }

    /// Consumes one draw and returns the new state plus its mode-selected label.
    /// For uniform draws, advances with probability 3/4 (capped at 63), else resets.
    #[inline(never)]
    pub fn step(&mut self, draw: u64) -> (u8, &'static str) {
        self.state = transition(self.state, draw);
        (
            self.state,
            LABELS[usize::from(self.state & self.label_mask & 63)],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn all_state_transitions_and_three_quarter_probability() {
        for state in 0..64 {
            for residue in 0..4_u64 {
                let expected = if residue == 0 { 0 } else { (state + 1).min(63) };
                for upper in [0, 1 << 32, !3_u64] {
                    assert_eq!(transition(state, upper | residue), expected);
                }
            }
        }
    }

    #[test]
    fn cap_and_reset() {
        let mut p = Probe::new(true);
        for i in 1..=100 {
            assert_eq!(p.step(1).0, i.min(63));
        }
        assert_eq!(p.step(0).0, 0);
        assert_eq!(p.step(3).0, 1);
    }

    #[test]
    fn labels_are_fixed_width_nonmonotonic_permutation() {
        assert_eq!(LABELS.iter().collect::<HashSet<_>>().len(), 64);
        let values: Vec<_> = LABELS
            .iter()
            .map(|label| {
                assert_eq!(label.len(), 2);
                u8::from_str_radix(label, 16).unwrap()
            })
            .collect();
        assert_eq!(
            values.iter().copied().collect::<HashSet<_>>(),
            (0..64).collect()
        );
        assert!(values.windows(2).any(|v| v[0] > v[1]));
        assert!(values.windows(2).any(|v| v[0] < v[1]));
    }

    #[test]
    fn modes_have_identical_actual_traces_for_same_tape() {
        let mut dynamic = Probe::new(true);
        let mut constant = Probe::new(false);
        let tape = (0..100).map(|_| 3).chain([0, 1, 2, 3, 4, u64::MAX]);
        let mut differing_labels = 0;
        for draw in tape {
            let (ds, dl) = dynamic.step(draw);
            let (cs, cl) = constant.step(draw);
            assert_eq!(ds, cs);
            assert_eq!(dl, LABELS[usize::from(ds)]);
            assert_eq!(cl, LABELS[0]);
            assert_eq!(dl.len(), cl.len());
            differing_labels += usize::from(dl != cl);
        }
        assert!(differing_labels > 0);
    }
}
