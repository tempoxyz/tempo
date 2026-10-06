//! circomlib-compatible Poseidon over the BN254 scalar field.
//!
//! Uses circomlib's optimized constants, which replace the dense MDS matrix in partial rounds
//! with sparse matrices. The output equals circomlib's `Poseidon(n)` template.

mod constants_t8;

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field};

/// Full rounds, split evenly before and after the partial rounds.
const FULL_ROUNDS: usize = 8;

/// Partial rounds for width 8, from circomlib's `N_ROUNDS_P`.
const PARTIAL_ROUNDS_T8: usize = 64;

/// State width for seven inputs.
const T8: usize = 8;

/// Hashes seven field elements with circomlib's `Poseidon(7)`.
pub fn poseidon7(inputs: &[Fr; 7]) -> Fr {
    use constants_t8::{C, M, P, S};

    const T: usize = T8;
    const HALF: usize = FULL_ROUNDS / 2;

    let mut state = [Fr::ZERO; T];
    state[1..].copy_from_slice(inputs);
    add_constants(&mut state, &C[..T]);

    for round in 0..HALF - 1 {
        sbox_full(&mut state);
        add_constants(&mut state, &C[(round + 1) * T..(round + 2) * T]);
        state = mix(&state, &M);
    }
    sbox_full(&mut state);
    add_constants(&mut state, &C[HALF * T..(HALF + 1) * T]);
    state = mix(&state, &P);

    let partial = (HALF + 1) * T;
    for (round, sparse) in S.chunks_exact(2 * T - 1).enumerate() {
        state[0] = pow5(state[0]) + C[partial + round];
        let mut first = Fr::ZERO;
        for (s, x) in sparse[..T].iter().zip(&state) {
            first += *s * x;
        }
        let head = state[0];
        for (x, s) in state[1..].iter_mut().zip(&sparse[T..]) {
            *x += head * s;
        }
        state[0] = first;
    }

    let tail = partial + PARTIAL_ROUNDS_T8;
    for round in 0..HALF - 1 {
        sbox_full(&mut state);
        add_constants(&mut state, &C[tail + round * T..tail + (round + 1) * T]);
        state = mix(&state, &M);
    }
    sbox_full(&mut state);

    let mut out = Fr::ZERO;
    for (row, x) in M.iter().zip(&state) {
        out += row[0] * x;
    }
    out
}

#[inline(always)]
fn pow5(x: Fr) -> Fr {
    let x2 = x.square();
    x2.square() * x
}

#[inline(always)]
fn sbox_full<const T: usize>(state: &mut [Fr; T]) {
    for x in state.iter_mut() {
        *x = pow5(*x);
    }
}

#[inline(always)]
fn add_constants<const T: usize>(state: &mut [Fr; T], constants: &[Fr]) {
    for (x, c) in state.iter_mut().zip(constants) {
        *x += c;
    }
}

/// Multiplies the state by `matrix`, as circomlib's `Mix`: `out[i] = sum_j matrix[j][i] * in[j]`.
#[inline(always)]
fn mix<const T: usize>(state: &[Fr; T], matrix: &[[Fr; T]; T]) -> [Fr; T] {
    let mut out = [Fr::ZERO; T];
    for (row, x) in matrix.iter().zip(state) {
        for (o, m) in out.iter_mut().zip(row) {
            *o += *m * x;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::MontFp;

    // Expected values computed with circomlibjs 0.1.7 `buildPoseidon` (and checked against
    // `buildPoseidonReference`, the unoptimized permutation).
    #[test]
    fn matches_circomlib() {
        let cases: [([Fr; 7], Fr); 3] = [
            (
                [1u64, 2, 3, 4, 5, 6, 7].map(Fr::from),
                MontFp!(
                    "12748163991115452309045839028154629052133952896122405799815156419278439301912"
                ),
            ),
            (
                [Fr::ZERO; 7],
                MontFp!(
                    "4650195440642623795323580690232682597343117209016245979902989581920340875814"
                ),
            ),
            (
                [
                    MontFp!(
                        "21888242871839275222246405745257275088548364400416034343698204186575808495616"
                    ),
                    Fr::from(1u64),
                    MontFp!("1461501637330902918203684832716283019655932542975"),
                    MontFp!("18446744073709551616"),
                    Fr::from(600u64),
                    Fr::from(1_700_000_000u64),
                    Fr::from(123_456_789u64),
                ],
                MontFp!(
                    "12417695477114946618717948556960537121882240102799095195289794398708817650015"
                ),
            ),
        ];
        for (inputs, expected) in cases {
            assert_eq!(poseidon7(&inputs), expected);
        }
    }
}
