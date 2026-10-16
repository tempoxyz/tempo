//! Optimized ECDSA verification over a prehashed 256-bit digest for P-256 and
//! secp256k1.
//!
//! This is a circuit-shape port of the production verifier of Freigen PR #14
//! (`Freigen/F2Z/Examples/EcdsaP256/Radix32Production.lean`, head `24fa108`):
//!
//! - `u2*Q` uses signed radix-32 (modified Booth) digits over a 17-entry
//!   magnitude table built with checked incomplete chords,
//! - `u1*G` uses a mixed-width fixed-base comb (eight 12-bit and twelve 13-bit
//!   signed odd windows with factored 7-bit inner / outer-plus-sign one-hots,
//!   plus a 4-bit top window), accumulated with checked incomplete chords,
//! - complete additions use collapsed (gated) slope and output selectors, and
//!   doublings use tight quotient widths,
//! - the terminal complete addition is fused with the comparison against `r`
//!   through a byte/bit block comparator against `p - n`.
//!
//! Every function mirrors a Lean definition of the same (snake-cased) name and
//! allocates hints, `bitz` lifts, and rank-1 rows in the same order, so the
//! P-256 instantiation produces the byte-identical constraint system (see the
//! `exactness` test). Representative bounds are carried exactly because they
//! determine the bias constants of biased subtraction and quotient checks.
//!
//! The Freigen soundness, completeness, and well-formedness proofs cover the
//! P-256 instantiation only. The secp256k1 instantiation differs only where
//! the curve requires it (see [`Curve`] and the module notes on `a = 0`, the
//! 17-block terminal comparator, and the fixed tables); it is unverified.

use std::array;
use std::sync::OnceLock;

use num_traits::Zero;

use circuit::{BoolRepresentation, BoolWitness, Circuit, HintError, HintResult, PackedBits};

use crate::ecdsa::{
    AddControl, Curve, Elem, Lc, Modulus, P256_Z_LIMBS, P256Coefficient, Point, Rep, S, ScalarElem,
    U256, UInt, UInt256, Wide, and_bit, and3_bit, assert_on_curve, assert_zero, evaluated_is_one,
    evaluated_usize, indicators_impl, lazy_assert_mul_eq, lazy_divide, lazy_mul_sub_to_elem,
    lazy_reduce_scalar, lc_u64, lc_words, lift_input_word, modular_inverse_u256, modulus_multiple,
    multiply_wide, of_elem, of_u, packed_evaluated, packed_flag_inverse_u256, packed_wide,
    packed_wide_remainder_quotient, point_from_elems, relaxed_mul, relaxed_reduce_small, rep_add,
    rep_scale, rep_sub, rep_u64, scalar_window, uint_from_repr, uint_from_repr_with_lifts,
};

pub use crate::ecdsa::VERIFY_DIGEST_INPUT_BITS;

/// Total Boolean witness size of the standalone verifier, including inputs.
pub const VERIFY_DIGEST_WITNESS_BITS: usize = 874_762;

/// Number of packed `M * w` bits (Freigen `mRows`), including the constant one.
pub const VERIFY_DIGEST_INTEGER_WITNESS_BITS: usize = 874_763;

/// Number of rank-1 constraints for P-256 (Freigen `r1csRows`).
pub const VERIFY_DIGEST_R1CS_ROWS: usize = 7_954;

const WIDTH: usize = 256;

type Repr<CS, const N: usize, const M: usize> = <<CS as Circuit>::Bool as BoolWitness>::Repr<N, M>;

fn coefficient_words<CS: Circuit>(words: &[u64]) -> P256Coefficient<CS> {
    CS::coefficient_from_le_words::<P256_Z_LIMBS>(words)
}

fn pow2<CS: Circuit>(exponent: usize) -> P256Coefficient<CS> {
    let mut words = [0_u64; 5];
    words[exponent / 64] = 1 << (exponent % 64);
    coefficient_words::<CS>(&words)
}

fn small<CS: Circuit>(value: u64) -> P256Coefficient<CS> {
    P256Coefficient::<CS>::from(value)
}

fn lc_zero<CS: Circuit>() -> Lc<CS> {
    lc_u64(0)
}

fn lc_sum<CS: Circuit>(terms: impl IntoIterator<Item = Lc<CS>>) -> Lc<CS> {
    terms.into_iter().fold(lc_zero::<CS>(), Lc::add)
}

fn r1c<CS: Circuit>(circuit: &mut CS, a: Lc<CS>, b: Lc<CS>, c: Lc<CS>) {
    circuit.assert_r1c::<P256_Z_LIMBS>(a.z, b.z, c.z);
}

fn modulus_lc<CS: Circuit>(modulus: Modulus) -> Lc<CS> {
    lc_words(&modulus.words().0)
}

fn rep<CS: Circuit>(value: Lc<CS>, bound: usize) -> Rep<CS> {
    Rep { value, bound }
}

fn wide_words(value: &Wide<9>) -> [u64; 9] {
    value.0
}

fn modulus_wide(modulus: Modulus) -> Wide<9> {
    modulus_multiple(modulus, 1)
}

/// `a = -3` doubling-numerator correction; `None` for `a = 0`.
fn tangent_numerator<CS: Circuit>(curve: Curve, x2: Rep<CS>) -> Rep<CS> {
    if curve.a_is_minus_three() {
        rep_sub(curve.base(), rep_scale(3, x2), rep_u64(3))
    } else {
        rep_scale(3, x2)
    }
}

// ---------------------------------------------------------------------------
// Generic shifted-product, division, and decomposition helpers.
// ---------------------------------------------------------------------------

/// Hint bits `r | q` for `x*y + bias - target = r + p*q`.
fn shifted_product_bits<CS: Circuit, const N: usize, const M: usize>(
    circuit: &mut CS,
    modulus: Modulus,
    x: &Lc<CS>,
    y: &Lc<CS>,
    target: Option<&Lc<CS>>,
    bias: Wide<9>,
    description: &'static str,
) -> Repr<CS, N, M> {
    let x_eval = x.capture();
    let y_eval = y.capture();
    let target_eval = target.map(Lc::capture);
    let modulus_words = modulus.words();
    circuit.hint::<P256_Z_LIMBS, N, M, _>(move |context| {
        let a = Wide::<9>::from_evaluated(x_eval.evaluate_words(context), description)?;
        let b = Wide::<9>::from_evaluated(y_eval.evaluate_words(context), description)?;
        let mut shifted = multiply_wide(a, b);
        let mut valid = !shifted.add_assign(bias);
        if let Some(target) = &target_eval {
            let target = Wide::<9>::from_evaluated(target.evaluate_words(context), description)?;
            valid &= shifted.sub_assign(target);
        }
        if !valid {
            return Err(HintError::new(format!("negative {description} dividend")));
        }
        let (quotient, remainder) = shifted.div_rem(modulus_words);
        Ok(packed_wide_remainder_quotient(remainder, quotient))
    })
}

/// Hint bits `value | q` for `value*den = num + p*q - bias`.
fn division_bits<CS: Circuit, const N: usize, const M: usize>(
    circuit: &mut CS,
    modulus: Modulus,
    denominator: &Lc<CS>,
    numerator: &Lc<CS>,
    bias: Wide<9>,
    description: &'static str,
) -> Repr<CS, N, M> {
    let denominator_eval = denominator.capture();
    let numerator_eval = numerator.capture();
    let modulus_words = modulus.words();
    circuit.hint::<P256_Z_LIMBS, N, M, _>(move |context| {
        let a = Wide::<9>::from_evaluated(denominator_eval.evaluate_words(context), description)?;
        let b = Wide::<9>::from_evaluated(numerator_eval.evaluate_words(context), description)?;
        let (_, denominator) = a.div_rem(modulus_words);
        let inverse = modular_inverse_u256(denominator, modulus_words)
            .ok_or_else(|| HintError::new(format!("zero denominator in {description}")))?;
        let (_, numerator) = b.div_rem(modulus_words);
        let mut wide_inverse = Wide::<9>([0; 9]);
        wide_inverse.0[..4].copy_from_slice(&inverse.0);
        let mut wide_numerator = Wide::<9>([0; 9]);
        wide_numerator.0[..4].copy_from_slice(&numerator.0);
        let (_, value) = multiply_wide(wide_inverse, wide_numerator).div_rem(modulus_words);
        let mut wide_value = Wide::<9>([0; 9]);
        wide_value.0[..4].copy_from_slice(&value.0);
        let mut shifted = multiply_wide(wide_value, a);
        if shifted.add_assign(bias) || !shifted.sub_assign(b) {
            return Err(HintError::new(format!("negative {description} dividend")));
        }
        let (quotient, _) = shifted.div_rem(modulus_words);
        Ok(packed_wide_remainder_quotient(value, quotient))
    })
}

/// Decodes a `256 + QN`-bit hint as a 256-bit word followed by its quotient.
fn split_rq<CS: Circuit, const N: usize, const M: usize, const QN: usize, const QM: usize>(
    circuit: &mut CS,
    bits: &Repr<CS, N, M>,
) -> (UInt256<CS>, UInt<CS, QN, QM>) {
    assert_eq!(N, WIDTH + QN);
    let r = uint_from_repr::<CS, 256, 4>(circuit, bits.slice::<256, 4>(0));
    let q = uint_from_repr::<CS, QN, QM>(circuit, bits.slice::<QN, QM>(WIDTH));
    (r, q)
}

/// `x*y = r + p*q` with an `N - 256`-bit quotient (`doubleSquare`).
fn mul_rq<CS: Circuit, const N: usize, const M: usize, const QN: usize, const QM: usize>(
    circuit: &mut CS,
    modulus: Modulus,
    x: &Rep<CS>,
    y: &Rep<CS>,
) -> Rep<CS> {
    let zero = Wide::<9>([0; 9]);
    let bits = shifted_product_bits::<CS, N, M>(
        circuit, modulus, &x.value, &y.value, None, zero, "squaring",
    );
    let (r, q) = split_rq::<CS, N, M, QN, QM>(circuit, &bits);
    let rhs = r.value.clone().add(q.value.scale(modulus.value()));
    r1c(circuit, x.value.clone(), y.value.clone(), rhs);
    rep(r.value, 2)
}

/// `x*y + bias - target = r + p*q` (`finishDoubleX`/`Y`, `collapsedCandidateX`/`Y`).
fn mul_sub_rq<CS: Circuit, const N: usize, const M: usize, const QN: usize, const QM: usize>(
    circuit: &mut CS,
    modulus: Modulus,
    x: &Rep<CS>,
    y: &Rep<CS>,
    target: &Rep<CS>,
) -> Elem<CS> {
    let bias = modulus_multiple(modulus, target.bound);
    let bits = shifted_product_bits::<CS, N, M>(
        circuit,
        modulus,
        &x.value,
        &y.value,
        Some(&target.value),
        bias,
        "affine product",
    );
    let (r, q) = split_rq::<CS, N, M, QN, QM>(circuit, &bits);
    let rhs = r
        .value
        .clone()
        .add(target.value.clone())
        .add(q.value.scale(modulus.value()))
        .sub(lc_words(&wide_words(&bias)));
    r1c(circuit, x.value.clone(), y.value.clone(), rhs);
    Elem { value: r }
}

/// `value*den = num + p*q - bias` (`doubleSlopeFromSquare`, `collapsedSlope`).
fn divide_rq<CS: Circuit, const N: usize, const M: usize, const QN: usize, const QM: usize>(
    circuit: &mut CS,
    modulus: Modulus,
    denominator: &Rep<CS>,
    numerator: &Rep<CS>,
) -> Rep<CS> {
    let bias = modulus_multiple(modulus, numerator.bound);
    let bits = division_bits::<CS, N, M>(
        circuit,
        modulus,
        &denominator.value,
        &numerator.value,
        bias,
        "affine slope",
    );
    let (value, q) = split_rq::<CS, N, M, QN, QM>(circuit, &bits);
    let rhs = numerator
        .value
        .clone()
        .add(q.value.scale(modulus.value()))
        .sub(lc_words(&wide_words(&bias)));
    r1c(circuit, value.value.clone(), denominator.value.clone(), rhs);
    rep(value.value, 2)
}

// ---------------------------------------------------------------------------
// P256/Impl.lean: AffineSlope doubling and collapsed complete addition.
// ---------------------------------------------------------------------------

/// `doubleSquare`: `x^2 = r + p*q` with a 256-bit quotient.
fn double_square<CS: Circuit>(circuit: &mut CS, curve: Curve, point: &Point<CS>) -> Rep<CS> {
    mul_rq::<CS, 512, 8, 256, 4>(circuit, curve.base(), &point.x, &point.x)
}

/// `doubleComplete`. At infinity `(0, 0, 1)` the `a = -3` numerator is
/// cancelled by `3*infinity` and the denominator becomes one. For `a = 0` the
/// numerator `3x^2` already vanishes at `(0, 0)`.
fn double_complete<CS: Circuit>(circuit: &mut CS, curve: Curve, point: Point<CS>) -> Point<CS> {
    let base = curve.base();
    let x2 = double_square(circuit, curve, &point);
    let numerator = if curve.a_is_minus_three() {
        rep_add(
            tangent_numerator(curve, x2),
            rep(point.infinity.clone().scale_coefficient(small::<CS>(3)), 1),
        )
    } else {
        tangent_numerator(curve, x2)
    };
    let denominator = rep_add(
        rep_scale(2, point.y.clone()),
        rep(point.infinity.clone(), 1),
    );
    let slope = divide_rq::<CS, 513, 9, 257, 5>(circuit, base, &denominator, &numerator);
    let x3 = mul_sub_rq::<CS, 512, 8, 256, 4>(
        circuit,
        base,
        &slope,
        &slope,
        &rep_scale(2, point.x.clone()),
    );
    let x3 = of_elem(&x3);
    let factor = rep_sub(base, point.x.clone(), x3.clone());
    let y3 = mul_sub_rq::<CS, 514, 9, 258, 5>(circuit, base, &slope, &factor, &point.y);
    Point {
        x: x3,
        y: of_elem(&y3),
        infinity: point.infinity,
    }
}

/// `zeroTestBound4Prepare`: zero flag and canonical inverse.
fn zero_test_prepare<CS: Circuit>(
    circuit: &mut CS,
    modulus: Modulus,
    x: &Rep<CS>,
) -> (Lc<CS>, UInt256<CS>) {
    let x_eval = x.value.capture();
    let modulus_words = modulus.words();
    let bits = circuit.hint::<P256_Z_LIMBS, 257, 5, _>(move |context| {
        let a = Wide::<9>::from_evaluated(x_eval.evaluate_words(context), "zero-test operand")?;
        let (_, value) = a.div_rem(modulus_words);
        let inverse = modular_inverse_u256(value, modulus_words).unwrap_or(U256::ZERO);
        Ok(packed_flag_inverse_u256(value.is_zero(), inverse))
    });
    let z = uint_from_repr::<CS, 1, 1>(circuit, bits.slice::<1, 1>(0)).value;
    let inverse = uint_from_repr::<CS, 256, 4>(circuit, bits.slice::<256, 4>(1));
    (z, inverse)
}

/// Zero-test inverse check `x * inverse = (1 - z) + p*q - p` with a `QN`-bit
/// quotient.
fn zero_test_inverse_check<CS: Circuit, const QN: usize, const QM: usize>(
    circuit: &mut CS,
    modulus: Modulus,
    x: &Rep<CS>,
    z: &Lc<CS>,
    inverse: &UInt256<CS>,
) {
    let x_eval = x.value.capture();
    let inverse_eval = inverse.value.capture();
    let z_eval = z.capture();
    let modulus_words = modulus.words();
    let p = modulus_wide(modulus);
    let bits = circuit.hint::<P256_Z_LIMBS, QN, QM, _>(move |context| {
        let a = Wide::<9>::from_evaluated(x_eval.evaluate_words(context), "zero-test operand")?;
        let b = Wide::<9>::from_evaluated(inverse_eval.evaluate_words(context), "inverse")?;
        let z_is_one = evaluated_is_one(z_eval.evaluate_words(context));
        let mut shifted = multiply_wide(a, b);
        let mut valid = !shifted.add_assign(p);
        if !z_is_one {
            let mut one = Wide::<9>([0; 9]);
            one.0[0] = 1;
            valid &= shifted.sub_assign(one);
        }
        if !valid {
            return Err(HintError::new("negative zero-test inverse quotient"));
        }
        let (quotient, _) = shifted.div_rem(modulus_words);
        Ok(packed_wide(quotient))
    });
    let q = uint_from_repr::<CS, QN, QM>(circuit, bits);
    let rhs = lc_u64::<CS>(1)
        .sub(z.clone())
        .add(q.value.scale(modulus.value()))
        .sub(modulus_lc(modulus));
    r1c(circuit, x.value.clone(), inverse.value.clone(), rhs);
}

/// Zero-branch check `z * x = p*q` with a `QN`-bit quotient.
fn zero_test_zero_check<CS: Circuit, const QN: usize, const QM: usize>(
    circuit: &mut CS,
    modulus: Modulus,
    x: &Rep<CS>,
    z: &Lc<CS>,
) {
    let z_eval = z.capture();
    let x_eval = x.value.capture();
    let modulus_words = modulus.words();
    let bits = circuit.hint::<P256_Z_LIMBS, QN, QM, _>(move |context| {
        if !evaluated_is_one(z_eval.evaluate_words(context)) {
            return Ok(PackedBits::zero());
        }
        let x = Wide::<9>::from_evaluated(x_eval.evaluate_words(context), "zero-test operand")?;
        let (quotient, _) = x.div_rem(modulus_words);
        Ok(packed_wide(quotient))
    });
    let q = uint_from_repr::<CS, QN, QM>(circuit, bits);
    r1c(
        circuit,
        z.clone(),
        x.value.clone(),
        q.value.scale(modulus.value()),
    );
}

/// `zeroTestBound4`: for representatives below `4p`.
fn zero_test_bound4<CS: Circuit>(circuit: &mut CS, modulus: Modulus, x: &Rep<CS>) -> Lc<CS> {
    let (z, inverse) = zero_test_prepare(circuit, modulus, x);
    zero_test_inverse_check::<CS, 258, 5>(circuit, modulus, x, &z, &inverse);
    zero_test_zero_check::<CS, 2, 1>(circuit, modulus, x, &z);
    z
}

/// `zeroTestCanonicalSum`: for sums of two canonical representatives.
fn zero_test_canonical_sum<CS: Circuit>(circuit: &mut CS, modulus: Modulus, x: &Rep<CS>) -> Lc<CS> {
    let (z, inverse) = zero_test_prepare(circuit, modulus, x);
    zero_test_inverse_check::<CS, 257, 5>(circuit, modulus, x, &z, &inverse);
    zero_test_zero_check::<CS, 1, 1>(circuit, modulus, x, &z);
    z
}

/// `classifyAdd`.
fn classify_add<CS: Circuit>(
    circuit: &mut CS,
    curve: Curve,
    p: &Point<CS>,
    q: &Point<CS>,
) -> AddControl<CS> {
    let base = curve.base();
    let dx = rep_sub(base, q.x.clone(), p.x.clone());
    let y_sum = rep_add(p.y.clone(), q.y.clone());
    let same_x = zero_test_bound4(circuit, base, &dx);
    let opposite_y = zero_test_canonical_sum(circuit, base, &y_sum);
    let one = lc_u64::<CS>(1);
    let finite = and_bit(
        circuit,
        one.clone().sub(p.infinity.clone()),
        one.clone().sub(q.infinity.clone()),
    );
    let double_kind = and_bit(circuit, same_x.clone(), one.clone().sub(opposite_y.clone()));
    let double_case = and_bit(circuit, finite.clone(), double_kind);
    let generic_case = and_bit(circuit, finite.clone(), one.sub(same_x.clone()));
    AddControl {
        same_x,
        opposite_y,
        finite,
        double_case: double_case.clone(),
        active: double_case.add(generic_case),
    }
}

/// `selectGated3Rep` / `selectGated4Rep`: the first gate equal to one selects
/// its value (the last value otherwise), and every gate pins the output.
fn select_gated<CS: Circuit, const N: usize, const M: usize>(
    circuit: &mut CS,
    gates: &[Lc<CS>],
    values: &[Rep<CS>],
    out_bound: usize,
) -> Rep<CS> {
    debug_assert_eq!(gates.len(), values.len());
    let gate_evals: Vec<_> = gates[..gates.len() - 1].iter().map(Lc::capture).collect();
    let value_evals: Vec<_> = values.iter().map(|value| value.value.capture()).collect();
    let bits = circuit.hint::<P256_Z_LIMBS, N, M, _>(move |context| {
        let index = gate_evals
            .iter()
            .position(|gate| evaluated_is_one(gate.evaluate_words(context)))
            .unwrap_or(value_evals.len() - 1);
        packed_evaluated(
            value_evals[index].evaluate_words(context),
            "gated selection",
        )
    });
    let out = uint_from_repr::<CS, N, M>(circuit, bits).value;
    for (gate, value) in gates.iter().zip(values) {
        r1c(
            circuit,
            gate.clone(),
            out.clone().sub(value.value.clone()),
            lc_zero(),
        );
    }
    rep(out, out_bound)
}

/// `selectSlopeOperandsCollapsedTight`: returns `(numerator, denominator)`.
fn select_slope_operands_collapsed_tight<CS: Circuit>(
    circuit: &mut CS,
    curve: Curve,
    p: &Point<CS>,
    q: &Point<CS>,
    control: &AddControl<CS>,
) -> (Rep<CS>, Rep<CS>) {
    let base = curve.base();
    let x2 = double_square(circuit, curve, p);
    let gates = [
        control.double_case.clone(),
        control.active.clone().sub(control.double_case.clone()),
        lc_u64::<CS>(1).sub(control.active.clone()),
    ];
    let numerator = select_gated::<CS, 259, 5>(
        circuit,
        &gates,
        &[
            tangent_numerator(curve, x2),
            rep_sub(base, q.y.clone(), p.y.clone()),
            rep_u64(0),
        ],
        5,
    );
    let denominator = select_gated::<CS, 258, 5>(
        circuit,
        &gates,
        &[
            rep_scale(2, p.y.clone()),
            rep_sub(base, q.x.clone(), p.x.clone()),
            rep_u64(1),
        ],
        3,
    );
    (numerator, denominator)
}

/// `collapsedSlope`.
fn collapsed_slope<CS: Circuit>(
    circuit: &mut CS,
    curve: Curve,
    numerator: &Rep<CS>,
    denominator: &Rep<CS>,
) -> Rep<CS> {
    divide_rq::<CS, 514, 9, 258, 5>(circuit, curve.base(), denominator, numerator)
}

/// `collapsedCandidateX`.
fn collapsed_candidate_x<CS: Circuit>(
    circuit: &mut CS,
    curve: Curve,
    p: &Point<CS>,
    q: &Point<CS>,
    slope: &Rep<CS>,
) -> Elem<CS> {
    let target = rep_add(p.x.clone(), q.x.clone());
    mul_sub_rq::<CS, 512, 8, 256, 4>(circuit, curve.base(), slope, slope, &target)
}

/// `collapsedCandidateY`.
fn collapsed_candidate_y<CS: Circuit>(
    circuit: &mut CS,
    curve: Curve,
    p: &Point<CS>,
    slope: &Rep<CS>,
    x3: &Elem<CS>,
) -> Elem<CS> {
    let factor = rep_sub(curve.base(), p.x.clone(), of_elem(x3));
    mul_sub_rq::<CS, 514, 9, 258, 5>(circuit, curve.base(), slope, &factor, &p.y)
}

/// `selectAddCoordinateCollapsed`.
#[allow(clippy::too_many_arguments)]
fn select_add_coordinate_collapsed<CS: Circuit>(
    circuit: &mut CS,
    p_coord: &Rep<CS>,
    q_coord: &Rep<CS>,
    candidate: Rep<CS>,
    p: &Point<CS>,
    q: &Point<CS>,
    control: &AddControl<CS>,
    both_infinity: &Lc<CS>,
) -> Rep<CS> {
    select_gated::<CS, 256, 4>(
        circuit,
        &[
            control.active.clone(),
            p.infinity.clone(),
            q.infinity.clone().sub(both_infinity.clone()),
            control.finite.clone().sub(control.active.clone()),
        ],
        &[candidate, q_coord.clone(), p_coord.clone(), rep_u64(0)],
        2,
    )
}

/// `addCompleteCollapsed`.
fn add_complete_collapsed<CS: Circuit>(
    circuit: &mut CS,
    curve: Curve,
    p: Point<CS>,
    q: Point<CS>,
) -> Point<CS> {
    let control = classify_add(circuit, curve, &p, &q);
    let (numerator, denominator) =
        select_slope_operands_collapsed_tight(circuit, curve, &p, &q, &control);
    let slope = collapsed_slope(circuit, curve, &numerator, &denominator);
    let candidate_x = collapsed_candidate_x(circuit, curve, &p, &q, &slope);
    let candidate_y = collapsed_candidate_y(circuit, curve, &p, &slope, &candidate_x);
    let candidate_x = of_elem(&candidate_x);
    let candidate_y = of_elem(&candidate_y);

    let both_infinity = and_bit(circuit, p.infinity.clone(), q.infinity.clone());
    let x = select_add_coordinate_collapsed(
        circuit,
        &p.x,
        &q.x,
        candidate_x,
        &p,
        &q,
        &control,
        &both_infinity,
    );
    let y = select_add_coordinate_collapsed(
        circuit,
        &p.y,
        &q.y,
        candidate_y,
        &p,
        &q,
        &control,
        &both_infinity,
    );
    let finite_opposite = and3_bit(circuit, control.same_x, control.opposite_y, control.finite);
    Point {
        x,
        y,
        infinity: both_infinity.add(finite_opposite),
    }
}

/// `addIncompleteChecked` (IncompleteImpl.lean): both inputs must be finite
/// and `Q.x - P.x` must be invertible, or the circuit is unsatisfiable.
fn add_incomplete_checked<CS: Circuit>(
    circuit: &mut CS,
    curve: Curve,
    p: Point<CS>,
    q: Point<CS>,
) -> Point<CS> {
    let base = curve.base();
    assert_zero(circuit, p.infinity.clone());
    assert_zero(circuit, q.infinity.clone());
    let denominator = rep_sub(base, q.x.clone(), p.x.clone());
    let _ = lazy_divide(circuit, base, denominator.clone(), rep_u64(1));
    let numerator = rep_sub(base, q.y.clone(), p.y.clone());
    let slope = lazy_divide(circuit, base, denominator, numerator);
    let candidate_x = lazy_mul_sub_to_elem(
        circuit,
        base,
        slope.clone(),
        slope.clone(),
        rep_add(p.x.clone(), q.x.clone()),
    );
    let candidate_x = of_elem(&candidate_x);
    let candidate_y = lazy_mul_sub_to_elem(
        circuit,
        base,
        slope,
        rep_sub(base, p.x.clone(), candidate_x.clone()),
        p.y,
    );
    Point {
        x: candidate_x,
        y: of_elem(&candidate_y),
        infinity: lc_zero(),
    }
}

// ---------------------------------------------------------------------------
// EcdsaP256/Radix32Impl.lean: signed radix-32 variable-base multiplication.
// ---------------------------------------------------------------------------

struct Radix32Table<CS: Circuit> {
    low: Vec<Point<CS>>,
    p16: Point<CS>,
}

/// `materializeRadix32Multiples`.
fn materialize_radix32_multiples<CS: Circuit>(
    circuit: &mut CS,
    curve: Curve,
    p1: Point<CS>,
) -> Radix32Table<CS> {
    let mut low: Vec<Point<CS>> = Vec::with_capacity(16);
    low.push(Point {
        x: rep_u64(0),
        y: rep_u64(0),
        infinity: lc_u64(1),
    });
    low.push(p1.clone());
    // p2 = 2*p1, then alternately p(2k+1) = p(2k) + p1 and p(2k+2) = 2*p(k+1).
    let p2 = double_complete(circuit, curve, p1.clone());
    low.push(p2);
    for k in 2..8 {
        let odd = add_incomplete_checked(circuit, curve, low[2 * k - 2].clone(), p1.clone());
        low.push(odd);
        let even = double_complete(circuit, curve, low[k].clone());
        low.push(even);
    }
    let p15 = add_incomplete_checked(circuit, curve, low[14].clone(), p1);
    low.push(p15);
    let p16 = double_complete(circuit, curve, low[8].clone());
    Radix32Table { low, p16 }
}

/// `applyPointSign`.
fn apply_point_sign<CS: Circuit>(
    circuit: &mut CS,
    curve: Curve,
    negative: Lc<CS>,
    point: Point<CS>,
) -> Point<CS> {
    let base = curve.base();
    let negative_eval = negative.capture();
    let y_eval = point.y.value.capture();
    let modulus_words = modulus_wide(base);
    let bits = circuit.hint::<P256_Z_LIMBS, 256, 4, _>(move |context| {
        let y_words = y_eval.evaluate_words(context);
        if !evaluated_is_one(negative_eval.evaluate_words(context)) {
            return packed_evaluated(y_words, "signed point coordinate");
        }
        let y = Wide::<9>::from_evaluated(y_words, "signed point coordinate")?;
        let mut value = modulus_words;
        if !value.sub_assign(y) {
            return Err(HintError::new("negative signed point coordinate"));
        }
        Ok(packed_wide(value))
    });
    let y = uint_from_repr::<CS, 256, 4>(circuit, bits).value;
    r1c(
        circuit,
        negative,
        modulus_lc::<CS>(base).sub(point.y.value.clone().scale_coefficient(small::<CS>(2))),
        y.clone().sub(point.y.value),
    );
    Point {
        x: point.x,
        y: rep(y, 2),
        infinity: point.infinity,
    }
}

/// `SignedDigit`: 33-way one-hot over digit values `-16..=16`.
struct SignedDigit<CS: Circuit> {
    one_hot: Vec<Lc<CS>>,
}

impl<CS: Circuit> SignedDigit<CS> {
    fn magnitude(&self) -> Lc<CS> {
        lc_sum(self.one_hot.iter().enumerate().map(|(slot, bit)| {
            bit.clone()
                .scale_coefficient(small::<CS>((slot as i64 - 16).unsigned_abs()))
        }))
    }

    fn negative(&self) -> Lc<CS> {
        lc_sum(self.one_hot[..16].iter().cloned())
    }

    /// `signedNonzeroMagnitudeGate`.
    fn nonzero_magnitude_gate(&self, i: usize) -> Lc<CS> {
        self.one_hot[15 - i]
            .clone()
            .add(self.one_hot[17 + i].clone())
    }
}

/// `signedDigitIndicators`.
fn signed_digit_indicators<CS: Circuit>(circuit: &mut CS, value: Lc<CS>) -> SignedDigit<CS> {
    let (_, one_hot) = indicators_impl::<CS, 33, 1>(circuit, value.add(lc_u64(16)));
    SignedDigit { one_hot }
}

/// `boothDigit`.
fn booth_digit<CS: Circuit>(k: &ScalarElem<CS>, i: usize) -> Lc<CS> {
    if i < 51 {
        let low = scalar_window(k, 5 * i, 4);
        let previous = if i == 0 {
            lc_zero()
        } else {
            scalar_window(k, 5 * i - 1, 1)
        };
        let top = scalar_window(k, 5 * i + 4, 1);
        low.add(previous)
            .sub(top.scale_coefficient(small::<CS>(16)))
    } else {
        scalar_window(k, 255, 1).add(scalar_window(k, 254, 1))
    }
}

/// `lookupSignedMagnitudeRep`.
fn lookup_signed_magnitude_rep<CS: Circuit>(
    circuit: &mut CS,
    digit: &SignedDigit<CS>,
    values: &[Rep<CS>],
) -> Rep<CS> {
    let magnitude_eval = digit.magnitude().capture();
    let value_evals: Vec<_> = values.iter().map(|value| value.value.capture()).collect();
    let bits = circuit.hint::<P256_Z_LIMBS, 256, 4, _>(move |context| {
        let index = evaluated_usize(magnitude_eval.evaluate_words(context), "magnitude")?;
        let value = value_evals
            .get(index)
            .ok_or_else(|| HintError::new("signed magnitude out of range"))?;
        packed_evaluated(value.evaluate_words(context), "signed-magnitude coordinate")
    });
    let word = uint_from_repr::<CS, 256, 4>(circuit, bits).value;
    r1c(
        circuit,
        digit.one_hot[16].clone(),
        word.clone().sub(values[0].value.clone()),
        lc_zero(),
    );
    for i in 0..16 {
        r1c(
            circuit,
            digit.nonzero_magnitude_gate(i),
            word.clone().sub(values[i + 1].value.clone()),
            lc_zero(),
        );
    }
    rep(word, 2)
}

/// `lookupSignedMagnitudeFlag`.
fn lookup_signed_magnitude_flag<CS: Circuit>(
    circuit: &mut CS,
    digit: &SignedDigit<CS>,
    values: &[Lc<CS>],
) -> Lc<CS> {
    let magnitude_eval = digit.magnitude().capture();
    let value_evals: Vec<_> = values.iter().map(Lc::capture).collect();
    let bits = circuit.hint::<P256_Z_LIMBS, 1, 1, _>(move |context| {
        let index = evaluated_usize(magnitude_eval.evaluate_words(context), "magnitude")?;
        let value = value_evals
            .get(index)
            .ok_or_else(|| HintError::new("signed magnitude out of range"))?;
        Ok(PackedBits::from_array([evaluated_is_one(
            value.evaluate_words(context),
        )]))
    });
    let out = Lc {
        z: circuit.bitz::<P256_Z_LIMBS>(bits.bit(0)),
    };
    r1c(
        circuit,
        digit.one_hot[16].clone(),
        out.clone().sub(values[0].clone()),
        lc_zero(),
    );
    for i in 0..16 {
        r1c(
            circuit,
            digit.nonzero_magnitude_gate(i),
            out.clone().sub(values[i + 1].clone()),
            lc_zero(),
        );
    }
    out
}

/// `selectSignedRadix32Point`.
fn select_signed_radix32_point<CS: Circuit>(
    circuit: &mut CS,
    curve: Curve,
    digit: &SignedDigit<CS>,
    table: &Radix32Table<CS>,
) -> Point<CS> {
    let all = || table.low.iter().chain(std::iter::once(&table.p16));
    let xs: Vec<_> = all().map(|point| point.x.clone()).collect();
    let ys: Vec<_> = all().map(|point| point.y.clone()).collect();
    let flags: Vec<_> = all().map(|point| point.infinity.clone()).collect();
    let x = lookup_signed_magnitude_rep(circuit, digit, &xs);
    let y = lookup_signed_magnitude_rep(circuit, digit, &ys);
    let infinity = lookup_signed_magnitude_flag(circuit, digit, &flags);
    apply_point_sign(circuit, curve, digit.negative(), Point { x, y, infinity })
}

/// `signedRadix32VariableMul` (FixedBaseCombImpl.lean).
fn signed_radix32_variable_mul<CS: Circuit>(
    circuit: &mut CS,
    curve: Curve,
    u2: &ScalarElem<CS>,
    q: Point<CS>,
) -> Point<CS> {
    let table = materialize_radix32_multiples(circuit, curve, q);
    let top = signed_digit_indicators(circuit, booth_digit(u2, 51));
    let mut accumulator = select_signed_radix32_point(circuit, curve, &top, &table);
    for i in 0..255 {
        accumulator = double_complete(circuit, curve, accumulator);
        let exponent = 254 - i;
        if exponent % 5 == 0 {
            let digit = signed_digit_indicators(circuit, booth_digit(u2, exponent / 5));
            let point = select_signed_radix32_point(circuit, curve, &digit, &table);
            accumulator = add_complete_collapsed(circuit, curve, accumulator, point);
        }
    }
    accumulator
}

// ---------------------------------------------------------------------------
// EcdsaP256/FixedBaseCombImpl.lean: mixed-width fixed-base comb.
// ---------------------------------------------------------------------------

/// Number of 12-bit and 13-bit comb windows.
const COMB12_WINDOWS: usize = 8;
const COMB13_WINDOWS: usize = 12;

/// An affine point as little-endian words: `(x, y, p - y)`.
type TablePoint = ([u64; 4], [u64; 4], [u64; 4]);

/// Fixed-base tables of one curve.
struct FixedTables {
    /// For window `w` (twelve-bit windows first), the odd multiples
    /// `(2i + 1) * 2^offset * G` for `i < 2^(width - 1)`.
    windows: Vec<Vec<TablePoint>>,
    /// `topCombX`/`topCombY` for one-hot indices `0..32`.
    top: Vec<TablePoint>,
}

fn comb_window(window: usize) -> (usize, usize) {
    if window < COMB12_WINDOWS {
        (12 * window, 12)
    } else {
        (96 + 13 * (window - COMB12_WINDOWS), 13)
    }
}

fn words_from_be(bytes: &[u8]) -> [u64; 4] {
    array::from_fn(|i| {
        let start = 32 - 8 * (i + 1);
        u64::from_be_bytes(bytes[start..start + 8].try_into().unwrap())
    })
}

fn negate_mod(modulus: U256, y: [u64; 4]) -> [u64; 4] {
    let mut value = Wide::<4>(modulus.0);
    let valid = value.sub_assign(Wide::<4>(y));
    debug_assert!(valid);
    value.0
}

macro_rules! fixed_tables_for {
    ($name:ident, $krate:ident) => {
        fn $name(modulus: U256) -> FixedTables {
            use $krate::ProjectivePoint;
            #[allow(unused_imports)]
            use $krate::elliptic_curve::group::{Curve as _, Group as _};
            use $krate::elliptic_curve::sec1::ToEncodedPoint;

            let generator = ProjectivePoint::GENERATOR;
            let mut powers = Vec::with_capacity(257);
            let mut power = generator;
            for _ in 0..=256 {
                powers.push(power);
                power = power.double();
            }
            let mut projective = Vec::with_capacity(65_536 + 32);
            let mut lengths = Vec::new();
            for window in 0..COMB12_WINDOWS + COMB13_WINDOWS {
                let (offset, width) = comb_window(window);
                let count = 1_usize << (width - 1);
                let step = powers[offset + 1];
                let mut point = powers[offset];
                for _ in 0..count {
                    projective.push(point);
                    point += step;
                }
                lengths.push(count);
            }
            for index in 0..32_u64 {
                let raw = index % 16;
                let parity = index / 16;
                let point = if raw >= 8 {
                    // ((2*raw + 1 - 16) * 2^252 - (1 - parity)) * G
                    let mut multiple = ProjectivePoint::IDENTITY;
                    for _ in 0..(2 * raw + 1 - 16) {
                        multiple += powers[252];
                    }
                    if parity == 0 {
                        multiple -= generator;
                    }
                    multiple
                } else {
                    generator
                };
                projective.push(point);
            }
            let affine: Vec<_> = projective.iter().map(|point| point.to_affine()).collect();
            let mut points = affine.iter().map(|point| {
                let encoded = point.to_encoded_point(false);
                let x = words_from_be(encoded.x().unwrap());
                let y = words_from_be(encoded.y().unwrap());
                (x, y, negate_mod(modulus, y))
            });
            let windows = lengths
                .iter()
                .map(|&count| points.by_ref().take(count).collect())
                .collect();
            let top = points.collect();
            FixedTables { windows, top }
        }
    };
}

fixed_tables_for!(p256_fixed_tables, p256);
fixed_tables_for!(k256_fixed_tables, k256);

fn fixed_tables(curve: Curve) -> &'static FixedTables {
    static P256_TABLES: OnceLock<FixedTables> = OnceLock::new();
    static K1_TABLES: OnceLock<FixedTables> = OnceLock::new();
    match curve {
        Curve::P256 => P256_TABLES.get_or_init(|| p256_fixed_tables(curve.base().words())),
        Curve::Secp256k1 => K1_TABLES.get_or_init(|| k256_fixed_tables(curve.base().words())),
    }
}

/// Materializes the fixed-base comb tables of both curves. Call this during
/// setup to exclude one-time table construction from latency measurements.
pub fn prepare() {
    let _ = fixed_tables(Curve::P256);
    let _ = fixed_tables(Curve::Secp256k1);
}

/// `combBit`: the comb consumes `k >> 1` with an implicit top bit of one.
fn comb_bit<CS: Circuit>(k: &ScalarElem<CS>, i: usize) -> Lc<CS> {
    if i < 255 {
        k.int_bits[i + 1].clone()
    } else {
        lc_u64(1)
    }
}

fn comb_window_value<CS: Circuit>(bits: &[Lc<CS>]) -> Lc<CS> {
    lc_sum(
        bits.iter()
            .enumerate()
            .map(|(i, bit)| bit.clone().scale_coefficient(pow2::<CS>(i))),
    )
}

/// `xnorBit`.
fn xnor_bit<CS: Circuit>(circuit: &mut CS, sign: Lc<CS>, bit: Lc<CS>) -> Lc<CS> {
    let both = and_bit(circuit, sign.clone(), bit.clone());
    both.scale_coefficient(small::<CS>(2))
        .sub(sign)
        .sub(bit)
        .add(lc_u64(1))
}

/// `signedMagnitudeIndex`.
fn signed_magnitude_index(width: usize, raw: usize) -> usize {
    let half = 1 << (width - 1);
    if raw >= half {
        raw - half
    } else {
        half - 1 - raw
    }
}

/// `materializeFixedCoordinate` with the X (`want_y = false`) or signed Y
/// coordinate of `fixedSignedPoint`.
fn materialize_fixed_coordinate<CS: Circuit>(
    circuit: &mut CS,
    table: &'static [TablePoint],
    width: usize,
    want_y: bool,
    raw: &Lc<CS>,
) -> UInt256<CS> {
    let raw_eval = raw.capture();
    let bits = circuit.hint::<P256_Z_LIMBS, 256, 4, _>(move |context| {
        let raw = evaluated_usize(raw_eval.evaluate_words(context), "comb window")?;
        let (x, y, negated_y) = table
            .get(signed_magnitude_index(width, raw))
            .ok_or_else(|| HintError::new("comb window out of range"))?;
        let value = if !want_y {
            x
        } else if raw >= 1 << (width - 1) {
            y
        } else {
            negated_y
        };
        Ok(PackedBits::from_words(*value))
    });
    uint_from_repr::<CS, 256, 4>(circuit, bits)
}

/// `lookupFixedFactored`. `OUTER = 2^(width - 7)`.
fn lookup_fixed_factored<CS: Circuit, const OUTER: usize>(
    circuit: &mut CS,
    table: &'static [TablePoint],
    width: usize,
    bits: &[Lc<CS>],
) -> Point<CS> {
    assert_eq!(OUTER, 1 << (width - 7));
    assert_eq!(table.len(), 1 << (width - 1));
    let raw = comb_window_value(bits);
    let sign = bits[width - 1].clone();
    let magnitude: Vec<_> = (0..width - 1)
        .map(|i| xnor_bit(circuit, sign.clone(), bits[i].clone()))
        .collect();
    let inner_digit = comb_window_value(&magnitude[..7]);
    let outer_digit = comb_window_value(&magnitude[7..width - 1])
        .add(sign.scale_coefficient(pow2::<CS>(width - 8)));
    let (_, inner) = indicators_impl::<CS, 128, 2>(circuit, inner_digit);
    let (_, outer) = indicators_impl::<CS, OUTER, 1>(circuit, outer_digit);
    let x = materialize_fixed_coordinate(circuit, table, width, false, &raw);
    let y = materialize_fixed_coordinate(circuit, table, width, true, &raw);

    // assertFactoredCoordinates
    let half = 1 << (width - 8);
    for (o, gate) in outer.iter().enumerate() {
        let magnitude_outer = o % half;
        let negative = o / half == 0;
        let entries = &table[128 * magnitude_outer..128 * (magnitude_outer + 1)];
        let inner_x = lc_sum(
            entries
                .iter()
                .zip(&inner)
                .map(|((x, _, _), bit)| bit.clone().scale_coefficient(coefficient_words::<CS>(x))),
        );
        let inner_y = lc_sum(entries.iter().zip(&inner).map(|((_, y, negated_y), bit)| {
            let coefficient = if negative { negated_y } else { y };
            bit.clone()
                .scale_coefficient(coefficient_words::<CS>(coefficient))
        }));
        r1c(
            circuit,
            gate.clone(),
            x.value.clone().sub(inner_x),
            lc_zero(),
        );
        r1c(
            circuit,
            gate.clone(),
            y.value.clone().sub(inner_y),
            lc_zero(),
        );
    }
    Point {
        x: rep(x.value, 2),
        y: rep(y.value, 2),
        infinity: lc_zero(),
    }
}

/// `lookupFixed12` / `lookupFixed13`.
fn lookup_fixed<CS: Circuit>(
    circuit: &mut CS,
    curve: Curve,
    k: &ScalarElem<CS>,
    window: usize,
) -> Point<CS> {
    let (offset, width) = comb_window(window);
    let bits: Vec<_> = (0..width).map(|i| comb_bit(k, offset + i)).collect();
    let table = fixed_tables(curve).windows[window].as_slice();
    if width == 12 {
        lookup_fixed_factored::<CS, 32>(circuit, table, width, &bits)
    } else {
        lookup_fixed_factored::<CS, 64>(circuit, table, width, &bits)
    }
}

/// `lookupFixedTop`.
fn lookup_fixed_top<CS: Circuit>(circuit: &mut CS, curve: Curve, k: &ScalarElem<CS>) -> Point<CS> {
    let bits: Vec<_> = (252..256).map(|i| comb_bit(k, i)).collect();
    let raw = comb_window_value(&bits);
    let parity = k.int_bits[0].clone();
    let index = raw.add(parity.scale_coefficient(small::<CS>(16)));
    let (_, one_hot) = indicators_impl::<CS, 32, 1>(circuit, index);
    let top = &fixed_tables(curve).top;
    let x = lc_sum(
        top.iter()
            .zip(&one_hot)
            .map(|((x, _, _), bit)| bit.clone().scale_coefficient(coefficient_words::<CS>(x))),
    );
    let y = lc_sum(
        top.iter()
            .zip(&one_hot)
            .map(|((_, y, _), bit)| bit.clone().scale_coefficient(coefficient_words::<CS>(y))),
    );
    Point {
        x: rep(x, 2),
        y: rep(y, 2),
        infinity: lc_zero(),
    }
}

/// `fixedBaseCombComplete`: `fixedBaseComb12`, `fixedBaseComb13Incomplete`,
/// and a final complete addition of the top window.
fn fixed_base_comb_complete<CS: Circuit>(
    circuit: &mut CS,
    curve: Curve,
    k: &ScalarElem<CS>,
) -> Point<CS> {
    let mut accumulator = lookup_fixed(circuit, curve, k, 0);
    for window in 1..COMB12_WINDOWS + COMB13_WINDOWS {
        let point = lookup_fixed(circuit, curve, k, window);
        accumulator = add_incomplete_checked(circuit, curve, accumulator, point);
    }
    let top = lookup_fixed_top(circuit, curve, k);
    add_complete_collapsed(circuit, curve, accumulator, top)
}

// ---------------------------------------------------------------------------
// EcdsaP256/DirectTerminalBlockImpl.lean: fused terminal acceptance.
// ---------------------------------------------------------------------------

/// `deltaBlockPairSatisfies`.
fn delta_block_pair_satisfies(r: &S, delta: &S, block: usize, offset: usize) -> bool {
    let start = 8 * block;
    let shifted = r >> start;
    let selected = &shifted % 256_u32;
    shifted == &selected + ((delta >> (start + 8)) << 8)
        && (&selected >> offset) + 1_u32 == (delta >> (start + offset)) % (1_u32 << (8 - offset))
}

/// `firstDeltaBlockPair` over `blocks * 8` candidates.
fn first_delta_block_pair(r: &S, delta: &S, blocks: usize) -> (usize, usize) {
    (0..blocks * 8)
        .find(|index| delta_block_pair_satisfies(r, delta, index / 8, index % 8))
        .map_or((0, 0), |index| (index / 8, index % 8))
}

fn evaluated_biguint(words: &[u64], description: &str) -> HintResult<S> {
    if words.last().is_some_and(|word| word >> 63 != 0) {
        return Err(HintError::new(format!("negative {description}")));
    }
    Ok(S::new(
        words
            .iter()
            .flat_map(|word| [*word as u32, (*word >> 32) as u32])
            .collect(),
    ))
}

/// `addCompleteCollapsedDeltaBlock` with `selectAddOutputDeltaBlock` and
/// `deltaBlockComparator`. `BLOCKS` byte blocks must cover `p - n`: 16 for
/// P-256 (`p - n < 2^127`) and 17 for secp256k1 (`p - n < 2^129`). `N` is the
/// hint width `2 + BLOCKS + 8 + 8`.
fn add_complete_collapsed_delta_block<CS: Circuit, const BLOCKS: usize, const N: usize>(
    circuit: &mut CS,
    curve: Curve,
    r: &ScalarElem<CS>,
    p: Point<CS>,
    q: Point<CS>,
) {
    assert_eq!(N, 18 + BLOCKS);
    let base = curve.base();
    let scalar = curve.scalar();
    let delta = base.value() - scalar.value();
    assert!(delta.bits() as usize <= 8 * BLOCKS);

    let control = classify_add(circuit, curve, &p, &q);
    let (numerator, denominator) =
        select_slope_operands_collapsed_tight(circuit, curve, &p, &q, &control);
    let slope = collapsed_slope(circuit, curve, &numerator, &denominator);
    let candidate_x = of_elem(&collapsed_candidate_x(circuit, curve, &p, &q, &slope));

    let both_infinity = and_bit(circuit, p.infinity.clone(), q.infinity.clone());
    let r_value = r.elem.value.value.clone();
    let evals = [
        control.active.capture(),
        p.infinity.capture(),
        q.infinity.capture(),
        candidate_x.value.capture(),
        p.x.value.capture(),
        q.x.value.capture(),
        r_value.capture(),
    ];
    let hint_delta = delta.clone();
    let bits = circuit.hint::<P256_Z_LIMBS, N, 1, _>(move |context| {
        let [active, p_infinity, q_infinity, candidate_x, p_x, q_x, r] = &evals;
        let source = if evaluated_is_one(active.evaluate_words(context)) {
            Some(candidate_x)
        } else if evaluated_is_one(p_infinity.evaluate_words(context)) {
            Some(q_x)
        } else if evaluated_is_one(q_infinity.evaluate_words(context)) {
            Some(p_x)
        } else {
            None
        };
        let source = match source {
            Some(source) => evaluated_biguint(source.evaluate_words(context), "terminal X source")?,
            None => S::zero(),
        };
        let r = evaluated_biguint(r.evaluate_words(context), "signature r")?;
        let x = &source % base.value();
        let q_base = &source / base.value();
        let q_scalar = if x >= r {
            (&x - &r) / scalar.value()
        } else {
            S::zero()
        };
        let q_scalar = q_scalar.bit(0);
        let (block, offset) = first_delta_block_pair(&r, &hint_delta, BLOCKS);
        Ok(PackedBits::from_fn(|i| {
            if i == 0 {
                q_base.bit(0)
            } else if i == 1 {
                q_scalar
            } else if i < 2 + BLOCKS {
                q_scalar && i - 2 == block
            } else if i < 10 + BLOCKS {
                q_scalar && i - 2 - BLOCKS == offset
            } else {
                r.bit((8 * block + (i - 10 - BLOCKS)) as u64)
            }
        }))
    });
    let q_base = uint_from_repr::<CS, 1, 1>(circuit, bits.slice::<1, 1>(0)).value;
    let q_scalar = uint_from_repr::<CS, 1, 1>(circuit, bits.slice::<1, 1>(1)).value;
    let (_, outer) =
        uint_from_repr_with_lifts::<CS, BLOCKS, 1>(circuit, bits.slice::<BLOCKS, 1>(2));
    let (_, inner) = uint_from_repr_with_lifts::<CS, 8, 1>(circuit, bits.slice::<8, 1>(2 + BLOCKS));
    let (selected, selected_bits) =
        uint_from_repr_with_lifts::<CS, 8, 1>(circuit, bits.slice::<8, 1>(10 + BLOCKS));
    let target = r_value
        .add(q_scalar.clone().scale(scalar.value()))
        .add(q_base.scale(base.value()));
    r1c(
        circuit,
        control.active.clone(),
        candidate_x.value.sub(target.clone()),
        lc_zero(),
    );
    r1c(
        circuit,
        p.infinity.clone(),
        q.x.value.clone().sub(target.clone()),
        lc_zero(),
    );
    r1c(
        circuit,
        q.infinity.clone().sub(both_infinity.clone()),
        p.x.value.clone().sub(target),
        lc_zero(),
    );

    // deltaBlockComparator
    let one = lc_u64::<CS>(1);
    r1c(
        circuit,
        one.clone(),
        lc_sum(outer.iter().cloned()).sub(q_scalar.clone()),
        lc_zero(),
    );
    r1c(
        circuit,
        one.clone(),
        lc_sum(inner.iter().cloned()).sub(q_scalar),
        lc_zero(),
    );
    for (i, gate) in outer.iter().enumerate() {
        let start = 8 * i;
        let scalar_bits = lc_sum(
            r.int_bits[start..]
                .iter()
                .enumerate()
                .map(|(j, bit)| bit.clone().scale_coefficient(pow2::<CS>(j))),
        );
        let expected = selected
            .value
            .clone()
            .add(Lc::<CS>::from_biguint(&((&delta >> (start + 8)) << 8)));
        r1c(circuit, gate.clone(), scalar_bits.sub(expected), lc_zero());
    }
    for (j, gate) in inner.iter().enumerate() {
        let selected_from = lc_sum(
            selected_bits[j..]
                .iter()
                .enumerate()
                .map(|(i, bit)| bit.clone().scale_coefficient(pow2::<CS>(i))),
        );
        let outer_from = lc_sum(outer.iter().enumerate().map(|(i, bit)| {
            let block = (&delta >> (8 * i + j)) % (1_u32 << (8 - j));
            bit.clone().scale(&block)
        }));
        r1c(
            circuit,
            gate.clone(),
            selected_from.sub(outer_from.sub(one.clone())),
            lc_zero(),
        );
    }

    let finite_opposite = and3_bit(circuit, control.same_x, control.opposite_y, control.finite);
    assert_zero(circuit, both_infinity.add(finite_opposite));
}

impl<CS: Circuit> Lc<CS> {
    fn from_biguint(value: &S) -> Self {
        crate::ecdsa::lc_constant(value)
    }
}

// ---------------------------------------------------------------------------
// Radix32Production.lean: `verifyDigestFromBits`.
// ---------------------------------------------------------------------------

/// Builds the optimized ECDSA verifier for `curve` from seven little-endian
/// 256-bit input words ordered as digest, Q.x, Q.y, r, s, r^-1, s^-1.
pub fn verify_digest_circuit<CS: Circuit>(
    circuit: &mut CS,
    curve: Curve,
    inputs: &[CS::Bool; VERIFY_DIGEST_INPUT_BITS],
) {
    let words: [Repr<CS, 256, 4>; 7] = array::from_fn(|slot| {
        <Repr<CS, 256, 4> as BoolRepresentation<CS::Bool, 256, 4>>::from_array(array::from_fn(
            |bit| inputs[slot * WIDTH + bit].clone(),
        ))
    });
    let mut words = words.into_iter();
    let digest = lift_input_word(circuit, words.next().unwrap());
    let qx = lift_input_word(circuit, words.next().unwrap());
    let qy = lift_input_word(circuit, words.next().unwrap());
    let r = lift_input_word(circuit, words.next().unwrap());
    let s = lift_input_word(circuit, words.next().unwrap());
    let r_inverse = lift_input_word(circuit, words.next().unwrap());
    let s_inverse = lift_input_word(circuit, words.next().unwrap());

    // canonicalizeInput
    let qx = of_u(circuit, curve.base(), qx.elem.value);
    let qy = of_u(circuit, curve.base(), qy.elem.value);
    let r_elem = of_u(circuit, curve.scalar(), r.elem.value.clone());
    let s = of_u(circuit, curve.scalar(), s.elem.value);
    let r_inverse = of_u(circuit, curve.scalar(), r_inverse.elem.value);
    let s_inverse = of_u(circuit, curve.scalar(), s_inverse.elem.value);

    // validateCanonicalInput
    assert_on_curve(circuit, curve, &qx, &qy);
    lazy_assert_mul_eq(
        circuit,
        curve.scalar(),
        of_elem(&r_elem),
        of_elem(&r_inverse),
        rep_u64(1),
    );
    lazy_assert_mul_eq(
        circuit,
        curve.scalar(),
        of_elem(&s),
        of_elem(&s_inverse),
        rep_u64(1),
    );

    // deriveScalars
    let z = relaxed_reduce_small(circuit, curve.scalar(), digest.elem.value.value);
    let u1_relaxed = relaxed_mul(circuit, curve.scalar(), z, s_inverse.clone());
    let u2_relaxed = relaxed_mul(circuit, curve.scalar(), r_elem, s_inverse);
    let u1 = lazy_reduce_scalar(circuit, curve.scalar(), of_elem(&u1_relaxed));
    let u2 = lazy_reduce_scalar(circuit, curve.scalar(), of_elem(&u2_relaxed));

    // fixedCombVerificationDeltaBlock
    let q = point_from_elems(&qx, &qy);
    let variable_part = signed_radix32_variable_mul(circuit, curve, &u2, q);
    let fixed_part = fixed_base_comb_complete(circuit, curve, &u1);
    match curve {
        Curve::P256 => add_complete_collapsed_delta_block::<CS, 16, 34>(
            circuit,
            curve,
            &r,
            variable_part,
            fixed_part,
        ),
        Curve::Secp256k1 => add_complete_collapsed_delta_block::<CS, 17, 35>(
            circuit,
            curve,
            &r,
            variable_part,
            fixed_part,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use circuit::constraints::{ConstraintGenerator, ConstraintMatrices};
    use circuit::matrix_products::StoredInteger;
    use circuit::stats::{Dummy, LeanStats, Stats};
    use circuit::witgen::ProductWitgen;
    use num_bigint::{BigInt, Sign};
    use sha2::{Digest, Sha256};
    use std::panic::{AssertUnwindSafe, catch_unwind};

    fn lean_stats(curve: Curve) -> LeanStats {
        let mut stats = Stats::new(VERIFY_DIGEST_INPUT_BITS);
        verify_digest_circuit(&mut stats, curve, &[Dummy; VERIFY_DIGEST_INPUT_BITS]);
        stats.lean_stats()
    }

    #[test]
    fn p256_dimensions_match_freigen_pr14() {
        assert_eq!(
            lean_stats(Curve::P256),
            LeanStats {
                m_rows: 874_763,
                m_cols: 874_763,
                r1cs_rows: 7_954,
            }
        );
    }

    #[test]
    fn secp256k1_dimensions_add_one_comparator_block() {
        // The secp256k1 `p - n` needs a 17th comparator byte: one more hinted
        // selector bit, lift, and gated row.
        assert_eq!(
            lean_stats(Curve::Secp256k1),
            LeanStats {
                m_rows: 874_764,
                m_cols: 874_764,
                r1cs_rows: 7_955,
            }
        );
    }

    // -- Freigen binary serialization (`Freigen/F2Z/Serialization.lean`). --

    fn push_u32(out: &mut Vec<u8>, value: usize) {
        out.extend_from_slice(&u32::try_from(value).unwrap().to_le_bytes());
    }

    fn push_int(out: &mut Vec<u8>, value: &BigInt) {
        // ZigZag, then unsigned LEB128.
        let mut n = if value.sign() == Sign::Minus {
            (-value).to_biguint().unwrap() * 2_u32 - 1_u32
        } else {
            value.to_biguint().unwrap() * 2_u32
        };
        loop {
            let byte = (&n % 128_u32).to_u64_digits().first().copied().unwrap_or(0) as u8;
            n >>= 7;
            if n.is_zero() {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
    }

    /// Serializes generated matrices exactly as Freigen's `CS.serialize`.
    pub(super) fn serialize(matrices: &ConstraintMatrices<BigInt>) -> Vec<u8> {
        let mut out = Vec::new();
        push_u32(&mut out, matrices.m.row_count());
        for row in matrices.m.rows() {
            push_u32(&mut out, row.positions().len());
            for &column in row.positions() {
                push_u32(&mut out, column);
            }
        }
        for matrix in [&matrices.a, &matrices.b, &matrices.c] {
            push_u32(&mut out, matrix.row_count());
            for row in matrix.rows() {
                push_u32(&mut out, row.entries().len());
                for (column, coefficient) in row.entries() {
                    push_u32(&mut out, *column);
                    push_int(&mut out, coefficient);
                }
            }
        }
        out
    }

    /// Byte offsets of every serialized row, labelled for diagnostics.
    fn row_offsets(bytes: &[u8]) -> Vec<(String, usize)> {
        let mut offset = 0;
        let read_u32 = |offset: &mut usize| {
            let value = u32::from_le_bytes(bytes[*offset..*offset + 4].try_into().unwrap());
            *offset += 4;
            value as usize
        };
        let mut rows = Vec::new();
        let m_rows = read_u32(&mut offset);
        for row in 0..m_rows {
            rows.push((format!("M row {row}"), offset));
            let count = read_u32(&mut offset);
            offset += 4 * count;
        }
        for name in ["A", "B", "C"] {
            let count_rows = read_u32(&mut offset);
            for row in 0..count_rows {
                rows.push((format!("{name} row {row}"), offset));
                let count = read_u32(&mut offset);
                for _ in 0..count {
                    offset += 4;
                    while bytes[offset] & 0x80 != 0 {
                        offset += 1;
                    }
                    offset += 1;
                }
            }
        }
        assert_eq!(offset, bytes.len(), "trailing bytes");
        rows
    }

    fn generate(curve: Curve) -> ConstraintMatrices<BigInt> {
        let mut generator = ConstraintGenerator::<BigInt>::new(VERIFY_DIGEST_INPUT_BITS);
        let inputs = generator.boxed_inputs::<VERIFY_DIGEST_INPUT_BITS>();
        verify_digest_circuit(&mut generator, curve, &inputs);
        generator.into_matrices()
    }

    /// Byte-for-byte equality with Freigen PR #14's production
    /// `verifyDigestCS`, exported by `lake exe ecdsa_cs_export` in the PR
    /// worktree. Set `FREIGEN_ECDSA_CS` to the exported file; the test is
    /// skipped when the file is absent.
    #[test]
    fn p256_constraint_system_is_byte_identical_to_freigen_pr14() {
        let path = std::env::var("FREIGEN_ECDSA_CS").unwrap_or_else(|_| {
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../freigen-pr14/verify_digest_cs.bin"
            )
            .into()
        });
        let Ok(lean) = std::fs::read(&path) else {
            eprintln!("skipping exactness check: {path} not found");
            return;
        };
        let matrices = generate(Curve::P256);
        matrices.validate_shape().unwrap();
        let rust = serialize(&matrices);
        if rust != lean {
            let lean_rows = row_offsets(&lean);
            let rust_rows = row_offsets(&rust);
            for (index, ((name, lean_offset), (_, rust_offset))) in
                lean_rows.iter().zip(&rust_rows).enumerate()
            {
                let lean_end = lean_rows.get(index + 1).map_or(lean.len(), |row| row.1);
                let rust_end = rust_rows.get(index + 1).map_or(rust.len(), |row| row.1);
                if lean[*lean_offset..lean_end] != rust[*rust_offset..rust_end] {
                    panic!(
                        "first mismatch at {name}: lean {:?} rust {:?}",
                        &lean[*lean_offset..lean_end.min(lean_offset + 64)],
                        &rust[*rust_offset..rust_end.min(rust_offset + 64)]
                    );
                }
            }
            panic!(
                "serializations differ in length: lean {} rows / {} bytes, rust {} rows / {} bytes",
                lean_rows.len(),
                lean.len(),
                rust_rows.len(),
                rust.len()
            );
        }
        eprintln!("exactness: {} identical bytes from {path}", rust.len());
    }

    // -- Witness generation. --

    fn stored_bigint(value: &StoredInteger) -> BigInt {
        let bytes: Vec<u8> = value
            .words()
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        BigInt::from_signed_bytes_le(&bytes)
    }

    fn inverse(value: &S, modulus: &S) -> S {
        value.modpow(&(modulus - 2_u32), modulus)
    }

    /// Verifier words: digest, Q.x, Q.y, r, s, r^-1, s^-1.
    #[derive(Clone)]
    struct Input {
        curve: Curve,
        digest: S,
        qx: S,
        qy: S,
        r: S,
        s: S,
    }

    impl Input {
        fn values(&self) -> [S; 7] {
            let n = self.curve.order();
            [
                self.digest.clone(),
                self.qx.clone(),
                self.qy.clone(),
                self.r.clone(),
                self.s.clone(),
                inverse(&self.r, n),
                inverse(&self.s, n),
            ]
        }

        fn bits(&self) -> Vec<bool> {
            let values = self.values();
            (0..VERIFY_DIGEST_INPUT_BITS)
                .map(|index| values[index / 256].bit((index % 256) as u64))
                .collect()
        }
    }

    /// Runs honest witness generation; a failing hint or any unsatisfied
    /// rank-1 row is a rejection.
    fn accepts(input: &Input) -> bool {
        let bits = input.bits();
        let inputs: &[bool; VERIFY_DIGEST_INPUT_BITS] = bits.as_slice().try_into().unwrap();
        let run = catch_unwind(AssertUnwindSafe(|| {
            let mut witgen =
                ProductWitgen::with_inputs_and_capacity(inputs, VERIFY_DIGEST_WITNESS_BITS + 1);
            verify_digest_circuit(&mut witgen, input.curve, inputs);
            witgen
        }));
        let Ok(witgen) = run else {
            eprintln!("rejected by a failing hint");
            return false;
        };
        let products = witgen.products();
        let rows = match input.curve {
            Curve::P256 => VERIFY_DIGEST_R1CS_ROWS,
            Curve::Secp256k1 => VERIFY_DIGEST_R1CS_ROWS + 1,
        };
        let witness_bits = match input.curve {
            Curve::P256 => VERIFY_DIGEST_WITNESS_BITS,
            Curve::Secp256k1 => VERIFY_DIGEST_WITNESS_BITS + 1,
        };
        assert_eq!(products.a_mw.len(), rows);
        assert_eq!(witgen.witness().bit_len(), witness_bits);
        assert_eq!(witgen.integer_witness().bit_len(), witness_bits + 1);
        let failing = products
            .a_mw
            .iter()
            .zip(&products.b_mw)
            .zip(&products.c_mw)
            .position(|((a, b), c)| stored_bigint(a) * stored_bigint(b) != stored_bigint(c));
        if let Some(row) = failing {
            eprintln!("rejected by unsatisfied row {row}");
        }
        failing.is_none()
    }

    fn seed(label: &str) -> [u8; 32] {
        Sha256::digest(label.as_bytes()).into()
    }

    fn p256_signature(label: &str) -> Input {
        use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
        let key = SigningKey::from_slice(&seed(&format!("p256 key {label}"))).unwrap();
        let digest = seed(&format!("p256 message {label}"));
        let signature: Signature = key.sign_prehash(&digest).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        let bytes = signature.to_bytes();
        Input {
            curve: Curve::P256,
            digest: S::from_bytes_be(&digest),
            qx: S::from_bytes_be(point.x().unwrap()),
            qy: S::from_bytes_be(point.y().unwrap()),
            r: S::from_bytes_be(&bytes[..32]),
            s: S::from_bytes_be(&bytes[32..]),
        }
    }

    fn k256_signature(label: &str) -> Input {
        use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
        let key = SigningKey::from_slice(&seed(&format!("k256 key {label}"))).unwrap();
        let digest = seed(&format!("k256 message {label}"));
        let signature: Signature = key.sign_prehash(&digest).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        let bytes = signature.to_bytes();
        Input {
            curve: Curve::Secp256k1,
            digest: S::from_bytes_be(&digest),
            qx: S::from_bytes_be(point.x().unwrap()),
            qy: S::from_bytes_be(point.y().unwrap()),
            r: S::from_bytes_be(&bytes[..32]),
            s: S::from_bytes_be(&bytes[32..]),
        }
    }

    /// `EcdsaInputs::trivial`: Q = G, r = Gx mod n, s = e + r.
    fn trivial(curve: Curve, digest: &[u8; 32]) -> Input {
        let n = curve.order();
        let (gx, gy) = curve.generator();
        let r = gx % n;
        let s = (S::from_bytes_be(digest) + &r) % n;
        Input {
            curve,
            digest: S::from_bytes_be(digest),
            qx: gx.clone(),
            qy: gy.clone(),
            r,
            s,
        }
    }

    fn check_curve(curve: Curve, sign: fn(&str) -> Input) {
        prepare();
        let mut honest: Vec<Input> = (0..4).map(|i| sign(&i.to_string())).collect();
        honest.push(trivial(curve, &seed("trivial")));
        honest.push(trivial(curve, &[0; 32]));
        // u1 = u2: e = r.
        let r = curve.generator().0 % curve.order();
        let mut e = [0_u8; 32];
        let r_bytes = r.to_bytes_be();
        e[32 - r_bytes.len()..].copy_from_slice(&r_bytes);
        honest.push(trivial(curve, &e));
        for (index, input) in honest.iter().enumerate() {
            assert!(accepts(input), "{curve:?} honest input {index} rejected");
        }

        let base = sign("tamper");
        assert!(accepts(&base));
        let n = curve.order();
        let other = sign("other key");
        let tampered = [
            (
                "r + 1",
                Input {
                    r: (&base.r + 1_u32) % n,
                    ..base.clone()
                },
            ),
            (
                "s + 1",
                Input {
                    s: (&base.s + 1_u32) % n,
                    ..base.clone()
                },
            ),
            (
                "n - r",
                Input {
                    // High-s is an ECDSA malleation and stays valid; flip r instead.
                    r: (n - &base.r) % n,
                    ..base.clone()
                },
            ),
            (
                "digest ^ 1",
                Input {
                    digest: &base.digest ^ S::one(),
                    ..base.clone()
                },
            ),
            (
                "other key",
                Input {
                    qx: other.qx.clone(),
                    qy: other.qy.clone(),
                    ..base.clone()
                },
            ),
            (
                "off-curve key",
                Input {
                    qy: (&base.qy + 1_u32) % curve.base().value(),
                    ..base.clone()
                },
            ),
            (
                "Q = -Q",
                Input {
                    qy: curve.base().value() - &base.qy,
                    ..base.clone()
                },
            ),
        ];
        for (label, input) in &tampered {
            assert!(
                !accepts(input),
                "{curve:?} tampered input `{label}` accepted"
            );
        }
        // ECDSA signatures are malleable: (r, n - s) also verifies.
        assert!(accepts(&Input {
            s: n - &base.s,
            ..base.clone()
        }));
    }

    use num_traits::One;

    /// A valid signature whose nonce point has `n <= x(R) < p`, so that
    /// `r = x(R) - n` and the terminal comparator must prove `r < p - n`.
    /// Pick R by its x-coordinate, then solve for the key:
    /// `Q = u2^-1 (R - u1 G)`, `s = r / u2`, `e = u1 s`.
    macro_rules! high_x_signature {
        ($name:ident, $krate:ident, $curve:expr) => {
            fn $name(u1: u64, u2: u64) -> Input {
                use $krate::elliptic_curve::ff::PrimeField;
                use $krate::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
                use $krate::{AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar};
                let curve: Curve = $curve;
                let n = curve.order();
                let to_bytes = |value: &S| {
                    let bytes = value.to_bytes_be();
                    let mut out = [0_u8; 32];
                    out[32 - bytes.len()..].copy_from_slice(&bytes);
                    out
                };
                let mut x = n + 12_345_u32;
                let point = loop {
                    let mut encoded = vec![2_u8];
                    encoded.extend_from_slice(&to_bytes(&x));
                    let encoded = EncodedPoint::from_bytes(&encoded).unwrap();
                    let point = AffinePoint::from_encoded_point(&encoded);
                    if bool::from(point.is_some()) {
                        break point.unwrap();
                    }
                    x += 1_u32;
                };
                assert!(&x >= n && &x < curve.base().value());
                let scalar =
                    |value: &S| Scalar::from_repr(FieldBytes::from(to_bytes(value))).unwrap();
                let r = &x - n;
                let u1 = Scalar::from(u1);
                let u2 = Scalar::from(u2);
                let u2_inverse = u2.invert().unwrap();
                let q =
                    (ProjectivePoint::from(point) - ProjectivePoint::GENERATOR * u1) * u2_inverse;
                let s = scalar(&r) * u2_inverse;
                let e = u1 * s;
                let q = q.to_affine().to_encoded_point(false);
                Input {
                    curve,
                    digest: S::from_bytes_be(&e.to_repr()),
                    qx: S::from_bytes_be(q.x().unwrap()),
                    qy: S::from_bytes_be(q.y().unwrap()),
                    r,
                    s: S::from_bytes_be(&s.to_repr()),
                }
            }
        };
    }

    high_x_signature!(p256_high_x, p256, Curve::P256);
    high_x_signature!(k256_high_x, k256, Curve::Secp256k1);

    #[test]
    fn terminal_comparator_accepts_x_above_the_group_order() {
        prepare();
        for (u1, u2) in [(3, 5), (0x1234_5678, 0x9abc_def0)] {
            for input in [p256_high_x(u1, u2), k256_high_x(u1, u2)] {
                assert!(
                    accepts(&input),
                    "{:?} high-x signature rejected",
                    input.curve
                );
                // The non-canonical encoding r + n is not a scalar.
                let n = input.curve.order();
                assert!(!accepts(&Input {
                    r: (&input.r + 1_u32) % n,
                    ..input.clone()
                }));
            }
        }
    }

    #[test]
    fn p256_signatures_accept_and_tampering_rejects() {
        check_curve(Curve::P256, p256_signature);
    }

    #[test]
    fn secp256k1_signatures_accept_and_tampering_rejects() {
        check_curve(Curve::Secp256k1, k256_signature);
    }
}
