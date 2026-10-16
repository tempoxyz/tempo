//! ECDSA verification over a prehashed 256-bit digest for short-Weierstrass
//! curves with 256-bit base and scalar fields: P-256 and secp256k1.
//!
//! Vendored from BitZ `crates/circuit/src/p256.rs` at `d7e7257`, which is a
//! circuit-shape port of Freigen's Lean P-256 implementation. The only changes
//! are a [`Curve`] parameter for the moduli, `a`, `b`, and generator, and the
//! removal of the upstream tests. The Freigen soundness proofs cover the
//! P-256 instantiation only; the secp256k1 instantiation is unverified.
//!
//! The relation now uses the optimized verifier in [`crate::ecdsa_fast`], which
//! reuses this module's lazy-representative primitives and hint arithmetic.

use std::array;
use std::cmp::Ordering;
use std::sync::{LazyLock, OnceLock};

use crypto_bigint::{Odd, U256 as CryptoU256};
use num_traits::{One, Zero};

use circuit::{
    BoolRepresentation, BoolWitness, Circuit, HintError, HintResult, PackedBits, WitnessContext,
};

/// Number of Boolean inputs: digest, public-key coordinates, signature
/// scalars, and the two inverse witnesses.
pub const VERIFY_DIGEST_INPUT_BITS: usize = 7 * 256;

/// Total Boolean witness size of the standalone verifier, including inputs.
pub const VERIFY_DIGEST_WITNESS_BITS: usize = 1_215_662;

/// Number of packed `M * w` bits, including the implicit constant one.
pub const VERIFY_DIGEST_INTEGER_WITNESS_BITS: usize = 1_215_663;

/// Number of rank-1 constraints.
pub const VERIFY_DIGEST_R1CS_ROWS: usize = 7_061;

/// Signed width used by witness-oriented backends for P-256 intermediates.
/// The widest values are products of 262-bit affine-formula operands.
pub const P256_Z_LIMBS: usize = 9;

pub(crate) const WIDTH: usize = 256;
pub(crate) const WORD_LIMBS: usize = 4;

pub(crate) type P256Z<CS> = <CS as Circuit>::Z<P256_Z_LIMBS>;
pub(crate) type P256Coefficient<CS> = <CS as Circuit>::Coefficient<P256_Z_LIMBS>;
pub(crate) type S = num_bigint::BigUint;

pub(crate) fn parse_hex(hex: &[u8]) -> S {
    S::parse_bytes(hex, 16).unwrap()
}
pub(crate) static P256_BASE: LazyLock<S> = LazyLock::new(|| {
    parse_hex(b"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")
});

pub(crate) static P256_SCALAR: LazyLock<S> = LazyLock::new(|| {
    parse_hex(b"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
});

pub(crate) static P256_B: LazyLock<S> = LazyLock::new(|| {
    parse_hex(b"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b")
});

pub(crate) static P256_GX: LazyLock<S> = LazyLock::new(|| {
    parse_hex(b"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
});

pub(crate) static P256_GY: LazyLock<S> = LazyLock::new(|| {
    parse_hex(b"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
});

pub(crate) static K1_BASE: LazyLock<S> = LazyLock::new(|| {
    parse_hex(b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")
});

pub(crate) static K1_SCALAR: LazyLock<S> = LazyLock::new(|| {
    parse_hex(b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
});

pub(crate) static K1_B: LazyLock<S> = LazyLock::new(|| S::from(7_u64));

pub(crate) static K1_GX: LazyLock<S> = LazyLock::new(|| {
    parse_hex(b"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
});

pub(crate) static K1_GY: LazyLock<S> = LazyLock::new(|| {
    parse_hex(b"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
});

/// A short-Weierstrass curve `y^2 = x^3 + ax + b` supported by the verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Curve {
    /// NIST P-256 (`a = -3`), used by WebAuthn passkeys.
    P256,
    /// secp256k1 (`a = 0`), used by Ethereum-style hardware keys.
    Secp256k1,
}

impl Curve {
    pub(crate) fn base(self) -> Modulus {
        match self {
            Self::P256 => Modulus::P256Base,
            Self::Secp256k1 => Modulus::K1Base,
        }
    }

    pub(crate) fn scalar(self) -> Modulus {
        match self {
            Self::P256 => Modulus::P256Scalar,
            Self::Secp256k1 => Modulus::K1Scalar,
        }
    }

    /// Whether `a = -3`; otherwise `a = 0`.
    pub(crate) fn a_is_minus_three(self) -> bool {
        self == Self::P256
    }

    pub(crate) fn b(self) -> &'static S {
        match self {
            Self::P256 => &P256_B,
            Self::Secp256k1 => &K1_B,
        }
    }

    /// The generator's affine coordinates.
    pub fn generator(self) -> (&'static S, &'static S) {
        match self {
            Self::P256 => (&P256_GX, &P256_GY),
            Self::Secp256k1 => (&K1_GX, &K1_GY),
        }
    }

    /// The group order.
    pub fn order(self) -> &'static S {
        self.scalar().value()
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Modulus {
    P256Base,
    P256Scalar,
    K1Base,
    K1Scalar,
}

impl Modulus {
    pub(crate) fn value(self) -> &'static S {
        match self {
            Self::P256Base => &P256_BASE,
            Self::P256Scalar => &P256_SCALAR,
            Self::K1Base => &K1_BASE,
            Self::K1Scalar => &K1_SCALAR,
        }
    }

    pub(crate) fn words(self) -> U256 {
        match self {
            Self::P256Base => U256([
                0xffff_ffff_ffff_ffff,
                0x0000_0000_ffff_ffff,
                0,
                0xffff_ffff_0000_0001,
            ]),
            Self::P256Scalar => U256([
                0xf3b9_cac2_fc63_2551,
                0xbce6_faad_a717_9e84,
                0xffff_ffff_ffff_ffff,
                0xffff_ffff_0000_0000,
            ]),
            Self::K1Base => U256([
                0xffff_fffe_ffff_fc2f,
                0xffff_ffff_ffff_ffff,
                0xffff_ffff_ffff_ffff,
                0xffff_ffff_ffff_ffff,
            ]),
            Self::K1Scalar => U256([
                0xbfd2_5e8c_d036_4141,
                0xbaae_dce6_af48_a03b,
                0xffff_ffff_ffff_fffe,
                0xffff_ffff_ffff_ffff,
            ]),
        }
    }
}

pub(crate) struct Lc<CS: Circuit> {
    pub(crate) z: P256Z<CS>,
}

#[derive(Clone)]
pub(crate) struct CapturedValue<ZW> {
    pub(crate) z: ZW,
}

impl<ZW> CapturedValue<ZW> {
    pub(crate) fn evaluate_words<'a, BW, C>(
        &'a self,
        context: &dyn WitnessContext<ZW, BW, C>,
    ) -> &'a [u64] {
        context
            .eval_z_words(&self.z)
            .expect("fixed-width integer hint context required by the P-256 circuit")
    }
}

impl<CS: Circuit> Clone for Lc<CS> {
    fn clone(&self) -> Self {
        Self { z: self.z.clone() }
    }
}

impl<CS: Circuit> Lc<CS> {
    pub(crate) fn capture(&self) -> CapturedValue<P256Z<CS>> {
        CapturedValue { z: self.z.clone() }
    }

    pub(crate) fn add(self, rhs: Self) -> Self {
        Self { z: self.z + rhs.z }
    }

    pub(crate) fn sub(self, rhs: Self) -> Self {
        Self { z: self.z - rhs.z }
    }

    pub(crate) fn scale(self, coefficient: &S) -> Self {
        self.scale_coefficient(coefficient_for::<CS>(coefficient))
    }

    pub(crate) fn scale_coefficient(self, coefficient: P256Coefficient<CS>) -> Self {
        Self {
            z: self.z * coefficient,
        }
    }
}

pub(crate) struct UInt<CS: Circuit, const N: usize, const M: usize> {
    pub(crate) bits: <CS::Bool as BoolWitness>::Repr<N, M>,
    pub(crate) value: Lc<CS>,
}

impl<CS: Circuit, const N: usize, const M: usize> Clone for UInt<CS, N, M> {
    fn clone(&self) -> Self {
        Self {
            bits: self.bits.clone(),
            value: self.value.clone(),
        }
    }
}

pub(crate) type UInt256<CS> = UInt<CS, WIDTH, WORD_LIMBS>;

pub(crate) struct Elem<CS: Circuit> {
    pub(crate) value: UInt256<CS>,
}

impl<CS: Circuit> Clone for Elem<CS> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
        }
    }
}

pub(crate) struct Rep<CS: Circuit> {
    pub(crate) value: Lc<CS>,
    pub(crate) bound: usize,
}

impl<CS: Circuit> Clone for Rep<CS> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            bound: self.bound,
        }
    }
}

pub(crate) struct Point<CS: Circuit> {
    pub(crate) x: Rep<CS>,
    pub(crate) y: Rep<CS>,
    pub(crate) infinity: Lc<CS>,
}

impl<CS: Circuit> Clone for Point<CS> {
    fn clone(&self) -> Self {
        Self {
            x: self.x.clone(),
            y: self.y.clone(),
            infinity: self.infinity.clone(),
        }
    }
}

pub(crate) fn coefficient_for<CS: Circuit>(value: &S) -> P256Coefficient<CS> {
    let mut words = [0; P256_Z_LIMBS];
    for (output, word) in words.iter_mut().zip(value.iter_u64_digits()) {
        *output = word;
    }
    CS::coefficient_from_le_words(&words)
}

pub(crate) fn lc_constant<CS: Circuit>(value: &S) -> Lc<CS> {
    Lc {
        z: P256Z::<CS>::from(coefficient_for::<CS>(value)),
    }
}

pub(crate) fn lc_words<CS: Circuit>(words: &[u64]) -> Lc<CS> {
    Lc {
        z: P256Z::<CS>::from(CS::coefficient_from_le_words(words)),
    }
}

pub(crate) fn lc_u64<CS: Circuit>(value: u64) -> Lc<CS> {
    Lc {
        z: P256Z::<CS>::from(P256Coefficient::<CS>::from(value)),
    }
}

pub(crate) fn assert_zero<CS: Circuit>(circuit: &mut CS, value: Lc<CS>) {
    circuit.assert_r1c::<P256_Z_LIMBS>(P256Z::<CS>::zero(), P256Z::<CS>::zero(), value.z);
}

pub(crate) fn repr_bits<BW, const N: usize, const M: usize>(repr: &BW::Repr<N, M>) -> Vec<BW>
where
    BW: BoolWitness,
{
    (0..N).map(|index| repr.bit(index)).collect()
}

pub(crate) fn uint_from_repr<CS: Circuit, const N: usize, const M: usize>(
    circuit: &mut CS,
    bits: <CS::Bool as BoolWitness>::Repr<N, M>,
) -> UInt<CS, N, M> {
    let (z, _) = circuit.bitz_unsigned::<P256_Z_LIMBS, N, M, N>(&bits);
    UInt {
        bits,
        value: Lc { z },
    }
}

pub(crate) fn uint_from_repr_with_lifts<CS: Circuit, const N: usize, const M: usize>(
    circuit: &mut CS,
    bits: <CS::Bool as BoolWitness>::Repr<N, M>,
) -> (UInt<CS, N, M>, Vec<Lc<CS>>) {
    let handles = repr_bits::<CS::Bool, N, M>(&bits);
    let mut lifted = Vec::with_capacity(N);
    let mut z = P256Z::<CS>::zero();
    let mut power = P256Coefficient::<CS>::one();
    for bit in handles {
        let bit_z = circuit.bitz::<P256_Z_LIMBS>(bit);
        z += bit_z.clone() * power.clone();
        lifted.push(Lc { z: bit_z });
        power += power.clone();
    }
    (
        UInt {
            bits,
            value: Lc { z },
        },
        lifted,
    )
}

pub(crate) fn hinted_bits<CS: Circuit, const N: usize, const M: usize>(
    circuit: &mut CS,
    expression: CapturedValue<P256Z<CS>>,
    description: &'static str,
) -> <CS::Bool as BoolWitness>::Repr<N, M> {
    circuit.hint::<P256_Z_LIMBS, N, M, _>(move |context| {
        packed_evaluated(expression.evaluate_words(context), description)
    })
}

pub(crate) fn uint_from_int<CS: Circuit, const N: usize, const M: usize>(
    circuit: &mut CS,
    value: Lc<CS>,
    description: &'static str,
) -> UInt<CS, N, M> {
    let bits = hinted_bits::<CS, N, M>(circuit, value.capture(), description);
    let output = uint_from_repr(circuit, bits);
    assert_zero(circuit, value.sub(output.value.clone()));
    output
}

pub(crate) fn assert_lt<CS: Circuit>(circuit: &mut CS, modulus: Modulus, value: &UInt256<CS>) {
    let mut bound = modulus.words().0;
    let mut borrow = true;
    for word in &mut bound {
        let (difference, next_borrow) = word.overflowing_sub(u64::from(borrow));
        *word = difference;
        borrow = next_borrow;
    }
    debug_assert!(!borrow);
    let slack = lc_words::<CS>(&bound).sub(value.value.clone());
    let _ = uint_from_int::<CS, WIDTH, WORD_LIMBS>(circuit, slack, "range-check slack");
}

pub(crate) fn of_u<CS: Circuit>(
    circuit: &mut CS,
    modulus: Modulus,
    value: UInt256<CS>,
) -> Elem<CS> {
    assert_lt(circuit, modulus, &value);
    Elem { value }
}

pub(crate) fn of_elem<CS: Circuit>(value: &Elem<CS>) -> Rep<CS> {
    Rep {
        value: value.value.value.clone(),
        bound: 2,
    }
}

pub(crate) fn rep_constant<CS: Circuit>(value: &S) -> Rep<CS> {
    Rep {
        value: lc_constant(value),
        bound: 2,
    }
}

pub(crate) fn rep_u64<CS: Circuit>(value: u64) -> Rep<CS> {
    Rep {
        value: lc_u64(value),
        bound: 2,
    }
}

pub(crate) fn rep_add<CS: Circuit>(left: Rep<CS>, right: Rep<CS>) -> Rep<CS> {
    Rep {
        value: left.value.add(right.value),
        bound: left.bound + right.bound,
    }
}

pub(crate) fn rep_sub<CS: Circuit>(modulus: Modulus, left: Rep<CS>, right: Rep<CS>) -> Rep<CS> {
    let bias = modulus_multiple(modulus, right.bound);
    Rep {
        value: left.value.add(lc_words(&bias.0)).sub(right.value),
        bound: left.bound + right.bound,
    }
}

pub(crate) fn rep_scale<CS: Circuit>(coefficient: usize, value: Rep<CS>) -> Rep<CS> {
    Rep {
        value: value
            .value
            .scale_coefficient(P256Coefficient::<CS>::from(coefficient as u64)),
        bound: coefficient * value.bound,
    }
}

pub(crate) fn split_521<CS: Circuit>(
    circuit: &mut CS,
    bits: <CS::Bool as BoolWitness>::Repr<521, 9>,
) -> (UInt256<CS>, UInt<CS, 265, 5>) {
    let remainder = bits.slice::<256, 4>(0);
    let quotient = bits.slice::<265, 5>(WIDTH);
    (
        uint_from_repr::<CS, WIDTH, WORD_LIMBS>(circuit, remainder),
        uint_from_repr::<CS, 265, 5>(circuit, quotient),
    )
}

pub(crate) fn lazy_mul<CS: Circuit>(
    circuit: &mut CS,
    modulus: Modulus,
    x: Rep<CS>,
    y: Rep<CS>,
) -> Rep<CS> {
    let x_eval = x.value.capture();
    let y_eval = y.value.capture();
    let modulus_words = modulus.words();
    let bits = circuit.hint::<P256_Z_LIMBS, 521, 9, _>(move |context| {
        let a = Wide::<9>::from_evaluated(
            x_eval.evaluate_words(context),
            "lazy multiplication operand",
        )?;
        let b = Wide::<9>::from_evaluated(
            y_eval.evaluate_words(context),
            "lazy multiplication operand",
        )?;
        let product = multiply_wide(a, b);
        let (quotient, remainder) = product.div_rem(modulus_words);
        Ok(packed_wide_remainder_quotient(remainder, quotient))
    });
    let (r, q) = split_521(circuit, bits);
    let rhs = r.value.clone().add(q.value.clone().scale(modulus.value()));
    circuit.assert_r1c::<P256_Z_LIMBS>(x.value.z, y.value.z, rhs.z);
    Rep {
        value: r.value,
        bound: 2,
    }
}

pub(crate) fn lazy_mul_sub_to_elem<CS: Circuit>(
    circuit: &mut CS,
    modulus: Modulus,
    x: Rep<CS>,
    y: Rep<CS>,
    target: Rep<CS>,
) -> Elem<CS> {
    let bias = modulus_multiple(modulus, target.bound);
    let x_eval = x.value.capture();
    let y_eval = y.value.capture();
    let target_eval = target.value.capture();
    let modulus_words = modulus.words();
    let hint_bias = bias;
    let bits = circuit.hint::<P256_Z_LIMBS, 521, 9, _>(move |context| {
        let x = Wide::<9>::from_evaluated(x_eval.evaluate_words(context), "affine factor")?;
        let y = Wide::<9>::from_evaluated(y_eval.evaluate_words(context), "affine factor")?;
        let target = Wide::<9>::from_evaluated(
            target_eval.evaluate_words(context),
            "affine product target",
        )?;
        let mut shifted = multiply_wide(x, y);
        if shifted.add_assign(hint_bias) || !shifted.sub_assign(target) {
            return Err(HintError::new("invalid affine product dividend bounds"));
        }
        let (quotient, remainder) = shifted.div_rem(modulus_words);
        Ok(packed_wide_remainder_quotient(remainder, quotient))
    });
    let (r, q) = split_521(circuit, bits);
    let rhs = r
        .value
        .clone()
        .add(target.value.clone())
        .add(q.value.clone().scale(modulus.value()))
        .sub(lc_words(&bias.0));
    circuit.assert_r1c::<P256_Z_LIMBS>(x.value.z, y.value.z, rhs.z);
    Elem { value: r }
}

pub(crate) fn lazy_divide<CS: Circuit>(
    circuit: &mut CS,
    modulus: Modulus,
    denominator: Rep<CS>,
    numerator: Rep<CS>,
) -> Rep<CS> {
    let bias = modulus_multiple(modulus, numerator.bound);
    let denominator_eval = denominator.value.capture();
    let numerator_eval = numerator.value.capture();
    let modulus_words = modulus.words();
    let hint_bias = bias;
    let bits = circuit.hint::<P256_Z_LIMBS, 521, 9, _>(move |context| {
        let a = Wide::<9>::from_evaluated(
            denominator_eval.evaluate_words(context),
            "division denominator",
        )?;
        let b = Wide::<9>::from_evaluated(
            numerator_eval.evaluate_words(context),
            "division numerator",
        )?;
        let (_, denominator) = a.div_rem(modulus_words);
        let inverse = modular_inverse_u256(denominator, modulus_words)
            .ok_or_else(|| HintError::new("zero or noninvertible division denominator"))?;
        let (_, numerator) = b.div_rem(modulus_words);
        let inverse_product = multiply_wide(widen_u256(inverse), widen_u256(numerator));
        let (_, value) = inverse_product.div_rem(modulus_words);
        let mut shifted = multiply_wide(widen_u256(value), a);
        if shifted.add_assign(hint_bias) || !shifted.sub_assign(b) {
            return Err(HintError::new("invalid lazy division dividend bounds"));
        }
        let (quotient, remainder) = shifted.div_rem(modulus_words);
        debug_assert!(remainder.is_zero());
        Ok(packed_wide_remainder_quotient(value, quotient))
    });
    let (value, q) = split_521(circuit, bits);
    let rhs = numerator
        .value
        .clone()
        .add(q.value.clone().scale(modulus.value()))
        .sub(lc_words(&bias.0));
    circuit.assert_r1c::<P256_Z_LIMBS>(value.value.z.clone(), denominator.value.z, rhs.z);
    Rep {
        value: value.value,
        bound: 2,
    }
}

pub(crate) fn lazy_reduce<CS: Circuit>(circuit: &mut CS, modulus: Modulus, x: Rep<CS>) -> Elem<CS> {
    let x_eval = x.value.capture();
    let modulus_words = modulus.words();
    let bits = circuit.hint::<P256_Z_LIMBS, 521, 9, _>(move |context| {
        let value =
            Wide::<9>::from_evaluated(x_eval.evaluate_words(context), "lazy reduction operand")?;
        let (quotient, remainder) = value.div_rem(modulus_words);
        Ok(packed_wide_remainder_quotient(remainder, quotient))
    });
    let (r, q) = split_521(circuit, bits);
    let relation = x
        .value
        .sub(r.value.clone().add(q.value.scale(modulus.value())));
    assert_zero(circuit, relation);
    of_u(circuit, modulus, r)
}

pub(crate) fn lazy_reduce_scalar<CS: Circuit>(
    circuit: &mut CS,
    modulus: Modulus,
    x: Rep<CS>,
) -> ScalarElem<CS> {
    let x_eval = x.value.capture();
    let modulus_words = modulus.words();
    let bits = circuit.hint::<P256_Z_LIMBS, 521, 9, _>(move |context| {
        let value =
            Wide::<9>::from_evaluated(x_eval.evaluate_words(context), "lazy reduction operand")?;
        let (quotient, remainder) = value.div_rem(modulus_words);
        Ok(packed_wide_remainder_quotient(remainder, quotient))
    });
    let remainder = bits.slice::<256, 4>(0);
    let quotient = bits.slice::<265, 5>(WIDTH);
    let (r, int_bits) = uint_from_repr_with_lifts::<CS, 256, 4>(circuit, remainder);
    let q = uint_from_repr::<CS, 265, 5>(circuit, quotient);
    let relation = x
        .value
        .sub(r.value.clone().add(q.value.scale(modulus.value())));
    assert_zero(circuit, relation);
    assert_lt(circuit, modulus, &r);
    ScalarElem {
        elem: Elem { value: r },
        int_bits,
    }
}

pub(crate) fn lazy_assert_mul_eq<CS: Circuit>(
    circuit: &mut CS,
    modulus: Modulus,
    x: Rep<CS>,
    y: Rep<CS>,
    target: Rep<CS>,
) {
    let bias = modulus_multiple(modulus, target.bound);
    let x_eval = x.value.capture();
    let y_eval = y.value.capture();
    let target_eval = target.value.capture();
    let modulus_words = modulus.words();
    let hint_bias = bias;
    let bits = circuit.hint::<P256_Z_LIMBS, 265, 5, _>(move |context| {
        let x = Wide::<9>::from_evaluated(x_eval.evaluate_words(context), "relation factor")?;
        let y = Wide::<9>::from_evaluated(y_eval.evaluate_words(context), "relation factor")?;
        let target = Wide::<9>::from_evaluated(
            target_eval.evaluate_words(context),
            "modular relation target",
        )?;
        let mut shifted = multiply_wide(x, y);
        if shifted.add_assign(hint_bias) || !shifted.sub_assign(target) {
            return Err(HintError::new("invalid modular relation quotient bounds"));
        }
        let (quotient, remainder) = shifted.div_rem(modulus_words);
        debug_assert!(remainder.is_zero());
        Ok(packed_wide(quotient))
    });
    let q = uint_from_repr::<CS, 265, 5>(circuit, bits);
    let rhs = target
        .value
        .add(q.value.scale(modulus.value()))
        .sub(lc_words(&bias.0));
    circuit.assert_r1c::<P256_Z_LIMBS>(x.value.z, y.value.z, rhs.z);
}

pub(crate) fn relaxed_reduce_small<CS: Circuit>(
    circuit: &mut CS,
    modulus: Modulus,
    x: Lc<CS>,
) -> Elem<CS> {
    let x_eval = x.capture();
    let modulus_words = modulus.words();
    let bits = circuit.hint::<P256_Z_LIMBS, 258, 5, _>(move |context| {
        let value =
            Wide::<9>::from_evaluated(x_eval.evaluate_words(context), "relaxed modular dividend")?;
        let (quotient, remainder) = value.div_rem(modulus_words);
        Ok(packed_wide_remainder_quotient(remainder, quotient))
    });
    let r_bits = bits.slice::<256, 4>(0);
    let q_bits = bits.slice::<2, 1>(WIDTH);
    let r = uint_from_repr::<CS, 256, 4>(circuit, r_bits);
    let q = uint_from_repr::<CS, 2, 1>(circuit, q_bits);
    let relation = x.sub(r.value.clone().add(q.value.scale(modulus.value())));
    assert_zero(circuit, relation);
    Elem { value: r }
}

pub(crate) fn relaxed_mul<CS: Circuit>(
    circuit: &mut CS,
    modulus: Modulus,
    x: Elem<CS>,
    y: Elem<CS>,
) -> Elem<CS> {
    let x_eval = x.value.value.capture();
    let y_eval = y.value.value.capture();
    let modulus_words = modulus.words();
    let bits = circuit.hint::<P256_Z_LIMBS, 514, 9, _>(move |context| {
        let a = Wide::<9>::from_evaluated(
            x_eval.evaluate_words(context),
            "relaxed multiplication factor",
        )?;
        let b = Wide::<9>::from_evaluated(
            y_eval.evaluate_words(context),
            "relaxed multiplication factor",
        )?;
        let value = multiply_wide(a, b);
        let (quotient, remainder) = value.div_rem(modulus_words);
        Ok(packed_wide_remainder_quotient(remainder, quotient))
    });
    let r_bits = bits.slice::<256, 4>(0);
    let q_bits = bits.slice::<258, 5>(WIDTH);
    let r = uint_from_repr::<CS, 256, 4>(circuit, r_bits);
    let q = uint_from_repr::<CS, 258, 5>(circuit, q_bits);
    let rhs = r.value.clone().add(q.value.scale(modulus.value()));
    circuit.assert_r1c::<P256_Z_LIMBS>(x.value.value.z, y.value.value.z, rhs.z);
    Elem { value: r }
}

pub(crate) fn packed_evaluated<const N: usize, const M: usize>(
    words: &[u64],
    description: &str,
) -> HintResult<PackedBits<N, M>> {
    if words.last().is_some_and(|word| word >> 63 != 0) {
        return Err(HintError::new(format!("negative {description}")));
    }
    Ok(PackedBits::from_words(array::from_fn(|index| {
        words.get(index).copied().unwrap_or(0)
    })))
}

pub(crate) fn evaluated_is_one(words: &[u64]) -> bool {
    words.first() == Some(&1) && words[1..].iter().all(|word| *word == 0)
}

pub(crate) fn evaluated_usize(words: &[u64], description: &str) -> HintResult<usize> {
    if words.last().is_some_and(|word| word >> 63 != 0)
        || words
            .get(1..)
            .is_some_and(|words| words.iter().any(|word| *word != 0))
    {
        return Err(HintError::new(format!("invalid {description}")));
    }
    usize::try_from(words.first().copied().unwrap_or(0))
        .map_err(|_| HintError::new(format!("oversized {description}")))
}

pub(crate) fn packed_flag_inverse_u256(flag: bool, inverse: U256) -> PackedBits<257, 5> {
    let mut carry = u64::from(flag);
    PackedBits::from_words(array::from_fn(|index| {
        let word = inverse.0.get(index).copied().unwrap_or(0);
        let output = (word << 1) | carry;
        carry = word >> 63;
        output
    }))
}

/// An allocation-free integer used by P-256 hint arithmetic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct U256(pub(crate) [u64; 4]);

impl U256 {
    pub(crate) const ZERO: Self = Self([0; 4]);

    pub(crate) fn is_zero(self) -> bool {
        self == Self::ZERO
    }

    pub(crate) fn is_even(self) -> bool {
        self.0[0] & 1 == 0
    }

    pub(crate) fn cmp_words(self, rhs: Self) -> Ordering {
        for index in (0..4).rev() {
            match self.0[index].cmp(&rhs.0[index]) {
                Ordering::Equal => {}
                ordering => return ordering,
            }
        }
        Ordering::Equal
    }
}

impl<'a> TryFrom<&'a S> for U256 {
    type Error = ();

    fn try_from(value: &'a S) -> Result<Self, Self::Error> {
        let digits = value.to_u64_digits();
        if digits.len() > 4 {
            return Err(());
        }
        let mut words = [0; 4];
        words[..digits.len()].copy_from_slice(&digits);
        Ok(Self(words))
    }
}

impl From<U256> for S {
    fn from(v: U256) -> Self {
        let digits =
            v.0.into_iter()
                .flat_map(|word| [word as u32, (word >> 32) as u32]);
        Self::new(digits.collect())
    }
}

/// A little-endian unsigned integer for P-256 hint arithmetic. Nine limbs
/// match the circuit's signed Z capacity; eighteen hold a full product.
#[derive(Clone, Copy)]
pub(crate) struct Wide<const L: usize>(pub(crate) [u64; L]);

impl<const L: usize> Wide<L> {
    pub(crate) fn from_evaluated(words: &[u64], description: &str) -> HintResult<Self> {
        if words.last().is_some_and(|word| word >> 63 != 0) {
            return Err(HintError::new(format!("negative {description}")));
        }
        if words.len() > L && words[L..].iter().any(|word| *word != 0) {
            return Err(HintError::new(format!("oversized {description}")));
        }
        let mut output = [0; L];
        let copied = words.len().min(L);
        output[..copied].copy_from_slice(&words[..copied]);
        Ok(Self(output))
    }

    pub(crate) fn add_assign<const K: usize>(&mut self, rhs: Wide<K>) -> bool {
        let mut carry = false;
        for index in 0..L {
            let word = rhs.0.get(index).copied().unwrap_or(0);
            let (sum, first_carry) = self.0[index].overflowing_add(word);
            let (sum, second_carry) = sum.overflowing_add(u64::from(carry));
            self.0[index] = sum;
            carry = first_carry || second_carry;
        }
        carry
            || rhs
                .0
                .get(L..)
                .is_some_and(|words| words.iter().any(|word| *word != 0))
    }

    /// Subtracts `rhs`, returning false if the unsigned result would be
    /// negative. The wrapped output must be discarded in that case.
    pub(crate) fn sub_assign<const K: usize>(&mut self, rhs: Wide<K>) -> bool {
        let mut borrow = false;
        for index in 0..L {
            let word = rhs.0.get(index).copied().unwrap_or(0);
            let (difference, first_borrow) = self.0[index].overflowing_sub(word);
            let (difference, second_borrow) = difference.overflowing_sub(u64::from(borrow));
            self.0[index] = difference;
            borrow = first_borrow || second_borrow;
        }
        !borrow
            && !rhs
                .0
                .get(L..)
                .is_some_and(|words| words.iter().any(|word| *word != 0))
    }

    pub(crate) fn div_rem(self, modulus: U256) -> (Wide<L>, U256) {
        debug_assert!(modulus.0[3] >> 63 != 0);
        let mut quotient = [0; L];
        let mut dividend = self.0;
        let dividend_len = dividend
            .iter()
            .rposition(|word| *word != 0)
            .map_or(0, |index| index + 1);
        if dividend_len <= 4 {
            let mut remainder = [0; 4];
            remainder[..dividend_len].copy_from_slice(&dividend[..dividend_len]);
            let remainder = U256(remainder);
            if remainder.cmp_words(modulus) == Ordering::Less {
                return (Wide(quotient), remainder);
            }
        }

        // Knuth's Algorithm D. Both P-256 moduli are already normalized (the
        // top divisor bit is set), so no normalization shifts are needed.
        let divisor_high = modulus.0[3];
        let divisor_next = modulus.0[2];
        let quotient_len = dividend_len - 3;
        let mut extra_high = 0_u64;
        for j in (0..quotient_len).rev() {
            let active_len = 4 + j;
            let high = dividend[active_len - 1];
            let next = dividend[active_len - 2];
            let (mut estimate, mut estimate_remainder) = if extra_high < divisor_high {
                let numerator = (u128::from(extra_high) << 64) | u128::from(high);
                (
                    (numerator / u128::from(divisor_high)) as u64,
                    numerator % u128::from(divisor_high),
                )
            } else {
                debug_assert_eq!(extra_high, divisor_high);
                (u64::MAX, u128::from(extra_high) + u128::from(high))
            };

            while estimate_remainder <= u128::from(u64::MAX)
                && (estimate_remainder << 64) + u128::from(next)
                    < u128::from(estimate) * u128::from(divisor_next)
            {
                estimate -= 1;
                estimate_remainder += u128::from(divisor_high);
            }

            let mut offset_carry = u64::MAX;
            for (word, divisor) in dividend[j..j + 4].iter_mut().zip(modulus.0) {
                let offset_sum = (u128::from(u64::MAX) << 64) + u128::from(*word)
                    - u128::from(u64::MAX)
                    + u128::from(offset_carry)
                    - u128::from(divisor) * u128::from(estimate);
                *word = offset_sum as u64;
                offset_carry = (offset_sum >> 64) as u64;
            }
            let mut borrow = u64::MAX - offset_carry;
            if borrow > extra_high {
                estimate -= 1;
                let mut carry = false;
                for (word, divisor) in dividend[j..j + 4].iter_mut().zip(modulus.0) {
                    let (sum, first_carry) = word.overflowing_add(divisor);
                    let (sum, second_carry) = sum.overflowing_add(u64::from(carry));
                    *word = sum;
                    carry = first_carry || second_carry;
                }
                borrow -= u64::from(carry);
            }
            debug_assert_eq!(borrow, extra_high);
            quotient[j] = estimate;
            extra_high = dividend[active_len - 1];
        }

        let remainder = U256([dividend[0], dividend[1], dividend[2], extra_high]);
        debug_assert!(remainder.cmp_words(modulus) == Ordering::Less);
        (Wide(quotient), remainder)
    }
}

pub(crate) fn multiply_wide(left: Wide<9>, right: Wide<9>) -> Wide<18> {
    let mut output = [0; 18];
    let left_len = left
        .0
        .iter()
        .rposition(|word| *word != 0)
        .map_or(0, |index| index + 1);
    let right_len = right
        .0
        .iter()
        .rposition(|word| *word != 0)
        .map_or(0, |index| index + 1);
    for i in 0..left_len {
        let mut carry = 0_u128;
        for j in 0..right_len {
            let accumulated =
                u128::from(left.0[i]) * u128::from(right.0[j]) + u128::from(output[i + j]) + carry;
            output[i + j] = accumulated as u64;
            carry = accumulated >> 64;
        }
        output[i + right_len] = carry as u64;
    }
    Wide(output)
}

pub(crate) fn widen_u256<const L: usize>(value: U256) -> Wide<L> {
    assert!(L >= 4);
    let mut output = [0; L];
    output[..4].copy_from_slice(&value.0);
    Wide(output)
}

pub(crate) fn modulus_multiple(modulus: Modulus, factor: usize) -> Wide<9> {
    let factor = u64::try_from(factor).expect("P-256 representative bound exceeds u64");
    let mut output = [0; 9];
    let mut carry = 0_u128;
    for (index, word) in modulus.words().0.into_iter().enumerate() {
        let product = u128::from(word) * u128::from(factor) + carry;
        output[index] = product as u64;
        carry = product >> 64;
    }
    output[4] = carry as u64;
    Wide(output)
}

pub(crate) fn packed_wide<const N: usize, const M: usize, const L: usize>(
    value: Wide<L>,
) -> PackedBits<N, M> {
    PackedBits::from_words(array::from_fn(|index| {
        value.0.get(index).copied().unwrap_or(0)
    }))
}

pub(crate) fn packed_wide_remainder_quotient<const N: usize, const M: usize, const L: usize>(
    remainder: U256,
    quotient: Wide<L>,
) -> PackedBits<N, M> {
    PackedBits::from_words(array::from_fn(|index| {
        if index < 4 {
            remainder.0[index]
        } else {
            quotient.0.get(index - 4).copied().unwrap_or(0)
        }
    }))
}

pub(crate) fn modular_inverse_u256(u: U256, v: U256) -> Option<U256> {
    if u.cmp_words(v) != Ordering::Less {
        return None;
    }
    if u.is_zero() || v.is_zero() || v.is_even() {
        return None;
    }
    if u.0 == [1, 0, 0, 0] {
        return Some(u);
    }
    let value = CryptoU256::from_words(u.0);
    let modulus: Option<Odd<CryptoU256>> = Odd::new(CryptoU256::from_words(v.0)).into();
    let inverse: Option<CryptoU256> = value.invert_odd_mod_vartime(&modulus?).into();
    inverse.map(|inverse| U256(inverse.to_words()))
}

pub(crate) fn modular_inverse(value: &S, modulus: &S) -> Option<S> {
    let reduced;
    let value = if value < modulus {
        value
    } else {
        reduced = value % modulus;
        &reduced
    };
    modular_inverse_u256(U256::try_from(value).ok()?, U256::try_from(modulus).ok()?).map(S::from)
}

pub(crate) fn point_from_elems<CS: Circuit>(x: &Elem<CS>, y: &Elem<CS>) -> Point<CS> {
    Point {
        x: of_elem(x),
        y: of_elem(y),
        infinity: lc_u64(0),
    }
}

pub(crate) fn infinity<CS: Circuit>() -> Point<CS> {
    Point {
        x: rep_u64(0),
        y: rep_u64(0),
        infinity: lc_u64(1),
    }
}

pub(crate) fn and_bit<CS: Circuit>(circuit: &mut CS, x: Lc<CS>, y: Lc<CS>) -> Lc<CS> {
    let x_eval = x.capture();
    let y_eval = y.capture();
    let bits = circuit.hint::<P256_Z_LIMBS, 1, 1, _>(move |context| {
        let value = evaluated_is_one(x_eval.evaluate_words(context))
            && evaluated_is_one(y_eval.evaluate_words(context));
        Ok(PackedBits::from_array([value]))
    });
    let out = uint_from_repr::<CS, 1, 1>(circuit, bits).value;
    circuit.assert_r1c::<P256_Z_LIMBS>(x.z, y.z, out.z.clone());
    out
}

pub(crate) fn and3_bit<CS: Circuit>(circuit: &mut CS, x: Lc<CS>, y: Lc<CS>, z: Lc<CS>) -> Lc<CS> {
    let xy = and_bit(circuit, x, y);
    and_bit(circuit, z, xy)
}

pub(crate) fn lazy_zero_test<CS: Circuit>(
    circuit: &mut CS,
    modulus: Modulus,
    x: Rep<CS>,
) -> Lc<CS> {
    let x_eval = x.value.capture();
    let modulus_words = modulus.words();
    let bits = circuit.hint::<P256_Z_LIMBS, 257, 5, _>(move |context| {
        let a = Wide::<9>::from_evaluated(x_eval.evaluate_words(context), "zero-test operand")?;
        let (_, value) = a.div_rem(modulus_words);
        let is_zero = value.is_zero();
        let inverse = modular_inverse_u256(value, modulus_words).unwrap_or(U256::ZERO);
        Ok(packed_flag_inverse_u256(is_zero, inverse))
    });
    let z_bits = bits.slice::<1, 1>(0);
    let inverse_bits = bits.slice::<256, 4>(1);
    let z = uint_from_repr::<CS, 1, 1>(circuit, z_bits).value;
    let inverse = uint_from_repr::<CS, 256, 4>(circuit, inverse_bits);
    lazy_assert_mul_eq(
        circuit,
        modulus,
        x.clone(),
        of_elem(&Elem { value: inverse }),
        Rep {
            value: lc_u64::<CS>(1).sub(z.clone()),
            bound: 1,
        },
    );

    let z_eval = z.capture();
    let x_eval = x.value.capture();
    let modulus_words = modulus.words();
    let q_bits = circuit.hint::<P256_Z_LIMBS, 9, 1, _>(move |context| {
        let z = Wide::<9>::from_evaluated(z_eval.evaluate_words(context), "zero-test flag")?;
        let x = Wide::<9>::from_evaluated(
            x_eval.evaluate_words(context),
            "zero-test quotient operand",
        )?;
        let product = multiply_wide(z, x);
        let (quotient, remainder) = product.div_rem(modulus_words);
        debug_assert!(remainder.is_zero());
        Ok(packed_wide(quotient))
    });
    let q = uint_from_repr::<CS, 9, 1>(circuit, q_bits);
    circuit.assert_r1c::<P256_Z_LIMBS>(z.z.clone(), x.value.z, q.value.scale(modulus.value()).z);
    z
}

pub(crate) fn select_rep<CS: Circuit, const N: usize, const M: usize>(
    circuit: &mut CS,
    choose: Lc<CS>,
    when_one: Rep<CS>,
    when_zero: Rep<CS>,
    out_bound: usize,
) -> Rep<CS> {
    let choose_eval = choose.capture();
    let one_eval = when_one.value.capture();
    let zero_eval = when_zero.value.capture();
    let bits = circuit.hint::<P256_Z_LIMBS, N, M, _>(move |context| {
        let value = if evaluated_is_one(choose_eval.evaluate_words(context)) {
            one_eval.evaluate_words(context)
        } else {
            zero_eval.evaluate_words(context)
        };
        packed_evaluated(value, "selection")
    });
    let out = uint_from_repr::<CS, N, M>(circuit, bits).value;
    let difference = when_one.value.sub(when_zero.value.clone());
    let output_difference = out.clone().sub(when_zero.value);
    circuit.assert_r1c::<P256_Z_LIMBS>(choose.z, difference.z, output_difference.z);
    Rep {
        value: out,
        bound: out_bound,
    }
}

pub(crate) fn select_canonical<CS: Circuit>(
    circuit: &mut CS,
    choose: Lc<CS>,
    when_one: Rep<CS>,
    when_zero: Rep<CS>,
) -> Rep<CS> {
    select_rep::<CS, 256, 4>(circuit, choose, when_one, when_zero, 2)
}

pub(crate) fn select_formula<CS: Circuit>(
    circuit: &mut CS,
    choose: Lc<CS>,
    when_one: Rep<CS>,
    when_zero: Rep<CS>,
) -> Rep<CS> {
    select_rep::<CS, 262, 5>(circuit, choose, when_one, when_zero, 66)
}

pub(crate) fn double_complete<CS: Circuit>(
    circuit: &mut CS,
    curve: Curve,
    point: Point<CS>,
) -> Point<CS> {
    let x2 = lazy_mul(circuit, curve.base(), point.x.clone(), point.x.clone());
    // With a = -3 the infinity flag restores a zero numerator at (0, 0);
    // with a = 0 the numerator 3x^2 already vanishes there.
    let numerator = if curve.a_is_minus_three() {
        rep_add(
            rep_sub(curve.base(), rep_scale(3, x2), rep_u64::<CS>(3)),
            Rep {
                value: point
                    .infinity
                    .clone()
                    .scale_coefficient(P256Coefficient::<CS>::from(3_u64)),
                bound: 1,
            },
        )
    } else {
        rep_scale(3, x2)
    };
    let denominator = rep_add(
        rep_scale(2, point.y.clone()),
        Rep {
            value: point.infinity.clone(),
            bound: 1,
        },
    );
    let slope = lazy_divide(circuit, curve.base(), denominator, numerator);
    let x3 = lazy_mul_sub_to_elem(
        circuit,
        curve.base(),
        slope.clone(),
        slope.clone(),
        rep_scale(2, point.x.clone()),
    );
    let x3_rep = of_elem(&x3);
    let y3 = lazy_mul_sub_to_elem(
        circuit,
        curve.base(),
        slope,
        rep_sub(curve.base(), point.x, x3_rep.clone()),
        point.y,
    );
    Point {
        x: x3_rep,
        y: of_elem(&y3),
        infinity: point.infinity,
    }
}

pub(crate) struct AddControl<CS: Circuit> {
    pub(crate) same_x: Lc<CS>,
    pub(crate) opposite_y: Lc<CS>,
    pub(crate) finite: Lc<CS>,
    pub(crate) double_case: Lc<CS>,
    pub(crate) active: Lc<CS>,
}

pub(crate) fn add_complete<CS: Circuit>(
    circuit: &mut CS,
    curve: Curve,
    p: Point<CS>,
    q: Point<CS>,
) -> Point<CS> {
    let dx = rep_sub(curve.base(), q.x.clone(), p.x.clone());
    let y_sum = rep_add(p.y.clone(), q.y.clone());
    let same_x = lazy_zero_test(circuit, curve.base(), dx.clone());
    let opposite_y = lazy_zero_test(circuit, curve.base(), y_sum);
    let finite = and_bit(
        circuit,
        lc_u64::<CS>(1).sub(p.infinity.clone()),
        lc_u64::<CS>(1).sub(q.infinity.clone()),
    );
    let double_kind = and_bit(
        circuit,
        same_x.clone(),
        lc_u64::<CS>(1).sub(opposite_y.clone()),
    );
    let double_case = and_bit(circuit, finite.clone(), double_kind);
    let generic_case = and_bit(circuit, finite.clone(), lc_u64::<CS>(1).sub(same_x.clone()));
    let control = AddControl {
        same_x,
        opposite_y,
        finite,
        double_case: double_case.clone(),
        active: double_case.add(generic_case),
    };

    let dy = rep_sub(curve.base(), q.y.clone(), p.y.clone());
    let x2 = lazy_mul(circuit, curve.base(), p.x.clone(), p.x.clone());
    let double_numerator = if curve.a_is_minus_three() {
        rep_sub(curve.base(), rep_scale(3, x2), rep_u64::<CS>(3))
    } else {
        rep_scale(3, x2)
    };
    let double_denominator = rep_scale(2, p.y.clone());
    let selected_numerator =
        select_formula(circuit, control.double_case.clone(), double_numerator, dy);
    let selected_denominator =
        select_formula(circuit, control.double_case.clone(), double_denominator, dx);
    let numerator = select_formula(
        circuit,
        control.active.clone(),
        selected_numerator,
        rep_u64(0),
    );
    let denominator = select_formula(
        circuit,
        control.active.clone(),
        selected_denominator,
        rep_u64(1),
    );
    let slope = lazy_divide(circuit, curve.base(), denominator, numerator);
    let candidate_x = lazy_mul_sub_to_elem(
        circuit,
        curve.base(),
        slope.clone(),
        slope.clone(),
        rep_add(p.x.clone(), q.x.clone()),
    );
    let candidate_x = of_elem(&candidate_x);
    let candidate_y = lazy_mul_sub_to_elem(
        circuit,
        curve.base(),
        slope,
        rep_sub(curve.base(), p.x.clone(), candidate_x.clone()),
        p.y.clone(),
    );
    let candidate_y = of_elem(&candidate_y);

    let inactive_x0 = select_canonical(circuit, q.infinity.clone(), p.x.clone(), rep_u64(0));
    let inactive_y0 = select_canonical(circuit, q.infinity.clone(), p.y.clone(), rep_u64(0));
    let inactive_x = select_canonical(circuit, p.infinity.clone(), q.x.clone(), inactive_x0);
    let inactive_y = select_canonical(circuit, p.infinity.clone(), q.y.clone(), inactive_y0);
    let x = select_canonical(circuit, control.active.clone(), candidate_x, inactive_x);
    let y = select_canonical(circuit, control.active, candidate_y, inactive_y);
    let both_infinity = and_bit(circuit, p.infinity, q.infinity);
    let finite_opposite = and3_bit(circuit, control.same_x, control.opposite_y, control.finite);
    Point {
        x,
        y,
        infinity: both_infinity.add(finite_opposite),
    }
}

pub(crate) fn materialize_multiples<CS: Circuit>(
    circuit: &mut CS,
    curve: Curve,
    q: Point<CS>,
) -> Vec<Point<CS>> {
    let p1 = q;
    let mut output = Vec::with_capacity(16);
    output.push(infinity());
    output.push(p1.clone());
    let mut previous = p1.clone();
    for _ in 2..16 {
        previous = add_complete(circuit, curve, previous, p1.clone());
        output.push(previous.clone());
    }
    output
}

pub(crate) fn indicators_impl<CS: Circuit, const N: usize, const M: usize>(
    circuit: &mut CS,
    digit: Lc<CS>,
) -> (UInt<CS, N, M>, Vec<Lc<CS>>) {
    let digit_eval = digit.capture();
    let bits = circuit.hint::<P256_Z_LIMBS, N, M, _>(move |context| {
        let digit = evaluated_usize(digit_eval.evaluate_words(context), "indicator digit")?;
        Ok(PackedBits::from_fn(|i| digit == i))
    });
    let bit_handles = repr_bits::<CS::Bool, N, M>(&bits);
    let mut lifted = Vec::with_capacity(N);
    let mut full = P256Z::<CS>::zero();
    let mut power = P256Coefficient::<CS>::one();
    for bit in &bit_handles {
        let z = circuit.bitz::<P256_Z_LIMBS>(bit.clone());
        full += z.clone() * power.clone();
        lifted.push(Lc { z });
        power += power.clone();
    }
    let out = UInt {
        bits,
        value: Lc { z: full },
    };
    let sum = lifted.iter().cloned().fold(lc_u64::<CS>(0), Lc::add);
    assert_zero(circuit, sum.sub(lc_u64(1)));
    let weighted = lifted
        .iter()
        .cloned()
        .enumerate()
        .fold(lc_u64::<CS>(0), |sum, (i, bit)| {
            sum.add(bit.scale_coefficient(P256Coefficient::<CS>::from(i as u64)))
        });
    assert_zero(circuit, weighted.sub(digit));
    (out, lifted)
}

pub(crate) fn lookup_rep<CS: Circuit>(
    circuit: &mut CS,
    digit: Lc<CS>,
    indicators: &[Lc<CS>],
    values: &[Rep<CS>],
) -> Rep<CS> {
    let digit_eval = digit.capture();
    let value_evals: Vec<_> = values.iter().map(|value| value.value.capture()).collect();
    let bits = circuit.hint::<P256_Z_LIMBS, 256, 4, _>(move |context| {
        let index = evaluated_usize(digit_eval.evaluate_words(context), "lookup digit")?;
        let expression = value_evals
            .get(index)
            .ok_or_else(|| HintError::new("lookup digit out of range"))?;
        packed_evaluated(expression.evaluate_words(context), "lookup value")
    });
    let out = uint_from_repr::<CS, 256, 4>(circuit, bits).value;
    for (indicator, value) in indicators.iter().zip(values) {
        circuit.assert_r1c::<P256_Z_LIMBS>(
            indicator.z.clone(),
            out.clone().sub(value.value.clone()).z,
            P256Z::<CS>::zero(),
        );
    }
    Rep {
        value: out,
        bound: 2,
    }
}

pub(crate) fn lookup_flag<CS: Circuit>(
    circuit: &mut CS,
    digit: Lc<CS>,
    indicators: &[Lc<CS>],
    flags: &[Lc<CS>],
) -> Lc<CS> {
    let digit_eval = digit.capture();
    let flag_evals: Vec<_> = flags.iter().map(Lc::capture).collect();
    let bits = circuit.hint::<P256_Z_LIMBS, 1, 1, _>(move |context| {
        let index = evaluated_usize(digit_eval.evaluate_words(context), "flag lookup digit")?;
        let flag = flag_evals
            .get(index)
            .ok_or_else(|| HintError::new("flag lookup digit out of range"))?;
        Ok(PackedBits::from_array([evaluated_is_one(
            flag.evaluate_words(context),
        )]))
    });
    let out = uint_from_repr::<CS, 1, 1>(circuit, bits).value;
    for (indicator, flag) in indicators.iter().zip(flags) {
        circuit.assert_r1c::<P256_Z_LIMBS>(
            indicator.z.clone(),
            out.clone().sub(flag.clone()).z,
            P256Z::<CS>::zero(),
        );
    }
    out
}

pub(crate) fn lookup_point<CS: Circuit>(
    circuit: &mut CS,
    digit: Lc<CS>,
    table: &[Point<CS>],
) -> Point<CS> {
    let (_, indicator_bits) = indicators_impl::<CS, 16, 1>(circuit, digit.clone());
    let xs: Vec<_> = table.iter().map(|point| point.x.clone()).collect();
    let ys: Vec<_> = table.iter().map(|point| point.y.clone()).collect();
    let flags: Vec<_> = table.iter().map(|point| point.infinity.clone()).collect();
    Point {
        x: lookup_rep(circuit, digit.clone(), &indicator_bits, &xs),
        y: lookup_rep(circuit, digit.clone(), &indicator_bits, &ys),
        infinity: lookup_flag(circuit, digit, &indicator_bits, &flags),
    }
}

pub(crate) fn generator_table(curve: Curve) -> &'static Vec<(S, S)> {
    static P256_TABLE: OnceLock<Vec<(S, S)>> = OnceLock::new();
    static K1_TABLE: OnceLock<Vec<(S, S)>> = OnceLock::new();
    let table = match curve {
        Curve::P256 => &P256_TABLE,
        Curve::Secp256k1 => &K1_TABLE,
    };
    table.get_or_init(|| {
        let modulus = curve.base().value();
        let (gx, gy) = curve.generator();
        let generator = (gx.clone(), gy.clone());
        let mut table = Vec::with_capacity(256);
        table.push((S::zero(), S::zero()));
        let mut point = generator.clone();
        table.push(point.clone());
        for _ in 2..256 {
            point = affine_add(curve, &point, &generator, modulus);
            table.push(point.clone());
        }
        table
    })
}

/// Materializes the fixed-base generator tables used by witness generation.
/// Call this during benchmark or service setup to exclude one-time constant
/// initialization from latency measurements.
pub fn prepare() {
    let _ = generator_table(Curve::P256);
    let _ = generator_table(Curve::Secp256k1);
}

pub(crate) fn affine_add(curve: Curve, left: &(S, S), right: &(S, S), modulus: &S) -> (S, S) {
    let numerator = if left == right {
        let a_term = if curve.a_is_minus_three() {
            modulus - S::from(3_u64)
        } else {
            S::zero()
        };
        (S::from(3_u64) * &left.0 * &left.0 + a_term) % modulus
    } else {
        (&right.1 + modulus - &left.1) % modulus
    };
    let denominator = if left == right {
        (S::from(2_u64) * &left.1) % modulus
    } else {
        (&right.0 + modulus - &left.0) % modulus
    };
    let slope = numerator * modular_inverse(&denominator, modulus).unwrap() % modulus;
    let x = (&slope * &slope + modulus * 2_u64 - &left.0 - &right.0) % modulus;
    let y = (&slope * ((&left.0 + modulus - &x) % modulus) + modulus - &left.1) % modulus;
    (x, y)
}

pub(crate) fn generator_coefficients<CS: Circuit>(
    curve: Curve,
) -> Vec<(P256Coefficient<CS>, P256Coefficient<CS>)> {
    generator_table(curve)
        .iter()
        .map(|(x, y)| (coefficient_for::<CS>(x), coefficient_for::<CS>(y)))
        .collect()
}

pub(crate) fn lookup_generator_byte<CS: Circuit>(
    circuit: &mut CS,
    digit: Lc<CS>,
    table: &[(P256Coefficient<CS>, P256Coefficient<CS>)],
) -> Point<CS> {
    let (_, indicators) = indicators_impl::<CS, 256, 4>(circuit, digit);
    let x = indicators
        .iter()
        .zip(table)
        .fold(lc_u64::<CS>(0), |sum, (bit, (x, _))| {
            sum.add(bit.clone().scale_coefficient(x.clone()))
        });
    let y = indicators
        .iter()
        .zip(table)
        .fold(lc_u64::<CS>(0), |sum, (bit, (_, y))| {
            sum.add(bit.clone().scale_coefficient(y.clone()))
        });
    Point {
        x: Rep { value: x, bound: 2 },
        y: Rep { value: y, bound: 2 },
        infinity: indicators[0].clone(),
    }
}

// A UInt retains the combined integer LC, but Lean's window expressions refer
// to individual intBits. Keep those lifts explicitly for scalar windows.
pub(crate) struct ScalarElem<CS: Circuit> {
    pub(crate) elem: Elem<CS>,
    pub(crate) int_bits: Vec<Lc<CS>>,
}

impl<CS: Circuit> Clone for ScalarElem<CS> {
    fn clone(&self) -> Self {
        Self {
            elem: self.elem.clone(),
            int_bits: self.int_bits.clone(),
        }
    }
}

pub(crate) fn lift_input_word<CS: Circuit>(
    circuit: &mut CS,
    bits: <CS::Bool as BoolWitness>::Repr<256, 4>,
) -> ScalarElem<CS> {
    let handles = repr_bits::<CS::Bool, 256, 4>(&bits);
    let mut lifted = Vec::with_capacity(256);
    let mut z = P256Z::<CS>::zero();
    let mut power = P256Coefficient::<CS>::one();
    for bit in handles {
        let bit_z = circuit.bitz::<P256_Z_LIMBS>(bit.clone());
        z += bit_z.clone() * power.clone();
        lifted.push(Lc { z: bit_z });
        power += power.clone();
    }
    ScalarElem {
        elem: Elem {
            value: UInt {
                bits,
                value: Lc { z },
            },
        },
        int_bits: lifted,
    }
}

pub(crate) fn scalar_window<CS: Circuit>(
    scalar: &ScalarElem<CS>,
    start: usize,
    width: usize,
) -> Lc<CS> {
    scalar.int_bits[start..start + width]
        .iter()
        .cloned()
        .enumerate()
        .fold(lc_u64::<CS>(0), |sum, (bit, value)| {
            sum.add(value.scale_coefficient(P256Coefficient::<CS>::from(1_u64 << bit)))
        })
}

pub(crate) fn joint_scalar_mul<CS: Circuit>(
    circuit: &mut CS,
    curve: Curve,
    u1: ScalarElem<CS>,
    u2: ScalarElem<CS>,
    q: Point<CS>,
) -> Point<CS> {
    let q_table = materialize_multiples(circuit, curve, q);
    let g_table = generator_coefficients::<CS>(curve);
    let mut accumulator = infinity();
    for i in 0..32 {
        let d1 = scalar_window(&u1, 248 - 8 * i, 8);
        let d2_hi = scalar_window(&u2, 252 - 8 * i, 4);
        let d2_lo = scalar_window(&u2, 248 - 8 * i, 4);
        let q_hi = lookup_point(circuit, d2_hi, &q_table);
        let q_lo = lookup_point(circuit, d2_lo, &q_table);
        let g = lookup_generator_byte(circuit, d1, &g_table);
        for _ in 0..4 {
            accumulator = double_complete(circuit, curve, accumulator);
        }
        accumulator = add_complete(circuit, curve, accumulator, q_hi);
        for _ in 0..4 {
            accumulator = double_complete(circuit, curve, accumulator);
        }
        accumulator = add_complete(circuit, curve, accumulator, q_lo);
        accumulator = add_complete(circuit, curve, accumulator, g);
    }
    accumulator
}

pub(crate) fn assert_on_curve<CS: Circuit>(
    circuit: &mut CS,
    curve: Curve,
    x: &Elem<CS>,
    y: &Elem<CS>,
) {
    let x = of_elem(x);
    let y = of_elem(y);
    let x2 = lazy_mul(circuit, curve.base(), x.clone(), x.clone());
    let x3 = lazy_mul(circuit, curve.base(), x2, x.clone());
    let x3_plus_b = rep_add(x3, rep_constant(curve.b()));
    let rhs = if curve.a_is_minus_three() {
        rep_sub(curve.base(), x3_plus_b, rep_scale(3, x))
    } else {
        x3_plus_b
    };
    lazy_assert_mul_eq(circuit, curve.base(), y.clone(), y, rhs);
}

pub(crate) fn assert_elem_eq<CS: Circuit>(circuit: &mut CS, left: &Elem<CS>, right: &Elem<CS>) {
    assert_zero(
        circuit,
        left.value.value.clone().sub(right.value.value.clone()),
    );
}

/// Builds the standalone ECDSA verifier for `curve` from seven little-endian
/// 256-bit input words ordered as digest, Q.x, Q.y, r, s, r^-1, s^-1.
pub fn verify_digest_circuit<CS: Circuit>(
    circuit: &mut CS,
    curve: Curve,
    inputs: &[CS::Bool; VERIFY_DIGEST_INPUT_BITS],
) {
    let words: [<CS::Bool as BoolWitness>::Repr<256, 4>; 7] = array::from_fn(|slot| {
        <CS::Bool as BoolWitness>::Repr::from_array(array::from_fn(|bit| {
            inputs[slot * WIDTH + bit].clone()
        }))
    });
    // These seven U.fromWord calls are deliberately kept in input order.
    let mut words = words.into_iter();
    let digest = lift_input_word(circuit, words.next().unwrap());
    let qx = lift_input_word(circuit, words.next().unwrap());
    let qy = lift_input_word(circuit, words.next().unwrap());
    let r = lift_input_word(circuit, words.next().unwrap());
    let s = lift_input_word(circuit, words.next().unwrap());
    let r_inverse = lift_input_word(circuit, words.next().unwrap());
    let s_inverse = lift_input_word(circuit, words.next().unwrap());

    let qx = of_u(circuit, curve.base(), qx.elem.value);
    let qy = of_u(circuit, curve.base(), qy.elem.value);
    let r = of_u(circuit, curve.scalar(), r.elem.value);
    let s = of_u(circuit, curve.scalar(), s.elem.value);
    let r_inverse = of_u(circuit, curve.scalar(), r_inverse.elem.value);
    let s_inverse = of_u(circuit, curve.scalar(), s_inverse.elem.value);

    assert_on_curve(circuit, curve, &qx, &qy);
    lazy_assert_mul_eq(
        circuit,
        curve.scalar(),
        of_elem(&r),
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

    let z = relaxed_reduce_small(circuit, curve.scalar(), digest.elem.value.value);
    let u1_relaxed = relaxed_mul(circuit, curve.scalar(), z, s_inverse.clone());
    let u2_relaxed = relaxed_mul(circuit, curve.scalar(), r.clone(), s_inverse);
    let u1 = lazy_reduce_scalar(circuit, curve.scalar(), of_elem(&u1_relaxed));
    let u2 = lazy_reduce_scalar(circuit, curve.scalar(), of_elem(&u2_relaxed));

    let q = point_from_elems(&qx, &qy);
    let sum = joint_scalar_mul(circuit, curve, u1, u2, q);
    assert_zero(circuit, sum.infinity);
    let x_canonical = lazy_reduce(circuit, curve.base(), sum.x);
    let x_mod_n = relaxed_reduce_small(circuit, curve.scalar(), x_canonical.value.value);
    assert_elem_eq(circuit, &x_mod_n, &r);
}
