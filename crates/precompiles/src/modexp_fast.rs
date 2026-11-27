//! Fast stack-allocated 256-bit modular exponentiation installed as evm2 global [`Crypto`]
//! provider for the MODEXP (0x05) precompile.
//!
//! Covers:
//! - secp256k1 base field (p = 2^256 - 2^32 - 977) with direct pseudo-Mersenne reduction and
//!   the optimal 253-squaring, 13-multiplication addition chain for e = (p + 1) / 4 (square root /
//!   point decompression), plus inv_mod for e = p - 2 and 4-bit windowed exponentiation for
//!   other exponents.
//! - Arbitrary odd moduli up to 256 bits (m > 1) via stack-allocated 4-limb CIOS Montgomery
//!   multiplication and 4-bit windowed exponentiation.
//! - Larger or even moduli delegate directly to [`DefaultCrypto`].

use alloy_primitives::{U256, uint};
use evm2::precompiles::{Crypto, DefaultCrypto, PrecompileHalt, install_crypto};
use std::sync::Once;

/// secp256k1 base field prime p = 2^256 - 2^32 - 977.
const SECP256K1_P: U256 =
    uint!(0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_U256);

/// (SECP256K1_P + 1) / 4: square-root exponent mod SECP256K1_P.
const SECP256K1_SQRT_EXP: U256 =
    uint!(0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c_U256);

/// SECP256K1_P - 2: Fermat inverse exponent mod SECP256K1_P.
const SECP256K1_INV_EXP: U256 =
    uint!(0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d_U256);

/// (SECP256K1_P - 1) / 2: Euler criterion (Legendre symbol) exponent mod SECP256K1_P.
const SECP256K1_EULER_EXP: U256 =
    uint!(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe17_U256);

/// 2^256 - SECP256K1_P = 2^32 + 977.
const SECP256K1_K: u64 = 0x1_0000_03d1;

/// Well-known primes for Fermat inverse fast path (e == p - 2).
const FERMAT_PRIMES: [U256; 6] = uint!([
    0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001_U256,
    0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47_U256,
    0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_U256,
    0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141_U256,
    0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff_U256,
    0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551_U256,
]);

/// Global Tempo [`Crypto`] provider accelerating 256-bit MODEXP.
#[derive(Clone, Copy, Debug, Default)]
pub struct TempoCrypto;

/// Installs [`TempoCrypto`] as evm2 global crypto provider (idempotent).
#[inline]
pub fn install_tempo_crypto() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let _ = install_crypto(TempoCrypto);
    });
}

impl Crypto for TempoCrypto {
    #[inline]
    fn modexp(&self, base: &[u8], exp: &[u8], modulus: &[u8]) -> Result<Vec<u8>, PrecompileHalt> {
        if let Some(res) = modexp_u256_fast(base, exp, modulus) {
            return Ok(res);
        }
        DefaultCrypto::new().modexp(base, exp, modulus)
    }
}

#[inline]
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[first_nonzero..]
}

#[inline]
fn u256_to_be_minimal(v: U256) -> Vec<u8> {
    if v.is_zero() {
        return Vec::new();
    }
    let bytes = v.to_be_bytes::<32>();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(32);
    bytes[start..].to_vec()
}

/// Fast path for operands whose significant bytes fit in 256 bits (<= 32 bytes).
/// Returns None for even moduli > 1 or operands wider than 256 bits.
pub(crate) fn modexp_u256_fast(base: &[u8], exp: &[u8], modulus: &[u8]) -> Option<Vec<u8>> {
    let m_bytes = strip_leading_zeros(modulus);
    if m_bytes.is_empty() {
        return Some(Vec::new());
    }
    if m_bytes.len() > 32 {
        return None;
    }
    let b_bytes = strip_leading_zeros(base);
    let e_bytes = strip_leading_zeros(exp);
    if b_bytes.len() > 32 || e_bytes.len() > 32 {
        return None;
    }

    let m = U256::from_be_slice(m_bytes);
    if m == U256::from(1u64) {
        return Some(Vec::new());
    }
    if e_bytes.is_empty() {
        return Some(vec![1u8]);
    }
    if b_bytes.is_empty() {
        return Some(Vec::new());
    }

    let e = U256::from_be_slice(e_bytes);
    let b = U256::from_be_slice(b_bytes);

    if m == SECP256K1_P {
        let b_red = if b >= SECP256K1_P { b - SECP256K1_P } else { b };
        if b_red.is_zero() {
            return Some(Vec::new());
        }
        let res = if e == SECP256K1_EULER_EXP {
            legendre_euler(b_red, SECP256K1_P)
        } else if e == SECP256K1_SQRT_EXP {
            secp256k1_pow_sqrt(b_red)
        } else if e == SECP256K1_INV_EXP {
            b_red.inv_mod(SECP256K1_P).unwrap_or_default()
        } else {
            secp256k1_pow(b_red, e)
        };
        return Some(u256_to_be_minimal(res));
    }

    if !m.bit(0) {
        return None;
    }

    if e == m - U256::from(2u64) && FERMAT_PRIMES.contains(&m) {
        let inv = b.inv_mod(m).unwrap_or_default();
        return Some(u256_to_be_minimal(inv));
    }
    if e == ((m - U256::from(1u64)) >> 1usize) && FERMAT_PRIMES.contains(&m) {
        let b_red = if b >= m { b % m } else { b };
        if b_red.is_zero() {
            return Some(Vec::new());
        }
        return Some(u256_to_be_minimal(legendre_euler(b_red, m)));
    }

    let b_red = if b >= m { b % m } else { b };
    if b_red.is_zero() {
        return Some(Vec::new());
    }
    let res = mont_pow_u256(b_red, e, m);
    Some(u256_to_be_minimal(res))
}

#[inline(always)]
fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let sum = u128::from(a) + u128::from(b) + u128::from(carry);
    (sum as u64, (sum >> 64) as u64)
}

#[inline(always)]
fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let diff = u128::from(a).wrapping_sub(u128::from(b) + u128::from(borrow));
    (diff as u64, (diff >> 127) as u64)
}

#[inline(always)]
fn mac(acc: u64, a: u64, b: u64, carry: u64) -> (u64, u64) {
    let prod = u128::from(acc) + u128::from(a) * u128::from(b) + u128::from(carry);
    (prod as u64, (prod >> 64) as u64)
}

#[inline(always)]
fn secp256k1_reduce_512(t: [u64; 8]) -> [u64; 4] {
    let (r0, c) = mac(t[0], t[4], SECP256K1_K, 0);
    let (r1, c) = mac(t[1], t[5], SECP256K1_K, c);
    let (r2, c) = mac(t[2], t[6], SECP256K1_K, c);
    let (r3, c) = mac(t[3], t[7], SECP256K1_K, c);

    let ck = u128::from(c) * u128::from(SECP256K1_K);
    let (r0, c) = adc(r0, ck as u64, 0);
    let (r1, c) = adc(r1, (ck >> 64) as u64, c);
    let (r2, c) = adc(r2, 0, c);
    let (r3, c) = adc(r3, 0, c);

    let (mut r0, mut r1, mut r2, mut r3) = if c != 0 {
        let (r0, c) = adc(r0, SECP256K1_K, 0);
        let (r1, c) = adc(r1, 0, c);
        let (r2, c) = adc(r2, 0, c);
        let (r3, _) = adc(r3, 0, c);
        (r0, r1, r2, r3)
    } else {
        (r0, r1, r2, r3)
    };

    let (d0, b) = sbb(r0, 0xffff_fffe_ffff_fc2f, 0);
    let (d1, b) = sbb(r1, u64::MAX, b);
    let (d2, b) = sbb(r2, u64::MAX, b);
    let (d3, b) = sbb(r3, u64::MAX, b);
    if b == 0 {
        r0 = d0;
        r1 = d1;
        r2 = d2;
        r3 = d3;
    }
    [r0, r1, r2, r3]
}

#[inline(always)]
fn secp256k1_mul(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let (t0, c) = mac(0, a[0], b[0], 0);
    let (t1, c) = mac(0, a[0], b[1], c);
    let (t2, c) = mac(0, a[0], b[2], c);
    let (t3, t4) = mac(0, a[0], b[3], c);

    let (t1, c) = mac(t1, a[1], b[0], 0);
    let (t2, c) = mac(t2, a[1], b[1], c);
    let (t3, c) = mac(t3, a[1], b[2], c);
    let (t4, t5) = mac(t4, a[1], b[3], c);

    let (t2, c) = mac(t2, a[2], b[0], 0);
    let (t3, c) = mac(t3, a[2], b[1], c);
    let (t4, c) = mac(t4, a[2], b[2], c);
    let (t5, t6) = mac(t5, a[2], b[3], c);

    let (t3, c) = mac(t3, a[3], b[0], 0);
    let (t4, c) = mac(t4, a[3], b[1], c);
    let (t5, c) = mac(t5, a[3], b[2], c);
    let (t6, t7) = mac(t6, a[3], b[3], c);

    secp256k1_reduce_512([t0, t1, t2, t3, t4, t5, t6, t7])
}

#[inline(always)]
fn secp256k1_sqr(a: [u64; 4]) -> [u64; 4] {
    let (t1, c) = mac(0, a[0], a[1], 0);
    let (t2, c) = mac(0, a[0], a[2], c);
    let (t3, t4) = mac(0, a[0], a[3], c);

    let (t3, c) = mac(t3, a[1], a[2], 0);
    let (t4, t5) = mac(t4, a[1], a[3], c);

    let (t5, t6) = mac(t5, a[2], a[3], 0);

    let t7 = t6 >> 63;
    let t6 = (t6 << 1) | (t5 >> 63);
    let t5 = (t5 << 1) | (t4 >> 63);
    let t4 = (t4 << 1) | (t3 >> 63);
    let t3 = (t3 << 1) | (t2 >> 63);
    let t2 = (t2 << 1) | (t1 >> 63);
    let t1 = t1 << 1;

    let (t0, c) = mac(0, a[0], a[0], 0);
    let (t1, c) = adc(t1, 0, c);
    let (t2, c) = mac(t2, a[1], a[1], c);
    let (t3, c) = adc(t3, 0, c);
    let (t4, c) = mac(t4, a[2], a[2], c);
    let (t5, c) = adc(t5, 0, c);
    let (t6, c) = mac(t6, a[3], a[3], c);
    let (t7, _) = adc(t7, 0, c);

    secp256k1_reduce_512([t0, t1, t2, t3, t4, t5, t6, t7])
}

#[inline(always)]
fn secp256k1_sqrn(mut a: [u64; 4], n: u32) -> [u64; 4] {
    for _ in 0..n {
        a = secp256k1_sqr(a);
    }
    a
}

/// Computes `a^((p - 1) / 2) mod p` for an odd prime `p` and `0 < a < p` using
/// the multiplication-free binary Jacobi symbol algorithm.
fn legendre_euler(mut a: U256, p: U256) -> U256 {
    let mut n = p;
    let mut neg = false;
    let tz = a.trailing_zeros();
    if tz > 0 {
        a >>= tz;
        if (tz & 1) != 0 {
            let n_mod8 = n.as_limbs()[0] & 7;
            if n_mod8 == 3 || n_mod8 == 5 {
                neg = !neg;
            }
        }
    }
    while a != n {
        if a < n {
            core::mem::swap(&mut a, &mut n);
            if (a.as_limbs()[0] & 3) == 3 && (n.as_limbs()[0] & 3) == 3 {
                neg = !neg;
            }
        }
        a -= n;
        let tz = a.trailing_zeros();
        a >>= tz;
        if (tz & 1) != 0 {
            let n_mod8 = n.as_limbs()[0] & 7;
            if n_mod8 == 3 || n_mod8 == 5 {
                neg = !neg;
            }
        }
    }
    if neg {
        p - U256::from(1u64)
    } else {
        U256::from(1u64)
    }
}

fn secp256k1_pow_sqrt(a: U256) -> U256 {
    let x1 = *a.as_limbs();
    let x2 = secp256k1_mul(secp256k1_sqr(x1), x1);
    let x3 = secp256k1_mul(secp256k1_sqr(x2), x1);
    let x6 = secp256k1_mul(secp256k1_sqrn(x3, 3), x3);
    let x9 = secp256k1_mul(secp256k1_sqrn(x6, 3), x3);
    let x11 = secp256k1_mul(secp256k1_sqrn(x9, 2), x2);
    let x22 = secp256k1_mul(secp256k1_sqrn(x11, 11), x11);
    let x44 = secp256k1_mul(secp256k1_sqrn(x22, 22), x22);
    let x88 = secp256k1_mul(secp256k1_sqrn(x44, 44), x44);
    let x176 = secp256k1_mul(secp256k1_sqrn(x88, 88), x88);
    let x220 = secp256k1_mul(secp256k1_sqrn(x176, 44), x44);
    let x223 = secp256k1_mul(secp256k1_sqrn(x220, 3), x3);

    let t = secp256k1_mul(secp256k1_sqrn(x223, 23), x22);
    let t = secp256k1_mul(secp256k1_sqrn(t, 6), x2);
    let t = secp256k1_sqrn(t, 2);
    U256::from_limbs(t)
}

fn secp256k1_pow(a: U256, exp: U256) -> U256 {
    let mut table = [[0u64; 4]; 16];
    table[0] = [1, 0, 0, 0];
    table[1] = *a.as_limbs();
    for i in 2..16 {
        table[i] = secp256k1_mul(table[i - 1], table[1]);
    }

    let e_limbs = exp.as_limbs();
    let mut acc = [1u64, 0, 0, 0];
    let mut started = false;
    for &limb in e_limbs.iter().rev() {
        for shift in (0..64).step_by(4).rev() {
            let nibble = ((limb >> shift) & 0xf) as usize;
            if started {
                acc = secp256k1_sqr(acc);
                acc = secp256k1_sqr(acc);
                acc = secp256k1_sqr(acc);
                acc = secp256k1_sqr(acc);
                if nibble != 0 {
                    acc = secp256k1_mul(acc, table[nibble]);
                }
            } else if nibble != 0 {
                acc = table[nibble];
                started = true;
            }
        }
    }
    U256::from_limbs(acc)
}

#[inline(always)]
fn mont_inv64(m0: u64) -> u64 {
    let mut inv = m0;
    inv = inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(inv)));
    inv = inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(inv)));
    inv = inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(inv)));
    inv = inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(inv)));
    inv = inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(inv)));
    inv.wrapping_neg()
}

#[inline(always)]
fn mont_mul_cios(a: [u64; 4], b: [u64; 4], m: [u64; 4], m_inv: u64) -> [u64; 4] {
    let mut t = [0u64; 5];
    for &ai in &a {
        let (r0, c) = mac(t[0], ai, b[0], 0);
        let (r1, c) = mac(t[1], ai, b[1], c);
        let (r2, c) = mac(t[2], ai, b[2], c);
        let (r3, c) = mac(t[3], ai, b[3], c);
        let (r4, c2) = adc(t[4], c, 0);

        let k = r0.wrapping_mul(m_inv);
        let (_, c) = mac(r0, k, m[0], 0);
        let (s0, c) = mac(r1, k, m[1], c);
        let (s1, c) = mac(r2, k, m[2], c);
        let (s2, c) = mac(r3, k, m[3], c);
        let (s3, c) = adc(r4, c, 0);
        let s4 = c2 + c;

        t = [s0, s1, s2, s3, s4];
    }

    let (d0, borrow) = sbb(t[0], m[0], 0);
    let (d1, borrow) = sbb(t[1], m[1], borrow);
    let (d2, borrow) = sbb(t[2], m[2], borrow);
    let (d3, borrow) = sbb(t[3], m[3], borrow);
    let (_, borrow) = sbb(t[4], 0, borrow);
    if borrow == 0 {
        [d0, d1, d2, d3]
    } else {
        [t[0], t[1], t[2], t[3]]
    }
}

#[inline]
fn mont_r2(m: U256) -> [u64; 4] {
    let r = m.wrapping_neg() % m;
    let r2 = r.mul_mod(r, m);
    *r2.as_limbs()
}

fn mont_pow_u256(base: U256, exp: U256, m: U256) -> U256 {
    let m_limbs = *m.as_limbs();
    let m_inv = mont_inv64(m_limbs[0]);
    let r2 = mont_r2(m);
    let one_mont = mont_mul_cios([1, 0, 0, 0], r2, m_limbs, m_inv);
    let base_mont = mont_mul_cios(*base.as_limbs(), r2, m_limbs, m_inv);

    let mut table = [[0u64; 4]; 16];
    table[0] = one_mont;
    table[1] = base_mont;
    for i in 2..16 {
        table[i] = mont_mul_cios(table[i - 1], base_mont, m_limbs, m_inv);
    }

    let e_limbs = exp.as_limbs();
    let mut acc = one_mont;
    let mut started = false;
    for &limb in e_limbs.iter().rev() {
        for shift in (0..64).step_by(4).rev() {
            let nibble = ((limb >> shift) & 0xf) as usize;
            if started {
                acc = mont_mul_cios(acc, acc, m_limbs, m_inv);
                acc = mont_mul_cios(acc, acc, m_limbs, m_inv);
                acc = mont_mul_cios(acc, acc, m_limbs, m_inv);
                acc = mont_mul_cios(acc, acc, m_limbs, m_inv);
                if nibble != 0 {
                    acc = mont_mul_cios(acc, table[nibble], m_limbs, m_inv);
                }
            } else if nibble != 0 {
                acc = table[nibble];
                started = true;
            }
        }
    }

    let out = mont_mul_cios(acc, [1, 0, 0, 0], m_limbs, m_inv);
    U256::from_limbs(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_matches_default(base: &[u8], exp: &[u8], modulus: &[u8]) {
        let expected = DefaultCrypto::new().modexp(base, exp, modulus).unwrap();
        let actual = TempoCrypto.modexp(base, exp, modulus).unwrap();
        assert_eq!(
            strip_leading_zeros(&actual),
            strip_leading_zeros(&expected),
            "mismatch for base={base:x?} exp={exp:x?} mod={modulus:x?}"
        );
    }

    #[test]
    fn secp256k1_sqrt_matches_default() {
        let p_bytes = SECP256K1_P.to_be_bytes::<32>();
        let e_bytes = SECP256K1_SQRT_EXP.to_be_bytes::<32>();
        let gx = uint!(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798_U256);
        let rhs = gx
            .mul_mod(gx, SECP256K1_P)
            .mul_mod(gx, SECP256K1_P)
            .add_mod(U256::from(7u64), SECP256K1_P);
        assert_matches_default(&rhs.to_be_bytes::<32>(), &e_bytes, &p_bytes);

        for b in [
            U256::ZERO,
            U256::from(1u64),
            U256::from(2u64),
            U256::from(7u64),
            SECP256K1_P - U256::from(1u64),
            SECP256K1_P,
            SECP256K1_P + U256::from(1u64),
            U256::MAX,
        ] {
            assert_matches_default(&b.to_be_bytes::<32>(), &e_bytes, &p_bytes);
        }

        let mut s = 0x1234_5678_9abc_def0u64;
        let mut next_u64 = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for _ in 0..64 {
            let b = U256::from_limbs([next_u64(), next_u64(), next_u64(), next_u64()]);
            assert_matches_default(&b.to_be_bytes::<32>(), &e_bytes, &p_bytes);
        }
        let euler_bytes = SECP256K1_EULER_EXP.to_be_bytes::<32>();
        assert_matches_default(&rhs.to_be_bytes::<32>(), &euler_bytes, &p_bytes);
        for b in [
            U256::ZERO,
            U256::from(1u64),
            U256::from(2u64),
            U256::from(3u64),
            U256::from(7u64),
            SECP256K1_P - U256::from(1u64),
            SECP256K1_P,
            U256::MAX,
        ] {
            assert_matches_default(&b.to_be_bytes::<32>(), &euler_bytes, &p_bytes);
        }
        for _ in 0..64 {
            let b = U256::from_limbs([next_u64(), next_u64(), next_u64(), next_u64()]);
            assert_matches_default(&b.to_be_bytes::<32>(), &euler_bytes, &p_bytes);
        }
        for &prime in &FERMAT_PRIMES {
            let exp: U256 = (prime - U256::from(1u64)) >> 1usize;
            let b = U256::from_limbs([next_u64(), next_u64(), next_u64(), next_u64()]);
            assert_matches_default(
                &b.to_be_bytes::<32>(),
                &exp.to_be_bytes::<32>(),
                &prime.to_be_bytes::<32>(),
            );
        }
    }

    #[test]
    fn general_u256_and_edge_cases_match_default() {
        let mut s = 0xfedc_ba98_7654_3210u64;
        let mut next_u64 = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };

        assert_matches_default(&[5], &[3], &[]);
        assert_matches_default(&[5], &[3], &[0, 0, 0]);
        assert_matches_default(&[5], &[3], &[1]);
        assert_matches_default(&[0], &[0], &[7]);
        assert_matches_default(&[0], &[5], &[7]);
        assert_matches_default(&[5], &[0], &[1]);
        assert_matches_default(&[5], &[13], &[100]);
        assert_matches_default(&[0, 0, 0, 5], &[0, 0, 17], &[0, 0, 97]);

        let p_bytes = SECP256K1_P.to_be_bytes::<32>();
        assert_matches_default(
            &U256::from(42u64).to_be_bytes::<32>(),
            &SECP256K1_INV_EXP.to_be_bytes::<32>(),
            &p_bytes,
        );
        for _ in 0..16 {
            let b = U256::from_limbs([next_u64(), next_u64(), next_u64(), next_u64()]);
            let e = U256::from_limbs([next_u64(), next_u64(), next_u64(), next_u64()]);
            assert_matches_default(&b.to_be_bytes::<32>(), &e.to_be_bytes::<32>(), &p_bytes);
        }

        for &prime in &FERMAT_PRIMES {
            let b = U256::from_limbs([next_u64(), next_u64(), next_u64(), next_u64()]);
            let e = U256::from_limbs([next_u64(), next_u64(), next_u64(), next_u64()]);
            assert_matches_default(
                &b.to_be_bytes::<32>(),
                &e.to_be_bytes::<32>(),
                &prime.to_be_bytes::<32>(),
            );
            assert_matches_default(
                &b.to_be_bytes::<32>(),
                &(prime - U256::from(2u64)).to_be_bytes::<32>(),
                &prime.to_be_bytes::<32>(),
            );
        }

        for limbs in 1..=4 {
            for _ in 0..16 {
                let mut ml = [0u64; 4];
                for slot in ml.iter_mut().take(limbs) {
                    *slot = next_u64();
                }
                ml[0] |= 1;
                if ml == [1, 0, 0, 0] {
                    ml[0] = 3;
                }
                let m = U256::from_limbs(ml);
                let b = U256::from_limbs([next_u64(), next_u64(), next_u64(), next_u64()]);
                let e = U256::from_limbs([next_u64(), next_u64(), next_u64(), next_u64()]);
                assert_matches_default(
                    &b.to_be_bytes::<32>(),
                    &e.to_be_bytes::<32>(),
                    &m.to_be_bytes::<32>(),
                );
            }
        }
    }
}
