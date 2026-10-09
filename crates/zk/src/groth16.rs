//! Groth16 verification over BN254 with a single public input.
//!
//! Points use the [EIP-197](https://eips.ethereum.org/EIPS/eip-197) uncompressed encoding:
//! 32-byte big-endian coordinates, with `F_p^2` elements written as `(c1, c0)`.

use crate::field::bigint_from_be;
use alloy_primitives::keccak256;
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{
    AffineRepr, CurveGroup, VariableBaseMSM,
    pairing::{Pairing, PairingOutput},
};
use ark_ff::{AdditiveGroup, BigInteger, PrimeField, Zero};

/// Length of an encoded proof: `A` (G1) `|| B` (G2) `|| C` (G1).
pub const PROOF_LENGTH: usize = 256;

/// Length of an encoded verifying key: `alpha` (G1), `beta`, `gamma`, `delta` (G2), `IC[0]`,
/// `IC[1]` (G1).
pub const VERIFYING_KEY_LENGTH: usize = 576;

const G1_LENGTH: usize = 64;
const G2_LENGTH: usize = 128;

type G2Prepared = <Bn254 as Pairing>::G2Prepared;

/// Why an encoded point was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PointError {
    /// A coordinate is not less than the base field modulus.
    #[error("coordinate is not a canonical base field element")]
    NonCanonicalCoordinate,
    /// The encoding is the point at infinity.
    #[error("point at infinity")]
    PointAtInfinity,
    /// The point does not satisfy the curve equation.
    #[error("point is not on the curve")]
    NotOnCurve,
    /// The G2 point is outside the prime-order subgroup.
    #[error("point is not in the prime-order subgroup")]
    NotInSubgroup,
}

/// A Groth16 proof whose points passed every encoding, curve, and subgroup check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    a: G1Affine,
    b: G2Affine,
    c: G1Affine,
    bytes: [u8; PROOF_LENGTH],
}

impl Proof {
    /// Decodes and validates a proof.
    pub fn decode(bytes: &[u8; PROOF_LENGTH]) -> Result<Self, PointError> {
        Ok(Self {
            a: decode_g1(&bytes[..G1_LENGTH])?,
            b: decode_g2(&bytes[G1_LENGTH..G1_LENGTH + G2_LENGTH])?,
            c: decode_g1(&bytes[G1_LENGTH + G2_LENGTH..])?,
            bytes: *bytes,
        })
    }

    /// Returns the encoded proof.
    pub const fn as_bytes(&self) -> &[u8; PROOF_LENGTH] {
        &self.bytes
    }
}

/// A Groth16 verifying key for a circuit with one public input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey {
    alpha: G1Affine,
    beta: G2Affine,
    gamma: G2Affine,
    delta: G2Affine,
    ic: [G1Affine; 2],
}

impl VerifyingKey {
    /// Decodes and validates a verifying key.
    pub fn decode(bytes: &[u8; VERIFYING_KEY_LENGTH]) -> Result<Self, PointError> {
        let (alpha, rest) = bytes.split_at(G1_LENGTH);
        let (beta, rest) = rest.split_at(G2_LENGTH);
        let (gamma, rest) = rest.split_at(G2_LENGTH);
        let (delta, rest) = rest.split_at(G2_LENGTH);
        let (ic0, ic1) = rest.split_at(G1_LENGTH);
        Ok(Self {
            alpha: decode_g1(alpha)?,
            beta: decode_g2(beta)?,
            gamma: decode_g2(gamma)?,
            delta: decode_g2(delta)?,
            ic: [decode_g1(ic0)?, decode_g1(ic1)?],
        })
    }

    /// Encodes the verifying key.
    pub fn encode(&self) -> [u8; VERIFYING_KEY_LENGTH] {
        let mut out = [0u8; VERIFYING_KEY_LENGTH];
        let mut offset = 0;
        for chunk in [
            &encode_g1(&self.alpha)[..],
            &encode_g2(&self.beta),
            &encode_g2(&self.gamma),
            &encode_g2(&self.delta),
            &encode_g1(&self.ic[0]),
            &encode_g1(&self.ic[1]),
        ] {
            out[offset..offset + chunk.len()].copy_from_slice(chunk);
            offset += chunk.len();
        }
        out
    }

    /// Precomputes the pairing `e(alpha, beta)` and the line coefficients of the fixed G2 points.
    pub fn prepare(&self) -> PreparedVerifyingKey {
        PreparedVerifyingKey {
            alpha_beta: Bn254::pairing(self.alpha, self.beta),
            neg_alpha: (-self.alpha.into_group()).into_affine(),
            beta: self.beta.into(),
            neg_gamma: (-self.gamma.into_group()).into_affine().into(),
            neg_delta: (-self.delta.into_group()).into_affine().into(),
            ic: self.ic,
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) const fn from_parts(
        alpha: G1Affine,
        beta: G2Affine,
        gamma: G2Affine,
        delta: G2Affine,
        ic: [G1Affine; 2],
    ) -> Self {
        Self {
            alpha,
            beta,
            gamma,
            delta,
            ic,
        }
    }
}

/// A verifying key with its fixed pairing inputs precomputed.
#[derive(Clone, Debug)]
pub struct PreparedVerifyingKey {
    alpha_beta: PairingOutput<Bn254>,
    neg_alpha: G1Affine,
    beta: G2Prepared,
    neg_gamma: G2Prepared,
    neg_delta: G2Prepared,
    ic: [G1Affine; 2],
}

impl PreparedVerifyingKey {
    /// Verifies one proof: `e(A, B) = e(alpha, beta) * e(L, gamma) * e(C, delta)`, where
    /// `L = IC[0] + public_input * IC[1]`.
    pub fn verify(&self, proof: &Proof, public_input: &Fr) -> bool {
        let l = (self.ic[0].into_group() + self.ic[1] * public_input).into_affine();
        let ml = Bn254::multi_miller_loop(
            [proof.a, l, proof.c],
            [
                G2Prepared::from(proof.b),
                self.neg_gamma.clone(),
                self.neg_delta.clone(),
            ],
        );
        Bn254::final_exponentiation(ml).is_some_and(|result| result == self.alpha_beta)
    }

    /// Verifies several proofs with one final exponentiation.
    ///
    /// Each equation is weighted by a 128-bit value from a Fiat-Shamir transcript of every proof
    /// and public input, so an invalid proof makes the batch fail except with probability about
    /// `2^-128`. A failed batch does not say which proof is invalid; see [`Self::find_invalid`].
    pub fn verify_batch(&self, items: &[(&Proof, Fr)]) -> bool {
        match items {
            [] => return true,
            [(proof, input)] => return self.verify(proof, input),
            _ => {}
        }

        let weights = batch_weights(items);
        let mut weight_sum = Fr::ZERO;
        let mut input_sum = Fr::ZERO;
        let mut g1 = Vec::with_capacity(items.len() + 3);
        let mut g2 = Vec::with_capacity(items.len() + 3);
        let mut cs = Vec::with_capacity(items.len());
        for ((proof, input), weight) in items.iter().zip(&weights) {
            weight_sum += weight;
            input_sum += *input * weight;
            g1.push((proof.a * weight).into_affine());
            g2.push(G2Prepared::from(proof.b));
            cs.push(proof.c);
        }

        let l = (self.ic[0] * weight_sum + self.ic[1] * input_sum).into_affine();
        let c = G1Projective::msm(&cs, &weights)
            .expect("one weight per proof")
            .into_affine();
        let alpha = (self.neg_alpha * weight_sum).into_affine();
        g1.extend([l, c, alpha]);
        g2.extend([
            self.neg_gamma.clone(),
            self.neg_delta.clone(),
            self.beta.clone(),
        ]);

        Bn254::final_exponentiation(Bn254::multi_miller_loop(g1, g2))
            .is_some_and(|result| result.is_zero())
    }

    /// Returns the indexes of proofs that fail individual verification.
    pub fn find_invalid(&self, items: &[(&Proof, Fr)]) -> Vec<usize> {
        items
            .iter()
            .enumerate()
            .filter(|(_, (proof, input))| !self.verify(proof, input))
            .map(|(index, _)| index)
            .collect()
    }
}

/// Derives one nonzero 128-bit weight per item from a transcript of every proof and input.
fn batch_weights(items: &[(&Proof, Fr)]) -> Vec<Fr> {
    let mut transcript = Vec::with_capacity(16 + items.len() * (PROOF_LENGTH + 32));
    transcript.extend_from_slice(b"tempo:zk-batch:v1");
    for (proof, input) in items {
        transcript.extend_from_slice(proof.as_bytes());
        transcript.extend_from_slice(&input.into_bigint().to_bytes_be());
    }
    let seed = keccak256(&transcript);

    (0..items.len() as u64)
        .map(|index| {
            let mut buf = [0u8; 40];
            buf[..32].copy_from_slice(seed.as_slice());
            buf[32..].copy_from_slice(&index.to_be_bytes());
            let digest = keccak256(buf);
            let weight = u128::from_be_bytes(digest[..16].try_into().expect("16 bytes"));
            Fr::from(weight.max(1))
        })
        .collect()
}

fn decode_fq(bytes: &[u8]) -> Result<Fq, PointError> {
    let bytes: &[u8; 32] = bytes.try_into().expect("32-byte coordinate");
    Fq::from_bigint(bigint_from_be(bytes)).ok_or(PointError::NonCanonicalCoordinate)
}

fn decode_g1(bytes: &[u8]) -> Result<G1Affine, PointError> {
    let x = decode_fq(&bytes[..32])?;
    let y = decode_fq(&bytes[32..])?;
    if x.is_zero() && y.is_zero() {
        return Err(PointError::PointAtInfinity);
    }
    let point = G1Affine::new_unchecked(x, y);
    // G1 has cofactor one, so every point on the curve is in the subgroup.
    if !point.is_on_curve() {
        return Err(PointError::NotOnCurve);
    }
    Ok(point)
}

fn decode_g2(bytes: &[u8]) -> Result<G2Affine, PointError> {
    let x = Fq2::new(decode_fq(&bytes[32..64])?, decode_fq(&bytes[..32])?);
    let y = Fq2::new(decode_fq(&bytes[96..])?, decode_fq(&bytes[64..96])?);
    if x.is_zero() && y.is_zero() {
        return Err(PointError::PointAtInfinity);
    }
    let point = G2Affine::new_unchecked(x, y);
    if !point.is_on_curve() {
        return Err(PointError::NotOnCurve);
    }
    if !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(PointError::NotInSubgroup);
    }
    Ok(point)
}

fn encode_fq(value: &Fq, out: &mut [u8]) {
    out.copy_from_slice(&value.into_bigint().to_bytes_be());
}

pub(crate) fn encode_g1(point: &G1Affine) -> [u8; G1_LENGTH] {
    let mut out = [0u8; G1_LENGTH];
    let (x, y) = point.xy().expect("encoded points are finite");
    encode_fq(&x, &mut out[..32]);
    encode_fq(&y, &mut out[32..]);
    out
}

pub(crate) fn encode_g2(point: &G2Affine) -> [u8; G2_LENGTH] {
    let mut out = [0u8; G2_LENGTH];
    let (x, y) = point.xy().expect("encoded points are finite");
    encode_fq(&x.c1, &mut out[..32]);
    encode_fq(&x.c0, &mut out[32..64]);
    encode_fq(&y.c1, &mut out[64..96]);
    encode_fq(&y.c0, &mut out[96..]);
    out
}

#[cfg(any(test, feature = "test-utils"))]
pub(crate) fn encode_proof(a: &G1Affine, b: &G2Affine, c: &G1Affine) -> [u8; PROOF_LENGTH] {
    let mut out = [0u8; PROOF_LENGTH];
    out[..G1_LENGTH].copy_from_slice(&encode_g1(a));
    out[G1_LENGTH..G1_LENGTH + G2_LENGTH].copy_from_slice(&encode_g2(b));
    out[G1_LENGTH + G2_LENGTH..].copy_from_slice(&encode_g1(c));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{field::BN254_BASE_FIELD, test_utils::TestTrapdoor};
    use ark_ec::PrimeGroup;
    use ark_ff::Field;

    fn setup() -> (TestTrapdoor, PreparedVerifyingKey) {
        let trapdoor = TestTrapdoor::new(7);
        let pvk = trapdoor.verifying_key().prepare();
        (trapdoor, pvk)
    }

    #[test]
    fn verifies_valid_and_rejects_wrong_input() {
        let (trapdoor, pvk) = setup();
        let input = Fr::from(42u64);
        let proof = Proof::decode(&trapdoor.prove(&input, 1)).unwrap();
        assert!(pvk.verify(&proof, &input));
        assert!(!pvk.verify(&proof, &Fr::from(43u64)));
    }

    #[test]
    fn verifying_key_roundtrip() {
        let (trapdoor, _) = setup();
        let vk = trapdoor.verifying_key();
        assert_eq!(VerifyingKey::decode(&vk.encode()).unwrap(), vk);
    }

    #[test]
    fn rerandomized_proof_still_verifies() {
        // Groth16 proofs are malleable: (A / s, B * s, C) verifies for the same input. ZK
        // signatures stop this by signing the proof bytes with the access key.
        let (trapdoor, pvk) = setup();
        let input = Fr::from(5u64);
        let proof = Proof::decode(&trapdoor.prove(&input, 2)).unwrap();
        let s = Fr::from(3u64);
        let a = (proof.a * s.inverse().unwrap()).into_affine();
        let b = (proof.b * s).into_affine();
        let mauled = Proof::decode(&encode_proof(&a, &b, &proof.c)).unwrap();
        assert_ne!(mauled.as_bytes(), proof.as_bytes());
        assert!(pvk.verify(&mauled, &input));
    }

    #[test]
    fn batch_rejects_an_invalid_proof_at_each_position() {
        let (trapdoor, pvk) = setup();
        let proofs: Vec<(Proof, Fr)> = (0..6u64)
            .map(|i| {
                let input = Fr::from(100 + i);
                (Proof::decode(&trapdoor.prove(&input, i)).unwrap(), input)
            })
            .collect();
        let items: Vec<(&Proof, Fr)> = proofs.iter().map(|(p, x)| (p, *x)).collect();
        assert!(pvk.verify_batch(&items));
        assert!(pvk.find_invalid(&items).is_empty());

        for bad in 0..items.len() {
            let mut items = items.clone();
            items[bad].1 += Fr::ONE;
            assert!(
                !pvk.verify_batch(&items),
                "batch accepted a bad proof at {bad}"
            );
            assert_eq!(pvk.find_invalid(&items), vec![bad]);
        }
        assert!(pvk.verify_batch(&[]));
    }

    #[test]
    fn rejects_bad_points() {
        let (trapdoor, _) = setup();
        let valid = trapdoor.prove(&Fr::from(1u64), 3);

        // Coordinate equal to the base field modulus.
        let mut bytes = valid;
        bytes[..32].copy_from_slice(&BN254_BASE_FIELD.to_be_bytes::<32>());
        assert_eq!(
            Proof::decode(&bytes),
            Err(PointError::NonCanonicalCoordinate)
        );

        // Infinity encodings for A, B, and C.
        for range in [0..64, 64..192, 192..256] {
            let mut bytes = valid;
            bytes[range].fill(0);
            assert_eq!(Proof::decode(&bytes), Err(PointError::PointAtInfinity));
        }

        // A point off the curve.
        let mut bytes = valid;
        bytes[63] ^= 1;
        assert_eq!(Proof::decode(&bytes), Err(PointError::NotOnCurve));
        let mut bytes = valid;
        bytes[191] ^= 1;
        assert_eq!(Proof::decode(&bytes), Err(PointError::NotOnCurve));

        // A point on the twist curve but outside the prime-order subgroup.
        let mut bytes = valid;
        bytes[64..192].copy_from_slice(&encode_g2(&non_subgroup_g2()));
        assert_eq!(Proof::decode(&bytes), Err(PointError::NotInSubgroup));

        // Swapping the two halves of an F_p^2 coordinate changes the point.
        let mut bytes = valid;
        let (x1, x0) = (bytes[64..96].to_vec(), bytes[96..128].to_vec());
        bytes[64..96].copy_from_slice(&x0);
        bytes[96..128].copy_from_slice(&x1);
        assert!(Proof::decode(&bytes).is_err());
    }

    #[test]
    fn generator_encoding_matches_eip197() {
        // EIP-197 G2 generator, written as (x.c1, x.c0, y.c1, y.c0).
        let expected = [
            "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2",
            "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed",
            "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b",
            "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
        ]
        .concat();
        let encoded = encode_g2(&G2Affine::generator());
        assert_eq!(alloy_primitives::hex::encode(encoded), expected);
        assert_eq!(
            decode_g2(&encoded).unwrap(),
            ark_bn254::G2Projective::generator().into_affine()
        );
    }

    /// Finds a point on the G2 curve outside the prime-order subgroup.
    fn non_subgroup_g2() -> G2Affine {
        let mut x = Fq2::new(Fq::from(1u64), Fq::from(1u64));
        loop {
            if let Some(point) = G2Affine::get_point_from_x_unchecked(x, false)
                && !point.is_in_correct_subgroup_assuming_on_curve()
            {
                return point;
            }
            x += Fq2::ONE;
        }
    }
}
