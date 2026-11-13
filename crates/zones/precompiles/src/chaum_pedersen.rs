//! Chaum-Pedersen DLOG equality proof verification for encrypted Zone deposits.
//!
//! Verifies the ECDH computation by proving knowledge of `privSeq` such that:
//! - `pubSeq = privSeq * G` (their public key)
//! - `sharedSecretPoint = privSeq * ephemeralPub`
//!
//! Verification equations:
//! - `R1 = s*G - c*pubSeq`
//! - `R2 = s*ephemeralPub - c*sharedSecretPoint`
//! - `c' = keccak256(G, ephemeralPub, pubSeq, sharedSecretPoint, R1, R2)`
//! - Check: `c == c'`
//!
//! Uses the NCC-audited [`k256`] crate (v0.13.4) for secp256k1 operations.

use alloy_primitives::Keccak256;
use k256::{
    AffinePoint, FieldBytes, ProjectivePoint, Scalar,
    elliptic_curve::{
        ops::Reduce,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
};
use tempo_contracts::zones::ChaumPedersenProof;
use tempo_precompiles::storage::StorageCtx;

/// Gas cost for Chaum-Pedersen proof verification (two EC muls + hashing).
const CP_VERIFY_GAS: u64 = 6_000;

/// Charge the gas cost for Chaum-Pedersen proof verification.
pub(crate) fn charge_gas() -> tempo_precompiles::Result<()> {
    StorageCtx::default().deduct_gas(CP_VERIFY_GAS)
}

/// Verify a Chaum-Pedersen DLOG equality proof on secp256k1.
///
/// Proves knowledge of scalar `x` such that `pubSeq = x*G` AND `sharedSecret = x*ephemeralPub`.
pub(crate) fn verify(
    ephemeral_pub_x: &[u8; 32],
    ephemeral_pub_y_parity: u8,
    shared_secret_x: &[u8; 32],
    shared_secret_y_parity: u8,
    sequencer_pub_x: &[u8; 32],
    sequencer_pub_y_parity: u8,
    proof: &ChaumPedersenProof,
) -> bool {
    // Recover points
    let Some(ephemeral_pub) = recover_point(ephemeral_pub_x, ephemeral_pub_y_parity) else {
        return false;
    };
    let Some(shared_secret_point) = recover_point(shared_secret_x, shared_secret_y_parity) else {
        return false;
    };
    let Some(sequencer_pub) = recover_point(sequencer_pub_x, sequencer_pub_y_parity) else {
        return false;
    };

    // Deserialize proof scalars by reducing modulo the group order.
    let s = <Scalar as Reduce<k256::U256>>::reduce_bytes(&proof.s.0.into());
    let c = <Scalar as Reduce<k256::U256>>::reduce_bytes(&proof.c.0.into());

    // R1 = s*G - c*pubSeq
    let r1 = ProjectivePoint::GENERATOR * s - ProjectivePoint::from(sequencer_pub) * c;

    // R2 = s*ephemeralPub - c*sharedSecretPoint
    let r2 =
        ProjectivePoint::from(ephemeral_pub) * s - ProjectivePoint::from(shared_secret_point) * c;

    let r1_affine = AffinePoint::from(r1);
    let r2_affine = AffinePoint::from(r2);

    // Recompute challenge and compare
    let c_prime = challenge_hash(
        &ephemeral_pub,
        &sequencer_pub,
        &shared_secret_point,
        &r1_affine,
        &r2_affine,
    );

    c == c_prime
}

/// Recover a secp256k1 affine point from compressed form (x coordinate + y parity).
///
/// `y_parity` follows SEC1: `0x02` for even y, `0x03` for odd y. `0x05` Compact encoding for even
/// points is also accepted.
pub(crate) fn recover_point(x_bytes: &[u8; 32], y_parity: u8) -> Option<AffinePoint> {
    let mut encoded = [0u8; 33];
    encoded[0] = y_parity;
    encoded[1..].copy_from_slice(x_bytes);

    let point = k256::EncodedPoint::from_bytes(encoded).ok()?;
    Option::from(AffinePoint::from_encoded_point(&point))
}

/// Compute the Chaum-Pedersen challenge hash.
///
/// `c = keccak256(G || ephemeralPub || pubSeq || sharedSecretPoint || R1 || R2)`
///
/// Shared between the verifier (precompile) and prover (ecies module).
pub(crate) fn challenge_hash(
    ephemeral_pub: &AffinePoint,
    sequencer_pub: &AffinePoint,
    shared_secret: &AffinePoint,
    r1: &AffinePoint,
    r2: &AffinePoint,
) -> Scalar {
    let g_affine = AffinePoint::from(ProjectivePoint::GENERATOR);

    let mut hasher = Keccak256::new();
    for point in [
        &g_affine,
        ephemeral_pub,
        sequencer_pub,
        shared_secret,
        r1,
        r2,
    ] {
        hasher.update(point.to_encoded_point(false).as_bytes());
    }

    let hash = hasher.finalize();
    <Scalar as Reduce<k256::U256>>::reduce_bytes(FieldBytes::from_slice(&hash.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use k256::elliptic_curve::{Field, PrimeField, rand_core::OsRng};

    fn proof(s: [u8; 32], c: [u8; 32]) -> ChaumPedersenProof {
        ChaumPedersenProof {
            s: B256::from(s),
            c: B256::from(c),
        }
    }

    #[test]
    fn test_recover_point_generator() {
        let g = AffinePoint::from(ProjectivePoint::GENERATOR);
        let encoded = g.to_encoded_point(true);
        let x: [u8; 32] = encoded.x().unwrap().as_slice().try_into().unwrap();
        let parity = encoded.as_bytes()[0];

        let recovered = recover_point(&x, parity).expect("should recover generator");
        assert_eq!(recovered, g);
    }

    #[test]
    fn test_chaum_pedersen_verify() {
        let mut rng = OsRng;
        let priv_seq = Scalar::random(&mut rng);
        let pub_seq = (ProjectivePoint::GENERATOR * priv_seq).to_affine();
        let eph_priv = Scalar::random(&mut rng);
        let eph_pub = (ProjectivePoint::GENERATOR * eph_priv).to_affine();
        let shared_secret = (ProjectivePoint::from(eph_pub) * priv_seq).to_affine();

        let k = Scalar::random(&mut rng);
        let r1 = (ProjectivePoint::GENERATOR * k).to_affine();
        let r2 = (ProjectivePoint::from(eph_pub) * k).to_affine();
        let c = challenge_hash(&eph_pub, &pub_seq, &shared_secret, &r1, &r2);
        let s = k + c * priv_seq;
        // A proof whose R1/R2 recompute to the identity.
        let degenerate_c = Scalar::random(&mut rng);

        // (x, parity) of the ephemeral pubkey, shared secret and sequencer pubkey.
        let points = [eph_pub, shared_secret, pub_seq].map(|point| {
            let encoded = point.to_encoded_point(true);
            let x: [u8; 32] = encoded.x().unwrap().as_slice().try_into().unwrap();
            (x, encoded.as_bytes()[0])
        });
        let flip_parity = |index: usize| {
            let mut flipped = points;
            flipped[index].1 = if points[index].1 == 0x02 { 0x03 } else { 0x02 };
            flipped
        };
        let valid_proof = proof(s.to_repr().into(), c.to_repr().into());

        for (case, [(eph_x, eph_parity), (ss_x, ss_parity), (ps_x, ps_parity)], proof, expected) in [
            ("valid proof", points, valid_proof.clone(), true),
            (
                "invalid proof",
                points,
                proof([0xAAu8; 32], [0xBBu8; 32]),
                false,
            ),
            (
                "tampered s",
                points,
                proof((s + Scalar::ONE).to_repr().into(), c.to_repr().into()),
                false,
            ),
            (
                "tampered c",
                points,
                proof(s.to_repr().into(), (c + Scalar::ONE).to_repr().into()),
                false,
            ),
            (
                "wrong ephemeral pubkey parity",
                flip_parity(0),
                valid_proof.clone(),
                false,
            ),
            (
                "wrong shared secret parity",
                flip_parity(1),
                valid_proof,
                false,
            ),
            (
                "degenerate proof with identity R1/R2",
                points,
                proof(
                    (degenerate_c * priv_seq).to_repr().into(),
                    degenerate_c.to_repr().into(),
                ),
                false,
            ),
        ] {
            assert_eq!(
                verify(
                    &eph_x, eph_parity, &ss_x, ss_parity, &ps_x, ps_parity, &proof
                ),
                expected,
                "{case}"
            );
        }
    }

    #[test]
    fn test_recover_point_invalid_parity() {
        let g = AffinePoint::from(ProjectivePoint::GENERATOR);
        let encoded = g.to_encoded_point(true);
        let x: [u8; 32] = encoded.x().unwrap().as_slice().try_into().unwrap();

        assert!(recover_point(&x, 0x00).is_none());
        assert!(recover_point(&x, 0x04).is_none());
        assert!(recover_point(&x, 0xFF).is_none());
    }
}
