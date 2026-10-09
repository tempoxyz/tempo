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
use tempo_precompiles::storage::StorageCtx;
use tempo_zone_contracts::ChaumPedersenProof;

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
    use k256::elliptic_curve::{Field, PrimeField};

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
    fn test_chaum_pedersen_valid_proof() {
        let mut rng = rand::thread_rng();
        let priv_seq = Scalar::random(&mut rng);
        let pub_seq = (ProjectivePoint::GENERATOR * priv_seq).to_affine();

        let eph_priv = Scalar::random(&mut rng);
        let eph_pub = (ProjectivePoint::GENERATOR * eph_priv).to_affine();

        let shared_secret = (ProjectivePoint::from(eph_pub) * priv_seq).to_affine();

        // Generate proof
        let k = Scalar::random(&mut rng);
        let r1 = (ProjectivePoint::GENERATOR * k).to_affine();
        let r2 = (ProjectivePoint::from(eph_pub) * k).to_affine();

        let c = challenge_hash(&eph_pub, &pub_seq, &shared_secret, &r1, &r2);
        let s = k + c * priv_seq;

        let eph_enc = eph_pub.to_encoded_point(true);
        let ss_enc = shared_secret.to_encoded_point(true);
        let ps_enc = pub_seq.to_encoded_point(true);

        let valid = verify(
            eph_enc.x().unwrap().as_slice().try_into().unwrap(),
            eph_enc.as_bytes()[0],
            ss_enc.x().unwrap().as_slice().try_into().unwrap(),
            ss_enc.as_bytes()[0],
            ps_enc.x().unwrap().as_slice().try_into().unwrap(),
            ps_enc.as_bytes()[0],
            &proof(s.to_repr().into(), c.to_repr().into()),
        );

        assert!(valid, "valid Chaum-Pedersen proof should verify");
    }

    #[test]
    fn test_chaum_pedersen_invalid_proof() {
        let mut rng = rand::thread_rng();
        let priv_seq = Scalar::random(&mut rng);
        let pub_seq = (ProjectivePoint::GENERATOR * priv_seq).to_affine();

        let eph_priv = Scalar::random(&mut rng);
        let eph_pub = (ProjectivePoint::GENERATOR * eph_priv).to_affine();
        let shared_secret = (ProjectivePoint::from(eph_pub) * priv_seq).to_affine();

        let eph_enc = eph_pub.to_encoded_point(true);
        let ss_enc = shared_secret.to_encoded_point(true);
        let ps_enc = pub_seq.to_encoded_point(true);

        let valid = verify(
            eph_enc.x().unwrap().as_slice().try_into().unwrap(),
            eph_enc.as_bytes()[0],
            ss_enc.x().unwrap().as_slice().try_into().unwrap(),
            ss_enc.as_bytes()[0],
            ps_enc.x().unwrap().as_slice().try_into().unwrap(),
            ps_enc.as_bytes()[0],
            &proof([0xAAu8; 32], [0xBBu8; 32]),
        );

        assert!(!valid, "invalid proof should not verify");
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

    #[test]
    fn test_chaum_pedersen_tampered_s() {
        let mut rng = rand::thread_rng();
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

        let s_tampered = s + Scalar::ONE;

        let eph_enc = eph_pub.to_encoded_point(true);
        let ss_enc = shared_secret.to_encoded_point(true);
        let ps_enc = pub_seq.to_encoded_point(true);

        let valid = verify(
            eph_enc.x().unwrap().as_slice().try_into().unwrap(),
            eph_enc.as_bytes()[0],
            ss_enc.x().unwrap().as_slice().try_into().unwrap(),
            ss_enc.as_bytes()[0],
            ps_enc.x().unwrap().as_slice().try_into().unwrap(),
            ps_enc.as_bytes()[0],
            &proof(s_tampered.to_repr().into(), c.to_repr().into()),
        );

        assert!(!valid, "tampered s should not verify");
    }

    #[test]
    fn test_chaum_pedersen_tampered_c() {
        let mut rng = rand::thread_rng();
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

        let c_tampered = c + Scalar::ONE;

        let eph_enc = eph_pub.to_encoded_point(true);
        let ss_enc = shared_secret.to_encoded_point(true);
        let ps_enc = pub_seq.to_encoded_point(true);

        let valid = verify(
            eph_enc.x().unwrap().as_slice().try_into().unwrap(),
            eph_enc.as_bytes()[0],
            ss_enc.x().unwrap().as_slice().try_into().unwrap(),
            ss_enc.as_bytes()[0],
            ps_enc.x().unwrap().as_slice().try_into().unwrap(),
            ps_enc.as_bytes()[0],
            &proof(s.to_repr().into(), c_tampered.to_repr().into()),
        );

        assert!(!valid, "tampered c should not verify");
    }

    #[test]
    fn test_chaum_pedersen_wrong_shared_secret_parity() {
        let mut rng = rand::thread_rng();
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

        let eph_enc = eph_pub.to_encoded_point(true);
        let ss_enc = shared_secret.to_encoded_point(true);
        let ps_enc = pub_seq.to_encoded_point(true);

        let ss_parity = ss_enc.as_bytes()[0];
        let flipped_ss_parity = if ss_parity == 0x02 { 0x03 } else { 0x02 };

        let valid = verify(
            eph_enc.x().unwrap().as_slice().try_into().unwrap(),
            eph_enc.as_bytes()[0],
            ss_enc.x().unwrap().as_slice().try_into().unwrap(),
            flipped_ss_parity,
            ps_enc.x().unwrap().as_slice().try_into().unwrap(),
            ps_enc.as_bytes()[0],
            &proof(s.to_repr().into(), c.to_repr().into()),
        );

        assert!(!valid, "wrong shared secret parity should not verify");
    }

    #[test]
    fn test_chaum_pedersen_wrong_ephemeral_parity() {
        let mut rng = rand::thread_rng();
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

        let eph_enc = eph_pub.to_encoded_point(true);
        let ss_enc = shared_secret.to_encoded_point(true);
        let ps_enc = pub_seq.to_encoded_point(true);

        let eph_parity = eph_enc.as_bytes()[0];
        let flipped_eph_parity = if eph_parity == 0x02 { 0x03 } else { 0x02 };

        let valid = verify(
            eph_enc.x().unwrap().as_slice().try_into().unwrap(),
            flipped_eph_parity,
            ss_enc.x().unwrap().as_slice().try_into().unwrap(),
            ss_enc.as_bytes()[0],
            ps_enc.x().unwrap().as_slice().try_into().unwrap(),
            ps_enc.as_bytes()[0],
            &proof(s.to_repr().into(), c.to_repr().into()),
        );

        assert!(!valid, "wrong ephemeral pubkey parity should not verify");
    }

    #[test]
    fn test_chaum_pedersen_identity_r1_r2() {
        let mut rng = rand::thread_rng();
        let priv_seq = Scalar::random(&mut rng);
        let pub_seq = (ProjectivePoint::GENERATOR * priv_seq).to_affine();
        let eph_priv = Scalar::random(&mut rng);
        let eph_pub = (ProjectivePoint::GENERATOR * eph_priv).to_affine();
        let shared_secret = (ProjectivePoint::from(eph_pub) * priv_seq).to_affine();

        let c = Scalar::random(&mut rng);
        let s = c * priv_seq;

        let eph_enc = eph_pub.to_encoded_point(true);
        let ss_enc = shared_secret.to_encoded_point(true);
        let ps_enc = pub_seq.to_encoded_point(true);

        let valid = verify(
            eph_enc.x().unwrap().as_slice().try_into().unwrap(),
            eph_enc.as_bytes()[0],
            ss_enc.x().unwrap().as_slice().try_into().unwrap(),
            ss_enc.as_bytes()[0],
            ps_enc.x().unwrap().as_slice().try_into().unwrap(),
            ps_enc.as_bytes()[0],
            &proof(s.to_repr().into(), c.to_repr().into()),
        );

        assert!(
            !valid,
            "degenerate proof with identity R1/R2 should not verify"
        );
    }
}
