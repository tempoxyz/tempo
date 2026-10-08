//! Test proving with a known trapdoor.
//!
//! Whoever knows a verifying key's trapdoor can produce a valid proof for any public input,
//! without a circuit. Never enable this feature in a node build: an installed test key lets
//! anyone forge ZK signatures.

use crate::groth16::{PROOF_LENGTH, PreparedVerifyingKey, VerifyingKey, encode_proof};
use alloy_primitives::keccak256;
use ark_bn254::{Fr, G1Projective, G2Projective};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{AdditiveGroup, Field, PrimeField};
use std::sync::RwLock;

/// Seed of the trapdoor installed by [`install_test_verifying_key`].
pub const DEFAULT_TEST_SEED: u64 = 0x1131;

static OVERRIDES: RwLock<[Option<&'static PreparedVerifyingKey>; 256]> = RwLock::new([None; 256]);

/// Makes `scheme` accept proofs from `TestTrapdoor::new(DEFAULT_TEST_SEED)` in this process, and
/// returns that trapdoor.
pub fn install_test_verifying_key(scheme: u8) -> TestTrapdoor {
    let trapdoor = TestTrapdoor::new(DEFAULT_TEST_SEED);
    let mut overrides = OVERRIDES.write().expect("not poisoned");
    if overrides[scheme as usize].is_none() {
        overrides[scheme as usize] = Some(Box::leak(Box::new(trapdoor.verifying_key().prepare())));
    }
    trapdoor
}

pub(crate) fn verifying_key_override(scheme: u8) -> Option<&'static PreparedVerifyingKey> {
    OVERRIDES.read().expect("not poisoned")[scheme as usize]
}

/// The secret scalars of a test verifying key.
#[derive(Clone, Debug)]
pub struct TestTrapdoor {
    alpha: Fr,
    beta: Fr,
    gamma: Fr,
    delta: Fr,
    ic: [Fr; 2],
}

impl TestTrapdoor {
    /// Derives a trapdoor from `seed`.
    pub fn new(seed: u64) -> Self {
        let scalar = |label: u8| scalar(seed, label, 0);
        Self {
            alpha: scalar(1),
            beta: scalar(2),
            gamma: scalar(3),
            delta: scalar(4),
            ic: [scalar(5), scalar(6)],
        }
    }

    /// Returns the verifying key for this trapdoor.
    pub fn verifying_key(&self) -> VerifyingKey {
        let g1 = G1Projective::generator();
        let g2 = G2Projective::generator();
        VerifyingKey::from_parts(
            (g1 * self.alpha).into_affine(),
            (g2 * self.beta).into_affine(),
            (g2 * self.gamma).into_affine(),
            (g2 * self.delta).into_affine(),
            [
                (g1 * self.ic[0]).into_affine(),
                (g1 * self.ic[1]).into_affine(),
            ],
        )
    }

    /// Returns a valid proof for `public_input`. Different `nonce` values give different proofs.
    pub fn prove(&self, public_input: &Fr, nonce: u64) -> [u8; PROOF_LENGTH] {
        let a = scalar(nonce, 7, self.alpha.into_bigint().0[0]);
        let b = scalar(nonce, 8, self.beta.into_bigint().0[0]);
        let l = self.ic[0] + *public_input * self.ic[1];
        let c = (a * b - self.alpha * self.beta - l * self.gamma)
            * self.delta.inverse().expect("nonzero delta");
        let g1 = G1Projective::generator();
        let g2 = G2Projective::generator();
        encode_proof(
            &(g1 * a).into_affine(),
            &(g2 * b).into_affine(),
            &(g1 * c).into_affine(),
        )
    }
}

/// Derives a nonzero scalar from a seed, a label, and a domain value.
fn scalar(seed: u64, label: u8, domain: u64) -> Fr {
    let mut buf = [0u8; 17];
    buf[..8].copy_from_slice(&seed.to_be_bytes());
    buf[8] = label;
    buf[9..].copy_from_slice(&domain.to_be_bytes());
    let value = Fr::from_be_bytes_mod_order(keccak256(buf).as_slice());
    if value == Fr::ZERO { Fr::ONE } else { value }
}
