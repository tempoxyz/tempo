//! Proof verification for Tempo ZK signatures ([TIP-1131]).
//!
//! Provides the circomlib-compatible Poseidon hash used for public inputs ([TIP-1133]), Groth16
//! verification over BN254 (single and batched), and the registry of proof schemes.
//!
//! [TIP-1131]: https://docs.tempo.xyz/protocol/tips/tip-1131
//! [TIP-1133]: https://docs.tempo.xyz/protocol/tips/tip-1133

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg), allow(unexpected_cfgs))]

pub mod field;
pub mod groth16;
pub mod poseidon;

mod scheme;
pub use scheme::{NAMESPACE_OIDC, SCHEME_OIDC_RS256_V1, Scheme, scheme};

#[cfg(feature = "oidc-devnet")]
pub use scheme::install_devnet_key;

mod statement;
pub use statement::{MESSAGE_TAG, MessageStatement, SignatureStatement};

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

pub use ark_bn254::Fr;
pub use groth16::{PointError, PreparedVerifyingKey, Proof, VerifyingKey};

use rayon::prelude::*;

/// Proofs per batch when verifying many proofs in parallel.
const PARALLEL_BATCH: usize = 16;

/// Verifies proofs in parallel batches and returns one result per item, in order.
///
/// A batch that fails is checked proof by proof, so one invalid proof costs its batch a second
/// pass but never changes another proof's result.
pub fn verify_many(key: &PreparedVerifyingKey, items: &[(&Proof, Fr)]) -> Vec<bool> {
    items
        .par_chunks(PARALLEL_BATCH)
        .map(|chunk| {
            if key.verify_batch(chunk) {
                vec![true; chunk.len()]
            } else {
                chunk
                    .iter()
                    .map(|(proof, input)| key.verify(proof, input))
                    .collect()
            }
        })
        .collect::<Vec<_>>()
        .concat()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;

    #[test]
    fn verify_many_reports_each_result() {
        let trapdoor = test_utils::TestTrapdoor::new(9);
        let key = trapdoor.verifying_key().prepare();
        let proofs: Vec<(Proof, Fr)> = (0..40u64)
            .map(|i| {
                let input = Fr::from(i);
                (Proof::decode(&trapdoor.prove(&input, i)).unwrap(), input)
            })
            .collect();
        let mut items: Vec<(&Proof, Fr)> = proofs.iter().map(|(p, x)| (p, *x)).collect();
        assert!(verify_many(&key, &items).into_iter().all(|ok| ok));

        items[3].1 += Fr::ONE;
        items[37].1 += Fr::ONE;
        let results = verify_many(&key, &items);
        let invalid: Vec<usize> = (0..results.len()).filter(|i| !results[*i]).collect();
        assert_eq!(invalid, vec![3, 37]);
    }
}
