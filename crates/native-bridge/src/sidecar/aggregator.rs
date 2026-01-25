//! Signature aggregator - collects partials and recovers threshold signatures.
//!
//! Uses the MinSig variant (G2 public keys, G1 signatures) to match consensus,
//! allowing reuse of the same DKG shares for both consensus and bridge signing.

use std::collections::HashMap;

use alloy_primitives::B256;
use commonware_codec::Encode;
use commonware_cryptography::bls12381::primitives::{
    group::G1,
    ops::threshold,
    sharing::Sharing,
    variant::{MinSig, PartialSignature as CwPartialSignature},
};
use commonware_parallel::Sequential;
use commonware_utils::{Faults, N3f1, Participant};

use crate::{
    attestation::{AggregatedSignature, PartialSignature, PendingAttestation},
    error::{BridgeError, Result},
    message::{G1_COMPRESSED_LEN, Message},
    signer::deserialize_g1,
};

/// Aggregates partial signatures into threshold signatures.
///
/// Uses MinSig variant (same as consensus): G1 signatures, G2 public keys.
pub struct Aggregator {
    /// The sharing information from DKG (contains polynomial and interpolation info).
    /// This is the same sharing from consensus DKG.
    sharing: Sharing<MinSig>,
    /// Current epoch for the aggregated signatures.
    epoch: u64,
    /// Pending attestations awaiting enough partial signatures.
    pending: HashMap<B256, (PendingAttestation, Message)>,
}

impl Aggregator {
    /// Create a new aggregator with the given sharing and epoch.
    ///
    /// The sharing comes from the consensus DKG ceremony and contains the public polynomial
    /// needed for threshold signature recovery. The same sharing is used for both
    /// consensus and bridge signing.
    pub fn new(sharing: Sharing<MinSig>, epoch: u64) -> Self {
        Self {
            sharing,
            epoch,
            pending: HashMap::new(),
        }
    }

    /// Get the threshold (minimum signatures needed for recovery).
    pub fn threshold<M: Faults>(&self) -> u32 {
        self.sharing.required::<M>()
    }

    /// Update the epoch (e.g., after a key rotation).
    pub fn set_epoch(&mut self, epoch: u64) {
        self.epoch = epoch;
    }

    /// Update the sharing (e.g., after a key rotation).
    pub fn set_sharing(&mut self, sharing: Sharing<MinSig>) {
        self.sharing = sharing;
    }

    /// Add a partial signature. Returns aggregated signature if threshold reached.
    pub fn add_partial(
        &mut self,
        attestation_hash: B256,
        partial: PartialSignature,
        message: &Message,
    ) -> Option<(AggregatedSignature, Message)> {
        let threshold = self.sharing.required::<N3f1>() as usize;

        let (pending, msg) = self.pending.entry(attestation_hash).or_insert_with(|| {
            (
                PendingAttestation::new(attestation_hash, threshold),
                message.clone(),
            )
        });

        if !pending.add_partial(partial) {
            tracing::debug!(
                hash = %attestation_hash,
                "duplicate partial signature rejected"
            );
            return None;
        }

        if pending.has_threshold() {
            let partials = pending.partials.clone();
            let msg_clone = msg.clone();

            match self.aggregate_partials(&partials) {
                Ok(sig) => {
                    self.pending.remove(&attestation_hash);
                    tracing::info!(
                        hash = %attestation_hash,
                        partial_count = partials.len(),
                        "threshold signature recovered"
                    );
                    return Some((sig, msg_clone));
                }
                Err(e) => {
                    tracing::error!(
                        hash = %attestation_hash,
                        error = %e,
                        "threshold signature recovery failed"
                    );
                }
            }
        }

        None
    }

    /// Aggregate partial signatures into a threshold signature using Lagrange interpolation.
    fn aggregate_partials(&self, partials: &[PartialSignature]) -> Result<AggregatedSignature> {
        // Convert our wire-format partial signatures to commonware format
        let cw_partials: Vec<CwPartialSignature<MinSig>> = partials
            .iter()
            .map(|p| {
                let g1_sig = deserialize_g1(&p.signature)?;
                Ok(CwPartialSignature {
                    index: Participant::new(p.index),
                    value: g1_sig,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        // Recover the threshold signature using the sharing's interpolation
        let threshold_sig: G1 =
            threshold::recover::<MinSig, _, N3f1>(&self.sharing, &cw_partials, &Sequential)
                .map_err(|e| {
                    BridgeError::Aggregation(format!("threshold recovery failed: {e:?}"))
                })?;

        // Serialize the recovered signature (G1, 48 bytes)
        let sig_bytes = serialize_g1(&threshold_sig)?;

        Ok(AggregatedSignature::new(sig_bytes, self.epoch))
    }

    /// Get the number of pending attestations.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Get the number of partial signatures collected for a given attestation.
    pub fn partial_count(&self, attestation_hash: &B256) -> usize {
        self.pending
            .get(attestation_hash)
            .map(|(p, _)| p.partials.len())
            .unwrap_or(0)
    }

    /// Remove stale pending attestations (e.g., for garbage collection).
    pub fn remove_pending(&mut self, attestation_hash: &B256) -> bool {
        self.pending.remove(attestation_hash).is_some()
    }
}

/// Serialize a G1 point to compressed bytes (48 bytes).
fn serialize_g1(point: &G1) -> Result<[u8; G1_COMPRESSED_LEN]> {
    let bytes = point.encode();
    if bytes.len() != G1_COMPRESSED_LEN {
        return Err(BridgeError::InvalidSignatureLength {
            expected: G1_COMPRESSED_LEN,
            actual: bytes.len(),
        });
    }

    let mut result = [0u8; G1_COMPRESSED_LEN];
    result.copy_from_slice(&bytes);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{message::BLS_DST, signer::BLSSigner};
    use commonware_cryptography::bls12381::{
        dkg,
        primitives::{ops::verify, sharing::Mode},
    };
    use commonware_utils::NZU32;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn test_aggregate_partials_threshold_3_of_5() {
        let mut rng = StdRng::seed_from_u64(42);
        let n = NZU32!(5);

        // Generate shares using commonware DKG (MinSig variant, same as consensus)
        let (sharing, shares) = dkg::deal_anonymous::<MinSig, N3f1>(&mut rng, Mode::default(), n);
        let threshold = sharing.required::<N3f1>();
        let threshold_public = sharing.public();

        let mut aggregator = Aggregator::new(sharing.clone(), 1);

        let message = Message::new(
            alloy_primitives::Address::repeat_byte(0xAA),
            B256::repeat_byte(0x11),
            1,
            12345,
        );
        let attestation_hash = message.attestation_hash();

        // Create signers and sign with threshold number of shares
        let mut result = None;
        for share in shares.iter().take(threshold as usize) {
            let signer = BLSSigner::new(share.clone());
            let partial = signer.sign_partial(attestation_hash).unwrap();

            if let Some(r) = aggregator.add_partial(attestation_hash, partial, &message) {
                result = Some(r);
            }
        }

        // Should have recovered the threshold signature
        assert!(result.is_some(), "threshold signature should be recovered");

        let (agg_sig, _msg) = result.unwrap();
        assert_eq!(agg_sig.signature.len(), 48); // G1 compressed
        assert_eq!(agg_sig.epoch, 1);

        // Verify the aggregated signature against the threshold public key (G2)
        let threshold_sig = deserialize_g1(&agg_sig.signature).unwrap();
        let result = verify::<MinSig>(
            threshold_public,
            BLS_DST,
            attestation_hash.as_slice(),
            &threshold_sig,
        );
        assert!(
            result.is_ok(),
            "threshold signature should verify: {result:?}"
        );
    }

    #[test]
    fn test_aggregate_insufficient_partials() {
        let mut rng = StdRng::seed_from_u64(43);
        let n = NZU32!(5);

        let (sharing, shares) = dkg::deal_anonymous::<MinSig, N3f1>(&mut rng, Mode::default(), n);
        let threshold = sharing.required::<N3f1>();

        let mut aggregator = Aggregator::new(sharing, 1);

        let message = Message::new(
            alloy_primitives::Address::repeat_byte(0xBB),
            B256::repeat_byte(0x22),
            1,
            12345,
        );
        let attestation_hash = message.attestation_hash();

        // Only add threshold-1 partials
        let insufficient = (threshold as usize).saturating_sub(1);
        for share in shares.iter().take(insufficient) {
            let signer = BLSSigner::new(share.clone());
            let partial = signer.sign_partial(attestation_hash).unwrap();

            let result = aggregator.add_partial(attestation_hash, partial, &message);
            assert!(
                result.is_none(),
                "should not recover with insufficient partials"
            );
        }

        assert_eq!(aggregator.partial_count(&attestation_hash), insufficient);
    }

    #[test]
    fn test_duplicate_partial_rejected() {
        let mut rng = StdRng::seed_from_u64(44);
        let n = NZU32!(5);

        let (sharing, shares) = dkg::deal_anonymous::<MinSig, N3f1>(&mut rng, Mode::default(), n);

        let mut aggregator = Aggregator::new(sharing, 1);

        let message = Message::new(
            alloy_primitives::Address::repeat_byte(0xCC),
            B256::repeat_byte(0x33),
            1,
            12345,
        );
        let attestation_hash = message.attestation_hash();

        let signer = BLSSigner::new(shares[0].clone());
        let partial = signer.sign_partial(attestation_hash).unwrap();

        // First add should succeed
        let result = aggregator.add_partial(attestation_hash, partial.clone(), &message);
        assert!(result.is_none());
        assert_eq!(aggregator.partial_count(&attestation_hash), 1);

        // Duplicate should be rejected
        let result = aggregator.add_partial(attestation_hash, partial, &message);
        assert!(result.is_none());
        assert_eq!(aggregator.partial_count(&attestation_hash), 1);
    }
}
