//! Provider-independent, head-only authenticated progress and immutable read snapshots.

use std::{num::NonZeroU64, sync::Arc};

use alloy_consensus::{BlockHeader as _, Sealable as _};
use commonware_codec::DecodeExt as _;
use commonware_consensus::types::{Epocher as _, FixedEpocher, Height};
use rand_core::CryptoRng;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_finality::{CertifiedHeader, FinalizationVerifier, NetworkIdentity};
use tempo_primitives::TempoHeader;

use tempo_state_proof::{ProofError, ProofLimits, ProofTargets, VerifiedBatch, verify_multi_proof};

/// Immutable authenticated snapshot. Holding this value keeps an in-flight read tied to its
/// actual block even when public progress advances. It does not promise global freshness.
#[derive(Clone)]
pub struct Snapshot(Arc<CertifiedHeader>);

impl Snapshot {
    pub fn header(&self) -> &TempoHeader {
        &self.0.header
    }

    pub fn evidence(&self) -> &CertifiedHeader {
        &self.0
    }

    /// Verify directly fetched proofs against this snapshot, never an RPC `latest` root.
    pub fn verify(
        &self,
        targets: &ProofTargets,
        responses: &[alloy_rpc_types_eth::EIP1186AccountProofResponse],
        limits: ProofLimits,
    ) -> Result<VerifiedBatch, ProofError> {
        verify_multi_proof(self.header().state_root(), targets, responses, limits)
    }
}

/// A single authoritative verification state shared across all upstreams.
///
/// No networking or filesystem trust is implicit. This tracker does not claim durable progress.
/// Same-key sparse jumps rely on consensus safety, not a contiguous skipped-header history proof.
/// After a signature failure, fetch authenticated boundary certificates and explicitly call
/// [`Self::authenticate_transition`]; never replace the identity using discovery metadata.
pub struct HeadTracker {
    verifier: FinalizationVerifier,
    head: Option<Snapshot>,
}

// Staging must not share mutable scheme caches with publicly accepted progress.
impl Clone for HeadTracker {
    fn clone(&self) -> Self {
        Self {
            verifier: FinalizationVerifier::new(
                self.identity().clone(),
                self.verifier.epoch_strategy().clone(),
            ),
            head: self.head.clone(),
        }
    }
}

impl HeadTracker {
    /// `identity` and `epoch_length` must come from explicitly configured trusted chain data.
    pub fn new(identity: NetworkIdentity, epoch_length: NonZeroU64) -> Self {
        Self {
            verifier: FinalizationVerifier::new(identity, FixedEpocher::new(epoch_length)),
            head: None,
        }
    }

    pub fn snapshot(&self) -> Option<Snapshot> {
        self.head.clone()
    }

    pub fn identity(&self) -> &NetworkIdentity {
        self.verifier.network_identity()
    }

    /// Verify a selected candidate and advance public in-memory progress without regression.
    /// Returns the existing snapshot for an identical already verified head.
    pub fn accept(
        &mut self,
        rng: &mut impl CryptoRng,
        evidence: CertifiedHeader,
    ) -> Result<Snapshot, Error> {
        check_size(&evidence)?;
        if let Some(head) = &self.head {
            if evidence.header.number() < head.header().number() {
                return Err(Error::Regression);
            }
            if evidence == *head.0 {
                return Ok(head.clone());
            }
        }
        self.verify_evidence(rng, &evidence)?;
        if let Some(head) = &self.head
            && evidence.header.number() == head.header().number()
        {
            if evidence.header.hash_slow() != head.header().hash_slow() {
                return Err(Error::ConflictingHead);
            }
            return Ok(head.clone());
        }
        let snapshot = Snapshot(Arc::new(evidence));
        self.head = Some(snapshot.clone());
        Ok(snapshot)
    }

    /// Authenticate a signing-key transition with a *finalized* boundary under the current key.
    ///
    /// This is separate from head advancement: a needed boundary can be older than the selected
    /// head. All checks happen before the identity changes. Only the current key is retained, so
    /// skipped heads/epochs cannot create an unbounded scheme map in the light client.
    pub fn authenticate_transition(
        &mut self,
        rng: &mut impl CryptoRng,
        boundary: &CertifiedHeader,
    ) -> Result<(), Error> {
        check_size(boundary)?;
        let info = self
            .verifier
            .epoch_strategy()
            .containing(Height::new(boundary.header.number()))
            .expect("fixed epocher supports every height");
        if info.last().get() != boundary.header.number() {
            return Err(Error::NotBoundary);
        }
        self.verify_evidence(rng, boundary)?;
        let outcome = OnchainDkgOutcome::decode(boundary.header.extra_data().as_ref())
            .map_err(Error::MalformedBoundary)?;
        let next_epoch = boundary
            .epoch
            .checked_add(1)
            .ok_or(Error::TransitionEpoch)?;
        if outcome.epoch != next_epoch || next_epoch <= self.identity().from_epoch {
            return Err(Error::TransitionEpoch);
        }
        if let Some(head) = &self.head {
            if head.0.epoch >= next_epoch && outcome.network_identity() != &self.identity().identity
            {
                return Err(Error::ConflictingIdentity);
            }
            if head.header().number() == boundary.header.number()
                && head.header().hash_slow() != boundary.header.hash_slow()
            {
                return Err(Error::ConflictingHead);
            }
        }
        self.verifier = FinalizationVerifier::new(
            NetworkIdentity {
                from_epoch: next_epoch,
                identity: *outcome.network_identity(),
            },
            self.verifier.epoch_strategy().clone(),
        );
        Ok(())
    }

    /// Light tracking needs only the current configured key, unlike full-node marshal consumers.
    /// Discard per-epoch retention even if a subsequently checked transition outcome fails, so
    /// replaying old authenticated boundaries cannot accumulate an unbounded scheme cache.
    fn verify_evidence(
        &self,
        rng: &mut impl CryptoRng,
        evidence: &CertifiedHeader,
    ) -> Result<(), Error> {
        let result = self.verifier.decode_and_verify_header(rng, evidence);
        self.verifier.clear_cached_schemes();
        result.map(|_| ()).map_err(Into::into)
    }
}

// Limits are provisional safety ceilings, not claims about measured performance. Certificates are
// constant-size; DKG outcomes grow with the validator set. The transport must cap JSON bytes too.
fn check_size(evidence: &CertifiedHeader) -> Result<(), Error> {
    if evidence.certificate.len() > 16 * 1024 || evidence.header.extra_data().len() > 1024 * 1024 {
        return Err(Error::EvidenceSize);
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Verification(#[from] tempo_finality::Error),
    #[error("finalized candidate would regress verified progress")]
    Regression,
    #[error("conflicting authenticated finalized headers at the same height")]
    ConflictingHead,
    #[error("transition evidence is not an epoch-boundary header")]
    NotBoundary,
    #[error("invalid DKG outcome in authenticated boundary: {0}")]
    MalformedBoundary(#[source] commonware_codec::Error),
    #[error("DKG outcome does not activate in the boundary's next epoch")]
    TransitionEpoch,
    #[error("authenticated key transition conflicts with an already accepted head")]
    ConflictingIdentity,
    #[error("finalization evidence exceeds resource limits")]
    EvidenceSize,
}
