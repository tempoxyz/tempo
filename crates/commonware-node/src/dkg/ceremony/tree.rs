//! A tree of dealings.

use std::collections::{BTreeMap, HashMap, HashSet};

use alloy_consensus::BlockHeader;
use commonware_consensus::{Block as _, types::Epoch};
use commonware_cryptography::{
    bls12381::{
        dkg,
        dkg::{Arbiter, arbiter},
        primitives::{poly::Public, variant::MinSig},
    },
    ed25519::PublicKey,
};
use commonware_utils::{set::Ordered, union};
use eyre::Report;
use tempo_dkg_onchain_artifacts::IntermediateOutcome;
use tracing::{info, instrument, warn};

use crate::{
    consensus::Digest,
    dkg::{
        HardforkRegime,
        ceremony::{ACK_NAMESPACE, OUTCOME_NAMESPACE, WEIGHT_RECOVERY_CONCURRENCY},
    },
    epoch::{self, first_block_in_epoch},
};

#[derive(Debug)]
pub(in crate::dkg) struct HasHoles {
    pub(in crate::dkg) notarized_hole: Digest,
}

pub(in crate::dkg) struct TreeOfDealings {
    /// A chain of finalized blocks.
    finalized_by_height: BTreeMap<u64, ReducedBlock>,

    /// An index of digest -> height.
    finalized_by_digest: HashMap<Digest, u64>,

    notarized_by_digest: HashMap<Digest, ReducedBlock>,

    /// The epoch for which this tree is collecting blocks.
    epoch: Epoch,
    epoch_length: u64,

    input_polynomial: Public<MinSig>,
    dealers: Ordered<PublicKey>,
    players: Ordered<PublicKey>,

    hardfork_regime: HardforkRegime,
    namespace: Vec<u8>,
}

impl TreeOfDealings {
    pub(super) fn new(
        epoch: Epoch,
        epoch_length: u64,
        input_polynomial: Public<MinSig>,
        dealers: Ordered<PublicKey>,
        players: Ordered<PublicKey>,
        hardfork_regime: HardforkRegime,
        namespace: Vec<u8>,
    ) -> Self {
        Self {
            finalized_by_height: BTreeMap::new(),
            finalized_by_digest: HashMap::new(),

            notarized_by_digest: HashMap::new(),

            epoch,
            epoch_length,
            input_polynomial,
            dealers,
            players,
            hardfork_regime,
            namespace,
        }
    }

    /// Adds a finalized block to the tree.
    ///
    /// Returns the dealer of the dealing, if the block contained one.
    #[instrument(
        skip_all,
        fields(block.height = block.height(), block.digest = %block.digest()),
    )]
    pub(super) fn add_finalized(
        &mut self,
        block: crate::consensus::block::Block,
    ) -> Option<PublicKey> {
        let block_digest = block.digest();
        let block_height = block.height();
        let block_epoch = commonware_consensus::utils::epoch(self.epoch_length, block_height);

        let reduced_block = ReducedBlock::from_block(block);
        let dealing = reduced_block
            .dealing
            .clone()
            .map(|dealing| dealing.dealer().clone());

        // Ensure the outcome is for the current round.
        if block_epoch != self.epoch {
            info!(
                "block at height `{block_height}` is for epoch `{block_epoch}`, \
                but tree is tracking dealings in epoch `{}`; ignoring",
                self.epoch,
            );
            return dealing;
        }

        if self.finalized_by_height.contains_key(&block_height) {
            info!("tree already contains block at its height; ignoring");
            return dealing;
        }

        self.finalized_by_height.insert(block_height, reduced_block);
        self.finalized_by_digest.insert(block_digest, block_height);

        self.notarized_by_digest
            .retain(|_, block| block.height > block_height);

        dealing
    }

    #[instrument(
        skip_all,
        fields(block.height = block.height(), block.digest = %block.digest()),
    )]
    pub(super) fn add_notarized(&mut self, block: crate::consensus::block::Block) {
        let block_digest = block.digest();
        let block_height = block.height();
        let block_epoch = commonware_consensus::utils::epoch(self.epoch_length, block_height);

        // Ensure the outcome is for the current round.
        if block_epoch != self.epoch {
            info!(
                "block at height `{block_height}` is for epoch `{block_epoch}`, \
                but tree is tracking dealings in epoch `{}`; ignoring",
                self.epoch,
            );
            return;
        }

        if self.finalized_by_height.contains_key(&block.height()) {
            info!("a finalized block at that height is already known; ignoring");
            return;
        }

        let reduced_block = ReducedBlock::from_block(block);

        self.notarized_by_digest.insert(block_digest, reduced_block);
    }

    /// Finalizes the ceremony up to `digest`.
    ///
    /// If the ceremony can be finalized, then the finalization result is
    /// available in Ok-position.
    ///
    /// If the ceremony could not be finalized, the digest of the block for
    /// which there is a gap (as well )
    /// highest finalized block will be returned in Error-position.
    #[expect(
        clippy::type_complexity,
        reason = "closely tracks the result of arbiter; should rework this when updating to commonware's dkg2"
    )]
    pub(super) fn finalize_up_to_digest(
        &self,
        digest: Digest,
    ) -> Result<
        (
            Result<arbiter::Output<MinSig>, dkg::Error>,
            HashSet<PublicKey>,
        ),
        HasHoles,
    > {
        // The finalized block up to which the ceremony will be finalized.
        let finalized_height = self.finalized_by_digest.get(&digest).copied();

        // If `digest` is not finalized, see if it exists among the notarized
        // blocks. If it is and if a path can be constructed from it to the
        // finalized blocks, put the path of digests into `notarized_digests`.
        //
        // If no path exists (if there is a hole), return that.
        let mut path_of_notarized_digests = Vec::new();
        if finalized_height.is_none() {
            let height_to_reach = self.finalized_by_height.last_key_value().map_or_else(
                || first_block_in_epoch(self.epoch_length, self.epoch),
                |(height, _)| *height + 1,
            );

            let notarized_hole = if let Some(mut block) = self.notarized_by_digest.get(&digest) {
                loop {
                    path_of_notarized_digests.push(block.digest);
                    if block.height <= height_to_reach {
                        if height_to_reach != first_block_in_epoch(self.epoch_length, self.epoch) {
                            assert_eq!(
                                self.finalized_by_height[&(height_to_reach - 1)].digest,
                                block.parent,
                                "height_to_reach is latest_finalized.height + 1; \
                                this means that block.parent == latest_finalized.digest;
                                if that is not the case something is terribly wrong"
                            );
                        }

                        break None;
                    }
                    match self.notarized_by_digest.get(&block.parent) {
                        Some(b) => block = b,
                        None => {
                            break Some(block.parent);
                        }
                    }
                }
            } else {
                Some(digest)
            };

            if let Some(notarized_hole) = notarized_hole {
                // TODO: Return the hole and which height needs to be reached.
                return Err(HasHoles { notarized_hole });
            }

            assert!(
                !path_of_notarized_digests.is_empty(),
                "if the digest is not among finalized, and if there are no holes, \
                then the list of notarized digests to talk cannot be empty"
            );
        }

        let mut arbiter = Arbiter::<PublicKey, MinSig>::new(
            Some(self.input_polynomial.clone()),
            self.dealers.clone(),
            self.players.clone(),
            WEIGHT_RECOVERY_CONCURRENCY,
        );

        let range = 0..=finalized_height.unwrap_or(u64::MAX);
        for dealing in self
            .finalized_by_height
            .range(range)
            .map(|(_, block)| block)
            .chain(
                path_of_notarized_digests
                    .into_iter()
                    .rev()
                    // NOTE: Infallible; notarized_digests was populated from
                    // self.notarized_by_digest.
                    .map(|d| &self.notarized_by_digest[&d]),
            )
            .filter_map(|block| block.dealing.as_ref())
        {
            match self.verify_dealing(dealing).map_err(|err| *err.0) {
                // Don't disqualify unknown dealers - if unknown dealers are
                // added to the arbiter it will panic on finalize.
                Err(VerificationErrorKind::UnknownDealer { dealer }) => {
                    warn!(%dealer, "dealer in dealing was not known");
                }
                Err(reason) => {
                    warn!(reason = %Report::new(reason), "disqualifiying dealer");
                    arbiter.disqualify(dealing.dealer().clone());
                }
                Ok(ack_indices) => {
                    if let Err(reason) = arbiter.commitment(
                        dealing.dealer().clone(),
                        dealing.commitment().clone(),
                        ack_indices,
                        dealing.reveals().to_vec(),
                    ) {
                        tracing::warn!(
                            reason = %Report::new(reason),
                            "failed tracking dealing in arbiter",
                        );
                    }
                }
            }
        }
        Ok(arbiter.finalize())
    }

    fn verify_dealing(&self, dealing: &IntermediateOutcome) -> Result<Vec<u32>, VerificationError> {
        if self.dealers.position(dealing.dealer()).is_none() {
            Err(VerificationErrorKind::UnknownDealer {
                dealer: dealing.dealer().clone(),
            })?;
        }

        // Verify the dealer's signature before considering processing the outcome.
        if !match self.hardfork_regime {
            HardforkRegime::PostAllegretto => {
                dealing.verify(&union(&self.namespace, OUTCOME_NAMESPACE))
            }
            HardforkRegime::PreAllegretto => {
                dealing.verify_pre_allegretto(&union(&self.namespace, OUTCOME_NAMESPACE))
            }
        } {
            Err(VerificationErrorKind::BadDealingSignature)?;
        }

        // Verify all ack signatures
        let mut ack_indices = vec![];
        for ack in dealing.acks() {
            let idx = self.players.position(ack.player()).ok_or_else(|| {
                VerificationErrorKind::UnknownPlayer {
                    player: ack.player().clone(),
                }
            })?;
            if !ack.verify(
                &union(&self.namespace, ACK_NAMESPACE),
                ack.player(),
                self.epoch,
                dealing.dealer(),
                dealing.commitment(),
            ) {
                Err(VerificationErrorKind::BadAckSignature {
                    player: ack.player().clone(),
                })?;
            }

            ack_indices.push(idx as u32);
        }

        Ok(ack_indices)
    }

    pub(super) fn find_gaps_up_to_height(&self, height: u64) -> Vec<u64> {
        let mut holes = vec![];

        // Special case genesis - there is no genesis block.
        let first_height_in_epoch = std::cmp::max(
            1,
            epoch::first_block_in_epoch(self.epoch_length, self.epoch),
        );

        for h in first_height_in_epoch..height {
            if !self.finalized_by_height.contains_key(&h) {
                holes.push(h);
            }
        }
        holes
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
struct VerificationError(Box<VerificationErrorKind>);

impl From<VerificationErrorKind> for VerificationError {
    fn from(kind: VerificationErrorKind) -> Self {
        Self(Box::new(kind))
    }
}

#[derive(Debug, thiserror::Error)]
enum VerificationErrorKind {
    #[error(
        "the dealer `{dealer}` recorded in the dealing outcome was not among the dealers of the ceremony"
    )]
    UnknownDealer { dealer: PublicKey },
    #[error("could not verify the dealing signature")]
    BadDealingSignature,
    #[error("could not verify the ack signature for player `{player}`")]
    BadAckSignature { player: PublicKey },
    #[error("player `{player}` of ack recorded in dealing is unknown")]
    UnknownPlayer { player: PublicKey },
}

/// A block reduced to only its minimally required information for a DKG ceremony.
#[derive(Debug)]
struct ReducedBlock {
    digest: Digest,
    parent: Digest,
    height: u64,
    dealing: Option<IntermediateOutcome>,
}

impl ReducedBlock {
    fn from_block(block: crate::consensus::block::Block) -> Self {
        let digest = block.digest();
        let parent = block.parent_digest();
        let height = block.height();
        let mut dealing = None;

        if !block.header().extra_data().is_empty() {
            match block.try_read_ceremony_deal_outcome() {
                Err(error) => warn!(
                    %error,
                    "failed reading ceremony deal outcome; treating it as absent",
                ),
                Ok(d) => {
                    dealing.replace(d);
                }
            }
        }

        Self {
            digest,
            parent,
            height,
            dealing,
        }
    }
}
