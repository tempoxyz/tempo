//! Shared state for the feed module.

use crate::{alias::marshal, consensus::Digest};
use alloy_consensus::BlockHeader as _;
use alloy_primitives::hex;
use commonware_codec::{Encode, ReadExt as _};
use commonware_consensus::{
    Heightable as _,
    marshal::ingress::mailbox::Identifier,
    types::{Epoch, Epocher as _, FixedEpocher, Height},
};
use parking_lot::RwLock;
use reth_rpc_convert::transaction::FromConsensusHeader;
use std::sync::{Arc, OnceLock};
use tempo_alloy::rpc::TempoHeaderResponse;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_node::rpc::consensus::{
    CertifiedBlock, ConsensusFeed, ConsensusState, Event, IdentityProofError, IdentityTransition,
    IdentityTransitionResponse, Query, TransitionProofData,
};
use tokio::sync::broadcast;

const BROADCAST_CHANNEL_SIZE: usize = 1024;

/// Internal shared state for the feed.
pub(super) struct FeedState {
    /// Latest notarized block.
    pub(super) latest_notarized: Option<CertifiedBlock>,
    /// Latest finalized block.
    pub(super) latest_finalized: Option<CertifiedBlock>,
}

/// Handle to shared feed state.
///
/// This handle can be cloned and used by both:
/// - The feed actor (to update state when processing Activity)
/// - RPC handlers (implements `ConsensusFeed`)
#[derive(Clone)]
pub struct FeedStateHandle {
    state: Arc<RwLock<FeedState>>,
    marshal: Arc<OnceLock<marshal::Mailbox>>,
    epocher: Arc<OnceLock<FixedEpocher>>,
    events_tx: broadcast::Sender<Event>,
}

impl FeedStateHandle {
    /// Create a new feed state handle.
    ///
    /// The marshal mailbox can be set later using `set_marshal`.
    /// Until set, historical finalization lookups will return `None`.
    pub fn new() -> Self {
        let (events_tx, _) = broadcast::channel(BROADCAST_CHANNEL_SIZE);
        Self {
            state: Arc::new(RwLock::new(FeedState {
                latest_notarized: None,
                latest_finalized: None,
            })),
            marshal: Arc::new(OnceLock::new()),
            epocher: Arc::new(OnceLock::new()),
            events_tx,
        }
    }

    /// Set the marshal mailbox for historical finalization lookups. Should only be called once.
    pub(crate) fn set_marshal(&self, marshal: marshal::Mailbox) {
        let _ = self.marshal.set(marshal);
    }

    /// Set the epocher for epoch boundary calculations. Should only be called once.
    pub(crate) fn set_epocher(&self, epocher: FixedEpocher) {
        let _ = self.epocher.set(epocher);
    }

    /// Get the broadcast sender for events.
    pub(super) fn events_tx(&self) -> &broadcast::Sender<Event> {
        &self.events_tx
    }

    /// Get write access to the internal state.
    pub(super) fn write(&self) -> parking_lot::RwLockWriteGuard<'_, FeedState> {
        self.state.write()
    }

    /// Get the marshal mailbox, logging if not yet set.
    fn marshal(&self) -> Option<marshal::Mailbox> {
        let marshal = self.marshal.get().cloned();
        if marshal.is_none() {
            tracing::debug!("marshal not yet set");
        }
        marshal
    }

    /// Get the epocher, logging if not yet set.
    fn epocher(&self) -> Option<FixedEpocher> {
        let epocher = self.epocher.get().cloned();
        if epocher.is_none() {
            tracing::debug!("epocher not yet set");
        }
        epocher
    }

    /// Fill in the height for a block if it's missing by querying the marshal.
    async fn maybe_fill_height(&self, block: &mut CertifiedBlock) {
        if block.height.is_none()
            && let Some(mut marshal) = self.marshal()
        {
            block.height = marshal
                .get_block(&Digest(block.digest))
                .await
                .map(|b| b.height().get());
        }
    }
}

impl Default for FeedStateHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for FeedStateHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state.read();
        f.debug_struct("FeedStateHandle")
            .field("latest_notarized", &state.latest_notarized)
            .field("latest_finalized", &state.latest_finalized)
            .field("marshal_set", &self.marshal.get().is_some())
            .field("subscriber_count", &self.events_tx.receiver_count())
            .finish()
    }
}

impl ConsensusFeed for FeedStateHandle {
    async fn get_finalization(&self, query: Query) -> Option<CertifiedBlock> {
        match query {
            Query::Latest => {
                let mut block = self.state.read().latest_finalized.clone()?;
                self.maybe_fill_height(&mut block).await;
                Some(block)
            }
            Query::Height(height) => {
                let mut marshal = self.marshal()?;
                let finalization = marshal.get_finalization(Height::new(height)).await?;

                Some(CertifiedBlock {
                    epoch: finalization.proposal.round.epoch().get(),
                    view: finalization.proposal.round.view().get(),
                    height: Some(height),
                    digest: finalization.proposal.payload.0,
                    certificate: hex::encode(finalization.certificate.encode()),
                })
            }
        }
    }

    async fn get_latest(&self) -> ConsensusState {
        let (mut finalized, notarized) = {
            let state = self.state.read();
            (
                state.latest_finalized.clone(),
                state.latest_notarized.clone(),
            )
        };

        if let Some(ref mut block) = finalized {
            self.maybe_fill_height(block).await;
        }

        ConsensusState {
            finalized,
            notarized,
        }
    }

    async fn subscribe(&self) -> Option<broadcast::Receiver<Event>> {
        Some(self.events_tx.subscribe())
    }

    async fn get_identity_transition_proof(
        &self,
        from_epoch: Option<u64>,
        full: bool,
    ) -> Result<IdentityTransitionResponse, IdentityProofError> {
        let Some((mut marshal, epocher)) = self.marshal().zip(self.epocher()) else {
            return Err(IdentityProofError::NotReady);
        };

        // Determine starting epoch (from param, or latest finalized)
        let start_epoch = if let Some(epoch) = from_epoch {
            epoch
        } else {
            marshal
                .get_info(Identifier::Latest)
                .await
                .and_then(|(h, _)| epocher.containing(h))
                .ok_or(IdentityProofError::NotReady)?
                .epoch()
                .get()
        };

        // Identity active at epoch N is set by the last block of epoch N-1
        // (epoch 0 uses its own last block - genesis identity)
        let identity_outcome =
            get_outcome(&mut marshal, &epocher, start_epoch.saturating_sub(1)).await?;
        let mut curr_pubkey = *identity_outcome.sharing().public();
        let identity = hex::encode(curr_pubkey.encode());

        let mut transitions = Vec::new();

        // Walk backwards comparing public keys to detect full DKG transitions.
        let mut search_epoch = start_epoch.saturating_sub(1);
        while search_epoch > 0 {
            let prev_outcome = get_outcome(&mut marshal, &epocher, search_epoch - 1).await?;
            let prev_pubkey = *prev_outcome.sharing().public();

            // If keys differ, there was a full DKG at search_epoch
            if curr_pubkey != prev_pubkey {
                // Fetch the block and certificate that committed the new identity
                let proof_height = epocher
                    .last(Epoch::new(search_epoch))
                    .expect("fixed epocher is valid for all epochs");
                let proof_block = marshal
                    .get_block(proof_height)
                    .await
                    .ok_or(IdentityProofError::PrunedData(proof_height.get()))?;
                let finalization = marshal
                    .get_finalization(proof_height)
                    .await
                    .ok_or(IdentityProofError::PrunedData(proof_height.get()))?;

                transitions.push(IdentityTransition {
                    transition_epoch: search_epoch,
                    old_public_key: hex::encode(prev_pubkey.encode()),
                    new_public_key: hex::encode(curr_pubkey.encode()),
                    proof: TransitionProofData {
                        header: TempoHeaderResponse::from_consensus_header(
                            proof_block.clone_sealed_header(),
                            0,
                        ),
                        finalization: hex::encode(finalization.encode()),
                    },
                });

                if !full {
                    break;
                }
            }

            curr_pubkey = prev_pubkey;
            search_epoch -= 1;
        }

        Ok(IdentityTransitionResponse {
            identity,
            transitions,
        })
    }
}

/// Fetch last block of epoch and decode DKG outcome.
async fn get_outcome(
    marshal: &mut marshal::Mailbox,
    epocher: &FixedEpocher,
    epoch: u64,
) -> Result<OnchainDkgOutcome, IdentityProofError> {
    let height = epocher
        .last(Epoch::new(epoch))
        .expect("fixed epocher is valid for all epochs");
    let block = marshal
        .get_block(height)
        .await
        .ok_or(IdentityProofError::PrunedData(height.get()))?;
    OnchainDkgOutcome::read(&mut block.header().extra_data().as_ref())
        .map_err(|_| IdentityProofError::MalformedData(height.get()))
}
