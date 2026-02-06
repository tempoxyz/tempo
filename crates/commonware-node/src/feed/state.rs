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

/// Cached identity transition chain.
///
/// Stores transitions from a starting epoch back towards genesis.
/// Can be extended for newer epochs or subsectioned for older queries.
#[derive(Clone, Default)]
struct IdentityTransitionCache {
    /// The epoch from which the chain was built (inclusive).
    from_epoch: u64,
    /// The earliest epoch we walked to (0 if we reached genesis).
    to_epoch: u64,
    /// Identity at `from_epoch`.
    identity: String,
    /// Cached transitions, ordered newest to oldest.
    transitions: Arc<Vec<IdentityTransition>>,
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
    /// Cache for identity transition proofs to avoid re-walking the chain.
    identity_cache: Arc<RwLock<Option<IdentityTransitionCache>>>,
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
            identity_cache: Arc::new(RwLock::new(None)),
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

    /// Serve identity transition proof from cache, returning a subsection if needed.
    fn serve_from_cache(
        &self,
        cache: &IdentityTransitionCache,
        start_epoch: u64,
        full: bool,
    ) -> IdentityTransitionResponse {
        // Filter transitions to only include those at or before start_epoch
        let transitions: Vec<_> = cache
            .transitions
            .iter()
            .filter(|t| t.transition_epoch <= start_epoch)
            .cloned()
            .collect();

        // Determine identity at start_epoch:
        // - If start_epoch == from_epoch, use cached identity
        // - Otherwise, find the first transition AFTER start_epoch and use its old_identity
        //   (that was the identity at start_epoch before that transition happened)
        // - If no transition after start_epoch, identity hasn't changed since from_epoch
        let identity = if start_epoch == cache.from_epoch {
            cache.identity.clone()
        } else {
            // Find first transition that happened AFTER start_epoch
            cache
                .transitions
                .iter()
                .find(|t| t.transition_epoch > start_epoch)
                .map(|t| t.old_identity.clone())
                .unwrap_or_else(|| cache.identity.clone())
        };

        // If not full, only return the most recent transition
        let transitions = if full {
            transitions
        } else {
            transitions.into_iter().take(1).collect()
        };

        IdentityTransitionResponse {
            identity,
            transitions,
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
                    certificate: hex::encode(finalization.encode()),
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

        // Check if we can serve from cache
        let cached = self.identity_cache.read().clone();
        if let Some(ref cache) = cached {
            // Requested epoch is within cached range - return subsection
            if start_epoch <= cache.from_epoch && start_epoch >= cache.to_epoch {
                return Ok(self.serve_from_cache(cache, start_epoch, full));
            }
        }

        // Identity active at epoch N is set by the last block of epoch N-1
        // (epoch 0 uses its own last block - genesis identity)
        let identity_outcome =
            get_outcome(&mut marshal, &epocher, start_epoch.saturating_sub(1)).await?;
        let mut curr_pubkey = *identity_outcome.sharing().public();
        let identity = hex::encode(curr_pubkey.encode());

        let mut transitions = Vec::new();

        // Walk backwards comparing public keys to detect full DKG transitions.
        // On errors, we return what we've collected so far rather than failing entirely.
        let mut search_epoch = start_epoch.saturating_sub(1);
        let mut reached_genesis = start_epoch == 0;

        // If we have a cache, try to connect to it instead of walking all the way
        let cache_connect_epoch = cached.as_ref().map(|c| c.from_epoch);

        while search_epoch > 0 {
            // Check if we can connect to cached data
            if let Some(connect_epoch) = cache_connect_epoch
                && search_epoch <= connect_epoch
                && let Some(ref cache) = cached
            {
                // Append cached transitions and stop walking
                transitions.extend(cache.transitions.iter().cloned());
                search_epoch = cache.to_epoch;
                reached_genesis = cache.to_epoch == 0;
                break;
            }

            let prev_outcome = match get_outcome(&mut marshal, &epocher, search_epoch - 1).await {
                Ok(o) => o,
                Err(err) => {
                    tracing::info!(
                        ?err,
                        start_epoch,
                        search_epoch,
                        "stopping identity transition walk early (failed to fetch previous outcome)"
                    );
                    break;
                }
            };
            let prev_pubkey = *prev_outcome.sharing().public();

            // If keys differ, there was a full DKG at search_epoch
            if curr_pubkey != prev_pubkey {
                // Fetch the block and certificate that committed the new identity
                let proof_height = epocher
                    .last(Epoch::new(search_epoch))
                    .expect("fixed epocher is valid for all epochs");

                let Some(proof_block) = marshal.get_block(proof_height).await else {
                    tracing::info!(
                        height = proof_height.get(),
                        start_epoch,
                        search_epoch,
                        "stopping identity transition walk early (proof block pruned)"
                    );
                    break;
                };

                let Some(finalization) = marshal.get_finalization(proof_height).await else {
                    tracing::info!(
                        height = proof_height.get(),
                        start_epoch,
                        search_epoch,
                        "stopping identity transition walk early (finalization pruned)"
                    );
                    break;
                };

                transitions.push(IdentityTransition {
                    transition_epoch: search_epoch,
                    old_identity: hex::encode(prev_pubkey.encode()),
                    new_identity: hex::encode(curr_pubkey.encode()),
                    proof: Some(TransitionProofData {
                        header: TempoHeaderResponse::from_consensus_header(
                            proof_block.clone_sealed_header(),
                            0,
                        ),
                        finalization_certificate: hex::encode(finalization.encode()),
                    }),
                });

                if !full {
                    break;
                }
            }

            curr_pubkey = prev_pubkey;
            search_epoch -= 1;
        }

        // If we walked all the way to epoch 0, we reached genesis
        if full && search_epoch == 0 {
            reached_genesis = true;
        }

        // Include genesis identity as explicit terminal marker when we reached it.
        // There is never a finalization certificate for genesis, so proof is None.
        if full && reached_genesis {
            // Only add genesis marker if not already present from cache
            let has_genesis = transitions
                .last()
                .is_some_and(|t| t.transition_epoch == 0 && t.proof.is_none());
            if !has_genesis {
                match get_outcome(&mut marshal, &epocher, 0).await {
                    Ok(genesis_outcome) => {
                        let genesis_pubkey = *genesis_outcome.sharing().public();
                        let genesis_identity = hex::encode(genesis_pubkey.encode());
                        transitions.push(IdentityTransition {
                            transition_epoch: 0,
                            old_identity: genesis_identity.clone(),
                            new_identity: genesis_identity,
                            proof: None,
                        });
                    }
                    Err(err) => {
                        tracing::debug!(
                            ?err,
                            "failed to fetch genesis outcome; omitting genesis marker"
                        );
                    }
                }
            }
        }

        // Update cache if this is a full query and we made progress
        if full {
            let new_cache = IdentityTransitionCache {
                from_epoch: start_epoch,
                to_epoch: search_epoch,
                identity: identity.clone(),
                transitions: Arc::new(transitions.clone()),
            };
            // Only update if this extends the cache (newer start OR older end)
            let should_update = cached
                .as_ref()
                .map(|c| start_epoch > c.from_epoch || search_epoch < c.to_epoch)
                .unwrap_or(true);
            // Merge with existing cache if we're extending
            let new_cache = if let Some(ref c) = cached {
                IdentityTransitionCache {
                    from_epoch: start_epoch.max(c.from_epoch),
                    to_epoch: search_epoch.min(c.to_epoch),
                    identity: if start_epoch >= c.from_epoch {
                        identity.clone()
                    } else {
                        c.identity.clone()
                    },
                    transitions: if start_epoch > c.from_epoch {
                        // Merge: new transitions + cached (deduplicated)
                        let mut merged = transitions.clone();
                        for t in c.transitions.iter() {
                            if !merged
                                .iter()
                                .any(|m| m.transition_epoch == t.transition_epoch)
                            {
                                merged.push(t.clone());
                            }
                        }
                        merged.sort_by_key(|t| std::cmp::Reverse(t.transition_epoch));
                        Arc::new(merged)
                    } else {
                        Arc::new(transitions.clone())
                    },
                }
            } else {
                new_cache
            };
            if should_update {
                *self.identity_cache.write() = Some(new_cache);
            }
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
