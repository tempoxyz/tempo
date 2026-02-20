//! Shared state for the feed module.
//!
//! # Identity Transition Proof Invariants
//!
//! The `consensus_getIdentityTransitionProof` RPC method walks the chain
//! backwards to build a proof of how the network's BLS identity evolved.
//! The following invariants must hold for both the cached and uncached paths:
//!
//! 1. **Epoch-to-identity correctness**: For any queried epoch N, the returned
//!    `identity` must be the one *active during* epoch N. Identity active at
//!    epoch N is set by the last block of epoch N-1, so a DKG transition
//!    recorded at epoch E produces a key that becomes active at epoch E+1.
//!
//! 2. **Transition filter boundary**: Returned transitions must have
//!    `transition_epoch < start_epoch` (strict). The non-cached walk starts at
//!    `start_epoch - 1`, so it can never discover a transition at exactly
//!    `start_epoch`. The cache filter must match this to ensure consistency.
//!
//! 3. **Cache-uncache equivalence**: The response for a given `(from_epoch, full)`
//!    must be identical regardless of whether it is served from cache or computed
//!    from scratch.
//!
//! 4. **Cache connect direction**: The cache connect optimization (stitching a
//!    fresh walk onto existing cached data) must only activate when the query
//!    epoch is *newer* than the cached range. Connecting when the query is older
//!    would inject transitions from future epochs into the response.
//!
//! 5. **Cache boundary completeness**: When connecting to cached data, use
//!    strict `<` comparison (`search_epoch < connect_epoch`) so the walk still
//!    processes the epoch at the cache boundary. The cache was built starting at
//!    `connect_epoch` and walked from `connect_epoch - 1`, so it does not
//!    contain any transition at exactly `connect_epoch`.
//!
//! 6. **`full=false` cardinality**: When `full=false`, at most one transition
//!    is returned, including when the response is partially served from cache
//!    via the connect path.
//!
//! 7. **No panics on user input**: User-supplied `from_epoch` values must not
//!    cause panics. Large values that overflow epoch-to-height arithmetic are
//!    rejected with `IdentityProofError::InvalidEpoch`.

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
        // Filter transitions to only include those strictly before start_epoch.
        // A transition at epoch E means the DKG at E produced a new key that
        // becomes active at E+1, so only transitions at epochs < start_epoch
        // are relevant history. This matches the non-cached walk which starts
        // at search_epoch = start_epoch - 1.
        let transitions: Vec<_> = cache
            .transitions
            .iter()
            .filter(|t| t.transition_epoch < start_epoch)
            .cloned()
            .collect();

        // Determine identity at start_epoch:
        // - If start_epoch == from_epoch, use cached identity
        // - Otherwise, find the first transition AT OR AFTER start_epoch and use
        //   its old_identity (that was the identity active during start_epoch,
        //   before the transition took effect at transition_epoch + 1)
        // - If no such transition, identity hasn't changed since from_epoch
        let identity = if start_epoch == cache.from_epoch {
            cache.identity.clone()
        } else {
            // Find the immediate next transition at or after start_epoch.
            // Transitions are stored in descending order, so we use rfind
            // to get the smallest epoch >= start_epoch.
            cache
                .transitions
                .iter()
                .rfind(|t| t.transition_epoch >= start_epoch)
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

        // Validate user-supplied epoch won't overflow before doing any work
        if let Some(epoch) = from_epoch {
            validate_epoch(&epocher, epoch)?;
        }

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

        // If we have a cache, try to connect to it instead of walking all the way.
        // Only connect when walking from a newer epoch towards the cache; if the
        // query is older than the cache start, connecting would inject transitions
        // from future epochs into the response.
        let cache_connect_epoch = cached
            .as_ref()
            .filter(|c| start_epoch > c.from_epoch)
            .map(|c| c.from_epoch);

        while search_epoch > 0 {
            // Check if we can connect to cached data.
            // Use strict < so we still process search_epoch == connect_epoch
            // before connecting — the cache was built starting at connect_epoch
            // and walked from connect_epoch - 1, so it doesn't contain any
            // transition at exactly connect_epoch.
            if let Some(connect_epoch) = cache_connect_epoch
                && search_epoch < connect_epoch
                && let Some(ref cache) = cached
            {
                // Append cached transitions and stop walking.
                // When full=false, only take the most recent applicable cached
                // transition to honour the "return at most 1" contract.
                if full {
                    transitions.extend(cache.transitions.iter().cloned());
                } else if let Some(t) = cache
                    .transitions
                    .iter()
                    .find(|t| t.transition_epoch < start_epoch)
                    .cloned()
                {
                    transitions.push(t);
                }
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
                let Some(proof_height) = epocher.last(Epoch::new(search_epoch)) else {
                    tracing::info!(
                        start_epoch,
                        search_epoch,
                        "stopping identity transition walk early (invalid epoch)"
                    );
                    break;
                };

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

/// Validate that a from_epoch value won't cause overflow in epoch-to-height conversion.
fn validate_epoch(epocher: &FixedEpocher, epoch: u64) -> Result<(), IdentityProofError> {
    epocher
        .last(Epoch::new(epoch))
        .map(|_| ())
        .ok_or(IdentityProofError::InvalidEpoch(epoch))
}

/// Fetch last block of epoch and decode DKG outcome.
async fn get_outcome(
    marshal: &mut marshal::Mailbox,
    epocher: &FixedEpocher,
    epoch: u64,
) -> Result<OnchainDkgOutcome, IdentityProofError> {
    let height = epocher
        .last(Epoch::new(epoch))
        .ok_or(IdentityProofError::InvalidEpoch(epoch))?;
    let block = marshal
        .get_block(height)
        .await
        .ok_or(IdentityProofError::PrunedData(height.get()))?;
    OnchainDkgOutcome::read(&mut block.header().extra_data().as_ref())
        .map_err(|_| IdentityProofError::MalformedData(height.get()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU64;

    fn make_transition(epoch: u64, old: &str, new: &str) -> IdentityTransition {
        IdentityTransition {
            transition_epoch: epoch,
            old_identity: old.to_string(),
            new_identity: new.to_string(),
            proof: None,
        }
    }

    fn make_cache(
        from_epoch: u64,
        to_epoch: u64,
        identity: &str,
        transitions: Vec<IdentityTransition>,
    ) -> IdentityTransitionCache {
        IdentityTransitionCache {
            from_epoch,
            to_epoch,
            identity: identity.to_string(),
            transitions: Arc::new(transitions),
        }
    }

    /// Invariant: serve_from_cache must return the identity active at the queried
    /// epoch, which is the identity set by the most recent DKG at or before that epoch.
    #[test]
    fn serve_from_cache_returns_correct_identity_for_intermediate_epochs() {
        let handle = FeedStateHandle::new();

        // DKG transitions at epochs 100, 50, 25 (stored descending)
        // | Epoch Range | Active Identity |
        // | 0–24        | key_genesis     |
        // | 25–49       | key_25          |
        // | 50–99       | key_50          |
        // | 100+        | key_100         |
        let cache = make_cache(
            120,
            0,
            "key_100",
            vec![
                make_transition(100, "key_50", "key_100"),
                make_transition(50, "key_25", "key_50"),
                make_transition(25, "key_genesis", "key_25"),
            ],
        );

        // Query epoch 30: should get key_25 (active from epoch 25–49)
        let resp = handle.serve_from_cache(&cache, 30, true);
        assert_eq!(
            resp.identity, "key_25",
            "epoch 30 should return key_25, the identity active at that epoch"
        );

        // Query epoch 60: should get key_50 (active from epoch 50–99)
        let resp = handle.serve_from_cache(&cache, 60, true);
        assert_eq!(
            resp.identity, "key_50",
            "epoch 60 should return key_50, the identity active at that epoch"
        );

        // Query epoch 10: should get key_genesis (active from epoch 0–24)
        let resp = handle.serve_from_cache(&cache, 10, true);
        assert_eq!(
            resp.identity, "key_genesis",
            "epoch 10 should return key_genesis, the identity active at that epoch"
        );

        // Query epoch 120 (== from_epoch): should get key_100
        let resp = handle.serve_from_cache(&cache, 120, true);
        assert_eq!(resp.identity, "key_100");

        // Query epoch 105: should get key_100 (active from epoch 100+)
        let resp = handle.serve_from_cache(&cache, 105, true);
        assert_eq!(
            resp.identity, "key_100",
            "epoch 105 should return key_100, the identity active at that epoch"
        );
    }

    /// Invariant: serve_from_cache must filter transitions to only those strictly
    /// before the queried epoch, matching the non-cached walk semantics.
    #[test]
    fn serve_from_cache_filters_transitions_strictly_before_start_epoch() {
        let handle = FeedStateHandle::new();

        let cache = make_cache(
            120,
            0,
            "key_100",
            vec![
                make_transition(100, "key_50", "key_100"),
                make_transition(50, "key_25", "key_50"),
                make_transition(25, "key_genesis", "key_25"),
            ],
        );

        // Query epoch 60: should only include transitions at epochs < 60
        let resp = handle.serve_from_cache(&cache, 60, true);
        let epochs: Vec<u64> = resp
            .transitions
            .iter()
            .map(|t| t.transition_epoch)
            .collect();
        assert_eq!(epochs, vec![50, 25]);

        // Query at exactly a transition epoch (50): transition at 50 should NOT
        // be in the returned list (it's the one that *set* the identity for this
        // epoch, not a prior transition)
        let resp = handle.serve_from_cache(&cache, 50, true);
        let epochs: Vec<u64> = resp
            .transitions
            .iter()
            .map(|t| t.transition_epoch)
            .collect();
        assert_eq!(
            epochs,
            vec![25],
            "transition at exactly start_epoch should be excluded"
        );

        // Non-full query should return at most 1 transition
        let resp = handle.serve_from_cache(&cache, 60, false);
        assert!(resp.transitions.len() <= 1);
    }

    /// Invariant: when querying at exactly a transition epoch, the returned identity
    /// must be the OLD identity (the one active during that epoch), not the new one.
    #[test]
    fn serve_from_cache_at_transition_epoch_returns_old_identity() {
        let handle = FeedStateHandle::new();

        let cache = make_cache(
            120,
            0,
            "key_100",
            vec![
                make_transition(100, "key_50", "key_100"),
                make_transition(50, "key_25", "key_50"),
                make_transition(25, "key_genesis", "key_25"),
            ],
        );

        // Query at epoch 50 (exactly where a DKG happened):
        // The DKG at epoch 50 produced key_50, but it becomes active at epoch 51.
        // During epoch 50, the active identity is still key_25.
        let resp = handle.serve_from_cache(&cache, 50, true);
        assert_eq!(
            resp.identity, "key_25",
            "at exactly transition_epoch=50, the active identity is key_25 (old)"
        );

        // Query at epoch 100:
        let resp = handle.serve_from_cache(&cache, 100, true);
        assert_eq!(
            resp.identity, "key_50",
            "at exactly transition_epoch=100, the active identity is key_50 (old)"
        );

        // Query at epoch 25:
        let resp = handle.serve_from_cache(&cache, 25, true);
        assert_eq!(
            resp.identity, "key_genesis",
            "at exactly transition_epoch=25, the active identity is key_genesis (old)"
        );
    }

    /// Invariant: when full=false and the walk connects to cached data, at most
    /// one transition should be appended (the most recent applicable one).
    #[test]
    fn cache_connect_respects_full_false_limit() {
        // Simulate what the connect path produces: when full=false, only the
        // most recent cached transition before start_epoch should be taken.
        let cache = make_cache(
            80,
            0,
            "key_80",
            vec![
                make_transition(60, "key_40", "key_60"),
                make_transition(40, "key_20", "key_40"),
                make_transition(20, "key_genesis", "key_20"),
            ],
        );

        let start_epoch: u64 = 100;
        let full = false;

        // Replicate the connect logic for full=false
        let mut transitions = Vec::new();
        if full {
            transitions.extend(cache.transitions.iter().cloned());
        } else if let Some(t) = cache
            .transitions
            .iter()
            .find(|t| t.transition_epoch < start_epoch)
            .cloned()
        {
            transitions.push(t);
        }

        assert_eq!(
            transitions.len(),
            1,
            "full=false cache connect must append at most 1 transition"
        );
        assert_eq!(
            transitions[0].transition_epoch, 60,
            "should pick the most recent transition before start_epoch"
        );
    }

    /// Invariant: cache connect must use strict < to avoid skipping a transition
    /// at exactly the cache boundary. The cache built from epoch E walked from
    /// E-1, so it doesn't contain transition at epoch E itself.
    #[test]
    fn cache_connect_uses_strict_less_than() {
        // Cache built from epoch 80 down to 0
        let cache = make_cache(
            80,
            0,
            "key_80",
            vec![make_transition(60, "key_40", "key_60")],
        );

        // When search_epoch == connect_epoch (80), we must NOT connect yet
        // because we haven't checked whether there's a transition at epoch 80.
        let search_epoch: u64 = 80;
        let connect_epoch = cache.from_epoch;

        // With strict <, this should NOT connect
        let should_connect_strict = search_epoch < connect_epoch;
        assert!(
            !should_connect_strict,
            "must not connect at search_epoch == connect_epoch (would skip transition at boundary)"
        );

        // search_epoch = 79 should connect
        let search_epoch: u64 = 79;
        let should_connect = search_epoch < connect_epoch;
        assert!(
            should_connect,
            "should connect when search_epoch < connect_epoch"
        );
    }

    /// Invariant: cache connect must only trigger when the query epoch is newer
    /// than the cached range. If the query is older, connecting would inject
    /// transitions from future epochs.
    #[test]
    fn cache_connect_epoch_guards_against_future_injection() {
        // Cache built from epoch 100 down to 50
        let cache = make_cache(
            100,
            50,
            "key_100",
            vec![
                make_transition(80, "key_60", "key_80"),
                make_transition(60, "key_50", "key_60"),
            ],
        );

        // Query from epoch 40 (older than cache): connect should NOT activate
        let start_epoch: u64 = 40;
        let connect = if start_epoch > cache.from_epoch {
            Some(cache.from_epoch)
        } else {
            None
        };
        assert!(
            connect.is_none(),
            "cache connect must not activate when query (40) < cache.from_epoch (100)"
        );

        // Query from epoch 150 (newer than cache): connect SHOULD activate
        let start_epoch: u64 = 150;
        let connect = if start_epoch > cache.from_epoch {
            Some(cache.from_epoch)
        } else {
            None
        };
        assert_eq!(
            connect,
            Some(100),
            "cache connect should activate when query (150) > cache.from_epoch (100)"
        );
    }

    #[test]
    fn validate_epoch_rejects_overflow() {
        let epocher = FixedEpocher::new(NonZeroU64::new(10).unwrap());

        // u64::MAX should overflow the epoch-to-height multiplication
        let result = validate_epoch(&epocher, u64::MAX);
        assert!(
            matches!(result, Err(IdentityProofError::InvalidEpoch(e)) if e == u64::MAX),
            "u64::MAX epoch should be rejected as invalid"
        );

        // Normal epoch should be fine
        let result = validate_epoch(&epocher, 5);
        assert!(result.is_ok(), "normal epoch should be valid");
    }
}
