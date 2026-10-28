//! Engine for the module.

use super::{
    Config, metrics,
    safe_tip::SafeTip,
    types::{Ack, Activity, Error, Item, TipAck},
};
use crate::{
    Automaton, Monitor, Reporter,
    aggregation::{scheme, types::Certificate},
    types::{Epoch, EpochDelta, Height, HeightDelta, Participant},
};
use commonware_cryptography::{
    Digest,
    certificate::{Provider, Scheme, Verifier},
};
use commonware_macros::select_loop;
use commonware_p2p::{
    Blocker, Receiver, Recipients, Sender,
    utils::codec::{WrappedSender, wrap},
};
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics, ReadOptions, Spawner, Storage,
    buffer::paged::CacheRef,
    spawn_cell,
    telemetry::metrics::{GaugeExt, histogram, status::Status},
};
use commonware_storage::journal::segmented::variable::{Config as JConfig, Journal};
use commonware_utils::{
    N3f1, PrioritySet,
    futures::{Pool as FuturesPool, rebind},
    non_empty,
    ordered::Quorum,
};
use futures::future::{self, Either};
use rand_core::CryptoRng;
use std::{
    cmp::max,
    collections::BTreeMap,
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::{debug, error, info, trace, warn};

/// An entry for a height that does not yet have a certificate.
enum Pending<S: Scheme, D: Digest> {
    /// The automaton has not yet provided the digest for this height.
    /// The signatures may have arbitrary digests.
    Unverified(BTreeMap<Epoch, BTreeMap<Participant, Ack<S, D>>>),

    /// Verified by the automaton. Now stores the digest.
    Verified(D, BTreeMap<Epoch, BTreeMap<Participant, Ack<S, D>>>),
}

/// The type returned by the `pending` pool, used by the application to return which digest is
/// associated with the given height.
struct DigestRequest<D: Digest> {
    /// The height in question.
    height: Height,

    /// The result of the verification.
    result: Result<D, Error>,

    /// Records the time taken to get the digest.
    timer: histogram::Timer,
}

/// Instance of the engine.
pub struct Engine<
    E: BufferPooler + Clock + Spawner + Storage + Metrics + CryptoRng,
    P: Provider<Scope = Epoch>,
    D: Digest,
    A: Automaton<Context = Height, Digest = D>,
    Z: Reporter<Activity = Activity<P::Scheme, D>>,
    M: Monitor<Index = Epoch>,
    B: Blocker<PublicKey = <P::Scheme as Verifier>::PublicKey>,
    T: Strategy,
> {
    // ---------- Interfaces ----------
    context: ContextCell<E>,
    automaton: A,
    monitor: M,
    provider: P,
    reporter: Z,
    blocker: B,
    strategy: T,

    // Pruning
    /// A tuple representing the epochs to keep in memory.
    /// The first element is the number of old epochs to keep.
    /// The second element is the number of future epochs to accept.
    ///
    /// For example, if the current epoch is 10, and the bounds are (1, 2), then
    /// epochs 9, 10, 11, and 12 are kept (and accepted);
    /// all others are pruned or rejected.
    epoch_bounds: (EpochDelta, EpochDelta),

    /// The concurrent number of chunks to process.
    window: HeightDelta,

    /// Number of heights to track below the tip when collecting acks and/or pruning.
    activity_timeout: HeightDelta,

    // Messaging
    /// Pool of pending futures to request a digest from the automaton.
    digest_requests: FuturesPool<'static, DigestRequest<D>>,

    // State
    /// The current epoch.
    epoch: Epoch,

    /// The current tip.
    tip: Height,

    /// Tracks the tips of all validators.
    safe_tip: SafeTip<<P::Scheme as Verifier>::PublicKey>,

    /// The keys represent the set of all `Height` values for which we are attempting to form a
    /// certificate, but do not yet have one. Values may be [Pending::Unverified] or [Pending::Verified],
    /// depending on whether the automaton has verified the digest or not.
    pending: BTreeMap<Height, Pending<P::Scheme, D>>,

    /// A map of heights with a certificate. Cached in memory if needed to send to other peers.
    confirmed: BTreeMap<Height, Certificate<P::Scheme, D>>,

    // ---------- Rebroadcasting ----------
    /// The frequency at which to rebroadcast pending heights.
    rebroadcast_timeout: Duration,

    /// A set of deadlines for rebroadcasting `Height` values that do not have a certificate.
    rebroadcast_deadlines: PrioritySet<Height, SystemTime>,

    // ---------- Journal ----------
    /// Journal for storing acks signed by this node.
    journal: Option<Journal<E, Activity<P::Scheme, D>>>,
    journal_partition: String,
    journal_write_buffer: NonZeroUsize,
    journal_replay_buffer: NonZeroUsize,
    journal_heights_per_section: NonZeroU64,
    journal_compression: Option<u8>,
    journal_page_cache: CacheRef,

    // ---------- Network ----------
    /// Whether to send acks as priority messages.
    priority_acks: bool,

    // ---------- Metrics ----------
    /// Metrics
    metrics: metrics::Metrics,
}

impl<
    E: BufferPooler + Clock + Spawner + Storage + Metrics + CryptoRng,
    P: Provider<Scope = Epoch, Scheme: scheme::Scheme<D>>,
    D: Digest,
    A: Automaton<Context = Height, Digest = D>,
    Z: Reporter<Activity = Activity<P::Scheme, D>>,
    M: Monitor<Index = Epoch>,
    B: Blocker<PublicKey = <P::Scheme as Verifier>::PublicKey>,
    T: Strategy,
> Engine<E, P, D, A, Z, M, B, T>
{
    /// Creates a new engine with the given context and configuration.
    pub fn new(context: E, cfg: Config<P, D, A, Z, M, B, T>) -> Self {
        let metrics = metrics::Metrics::init(&context);

        Self {
            context: ContextCell::new(context),
            automaton: cfg.automaton,
            reporter: cfg.reporter,
            monitor: cfg.monitor,
            provider: cfg.provider,
            blocker: cfg.blocker,
            strategy: cfg.strategy,
            epoch_bounds: cfg.epoch_bounds,
            window: HeightDelta::new(cfg.window.into()),
            activity_timeout: cfg.activity_timeout,
            epoch: Epoch::zero(),
            tip: Height::zero(),
            safe_tip: SafeTip::default(),
            digest_requests: FuturesPool::default(),
            pending: BTreeMap::new(),
            confirmed: BTreeMap::new(),
            rebroadcast_timeout: cfg.rebroadcast_timeout.into(),
            rebroadcast_deadlines: PrioritySet::new(),
            journal: None,
            journal_partition: cfg.journal_partition,
            journal_write_buffer: cfg.journal_write_buffer,
            journal_replay_buffer: cfg.journal_replay_buffer,
            journal_heights_per_section: cfg.journal_heights_per_section,
            journal_compression: cfg.journal_compression,
            journal_page_cache: cfg.journal_page_cache,
            priority_acks: cfg.priority_acks,
            metrics,
        }
    }

    /// Gets the scheme for a given epoch, returning an error if unavailable.
    fn scheme(&self, epoch: Epoch) -> Result<Arc<P::Scheme>, Error> {
        self.provider
            .scheme(epoch)
            .ok_or(Error::UnknownEpoch(epoch))
    }

    /// Runs the engine until the context is stopped.
    ///
    /// The engine will handle:
    /// - Requesting and processing digests from the automaton
    /// - Timeouts
    ///   - Refreshing the Epoch
    ///   - Rebroadcasting Acks
    /// - Messages from the network:
    ///   - Acks from other validators
    pub fn start(
        mut self,
        network: (
            impl Sender<PublicKey = <P::Scheme as Verifier>::PublicKey>,
            impl Receiver<PublicKey = <P::Scheme as Verifier>::PublicKey>,
        ),
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(network))
    }

    /// Inner run loop called by `start`.
    async fn run(
        mut self,
        network: (
            impl Sender<PublicKey = <P::Scheme as Verifier>::PublicKey>,
            impl Receiver<PublicKey = <P::Scheme as Verifier>::PublicKey>,
        ),
    ) {
        let (mut sender, mut receiver) = wrap(
            (),
            self.context.network_buffer_pool().clone(),
            network.0,
            network.1,
        );

        // Initialize the epoch
        let (latest, mut epoch_updates) = self.monitor.subscribe().await;
        self.epoch = latest;

        // Initialize Journal
        let journal_cfg = JConfig {
            partition: self.journal_partition.clone(),
            compression: self.journal_compression,
            codec_config: P::Scheme::certificate_codec_config_unbounded(),
            page_cache: self.journal_page_cache.clone(),
            write_buffer: self.journal_write_buffer,
        };
        let journal = Journal::init(self.context.child("journal"), journal_cfg)
            .await
            .expect("init failed");
        let (journal, unverified_heights) = self.replay(journal).await;
        self.journal = Some(journal);

        // Request digests for unverified heights
        for height in unverified_heights {
            trace!(%height, "requesting digest for unverified height from replay");
            self.get_digest(height);
        }

        // Initialize the tip manager
        let scheme = self
            .scheme(self.epoch)
            .expect("current epoch scheme must exist");
        self.safe_tip.init(scheme.participants());

        select_loop! {
            self.context,
            on_start => {
                let _ = self.metrics.tip.try_set(self.tip.get());

                // Propose a new digest if we are processing less than the window
                let next = self.next();

                // Underflow safe: next >= self.tip is guaranteed by next()
                if next.delta_from(self.tip).unwrap() < self.window {
                    trace!(%next, "requesting new digest");
                    assert!(
                        self.pending
                            .insert(next, Pending::Unverified(BTreeMap::new()))
                            .is_none()
                    );
                    self.get_digest(next);
                    continue;
                }

                // Get the rebroadcast deadline for the next height
                let rebroadcast = match self.rebroadcast_deadlines.peek() {
                    Some((_, &deadline)) => Either::Left(self.context.sleep_until(deadline)),
                    None => Either::Right(future::pending()),
                };
            },
            on_stopped => {
                debug!("shutdown");
            },
            // Handle refresh epoch deadline
            Some(epoch) = epoch_updates.recv() else {
                error!("epoch subscription failed");
                break;
            } => {
                // Refresh the epoch
                debug!(current = %self.epoch, new = %epoch, "refresh epoch");
                assert!(epoch >= self.epoch);
                self.epoch = epoch;

                // Update the tip manager
                let scheme = self
                    .scheme(self.epoch)
                    .expect("current epoch scheme must exist");
                self.safe_tip.reconcile(scheme.participants());

                // Update data structures by purging old epochs
                let min_epoch = self.epoch.saturating_sub(self.epoch_bounds.0);
                self.pending
                    .iter_mut()
                    .for_each(|(_, pending)| match pending {
                        self::Pending::Unverified(acks) => {
                            acks.retain(|epoch, _| *epoch >= min_epoch);
                        }
                        self::Pending::Verified(_, acks) => {
                            acks.retain(|epoch, _| *epoch >= min_epoch);
                        }
                    });

                continue;
            },

            // Sign a new ack
            request = self.digest_requests.next_completed() => {
                let DigestRequest {
                    height,
                    result,
                    timer,
                } = request;
                match result {
                    Err(err) => {
                        warn!(?err, %height, "automaton returned error");
                        self.metrics.digest.inc(Status::Dropped);
                    }
                    Ok(digest) => {
                        timer.observe(self.context.as_ref());
                        self = self.handle_digest(height, digest, &mut sender).await;
                    }
                }
            },

            // Handle incoming acks
            msg = receiver.recv() => {
                // Error handling
                let (sender, msg) = match msg {
                    Ok(r) => r,
                    Err(err) => {
                        warn!(?err, "ack receiver failed");
                        break;
                    }
                };
                let mut guard = self.metrics.acks.guard(Status::Invalid);
                let TipAck { ack, tip } = match msg {
                    Ok(peer_ack) => peer_ack,
                    Err(err) => {
                        commonware_p2p::block!(self.blocker, sender, ?err, "ack decode failed");
                        continue;
                    }
                };

                // Update the tip manager
                if self.safe_tip.update(sender.clone(), tip).is_some() {
                    // Fast-forward our tip if needed
                    let safe_tip = self.safe_tip.get();
                    if safe_tip > self.tip {
                        self = self.fast_forward_tip(safe_tip).await;
                    }
                }

                // Validate that we need to process the ack
                if let Err(err) = self.validate_ack(&ack, &sender) {
                    if err.blockable() {
                        commonware_p2p::block!(
                            self.blocker,
                            sender,
                            ?err,
                            "ack validation failure"
                        );
                    } else {
                        debug!(?sender, ?err, "ack validate failed");
                    }
                    continue;
                };

                // Handle the ack
                let accepted;
                (self, accepted) = self.handle_ack(&ack).await;
                if !accepted {
                    guard.set(Status::Failure);
                    continue;
                }

                // Update the metrics
                debug!(?sender, epoch = %ack.epoch, height = %ack.item.height, "ack");
                guard.set(Status::Success);
            },

            // Rebroadcast
            _ = rebroadcast => {
                // Get the next height to rebroadcast
                let (height, _) = self
                    .rebroadcast_deadlines
                    .pop()
                    .expect("no rebroadcast deadline");
                trace!(%height, "rebroadcasting");
                self = self.handle_rebroadcast(height, &mut sender).await;
            },
        }

        // Close journal on shutdown
        if let Some(journal) = self.journal.take() {
            journal.sync_all().await.expect("unable to sync journal");
        }
    }

    // ---------- Handling ----------

    /// Handles a digest returned by the automaton.
    async fn handle_digest(
        mut self,
        height: Height,
        digest: D,
        sender: &mut WrappedSender<
            impl Sender<PublicKey = <P::Scheme as Verifier>::PublicKey>,
            TipAck<P::Scheme, D>,
        >,
    ) -> Self {
        // Entry must be `Pending::Unverified`, or return early
        if !matches!(self.pending.get(&height), Some(Pending::Unverified(_))) {
            debug!(%height, "digest height not pending");
            return self;
        };

        // Move the entry to `Pending::Verified`
        let Some(Pending::Unverified(acks)) = self.pending.remove(&height) else {
            panic!("Pending::Unverified entry not found");
        };
        self.pending
            .insert(height, Pending::Verified(digest, BTreeMap::new()));

        // Handle each `ack` as if it was received over the network. This inserts the values into
        // the new map, and may form a certificate if enough acks are present. Only process acks
        // that match the verified digest.
        for epoch_acks in acks.values() {
            for epoch_ack in epoch_acks.values() {
                // Drop acks that don't match the verified digest
                if epoch_ack.item.digest != digest {
                    continue;
                }

                // Handle the ack
                (self, _) = self.handle_ack(epoch_ack).await;
            }
            // Break early if a certificate was formed
            if self.confirmed.contains_key(&height) {
                break;
            }
        }

        // Sign my own ack
        let signed;
        (self, signed) = self.sign_ack(height, digest).await;
        let Some(ack) = signed else {
            return self;
        };

        // Set the rebroadcast deadline for this height
        self.rebroadcast_deadlines
            .put(height, self.context.current() + self.rebroadcast_timeout);

        // Handle ack as if it was received over the network
        (self, _) = self.handle_ack(&ack).await;

        // Send ack over the network.
        self.broadcast(ack, sender);

        self
    }

    /// Handles an ack.
    ///
    /// Returns whether the ack was accepted. An ack is rejected if it is invalid or
    /// inapplicable (e.g. unknown scheme, non-pending height, digest mismatch).
    /// Duplicate acks are accepted as no-ops.
    async fn handle_ack(mut self, ack: &Ack<P::Scheme, D>) -> (Self, bool) {
        // Get the quorum (from scheme participants for the ack's epoch)
        let scheme = match self.scheme(ack.epoch) {
            Ok(scheme) => scheme,
            Err(err) => {
                debug!(?err, epoch = %ack.epoch, signer = %ack.attestation.signer, "ack for unknown scheme");
                return (self, false);
            }
        };
        let quorum = usize::try_from(scheme.participants().quorum::<N3f1>())
            .expect("quorum exceeds usize::MAX");

        // Get the acks and check digest consistency
        let acks_by_epoch = match self.pending.get_mut(&ack.item.height) {
            None => {
                // If the height is not in the pending pool, it may be confirmed
                // (i.e. we have a certificate for it).
                debug!(height = %ack.item.height, signer = %ack.attestation.signer, "ack height not pending");
                return (self, false);
            }
            Some(Pending::Unverified(acks)) => acks,
            Some(Pending::Verified(digest, acks)) => {
                // If we have a verified digest, ensure the ack matches it
                if ack.item.digest != *digest {
                    debug!(height = %ack.item.height, signer = %ack.attestation.signer, "ack digest mismatch");
                    return (self, false);
                }
                acks
            }
        };

        // Add the attestation (if not already present)
        let acks = acks_by_epoch.entry(ack.epoch).or_default();
        if acks.contains_key(&ack.attestation.signer) {
            return (self, true);
        }
        acks.insert(ack.attestation.signer, ack.clone());

        // If there exists a quorum of acks with the same digest (or for the verified digest if it exists), form a certificate
        let filtered = acks
            .values()
            .filter(|a| a.item.digest == ack.item.digest)
            .collect::<Vec<_>>();
        if filtered.len() >= quorum {
            // Every stored acknowledgement is verified and signer-unique, so a same-item quorum
            // satisfies the certificate scheme's assembly contract.
            let certificate =
                Certificate::from_acks(&*scheme, non_empty![@filtered], &self.strategy)
                    .expect("verified acknowledgement quorum must assemble");
            self.metrics.certificates.inc();
            self = self.handle_certificate(certificate).await;
        }

        (self, true)
    }

    /// Handles a certificate.
    async fn handle_certificate(mut self, certificate: Certificate<P::Scheme, D>) -> Self {
        // Check if we already have the certificate
        let height = certificate.item.height;
        if self.confirmed.contains_key(&height) {
            return self;
        }

        // Store the certificate
        self.confirmed.insert(height, certificate.clone());

        // Journal and notify the automaton
        let certified = Activity::Certified(certificate);
        self = self.record(certified.clone()).await.sync(height).await;
        self.reporter.report(certified);

        // Increase the tip if needed
        if height == self.tip {
            // Compute the next tip
            let mut new_tip = height.next();
            while self.confirmed.contains_key(&new_tip) && new_tip.get() < u64::MAX {
                new_tip = new_tip.next();
            }

            // If the next tip is larger, try to fast-forward the tip (may not be possible)
            if new_tip > self.tip {
                self = self.fast_forward_tip(new_tip).await;
            }
        }

        self
    }

    /// Handles a rebroadcast request for the given height.
    async fn handle_rebroadcast(
        mut self,
        height: Height,
        sender: &mut WrappedSender<
            impl Sender<PublicKey = <P::Scheme as Verifier>::PublicKey>,
            TipAck<P::Scheme, D>,
        >,
    ) -> Self {
        let Some(Pending::Verified(digest, acks)) = self.pending.get(&height) else {
            // The height may already be confirmed; continue silently if so
            return self;
        };
        let digest = *digest;

        // Get our signature
        let epoch = self.epoch;
        let scheme = match self.scheme(epoch) {
            Ok(scheme) => scheme,
            Err(err) => {
                warn!(?err, %height, "cannot rebroadcast: unknown scheme");
                return self;
            }
        };
        let Some(signer) = scheme.me() else {
            warn!(%epoch, %height, "cannot rebroadcast: not a signer");
            return self;
        };
        let ack = acks.get(&epoch).and_then(|acks| acks.get(&signer).cloned());
        let ack = match ack {
            Some(ack) => ack,
            None => {
                let signed;
                (self, signed) = self.sign_ack(height, digest).await;
                match signed {
                    Some(ack) => ack,
                    None => return self,
                }
            }
        };

        // Reinsert the height with a new deadline
        self.rebroadcast_deadlines
            .put(height, self.context.current() + self.rebroadcast_timeout);

        // Broadcast the ack to all peers
        self.broadcast(ack, sender);

        self
    }

    // ---------- Validation ----------

    /// Takes a raw ack (from sender) from the p2p network and validates it.
    ///
    /// Returns an error if the ack is invalid.
    fn validate_ack(
        &mut self,
        ack: &Ack<P::Scheme, D>,
        sender: &<P::Scheme as Verifier>::PublicKey,
    ) -> Result<(), Error> {
        // Validate epoch
        {
            let (eb_lo, eb_hi) = self.epoch_bounds;
            let bound_lo = self.epoch.saturating_sub(eb_lo);
            let bound_hi = self.epoch.saturating_add(eb_hi);
            if ack.epoch < bound_lo || ack.epoch > bound_hi {
                return Err(Error::AckEpochOutsideBounds(ack.epoch, bound_lo, bound_hi));
            }
        }

        // Validate sender matches the signer
        let scheme = self.scheme(ack.epoch)?;
        let participants = scheme.participants();
        let Some(signer) = participants.index(sender) else {
            return Err(Error::UnknownValidator(ack.epoch, sender.to_string()));
        };
        if signer != ack.attestation.signer {
            return Err(Error::PeerMismatch);
        }

        // Collect acks below the tip (if we don't yet have a certificate)
        let activity_threshold = self.tip.saturating_sub(self.activity_timeout);
        if ack.item.height < activity_threshold {
            return Err(Error::AckCertified(ack.item.height));
        }

        // If the height is above the tip (and the window), ignore for now
        if ack
            .item
            .height
            .delta_from(self.tip)
            .is_some_and(|d| d >= self.window)
        {
            return Err(Error::AckHeight(ack.item.height));
        }

        // Validate that we don't already have the ack
        if self.confirmed.contains_key(&ack.item.height) {
            return Err(Error::AckCertified(ack.item.height));
        }
        let have_ack = match self.pending.get(&ack.item.height) {
            None => false,
            Some(Pending::Unverified(epoch_map)) => epoch_map
                .get(&ack.epoch)
                .is_some_and(|acks| acks.contains_key(&ack.attestation.signer)),
            Some(Pending::Verified(digest, epoch_map)) => {
                // While we check this in the `handle_ack` function, checking early here avoids an
                // unnecessary signature check.
                if ack.item.digest != *digest {
                    return Err(Error::AckDigest(ack.item.height));
                }
                epoch_map
                    .get(&ack.epoch)
                    .is_some_and(|acks| acks.contains_key(&ack.attestation.signer))
            }
        };
        if have_ack {
            return Err(Error::AckDuplicate(sender.to_string(), ack.item.height));
        }

        // Validate signature
        if !ack.verify(self.context.as_mut(), &*scheme, &self.strategy) {
            return Err(Error::InvalidAckSignature);
        }

        Ok(())
    }

    // ---------- Helpers ----------

    /// Requests the digest from the automaton.
    ///
    /// Pending must contain the height.
    fn get_digest(&mut self, height: Height) {
        assert!(self.pending.contains_key(&height));
        let mut automaton = self.automaton.clone();
        let timer = self.metrics.digest_duration.timer(self.context.as_ref());
        self.digest_requests.push(async move {
            let receiver = automaton.propose(height).await;
            let result = receiver.await.map_err(Error::AppProposeCanceled);
            DigestRequest {
                height,
                result,
                timer,
            }
        });
    }

    /// Signs an ack for the given height, and digest. Stores the ack in the journal and returns it.
    /// Returns `None` if this node cannot sign at the current epoch.
    async fn sign_ack(mut self, height: Height, digest: D) -> (Self, Option<Ack<P::Scheme, D>>) {
        let epoch = self.epoch;
        let scheme = match self.scheme(epoch) {
            Ok(scheme) => scheme,
            Err(err) => {
                warn!(?err, %height, "cannot sign ack: unknown scheme");
                return (self, None);
            }
        };

        // Sign the item
        let item = Item { height, digest };
        let Some(ack) = Ack::sign(&*scheme, epoch, item) else {
            debug!(%epoch, %height, "cannot sign ack: not a signer");
            return (self, None);
        };

        // Journal the ack
        self = self
            .record(Activity::Ack(ack.clone()))
            .await
            .sync(height)
            .await;

        (self, Some(ack))
    }

    /// Broadcasts an ack to all peers with the appropriate priority.
    fn broadcast(
        &mut self,
        ack: Ack<P::Scheme, D>,
        sender: &mut WrappedSender<
            impl Sender<PublicKey = <P::Scheme as Verifier>::PublicKey>,
            TipAck<P::Scheme, D>,
        >,
    ) {
        sender.send(
            Recipients::All,
            TipAck { ack, tip: self.tip },
            self.priority_acks,
        );
    }

    /// Returns the next height that we should process. This is the minimum height for
    /// which we do not have a digest or an outstanding request to the automaton for the digest.
    fn next(&self) -> Height {
        let max_pending = self
            .pending
            .last_key_value()
            .map(|(k, _)| k.next())
            .unwrap_or_default();
        let max_confirmed = self
            .confirmed
            .last_key_value()
            .map(|(k, _)| k.next())
            .unwrap_or_default();
        max(self.tip, max(max_pending, max_confirmed))
    }

    /// Increases the tip to the given value, pruning stale entries.
    ///
    /// # Panics
    ///
    /// Panics if the given tip is less-than-or-equal-to the current tip.
    async fn fast_forward_tip(mut self, tip: Height) -> Self {
        assert!(tip > self.tip);

        // Prune data structures with buffer to prevent losing certificates
        let activity_threshold = tip.saturating_sub(self.activity_timeout);
        self.pending
            .retain(|height, _| *height >= activity_threshold);
        self.confirmed
            .retain(|height, _| *height >= activity_threshold);

        // Add tip to journal
        self = self.record(Activity::Tip(tip)).await.sync(tip).await;
        self.reporter.report(Activity::Tip(tip));

        // Prune journal with buffer
        let section = self.get_journal_section(activity_threshold);
        rebind(&mut self.journal, |journal| journal.prune(section))
            .await
            .expect("unable to prune journal");

        // Update the tip
        self.tip = tip;

        self
    }

    // ---------- Journal ----------

    /// Returns the section of the journal for the given `height`.
    const fn get_journal_section(&self, height: Height) -> u64 {
        height.get() / self.journal_heights_per_section.get()
    }

    /// Replays the journal, updating the state of the engine.
    /// Returns the journal and a list of unverified pending heights that need digest requests.
    async fn replay(
        &mut self,
        journal: Journal<E, Activity<P::Scheme, D>>,
    ) -> (Journal<E, Activity<P::Scheme, D>>, Vec<Height>) {
        let mut tip = Height::default();
        let mut certified = Vec::new();
        let mut acks = Vec::new();

        // Replay rebuilds the engine's in-memory state, so journal pages need
        // not remain in the OS page cache.
        let mut replay = journal
            .replay(0, 0, self.journal_replay_buffer, ReadOptions::DONT_CACHE)
            .await
            .expect("replay failed");
        while let Some(msg) = replay.next().await {
            let (_, _, _, activity) = msg.expect("replay failed");
            match activity {
                Activity::Tip(height) => {
                    tip = max(tip, height);
                    self.reporter.report(Activity::Tip(height));
                }
                Activity::Certified(certificate) => {
                    certified.push(certificate.clone());
                    self.reporter.report(Activity::Certified(certificate));
                }
                Activity::Ack(ack) => {
                    acks.push(ack.clone());
                    self.reporter.report(Activity::Ack(ack));
                }
            }
        }

        // Update the tip to the highest height in the journal
        self.tip = tip;
        let activity_threshold = tip.saturating_sub(self.activity_timeout);

        // Add certified items
        certified
            .iter()
            .filter(|certificate| certificate.item.height >= activity_threshold)
            .for_each(|certificate| {
                self.confirmed
                    .insert(certificate.item.height, certificate.clone());
            });

        // Group acks by height
        let mut acks_by_height: BTreeMap<Height, Vec<Ack<P::Scheme, D>>> = BTreeMap::new();
        for ack in acks {
            if ack.item.height >= activity_threshold
                && !self.confirmed.contains_key(&ack.item.height)
            {
                acks_by_height.entry(ack.item.height).or_default().push(ack);
            }
        }

        // Process each height's acks
        let mut unverified = Vec::new();
        for (height, mut acks_group) in acks_by_height {
            // Check if we have our own ack (which means we've verified the digest)
            let current_scheme = self.scheme(self.epoch).ok();
            let our_signer = current_scheme.as_ref().and_then(|s| s.me());
            let our_digest = our_signer.and_then(|signer| {
                acks_group
                    .iter()
                    .find(|ack| ack.epoch == self.epoch && ack.attestation.signer == signer)
                    .map(|ack| ack.item.digest)
            });

            // If our_digest exists, delete everything from acks_group that doesn't match it
            if let Some(digest) = our_digest {
                acks_group.retain(|other| other.item.digest == digest);
            }

            // Create a new epoch map
            let mut epoch_map = BTreeMap::new();
            for ack in acks_group {
                epoch_map
                    .entry(ack.epoch)
                    .or_insert_with(BTreeMap::new)
                    .insert(ack.attestation.signer, ack);
            }

            // Insert as Verified if we have our own ack (meaning we verified the digest),
            // otherwise as Unverified
            match our_digest {
                Some(digest) => {
                    self.pending
                        .insert(height, Pending::Verified(digest, epoch_map));

                    // If we've already generated an ack and it isn't yet confirmed, mark for immediate rebroadcast
                    self.rebroadcast_deadlines
                        .put(height, self.context.current());
                }
                None => {
                    self.pending.insert(height, Pending::Unverified(epoch_map));

                    // Add to unverified heights
                    unverified.push(height);
                }
            }
        }

        // After replay, ensure we have all heights from tip to next in pending or confirmed
        // to handle the case where we restart and some heights have no acks yet
        let next = self.next();
        for height in Height::range(self.tip, next) {
            // If we already have the height in pending or confirmed, skip
            if self.pending.contains_key(&height) || self.confirmed.contains_key(&height) {
                continue;
            }

            // Add missing height to pending
            self.pending
                .insert(height, Pending::Unverified(BTreeMap::new()));
            unverified.push(height);
        }
        info!(tip = %self.tip, %next, ?unverified, "replayed journal");

        (replay.finish().expect("replay failed"), unverified)
    }

    /// Appends an activity to the journal.
    async fn record(mut self, activity: Activity<P::Scheme, D>) -> Self {
        let height = match activity {
            Activity::Ack(ref ack) => ack.item.height,
            Activity::Certified(ref certificate) => certificate.item.height,
            Activity::Tip(h) => h,
        };
        let section = self.get_journal_section(height);
        rebind(&mut self.journal, |journal| {
            journal.append(section, &activity)
        })
        .await
        .expect("unable to append to journal");
        self
    }

    /// Syncs (ensures all data is written to disk).
    async fn sync(mut self, height: Height) -> Self {
        let section = self.get_journal_section(height);
        rebind(&mut self.journal, |journal| journal.sync(section))
            .await
            .expect("unable to sync journal");
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        aggregation::{mocks, scheme::ed25519},
        simplex::mocks::wrapped::{Behavior, Scheme as WrappedScheme},
    };
    use commonware_actor::Feedback;
    use commonware_cryptography::{Hasher as _, Sha256, certificate::mocks::Fixture};
    use commonware_p2p::Blocker;
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_utils::{NZU16, NZUsize, NonZeroDuration};

    #[derive(Clone)]
    struct NoopBlocker;

    impl Blocker for NoopBlocker {
        type PublicKey = commonware_cryptography::ed25519::PublicKey;

        fn block(&mut self, _peer: Self::PublicKey) -> Feedback {
            Feedback::Ok
        }

        fn blocked(&mut self) -> commonware_p2p::BlockedSubscription<Self::PublicKey> {
            let (_, receiver) =
                commonware_utils::channel::ring::channel(commonware_utils::NZUsize!(1));
            receiver
        }
    }

    #[test]
    #[should_panic(expected = "verified acknowledgement quorum must assemble")]
    fn assembly_failure_panics() {
        let runner = deterministic::Runner::timed(Duration::from_secs(10));
        runner.start(|mut context| async move {
            let epoch = Epoch::new(111);
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, b"aggregation-recovery-failure", 4);
            let provider = mocks::Provider::new();
            assert!(provider.register(
                epoch,
                WrappedScheme::new(schemes[0].clone(), Behavior::RecoveryFailure),
            ));
            let (_, reporter) = mocks::Reporter::new(
                context.child("reporter"),
                WrappedScheme::new(verifier, Behavior::Honest),
            );
            let page_cache = CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(10));
            let mut engine = Engine::new(
                context.child("engine"),
                Config {
                    monitor: mocks::Monitor::new(epoch),
                    provider,
                    automaton: mocks::Application::new(mocks::Strategy::Correct),
                    reporter,
                    blocker: NoopBlocker,
                    priority_acks: false,
                    rebroadcast_timeout: NonZeroDuration::new_panic(Duration::from_secs(1)),
                    epoch_bounds: (EpochDelta::new(1), EpochDelta::new(1)),
                    window: NonZeroU64::new(1).unwrap(),
                    activity_timeout: HeightDelta::new(10),
                    journal_partition: "aggregation-recovery-failure".to_string(),
                    journal_write_buffer: NZUsize!(4096),
                    journal_replay_buffer: NZUsize!(4096),
                    journal_heights_per_section: NonZeroU64::new(6).unwrap(),
                    journal_compression: None,
                    journal_page_cache: page_cache,
                    strategy: Sequential,
                },
            );

            let height = Height::new(0);
            let digest = Sha256::hash(&[b"payload"]);
            engine
                .pending
                .insert(height, Pending::Verified(digest, BTreeMap::new()));

            for scheme in schemes.iter().take(3) {
                let scheme = WrappedScheme::new(scheme.clone(), Behavior::Honest);
                let ack = Ack::sign(&scheme, epoch, Item { height, digest }).unwrap();
                (engine, _) = engine.handle_ack(&ack).await;
            }
        });
    }
}
