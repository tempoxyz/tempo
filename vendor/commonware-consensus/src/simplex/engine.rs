use super::{
    actors::{batcher, resolver, voter},
    config::Config,
    elector::Config as Elector,
    types::{Activity, Context},
};
use crate::{
    simplex::{scheme::Scheme, Plan},
    CertifiableAutomaton, Relay, Reporter,
};
use commonware_cryptography::Digest;
use commonware_macros::select;
use commonware_p2p::{Blocker, Receiver, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{
    spawn_cell, BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner, Storage,
};
use rand_core::CryptoRng;
use tracing::debug;

/// Instance of `simplex` consensus engine.
pub struct Engine<
    E: BufferPooler + Clock + CryptoRng + Spawner + Storage + Metrics,
    S: Scheme<D>,
    L: Elector<S>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    A: CertifiableAutomaton<Context = Context<D, S::PublicKey>, Digest = D>,
    R: Relay<Digest = D, PublicKey = S::PublicKey, Plan = Plan<S::PublicKey>>,
    F: Reporter<Activity = Activity<S, D>>,
    T: Strategy,
> {
    context: ContextCell<E>,

    voter: voter::Actor<E, S, L, B, D, A, R, F>,
    voter_mailbox: voter::Mailbox<S, D>,

    batcher: batcher::Actor<E, S, B, D, F, R, T>,
    batcher_mailbox: batcher::Mailbox<S, D>,

    resolver: resolver::Actor<E, S, B, D, T>,
    resolver_mailbox: resolver::Mailbox<S, D>,
}

impl<
        E: BufferPooler + Clock + CryptoRng + Spawner + Storage + Metrics,
        S: Scheme<D>,
        L: Elector<S>,
        B: Blocker<PublicKey = S::PublicKey>,
        D: Digest,
        A: CertifiableAutomaton<Context = Context<D, S::PublicKey>, Digest = D>,
        R: Relay<Digest = D, PublicKey = S::PublicKey, Plan = Plan<S::PublicKey>>,
        F: Reporter<Activity = Activity<S, D>>,
        T: Strategy,
    > Engine<E, S, L, B, D, A, R, F, T>
{
    /// Create a new `simplex` consensus engine.
    pub fn new(mut context: E, cfg: Config<S, L, B, D, A, R, F, T>) -> Self {
        // Ensure configuration is valid
        cfg.assert(&mut context);

        // Create batcher
        let (batcher, batcher_mailbox) = batcher::Actor::new(
            context.child("batcher"),
            batcher::Config {
                scheme: cfg.scheme.clone(),
                blocker: cfg.blocker.clone(),
                reporter: cfg.reporter.clone(),
                relay: cfg.relay.clone(),
                strategy: cfg.strategy.clone(),
                epoch: cfg.epoch,
                mailbox_size: cfg.mailbox_size,
                activity_timeout: cfg.activity_timeout,
                skip_timeout: cfg.skip_timeout,
                forwarding: cfg.forwarding,
            },
        );

        // Create voter
        let (voter, voter_mailbox) = voter::Actor::new(
            context.child("voter"),
            voter::Config {
                scheme: cfg.scheme.clone(),
                elector: cfg.elector,
                blocker: cfg.blocker.clone(),
                automaton: cfg.automaton,
                relay: cfg.relay,
                reporter: cfg.reporter,
                partition: cfg.partition,
                mailbox_size: cfg.mailbox_size,
                epoch: cfg.epoch,
                floor: cfg.floor,
                leader_timeout: cfg.leader_timeout,
                certification_timeout: cfg.certification_timeout,
                timeout_retry: cfg.timeout_retry,
                activity_timeout: cfg.activity_timeout,
                replay_buffer: cfg.replay_buffer,
                write_buffer: cfg.write_buffer,
                page_cache: cfg.page_cache,
            },
        );

        // Create resolver
        let (resolver, resolver_mailbox) = resolver::Actor::new(
            context.child("resolver"),
            resolver::Config {
                blocker: cfg.blocker,
                scheme: cfg.scheme,
                strategy: cfg.strategy,
                mailbox_size: cfg.mailbox_size,
                epoch: cfg.epoch,
                fetch_concurrent: cfg.fetch_concurrent,
                fetch_timeout: cfg.fetch_timeout,
            },
        );

        // Return the engine
        Self {
            context: ContextCell::new(context),

            voter,
            voter_mailbox,

            batcher,
            batcher_mailbox,

            resolver,
            resolver_mailbox,
        }
    }

    /// Start the `simplex` consensus engine.
    ///
    /// This will also rebuild the state of the engine from provided `Journal`.
    ///
    /// # Network Channels
    ///
    /// The engine requires three separate network channels, each carrying votes or
    /// certificates to help drive the consensus engine.
    ///
    /// ## `vote_network`
    ///
    /// Carries **individual votes**:
    /// - [`Notarize`](super::types::Notarize): Vote to notarize a proposal
    /// - [`Nullify`](super::types::Nullify): Vote to skip a view
    /// - [`Finalize`](super::types::Finalize): Vote to finalize a notarized proposal
    ///
    /// These messages are sent to the batcher, which performs batch signature
    /// verification before forwarding valid votes to the voter for aggregation.
    ///
    /// ## `certificate_network`
    ///
    /// Carries **certificates**:
    /// - [`Notarization`](super::types::Notarization): Proof that a proposal was notarized
    /// - [`Nullification`](super::types::Nullification): Proof that a view was skipped
    /// - [`Finalization`](super::types::Finalization): Proof that a proposal was finalized
    ///
    /// Certificates are broadcast on this channel as soon as they are constructed
    /// from collected votes. We separate this from the `vote_network` to optimistically
    /// allow for certificate processing to short-circuit vote processing (if we receive
    /// a certificate before processing pending votes, we can skip them).
    ///
    /// ## `resolver_network`
    ///
    /// Used for request-response certificate fetching. When a node needs to
    /// catch up on a view it missed (e.g., to verify a proposal's parent), it
    /// uses this channel to request certificates from peers. The resolver handles
    /// rate limiting, retries, and peer selection for these requests.
    pub fn start(
        mut self,
        vote_network: (
            impl Sender<PublicKey = S::PublicKey>,
            impl Receiver<PublicKey = S::PublicKey>,
        ),
        certificate_network: (
            impl Sender<PublicKey = S::PublicKey>,
            impl Receiver<PublicKey = S::PublicKey>,
        ),
        resolver_network: (
            impl Sender<PublicKey = S::PublicKey>,
            impl Receiver<PublicKey = S::PublicKey>,
        ),
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(vote_network, certificate_network, resolver_network)
        )
    }

    async fn run(
        self,
        vote_network: (
            impl Sender<PublicKey = S::PublicKey>,
            impl Receiver<PublicKey = S::PublicKey>,
        ),
        certificate_network: (
            impl Sender<PublicKey = S::PublicKey>,
            impl Receiver<PublicKey = S::PublicKey>,
        ),
        resolver_network: (
            impl Sender<PublicKey = S::PublicKey>,
            impl Receiver<PublicKey = S::PublicKey>,
        ),
    ) {
        // Start the batcher (receives votes via vote_network, certificates via certificate_network)
        // Batcher sends proposals/certificates to voter via voter_mailbox
        let (vote_sender, vote_receiver) = vote_network;
        let (certificate_sender, certificate_receiver) = certificate_network;
        let mut batcher_task = self.batcher.start(
            self.voter_mailbox.clone(),
            vote_receiver,
            certificate_receiver,
        );

        // Start the resolver (sends certificates to voter via voter_mailbox)
        let (resolver_sender, resolver_receiver) = resolver_network;
        let mut resolver_task =
            self.resolver
                .start(self.voter_mailbox, resolver_sender, resolver_receiver);

        // Start the voter
        let mut voter_task = self.voter.start(
            self.batcher_mailbox,
            self.resolver_mailbox,
            vote_sender,
            certificate_sender,
        );

        // If any task completes, the engine should stop
        let mut shutdown = self.context.stopped();
        select! {
            _ = &mut shutdown => {
                debug!("context shutdown, stopping engine");
            },
            voter = &mut voter_task => {
                debug!(?voter, "voter stopped, shutting down engine");
            },
            batcher = &mut batcher_task => {
                debug!(?batcher, "batcher stopped, shutting down engine");
            },
            resolver = &mut resolver_task => {
                debug!(?resolver, "resolver stopped, shutting down engine");
            },
        }
    }
}
