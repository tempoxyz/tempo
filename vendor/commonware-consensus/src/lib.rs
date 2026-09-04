//! Order opaque messages in a Byzantine environment.
//!
//! # Status
//!
//! Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

use commonware_macros::stability_scope;

stability_scope!(BETA {
    use commonware_codec::{Codec, Encode};
    use commonware_cryptography::Digestible;

    pub mod simplex;

    pub mod types;
    use types::{Epoch, Height, Round, View};

    /// Epochable is a trait that provides access to the epoch number.
    /// Any consensus message or object that is associated with a specific epoch should implement this.
    pub trait Epochable {
        /// Returns the epoch associated with this object.
        fn epoch(&self) -> Epoch;
    }

    /// Heightable is a trait that provides access to the height.
    /// Any consensus message or object that is associated with a specific height should implement this.
    pub trait Heightable {
        /// Returns the height associated with this object.
        fn height(&self) -> Height;
    }

    /// Viewable is a trait that provides access to the view (round) number.
    /// Any consensus message or object that is associated with a specific view should implement this.
    pub trait Viewable {
        /// Returns the view associated with this object.
        fn view(&self) -> View;
    }

    /// Roundable is a trait that provides access to the [`Round`] number.
    /// Any consensus message or object that implements [`Epochable`] and [`Viewable`] automatically
    /// implements this trait.
    pub trait Roundable: Epochable + Viewable {
        /// Returns the round associated with this object, derived from its epoch and view.
        fn round(&self) -> Round {
            Round::new(self.epoch(), self.view())
        }
    }

    impl<T: Epochable + Viewable> Roundable for T {}

    /// Block is the interface for a block in the blockchain.
    ///
    /// Blocks are used to track the progress of the consensus engine.
    pub trait Block: Heightable + Codec + Digestible + Send + Sync + 'static {
        /// Get the parent block's digest.
        fn parent(&self) -> Self::Digest;
    }

    /// CertifiableBlock extends [Block] with consensus context information.
    ///
    /// This trait is required for blocks used with deferred verification in [CertifiableAutomaton].
    /// It allows the verification context to be derived directly from the block when a validator
    /// needs to participate in certification but never verified the block locally (necessary for liveness).
    ///
    /// The [`Digestible`] implementation for a [`CertifiableBlock`] must commit to the block's
    /// embedded consensus context. In other words, changing [`CertifiableBlock::context`] for a
    /// block must also change [`Digestible::digest`].
    pub trait CertifiableBlock: Block {
        /// The consensus context type stored in this block.
        type Context: Clone + Encode;

        /// Get the consensus context that was used when this block was proposed.
        fn context(&self) -> Self::Context;
    }
});
stability_scope!(BETA, cfg(not(target_arch = "wasm32")) {
    use commonware_actor::Feedback;
    use commonware_cryptography::{Digest, PublicKey};
    use commonware_utils::channel::{fallible::OneshotExt, mpsc, oneshot};
    use std::future::Future;

    pub mod marshal;

    mod reporter;
    pub use reporter::*;

    /// Histogram buckets for measuring consensus latency.
    const LATENCY: [f64; 36] = [
        0.05, 0.1, 0.125, 0.15, 0.16, 0.17, 0.18, 0.19, 0.2, 0.21, 0.22, 0.23, 0.24, 0.25, 0.26,
        0.27, 0.28, 0.29, 0.3, 0.31, 0.32, 0.33, 0.34, 0.35, 0.36, 0.37, 0.38, 0.39, 0.4, 0.45,
        0.5, 0.6, 0.7, 0.8, 0.9, 1.0,
    ];

    /// Automaton is the interface responsible for driving the consensus forward by proposing new payloads
    /// and verifying payloads proposed by other participants.
    pub trait Automaton: Clone + Send + 'static {
        /// Context is metadata provided by the consensus engine associated with a given payload.
        ///
        /// This often includes things like the proposer, view number, the height, or the epoch.
        type Context;

        /// Hash of an arbitrary payload.
        type Digest: Digest;

        /// Generate a new payload for the given context.
        ///
        /// If it is possible to generate a payload, the Digest should be returned over the provided
        /// channel. If it is not possible to generate a payload, the channel can be dropped. If construction
        /// takes too long, the consensus engine may drop the provided proposal.
        ///
        /// Returning a payload from `propose` commits the local proposer to verifying
        /// the same `(context, payload)`.
        ///
        /// For [`CertifiableAutomaton`] implementations, returning a payload from
        /// `propose` also commits the local proposer to certifying that same
        /// `(round, payload)` if it later becomes notarized.
        fn propose(
            &mut self,
            context: Self::Context,
        ) -> impl Future<Output = oneshot::Receiver<Self::Digest>> + Send;

        /// Verify the payload is valid.
        ///
        /// This request is single-shot for the given `(context, payload)`. Once the returned
        /// channel resolves or closes, consensus treats verification as concluded and will not
        /// retry the same request. After a restart, however, consensus may request verification
        /// for the same `(context, payload)` again if the result was not durably recorded before
        /// shutdown.
        ///
        /// Implementations should therefore keep the request pending while the verdict may still
        /// change. Return `false` only when the payload is permanently invalid for this context.
        /// For example, temporary conditions such as time skew, missing dependencies, or data
        /// that may arrive later should not conclude verification with `false`.
        ///
        /// Closing the channel is also terminal for this request and should be reserved for cases
        /// where verification cannot ever produce a verdict anymore (for example, shutdown), not
        /// for temporary inability to decide.
        fn verify(
            &mut self,
            context: Self::Context,
            payload: Self::Digest,
        ) -> impl Future<Output = oneshot::Receiver<bool>> + Send;
    }

    /// CertifiableAutomaton extends [Automaton] with the ability to certify payloads before finalization.
    ///
    /// This trait is required by consensus implementations (like Simplex) that support a certification
    /// phase between notarization and finalization. Applications that do not need custom certification
    /// logic can use the default implementation which always certifies.
    pub trait CertifiableAutomaton: Automaton {
        /// Determine whether a verified payload is safe to commit.
        ///
        /// The round parameter identifies which consensus round is being certified, allowing
        /// applications to associate certification with the correct verification context. The
        /// same payload may appear in multiple rounds, so implementations must key any state
        /// on `(round, payload)` rather than `payload` alone.
        ///
        /// Like [`Automaton::verify`], payloads produced by [`Automaton::propose`] are certifiable-by-construction.
        /// Also like [`Automaton::verify`], certification is single-shot for the given
        /// `(round, payload)`. Once the returned channel resolves or closes, consensus treats
        /// certification as concluded and will not retry the same request. After a restart,
        /// however, consensus may request certification for the same `(round, payload)` again
        /// if the result was not durably recorded before shutdown.
        ///
        /// Implementations should therefore keep the request pending while the verdict may still
        /// change. Return `false` only when the payload is permanently uncertifiable for that
        /// round. Temporary conditions such as waiting for more data should not conclude
        /// certification with `false`.
        ///
        /// Closing the channel is also terminal for this request and should be reserved for cases
        /// where certification can no longer produce a verdict (for example, shutdown), not for temporary
        /// inability to decide.
        ///
        /// # Determinism Requirement
        ///
        /// The decision returned by `certify` must be deterministic and consistent across
        /// all honest participants to ensure liveness.
        fn certify(
            &mut self,
            _round: Round,
            _payload: Self::Digest,
        ) -> impl Future<Output = oneshot::Receiver<bool>> + Send {
            #[allow(clippy::async_yields_async)]
            async move {
                let (sender, receiver) = oneshot::channel();
                sender.send_lossy(true);
                receiver
            }
        }
    }

    /// Relay is the interface responsible for broadcasting payloads to the network.
    ///
    /// The consensus engine is only aware of a payload's digest, not its contents. It is up
    /// to the relay to efficiently broadcast the full payload to other participants.
    pub trait Relay: Clone + Send + 'static {
        /// Hash of an arbitrary payload.
        type Digest: Digest;

        /// Identity key of a network participant.
        type PublicKey: PublicKey;

        /// Directive for how a payload should be broadcast.
        ///
        /// Consensus mechanisms that need broadcast control (e.g. distinguishing
        /// initial broadcast from rebroadcasts) define a custom enum here. Mechanisms that
        /// treat every broadcast identically can set this to `()`.
        type Plan: Send;

        /// Broadcast a payload according to the given plan.
        fn broadcast(&mut self, payload: Self::Digest, plan: Self::Plan) -> Feedback;
    }

    /// Reporter is the interface responsible for reporting activity to some external actor.
    pub trait Reporter: Clone + Send + 'static {
        /// Activity is specified by the underlying consensus implementation and can be interpreted if desired.
        ///
        /// Examples of activity would be "vote", "finalize", or "fault". Various consensus implementations may
        /// want to reward (or penalize) participation in different ways and in different places. For example,
        /// validators could be required to send multiple types of messages (i.e. vote and finalize) and rewarding
        /// both equally may better align incentives with desired behavior.
        type Activity;

        /// Report some activity observed by the consensus implementation.
        fn report(&mut self, activity: Self::Activity) -> Feedback;
    }

    /// Monitor is the interface an external actor can use to observe the progress of a consensus implementation.
    ///
    /// Monitor is used to implement mechanisms that share the same set of active participants as consensus and/or
    /// perform some activity that requires some synchronization with the progress of consensus.
    ///
    /// Monitor can be implemented using [crate::Reporter] to avoid introducing complexity
    /// into any particular consensus implementation.
    pub trait Monitor: Clone + Send + 'static {
        /// Index is the type used to indicate the in-progress consensus decision.
        type Index;

        /// Create a channel that will receive updates when the latest index (also provided) changes.
        fn subscribe(
            &mut self,
        ) -> impl Future<Output = (Self::Index, mpsc::Receiver<Self::Index>)> + Send;
    }
});
stability_scope!(ALPHA {
    pub mod aggregation;
    pub mod ordered_broadcast;
});
stability_scope!(ALPHA, cfg(not(target_arch = "wasm32")) {
    use crate::marshal::ancestry::Ancestry;
    use commonware_cryptography::certificate::Scheme;
    use commonware_runtime::{Clock, Metrics, Spawner};
    use rand_core::Rng;

    /// Application is a minimal interface for standard implementations that operate over a stream
    /// of epoched blocks.
    pub trait Application<E>: Clone + Send + 'static
    where
        E: Rng + Spawner + Metrics + Clock,
    {
        /// The signing scheme used by the application.
        type SigningScheme: Scheme;

        /// Context is metadata provided by the consensus engine associated with a given payload.
        ///
        /// This often includes things like the proposer, view number, the height, or the epoch.
        type Context: Epochable;

        /// The block type produced by the application's builder.
        type Block: Block;

        /// Build a new block on top of the provided parent ancestry. If the build job fails,
        /// or the proposer's slot should be skipped, the implementor should return [None].
        ///
        /// This future may be cancelled before it completes. Implementations must be
        /// cancellation-safe.
        fn propose(
            &mut self,
            context: (E, Self::Context),
            ancestry: impl Ancestry<Self::Block>,
        ) -> impl Future<Output = Option<Self::Block>> + Send;

        /// Verify a block produced by the application's proposer, relative to its ancestry.
        ///
        /// This future should not resolve until the implementation can produce a stable verdict.
        /// Return `false` only when the block is permanently invalid for the supplied context and
        /// ancestry. If validity may still change as additional information becomes available,
        /// continue waiting instead of returning `false`.
        ///
        /// In other words, to abstain from voting, do not resolve this future yet. Keep it
        /// pending until the implementation can either prove the block valid, prove it invalid,
        /// or the consensus engine cancels the request. Abstaining is not represented by a
        /// special return value.
        ///
        /// This future may be cancelled before it completes. Implementations must be
        /// cancellation-safe.
        fn verify(
            &mut self,
            context: (E, Self::Context),
            ancestry: impl Ancestry<Self::Block>,
        ) -> impl Future<Output = bool> + Send;
    }
});
