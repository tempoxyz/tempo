use super::{
    elector::Config as Elector,
    types::{Activity, Context, Finalization},
};
use crate::{
    types::{Epoch, ViewDelta},
    CertifiableAutomaton, Epochable, Relay, Reporter, Viewable,
};
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_p2p::Blocker;
use commonware_parallel::Strategy;
use commonware_runtime::buffer::paged::CacheRef;
use rand_core::CryptoRng;
use std::{num::NonZeroUsize, time::Duration};

/// Controls whether and how the engine proactively forwards certified blocks
/// when entering the next view.
///
/// Forwarding is a best-effort liveness aid: when enabled, the batcher
/// broadcasts only after we locally certify a proposal and enter the next
/// view, avoiding sends for proposals that never pass certification.
#[derive(Debug, Clone, Copy)]
pub enum ForwardingPolicy {
    /// Do nothing when a certified proposal becomes eligible for forwarding.
    Disabled,
    /// Forward the block to all participants that did not vote for the proposal.
    ///
    /// To only send to the leader of the newly entered view, see [ForwardingPolicy::SilentLeader].
    SilentVoters,
    /// Forward the block to the leader of the newly entered view if they did not
    /// vote for the proposal.
    ///
    /// To forward to all participants that did not vote for the proposal, see [ForwardingPolicy::SilentVoters].
    SilentLeader,
}

impl ForwardingPolicy {
    /// Returns true if the policy is enabled.
    pub const fn is_enabled(&self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

/// The certified root from which a Simplex instance starts.
#[derive(Clone, Debug)]
pub enum Floor<S: Scheme, D: Digest> {
    /// Start from the epoch genesis payload at view 0.
    Genesis(D),
    /// Start from an already-finalized proposal.
    Finalized(Finalization<S, D>),
}

impl<S: Scheme, D: Digest> Floor<S, D> {
    fn assert<Rng>(&self, epoch: Epoch, rng: &mut Rng, scheme: &S, strategy: &impl Strategy)
    where
        Rng: CryptoRng,
        S: super::scheme::Scheme<D>,
    {
        if let Self::Finalized(finalization) = self {
            assert_eq!(
                finalization.epoch(),
                epoch,
                "floor finalization must be in the configured epoch"
            );
            assert!(
                !finalization.view().is_zero(),
                "use Floor::Genesis for the genesis view"
            );
            assert!(
                finalization.verify(rng, scheme, strategy),
                "floor finalization must verify"
            );
        }
    }
}

/// Configuration for the consensus engine.
pub struct Config<S, L, B, D, A, R, F, T>
where
    S: Scheme,
    L: Elector<S>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    A: CertifiableAutomaton<Context = Context<D, S::PublicKey>>,
    R: Relay,
    F: Reporter<Activity = Activity<S, D>>,
    T: Strategy,
{
    /// Signing scheme for the consensus engine.
    ///
    /// Consensus messages can be signed with a cryptosystem that differs from the static
    /// participant identity keys exposed in `participants`. For example, we can authenticate peers
    /// on the network with [commonware_cryptography::ed25519] keys while signing votes with shares distributed
    /// via [commonware_cryptography::bls12381::dkg] (which change each epoch). The scheme implementation is
    /// responsible for reusing the exact participant ordering carried by `participants` so that signer indices
    /// remain stable across both key spaces; if the order diverges, validators will reject votes as coming from
    /// the wrong validator.
    pub scheme: S,

    /// Leader election configuration.
    ///
    /// Determines how leaders are selected for each view. Built-in options include
    /// [`RoundRobin`](super::elector::RoundRobin) for deterministic rotation and
    /// [`Random`](super::elector::Random) for unpredictable selection using BLS
    /// threshold signatures.
    pub elector: L,

    /// Blocker for the network.
    ///
    /// Blocking is handled by [commonware_p2p].
    pub blocker: B,

    /// Automaton for the consensus engine.
    pub automaton: A,

    /// Relay for the consensus engine.
    pub relay: R,

    /// Reporter for the consensus engine.
    ///
    /// All activity is exported for downstream applications that benefit from total observability,
    /// consider wrapping with [`crate::simplex::scheme::reporter::AttributableReporter`] to
    /// automatically filter and verify activities based on scheme attributability.
    pub reporter: F,

    /// Strategy for parallel operations.
    pub strategy: T,

    /// Partition for the consensus engine.
    pub partition: String,

    /// Maximum number of messages to buffer on channels inside the consensus
    /// engine before blocking.
    pub mailbox_size: NonZeroUsize,

    /// Epoch for the consensus engine. Each running engine should have a unique epoch.
    pub epoch: Epoch,

    /// Certified root for the consensus engine.
    pub floor: Floor<S, D>,

    /// Number of bytes to buffer when replaying during startup.
    pub replay_buffer: NonZeroUsize,

    /// The size of the write buffer to use for each blob in the journal.
    pub write_buffer: NonZeroUsize,

    /// Page cache for the journal.
    pub page_cache: CacheRef,

    /// Amount of time to wait for a leader to propose a payload
    /// in a view.
    pub leader_timeout: Duration,

    /// Amount of time to wait for certification progress in a view
    /// before attempting to skip the view.
    pub certification_timeout: Duration,

    /// Amount of time to wait before retrying a nullify broadcast if
    /// stuck in a view.
    pub timeout_retry: Duration,

    /// Number of views behind finalized tip to track
    /// and persist activity derived from validator messages.
    pub activity_timeout: ViewDelta,

    /// Move to nullify immediately if the selected leader has been inactive
    /// for this many recent known views (we ignore views we don't have data for).
    ///
    /// This number should be less than or equal to `activity_timeout` (how
    /// many views we are tracking below the finalized tip).
    pub skip_timeout: ViewDelta,

    /// Timeout to wait for a peer to respond to a request.
    pub fetch_timeout: Duration,

    /// Number of concurrent requests to make at once.
    pub fetch_concurrent: NonZeroUsize,

    /// Policy for proactively forwarding certified blocks when entering the
    /// next view.
    pub forwarding: ForwardingPolicy,
}

impl<
        S: Scheme,
        L: Elector<S>,
        B: Blocker<PublicKey = S::PublicKey>,
        D: Digest,
        A: CertifiableAutomaton<Context = Context<D, S::PublicKey>>,
        R: Relay,
        F: Reporter<Activity = Activity<S, D>>,
        T: Strategy,
    > Config<S, L, B, D, A, R, F, T>
{
    /// Assert enforces that all configuration values are valid.
    ///
    /// The RNG is used to verify finalized floor certificates.
    pub fn assert<Rng>(&self, rng: &mut Rng)
    where
        Rng: CryptoRng,
        S: super::scheme::Scheme<D>,
    {
        assert!(
            !self.scheme.participants().is_empty(),
            "there must be at least one participant"
        );
        assert!(
            self.leader_timeout > Duration::default(),
            "leader timeout must be greater than zero"
        );
        assert!(
            self.certification_timeout > Duration::default(),
            "certification timeout must be greater than zero"
        );
        assert!(
            self.leader_timeout <= self.certification_timeout,
            "leader timeout must be less than or equal to certification timeout"
        );
        assert!(
            self.timeout_retry > Duration::default(),
            "timeout retry broadcast must be greater than zero"
        );
        assert!(
            !self.activity_timeout.is_zero(),
            "activity timeout must be greater than zero"
        );
        assert!(
            !self.skip_timeout.is_zero(),
            "skip timeout must be greater than zero"
        );
        assert!(
            self.skip_timeout <= self.activity_timeout,
            "skip timeout must be less than or equal to activity timeout"
        );
        assert!(
            self.fetch_timeout > Duration::default(),
            "fetch timeout must be greater than zero"
        );
        self.floor
            .assert(self.epoch, rng, &self.scheme, &self.strategy);
    }
}
