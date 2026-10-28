use super::{
    elector,
    types::{Activity, Context, Finalization},
};
use crate::{
    CertifiableAutomaton, Epochable, Relay, Reporter, Viewable,
    types::{Epoch, View, ViewDelta},
};
use commonware_cryptography::{Digest, certificate::Scheme};
use commonware_p2p::Blocker;
use commonware_parallel::Strategy;
use commonware_runtime::buffer::paged::CacheRef;
use rand_core::CryptoRng;
use std::{
    num::{NonZeroU64, NonZeroUsize},
    time::Duration,
};

/// Selects the maximum number of unfinalized terms that may be skipped.
#[derive(Debug, Clone, Copy, Default)]
pub enum SkipBudget {
    /// Uses the participant count as the budget.
    #[default]
    Participants,
    /// Uses the specified budget.
    Fixed(NonZeroU64),
}

impl SkipBudget {
    /// Resolves the configured budget for a participant count.
    pub(crate) const fn resolve(self, participants: usize) -> u64 {
        match self {
            Self::Participants => participants as u64,
            Self::Fixed(budget) => budget.get(),
        }
    }
}

/// Controls whether `nullify(v)` may be broadcast before the normal round deadlines.
///
/// Normal round deadlines remain active when the policy does not permit a skip.
#[derive(Debug, Clone, Copy)]
pub enum SkipPolicy {
    /// Disables skips.
    Disabled,
    /// Enables skips under the configured timeout and budget.
    Enabled {
        /// Duration after which an inactive leader may trigger a skip.
        ///
        /// This timeout must be greater than the certification timeout and timeout retry.
        timeout: Duration,
        /// Maximum number of unfinalized terms that may be skipped.
        budget: SkipBudget,
    },
}

/// Controls whether and how the engine proactively forwards blocks when
/// entering the next view.
///
/// Forwarding is a best-effort liveness aid. When enabled, the batcher
/// broadcasts on entering the next view for a proposal that is finalized, or
/// notarized without a failed certification. Targets are chosen from votes observed
/// locally, so a certificate signer whose vote never reached us still counts
/// as silent.
#[derive(Debug, Clone, Copy)]
pub enum ForwardPolicy {
    /// Do nothing when a proposal becomes eligible for forwarding.
    Disabled,
    /// Forward the block to all participants whose matching vote was not
    /// observed locally.
    ///
    /// To only send to the leader of the newly entered view, see [ForwardPolicy::SilentLeader].
    SilentVoters,
    /// Forward the block to the leader of the newly entered view if the
    /// leader's matching vote was not observed locally.
    ///
    /// To forward to all such participants, see [ForwardPolicy::SilentVoters].
    SilentLeader,
}

impl ForwardPolicy {
    /// Returns true if the policy is enabled.
    pub const fn is_enabled(&self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

/// The certified root from which a Simplex instance starts.
///
/// The floor must be durable and must never move backwards across restarts:
/// the voter prunes its durable vote journal relative to the floor, so
/// restarting with an earlier floor can re-enter views whose vote records
/// were already discarded (risking equivocation). Derive the floor from
/// application state that is persisted before the engine starts.
#[derive(Clone, Debug)]
pub enum Floor<S: Scheme, D: Digest> {
    /// Start from the epoch genesis payload at view 0.
    Genesis(D),
    /// Start from an already-finalized proposal.
    Finalized(Finalization<S, D>),
}

impl<S: Scheme, D: Digest> Floor<S, D> {
    /// The finalized view the engine starts from (`View::zero()` for genesis).
    pub(crate) fn view(&self) -> View {
        match self {
            Self::Genesis(_) => View::zero(),
            Self::Finalized(finalization) => finalization.view(),
        }
    }

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
    L: elector::Config<S>,
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
    ///
    /// Schemes must provide deterministic signatures (a participant must produce the same
    /// signature encoding every time it signs the same subject) because Simplex compares
    /// encoded votes when detecting equivocation.
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
    /// Activity is exported for every tracked view, including votes that arrive up to
    /// `view_retention` views below the highest finalized view; votes below that window
    /// are dropped without being reported. Reported votes are not guaranteed to be
    /// verified (see [`crate::simplex::types::Activity`]). Consider wrapping with
    /// [`crate::simplex::scheme::reporter::AttributableReporter`] to automatically filter
    /// and verify activities based on scheme attributability.
    ///
    /// Locally constructed votes are exported only after their journal entries are
    /// durable. Network votes are not persisted, so an equivocating sender may have
    /// different votes exported before and after a restart.
    pub reporter: F,

    /// Track individual votes after certification.
    ///
    /// By default, full vote evidence is released when the corresponding certificate
    /// is constructed or received, making later conflict reporting and peer blocking
    /// best effort. Enabling this retains each recorded vote until its round is
    /// pruned, increasing memory usage.
    pub track_historical_votes: bool,

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
    ///
    /// This timeout must be greater than the leader timeout.
    pub certification_timeout: Duration,

    /// Amount of time to wait before retrying a nullify broadcast if
    /// stuck in a view.
    pub timeout_retry: Duration,

    /// Number of views behind the finalized tip to track (in memory and in the
    /// journal) for recent activity.
    pub view_retention: ViewDelta,

    /// Policy governing whether `nullify(v)` may be broadcast before the normal round deadlines.
    pub skip: SkipPolicy,

    /// Timeout to wait for a peer to respond to a request.
    pub fetch_timeout: Duration,

    /// Policy for proactively forwarding blocks when entering the next view.
    pub forward: ForwardPolicy,
}

impl<
    S: Scheme,
    L: elector::Config<S>,
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

        // Vote-to-nullify timeouts.
        // certification_timeout > leader_timeout > 0.
        // skip timeout > certification_timeout and timeout_retry, when enabled.
        assert!(
            self.leader_timeout > Duration::default(),
            "leader timeout must be greater than zero"
        );
        assert!(
            self.certification_timeout > self.leader_timeout,
            "certification timeout must be greater than leader timeout"
        );

        if let SkipPolicy::Enabled { timeout, .. } = self.skip {
            assert!(
                timeout > self.certification_timeout,
                "skip timeout must be greater than certification timeout"
            );
            assert!(
                timeout > self.timeout_retry,
                "skip timeout must be greater than timeout retry"
            );
        }
        assert!(
            self.timeout_retry > Duration::default(),
            "timeout retry broadcast must be greater than zero"
        );
        assert!(
            !self.view_retention.is_zero(),
            "view retention timeout must be greater than zero"
        );
        assert!(
            self.fetch_timeout > Duration::default(),
            "fetch timeout must be greater than zero"
        );
        self.floor
            .assert(self.epoch, rng, &self.scheme, &self.strategy);
    }
}

#[cfg(test)]
mod tests {
    use super::SkipBudget;
    use std::num::NonZeroU64;

    #[test]
    fn skip_budget_resolves() {
        assert_eq!(SkipBudget::default().resolve(4), 4);
        assert_eq!(SkipBudget::Participants.resolve(7), 7);
        assert_eq!(SkipBudget::Fixed(NonZeroU64::new(9).unwrap()).resolve(4), 9);
    }
}
