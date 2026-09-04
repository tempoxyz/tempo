//! Simple and fast BFT agreement inspired by Simplex Consensus.
//!
//! Inspired by [Simplex Consensus](https://eprint.iacr.org/2023/463), `simplex` provides simple and fast BFT
//! agreement with network-speed view (i.e. block time) latency and optimal finalization latency in a
//! partially synchronous setting.
//!
//! # Features
//!
//! * Wicked Fast Block Times (2 Network Hops)
//! * Optimal Finalization Latency (3 Network Hops)
//! * Externalized Uptime and Fault Proofs
//! * Require Certification Before Finalization
//! * Decoupled Block Broadcast and Sync
//! * Lazy Message Verification
//! * Application-Defined Block Format
//! * Pluggable Hashing and Cryptography
//! * Embedded VRF (via [scheme::bls12381_threshold::vrf])
//!
//! # Design
//!
//! ## Protocol Description
//!
//! ### Genesis
//!
//! Genesis (view 0) is implicitly finalized. There is no finalization certificate for genesis;
//! [`Config::floor`](config::Config::floor) supplies the initial finalized state. Voting begins
//! at view 1, with the first proposal referencing genesis as its parent.
//!
//! ### Specification for View `v`
//!
//! Upon entering view `v`:
//! * Determine leader `l` for view `v`
//! * Set timer for leader proposal `t_l = 2Δ` and advance `t_a = 3Δ`
//!     * If leader `l` has not been active in last `r` views, set `t_l` to 0.
//! * If leader `l`, broadcast `notarize(c,v)`
//!   * If can't propose container in view `v` because missing notarization/nullification for a
//!     previous view `v_m`, request `v_m`
//!
//! Upon receiving first `notarize(c,v)` from `l`:
//! * Cancel `t_l`
//! * If the container's parent `c_parent` is finalized (or both notarized and certified) at `v_parent`
//!   and we have nullifications for all views between `v` and `v_parent`, verify `c` and broadcast `notarize(c,v)`
//!     * If verification of `c` fails, immediately broadcast `nullify(v)`
//!
//! Upon receiving `2f+1` `notarize(c,v)`:
//! * Cancel `t_a`
//! * Mark `c` as notarized
//! * Broadcast `notarization(c,v)` (even if we have not verified `c`)
//! * Attempt to certify `c` (see [Certification](#certification))
//!     * On success: broadcast `finalize(c,v)` (if have not broadcast `nullify(v)`) and enter `v+1`
//!     * On failure: broadcast `nullify(v)`
//!
//! Upon receiving `2f+1` `nullify(v)`:
//! * Broadcast `nullification(v)`
//! * Enter `v+1`
//!
//! Upon receiving `2f+1` `finalize(c,v)`:
//! * Mark `c` as finalized (and recursively finalize its parents)
//! * Broadcast `finalization(c,v)` (even if we have not verified `c`)
//!
//! Upon `t_l` or `t_a` firing:
//! * Broadcast `nullify(v)`
//! * Every `t_r` after `nullify(v)` broadcast that we are still in view `v`:
//!    * Rebroadcast `nullify(v)` and either `notarization(v-1)` or `nullification(v-1)`
//!
//! _When `2f+1` votes of a given type (`notarize(c,v)`, `nullify(v)`, or `finalize(c,v)`) have been have been collected
//! from unique participants, a certificate (`notarization(c,v)`, `nullification(v)`, or `finalization(c,v)`) can be assembled.
//! These certificates serve as a standalone proof of consensus progress that downstream systems can ingest without executing
//! the protocol._
//!
//! ### Joining Consensus
//!
//! As soon as `2f+1` nullifies or finalizes are observed for some view `v`, the `Voter` will
//! enter `v+1`. Notarizations advance the view if-and-only-if the application certifies them.
//! This means that a new participant joining consensus will immediately jump ahead on the previous
//! view's nullification or finalization and begin participating in consensus at the current view.
//!
//! ### Certification
//!
//! After a payload is notarized, the application can optionally delay or prevent finalization via the
//! [`CertifiableAutomaton::certify`](crate::CertifiableAutomaton::certify) method. By default, `certify`
//! returns `true` for all payloads, meaning finalization proceeds immediately after notarization.
//!
//! Customizing `certify` is useful for systems that employ erasure coding, where participants may want
//! to wait until they have received enough shards to reconstruct and validate the full block before
//! voting to finalize.
//!
//! If `certify` returns `true`, the participant broadcasts a `finalize` vote for the payload and enters the
//! next view. If `certify` returns `false`, the participant broadcasts `nullify` for the view instead (treating
//! it as an immediate timeout), and will refuse to build upon the proposal or notarize proposals that build upon it.
//! Thus, a payload can only be finalized if a quorum of participants certify it.
//!
//! Certification of some notarization should only be abandoned once a finalization at the same or higher view is observed.
//! Until then (say a nullification certificate for a view arrives before certification completes), the application should continue
//! attempting to complete certification. This increases the likelihood that we can vote on the next honest proposer's block (which
//! may build on our in-flight certification or the nullification). If we did not do this, it is possible that different parts of
//! the network (neither with quorum) would refuse to vote on each other's blocks (halting consensus).
//!
//! _The decision returned by `certify` must be deterministic and consistent across all honest participants to ensure
//! liveness._
//!
//! ### Deviations from Simplex Consensus
//!
//! * Fetch missing notarizations/nullifications as needed rather than assuming each proposal contains
//!   a set of all notarizations/nullifications for all historical blocks.
//! * Introduce distinct messages for `notarize` and `nullify` rather than referring to both as a `vote` for
//!   either a "block" or a "dummy block", respectively.
//! * Introduce a "leader timeout" to trigger early view transitions for unresponsive leaders.
//! * Skip "leader timeout" and "certification timeout" if a designated leader hasn't participated in
//!   some number of views (again to trigger early view transition for an unresponsive leader).
//! * Introduce message rebroadcast to continue making progress if messages from a given view are dropped (only way
//!   to ensure messages are reliably delivered is with a heavyweight reliable broadcast protocol).
//! * Treat local proposal failure as immediate timeout expiry and broadcast `nullify(v)`.
//! * Treat local verification failure as immediate timeout expiry and broadcast `nullify(v)`.
//! * Consider the current leader's `nullify(v)` as immediate timeout expiry and broadcast `nullify(v)`.
//! * Upon seeing `notarization(c,v)`, instead of moving to the view `v+1` immediately, request certification from
//!   the application (see [Certification](#certification)). Only move to view `v+1` and broadcast `finalize(c,v)`
//!   if certification succeeds, otherwise broadcast `nullify(v)` and refuse to build upon `c`.
//!
//! ## Protocol Properties
//!
//! ### Forced Inclusion (Tail-Forking Resistance)
//!
//! A notarized payload in view `v` must appear in the canonical chain if no nullification
//! certificate exists for `v`. This follows directly from the protocol rules:
//!
//! 1. To propose in view `v+k`, the leader must reference a certified parent in some view `v_p`
//!    and possess nullification certificates for every view between `v_p` and `v+k`.
//! 2. A nullification certificate for view `v` requires `2f+1` `nullify(v)` votes.
//! 3. An honest participant only broadcasts `nullify(v)` when a timeout fires (`t_l` or `t_a`)
//!    or when certification fails.
//!
//! Therefore, if view `v` completes without timeout and certification succeeds, no honest
//! participant has broadcast `nullify(v)`. With at most `f` Byzantine participants, at most `f`
//! `nullify(v)` votes exist, which is insufficient to form a nullification certificate. Without
//! that certificate, no future leader can skip view `v`, and the notarized payload must be
//! included as an ancestor in all subsequent proposals.
//!
//! ### Optimistic Finality
//!
//! The forced inclusion property provides a weaker but faster form of finality: once a
//! notarization certificate is observed for view `v` (without any timeout having fired),
//! the notarized payload can be treated as speculatively final. No future sequence of
//! proposals can exclude it from the canonical chain.
//!
//! This "speculative finality" is available after just 2 network hops (proposal + notarization),
//! compared to the 3 hops required for full finalization (proposal + notarization + finalization).
//! A notarized-but-not-yet-finalized payload can only be excluded in two scenarios:
//! `f+1` or more honest participants timed out, or certification failed. Because
//! certification is deterministic, it either fails for all honest participants or none,
//! so a certification failure always produces a nullification. In the common case
//! (no faults, no timeouts), exclusion cannot happen.
//!
//! ### Unchained Finalization
//!
//! Finalization does not require consecutive honest views. When a participant certifies
//! `notarization(c,v)`, it broadcasts `finalize(c,v)` and immediately enters `v+1`,
//! regardless of what happens in subsequent views. These `finalize(c,v)` votes accumulate
//! independently of the current view: even if views `v+1` through `v+k` all time out
//! (producing nullifications), the `finalize(c,v)` votes still count toward the `2f+1`
//! threshold needed to form `finalization(c,v)`.
//!
//! This means a payload notarized in view `v` can be finalized while the network is
//! in view `v+k` for any `k >= 1`. There is no requirement that a particular view
//! after `v` succeeds or that any subsequent leader cooperates. As long as `2f+1`
//! participants eventually certify and broadcast `finalize(c,v)`, the finalization
//! certificate will form.
//!
//! ## Architecture
//!
//! All logic is split into four components: the `Batcher`, the `Voter`, the `Resolver`, and the `Application` (provided by the user).
//! The `Batcher` is responsible for collecting messages from peers and lazily verifying them when a quorum is met. The `Voter`
//! is responsible for directing participation in the current view. The `Resolver` is responsible for
//! fetching artifacts from previous views required to verify proposed blocks in the latest view. Lastly, the `Application`
//! is responsible for proposing new blocks and indicating whether some block is valid.
//!
//! To drive great performance, all interactions between `Batcher`, `Voter`, `Resolver`, and `Application` are
//! non-blocking. This means that, for example, the `Voter` can continue processing messages while the
//! `Application` verifies a proposed block or the `Resolver` fetches a notarization.
//!
//! ```txt
//!                            +------------+          +++++++++++++++
//!                            |            +--------->+             +
//!                            |  Batcher   |          +    Peers    +
//!                            |            |<---------+             +
//!                            +-------+----+          +++++++++++++++
//!                                |   ^
//!                                |   |
//!                                |   |
//!                                |   |
//!                                v   |
//! +---------------+           +---------+            +++++++++++++++
//! |               |<----------+         +----------->+             +
//! |  Application  |           |  Voter  |            +    Peers    +
//! |               +---------->|         |<-----------+             +
//! +---------------+           +--+------+            +++++++++++++++
//!                                |   ^
//!                                |   |
//!                                |   |
//!                                |   |
//!                                v   |
//!                            +-------+----+          +++++++++++++++
//!                            |            +--------->+             +
//!                            |  Resolver  |          +    Peers    +
//!                            |            |<---------+             +
//!                            +------------+          +++++++++++++++
//! ```
//!
//! ### Batched Verification
//!
//! Unlike other consensus constructions that verify all incoming messages received from peers, for schemes
//! where [`Verifier::is_batchable()`](commonware_cryptography::certificate::Verifier::is_batchable) returns `true`
//! (such as [scheme::ed25519], [scheme::bls12381_multisig] and [scheme::bls12381_threshold]), `simplex` lazily
//! verifies messages (only when a quorum is met), enabling efficient batch verification. For schemes where
//! `is_batchable()` returns `false` (such as [scheme::secp256r1]), signatures are verified eagerly as they
//! arrive since there is no batching benefit.
//!
//! If an invalid signature is detected, the `Batcher` will perform repeated bisections over collected
//! messages to find the offending message (and block the peer(s) that sent it via [commonware_p2p::Blocker]).
//!
//! _If using a p2p implementation that is not authenticated, it is not safe to employ this optimization
//! as any attacking peer could simply reconnect from a different address. We recommend [commonware_p2p::authenticated]._
//!
//! ### Fetching Missing Certificates
//!
//! Instead of trying to fetch all possible certificates above the floor, we only attempt to fetch
//! nullifications for all views from the floor (last certified notarization or finalization) to the current view.
//! This technique, however, is not sufficient to guarantee progress.
//!
//! Consider the case where `f` honest participants have seen a finalization for a given view `v` (and nullifications only
//! from `v` to the current view `c`) but the remaining `f+1` honest participants have not (they have exclusively seen
//! nullifications from some view `o < v` to `c`). Neither partition of participants will vote for the other's proposals.
//!
//! To ensure progress is eventually made, leaders with nullified proposals directly broadcast the best finalization
//! certificate they are aware of to ensure all honest participants eventually consider the same proposal ancestry valid.
//!
//! _While a more aggressive recovery mechanism could be employed, like requiring all participants to broadcast their highest
//! finalization certificate after nullification, it would impose significant overhead under normal network
//! conditions (whereas the approach described incurs no overhead under normal network conditions). Recall, honest participants
//! already broadcast observed certificates to all other participants in each view (and misaligned participants should only ever
//! be observed following severe network degradation)._
//!
//! ## Pluggable Hashing and Cryptography
//!
//! Hashing is abstracted via the [commonware_cryptography::Hasher] trait and cryptography is abstracted via
//! the [commonware_cryptography::certificate::Scheme] trait, allowing deployments to employ approaches that best match their
//! requirements (or to provide their own without modifying any consensus logic). The following schemes
//! are supported out-of-the-box:
//!
//! ### [scheme::ed25519]
//!
//! [commonware_cryptography::ed25519] signatures are ["High-speed high-security signatures"](https://eprint.iacr.org/2011/368)
//! with 32 byte public keys and 64 byte signatures. While they are well-supported by commercial HSMs and offer efficient batch
//! verification, the signatures are not aggregatable (and certificates grow linearly with the quorum size).
//!
//! ### [scheme::bls12381_multisig]
//!
//! [commonware_cryptography::bls12381] is a ["digital signature scheme with aggregation properties"](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.txt).
//! Unlike [commonware_cryptography::ed25519], signatures from multiple participants (say the signers in a certificate) can be aggregated
//! into a single signature (reducing bandwidth usage per broadcast). That being said, [commonware_cryptography::bls12381] is much slower
//! to verify than [commonware_cryptography::ed25519] and isn't supported by most HSMs (a standardization effort expired in 2022).
//!
//! ### [scheme::secp256r1]
//!
//! [commonware_cryptography::secp256r1] signatures use the NIST P-256 elliptic curve (also known as prime256v1), which is widely
//! supported by commercial HSMs and hardware security modules. Unlike [commonware_cryptography::ed25519], Secp256r1 does not
//! benefit from batch verification, so signatures are verified individually. Certificates grow linearly with quorum size
//! (similar to ed25519).
//!
//! ### [scheme::bls12381_threshold]
//!
//! [scheme::bls12381_threshold] employs threshold cryptography (BLS12-381 threshold signatures with a `2f+1` of `3f+1` quorum)
//! to generate succinct consensus certificates (verifiable with just the static public key). This scheme requires instantiating
//! the shared secret via [commonware_cryptography::bls12381::dkg] and resharing whenever participants change.
//!
//! Two (non-attributable) variants are provided:
//!
//! - [scheme::bls12381_threshold::standard]: Certificates contain only a vote signature.
//!
//! - [scheme::bls12381_threshold::vrf]: Certificates contain a vote signature and a view signature (i.e. a seed that can be used
//!   as a VRF). This variant can be configured for random leader election (via [elector::Random]) and/or incorporate this randomness
//!   into execution.
//!
//! #### Embedded VRF ([scheme::bls12381_threshold::vrf])
//!
//! Every `notarize(c,v)` or `nullify(v)` message includes an `attestation(v)` (a partial signature over the view `v`). After `2f+1`
//! `notarize(c,v)` or `nullify(v)` messages are collected from unique participants, `seed(v)` can be recovered. Because `attestation(v)` is
//! only over the view `v`, the seed derived for a given view `v` is the same regardless of whether or not a block was notarized in said
//! view `v`.
//!
//! Because the value of `seed(v)` cannot be known prior to message broadcast by any participant (including the leader) in view `v`
//! and cannot be manipulated by any participant (deterministic for any `2f+1` signers at a given view `v`), it can be used both as a beacon
//! for leader election (where `seed(v)` determines the leader for `v+1`) and a source of randomness in execution (where `seed(v)`
//! is used as a seed in `v`).
//!
//! #### Succinct Certificates
//!
//! All broadcast consensus messages (`notarize(c,v)`, `nullify(v)`, `finalize(c,v)`) contain attestations (partial signatures) for a static
//! public key (derived from a group polynomial that can be recomputed during reconfiguration using [dkg](commonware_cryptography::bls12381::dkg)).
//! As soon as `2f+1` messages are collected, a threshold signature over `notarization(c,v)`, `nullification(v)`, and `finalization(c,v)`
//! can be recovered, respectively. Because the public key is static, any of these certificates can be verified by an external
//! process without following the consensus instance and/or tracking the current set of participants (as is typically required
//! to operate a lite client).
//!
//! These threshold signatures over `notarization(c,v)`, `nullification(v)`, and `finalization(c,v)` (i.e. the consensus certificates)
//! can be used to secure interoperability between different consensus instances and user interactions with an infrastructure provider
//! (where any data served can be proven to derive from some finalized block of some consensus instance with a known static public key).
//!
//! ## Persistence
//!
//! The `Voter` caches all data required to participate in consensus to avoid any disk reads on
//! on the critical path. To enable recovery, the `Voter` writes valid messages it receives from
//! consensus and messages it generates to a write-ahead log (WAL) implemented by [commonware_storage::journal::segmented::variable::Journal].
//! Before sending a message, any pending `Journal` appends are synced to prevent inadvertent Byzantine
//! behavior on restart (especially in the case of unclean shutdown). All appends made in the same event
//! loop iteration are coalesced into a single sync that runs after messages are constructed and before
//! any are broadcast (even if there is nothing to broadcast). The proposal payload relay is not a
//! consensus message and is not gated on this sync: to lower view latency, it is requested as soon
//! as the automaton returns a payload, which is safe because extra payload bytes (unlike votes)
//! cannot form a conflicting certificate (see [`Plan::Propose`]).
//!
//! ## Automaton Failure Semantics
//!
//! If a validator is the leader for a view but cannot build a valid payload yet (for example because
//! it is still syncing), it should decline the [`Automaton::propose`](crate::Automaton::propose)
//! request by dropping the response channel. Simplex treats this as a missing proposal, broadcasts
//! `nullify(v)`, and other validators can use the leader-nullify fast path to skip the view.
//!
//! Once `propose` returns a payload, the local proposer is committed to that payload for verification
//! and certification. [`Automaton::verify`](crate::Automaton::verify) and
//! [`CertifiableAutomaton::certify`](crate::CertifiableAutomaton::certify) are stable verdict APIs,
//! not backpressure or syncing signals. While missing data may still arrive (and/or a validator cannot
//! immediately determine if a payload is valid), implementations should keep these requests pending rather
//! than returning `false` or closing the channel.
//!
//! Returning `false` from `verify` means the proposal is permanently invalid and causes a local
//! nullify. Returning `false` from `certify` means the notarized payload is permanently
//! uncertifiable for that round and also causes a local nullify. Closing `certify` does not provide
//! a fast-skip signal and can halt progress because certification requests are not retried during
//! the same run. The safe way to stop working on certification is to keep the request pending until
//! Simplex drops it after finalizing the block or a descendant.

pub mod elector;
pub mod scheme;
pub mod types;

cfg_if::cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
        use crate::types::{Round, View, ViewDelta};
        use commonware_cryptography::PublicKey;
        use commonware_p2p::Recipients;

        mod actors;
        pub mod config;
        pub use config::{Config, Floor, ForwardingPolicy};
        mod engine;
        pub use engine::Engine;
        mod metrics;

        /// The minimum view we are tracking both in-memory and on-disk.
        pub(crate) const fn min_active(activity_timeout: ViewDelta, last_finalized: View) -> View {
            last_finalized.saturating_sub(activity_timeout)
        }

        /// Whether or not a view is interesting to us. This is a function
        /// of both `min_active` and whether or not the view is too far
        /// in the future (based on the view we are currently in).
        pub(crate) fn interesting(
            activity_timeout: ViewDelta,
            last_finalized: View,
            current: View,
            pending: View,
            allow_future: bool,
        ) -> bool {
            // If the view is genesis, skip it, genesis doesn't have votes
            if pending.is_zero() {
                return false;
            }
            if pending < min_active(activity_timeout, last_finalized) {
                return false;
            }
            if !allow_future && pending > current.next() {
                return false;
            }
            true
        }

        /// Describes how a payload should be broadcast to the network.
        pub enum Plan<P: PublicKey> {
            /// Initial broadcast of a newly proposed block to all participants.
            ///
            /// Requested before the proposer's notarize vote is durable: a
            /// proposer that crashes and restarts may emit this plan again
            /// with a different payload for the same round. Consumers must
            /// tolerate multiple candidates per round (at most one is ever
            /// referenced by the proposer's signed votes).
            Propose {
                /// The round in which the block was proposed.
                round: Round,
            },
            /// Forward a block to a specific set of peers.
            ///
            /// Requested only for a proposal already backed by a certificate.
            /// Forwarding is best-effort help for lagging peers and advertises
            /// nothing about the sender's own state, so it needs no durability
            /// ordering.
            Forward {
                /// The round in which the forwarded block was proposed.
                round: Round,
                /// The recipients to forward the block to.
                recipients: Recipients<P>,
            },
        }
    }
}

#[cfg(any(test, feature = "mocks"))]
pub mod mocks;

/// Convenience alias for [`N3f1::quorum`].
#[cfg(test)]
pub(crate) fn quorum(n: u32) -> u32 {
    use commonware_utils::{Faults, N3f1};

    N3f1::quorum(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{
            elector::{Config as Elector, Elector as ElectorTrait, Random, RoundRobin},
            mocks::{
                scheme as scheme_mocks,
                twins::{self, Elector as TwinsElector},
                wrapped,
            },
            scheme::{
                bls12381_multisig,
                bls12381_threshold::{
                    standard as bls12381_threshold_std,
                    vrf::{self as bls12381_threshold_vrf, Seedable},
                },
                ed25519, secp256r1, Scheme,
            },
            types::{
                Certificate, Finalization as TFinalization, Finalize as TFinalize,
                Notarization as TNotarization, Notarize as TNotarize,
                Nullification as TNullification, Nullify as TNullify, Proposal, Vote,
            },
        },
        types::{Epoch, Participant, Round},
        Monitor, Viewable,
    };
    use commonware_codec::{Decode, DecodeExt, Encode};
    use commonware_cryptography::{
        bls12381::primitives::variant::{MinPk, MinSig, Variant},
        certificate::mocks::Fixture,
        ed25519::{PrivateKey, PublicKey},
        sha256::{Digest as Sha256Digest, Digest as D},
        Hasher as _, Sha256, Signer as _,
    };
    use commonware_macros::{select, test_group, test_traced};
    use commonware_p2p::{
        simulated::{Config, Link, Network, Oracle, Receiver, Sender, SplitOrigin},
        utils::mocks::inert_channel,
        Manager as _, Recipients, Sender as _, TrackedPeers,
    };
    use commonware_parallel::{Sequential, Strategy};
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, telemetry::metrics::count_running_tasks, Clock,
        IoBuf, Metrics as _, Quota, Runner, Spawner, Strategizer as _, Supervisor as _,
    };
    use commonware_utils::{
        ordered::Set, sync::Mutex, test_rng, Faults, N3f1, NZUsize, TestRng, NZU16,
    };
    use engine::Engine;
    use futures::future::join_all;
    use rand::{rngs::StdRng, RngExt as _, SeedableRng};
    use rand_core::CryptoRng;
    use std::{
        collections::{BTreeMap, HashMap, HashSet},
        num::{NonZeroU16, NonZeroU32, NonZeroUsize},
        sync::Arc,
        time::Duration,
    };
    use tracing::{debug, info, warn};
    use types::Activity;

    // Invoke `$cb!($($args)*, $suffix, $elector, $fixture)` once per canonical
    // (elector, scheme) fixture.
    macro_rules! for_each_fixture {
        ($cb:ident!($($args:tt)*)) => {
            $cb!($($args)*, bls12381_threshold_vrf_min_pk, Random, bls12381_threshold_vrf::fixture::<MinPk, _>);
            $cb!($($args)*, bls12381_threshold_vrf_min_sig, Random, bls12381_threshold_vrf::fixture::<MinSig, _>);
            $cb!($($args)*, bls12381_threshold_std_min_pk, RoundRobin, bls12381_threshold_std::fixture::<MinPk, _>);
            $cb!($($args)*, bls12381_threshold_std_min_sig, RoundRobin, bls12381_threshold_std::fixture::<MinSig, _>);
            $cb!($($args)*, bls12381_multisig_min_pk, RoundRobin, bls12381_multisig::fixture::<MinPk, _>);
            $cb!($($args)*, bls12381_multisig_min_sig, RoundRobin, bls12381_multisig::fixture::<MinSig, _>);
            $cb!($($args)*, ed25519, RoundRobin, ed25519::fixture);
            $cb!($($args)*, secp256r1, RoundRobin, secp256r1::fixture);
        };
    }

    // Generate one `#[test_group("slow")] #[test_traced]` test per canonical
    // (elector, scheme) fixture, named `test_<callee>_<suffix>`. The helper takes
    // the elector as its third generic parameter.
    //
    // Supported forms:
    //   test_for_all_fixtures!(callee);                  // callee::<_, _, Elector>(fixture)
    //   test_for_all_fixtures!(callee, arg);             // callee::<_, _, Elector, _>(fixture, arg)
    //   test_for_all_fixtures!(callee, arg, level = "INFO"); // arg with a trace-level override
    //   test_for_all_fixtures!(callee, seeds = N);       // loops callee::<_, _, Elector>(seed, fixture)
    //   test_for_all_fixtures!(callee, level = "INFO");  // overrides the trace level
    macro_rules! test_for_all_fixtures {
        ($callee:ident) => {
            for_each_fixture!(test_for_all_fixtures!(@emit [test_traced] $callee [] []));
        };
        ($callee:ident, level = $level:literal) => {
            for_each_fixture!(test_for_all_fixtures!(@emit [test_traced($level)] $callee [] []));
        };
        ($callee:ident, seeds = $n:expr) => {
            for_each_fixture!(test_for_all_fixtures!(@seeded $n, $callee));
        };
        ($callee:ident, $arg:expr, level = $level:literal) => {
            for_each_fixture!(test_for_all_fixtures!(@emit [test_traced($level)] $callee [, _] [, $arg]));
        };
        ($callee:ident, $arg:expr) => {
            for_each_fixture!(test_for_all_fixtures!(@emit [test_traced] $callee [, _] [, $arg]));
        };
        (@emit [$traced:meta] $callee:ident [$($generics:tt)*] [$($args:tt)*], $suffix:ident, $elector:ty, $fixture:expr) => {
            paste::paste! {
                #[test_group("slow")]
                #[$traced]
                fn [<test_ $callee _ $suffix>]() {
                    $callee::<_, _, $elector $($generics)*>($fixture $($args)*);
                }
            }
        };
        (@seeded $n:expr, $callee:ident, $suffix:ident, $elector:ty, $fixture:expr) => {
            paste::paste! {
                #[test_group("slow")]
                #[test_traced]
                fn [<test_ $callee _ $suffix>]() {
                    for seed in 0..$n {
                        $callee::<_, _, $elector>(seed, $fixture);
                    }
                }
            }
        };
    }

    const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
    const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

    #[test]
    fn test_interesting() {
        let activity_timeout = ViewDelta::new(10);

        // Genesis view is never interesting
        assert!(!interesting(
            activity_timeout,
            View::zero(),
            View::zero(),
            View::zero(),
            false
        ));
        assert!(!interesting(
            activity_timeout,
            View::zero(),
            View::new(1),
            View::zero(),
            true
        ));

        // View below min_active is not interesting
        assert!(!interesting(
            activity_timeout,
            View::new(20),
            View::new(25),
            View::new(5), // below min_active (10)
            false
        ));

        // View at min_active boundary is interesting
        assert!(interesting(
            activity_timeout,
            View::new(20),
            View::new(25),
            View::new(10), // exactly min_active
            false
        ));

        // Future view beyond current.next() is not interesting when allow_future is false
        assert!(!interesting(
            activity_timeout,
            View::new(20),
            View::new(25),
            View::new(27),
            false
        ));

        // Future view beyond current.next() is interesting when allow_future is true
        assert!(interesting(
            activity_timeout,
            View::new(20),
            View::new(25),
            View::new(27),
            true
        ));

        // View at current.next() is interesting
        assert!(interesting(
            activity_timeout,
            View::new(20),
            View::new(25),
            View::new(26),
            false
        ));

        // View within valid range is interesting
        assert!(interesting(
            activity_timeout,
            View::new(20),
            View::new(25),
            View::new(22),
            false
        ));

        // When last_finalized is 0 and activity_timeout would underflow
        // min_active saturates at 0, so view 1 should still be interesting
        assert!(interesting(
            activity_timeout,
            View::zero(),
            View::new(5),
            View::new(1),
            false
        ));
    }

    /// Register a validator with the oracle.
    async fn register_validator(
        oracle: &mut Oracle<PublicKey, deterministic::Context>,
        validator: PublicKey,
    ) -> (
        (
            Sender<PublicKey, deterministic::Context>,
            Receiver<PublicKey>,
        ),
        (
            Sender<PublicKey, deterministic::Context>,
            Receiver<PublicKey>,
        ),
        (
            Sender<PublicKey, deterministic::Context>,
            Receiver<PublicKey>,
        ),
    ) {
        let control = oracle.control(validator.clone());
        let (vote_sender, vote_receiver) = control.register(0, TEST_QUOTA).await.unwrap();
        let (certificate_sender, certificate_receiver) =
            control.register(1, TEST_QUOTA).await.unwrap();
        let (resolver_sender, resolver_receiver) = control.register(2, TEST_QUOTA).await.unwrap();
        (
            (vote_sender, vote_receiver),
            (certificate_sender, certificate_receiver),
            (resolver_sender, resolver_receiver),
        )
    }

    /// Registers all validators using the oracle.
    async fn register_validators(
        oracle: &mut Oracle<PublicKey, deterministic::Context>,
        validators: &[PublicKey],
    ) -> HashMap<
        PublicKey,
        (
            (
                Sender<PublicKey, deterministic::Context>,
                Receiver<PublicKey>,
            ),
            (
                Sender<PublicKey, deterministic::Context>,
                Receiver<PublicKey>,
            ),
            (
                Sender<PublicKey, deterministic::Context>,
                Receiver<PublicKey>,
            ),
        ),
    > {
        let mut registrations = HashMap::new();
        for validator in validators.iter() {
            let registration = register_validator(oracle, validator.clone()).await;
            registrations.insert(validator.clone(), registration);
        }
        registrations
    }

    async fn start_test_network_with_peers<I>(
        context: deterministic::Context,
        peers: I,
        disconnect_on_block: bool,
    ) -> Oracle<PublicKey, deterministic::Context>
    where
        I: IntoIterator<Item = PublicKey>,
    {
        let (network, oracle) = Network::new_with_peers(
            context.child("network"),
            Config {
                max_size: 1024 * 1024,
                disconnect_on_block,
                tracked_peer_sets: NZUsize!(1),
            },
            peers,
        )
        .await;
        network.start();
        oracle
    }

    async fn start_test_network_with_split_peers<I, J>(
        context: deterministic::Context,
        primary: I,
        secondary: J,
        disconnect_on_block: bool,
    ) -> Oracle<PublicKey, deterministic::Context>
    where
        I: IntoIterator<Item = PublicKey>,
        J: IntoIterator<Item = PublicKey>,
    {
        let (network, oracle) = Network::new_with_split_peers(
            context.child("network"),
            Config {
                max_size: 1024 * 1024,
                disconnect_on_block,
                tracked_peer_sets: NZUsize!(1),
            },
            primary,
            secondary,
        )
        .await;
        network.start();
        oracle
    }

    /// Enum to describe the action to take when linking validators.
    enum Action {
        Link(Link),
        Update(Link), // Unlink and then link
        Unlink,
    }

    /// Links (or unlinks) validators using the oracle.
    ///
    /// The `action` parameter determines the action (e.g. link, unlink) to take.
    /// The `restrict_to` function can be used to restrict the linking to certain connections,
    /// otherwise all validators will be linked to all other validators.
    async fn link_validators(
        oracle: &mut Oracle<PublicKey, deterministic::Context>,
        validators: &[PublicKey],
        action: Action,
        restrict_to: Option<fn(usize, usize, usize) -> bool>,
    ) {
        for (i1, v1) in validators.iter().enumerate() {
            for (i2, v2) in validators.iter().enumerate() {
                // Ignore self
                if v2 == v1 {
                    continue;
                }

                // Restrict to certain connections
                if let Some(f) = restrict_to {
                    if !f(validators.len(), i1, i2) {
                        continue;
                    }
                }

                // Do any unlinking first
                match action {
                    Action::Update(_) | Action::Unlink => {
                        oracle.remove_link(v1.clone(), v2.clone()).await.unwrap();
                    }
                    _ => {}
                }

                // Do any linking after
                match action {
                    Action::Link(ref link) | Action::Update(ref link) => {
                        oracle
                            .add_link(v1.clone(), v2.clone(), link.clone())
                            .await
                            .unwrap();
                    }
                    _ => {}
                }
            }
        }
    }

    /// Counts lines where all patterns match and the trailing value is non-zero.
    fn count_nonzero_metric_lines(encoded: &str, patterns: &[&str]) -> u32 {
        encoded
            .lines()
            .filter(|line| patterns.iter().all(|p| line.contains(p)))
            .filter(|line| {
                line.split_whitespace()
                    .last()
                    .and_then(|s| s.parse::<u64>().ok())
                    .is_some_and(|n| n > 0)
            })
            .count() as u32
    }

    fn all_online<S, F, L, T>(
        mut fixture: F,
        strategy: impl FnOnce(&mut deterministic::Context) -> T + Send + 'static,
    ) where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
        T: Strategy,
    {
        // Create context
        let n = 5;
        let quorum = quorum(n) as usize;
        let required_containers = View::new(100);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(300));
        executor.start(|mut context| async move {
            // Register participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let strategy = strategy(&mut context);
            let mut oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &participants, Action::Link(link), None).await;

            // Create engines
            let elector = L::default();
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context
                    .child("validator")
                    .with_attribute("public_key", validator);

                // Configure engine
                let reporter_config = mocks::reporter::Config {
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
                reporters.push(reporter.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    me: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                    certify_latency: (10.0, 5.0),
                    should_certify: mocks::application::Certifier::Always,
                };
                let (actor, application) = mocks::application::Application::new(
                    context.child("application"),
                    application_cfg,
                );
                actor.start();
                let blocker = oracle.control(validator.clone());
                let cfg = config::Config {
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    strategy: strategy.clone(),
                    partition: validator.to_string(),
                    mailbox_size: NZUsize!(1024),
                    epoch: Epoch::new(333),
                    floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(
                        Epoch::new(333),
                    )),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_concurrent: NZUsize!(4),
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                    forwarding: ForwardingPolicy::Disabled,
                };
                let engine = Engine::new(context.child("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(pending, recovered, resolver));
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.child("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.recv().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check reporters for correct activity
            let latest_complete = required_containers.saturating_sub(activity_timeout);
            for reporter in reporters.iter() {
                // Ensure no faults
                reporter.assert_no_faults();

                // Ensure no invalid signatures
                reporter.assert_no_invalid();

                // Ensure certificates for all views
                {
                    let certified = reporter.certified.lock();
                    for view in View::range(View::new(1), latest_complete) {
                        // Ensure certificate for every view
                        if !certified.contains(&view) {
                            panic!("view: {view}");
                        }
                    }
                }

                // Ensure no forks
                let mut notarized = HashMap::new();
                let mut finalized = HashMap::new();
                {
                    let notarizes = reporter.notarizes.lock();
                    for view in View::range(View::new(1), latest_complete) {
                        // Ensure only one payload proposed per view
                        let Some(payloads) = notarizes.get(&view) else {
                            continue;
                        };
                        if payloads.len() > 1 {
                            panic!("view: {view}");
                        }
                        let (digest, notarizers) = payloads.iter().next().unwrap();
                        notarized.insert(view, *digest);

                        if notarizers.len() < quorum {
                            // We can't verify that everyone participated at every view because some nodes may
                            // have started later.
                            panic!("view: {view}");
                        }
                    }
                }
                {
                    let notarizations = reporter.notarizations.lock();
                    for view in View::range(View::new(1), latest_complete) {
                        // Ensure notarization matches digest from notarizes
                        let Some(notarization) = notarizations.get(&view) else {
                            continue;
                        };
                        let Some(digest) = notarized.get(&view) else {
                            continue;
                        };
                        assert_eq!(&notarization.proposal.payload, digest);
                    }
                }
                {
                    let finalizes = reporter.finalizes.lock();
                    for view in View::range(View::new(1), latest_complete) {
                        // Ensure only one payload proposed per view
                        let Some(payloads) = finalizes.get(&view) else {
                            continue;
                        };
                        if payloads.len() > 1 {
                            panic!("view: {view}");
                        }
                        let (digest, finalizers) = payloads.iter().next().unwrap();
                        finalized.insert(view, *digest);

                        // Only check at views below timeout
                        if view > latest_complete {
                            continue;
                        }

                        // Ensure everyone participating
                        if finalizers.len() < quorum {
                            // We can't verify that everyone participated at every view because some nodes may
                            // have started later.
                            panic!("view: {view}");
                        }

                        // Ensure no nullifies for any finalizers
                        let nullifies = reporter.nullifies.lock();
                        let Some(nullifies) = nullifies.get(&view) else {
                            continue;
                        };
                        for finalizers in payloads.values() {
                            for finalizer in finalizers.iter() {
                                if nullifies.contains(finalizer) {
                                    panic!("should not nullify and finalize at same view");
                                }
                            }
                        }
                    }
                }
                {
                    let finalizations = reporter.finalizations.lock();
                    for view in View::range(View::new(1), latest_complete) {
                        // Ensure finalization matches digest from finalizes
                        let Some(finalization) = finalizations.get(&view) else {
                            continue;
                        };
                        let Some(digest) = finalized.get(&view) else {
                            continue;
                        };
                        assert_eq!(&finalization.proposal.payload, digest);
                    }
                }
            }

            // Ensure no blocked connections
            let blocked = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty());
        });
    }

    test_for_all_fixtures!(all_online, |_| Sequential);

    #[test_group("slow")]
    #[test_traced]
    fn test_all_online_rayon_bls12381_threshold_vrf_min_pk() {
        all_online::<_, _, Random, _>(bls12381_threshold_vrf::fixture::<MinPk, _>, |context| {
            context.strategy(NZUsize!(2))
        });
    }

    fn non_genesis_floor_joiner_catches_tip<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        // First let a quorum finalize beyond genesis so the joiner has a real
        // floor certificate and existing tip to catch.
        let n = 5;
        let active_count = quorum(n) as usize;
        let initial_tip_target = View::new(15);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(300));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let mut oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            let active = &participants[..active_count];
            let joiner_idx = active_count;
            let joiner = participants[joiner_idx].clone();

            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, active, Action::Link(link.clone()), None).await;

            let elector = L::default();
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();

            for (idx, validator) in active.iter().enumerate() {
                let validator_context = context
                    .child("validator")
                    .with_attribute("public_key", validator);

                let reporter_config = mocks::reporter::Config {
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                };
                let reporter = mocks::reporter::Reporter::new(
                    validator_context.child("reporter"),
                    reporter_config,
                );
                reporters.push(reporter.clone());

                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    me: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                    certify_latency: (10.0, 5.0),
                    should_certify: mocks::application::Certifier::Always,
                };
                let (actor, application) = mocks::application::Application::new(
                    validator_context.child("application"),
                    application_cfg,
                );
                actor.start();

                let cfg = config::Config {
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                    blocker: oracle.control(validator.clone()),
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    strategy: Sequential,
                    partition: format!("joiner_catches_tip_{validator}"),
                    mailbox_size: NZUsize!(1024),
                    epoch: Epoch::new(333),
                    floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(
                        Epoch::new(333),
                    )),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_concurrent: NZUsize!(4),
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    page_cache: CacheRef::from_pooler(
                        &validator_context,
                        PAGE_SIZE,
                        PAGE_CACHE_SIZE,
                    ),
                    forwarding: ForwardingPolicy::Disabled,
                };
                let engine = Engine::new(validator_context.child("engine"), cfg);
                let (pending, recovered, resolver) =
                    register_validator(&mut oracle, validator.clone()).await;
                engine_handlers.push(engine.start(pending, recovered, resolver));
            }

            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(
                    context
                        .child("initial_finalizer")
                        .spawn(move |_| async move {
                            while latest < initial_tip_target {
                                latest = monitor.recv().await.expect("event missing");
                            }
                            latest
                        }),
                );
            }
            let tip_at_join = join_all(finalizers)
                .await
                .into_iter()
                .map(|result| result.expect("initial finalizer failed"))
                .min()
                .expect("initial validators missing");

            let (floor_view, floor_finalization) = {
                let finalizations = reporters[0].finalizations.lock();
                finalizations
                    .iter()
                    .filter(|(view, _)| **view > View::zero() && **view < tip_at_join)
                    .min_by_key(|(view, _)| view.get())
                    .map(|(view, finalization)| (*view, finalization.clone()))
                    .expect("non-genesis floor finalization missing")
            };
            assert!(floor_view > View::zero());
            assert!(floor_view < tip_at_join);

            // Start the extra validator from the non-genesis floor and require
            // it to catch both the existing tip and later cluster progress.
            for validator in active.iter() {
                oracle
                    .add_link(joiner.clone(), validator.clone(), link.clone())
                    .await
                    .unwrap();
                oracle
                    .add_link(validator.clone(), joiner.clone(), link.clone())
                    .await
                    .unwrap();
            }

            let joiner_context = context
                .child("validator")
                .with_attribute("public_key", &joiner);
            let reporter_config = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[joiner_idx].clone(),
                elector: elector.clone(),
            };
            let mut joiner_reporter =
                mocks::reporter::Reporter::new(joiner_context.child("reporter"), reporter_config);
            reporters.push(joiner_reporter.clone());

            let application_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: joiner.clone(),
                propose_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                certify_latency: (10.0, 5.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (actor, application) = mocks::application::Application::new(
                joiner_context.child("application"),
                application_cfg,
            );
            actor.start();

            let cfg = config::Config {
                scheme: schemes[joiner_idx].clone(),
                elector,
                blocker: oracle.control(joiner.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: joiner_reporter.clone(),
                strategy: Sequential,
                partition: format!("joiner_catches_tip_{joiner}"),
                mailbox_size: NZUsize!(1024),
                epoch: Epoch::new(333),
                floor: config::Floor::Finalized(floor_finalization),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout,
                skip_timeout,
                fetch_concurrent: NZUsize!(4),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&joiner_context, PAGE_SIZE, PAGE_CACHE_SIZE),
                forwarding: ForwardingPolicy::Disabled,
            };
            let engine = Engine::new(joiner_context.child("engine"), cfg);
            let (pending, recovered, resolver) = register_validator(&mut oracle, joiner).await;
            engine_handlers.push(engine.start(pending, recovered, resolver));

            let (mut joiner_latest, mut joiner_monitor) = joiner_reporter.subscribe().await;
            while joiner_latest < tip_at_join {
                joiner_latest = joiner_monitor.recv().await.expect("event missing");
            }

            let post_join_target = tip_at_join.saturating_add(ViewDelta::new(5));
            while joiner_latest < post_join_target {
                joiner_latest = joiner_monitor.recv().await.expect("event missing");
            }

            for reporter in reporters.iter() {
                reporter.assert_no_faults();
                reporter.assert_no_invalid();
            }

            let blocked = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty());
        });
    }

    test_for_all_fixtures!(non_genesis_floor_joiner_catches_tip);

    /// A dishonest leader (validator 0) proposes payloads that all honest peers
    /// refuse to certify.
    ///
    /// All n validators use the honest Application, but every peer's certifier
    /// rejects proposals from views where validator 0 is the elected leader.
    /// When validator 0 IS the leader, it short-circuits certification locally
    /// (it built the proposal) and votes finalize, but every other peer
    /// rejects via the Custom predicate and nullifies. The lone finalize vote
    /// cannot form a certificate (quorum=4). The nullification cert (4 honest
    /// peers) advances everyone.
    ///
    /// When an honest validator leads, all peers (including validator 0)
    /// certify normally and finalize. The cluster makes progress on honest
    /// leader views and nullifies dishonest leader views.
    fn dishonest_leader_certification_rejected<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        RoundRobin: Elector<S>,
    {
        let n = 5;
        let required_containers = View::new(50);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(300));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let mut oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;
            let mut registrations = register_validators(&mut oracle, &participants).await;

            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &participants, Action::Link(link), None).await;

            let elector = RoundRobin::default();
            let participants_set: Set<S::PublicKey> = participants.clone().try_into().unwrap();
            let built_elector = elector.clone().build(&participants_set);
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            let dishonest = Participant::new(0);
            for (idx, validator) in participants.iter().enumerate() {
                let context = context
                    .child("validator")
                    .with_attribute("public_key", validator);
                let reporter_config = mocks::reporter::Config {
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
                reporters.push(reporter.clone());

                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    me: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                    certify_latency: (10.0, 5.0),
                    should_certify: mocks::application::Certifier::Custom(Box::new({
                        let built_elector_clone = built_elector.clone();
                        move |round, _| built_elector_clone.elect(round, None) != dishonest
                    })),
                };
                let (actor, application) = mocks::application::Application::new(
                    context.child("application"),
                    application_cfg,
                );
                actor.start();

                let blocker = oracle.control(validator.clone());
                let cfg = config::Config {
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    strategy: Sequential,
                    partition: validator.to_string(),
                    mailbox_size: NZUsize!(1024),
                    epoch: Epoch::new(333),
                    floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(
                        Epoch::new(333),
                    )),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_concurrent: NZUsize!(4),
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                    forwarding: ForwardingPolicy::Disabled,
                };
                let engine = Engine::new(context.child("engine"), cfg);
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(pending, recovered, resolver));
            }

            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.child("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.recv().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            for reporter in reporters.iter() {
                reporter.assert_no_faults();
                reporter.assert_no_invalid();
            }
        });
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_dishonest_leader_certification_rejected() {
        dishonest_leader_certification_rejected::<_, _>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        dishonest_leader_certification_rejected::<_, _>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        dishonest_leader_certification_rejected::<_, _>(
            bls12381_threshold_std::fixture::<MinPk, _>,
        );
        dishonest_leader_certification_rejected::<_, _>(
            bls12381_threshold_std::fixture::<MinSig, _>,
        );
        dishonest_leader_certification_rejected::<_, _>(bls12381_multisig::fixture::<MinPk, _>);
        dishonest_leader_certification_rejected::<_, _>(bls12381_multisig::fixture::<MinSig, _>);
        dishonest_leader_certification_rejected::<_, _>(ed25519::fixture);
        dishonest_leader_certification_rejected::<_, _>(secp256r1::fixture);
    }

    fn observer<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        // Create context
        let n_active = 5;
        let required_containers = View::new(100);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(300));
        executor.start(|mut context| async move {
            // Register participants (active)
            let Fixture {
                participants,
                schemes,
                verifier,
                ..
            } = fixture(&mut context, &namespace, n_active);

            // Add observer (no share)
            let private_key_observer = PrivateKey::from_seed(n_active as u64);
            let public_key_observer = private_key_observer.public_key();

            let mut oracle = start_test_network_with_split_peers(
                context.child("network"),
                participants.clone(),
                [public_key_observer.clone()],
                true,
            )
            .await;

            // Register all (including observer) with the network
            let mut all_validators = participants.clone();
            all_validators.push(public_key_observer.clone());
            all_validators.sort();
            let mut registrations = register_validators(&mut oracle, &all_validators).await;

            // Link all peers (including observer)
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &all_validators, Action::Link(link), None).await;

            // Create engines
            let elector = L::default();
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();

            for (idx, validator) in participants.iter().enumerate() {
                let is_observer = *validator == public_key_observer;

                // Create scheme context
                let context = context
                    .child("validator")
                    .with_attribute("public_key", validator);

                // Configure engine
                let signing = if is_observer {
                    verifier.clone()
                } else {
                    schemes[idx].clone()
                };
                let reporter_config = mocks::reporter::Config {
                    participants: participants.clone().try_into().unwrap(),
                    scheme: signing.clone(),
                    elector: elector.clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
                reporters.push(reporter.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    me: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                    certify_latency: (10.0, 5.0),
                    should_certify: mocks::application::Certifier::Always,
                };
                let (actor, application) = mocks::application::Application::new(
                    context.child("application"),
                    application_cfg,
                );
                actor.start();
                let blocker = oracle.control(validator.clone());
                let cfg = config::Config {
                    scheme: signing.clone(),
                    elector: elector.clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    strategy: Sequential,
                    partition: validator.to_string(),
                    mailbox_size: NZUsize!(1024),
                    epoch: Epoch::new(333),
                    floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(
                        Epoch::new(333),
                    )),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_concurrent: NZUsize!(4),
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                    forwarding: ForwardingPolicy::Disabled,
                };
                let engine = Engine::new(context.child("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                engine.start(pending, recovered, resolver);
            }

            // Wait for all  engines to finish
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.child("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.recv().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Sanity check. The standalone secondary observer should still
            // process the chain to the same progress threshold as validators.
            for reporter in reporters.iter() {
                // Ensure no faults or invalid signatures
                reporter.assert_no_faults();
                reporter.assert_no_invalid();

                // Ensure no blocked connections
                let blocked = oracle.blocked().await.unwrap();
                assert!(blocked.is_empty());
            }
        });
    }

    test_for_all_fixtures!(observer);

    fn unclean_shutdown<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        // Create context
        let n = 5;
        let required_containers = View::new(100);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();

        // Random restarts every x seconds
        let shutdowns: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
        let supervised = Arc::new(Mutex::new(Vec::new()));
        let mut prev_checkpoint = None;

        // Create validator keys
        let mut rng = test_rng();
        let Fixture {
            participants,
            schemes,
            ..
        } = fixture(&mut rng, &namespace, n);
        let reporter_seed: [u8; 32] = rng.random();

        // Create block relay, shared across restarts.
        let relay = Arc::new(mocks::relay::Relay::<Sha256Digest, S::PublicKey>::new());

        loop {
            let participants = participants.clone();
            let schemes = schemes.clone();
            let shutdowns = shutdowns.clone();
            let supervised = supervised.clone();
            let relay = relay.clone();
            relay.deregister_all(); // Clear all recipients from previous restart.

            let f = |mut context: deterministic::Context| async move {
                // Register participants
                let mut oracle = start_test_network_with_peers(
                    context.child("network"),
                    participants.clone(),
                    true,
                )
                .await;
                let mut registrations = register_validators(&mut oracle, &participants).await;

                // Link all validators
                let link = Link {
                    latency: Duration::from_millis(50),
                    jitter: Duration::from_millis(50),
                    success_rate: 1.0,
                };
                link_validators(&mut oracle, &participants, Action::Link(link), None).await;

                // Create engines
                let elector = L::default();
                let relay = Arc::new(mocks::relay::Relay::new());
                let mut reporters = HashMap::new();
                let mut engine_handlers = Vec::new();
                for (idx, validator) in participants.iter().enumerate() {
                    // Create scheme context
                    let context = context
                        .child("validator")
                        .with_attribute("public_key", validator);

                    // Configure engine
                    let reporter_config = mocks::reporter::Config {
                        participants: participants.clone().try_into().unwrap(),
                        scheme: schemes[idx].clone(),
                        elector: elector.clone(),
                    };
                    let reporter_rng = StdRng::from_seed(reporter_seed);
                    let reporter = mocks::reporter::Reporter::new(reporter_rng, reporter_config);
                    reporters.insert(validator.clone(), reporter.clone());
                    let application_cfg = mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        me: validator.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                        certify_latency: (10.0, 5.0),
                        should_certify: mocks::application::Certifier::Always,
                    };
                    let (actor, application) = mocks::application::Application::new(
                        context.child("application"),
                        application_cfg,
                    );
                    actor.start();
                    let blocker = oracle.control(validator.clone());
                    let cfg = config::Config {
                        scheme: schemes[idx].clone(),
                        elector: elector.clone(),
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: reporter.clone(),
                        strategy: Sequential,
                        partition: validator.to_string(),
                        mailbox_size: NZUsize!(1024),
                        epoch: Epoch::new(333),
                        floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(
                            Epoch::new(333),
                        )),
                        leader_timeout: Duration::from_secs(1),
                        certification_timeout: Duration::from_secs(2),
                        timeout_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        skip_timeout,
                        fetch_concurrent: NZUsize!(4),
                        replay_buffer: NZUsize!(1024 * 1024),
                        write_buffer: NZUsize!(1024 * 1024),
                        page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                        forwarding: ForwardingPolicy::Disabled,
                    };
                    let engine = Engine::new(context.child("engine"), cfg);

                    // Start engine
                    let (pending, recovered, resolver) = registrations
                        .remove(validator)
                        .expect("validator should be registered");
                    engine_handlers.push(engine.start(pending, recovered, resolver));
                }

                // Store all finalizer handles
                let mut finalizers = Vec::new();
                for reporter in reporters.values_mut() {
                    let (mut latest, mut monitor) = reporter.subscribe().await;
                    finalizers.push(context.child("finalizer").spawn(move |_| async move {
                        while latest < required_containers {
                            latest = monitor.recv().await.expect("event missing");
                        }
                    }));
                }

                // Exit at random points for unclean shutdown of entire set
                let wait =
                    context.random_range(Duration::from_millis(100)..Duration::from_millis(2_000));
                let result = select! {
                    _ = context.sleep(wait) => {
                        // Collect reporters to check faults
                        {
                            let mut shutdowns = shutdowns.lock();
                            debug!(shutdowns = *shutdowns, elapsed = ?wait, "restarting");
                            *shutdowns += 1;
                        }
                        supervised.lock().push(reporters);
                        false
                    },
                    _ = join_all(finalizers) => {
                        // Check reporters for faults activity
                        let supervised = supervised.lock();
                        for reporters in supervised.iter() {
                            for reporter in reporters.values() {
                                reporter.assert_no_faults();
                            }
                        }
                        true
                    },
                };

                // Ensure no blocked connections
                let blocked = oracle.blocked().await.unwrap();
                assert!(blocked.is_empty());

                result
            };

            let (complete, checkpoint) = prev_checkpoint
                .map_or_else(
                    || deterministic::Runner::timed(Duration::from_secs(180)),
                    deterministic::Runner::from,
                )
                .start_and_recover(f);

            // Check if we should exit
            if complete {
                break;
            }

            prev_checkpoint = Some(checkpoint);
        }
    }

    test_for_all_fixtures!(unclean_shutdown);

    fn backfill<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        // Create context
        let n = 4;
        let required_containers = View::new(100);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(240));
        executor.start(|mut context| async move {
            // Register participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let mut oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // Link all validators except first
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(
                &mut oracle,
                &participants,
                Action::Link(link),
                Some(|_, i, j| ![i, j].contains(&0usize)),
            )
            .await;

            // Create engines
            let elector = L::default();
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx_scheme, validator) in participants.iter().enumerate() {
                // Skip first peer
                if idx_scheme == 0 {
                    continue;
                }

                // Create scheme context
                let context = context
                    .child("validator")
                    .with_attribute("public_key", validator);

                // Configure engine
                let reporter_config = mocks::reporter::Config {
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx_scheme].clone(),
                    elector: elector.clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
                reporters.push(reporter.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    me: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                    certify_latency: (10.0, 5.0),
                    should_certify: mocks::application::Certifier::Always,
                };
                let (actor, application) = mocks::application::Application::new(
                    context.child("application"),
                    application_cfg,
                );
                actor.start();
                let blocker = oracle.control(validator.clone());
                let cfg = config::Config {
                    scheme: schemes[idx_scheme].clone(),
                    elector: elector.clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    strategy: Sequential,
                    partition: validator.to_string(),
                    mailbox_size: NZUsize!(1024),
                    epoch: Epoch::new(333),
                    floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(
                        Epoch::new(333),
                    )),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_concurrent: NZUsize!(4),
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                    forwarding: ForwardingPolicy::Disabled,
                };
                let engine = Engine::new(context.child("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(pending, recovered, resolver));
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.child("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.recv().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Degrade network connections for online peers
            let link = Link {
                latency: Duration::from_secs(3),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            link_validators(
                &mut oracle,
                &participants,
                Action::Update(link.clone()),
                Some(|_, i, j| ![i, j].contains(&0usize)),
            )
            .await;

            // Wait for nullifications to accrue
            context.sleep(Duration::from_secs(60)).await;

            // Unlink second peer from all (except first)
            link_validators(
                &mut oracle,
                &participants,
                Action::Unlink,
                Some(|_, i, j| [i, j].contains(&1usize) && ![i, j].contains(&0usize)),
            )
            .await;

            // Configure engine for first peer
            let me = participants[0].clone();
            let context = context.child("validator").with_attribute("public_key", &me);

            // Link first peer to all (except second)
            link_validators(
                &mut oracle,
                &participants,
                Action::Link(link),
                Some(|_, i, j| [i, j].contains(&0usize) && ![i, j].contains(&1usize)),
            )
            .await;

            // Restore network connections for all online peers
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(3),
                success_rate: 1.0,
            };
            link_validators(
                &mut oracle,
                &participants,
                Action::Update(link),
                Some(|_, i, j| ![i, j].contains(&1usize)),
            )
            .await;

            // Configure engine
            let reporter_config = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            };
            let mut reporter =
                mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
            reporters.push(reporter.clone());
            let application_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                certify_latency: (10.0, 5.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (actor, application) =
                mocks::application::Application::new(context.child("application"), application_cfg);
            actor.start();
            let blocker = oracle.control(me.clone());
            let cfg = config::Config {
                scheme: schemes[0].clone(),
                elector: elector.clone(),
                blocker,
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                strategy: Sequential,
                partition: me.to_string(),
                mailbox_size: NZUsize!(1024),
                epoch: Epoch::new(333),
                floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(Epoch::new(
                    333,
                ))),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout,
                skip_timeout,
                fetch_concurrent: NZUsize!(4),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                forwarding: ForwardingPolicy::Disabled,
            };
            let engine = Engine::new(context.child("engine"), cfg);

            // Start engine
            let (pending, recovered, resolver) = registrations
                .remove(&me)
                .expect("validator should be registered");
            engine_handlers.push(engine.start(pending, recovered, resolver));

            // Wait for new engine to finalize required
            let (mut latest, mut monitor) = reporter.subscribe().await;
            while latest < required_containers {
                latest = monitor.recv().await.expect("event missing");
            }

            // Ensure no blocked connections
            let blocked = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty());
        });
    }

    test_for_all_fixtures!(backfill);

    fn one_offline<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        // Create context
        let n = 5;
        let quorum = quorum(n) as usize;
        let required_containers = View::new(100);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let max_exceptions = 10;
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(300));
        executor.start(|mut context| async move {
            // Register participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let mut oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // Link all validators except first
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(
                &mut oracle,
                &participants,
                Action::Link(link),
                Some(|_, i, j| ![i, j].contains(&0usize)),
            )
            .await;

            // Create engines
            let elector = L::default();
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx_scheme, validator) in participants.iter().enumerate() {
                // Skip first peer
                if idx_scheme == 0 {
                    continue;
                }

                // Create scheme context
                let context = context
                    .child("validator")
                    .with_attribute("public_key", validator);

                // Configure engine
                let reporter_config = mocks::reporter::Config {
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx_scheme].clone(),
                    elector: elector.clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
                reporters.push(reporter.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    me: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                    certify_latency: (10.0, 5.0),
                    should_certify: mocks::application::Certifier::Always,
                };
                let (actor, application) = mocks::application::Application::new(
                    context.child("application"),
                    application_cfg,
                );
                actor.start();
                let blocker = oracle.control(validator.clone());
                let cfg = config::Config {
                    scheme: schemes[idx_scheme].clone(),
                    elector: elector.clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    strategy: Sequential,
                    partition: validator.to_string(),
                    mailbox_size: NZUsize!(1024),
                    epoch: Epoch::new(333),
                    floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(
                        Epoch::new(333),
                    )),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_concurrent: NZUsize!(4),
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                    forwarding: ForwardingPolicy::Disabled,
                };
                let engine = Engine::new(context.child("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(pending, recovered, resolver));
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.child("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.recv().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check reporters for correct activity
            let exceptions = 0;
            let offline = &participants[0];
            for reporter in reporters.iter() {
                // Ensure no faults
                reporter.assert_no_faults();

                // Ensure no invalid signatures
                reporter.assert_no_invalid();

                // Ensure offline node is never active
                let mut exceptions = 0;
                {
                    let notarizes = reporter.notarizes.lock();
                    for (view, payloads) in notarizes.iter() {
                        for participants in payloads.values() {
                            if participants.contains(offline) {
                                panic!("view: {view}");
                            }
                        }
                    }
                }
                {
                    let nullifies = reporter.nullifies.lock();
                    for (view, participants) in nullifies.iter() {
                        if participants.contains(offline) {
                            panic!("view: {view}");
                        }
                    }
                }
                {
                    let finalizes = reporter.finalizes.lock();
                    for (view, payloads) in finalizes.iter() {
                        for finalizers in payloads.values() {
                            if finalizers.contains(offline) {
                                panic!("view: {view}");
                            }
                        }
                    }
                }

                // Identify offline views
                let mut offline_views = Vec::new();
                {
                    let leaders = reporter.leaders.lock();
                    for (view, leader) in leaders.iter() {
                        if leader == offline {
                            offline_views.push(*view);
                        }
                    }
                }
                assert!(!offline_views.is_empty());

                // Ensure nullifies/nullification collected for offline node
                {
                    let nullifies = reporter.nullifies.lock();
                    for view in offline_views.iter() {
                        let nullifies = nullifies.get(view).map_or(0, |n| n.len());
                        if nullifies < quorum {
                            warn!("missing expected view nullifies: {}", view);
                            exceptions += 1;
                        }
                    }
                }
                {
                    let nullifications = reporter.nullifications.lock();
                    for view in offline_views.iter() {
                        if !nullifications.contains_key(view) {
                            warn!("missing expected view nullifies: {}", view);
                            exceptions += 1;
                        }
                    }
                }

                // Ensure exceptions within allowed
                assert!(exceptions <= max_exceptions);
            }
            assert!(exceptions <= max_exceptions);

            // Ensure no blocked connections
            let blocked = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty());

            // Ensure online nodes are recording timeouts/nullifications for the offline leader
            let encoded = context.encode();
            let leader_label = format!("leader=\"{}\"", offline);
            assert!(
                count_nonzero_metric_lines(&encoded, &["_timeouts", &leader_label]) >= n - 1,
                "expected timeout metrics for offline leader"
            );
            assert_eq!(
                count_nonzero_metric_lines(&encoded, &["_nullifications", &leader_label]),
                n - 1,
                "expected all online nodes to record _nullifications for offline leader"
            );
        });
    }

    test_for_all_fixtures!(one_offline);

    fn slow_validator<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        // Create context
        let n = 5;
        let required_containers = View::new(50);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(300));
        executor.start(|mut context| async move {
            // Register participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let mut oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &participants, Action::Link(link), None).await;

            // Create engines
            let elector = L::default();
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx_scheme, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context
                    .child("validator")
                    .with_attribute("public_key", validator);

                // Configure engine
                let reporter_config = mocks::reporter::Config {
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx_scheme].clone(),
                    elector: elector.clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
                reporters.push(reporter.clone());
                let application_cfg = if idx_scheme == 0 {
                    mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        me: validator.clone(),
                        propose_latency: (10_000.0, 0.0),
                        verify_latency: (10_000.0, 5.0),
                        certify_latency: (10_000.0, 5.0),
                        should_certify: mocks::application::Certifier::Always,
                    }
                } else {
                    mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        me: validator.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                        certify_latency: (10.0, 5.0),
                        should_certify: mocks::application::Certifier::Always,
                    }
                };
                let (actor, application) = mocks::application::Application::new(
                    context.child("application"),
                    application_cfg,
                );
                actor.start();
                let blocker = oracle.control(validator.clone());
                let cfg = config::Config {
                    scheme: schemes[idx_scheme].clone(),
                    elector: elector.clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    strategy: Sequential,
                    partition: validator.to_string(),
                    mailbox_size: NZUsize!(1024),
                    epoch: Epoch::new(333),
                    floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(
                        Epoch::new(333),
                    )),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_concurrent: NZUsize!(4),
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                    forwarding: ForwardingPolicy::Disabled,
                };
                let engine = Engine::new(context.child("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(pending, recovered, resolver));
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.child("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.recv().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check reporters for correct activity
            let slow = &participants[0];
            for reporter in reporters.iter() {
                // Ensure no faults
                reporter.assert_no_faults();

                // Ensure no invalid signatures
                reporter.assert_no_invalid();

                // Ensure the slow validator never emits notarize or finalize
                // votes. It may still emit nullifies after timing out.
                {
                    let notarizes = reporter.notarizes.lock();
                    assert!(notarizes.values().all(|payloads| {
                        payloads
                            .values()
                            .all(|participants| !participants.contains(slow))
                    }));
                }
                {
                    let finalizes = reporter.finalizes.lock();
                    assert!(finalizes.values().all(|payloads| {
                        payloads
                            .values()
                            .all(|participants| !participants.contains(slow))
                    }));
                }

                // Ensure every reporter observes finalization progress to at least the target view.
                {
                    let finalizations = reporter.finalizations.lock();
                    assert!(finalizations
                        .keys()
                        .any(|view| *view >= required_containers));
                }
            }

            // Ensure no blocked connections
            let blocked = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty());
        });
    }

    test_for_all_fixtures!(slow_validator);

    fn all_recovery<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        // Create context
        let n = 5;
        let required_containers = View::new(100);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(2);
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(1800));
        executor.start(|mut context| async move {
            // Register participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let mut oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_secs(3),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &participants, Action::Link(link), None).await;

            // Create engines
            let elector = L::default();
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context
                    .child("validator")
                    .with_attribute("public_key", validator);

                // Configure engine
                let reporter_config = mocks::reporter::Config {
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
                reporters.push(reporter.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    me: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                    certify_latency: (10.0, 5.0),
                    should_certify: mocks::application::Certifier::Always,
                };
                let (actor, application) = mocks::application::Application::new(
                    context.child("application"),
                    application_cfg,
                );
                actor.start();
                let blocker = oracle.control(validator.clone());
                let cfg = config::Config {
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    strategy: Sequential,
                    partition: validator.to_string(),
                    mailbox_size: NZUsize!(1024),
                    epoch: Epoch::new(333),
                    floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(
                        Epoch::new(333),
                    )),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_concurrent: NZUsize!(4),
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                    forwarding: ForwardingPolicy::Disabled,
                };
                let engine = Engine::new(context.child("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(pending, recovered, resolver));
            }

            // Wait for a few virtual minutes (shouldn't finalize anything)
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (_, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.child("finalizer").spawn(move |context| async move {
                    select! {
                        _timeout = context.sleep(Duration::from_secs(60)) => {},
                        _done = monitor.recv() => {
                            panic!("engine should not notarize or finalize anything");
                        },
                    }
                }));
            }
            join_all(finalizers).await;

            // Unlink all validators to get latest view
            link_validators(&mut oracle, &participants, Action::Unlink, None).await;

            // Wait for a virtual minute (nothing should happen)
            context.sleep(Duration::from_secs(60)).await;

            // Get latest view
            let mut latest = View::zero();
            for reporter in reporters.iter() {
                let nullifies = reporter.nullifies.lock();
                let max = nullifies.keys().max().unwrap();
                if *max > latest {
                    latest = *max;
                }
            }

            // Update links
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &participants, Action::Link(link), None).await;

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.child("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.recv().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check reporters for correct activity
            for reporter in reporters.iter() {
                // Ensure no faults
                reporter.assert_no_faults();

                // Ensure no invalid signatures
                reporter.assert_no_invalid();

                // Ensure quick recovery.
                //
                // If the skip timeout isn't implemented correctly, we may go many views before participants
                // start to notarize a validator's proposal.
                {
                    // Ensure nearly all views around latest are notarized.
                    // We don't check for finalization since some of the blocks may fail to be
                    // certified for the purposes of testing.
                    let mut found = 0;
                    let notarizations = reporter.notarizations.lock();
                    for view in View::range(latest, latest.saturating_add(activity_timeout)) {
                        if notarizations.contains_key(&view) {
                            found += 1;
                        }
                    }
                    let tolerated_missing = skip_timeout.get().saturating_add(1);
                    assert!(
                        found >= activity_timeout.get().saturating_sub(tolerated_missing),
                        "found: {found}"
                    );
                }
            }

            // Ensure no blocked connections
            let blocked = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty());
        });
    }

    test_for_all_fixtures!(all_recovery);

    fn all_crash_after_nullify<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        // Create context
        let n = 4;
        let required_containers = View::new(10);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(3600));
        executor.start(|mut context| async move {
            // Register participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let mut oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // Participant 0 never starts an engine and no links exist yet, so no
            // view can produce a certificate before the crash below.
            let elector = L::default();
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx_scheme, validator) in participants.iter().enumerate() {
                // Skip first peer
                if idx_scheme == 0 {
                    continue;
                }

                // Create scheme context
                let context = context
                    .child("validator")
                    .with_attribute("public_key", validator);

                // Configure engine
                let reporter_config = mocks::reporter::Config {
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx_scheme].clone(),
                    elector: elector.clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
                reporters.push(reporter.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    me: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                    certify_latency: (10.0, 5.0),
                    should_certify: mocks::application::Certifier::Always,
                };
                let (actor, application) = mocks::application::Application::new(
                    context.child("application"),
                    application_cfg,
                );
                actor.start();
                let blocker = oracle.control(validator.clone());
                let cfg = config::Config {
                    scheme: schemes[idx_scheme].clone(),
                    elector: elector.clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    strategy: Sequential,
                    partition: validator.to_string(),
                    mailbox_size: NZUsize!(1024),
                    epoch: Epoch::new(333),
                    floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(
                        Epoch::new(333),
                    )),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_concurrent: NZUsize!(4),
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                    forwarding: ForwardingPolicy::Disabled,
                };
                let engine = Engine::new(context.child("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(pending, recovered, resolver));
            }

            // Wait for every online validator to construct its nullify vote for
            // view 1.
            let stalled = View::new(1);
            loop {
                let nullified = reporters.iter().zip(participants.iter().skip(1)).all(
                    |(reporter, validator)| {
                        reporter
                            .nullifies
                            .lock()
                            .get(&stalled)
                            .is_some_and(|nullifiers| nullifiers.contains(validator))
                    },
                );
                if nullified {
                    break;
                }
                context.sleep(Duration::from_millis(100)).await;
            }

            // The reporter observes our vote via the batcher, which can run ahead
            // of the voter's journal sync in the same instant. Wait one more tick
            // so every vote is durable before crashing.
            context.sleep(Duration::from_secs(1)).await;

            // Crash every online validator before any nullification certificate
            // can circulate.
            for handle in engine_handlers.drain(..) {
                handle.abort();
                let _ = handle.await;
            }
            relay.deregister_all();

            // Restore connectivity between the online validators.
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(
                &mut oracle,
                &participants,
                Action::Link(link),
                Some(|_, i, j| ![i, j].contains(&0usize)),
            )
            .await;

            // Restart every online validator from its journal.
            let mut reporters = Vec::new();
            for (idx_scheme, validator) in participants.iter().enumerate() {
                // Skip first peer
                if idx_scheme == 0 {
                    continue;
                }

                // Create scheme context
                let context = context
                    .child("validator_restarted")
                    .with_attribute("public_key", validator);

                // Configure engine
                let reporter_config = mocks::reporter::Config {
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx_scheme].clone(),
                    elector: elector.clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
                reporters.push(reporter.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    me: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                    certify_latency: (10.0, 5.0),
                    should_certify: mocks::application::Certifier::Always,
                };
                let (actor, application) = mocks::application::Application::new(
                    context.child("application"),
                    application_cfg,
                );
                actor.start();
                let blocker = oracle.control(validator.clone());
                let cfg = config::Config {
                    scheme: schemes[idx_scheme].clone(),
                    elector: elector.clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    strategy: Sequential,
                    partition: validator.to_string(),
                    mailbox_size: NZUsize!(1024),
                    epoch: Epoch::new(333),
                    floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(
                        Epoch::new(333),
                    )),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_concurrent: NZUsize!(4),
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                    forwarding: ForwardingPolicy::Disabled,
                };
                let engine = Engine::new(context.child("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) =
                    register_validator(&mut oracle, validator.clone()).await;
                engine.start(pending, recovered, resolver);
            }

            // The restarted validators must reconstruct a nullification for view 1
            // to make progress (participant 0 never votes, so every remaining vote
            // is required to reach quorum).
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.child("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.recv().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;
        });
    }

    test_for_all_fixtures!(all_crash_after_nullify);

    fn partition<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        // Create context
        let n = 10;
        let required_containers = View::new(50);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(900));
        executor.start(|mut context| async move {
            // Register participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let mut oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &participants, Action::Link(link.clone()), None).await;

            // Create engines
            let elector = L::default();
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context
                    .child("validator")
                    .with_attribute("public_key", validator);

                // Configure engine
                let reporter_config = mocks::reporter::Config {
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
                reporters.push(reporter.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    me: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                    certify_latency: (10.0, 5.0),
                    should_certify: mocks::application::Certifier::Always,
                };
                let (actor, application) = mocks::application::Application::new(
                    context.child("application"),
                    application_cfg,
                );
                actor.start();
                let blocker = oracle.control(validator.clone());
                let cfg = config::Config {
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    strategy: Sequential,
                    partition: validator.to_string(),
                    mailbox_size: NZUsize!(1024),
                    epoch: Epoch::new(333),
                    floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(
                        Epoch::new(333),
                    )),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_concurrent: NZUsize!(4),
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                    forwarding: ForwardingPolicy::Disabled,
                };
                let engine = Engine::new(context.child("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(pending, recovered, resolver));
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.child("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.recv().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Cut all links between validator halves
            fn separated(n: usize, a: usize, b: usize) -> bool {
                let m = n / 2;
                (a < m && b >= m) || (a >= m && b < m)
            }
            link_validators(&mut oracle, &participants, Action::Unlink, Some(separated)).await;

            // Wait for any in-progress notarizations/finalizations to finish
            context.sleep(Duration::from_secs(10)).await;

            // Wait for a few virtual minutes (shouldn't finalize anything)
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (_, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.child("finalizer").spawn(move |context| async move {
                    select! {
                        _timeout = context.sleep(Duration::from_secs(60)) => {},
                        _done = monitor.recv() => {
                            panic!("engine should not notarize or finalize anything");
                        },
                    }
                }));
            }
            join_all(finalizers).await;

            // Restore links
            link_validators(
                &mut oracle,
                &participants,
                Action::Link(link),
                Some(separated),
            )
            .await;

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                let required = latest.saturating_add(ViewDelta::new(required_containers.get()));
                finalizers.push(context.child("finalizer").spawn(move |_| async move {
                    while latest < required {
                        latest = monitor.recv().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check reporters for correct activity
            for reporter in reporters.iter() {
                // Ensure no faults
                reporter.assert_no_faults();

                // Ensure no invalid signatures
                reporter.assert_no_invalid();
            }

            // Ensure no blocked connections
            let blocked = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty());
        });
    }

    test_for_all_fixtures!(partition);

    fn slow_and_lossy_links_seeded<S, F, L>(seed: u64, mut fixture: F) -> String
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        // Create context
        let n = 5;
        let required_containers = View::new(50);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();
        let cfg = deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(5_000)));
        let executor = deterministic::Runner::new(cfg);
        executor.start(|mut context| async move {
            // Register participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let mut oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // Link all validators
            let degraded_link = Link {
                latency: Duration::from_millis(200),
                jitter: Duration::from_millis(150),
                success_rate: 0.5,
            };
            link_validators(
                &mut oracle,
                &participants,
                Action::Link(degraded_link),
                None,
            )
            .await;

            // Create engines
            let elector = L::default();
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context
                    .child("validator")
                    .with_attribute("public_key", validator);

                // Configure engine
                let reporter_config = mocks::reporter::Config {
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
                reporters.push(reporter.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    me: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                    certify_latency: (10.0, 5.0),
                    should_certify: mocks::application::Certifier::Always,
                };
                let (actor, application) = mocks::application::Application::new(
                    context.child("application"),
                    application_cfg,
                );
                actor.start();
                let blocker = oracle.control(validator.clone());
                let cfg = config::Config {
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    strategy: Sequential,
                    partition: validator.to_string(),
                    mailbox_size: NZUsize!(1024),
                    epoch: Epoch::new(333),
                    floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(
                        Epoch::new(333),
                    )),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_concurrent: NZUsize!(4),
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                    forwarding: ForwardingPolicy::Disabled,
                };
                let engine = Engine::new(context.child("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(pending, recovered, resolver));
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.child("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.recv().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check reporters for correct activity
            for reporter in reporters.iter() {
                // Ensure no faults
                reporter.assert_no_faults();

                // Ensure no invalid signatures
                reporter.assert_no_invalid();
            }

            // Ensure no blocked connections
            let blocked = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty());

            context.auditor().state()
        })
    }

    fn slow_and_lossy_links<S, F, L>(fixture: F) -> String
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        slow_and_lossy_links_seeded::<_, _, L>(6, fixture)
    }

    test_for_all_fixtures!(slow_and_lossy_links);

    fn determinism<S, F, L>(seed: u64, fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S> + Copy,
        L: Elector<S>,
    {
        // We use slow and lossy links as the deterministic test
        // because it is the most complex test.
        assert_eq!(
            slow_and_lossy_links_seeded::<_, _, L>(seed, fixture),
            slow_and_lossy_links_seeded::<_, _, L>(seed, fixture),
        );
    }

    test_for_all_fixtures!(determinism, seeds = 5);

    #[test_group("slow")]
    #[test_traced]
    fn test_distinct_states() {
        // Sanity check that different schemes produce different audit states.
        macro_rules! collect {
            ($vec:ident, $suffix:ident, $elector:ty, $fixture:expr) => {
                $vec.push((
                    stringify!($suffix),
                    slow_and_lossy_links_seeded::<_, _, $elector>(7, $fixture),
                ));
            };
        }
        let mut states = Vec::new();
        for_each_fixture!(collect!(states));
        for pair in states.windows(2) {
            assert_ne!(
                pair[0].1, pair[1].1,
                "state {} equals state {}",
                pair[0].0, pair[1].0
            );
        }
    }

    fn conflicter<S, F, L>(seed: u64, mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        // Create context
        let n = 4;
        let required_containers = View::new(50);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();
        let cfg = deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(30)));
        let executor = deterministic::Runner::new(cfg);
        executor.start(|mut context| async move {
            // Register participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let mut oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &participants, Action::Link(link), None).await;

            // Create engines
            let elector = L::default();
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            for (idx_scheme, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context
                    .child("validator")
                    .with_attribute("public_key", validator);

                // Start engine
                let reporter_config = mocks::reporter::Config {
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx_scheme].clone(),
                    elector: elector.clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                if idx_scheme == 0 {
                    let cfg = mocks::conflicter::Config {
                        scheme: schemes[idx_scheme].clone(),
                    };

                    let engine: mocks::conflicter::Conflicter<_, _, Sha256> =
                        mocks::conflicter::Conflicter::new(context.child("byzantine_engine"), cfg);
                    engine.start(pending);
                } else {
                    reporters.push(reporter.clone());
                    let application_cfg = mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        me: validator.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                        certify_latency: (10.0, 5.0),
                        should_certify: mocks::application::Certifier::Always,
                    };
                    let (actor, application) = mocks::application::Application::new(
                        context.child("application"),
                        application_cfg,
                    );
                    actor.start();
                    let blocker = oracle.control(validator.clone());
                    let cfg = config::Config {
                        scheme: schemes[idx_scheme].clone(),
                        elector: elector.clone(),
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: reporter.clone(),
                        strategy: Sequential,
                        partition: validator.to_string(),
                        mailbox_size: NZUsize!(1024),
                        epoch: Epoch::new(333),
                        floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(
                            Epoch::new(333),
                        )),
                        leader_timeout: Duration::from_secs(1),
                        certification_timeout: Duration::from_secs(2),
                        timeout_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        skip_timeout,
                        fetch_concurrent: NZUsize!(4),
                        replay_buffer: NZUsize!(1024 * 1024),
                        write_buffer: NZUsize!(1024 * 1024),
                        page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                        forwarding: ForwardingPolicy::Disabled,
                    };
                    let engine = Engine::new(context.child("engine"), cfg);
                    engine.start(pending, recovered, resolver);
                }
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.child("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.recv().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check reporters for correct activity
            let byz = &participants[0];
            let mut count_conflicting = 0;
            for reporter in reporters.iter() {
                // Ensure only faults for byz
                {
                    let faults = reporter.faults.lock();
                    assert_eq!(faults.len(), 1);
                    let faulter = faults.get(byz).expect("byzantine party is not faulter");
                    for faults in faulter.values() {
                        for fault in faults.iter() {
                            match fault {
                                Activity::ConflictingNotarize(_) => {
                                    count_conflicting += 1;
                                }
                                Activity::ConflictingFinalize(_) => {
                                    count_conflicting += 1;
                                }
                                _ => panic!("unexpected fault: {fault:?}"),
                            }
                        }
                    }
                }

                // Ensure no invalid signatures
                reporter.assert_no_invalid();
            }
            assert!(count_conflicting > 0);

            // Ensure conflicter is blocked
            let blocked = oracle.blocked().await.unwrap();
            assert!(!blocked.is_empty());
            for (a, b) in blocked {
                assert_ne!(&a, byz);
                assert_eq!(&b, byz);
            }
        });
    }

    test_for_all_fixtures!(conflicter, seeds = 5);

    fn invalid<S, F, L>(seed: u64, mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        // Create context
        let n = 4;
        let required_containers = View::new(50);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();
        let cfg = deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(30)));
        let executor = deterministic::Runner::new(cfg);
        executor.start(|mut context| async move {
            // Register participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            let schemes: Vec<_> = schemes
                .into_iter()
                .enumerate()
                .map(|(idx, scheme)| {
                    let is_byzantine = idx == 0;
                    let behavior = if is_byzantine {
                        wrapped::Behavior::CorruptSignature
                    } else {
                        wrapped::Behavior::Honest
                    };
                    wrapped::Scheme::new(scheme, behavior)
                })
                .collect();

            let mut oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &participants, Action::Link(link), None).await;

            // Create engines
            let elector = wrapped::Config(L::default());
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            for (idx_scheme, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context
                    .child("validator")
                    .with_attribute("public_key", validator);

                let reporter_config = mocks::reporter::Config {
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx_scheme].clone(),
                    elector: elector.clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
                reporters.push(reporter.clone());

                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    me: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                    certify_latency: (10.0, 5.0),
                    should_certify: mocks::application::Certifier::Always,
                };
                let (actor, application) = mocks::application::Application::new(
                    context.child("application"),
                    application_cfg,
                );
                actor.start();
                let blocker = oracle.control(validator.clone());
                let cfg = config::Config {
                    scheme: schemes[idx_scheme].clone(),
                    elector: elector.clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    strategy: Sequential,
                    partition: validator.clone().to_string(),
                    mailbox_size: NZUsize!(1024),
                    epoch: Epoch::new(333),
                    floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(
                        Epoch::new(333),
                    )),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_concurrent: NZUsize!(4),
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                    forwarding: ForwardingPolicy::Disabled,
                };
                let engine = Engine::new(context.child("engine"), cfg);
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                engine.start(pending, recovered, resolver);
            }

            // Wait for all engines to finish.
            // The byzantine node will not finish since it will mark any finalization
            // certificates it creates (using its own invalid signature) as invalid.
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut().skip(1) {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.child("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.recv().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check all reporters for activity
            for (i, reporter) in reporters.iter().enumerate() {
                // Ensure no faults
                reporter.assert_no_faults();

                // All nodes see invalid signatures since the honest reporters get unfiltered votes
                // once they pass the view.
                assert!(*reporter.invalid_votes.lock() > 0);

                // Only the byzantine node sees invalid certificates since it constructs them from
                // its own invalid vote. The honest nodes reject them before reaching the reporter.
                let is_byzantine = i == 0;
                if is_byzantine {
                    assert!(*reporter.invalid_certificates.lock() > 0);
                } else {
                    assert_eq!(*reporter.invalid_certificates.lock(), 0);
                }
            }

            // Ensure byzantine node is blocked by honest nodes.
            // The ">=" is because the Byzantine node may block itself.
            let blocked = oracle.blocked().await.unwrap();
            assert!(blocked.len() >= participants.len() - 1);
            let byz = &participants[0];
            for (_, b) in blocked {
                // Assert only the byzantine node is blocked.
                assert_eq!(&b, byz);
            }
        });
    }

    test_for_all_fixtures!(invalid, seeds = 5);

    // Test that when a node receives finalizations, it reports them.
    fn received_certificates_are_reported<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        let n = 4;
        let required_containers = View::new(10);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();
        let cfg = deterministic::Config::new()
            .with_seed(0)
            .with_timeout(Some(Duration::from_secs(30)));
        let executor = deterministic::Runner::new(cfg);
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            let mut oracle = start_test_network_with_peers(
                context.child("network"),
                participants.clone(),
                false,
            )
            .await;
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // Link all honest nodes. Only link node 0 to node 1.
            //
            // Node 0 cannot locally form a certificate because it only sees itself plus one honest
            // peer, but it should still receive the certificates relayed by that peer.
            let link = Link {
                latency: Duration::from_millis(100),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            fn link_graph(_: usize, i: usize, j: usize) -> bool {
                if i == 0 || j == 0 {
                    return i == 1 || j == 1;
                }
                true
            }
            link_validators(
                &mut oracle,
                &participants,
                Action::Link(link),
                Some(link_graph),
            )
            .await;

            let elector = L::default();
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            for (idx_scheme, validator) in participants.iter().enumerate() {
                let context = context
                    .child("validator")
                    .with_attribute("public_key", validator);
                let reporter_config = mocks::reporter::Config {
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx_scheme].clone(),
                    elector: elector.clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
                reporters.push(reporter.clone());

                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    me: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                    certify_latency: (10.0, 5.0),
                    should_certify: mocks::application::Certifier::Always,
                };
                let (actor, application) = mocks::application::Application::new(
                    context.child("application"),
                    application_cfg,
                );
                actor.start();
                let blocker = oracle.control(validator.clone());
                let cfg = config::Config {
                    scheme: schemes[idx_scheme].clone(),
                    elector: elector.clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    strategy: Sequential,
                    partition: validator.clone().to_string(),
                    mailbox_size: NZUsize!(1024),
                    epoch: Epoch::new(333),
                    floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(
                        Epoch::new(333),
                    )),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_concurrent: NZUsize!(4),
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                    forwarding: ForwardingPolicy::Disabled,
                };
                let engine = Engine::new(context.child("engine"), cfg);
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                engine.start(pending, recovered, resolver);
            }
            // Wait for an honest node to observe the finalizations
            let excluded_reporter = reporters[0].clone();
            let mut honest_reporter = reporters[1].clone();
            let (mut honest_latest, mut honest_monitor) = honest_reporter.subscribe().await;
            while honest_latest < required_containers {
                honest_latest = honest_monitor.recv().await.expect("event missing");
            }

            // Wait for all in-flight certificates to arrive at excluded node and be reported.
            context.sleep(Duration::from_secs(1)).await;

            // It should have received similar certificates to the honest node (with some
            // tolerance for initial views in which may not have yet been connected).
            let honest_notarized = {
                let notarizations = honest_reporter.notarizations.lock();
                View::range(View::new(1), required_containers.next())
                    .filter(|view| notarizations.contains_key(view))
                    .count()
            };
            let excluded_notarized = {
                let notarizations = excluded_reporter.notarizations.lock();
                View::range(View::new(1), required_containers.next())
                    .filter(|view| notarizations.contains_key(view))
                    .count()
            };
            assert!(
                excluded_notarized >= honest_notarized.saturating_sub(2),
                "honest_notarized: {honest_notarized}, excluded_notarized: {excluded_notarized}"
            );

            let honest_finalized = {
                let finalizations = honest_reporter.finalizations.lock();
                View::range(View::new(1), required_containers.next())
                    .filter(|view| finalizations.contains_key(view))
                    .count()
            };
            let excluded_finalized = {
                let finalizations = excluded_reporter.finalizations.lock();
                View::range(View::new(1), required_containers.next())
                    .filter(|view| finalizations.contains_key(view))
                    .count()
            };
            assert!(
                excluded_finalized >= honest_finalized.saturating_sub(2),
                "honest_finalized: {honest_finalized}, excluded_finalized: {excluded_finalized}"
            );
        });
    }

    test_for_all_fixtures!(received_certificates_are_reported);

    fn survives_burst<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        let n = 4;
        let epoch = Epoch::new(333);
        let namespace = b"mailbox_size_one_certificate_burst".to_vec();
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let me = participants[0].clone();
            let mut oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;
            let (pending, recovered, resolver) = register_validator(&mut oracle, me.clone()).await;

            let injector_pk = PrivateKey::from_seed(9_000_000).public_key();
            let (mut injector_sender, _injector_receiver) = oracle
                .control(injector_pk.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();
            let link = Link {
                latency: Duration::from_millis(0),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            oracle
                .add_link(injector_pk.clone(), me.clone(), link)
                .await
                .unwrap();
            oracle.manager().track(
                1,
                TrackedPeers::new(
                    Set::from_iter_dedup(std::iter::once(me.clone())),
                    Set::from_iter_dedup(std::iter::once(injector_pk.clone())),
                ),
            );
            context.sleep(Duration::from_millis(1)).await;

            let quorum = quorum(n) as usize;
            let notarization = |view: View, parent: View, payload: &[u8]| {
                let proposal =
                    Proposal::new(Round::new(epoch, view), parent, Sha256::hash(payload));
                let votes: Vec<_> = schemes
                    .iter()
                    .take(quorum)
                    .map(|scheme| TNotarize::sign(scheme, proposal.clone()).unwrap())
                    .collect();
                TNotarization::from_notarizes(&schemes[0], &votes, &Sequential)
                    .expect("notarization requires quorum")
            };
            let finalization = |view: View, parent: View, payload: &[u8]| {
                let proposal =
                    Proposal::new(Round::new(epoch, view), parent, Sha256::hash(payload));
                let votes: Vec<_> = schemes
                    .iter()
                    .take(quorum)
                    .map(|scheme| TFinalize::sign(scheme, proposal.clone()).unwrap())
                    .collect();
                TFinalization::from_finalizes(&schemes[0], &votes, &Sequential)
                    .expect("finalization requires quorum")
            };

            // Load the network with certificates that the batcher will want to pass to the voter
            for certificate in [
                Certificate::Notarization(notarization(View::new(1), View::zero(), b"payload-1")),
                Certificate::Notarization(notarization(View::new(2), View::new(1), b"payload-2")),
                Certificate::Notarization(notarization(View::new(3), View::new(2), b"payload-3")),
                Certificate::Finalization(finalization(View::new(3), View::new(2), b"payload-3")),
            ] {
                injector_sender.send(Recipients::One(me.clone()), certificate.encode(), true);
            }

            let elector = L::default();
            let reporter_config = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
            let mut monitor_reporter = reporter.clone();
            let (mut latest, mut monitor) = monitor_reporter.subscribe().await;

            let relay = Arc::new(mocks::relay::Relay::new());
            let application_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (0.0, 0.0),
                verify_latency: (0.0, 0.0),
                certify_latency: (0.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (mut application_actor, application) =
                mocks::application::Application::new(context.child("application"), application_cfg);
            application_actor.set_stall_proposals(true);
            application_actor.start();

            let cfg = config::Config {
                scheme: schemes[0].clone(),
                elector,
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application,
                reporter,
                strategy: Sequential,
                partition: me.to_string(),
                mailbox_size: NZUsize!(1),
                epoch,
                floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(epoch)),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                fetch_concurrent: NZUsize!(4),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                forwarding: ForwardingPolicy::Disabled,
            };
            let engine = Engine::new(context.child("engine"), cfg);
            engine.start(pending, recovered, resolver);

            while latest < View::new(3) {
                latest = monitor.recv().await.expect("finalization event missing");
            }
        });
    }

    test_for_all_fixtures!(survives_burst);

    fn impersonator<S, F, L>(seed: u64, mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        // Create context
        let n = 4;
        let required_containers = View::new(50);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();
        let cfg = deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(30)));
        let executor = deterministic::Runner::new(cfg);
        executor.start(|mut context| async move {
            // Register participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let mut oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &participants, Action::Link(link), None).await;

            // Create engines
            let elector = L::default();
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            for (idx_scheme, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context
                    .child("validator")
                    .with_attribute("public_key", validator);

                // Start engine
                let reporter_config = mocks::reporter::Config {
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx_scheme].clone(),
                    elector: elector.clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                if idx_scheme == 0 {
                    let cfg = mocks::impersonator::Config {
                        scheme: schemes[idx_scheme].clone(),
                    };

                    let engine: mocks::impersonator::Impersonator<_, _, Sha256> =
                        mocks::impersonator::Impersonator::new(
                            context.child("byzantine_engine"),
                            cfg,
                        );
                    engine.start(pending);
                } else {
                    reporters.push(reporter.clone());
                    let application_cfg = mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        me: validator.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                        certify_latency: (10.0, 5.0),
                        should_certify: mocks::application::Certifier::Always,
                    };
                    let (actor, application) = mocks::application::Application::new(
                        context.child("application"),
                        application_cfg,
                    );
                    actor.start();
                    let blocker = oracle.control(validator.clone());
                    let cfg = config::Config {
                        scheme: schemes[idx_scheme].clone(),
                        elector: elector.clone(),
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: reporter.clone(),
                        strategy: Sequential,
                        partition: validator.clone().to_string(),
                        mailbox_size: NZUsize!(1024),
                        epoch: Epoch::new(333),
                        floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(
                            Epoch::new(333),
                        )),
                        leader_timeout: Duration::from_secs(1),
                        certification_timeout: Duration::from_secs(2),
                        timeout_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        skip_timeout,
                        fetch_concurrent: NZUsize!(4),
                        replay_buffer: NZUsize!(1024 * 1024),
                        write_buffer: NZUsize!(1024 * 1024),
                        page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                        forwarding: ForwardingPolicy::Disabled,
                    };
                    let engine = Engine::new(context.child("engine"), cfg);
                    engine.start(pending, recovered, resolver);
                }
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.child("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.recv().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check reporters for correct activity
            let byz = &participants[0];
            for reporter in reporters.iter() {
                // Ensure no faults
                reporter.assert_no_faults();

                // Ensure no invalid signatures
                reporter.assert_no_invalid();
            }

            // Ensure invalid is blocked
            let blocked = oracle.blocked().await.unwrap();
            assert!(!blocked.is_empty());
            for (a, b) in blocked {
                assert_ne!(&a, byz);
                assert_eq!(&b, byz);
            }
        });
    }

    test_for_all_fixtures!(impersonator, seeds = 5);

    fn equivocator_seeded<S, F, L>(seed: u64, mut fixture: F) -> bool
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        // Create context
        let n = 7;
        let required_containers = View::new(50);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();
        let cfg = deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(60)));
        let executor = deterministic::Runner::new(cfg);
        executor.start(|mut context| async move {
            // Register participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let mut oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &participants, Action::Link(link), None).await;

            // Create engines
            let elector = L::default();
            let mut engines = Vec::new();
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            for (idx_scheme, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context
                    .child("validator")
                    .with_attribute("public_key", validator);

                // Start engine
                let reporter_config = mocks::reporter::Config {
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx_scheme].clone(),
                    elector: elector.clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
                reporters.push(reporter.clone());
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                if idx_scheme == 0 {
                    let cfg = mocks::equivocator::Config {
                        scheme: schemes[idx_scheme].clone(),
                        epoch: Epoch::new(333),
                        relay: relay.clone(),
                        hasher: Sha256::default(),
                        elector: elector.clone(),
                    };

                    let engine = mocks::equivocator::Equivocator::new(
                        context.child("byzantine_engine"),
                        cfg,
                    );
                    engines.push(engine.start(pending, recovered));
                } else {
                    let application_cfg = mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        me: validator.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                        certify_latency: (10.0, 5.0),
                        should_certify: mocks::application::Certifier::Always,
                    };
                    let (actor, application) = mocks::application::Application::new(
                        context.child("application"),
                        application_cfg,
                    );
                    actor.start();
                    let blocker = oracle.control(validator.clone());
                    let cfg = config::Config {
                        scheme: schemes[idx_scheme].clone(),
                        elector: elector.clone(),
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: reporter.clone(),
                        strategy: Sequential,
                        partition: validator.to_string(),
                        mailbox_size: NZUsize!(1024),
                        epoch: Epoch::new(333),
                        floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(
                            Epoch::new(333),
                        )),
                        leader_timeout: Duration::from_secs(1),
                        certification_timeout: Duration::from_secs(2),
                        timeout_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        skip_timeout,
                        fetch_concurrent: NZUsize!(4),
                        replay_buffer: NZUsize!(1024 * 1024),
                        write_buffer: NZUsize!(1024 * 1024),
                        page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                        forwarding: ForwardingPolicy::Disabled,
                    };
                    let engine = Engine::new(context.child("engine"), cfg);
                    engines.push(engine.start(pending, recovered, resolver));
                }
            }

            // Wait for all engines to hit required containers
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut().skip(1) {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.child("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.recv().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Abort a validator
            let idx = context.random_range(1..engines.len()); // skip byzantine validator
            let validator = &participants[idx];
            let handle = engines.remove(idx);
            handle.abort();
            let _ = handle.await;
            reporters.remove(idx);
            info!(idx, ?validator, "aborted validator");

            // Wait for all engines to hit required containers
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut().skip(1) {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.child("finalizer").spawn(move |_| async move {
                    while latest < View::new(required_containers.get() * 2) {
                        latest = monitor.recv().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Recreate engine
            info!(idx, ?validator, "restarting validator");
            let context = context
                .child("validator_restarted")
                .with_attribute("public_key", validator);

            // Start engine
            let reporter_config = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[idx].clone(),
                elector: elector.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
            let (pending, recovered, resolver) =
                register_validator(&mut oracle, validator.clone()).await;
            reporters.push(reporter.clone());
            let application_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: validator.clone(),
                propose_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                certify_latency: (10.0, 5.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (actor, application) =
                mocks::application::Application::new(context.child("application"), application_cfg);
            actor.start();
            let blocker = oracle.control(validator.clone());
            let cfg = config::Config {
                scheme: schemes[idx].clone(),
                elector: elector.clone(),
                blocker,
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                strategy: Sequential,
                partition: validator.to_string(),
                mailbox_size: NZUsize!(1024),
                epoch: Epoch::new(333),
                floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(Epoch::new(
                    333,
                ))),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout,
                skip_timeout,
                fetch_concurrent: NZUsize!(4),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                forwarding: ForwardingPolicy::Disabled,
            };
            let engine = Engine::new(context.child("engine"), cfg);
            engine.start(pending, recovered, resolver);

            // Wait for all engines to hit required containers
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut().skip(1) {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.child("finalizer").spawn(move |_| async move {
                    while latest < View::new(required_containers.get() * 3) {
                        latest = monitor.recv().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check equivocator blocking (we aren't guaranteed a fault will be produced
            // because it may not be possible to extract a conflicting vote from the certificate
            // we receive)
            let byz = &participants[0];
            let blocked = oracle.blocked().await.unwrap();
            for (a, b) in &blocked {
                assert_ne!(a, byz);
                assert_eq!(b, byz);
            }
            !blocked.is_empty()
        })
    }

    fn equivocator<S, F, L>(fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S> + Copy,
        L: Elector<S>,
    {
        let detected = (0..5).any(|seed| equivocator_seeded::<_, _, L>(seed, fixture));
        assert!(
            detected,
            "expected at least one seed to detect equivocation"
        );
    }

    test_for_all_fixtures!(equivocator);

    fn reconfigurer<S, F, L>(seed: u64, mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        // Create context
        let n = 4;
        let required_containers = View::new(50);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();
        let cfg = deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(30)));
        let executor = deterministic::Runner::new(cfg);
        executor.start(|mut context| async move {
            // Register participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let mut oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &participants, Action::Link(link), None).await;

            // Create engines
            let elector = L::default();
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            for (idx_scheme, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context
                    .child("validator")
                    .with_attribute("public_key", validator);

                // Start engine
                let reporter_config = mocks::reporter::Config {
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx_scheme].clone(),
                    elector: elector.clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                if idx_scheme == 0 {
                    let cfg = mocks::reconfigurer::Config {
                        scheme: schemes[idx_scheme].clone(),
                    };
                    let engine: mocks::reconfigurer::Reconfigurer<_, _, Sha256> =
                        mocks::reconfigurer::Reconfigurer::new(
                            context.child("byzantine_engine"),
                            cfg,
                        );
                    engine.start(pending);
                } else {
                    reporters.push(reporter.clone());
                    let application_cfg = mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        me: validator.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                        certify_latency: (10.0, 5.0),
                        should_certify: mocks::application::Certifier::Always,
                    };
                    let (actor, application) = mocks::application::Application::new(
                        context.child("application"),
                        application_cfg,
                    );
                    actor.start();
                    let blocker = oracle.control(validator.clone());
                    let cfg = config::Config {
                        scheme: schemes[idx_scheme].clone(),
                        elector: elector.clone(),
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: reporter.clone(),
                        strategy: Sequential,
                        partition: validator.to_string(),
                        mailbox_size: NZUsize!(1024),
                        epoch: Epoch::new(333),
                        floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(
                            Epoch::new(333),
                        )),
                        leader_timeout: Duration::from_secs(1),
                        certification_timeout: Duration::from_secs(2),
                        timeout_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        skip_timeout,
                        fetch_concurrent: NZUsize!(4),
                        replay_buffer: NZUsize!(1024 * 1024),
                        write_buffer: NZUsize!(1024 * 1024),
                        page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                        forwarding: ForwardingPolicy::Disabled,
                    };
                    let engine = Engine::new(context.child("engine"), cfg);
                    engine.start(pending, recovered, resolver);
                }
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.child("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.recv().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check reporters for correct activity
            let byz = &participants[0];
            for reporter in reporters.iter() {
                // Ensure no faults
                reporter.assert_no_faults();

                // Ensure no invalid signatures
                reporter.assert_no_invalid();
            }

            // Ensure reconfigurer is blocked (epoch mismatch)
            let blocked = oracle.blocked().await.unwrap();
            assert!(!blocked.is_empty());
            for (a, b) in blocked {
                assert_ne!(&a, byz);
                assert_eq!(&b, byz);
            }
        });
    }

    test_for_all_fixtures!(reconfigurer, seeds = 5);

    fn nuller<S, F, L>(seed: u64, mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        // Create context
        let n = 4;
        let required_containers = View::new(50);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();
        let cfg = deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(30)));
        let executor = deterministic::Runner::new(cfg);
        executor.start(|mut context| async move {
            // Register participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let mut oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &participants, Action::Link(link), None).await;

            // Create engines
            let elector = L::default();
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            for (idx_scheme, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context
                    .child("validator")
                    .with_attribute("public_key", validator);

                // Start engine
                let reporter_config = mocks::reporter::Config {
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx_scheme].clone(),
                    elector: elector.clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                if idx_scheme == 0 {
                    let cfg = mocks::nuller::Config {
                        scheme: schemes[idx_scheme].clone(),
                    };
                    let engine: mocks::nuller::Nuller<_, _, Sha256> =
                        mocks::nuller::Nuller::new(context.child("byzantine_engine"), cfg);
                    engine.start(pending);
                } else {
                    reporters.push(reporter.clone());
                    let application_cfg = mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        me: validator.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                        certify_latency: (10.0, 5.0),
                        should_certify: mocks::application::Certifier::Always,
                    };
                    let (actor, application) = mocks::application::Application::new(
                        context.child("application"),
                        application_cfg,
                    );
                    actor.start();
                    let blocker = oracle.control(validator.clone());
                    let cfg = config::Config {
                        scheme: schemes[idx_scheme].clone(),
                        elector: elector.clone(),
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: reporter.clone(),
                        strategy: Sequential,
                        partition: validator.clone().to_string(),
                        mailbox_size: NZUsize!(1024),
                        epoch: Epoch::new(333),
                        floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(
                            Epoch::new(333),
                        )),
                        leader_timeout: Duration::from_secs(1),
                        certification_timeout: Duration::from_secs(2),
                        timeout_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        skip_timeout,
                        fetch_concurrent: NZUsize!(4),
                        replay_buffer: NZUsize!(1024 * 1024),
                        write_buffer: NZUsize!(1024 * 1024),
                        page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                        forwarding: ForwardingPolicy::Disabled,
                    };
                    let engine = Engine::new(context.child("engine"), cfg);
                    engine.start(pending, recovered, resolver);
                }
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.child("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.recv().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check reporters for correct activity
            let byz = &participants[0];
            let mut count_nullify_and_finalize = 0;
            for reporter in reporters.iter() {
                // Ensure only faults for byz
                {
                    let faults = reporter.faults.lock();
                    assert_eq!(faults.len(), 1);
                    let faulter = faults.get(byz).expect("byzantine party is not faulter");
                    for faults in faulter.values() {
                        for fault in faults.iter() {
                            match fault {
                                Activity::NullifyFinalize(_) => {
                                    count_nullify_and_finalize += 1;
                                }
                                _ => panic!("unexpected fault: {fault:?}"),
                            }
                        }
                    }
                }

                // Ensure no invalid signatures
                reporter.assert_no_invalid();
            }
            assert!(count_nullify_and_finalize > 0);

            // Ensure nullifier is blocked
            let blocked = oracle.blocked().await.unwrap();
            assert!(!blocked.is_empty());
            for (a, b) in blocked {
                assert_ne!(&a, byz);
                assert_eq!(&b, byz);
            }
        });
    }

    test_for_all_fixtures!(nuller, seeds = 5);

    fn outdated<S, F, L>(seed: u64, mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        // Create context
        let n = 4;
        let required_containers = View::new(100);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();
        let cfg = deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(30)));
        let executor = deterministic::Runner::new(cfg);
        executor.start(|mut context| async move {
            // Register participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let mut oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &participants, Action::Link(link), None).await;

            // Create engines
            let elector = L::default();
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            for (idx_scheme, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context
                    .child("validator")
                    .with_attribute("public_key", validator);

                // Start engine
                let reporter_config = mocks::reporter::Config {
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx_scheme].clone(),
                    elector: elector.clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                if idx_scheme == 0 {
                    let cfg = mocks::outdated::Config {
                        scheme: schemes[idx_scheme].clone(),
                        view_delta: ViewDelta::new(activity_timeout.get().saturating_mul(4)),
                    };
                    let engine: mocks::outdated::Outdated<_, _, Sha256> =
                        mocks::outdated::Outdated::new(context.child("byzantine_engine"), cfg);
                    engine.start(pending);
                } else {
                    reporters.push(reporter.clone());
                    let application_cfg = mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        me: validator.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                        certify_latency: (10.0, 5.0),
                        should_certify: mocks::application::Certifier::Always,
                    };
                    let (actor, application) = mocks::application::Application::new(
                        context.child("application"),
                        application_cfg,
                    );
                    actor.start();
                    let blocker = oracle.control(validator.clone());
                    let cfg = config::Config {
                        scheme: schemes[idx_scheme].clone(),
                        elector: elector.clone(),
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: reporter.clone(),
                        strategy: Sequential,
                        partition: validator.clone().to_string(),
                        mailbox_size: NZUsize!(1024),
                        epoch: Epoch::new(333),
                        floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(
                            Epoch::new(333),
                        )),
                        leader_timeout: Duration::from_secs(1),
                        certification_timeout: Duration::from_secs(2),
                        timeout_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        skip_timeout,
                        fetch_concurrent: NZUsize!(4),
                        replay_buffer: NZUsize!(1024 * 1024),
                        write_buffer: NZUsize!(1024 * 1024),
                        page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                        forwarding: ForwardingPolicy::Disabled,
                    };
                    let engine = Engine::new(context.child("engine"), cfg);
                    engine.start(pending, recovered, resolver);
                }
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.child("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.recv().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check reporters for correct activity
            for reporter in reporters.iter() {
                // Ensure no faults
                reporter.assert_no_faults();

                // Ensure no invalid signatures
                reporter.assert_no_invalid();
            }

            // Ensure no blocked connections
            let blocked = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty());
        });
    }

    test_for_all_fixtures!(outdated, seeds = 5);

    fn run_1k<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        // Create context
        let n = 10;
        let required_containers = View::new(1_000);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();
        let cfg = deterministic::Config::new();
        let executor = deterministic::Runner::new(cfg);
        executor.start(|mut context| async move {
            // Register participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let mut oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(80),
                jitter: Duration::from_millis(10),
                success_rate: 0.98,
            };
            link_validators(&mut oracle, &participants, Action::Link(link), None).await;

            // Create engines
            let elector = L::default();
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context
                    .child("validator")
                    .with_attribute("public_key", validator);

                // Configure engine
                let reporter_config = mocks::reporter::Config {
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
                reporters.push(reporter.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    me: validator.clone(),
                    propose_latency: (100.0, 50.0),
                    verify_latency: (50.0, 40.0),
                    certify_latency: (50.0, 40.0),
                    should_certify: mocks::application::Certifier::Always,
                };
                let (actor, application) = mocks::application::Application::new(
                    context.child("application"),
                    application_cfg,
                );
                actor.start();
                let blocker = oracle.control(validator.clone());
                let cfg = config::Config {
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    strategy: Sequential,
                    partition: validator.to_string(),
                    mailbox_size: NZUsize!(1024),
                    epoch: Epoch::new(333),
                    floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(
                        Epoch::new(333),
                    )),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_concurrent: NZUsize!(4),
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                    forwarding: ForwardingPolicy::Disabled,
                };
                let engine = Engine::new(context.child("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(pending, recovered, resolver));
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.child("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.recv().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check reporters for correct activity
            for reporter in reporters.iter() {
                // Ensure no faults
                reporter.assert_no_faults();

                // Ensure no invalid signatures
                reporter.assert_no_invalid();
            }

            // Ensure no blocked connections
            let blocked = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty());
        })
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_1k() {
        run_1k::<_, _, RoundRobin>(scheme_mocks::fixture);
    }

    fn engine_shutdown<S, F, L>(seed: u64, mut fixture: F, graceful: bool)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        let n = 1;
        let namespace = b"consensus".to_vec();
        let cfg = deterministic::Config::default()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(10)));
        let executor = deterministic::Runner::new(cfg);
        executor.start(|mut context| async move {
            // Register a single participant
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let mut oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // Link the single validator to itself (no-ops for completeness)
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &participants, Action::Link(link), None).await;

            // Create engine
            let elector = L::default();
            let reporter_config = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
            let relay = Arc::new(mocks::relay::Relay::new());
            let application_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: participants[0].clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (actor, application) =
                mocks::application::Application::new(context.child("application"), application_cfg);
            actor.start();
            let blocker = oracle.control(participants[0].clone());
            let cfg = config::Config {
                scheme: schemes[0].clone(),
                elector: elector.clone(),
                blocker,
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                strategy: Sequential,
                partition: participants[0].clone().to_string(),
                mailbox_size: NZUsize!(64),
                epoch: Epoch::new(333),
                floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(Epoch::new(
                    333,
                ))),
                leader_timeout: Duration::from_millis(50),
                certification_timeout: Duration::from_millis(100),
                timeout_retry: Duration::from_millis(250),
                fetch_timeout: Duration::from_millis(50),
                activity_timeout: ViewDelta::new(4),
                skip_timeout: ViewDelta::new(2),
                fetch_concurrent: NZUsize!(4),
                replay_buffer: NZUsize!(1024 * 16),
                write_buffer: NZUsize!(1024 * 16),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                forwarding: ForwardingPolicy::Disabled,
            };
            let engine = Engine::new(context.child("engine"), cfg);

            // Start engine
            let (pending, recovered, resolver) = registrations
                .remove(&participants[0])
                .expect("validator should be registered");
            let handle = engine.start(pending, recovered, resolver);

            // Allow tasks to start
            context.sleep(Duration::from_millis(1000)).await;

            // Count running tasks under the engine prefix
            let running_before = count_running_tasks(&context, "engine");
            assert!(
                running_before > 0,
                "at least one engine task should be running"
            );

            // Make sure the engine is still running after some time
            context.sleep(Duration::from_millis(1500)).await;
            assert!(
                count_running_tasks(&context, "engine") > 0,
                "engine tasks should still be running"
            );

            // Shutdown engine and ensure children stop
            let running_after = if graceful {
                let result = context
                    .child("stop")
                    .stop(0, Some(Duration::from_secs(5)))
                    .await;
                assert!(
                    result.is_ok(),
                    "graceful shutdown should complete: {result:?}"
                );
                count_running_tasks(&context, "engine")
            } else {
                handle.abort();
                let _ = handle.await; // ensure parent tear-down runs

                // Give the runtime a tick to process aborts
                context.sleep(Duration::from_millis(1000)).await;
                count_running_tasks(&context, "engine")
            };
            assert_eq!(
                running_after, 0,
                "all engine tasks should be stopped, but {running_after} still running"
            );
        });
    }

    fn children_shutdown_on_engine_abort<S, F, L>(seed: u64, fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        engine_shutdown::<S, F, L>(seed, fixture, false);
    }

    test_for_all_fixtures!(children_shutdown_on_engine_abort, seeds = 10);

    fn graceful_shutdown<S, F, L>(seed: u64, fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        engine_shutdown::<S, F, L>(seed, fixture, true);
    }

    test_for_all_fixtures!(graceful_shutdown, seeds = 10);

    fn attributable_reporter_filtering<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        let n = 3;
        let required_containers = View::new(10);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
            // Register participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let mut oracle = start_test_network_with_peers(
                context.child("network"),
                participants.clone(),
                false,
            )
            .await;
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &participants, Action::Link(link), None).await;

            // Create engines with `AttributableReporter` wrapper
            let elector = L::default();
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            for (idx, validator) in participants.iter().enumerate() {
                let context = context
                    .child("validator")
                    .with_attribute("public_key", validator);

                let reporter_config = mocks::reporter::Config {
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                };
                let mock_reporter =
                    mocks::reporter::Reporter::new(context.child("mock_reporter"), reporter_config);

                // Wrap with `AttributableReporter`
                let attributable_reporter = scheme::reporter::AttributableReporter::new(
                    context.child("rng"),
                    schemes[idx].clone(),
                    mock_reporter.clone(),
                    Sequential,
                    true, // Enable verification
                );
                reporters.push(mock_reporter.clone());

                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    me: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                    certify_latency: (10.0, 5.0),
                    should_certify: mocks::application::Certifier::Always,
                };
                let (actor, application) = mocks::application::Application::new(
                    context.child("application"),
                    application_cfg,
                );
                actor.start();
                let blocker = oracle.control(validator.clone());
                let cfg = config::Config {
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: attributable_reporter,
                    strategy: Sequential,
                    partition: validator.to_string(),
                    mailbox_size: NZUsize!(1024),
                    epoch: Epoch::new(333),
                    floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(
                        Epoch::new(333),
                    )),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_concurrent: NZUsize!(4),
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                    forwarding: ForwardingPolicy::Disabled,
                };
                let engine = Engine::new(context.child("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                engine.start(pending, recovered, resolver);
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.child("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.recv().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Verify filtering behavior based on scheme attributability
            for reporter in reporters.iter() {
                // Ensure no faults (normal operation)
                reporter.assert_no_faults();

                // Ensure no invalid signatures
                reporter.assert_no_invalid();

                // Check that we have certificates reported
                {
                    let notarizations = reporter.notarizations.lock();
                    let finalizations = reporter.finalizations.lock();
                    assert!(
                        !notarizations.is_empty() || !finalizations.is_empty(),
                        "Certificates should be reported"
                    );
                }

                // Check notarizes
                let notarizes = reporter.notarizes.lock();
                let last_view = notarizes.keys().max().cloned().unwrap_or_default();
                for (view, payloads) in notarizes.iter() {
                    if *view == last_view {
                        continue; // Skip last view
                    }

                    let signers: usize = payloads.values().map(|signers| signers.len()).sum();

                    // For attributable schemes, we should see peer activities
                    if S::is_attributable() {
                        assert!(signers > 1, "view {view}: {signers}");
                    } else {
                        // For non-attributable, we shouldn't see any peer activities
                        assert_eq!(signers, 0);
                    }
                }

                // Check finalizes
                let finalizes = reporter.finalizes.lock();
                for payloads in finalizes.values() {
                    let signers: usize = payloads.values().map(|signers| signers.len()).sum();

                    // For attributable schemes, we should see peer activities
                    if S::is_attributable() {
                        assert!(signers > 1);
                    } else {
                        // For non-attributable, we shouldn't see any peer activities
                        assert_eq!(signers, 0);
                    }
                }
            }

            // Ensure no blocked connections (normal operation)
            let blocked = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty());
        });
    }

    test_for_all_fixtures!(attributable_reporter_filtering);

    fn split_views_no_lockup<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        // Scenario:
        // - View F: Finalization of B_1 seen by all participants.
        // - View F+1:
        //   - Nullification seen by honest (4..=6,7) and all 3 byzantines
        //   - Notarization of B_2A seen by honest (1..=3)
        // - View F+2:
        //   - Nullification seen by honest (1..=3,7) and all 3 byzantines
        //   - Notarization of B_2B seen by honest (4..=6)
        // - View F+3: Nullification. Seen by all participants.
        // - Then ensure progress resumes beyond F+3 after reconnecting

        // Define participant types
        enum ParticipantType {
            Group1,    // receives notarization for f+1, nullification for f+2
            Group2,    // receives nullification for f+1, notarization for f+2
            Ignorant,  // receives nullification for f+1 and f+2
            Byzantine, // nullify-only
        }
        let get_type = |idx: usize| -> ParticipantType {
            match idx {
                0..3 => ParticipantType::Group1,
                3..6 => ParticipantType::Group2,
                6 => ParticipantType::Ignorant,
                7..10 => ParticipantType::Byzantine,
                _ => unreachable!(),
            }
        };

        // Create context
        let n = 10;
        let quorum = quorum(n) as usize;
        assert_eq!(quorum, 7);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(300));
        executor.start(|mut context| async move {
            // Register participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let mut oracle = start_test_network_with_peers(
                context.child("network"),
                participants.clone(),
                false,
            )
            .await;
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // ========== Build the certificates manually ==========

            // Helper: assemble finalization from explicit signer indices
            let build_finalization = |proposal: &Proposal<D>| -> TFinalization<_, D> {
                let votes: Vec<_> = (0..=quorum)
                    .map(|i| TFinalize::sign(&schemes[i], proposal.clone()).unwrap())
                    .collect();
                TFinalization::from_finalizes(&schemes[0], &votes, &Sequential)
                    .expect("finalization quorum")
            };
            // Helper: assemble notarization from explicit signer indices
            let build_notarization = |proposal: &Proposal<D>| -> TNotarization<_, D> {
                let votes: Vec<_> = (0..=quorum)
                    .map(|i| TNotarize::sign(&schemes[i], proposal.clone()).unwrap())
                    .collect();
                TNotarization::from_notarizes(&schemes[0], &votes, &Sequential)
                    .expect("notarization quorum")
            };
            let build_nullification = |round: Round| -> TNullification<_> {
                let votes: Vec<_> = (0..=quorum)
                    .map(|i| TNullify::sign::<D>(&schemes[i], round).unwrap())
                    .collect();
                TNullification::from_nullifies(&schemes[0], &votes, &Sequential)
                    .expect("nullification quorum")
            };
            // Choose F=1 and construct B_1, B_2A, B_2B
            let f_view = 1;
            let round_f = Round::new(Epoch::new(333), View::new(f_view));
            let payload_b0 = Sha256::hash(b"B_F");
            let proposal_b0 = Proposal::new(round_f, View::new(f_view - 1), payload_b0);
            let payload_b1a = Sha256::hash(b"B_G1");
            let proposal_b1a = Proposal::new(
                Round::new(Epoch::new(333), View::new(f_view + 1)),
                View::new(f_view),
                payload_b1a,
            );
            let payload_b1b = Sha256::hash(b"B_G2");
            let proposal_b1b = Proposal::new(
                Round::new(Epoch::new(333), View::new(f_view + 2)),
                View::new(f_view),
                payload_b1b,
            );

            // Build notarization and finalization for the first block
            let b0_notarization = build_notarization(&proposal_b0);
            let b0_finalization = build_finalization(&proposal_b0);
            // Build notarizations for F+1 and F+2
            let b1a_notarization = build_notarization(&proposal_b1a);
            let b1b_notarization = build_notarization(&proposal_b1b);
            // Build nullifications for F+1 and F+2
            let null_a = build_nullification(Round::new(Epoch::new(333), View::new(f_view + 1)));
            let null_b = build_nullification(Round::new(Epoch::new(333), View::new(f_view + 2)));

            // Create an 11th non-participant injector and obtain senders
            let injector_pk = PrivateKey::from_seed(1_000_000).public_key();
            let (mut injector_sender, _inj_certificate_receiver) = oracle
                .control(injector_pk.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            // Create minimal one-way links from injector to all participants (not full mesh)
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            for p in participants.iter() {
                oracle
                    .add_link(injector_pk.clone(), p.clone(), link.clone())
                    .await
                    .unwrap();
            }
            oracle.manager().track(
                1,
                TrackedPeers::new(
                    Set::from_iter_dedup(participants.iter().cloned()),
                    Set::from_iter_dedup(std::slice::from_ref(&injector_pk).iter().cloned()),
                ),
            );
            context.sleep(Duration::from_millis(10)).await;

            // ========== Broadcast certificates over recovered network. ==========

            // View F:
            let msg = Certificate::<_, D>::Notarization(b0_notarization).encode();
            injector_sender.send(Recipients::All, msg, true);
            let msg = Certificate::<_, D>::Finalization(b0_finalization).encode();
            injector_sender.send(Recipients::All, msg, true);
            // View F+1:
            let notarization_msg = Certificate::<_, D>::Notarization(b1a_notarization);
            let nullification_msg = Certificate::<_, D>::Nullification(null_a.clone());
            for (i, participant) in participants.iter().enumerate() {
                let recipient = Recipients::One(participant.clone());
                let msg = match get_type(i) {
                    ParticipantType::Group1 => notarization_msg.encode(),
                    _ => nullification_msg.encode(),
                };
                injector_sender.send(recipient, msg, true);
            }
            // View F+2:
            let notarization_msg = Certificate::<_, D>::Notarization(b1b_notarization);
            let nullification_msg = Certificate::<_, D>::Nullification(null_b.clone());
            for (i, participant) in participants.iter().enumerate() {
                let recipient = Recipients::One(participant.clone());
                let msg = match get_type(i) {
                    ParticipantType::Group2 => notarization_msg.encode(),
                    _ => nullification_msg.encode(),
                };
                injector_sender.send(recipient, msg, true);
            }

            // ========== Create engines ==========

            // Start engines after preloading certificates into each participant's
            // recovered channel (ensuring processing before any leader attempts to issue a
            // conflicting vote).
            let elector = L::default();
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut honest_reporters = Vec::new();
            for (idx, validator) in participants.iter().enumerate() {
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                let participant_type = get_type(idx);
                if matches!(participant_type, ParticipantType::Byzantine) {
                    // Byzantine engines
                    let cfg = mocks::nullify_only::Config {
                        scheme: schemes[idx].clone(),
                    };
                    let engine: mocks::nullify_only::NullifyOnly<_, _, Sha256> =
                        mocks::nullify_only::NullifyOnly::new(
                            context
                                .child("byzantine")
                                .with_attribute("public_key", validator),
                            cfg,
                        );
                    engine.start(pending);
                    // Recovered/resolver channels are unused for byzantine actors.
                    drop(recovered);
                    drop(resolver);
                } else {
                    // Honest engines
                    let reporter_config = mocks::reporter::Config {
                        participants: participants.clone().try_into().unwrap(),
                        scheme: schemes[idx].clone(),
                        elector: elector.clone(),
                    };
                    let reporter = mocks::reporter::Reporter::new(
                        context
                            .child("reporter")
                            .with_attribute("public_key", validator),
                        reporter_config,
                    );
                    honest_reporters.push(reporter.clone());

                    let application_cfg = mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        me: validator.clone(),
                        propose_latency: (250.0, 50.0), // ensure we process certificates first
                        verify_latency: (10.0, 5.0),
                        certify_latency: (10.0, 5.0),
                        should_certify: mocks::application::Certifier::Always,
                    };
                    let (actor, application) = mocks::application::Application::new(
                        context
                            .child("application")
                            .with_attribute("public_key", validator),
                        application_cfg,
                    );
                    actor.start();
                    let blocker = oracle.control(validator.clone());
                    let cfg = config::Config {
                        scheme: schemes[idx].clone(),
                        elector: elector.clone(),
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: reporter.clone(),
                        strategy: Sequential,
                        partition: validator.to_string(),
                        mailbox_size: NZUsize!(1024),
                        epoch: Epoch::new(333),
                        floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(
                            Epoch::new(333),
                        )),
                        leader_timeout: Duration::from_secs(10),
                        certification_timeout: Duration::from_secs(10),
                        timeout_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        skip_timeout,
                        fetch_concurrent: NZUsize!(4),
                        replay_buffer: NZUsize!(1024 * 1024),
                        write_buffer: NZUsize!(1024 * 1024),
                        page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                        forwarding: ForwardingPolicy::Disabled,
                    };
                    let engine = Engine::new(
                        context
                            .child("engine")
                            .with_attribute("public_key", validator),
                        cfg,
                    );
                    engine.start(pending, recovered, resolver);
                }
            }

            // Allow started engines to consume preloaded certificates.
            context.sleep(Duration::from_secs(2)).await;

            // ========== Assert the exact certificates are seen in each view ==========

            // Assert the exact certificates in view F
            // All participants should have finalized B_0
            let view = View::new(f_view);
            for reporter in honest_reporters.iter() {
                let finalizations = reporter.finalizations.lock();
                assert!(finalizations.contains_key(&view));
            }

            // Assert the exact certificates in view F+1
            // Group 1 should have notarized B_1A only
            // All other participants should have nullified F+1
            let view = View::new(f_view + 1);
            for (i, reporter) in honest_reporters.iter().enumerate() {
                let finalizations = reporter.finalizations.lock();
                assert!(!finalizations.contains_key(&view));
                let nullifications = reporter.nullifications.lock();
                let notarizations = reporter.notarizations.lock();
                match get_type(i) {
                    ParticipantType::Group1 => {
                        assert!(notarizations.contains_key(&view));
                        assert!(!nullifications.contains_key(&view));
                    }
                    _ => {
                        assert!(nullifications.contains_key(&view));
                        assert!(!notarizations.contains_key(&view));
                    }
                }
            }

            // Assert the exact certificates in view F+2
            // Group 2 should have notarized B_1B only
            // All other participants should have nullified F+2
            let view = View::new(f_view + 2);
            for (i, reporter) in honest_reporters.iter().enumerate() {
                let finalizations = reporter.finalizations.lock();
                assert!(!finalizations.contains_key(&view));
                let nullifications = reporter.nullifications.lock();
                let notarizations = reporter.notarizations.lock();
                match get_type(i) {
                    ParticipantType::Group2 => {
                        assert!(notarizations.contains_key(&view));
                        assert!(!nullifications.contains_key(&view));
                    }
                    _ => {
                        assert!(nullifications.contains_key(&view));
                        assert!(!notarizations.contains_key(&view));
                    }
                }
            }

            // Assert no members have yet nullified view F+3
            let next_view = View::new(f_view + 3);
            for (i, reporter) in honest_reporters.iter().enumerate() {
                let nullifies = reporter.nullifies.lock();
                assert!(!nullifies.contains_key(&next_view), "reporter {i}");
            }

            // ========== Reconnect all participants ==========

            // Reconnect all participants fully using the helper
            link_validators(&mut oracle, &participants, Action::Link(link.clone()), None).await;

            // Wait until all honest reporters finalize strictly past F+2 (e.g., at least F+3)
            {
                let target = View::new(f_view + 3);
                let mut finalizers = Vec::new();
                for reporter in honest_reporters.iter_mut() {
                    let (mut latest, mut monitor) = reporter.subscribe().await;
                    finalizers.push(
                        context
                            .child("resume_finalizer")
                            .spawn(move |_| async move {
                                while latest < target {
                                    latest = monitor.recv().await.expect("event missing");
                                }
                            }),
                    );
                }
                join_all(finalizers).await;
            }

            // Sanity checks: no faults/invalid signatures, and no peers blocked
            for reporter in honest_reporters.iter() {
                reporter.assert_no_faults();
                reporter.assert_no_invalid();
            }
            let blocked = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty(), "blocked peers: {blocked:?}");
        });
    }

    test_for_all_fixtures!(split_views_no_lockup);

    fn tle<V, L>()
    where
        V: Variant,
        L: Elector<bls12381_threshold_vrf::Scheme<PublicKey, V>>,
    {
        // Create context
        let n = 4;
        let namespace = b"consensus".to_vec();
        let activity_timeout = ViewDelta::new(100);
        let skip_timeout = ViewDelta::new(50);
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
            // Register participants
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, &namespace, n);
            let mut oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(5),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &participants, Action::Link(link), None).await;

            // Create engines and reporters
            let elector = L::default();
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            let monitor_reporter = Arc::new(Mutex::new(None));
            for (idx, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context
                    .child("validator")
                    .with_attribute("public_key", validator);

                // Store first reporter for monitoring
                let reporter_config = mocks::reporter::Config {
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
                reporters.push(reporter.clone());
                if idx == 0 {
                    *monitor_reporter.lock() = Some(reporter.clone());
                }

                // Configure application
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    me: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                    certify_latency: (10.0, 5.0),
                    should_certify: mocks::application::Certifier::Always,
                };
                let (actor, application) = mocks::application::Application::new(
                    context.child("application"),
                    application_cfg,
                );
                actor.start();
                let blocker = oracle.control(validator.clone());
                let cfg = config::Config {
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    strategy: Sequential,
                    partition: validator.to_string(),
                    mailbox_size: NZUsize!(1024),
                    epoch: Epoch::new(333),
                    floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(
                        Epoch::new(333),
                    )),
                    leader_timeout: Duration::from_millis(100),
                    certification_timeout: Duration::from_millis(200),
                    timeout_retry: Duration::from_millis(500),
                    fetch_timeout: Duration::from_millis(100),
                    activity_timeout,
                    skip_timeout,
                    fetch_concurrent: NZUsize!(4),
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                    forwarding: ForwardingPolicy::Disabled,
                };
                let engine = Engine::new(context.child("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(pending, recovered, resolver));
            }

            // Prepare TLE test data
            let target = Round::new(Epoch::new(333), View::new(10)); // Encrypt for round (epoch 333, view 10)
            let message = b"Secret message for future view10"; // 32 bytes

            // Encrypt message
            let ciphertext = schemes[0].encrypt(&mut context, target, *message);

            // Wait for consensus to reach the target view and then decrypt
            let reporter = monitor_reporter.lock().clone().unwrap();
            loop {
                // Wait for notarization
                context.sleep(Duration::from_millis(100)).await;
                let notarizations = reporter.notarizations.lock();
                let Some(notarization) = notarizations.get(&target.view()) else {
                    continue;
                };

                // Decrypt the message using the seed
                let seed = notarization.seed();
                let decrypted = seed
                    .decrypt(&ciphertext)
                    .expect("Decryption should succeed with valid seed signature");
                assert_eq!(
                    message,
                    decrypted.as_ref(),
                    "Decrypted message should match original message"
                );
                break;
            }
        });
    }

    #[test_traced]
    fn test_tle() {
        tle::<MinPk, Random>();
        tle::<MinSig, Random>();
    }

    fn run_hailstorm<S, F, L>(
        seed: u64,
        shutdowns: usize,
        interval: ViewDelta,
        mut fixture: F,
    ) -> String
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        // Create context
        let n = 5;
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();
        let cfg = deterministic::Config::new().with_seed(seed);
        let executor = deterministic::Runner::new(cfg);
        executor.start(|mut context| async move {
            // Register participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let mut oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &participants, Action::Link(link), None).await;

            // Create engines
            let elector = L::default();
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = BTreeMap::new();
            let mut engine_handlers = BTreeMap::new();
            for (idx, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context
                    .child("validator")
                    .with_attribute("public_key", validator);

                // Configure engine
                let reporter_config = mocks::reporter::Config {
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
                reporters.insert(idx, reporter.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    me: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                    certify_latency: (10.0, 5.0),
                    should_certify: mocks::application::Certifier::Always,
                };
                let (actor, application) = mocks::application::Application::new(
                    context.child("application"),
                    application_cfg,
                );
                actor.start();
                let blocker = oracle.control(validator.clone());
                let cfg = config::Config {
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    strategy: Sequential,
                    partition: validator.to_string(),
                    mailbox_size: NZUsize!(1024),
                    epoch: Epoch::new(333),
                    floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(
                        Epoch::new(333),
                    )),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_concurrent: NZUsize!(4),
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                    forwarding: ForwardingPolicy::Disabled,
                };
                let engine = Engine::new(context.child("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                engine_handlers.insert(idx, engine.start(pending, recovered, resolver));
            }

            // Run shutdowns
            let mut target = View::zero();
            for i in 0..shutdowns {
                // Update target
                target = target.saturating_add(interval);

                // Wait for all engines to finish
                let mut finalizers = Vec::new();
                for reporter in reporters.values_mut() {
                    let (mut latest, mut monitor) = reporter.subscribe().await;
                    finalizers.push(context.child("finalizer").spawn(move |_| async move {
                        while latest < target {
                            latest = monitor.recv().await.expect("event missing");
                        }
                    }));
                }
                join_all(finalizers).await;
                target = target.saturating_add(interval);

                // Select a random engine to shutdown
                let idx = context.random_range(0..engine_handlers.len());
                let validator = &participants[idx];
                let handle = engine_handlers.remove(&idx).unwrap();
                handle.abort();
                let _ = handle.await;
                let selected_reporter = reporters.remove(&idx).unwrap();
                info!(idx, ?validator, "shutdown validator");

                // Wait for all engines to finish
                let mut finalizers = Vec::new();
                for reporter in reporters.values_mut() {
                    let (mut latest, mut monitor) = reporter.subscribe().await;
                    finalizers.push(context.child("finalizer").spawn(move |_| async move {
                        while latest < target {
                            latest = monitor.recv().await.expect("event missing");
                        }
                    }));
                }
                join_all(finalizers).await;
                target = target.saturating_add(interval);

                // Recreate engine
                info!(idx, ?validator, "restarting validator");
                let context = context
                    .child("validator_restarted")
                    .with_attribute("public_key", validator)
                    .with_attribute("restart", i);

                // Start engine
                let (pending, recovered, resolver) =
                    register_validator(&mut oracle, validator.clone()).await;
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    me: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                    certify_latency: (10.0, 5.0),
                    should_certify: mocks::application::Certifier::Always,
                };
                let (actor, application) = mocks::application::Application::new(
                    context.child("application"),
                    application_cfg,
                );
                actor.start();
                reporters.insert(idx, selected_reporter.clone());
                let blocker = oracle.control(validator.clone());
                let cfg = config::Config {
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: selected_reporter,
                    strategy: Sequential,
                    partition: validator.to_string(),
                    mailbox_size: NZUsize!(1024),
                    epoch: Epoch::new(333),
                    floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(
                        Epoch::new(333),
                    )),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_concurrent: NZUsize!(4),
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                    forwarding: ForwardingPolicy::Disabled,
                };
                let engine = Engine::new(context.child("engine"), cfg);
                engine_handlers.insert(idx, engine.start(pending, recovered, resolver));

                // Wait for all engines to hit required containers
                let mut finalizers = Vec::new();
                for reporter in reporters.values_mut() {
                    let (mut latest, mut monitor) = reporter.subscribe().await;
                    finalizers.push(context.child("finalizer").spawn(move |_| async move {
                        while latest < target {
                            latest = monitor.recv().await.expect("event missing");
                        }
                    }));
                }
                join_all(finalizers).await;
                info!(idx, ?validator, "validator recovered");
            }

            // Check reporters for correct activity
            let latest_complete = target.saturating_sub(activity_timeout);
            for reporter in reporters.values() {
                // Ensure no faults
                reporter.assert_no_faults();

                // Ensure no invalid signatures
                reporter.assert_no_invalid();

                // Ensure no forks
                let mut notarized = HashMap::new();
                let mut finalized = HashMap::new();
                {
                    let notarizes = reporter.notarizes.lock();
                    for view in View::range(View::new(1), latest_complete) {
                        // Ensure only one payload proposed per view
                        let Some(payloads) = notarizes.get(&view) else {
                            continue;
                        };
                        if payloads.len() > 1 {
                            panic!("view: {view}");
                        }
                        let (digest, _) = payloads.iter().next().unwrap();
                        notarized.insert(view, *digest);
                    }
                }
                {
                    let notarizations = reporter.notarizations.lock();
                    for view in View::range(View::new(1), latest_complete) {
                        // Ensure notarization matches digest from notarizes
                        let Some(notarization) = notarizations.get(&view) else {
                            continue;
                        };
                        let Some(digest) = notarized.get(&view) else {
                            continue;
                        };
                        assert_eq!(&notarization.proposal.payload, digest);
                    }
                }
                {
                    let finalizes = reporter.finalizes.lock();
                    for view in View::range(View::new(1), latest_complete) {
                        // Ensure only one payload proposed per view
                        let Some(payloads) = finalizes.get(&view) else {
                            continue;
                        };
                        if payloads.len() > 1 {
                            panic!("view: {view}");
                        }
                        let (digest, _) = payloads.iter().next().unwrap();
                        finalized.insert(view, *digest);

                        // Only check at views below timeout
                        if view > latest_complete {
                            continue;
                        }

                        // Ensure no nullifies for any finalizers
                        let nullifies = reporter.nullifies.lock();
                        let Some(nullifies) = nullifies.get(&view) else {
                            continue;
                        };
                        for finalizers in payloads.values() {
                            for finalizer in finalizers.iter() {
                                if nullifies.contains(finalizer) {
                                    panic!("should not nullify and finalize at same view");
                                }
                            }
                        }
                    }
                }
                {
                    let finalizations = reporter.finalizations.lock();
                    for view in View::range(View::new(1), latest_complete) {
                        // Ensure finalization matches digest from finalizes
                        let Some(finalization) = finalizations.get(&view) else {
                            continue;
                        };
                        let Some(digest) = finalized.get(&view) else {
                            continue;
                        };
                        assert_eq!(&finalization.proposal.payload, digest);
                    }
                }
            }

            // Ensure no blocked connections
            let blocked = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty());

            // Return state for audit
            context.auditor().state()
        })
    }

    // The hailstorm run must be deterministic: two runs with identical inputs
    // must produce identical audit state.
    fn hailstorm<S, F, L>(fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S> + Copy,
        L: Elector<S>,
    {
        assert_eq!(
            run_hailstorm::<_, _, L>(0, 10, ViewDelta::new(15), fixture),
            run_hailstorm::<_, _, L>(0, 10, ViewDelta::new(15), fixture),
        );
    }

    test_for_all_fixtures!(hailstorm);

    /// Configuration for a Twins testing campaign.
    ///
    /// A campaign generates adversarial primary/secondary recipient-set
    /// scenarios, splits Byzantine participants into twin halves, and verifies
    /// that honest nodes still finalize blocks after the adversarial prefix
    /// ends.
    ///
    /// # Fields
    ///
    /// - `n`: Total participants. The number of faults is derived as
    ///   `N3f1::max_faults(n)`. Larger `n` increases the per-scenario
    ///   compromised-set space but also makes each case slower to execute.
    ///
    /// - `rounds`: Number of adversarial rounds that form the attack prefix.
    ///   Each round independently places participants relative to the primary
    ///   and secondary recipient sets: outside both, both-halves,
    ///   primary-only, or secondary-only. The two recipient sets may overlap;
    ///   a participant in `both-halves` is visible to both twins in that view.
    ///   After these rounds, the network becomes fully synchronous. More
    ///   rounds exponentially increase the canonical scenario space.
    ///
    /// - `mode`: How multi-round scenarios are constructed. `Sampled` picks
    ///   independent recipient sets per round; `Sustained` repeats a single
    ///   recipient-set pattern across all rounds (modeling a persistent
    ///   adversarial split).
    ///
    /// - `max_cases`: Upper bound on the total emitted cases. Each case is a
    ///   (scenario, compromised-assignment) pair. Also caps scenario
    ///   enumeration (sampling uniformly when the space is larger). Cases
    ///   are shuffled and truncated to this budget.
    ///
    /// - `trailing_finalizations`: Number of finalizations each honest node
    ///   must produce *after* the adversarial prefix before the case is
    ///   considered successful. This is the liveness assertion -- it ensures
    ///   the protocol actually commits blocks under synchrony, not just
    ///   reaches a high view via nullifications.
    #[derive(Clone, Copy, Debug)]
    struct TwinsCampaign {
        n: u32,
        rounds: usize,
        mode: twins::Mode,
        max_cases: usize,
        trailing_finalizations: usize,
    }

    fn twins_campaign<S, F, L>(
        rng: &mut impl CryptoRng,
        campaign: TwinsCampaign,
        link: Link,
        mut fixture: F,
    ) where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        let n = campaign.n;
        let faults = N3f1::max_faults(n) as usize;
        let cases = twins::cases(
            rng,
            twins::Framework {
                participants: n as usize,
                faults,
                rounds: campaign.rounds,
                mode: campaign.mode,
                max_cases: campaign.max_cases,
            },
        );
        assert!(
            !cases.is_empty(),
            "twins campaign should generate at least one case"
        );
        for case in cases {
            let scenario = case.scenario.clone();
            let twin_indices = case.compromised.clone();
            assert_eq!(
                twin_indices.len(),
                faults,
                "unexpected twins count for n={n} (expected f={faults})",
            );

            let activity_timeout = ViewDelta::new(10);
            let skip_timeout = ViewDelta::new(5);
            let namespace = b"consensus".to_vec();
            let link = link.clone();
            let trailing_finalizations = campaign.trailing_finalizations;
            let mut case_fixture =
                |ctx: &mut deterministic::Context, ns: &[u8], n: u32| fixture(ctx, ns, n);
            let cfg = deterministic::Config::new().with_rng(Box::new(StdRng::from_rng(&mut *rng)));
            let executor = deterministic::Runner::new(cfg);
            executor.start(|mut context| async move {
                let Fixture {
                    participants,
                    schemes,
                    ..
                } = case_fixture(&mut context, &namespace, n);
                let participants: Arc<[_]> = participants.into();
                let mut oracle = start_test_network_with_peers(
                    context.child("network"),
                    participants.iter().cloned(),
                    false,
                )
                .await;
                let mut registrations = register_validators(&mut oracle, &participants).await;
                link_validators(&mut oracle, &participants, Action::Link(link), None).await;

                let elector = TwinsElector::new(L::default(), &scenario, n as usize);
                let relay = Arc::new(mocks::relay::Relay::new());
                let mut reporters = Vec::new();
                let mut engine_handlers = Vec::new();
                let twin_index_set: HashSet<usize> = twin_indices.iter().copied().collect();

                // Create twin engines (f Byzantine twins).
                for idx in twin_indices.iter().copied() {
                    let validator = &participants[idx];
                    let (
                        (vote_sender, vote_receiver),
                        (certificate_sender, certificate_receiver),
                        (_resolver_sender, _resolver_receiver),
                    ) = registrations
                        .remove(validator)
                        .expect("validator should be registered");

                    let make_vote_forwarder = || {
                        let participants = participants.clone();
                        let scenario = scenario.clone();
                        move |origin: SplitOrigin, _: &Recipients<_>, message: &IoBuf| {
                            let msg: Vote<S, D> = Vote::decode(message.clone()).unwrap();
                            let (primary, secondary) =
                                scenario.partitions(msg.view(), participants.as_ref());
                            match origin {
                                SplitOrigin::Primary => Some(Recipients::Some(primary)),
                                SplitOrigin::Secondary => Some(Recipients::Some(secondary)),
                            }
                        }
                    };
                    let make_certificate_forwarder = || {
                        let codec = schemes[idx].certificate_codec_config();
                        let participants = participants.clone();
                        let scenario = scenario.clone();
                        move |origin: SplitOrigin, _: &Recipients<_>, message: &IoBuf| {
                            let msg: Certificate<S, D> =
                                Certificate::decode_cfg(&mut message.as_ref(), &codec).unwrap();
                            let (primary, secondary) =
                                scenario.partitions(msg.view(), participants.as_ref());
                            match origin {
                                SplitOrigin::Primary => Some(Recipients::Some(primary)),
                                SplitOrigin::Secondary => Some(Recipients::Some(secondary)),
                            }
                        }
                    };
                    let make_vote_router = || {
                        let participants = participants.clone();
                        let scenario = scenario.clone();
                        move |(sender, message): &(_, IoBuf)| {
                            let msg: Vote<S, D> = Vote::decode(message.clone()).unwrap();
                            scenario.route(msg.view(), sender, participants.as_ref())
                        }
                    };
                    let make_certificate_router = || {
                        let codec = schemes[idx].certificate_codec_config();
                        let participants = participants.clone();
                        let scenario = scenario.clone();
                        move |(sender, message): &(_, IoBuf)| {
                            let msg: Certificate<S, D> =
                                Certificate::decode_cfg(&mut message.as_ref(), &codec).unwrap();
                            scenario.route(msg.view(), sender, participants.as_ref())
                        }
                    };
                    let (vote_sender_primary, vote_sender_secondary) =
                        vote_sender.split_with(make_vote_forwarder());
                    let (vote_receiver_primary, vote_receiver_secondary) = vote_receiver
                        .split_with(
                            context.child("pending_split").with_attribute("index", idx),
                            make_vote_router(),
                        );
                    let (certificate_sender_primary, certificate_sender_secondary) =
                        certificate_sender.split_with(make_certificate_forwarder());
                    let (certificate_receiver_primary, certificate_receiver_secondary) =
                        certificate_receiver.split_with(
                            context
                                .child("recovered_split")
                                .with_attribute("index", idx),
                            make_certificate_router(),
                        );

                    for (twin_label, pending, recovered) in [
                        (
                            "primary",
                            (vote_sender_primary, vote_receiver_primary),
                            (certificate_sender_primary, certificate_receiver_primary),
                        ),
                        (
                            "secondary",
                            (vote_sender_secondary, vote_receiver_secondary),
                            (certificate_sender_secondary, certificate_receiver_secondary),
                        ),
                    ] {
                        let partition = format!("twin_{idx}_{twin_label}");
                        let context = context
                            .child("twin")
                            .with_attribute("index", idx)
                            .with_attribute("side", twin_label);

                        let reporter_config = mocks::reporter::Config {
                            participants: participants.as_ref().try_into().unwrap(),
                            scheme: schemes[idx].clone(),
                            elector: elector.clone(),
                        };
                        let reporter = mocks::reporter::Reporter::new(
                            context.child("reporter"),
                            reporter_config,
                        );
                        reporters.push(reporter.clone());

                        let application_cfg = mocks::application::Config {
                            hasher: Sha256::default(),
                            relay: relay.clone(),
                            me: validator.clone(),
                            propose_latency: (10.0, 5.0),
                            verify_latency: (10.0, 5.0),
                            certify_latency: (10.0, 5.0),
                            should_certify: mocks::application::Certifier::Always,
                        };
                        let (actor, application) = mocks::application::Application::new(
                            context.child("application"),
                            application_cfg,
                        );
                        actor.start();

                        let blocker = oracle.control(validator.clone());
                        let cfg = config::Config {
                            scheme: schemes[idx].clone(),
                            elector: elector.clone(),
                            blocker,
                            automaton: application.clone(),
                            relay: application.clone(),
                            reporter: reporter.clone(),
                            strategy: Sequential,
                            partition,
                            mailbox_size: NZUsize!(1024),
                            epoch: Epoch::new(333),
                            floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(
                                Epoch::new(333),
                            )),
                            leader_timeout: Duration::from_secs(1),
                            certification_timeout: Duration::from_millis(1_500),
                            timeout_retry: Duration::from_secs(10),
                            fetch_timeout: Duration::from_secs(1),
                            activity_timeout,
                            skip_timeout,
                            fetch_concurrent: NZUsize!(4),
                            replay_buffer: NZUsize!(1024 * 1024),
                            write_buffer: NZUsize!(1024 * 1024),
                            page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                            forwarding: ForwardingPolicy::Disabled,
                        };
                        let engine = Engine::new(context.child("engine"), cfg);
                        engine_handlers.push(engine.start(
                            pending,
                            recovered,
                            inert_channel(participants.as_ref()),
                        ));
                    }
                }

                // Create honest engines.
                let honest_start = reporters.len();
                for (idx, validator) in participants.iter().enumerate() {
                    if twin_index_set.contains(&idx) {
                        continue;
                    }

                    let partition = format!("honest_{idx}");
                    let context = context.child("honest").with_attribute("index", idx);

                    let reporter_config = mocks::reporter::Config {
                        participants: participants.as_ref().try_into().unwrap(),
                        scheme: schemes[idx].clone(),
                        elector: elector.clone(),
                    };
                    let reporter =
                        mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
                    reporters.push(reporter.clone());

                    let application_cfg = mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        me: validator.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                        certify_latency: (10.0, 5.0),
                        should_certify: mocks::application::Certifier::Always,
                    };
                    let (actor, application) = mocks::application::Application::new(
                        context.child("application"),
                        application_cfg,
                    );
                    actor.start();

                    let blocker = oracle.control(validator.clone());
                    let cfg = config::Config {
                        scheme: schemes[idx].clone(),
                        elector: elector.clone(),
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: reporter.clone(),
                        strategy: Sequential,
                        partition,
                        mailbox_size: NZUsize!(1024),
                        epoch: Epoch::new(333),
                        floor: config::Floor::Genesis(mocks::application::genesis::<Sha256>(
                            Epoch::new(333),
                        )),
                        leader_timeout: Duration::from_secs(1),
                        certification_timeout: Duration::from_millis(1_500),
                        timeout_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        skip_timeout,
                        fetch_concurrent: NZUsize!(4),
                        replay_buffer: NZUsize!(1024 * 1024),
                        write_buffer: NZUsize!(1024 * 1024),
                        page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                        forwarding: ForwardingPolicy::Disabled,
                    };
                    let engine = Engine::new(context.child("engine"), cfg);

                    let (
                        (pending_sender, pending_receiver),
                        (recovered_sender, recovered_receiver),
                        _,
                    ) = registrations
                        .remove(validator)
                        .expect("validator should be registered");
                    engine_handlers.push(engine.start(
                        (pending_sender, pending_receiver),
                        (recovered_sender, recovered_receiver),
                        inert_channel(participants.as_ref()),
                    ));
                }

                // Wait for progress (liveness check) across honest replicas only.
                //
                // Only count finalizations after the adversarial prefix so we
                // verify the protocol actually recovers and makes progress under
                // synchrony. Finalizations during the prefix may be artifacts of
                // the attack setup and do not demonstrate liveness.
                //
                // Twin halves are Byzantine test machinery and are not required to
                // make progress for the campaign to establish honest-node liveness.
                let prefix_end = View::new(scenario.rounds().len() as u64);
                let mut finalizers = Vec::new();
                for (i, reporter) in reporters.iter_mut().skip(honest_start).enumerate() {
                    let (_latest, mut monitor) = reporter.subscribe().await;
                    let required = trailing_finalizations;
                    finalizers.push(context.child("finalizer").with_attribute("index", i).spawn(
                        move |_| async move {
                            let mut count = 0usize;
                            while count < required {
                                let view = monitor.recv().await.expect("event missing");
                                if view > prefix_end {
                                    count += 1;
                                }
                            }
                        },
                    ));
                }
                join_all(finalizers).await;

                // Verify safety: no conflicting finalizations across honest reporters.
                let mut finalized_at_view: BTreeMap<View, D> = BTreeMap::new();
                for reporter in reporters.iter().skip(honest_start) {
                    let finalizations = reporter.finalizations.lock();
                    for (view, finalization) in finalizations.iter() {
                        let digest = finalization.proposal.payload;
                        if let Some(existing) = finalized_at_view.get(view) {
                            assert_eq!(
                                existing, &digest,
                                "safety violation: conflicting finalizations at view {view}"
                            );
                        } else {
                            finalized_at_view.insert(*view, digest);
                        }
                    }
                }

                // Verify no invalid signatures were observed by honest replicas.
                for reporter in reporters.iter().skip(honest_start) {
                    reporter.assert_no_invalid();
                }

                // Ensure no honest signer appears under multiple payloads for the same view.
                let twin_identities: HashSet<_> = twin_indices
                    .iter()
                    .map(|idx| participants[*idx].clone())
                    .collect();
                let mut notarized_by_honest_signer: BTreeMap<View, HashMap<PublicKey, D>> =
                    BTreeMap::new();
                let mut finalized_by_honest_signer: BTreeMap<View, HashMap<PublicKey, D>> =
                    BTreeMap::new();
                for reporter in reporters.iter().skip(honest_start) {
                    let notarizes = reporter.notarizes.lock();
                    for (view, payloads) in notarizes.iter() {
                        let signers = notarized_by_honest_signer.entry(*view).or_default();
                        for (digest, payload_signers) in payloads.iter() {
                            for signer in payload_signers.iter() {
                                if twin_identities.contains(signer) {
                                    continue;
                                }
                                if let Some(existing) = signers.insert(signer.clone(), *digest) {
                                    assert_eq!(
                                    existing, *digest,
                                    "honest signer produced conflicting notarizes at view {view}"
                                );
                                }
                            }
                        }
                    }

                    let finalizes = reporter.finalizes.lock();
                    for (view, payloads) in finalizes.iter() {
                        let signers = finalized_by_honest_signer.entry(*view).or_default();
                        for (digest, payload_signers) in payloads.iter() {
                            for signer in payload_signers.iter() {
                                if twin_identities.contains(signer) {
                                    continue;
                                }
                                if let Some(existing) = signers.insert(signer.clone(), *digest) {
                                    assert_eq!(
                                    existing, *digest,
                                    "honest signer produced conflicting finalizes at view {view}"
                                );
                                }
                            }
                        }
                    }
                }

                // Ensure faults are attributable to twins.
                for reporter in reporters.iter().skip(honest_start) {
                    let faults = reporter.faults.lock();
                    for faulter in faults.keys() {
                        assert!(
                            twin_identities.contains(faulter),
                            "fault from non-twin participant"
                        );
                    }
                }

                let blocked = oracle.blocked().await.unwrap();
                for (_, faulter) in blocked {
                    assert!(
                        twin_identities.contains(&faulter),
                        "blocked peer attributed to non-twin participant"
                    );
                }
            });
        }
    }

    const TWINS_CAMPAIGN: TwinsCampaign = TwinsCampaign {
        n: 5,
        rounds: 3,
        mode: twins::Mode::Sampled,
        max_cases: 20,
        trailing_finalizations: 10,
    };

    const TWINS_LINK: Link = Link {
        latency: Duration::from_millis(500),
        jitter: Duration::from_millis(500),
        success_rate: 1.0,
    };

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn test_twins_sampled() {
        for link in [
            Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(10),
                success_rate: 1.0,
            },
            TWINS_LINK,
        ] {
            twins_campaign::<_, _, RoundRobin>(
                &mut test_rng(),
                TWINS_CAMPAIGN,
                link,
                scheme_mocks::fixture,
            );
        }
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn test_twins_sustained() {
        let campaign = TwinsCampaign {
            mode: twins::Mode::Sustained,
            ..TWINS_CAMPAIGN
        };
        for link in [
            Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(10),
                success_rate: 1.0,
            },
            TWINS_LINK,
        ] {
            twins_campaign::<_, _, RoundRobin>(
                &mut test_rng(),
                campaign,
                link,
                scheme_mocks::fixture,
            );
        }
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn test_twins_large_sampled() {
        let campaign = TwinsCampaign {
            n: 10,
            rounds: 5,
            ..TWINS_CAMPAIGN
        };
        twins_campaign::<_, _, RoundRobin>(
            &mut test_rng(),
            campaign,
            TWINS_LINK,
            scheme_mocks::fixture,
        );
    }

    #[test_group("slow")]
    #[test_traced("INFO")]
    fn test_twins_large_sustained() {
        let campaign = TwinsCampaign {
            n: 10,
            rounds: 5,
            mode: twins::Mode::Sustained,
            ..TWINS_CAMPAIGN
        };
        twins_campaign::<_, _, RoundRobin>(
            &mut test_rng(),
            campaign,
            TWINS_LINK,
            scheme_mocks::fixture,
        );
    }

    fn twins<S, F, L>(fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        twins_campaign::<_, _, L>(&mut test_rng(), TWINS_CAMPAIGN, TWINS_LINK, fixture);
    }

    test_for_all_fixtures!(twins, level = "INFO");
}
