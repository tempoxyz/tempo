//! Mock application used by `simplex` tests to produce and verify payloads,
//! simulating proposal/verification latency and broadcasting via a mock relay.

use super::relay::Relay;
use crate::{
    simplex::{types::Context, Plan},
    types::{Epoch, Round},
    Automaton as Au, CertifiableAutomaton as CAu, Relay as Re,
};
use bytes::Bytes;
use commonware_actor::Feedback;
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_macros::select_loop;
use commonware_p2p::Recipients;
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Spawner};
use commonware_utils::channel::{
    fallible::{FallibleExt, OneshotExt},
    mpsc, oneshot,
};
use rand::{Rng, RngExt as _};
use rand_distr::{Distribution, Normal};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
use tracing::debug;

pub enum Message<D: Digest, P: PublicKey> {
    Propose {
        context: Context<D, P>,
        response: oneshot::Sender<D>,
    },
    Verify {
        context: Context<D, P>,
        payload: D,
        response: oneshot::Sender<bool>,
    },
    Certify {
        round: Round,
        payload: D,
        response: oneshot::Sender<bool>,
    },
    Broadcast {
        payload: D,
        plan: Plan<P>,
    },
}

#[derive(Clone)]
pub struct Mailbox<D: Digest, P: PublicKey> {
    sender: mpsc::UnboundedSender<Message<D, P>>,
}

impl<D: Digest, P: PublicKey> Mailbox<D, P> {
    pub(super) const fn new(sender: mpsc::UnboundedSender<Message<D, P>>) -> Self {
        Self { sender }
    }
}

impl<D: Digest, P: PublicKey> Au for Mailbox<D, P> {
    type Digest = D;
    type Context = Context<D, P>;

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send_lossy(Message::Propose { context, response });
        receiver
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let (response, receiver) = oneshot::channel();
        self.sender.send_lossy(Message::Verify {
            context,
            payload,
            response,
        });
        receiver
    }
}

impl<D: Digest, P: PublicKey> CAu for Mailbox<D, P> {
    async fn certify(&mut self, round: Round, payload: Self::Digest) -> oneshot::Receiver<bool> {
        let (tx, rx) = oneshot::channel();
        self.sender.send_lossy(Message::Certify {
            round,
            payload,
            response: tx,
        });
        rx
    }
}

impl<D: Digest, P: PublicKey> Re for Mailbox<D, P> {
    type Digest = D;
    type PublicKey = P;
    type Plan = Plan<P>;

    fn broadcast(&mut self, payload: Self::Digest, plan: Plan<P>) -> Feedback {
        if self.sender.send_lossy(Message::Broadcast { payload, plan }) {
            Feedback::Ok
        } else {
            Feedback::Closed
        }
    }
}

const GENESIS_BYTES: &[u8] = b"genesis";

pub fn genesis<H: Hasher>(epoch: Epoch) -> H::Digest {
    let mut hasher = H::default();
    hasher.update(&(Bytes::from(GENESIS_BYTES), epoch).encode());
    hasher.finalize()
}

type Latency = (f64, f64);

/// Observer invoked on every `Message::Propose` request. Used by tests to
/// detect spurious propose calls.
type ProposeObserver<H, P> = Box<dyn Fn(Context<<H as Hasher>::Digest, P>) + Send + 'static>;

/// Observer invoked on every `Message::Verify` request. Used by tests to
/// detect spurious verification calls.
type VerifyObserver<H, P> =
    Box<dyn Fn(Context<<H as Hasher>::Digest, P>, <H as Hasher>::Digest) + Send + 'static>;

/// Predicate to determine whether a payload should be certified.
/// Returning true means certify, false means reject.
pub enum Certifier<D: Digest> {
    /// Always certify.
    Always,
    /// A custom predicate function that receives the round and payload digest.
    Custom(Box<dyn Fn(Round, D) -> bool + Send + 'static>),
    /// Drop the sender without responding, causing the receiver to be cancelled.
    /// This simulates scenarios where the automaton cannot determine certification
    /// (e.g., missing verification context in Marshaled).
    Cancel,
    /// Hold the sender alive without ever responding, simulating a certify that
    /// hangs indefinitely (e.g., block never arrives for reconstruction because
    /// the proposer is dead and shard gossip didn't deliver enough shards).
    Pending,
}

pub struct Config<H: Hasher, P: PublicKey> {
    pub hasher: H,

    pub relay: Arc<Relay<H::Digest, P>>,

    /// The public key of the participant.
    ///
    /// It is common to use multiple instances of an application in a single simulation, this
    /// helps to identify the source of both progress and errors.
    pub me: P,

    pub propose_latency: Latency,
    pub verify_latency: Latency,
    pub certify_latency: Latency,

    /// Predicate to determine whether a payload should be certified.
    pub should_certify: Certifier<H::Digest>,
}

pub struct Application<E: Clock + Rng + Spawner, H: Hasher, P: PublicKey> {
    context: ContextCell<E>,
    hasher: H,
    me: P,

    relay: Arc<Relay<H::Digest, P>>,
    broadcast: mpsc::UnboundedReceiver<(H::Digest, Bytes)>,

    mailbox: mpsc::UnboundedReceiver<Message<H::Digest, P>>,

    propose_latency: Normal<f64>,
    verify_latency: Normal<f64>,
    certify_latency: Normal<f64>,

    fail_verification: bool,
    drop_proposals: bool,
    stall_proposals: bool,
    drop_verifications: bool,
    should_certify: Certifier<H::Digest>,

    pending: HashMap<H::Digest, Bytes>,
    seen: HashMap<H::Digest, Bytes>,

    verified: HashSet<H::Digest>,

    /// Invoked on every `Message::Propose` request received by the application.
    /// Used by tests to detect spurious local-leader propose attempts (e.g. after replay).
    propose_observer: Option<ProposeObserver<H, P>>,

    /// Invoked on every `Message::Verify` request received by the application.
    /// Used by tests to detect spurious verification requests (e.g. after replay
    /// of a leader-owned proposal).
    verify_observer: Option<VerifyObserver<H, P>>,

    /// Senders held alive to simulate proposals that hang indefinitely
    /// (used when `stall_proposals` is set).
    pending_proposes: Vec<oneshot::Sender<H::Digest>>,

    /// Senders held alive to simulate certifications that hang indefinitely
    /// (used by [`Certifier::Pending`]).
    pending_certifications: Vec<oneshot::Sender<bool>>,
}

impl<E: Clock + Rng + Spawner, H: Hasher, P: PublicKey> Application<E, H, P> {
    pub fn new(context: E, cfg: Config<H, P>) -> (Self, Mailbox<H::Digest, P>) {
        // Register self on relay
        let broadcast = cfg.relay.register(cfg.me.clone());

        // Generate samplers
        let propose_latency = Normal::new(cfg.propose_latency.0, cfg.propose_latency.1).unwrap();
        let verify_latency = Normal::new(cfg.verify_latency.0, cfg.verify_latency.1).unwrap();
        let certify_latency = Normal::new(cfg.certify_latency.0, cfg.certify_latency.1).unwrap();

        // Return constructed application
        let (sender, receiver) = mpsc::unbounded_channel();
        (
            Self {
                context: ContextCell::new(context),
                hasher: cfg.hasher,
                me: cfg.me,

                relay: cfg.relay,
                broadcast,

                mailbox: receiver,

                propose_latency,
                verify_latency,
                certify_latency,

                fail_verification: false,
                drop_proposals: false,
                stall_proposals: false,
                drop_verifications: false,
                should_certify: cfg.should_certify,

                pending: HashMap::new(),
                seen: HashMap::new(),
                verified: HashSet::new(),
                propose_observer: None,
                verify_observer: None,
                pending_proposes: Vec::new(),
                pending_certifications: Vec::new(),
            },
            Mailbox::new(sender),
        )
    }

    pub const fn set_fail_verification(&mut self, fail: bool) {
        self.fail_verification = fail;
    }

    pub const fn set_drop_proposals(&mut self, drop: bool) {
        self.drop_proposals = drop;
    }

    /// When set, `Message::Propose` requests are held open indefinitely: the
    /// response sender is parked in `pending_proposes`, keeping the oneshot
    /// alive so the caller's `receiver` never resolves. This simulates a
    /// propose that is still in flight at the moment the voter crashes.
    pub const fn set_stall_proposals(&mut self, stall: bool) {
        self.stall_proposals = stall;
    }

    pub const fn set_drop_verifications(&mut self, drop: bool) {
        self.drop_verifications = drop;
    }

    pub fn set_propose_observer(&mut self, observer: ProposeObserver<H, P>) {
        self.propose_observer = Some(observer);
    }

    pub fn set_verify_observer(&mut self, observer: VerifyObserver<H, P>) {
        self.verify_observer = Some(observer);
    }

    #[cfg(not(feature = "mocks"))]
    fn panic(&self, msg: &str) -> ! {
        panic!("[{:?}] {}", self.me, msg);
    }

    /// When proposing a block, we do not care if the parent is verified (or even in our possession).
    /// Backfilling verification dependencies is considered out-of-scope for consensus.
    async fn propose(&mut self, context: Context<H::Digest, P>) -> H::Digest {
        // Simulate the propose latency
        let duration = self.propose_latency.sample(self.context.as_mut());
        self.context
            .sleep(Duration::from_millis(duration as u64))
            .await;

        // Generate the payload
        let rand = self.context.random::<u64>();
        let payload = (context.round, context.parent.1, rand).encode();
        self.hasher.update(&payload);
        let digest = self.hasher.finalize();

        // Mark verified
        self.verified.insert(digest);

        // Store pending payload
        self.pending.insert(digest, payload);
        digest
    }

    async fn verify(
        &mut self,
        context: Context<H::Digest, P>,
        payload: H::Digest,
        mut contents: Bytes,
    ) -> bool {
        // Simulate the verify latency
        let duration = self.verify_latency.sample(self.context.as_mut());
        self.context
            .sleep(Duration::from_millis(duration as u64))
            .await;

        // Check if we should fail verification
        if self.fail_verification {
            return false;
        }

        // Verify contents
        let Ok((parsed_round, parent, _)) = <(Round, H::Digest, u64)>::decode(&mut contents) else {
            #[cfg(feature = "mocks")]
            {
                // During fuzzing, return false for invalid payloads
                return false;
            }
            #[cfg(not(feature = "mocks"))]
            panic!("[{:?}] invalid payload", self.me);
        };

        if parsed_round != context.round {
            #[cfg(feature = "mocks")]
            {
                // During fuzzing, return false for round mismatches
                return false;
            }
            #[cfg(not(feature = "mocks"))]
            self.panic(&format!(
                "invalid round (in payload): {} != {}",
                parsed_round, context.round
            ));
        }
        if parent != context.parent.1 {
            #[cfg(feature = "mocks")]
            {
                // During fuzzing, return false for parent mismatches
                return false;
            }
            #[cfg(not(feature = "mocks"))]
            self.panic(&format!(
                "invalid parent (in payload): {:?} != {:?}",
                parent, context.parent.1
            ));
        }
        // We don't care about the random number
        self.verified.insert(payload);
        true
    }

    async fn certify(
        &mut self,
        round: Round,
        payload: H::Digest,
        _contents: Bytes,
    ) -> Option<bool> {
        // Simulate the certify latency
        let duration = self.certify_latency.sample(self.context.as_mut());
        self.context
            .sleep(Duration::from_millis(duration as u64))
            .await;

        // Use configured predicate to determine certification
        match &self.should_certify {
            Certifier::Always => Some(true),
            Certifier::Custom(func) => Some(func(round, payload)),
            Certifier::Cancel | Certifier::Pending => None,
        }
    }

    fn broadcast(&mut self, payload: H::Digest, plan: Plan<P>) {
        let (contents, recipients) = match plan {
            Plan::Propose { .. } => {
                let contents = self.pending.remove(&payload).expect("missing payload");
                self.seen.insert(payload, contents.clone());
                (contents, Recipients::All)
            }
            Plan::Forward { recipients, .. } => {
                let contents = match self.seen.get(&payload).cloned() {
                    Some(contents) => contents,
                    None => {
                        let Some(contents) = self.pending.get(&payload).cloned() else {
                            debug!("payload not found for forwarding");
                            return;
                        };
                        self.seen.insert(payload, contents.clone());
                        contents
                    }
                };
                (contents, recipients)
            }
        };
        self.relay
            .broadcast(&self.me, recipients, (payload, contents));
    }

    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        // Setup digest tracking
        #[allow(clippy::type_complexity)]
        let mut waiters: HashMap<
            H::Digest,
            Vec<(Context<H::Digest, P>, oneshot::Sender<bool>)>,
        > = HashMap::new();

        // Handle actions
        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping application");
            },
            Some(message) = self.mailbox.recv() else break => {
                match message {
                    Message::Propose { context, response } => {
                        if let Some(observer) = &self.propose_observer {
                            observer(context.clone());
                        }
                        if self.stall_proposals {
                            self.pending_proposes.push(response);
                            continue;
                        }
                        if self.drop_proposals {
                            continue;
                        }
                        let digest = self.propose(context).await;
                        response.send_lossy(digest);
                    }
                    Message::Verify {
                        context,
                        payload,
                        response,
                    } => {
                        if let Some(observer) = &self.verify_observer {
                            observer(context.clone(), payload);
                        }
                        if self.drop_verifications {
                            continue;
                        }
                        if let Some(contents) = self.seen.get(&payload) {
                            let verified = self.verify(context, payload, contents.clone()).await;
                            response.send_lossy(verified);
                        } else {
                            waiters
                                .entry(payload)
                                .or_default()
                                .push((context, response));
                        }
                    }
                    Message::Certify {
                        round,
                        payload,
                        response,
                    } => {
                        let contents = self.seen.get(&payload).cloned().unwrap_or_default();
                        if let Some(certified) = self.certify(round, payload, contents).await {
                            response.send_lossy(certified);
                        } else if matches!(self.should_certify, Certifier::Pending) {
                            // Hold the sender alive so the receiver never resolves.
                            // This simulates a certify that hangs indefinitely (e.g.,
                            // block never arrives for reconstruction).
                            self.pending_certifications.push(response);
                        }
                        // Cancel: drop sender -> immediate RecvError on receiver.
                    }
                    Message::Broadcast { payload, plan } => {
                        self.broadcast(payload, plan);
                    }
                }
            },
            Some((digest, contents)) = self.broadcast.recv() else break => {
                // Record digest for future use
                self.seen.insert(digest, contents.clone());

                // Check if we have a waiter
                if let Some(waiters) = waiters.remove(&digest) {
                    for (context, sender) in waiters {
                        let verified = self.verify(context, digest, contents.clone()).await;
                        sender.send_lossy(verified);
                    }
                }
            },
        }
    }
}
