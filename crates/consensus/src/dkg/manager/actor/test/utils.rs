//! Test doubles and construction helpers for the DKG manager actor.

use std::{
    collections::BTreeMap,
    io,
    num::{NonZeroU64, NonZeroUsize},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::SystemTime,
};

use alloy_consensus::Header;
use commonware_actor::{Feedback, Unreliable};
use commonware_codec::Encode as _;
use commonware_consensus::{
    Heightable as _, Reporter as _,
    marshal::{Update, core::DigestFallback},
    types::{Epoch, Epocher as _, FixedEpocher, Height},
};
use commonware_cryptography::{
    Signer as _,
    bls12381::{
        dkg::feldman_desmedt::{
            self as dkg, DealerPrivMsg, DealerPubMsg, Logs, Output, SignedDealerLog,
        },
        primitives::{group::Share, sharing::Sharing, variant::MinSig},
    },
    ed25519::{Batch, PrivateKey, PublicKey},
    transcript::Summary,
};
use commonware_math::algebra::Random as _;
use commonware_p2p::{CheckedSender, LimitedSender, Receiver, Recipients};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock, Handle, IoBufs, Supervisor as _, deterministic::Context,
    telemetry::metrics::histogram::Timed,
};
use commonware_utils::{
    Acknowledgement as _, N3f1, TryFromIterator as _, acknowledgement::Exact, ordered,
};
use futures::{StreamExt as _, channel::mpsc};
use rand_core::CryptoRng;
use reth_node_core::primitives::SealedBlock;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_primitives::{BlockBody, TempoHeader};

use super::super::{
    super::{Config, Mailbox, init},
    Block, Digest, EpochManager, ExecutionLayer, Marshal, State,
    state::{self, Round, ShareState},
};

pub(super) struct TestDkg {
    context: Context,
    partition_prefix: String,
    me: PrivateKey,
    last_finalized_height: Height,
    initial_state: Option<State>,
    storage: Option<state::Storage<Context>>,
    mailbox: Option<Mailbox>,
    handle: Option<Handle<()>>,
    sender: RecordingSender,
    network: Option<TestNetwork>,
    pub(super) execution_node: StubExecutionProvider,
    pub(super) marshal: StubMarshal,
    pub(super) epoch_manager: StubEpochManager,
}

impl TestDkg {
    pub(super) const INITIAL_EPOCH: Epoch = Epoch::new(1);
    const EPOCH_LENGTH: NonZeroU64 = NonZeroU64::new(10).unwrap();

    pub(super) fn epoch_strategy() -> FixedEpocher {
        FixedEpocher::new(Self::EPOCH_LENGTH)
    }

    pub(super) async fn new(context: Context, partition_prefix: impl Into<String>) -> Self {
        Self::from_state(context, partition_prefix, None).await
    }

    pub(super) async fn with_initial_state(
        mut context: Context,
        partition_prefix: impl Into<String>,
    ) -> Self {
        let (initial_state, _) = dkg_state(&mut context, Self::INITIAL_EPOCH, 4, false);
        Self::from_state(context, partition_prefix, initial_state).await
    }

    pub(super) async fn from_state(
        context: Context,
        partition_prefix: impl Into<String>,
        initial_state: impl Into<Option<State>>,
    ) -> Self {
        let partition_prefix = partition_prefix.into();
        let initial_state = initial_state.into();
        let storage = if let Some(state) = initial_state.clone() {
            Some(
                state::builder()
                    .partition_prefix(&partition_prefix)
                    .init_unverified(context.child("storage"))
                    .await
                    .unwrap()
                    .init_verified(state)
                    .await
                    .unwrap(),
            )
        } else {
            None
        };

        Self {
            context,
            partition_prefix,
            me: PrivateKey::from_seed(0),
            last_finalized_height: Height::new(9),
            initial_state,
            storage,
            mailbox: None,
            handle: None,
            sender: RecordingSender::default(),
            network: None,
            execution_node: StubExecutionProvider::default(),
            marshal: StubMarshal::default(),
            epoch_manager: StubEpochManager::default(),
        }
    }

    pub(super) fn initial_state(&self) -> &State {
        self.initial_state
            .as_ref()
            .expect("DKG state was not initialized by the harness")
    }

    pub(super) fn with_me(mut self, me: PrivateKey) -> Self {
        self.me = me;
        self
    }

    pub(super) fn with_last_finalized_height(mut self, height: Height) -> Self {
        self.last_finalized_height = height;
        self
    }

    pub(super) fn with_execution_node(mut self, execution_node: StubExecutionProvider) -> Self {
        self.execution_node = execution_node;
        self
    }

    pub(super) fn with_network(mut self, network: TestNetwork) -> Self {
        self.network = Some(network);
        self
    }

    pub(super) fn storage(&self) -> &state::Storage<Context> {
        self.storage
            .as_ref()
            .expect("DKG storage is not open while the actor is running")
    }

    pub(super) fn storage_mut(&mut self) -> &mut state::Storage<Context> {
        self.storage
            .as_mut()
            .expect("DKG storage is not open while the actor is running")
    }

    pub(super) async fn start(&mut self) {
        assert!(self.handle.is_none(), "DKG actor is already running");
        drop(self.storage.take());
        let (actor, mailbox) = init(
            self.context.child("actor"),
            Config {
                epoch_strategy: Self::epoch_strategy(),
                epoch_manager: self.epoch_manager.clone(),
                namespace: crate::config::NAMESPACE.to_vec(),
                me: self.me.clone(),
                mailbox_size: NonZeroUsize::new(1).unwrap(),
                marshal: self.marshal.clone(),
                last_finalized_height: self.last_finalized_height,
                partition_prefix: self.partition_prefix.clone(),
                execution_node: self.execution_node.clone(),
                initial_share: None,
            },
        )
        .await
        .unwrap();

        self.mailbox = Some(mailbox);
        self.handle = Some(match &self.network {
            Some(network) => actor.start(network.register(self.me.public_key())),
            None => actor.start((self.sender.clone(), InertReceiver)),
        });
    }

    pub(super) fn mailbox(&self) -> &Mailbox {
        self.mailbox.as_ref().expect("DKG actor is not running")
    }

    pub(super) fn sender(&self) -> &RecordingSender {
        &self.sender
    }

    pub(super) async fn report_finalized_header(&mut self, header: TempoHeader) {
        let (acknowledgement, waiter) = Exact::handle();
        assert!(
            self.mailbox
                .as_mut()
                .expect("DKG actor is not running")
                .report(Update::Block(Arc::new(block(header)), acknowledgement))
                .accepted()
        );
        waiter
            .await
            .expect("finalized block should be acknowledged");
    }

    pub(super) async fn has_dealer_log(&self, epoch: Epoch) -> bool {
        self.mailbox()
            .get_dealer_log(epoch)
            .await
            .unwrap()
            .is_some()
    }

    pub(super) async fn stop(&mut self) {
        self.mailbox.take();
        if let Some(handle) = self.handle.take() {
            handle.await.expect("DKG actor should stop");
        }
        self.reopen_storage().await;
    }

    pub(super) async fn wait_for_exit(&mut self) {
        let handle = self.handle.take().expect("DKG actor is not running");
        handle.await.expect("DKG actor should stop");
        self.mailbox.take();
        self.reopen_storage().await;
    }

    async fn reopen_storage(&mut self) {
        let unverified = state::builder()
            .partition_prefix(&self.partition_prefix)
            .init_unverified(self.context.child("storage"))
            .await
            .unwrap();
        self.storage = if let Some(state) = unverified.state().cloned() {
            Some(unverified.init_verified(state).await.unwrap())
        } else {
            None
        };
    }
}

impl Drop for TestDkg {
    fn drop(&mut self) {
        self.mailbox.take();
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

#[derive(Debug)]
pub(super) struct InertReceiver;

impl Receiver for InertReceiver {
    type Error = io::Error;
    type PublicKey = PublicKey;

    async fn recv(&mut self) -> Result<commonware_p2p::Message<Self::PublicKey>, Self::Error> {
        std::future::pending().await
    }
}

#[derive(Clone, Default)]
pub(super) struct TestNetwork {
    state: Arc<NetworkState>,
}

#[derive(Default)]
struct NetworkState {
    routes: Mutex<BTreeMap<PublicKey, mpsc::UnboundedSender<commonware_p2p::Message<PublicKey>>>>,
    deliveries: Mutex<Vec<(PublicKey, PublicKey)>>,
}

impl TestNetwork {
    pub(super) fn register(&self, public_key: PublicKey) -> (NetworkSender, NetworkReceiver) {
        let (sender, receiver) = mpsc::unbounded();
        self.state
            .routes
            .lock()
            .unwrap()
            .insert(public_key.clone(), sender);
        (
            NetworkSender {
                from: public_key,
                state: self.state.clone(),
            },
            NetworkReceiver { receiver },
        )
    }

    pub(super) fn deliveries_between(&self, from: &PublicKey, to: &PublicKey) -> usize {
        self.state
            .deliveries
            .lock()
            .unwrap()
            .iter()
            .filter(|(sender, recipient)| sender == from && recipient == to)
            .count()
    }
}

#[derive(Clone)]
pub(super) struct NetworkSender {
    from: PublicKey,
    state: Arc<NetworkState>,
}

pub(super) struct NetworkCheckedSender {
    from: PublicKey,
    state: Arc<NetworkState>,
    recipients: Vec<PublicKey>,
}

impl LimitedSender for NetworkSender {
    type PublicKey = PublicKey;
    type Checked<'a> = NetworkCheckedSender;

    fn check(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
    ) -> Result<Self::Checked<'_>, SystemTime> {
        let routes = self.state.routes.lock().unwrap();
        let recipients = match recipients {
            Recipients::One(recipient) => vec![recipient],
            Recipients::Some(recipients) => recipients,
            Recipients::All => routes.keys().cloned().collect(),
        }
        .into_iter()
        .filter(|recipient| routes.contains_key(recipient))
        .collect();
        drop(routes);

        Ok(NetworkCheckedSender {
            from: self.from.clone(),
            state: self.state.clone(),
            recipients,
        })
    }
}

impl CheckedSender for NetworkCheckedSender {
    type PublicKey = PublicKey;

    fn recipients(&self) -> Vec<Self::PublicKey> {
        self.recipients.clone()
    }

    fn send(self, message: impl Into<IoBufs> + Send, _priority: bool) -> Unreliable<Feedback> {
        let message = message.into().coalesce();
        let routes = self.state.routes.lock().unwrap();
        for recipient in &self.recipients {
            if routes.get(recipient).is_some_and(|sender| {
                sender
                    .unbounded_send((self.from.clone(), message.clone()))
                    .is_ok()
            }) {
                self.state
                    .deliveries
                    .lock()
                    .unwrap()
                    .push((self.from.clone(), recipient.clone()));
            }
        }
        Unreliable::new(Feedback::Ok)
    }
}

#[derive(Debug)]
pub(super) struct NetworkReceiver {
    receiver: mpsc::UnboundedReceiver<commonware_p2p::Message<PublicKey>>,
}

impl Receiver for NetworkReceiver {
    type Error = io::Error;
    type PublicKey = PublicKey;

    async fn recv(&mut self) -> Result<commonware_p2p::Message<Self::PublicKey>, Self::Error> {
        self.receiver
            .next()
            .await
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))
    }
}

#[derive(Clone, Default)]
pub(super) struct RecordingSender {
    sends: Arc<AtomicUsize>,
}

impl RecordingSender {
    pub(super) fn send_count(&self) -> usize {
        self.sends.load(Ordering::SeqCst)
    }
}

pub(super) struct RecordingCheckedSender {
    sends: Arc<AtomicUsize>,
    recipients: Vec<PublicKey>,
}

impl LimitedSender for RecordingSender {
    type PublicKey = PublicKey;
    type Checked<'a> = RecordingCheckedSender;

    fn check(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
    ) -> Result<Self::Checked<'_>, SystemTime> {
        let recipients = match recipients {
            Recipients::One(recipient) => vec![recipient],
            Recipients::Some(recipients) => recipients,
            Recipients::All => Vec::new(),
        };
        Ok(RecordingCheckedSender {
            sends: self.sends.clone(),
            recipients,
        })
    }
}

impl CheckedSender for RecordingCheckedSender {
    type PublicKey = PublicKey;

    fn recipients(&self) -> Vec<Self::PublicKey> {
        self.recipients.clone()
    }

    fn send(self, _message: impl Into<IoBufs> + Send, _priority: bool) -> Unreliable<Feedback> {
        self.sends.fetch_add(1, Ordering::SeqCst);
        Unreliable::new(Feedback::Ok)
    }
}

#[derive(Clone, Default)]
pub(super) struct StubExecutionProvider {
    headers: Arc<Mutex<BTreeMap<Height, TempoHeader>>>,
    reads: Arc<Mutex<Vec<Height>>>,
    next_players: Arc<Mutex<ordered::Set<PublicKey>>>,
    fail_next_players: Arc<AtomicBool>,
    fail_next_full_dkg_epoch: Arc<AtomicBool>,
}

impl StubExecutionProvider {
    pub(super) fn add_header(&self, header: TempoHeader) {
        self.headers
            .lock()
            .unwrap()
            .insert(Height::new(header.inner.number), header);
    }

    pub(super) fn reads(&self) -> Vec<Height> {
        self.reads.lock().unwrap().clone()
    }

    pub(super) fn set_next_players(&self, players: ordered::Set<PublicKey>) {
        *self.next_players.lock().unwrap() = players;
    }

    pub(super) fn fail_next_players(&self) {
        self.fail_next_players.store(true, Ordering::SeqCst);
    }

    pub(super) fn fail_next_full_dkg_epoch(&self) {
        self.fail_next_full_dkg_epoch.store(true, Ordering::SeqCst);
    }
}

impl ExecutionLayer for StubExecutionProvider {
    fn finalized_header(&self, height: Height) -> eyre::Result<Option<TempoHeader>> {
        self.reads.lock().unwrap().push(height);
        Ok(self.headers.lock().unwrap().get(&height).cloned())
    }

    fn next_players(&self, _digest: Digest) -> eyre::Result<ordered::Set<PublicKey>> {
        if self.fail_next_players.load(Ordering::SeqCst) {
            eyre::bail!("next players unavailable");
        }
        Ok(self.next_players.lock().unwrap().clone())
    }

    fn next_full_dkg_epoch(&self, _digest: Digest) -> eyre::Result<u64> {
        if self.fail_next_full_dkg_epoch.load(Ordering::SeqCst) {
            eyre::bail!("full DKG schedule unavailable");
        }
        Ok(0)
    }
}

#[derive(Clone, Default)]
pub(super) struct StubMarshal {
    blocks: Arc<Mutex<BTreeMap<Height, Block>>>,
    reads: Arc<Mutex<Vec<Height>>>,
    empty_ancestry: Arc<AtomicBool>,
}

impl StubMarshal {
    pub(super) fn add_block(&self, block: Block) {
        self.blocks.lock().unwrap().insert(block.height(), block);
    }

    pub(super) fn reads(&self) -> Vec<Height> {
        self.reads.lock().unwrap().clone()
    }

    pub(super) fn return_empty_ancestry(&self) {
        self.empty_ancestry.store(true, Ordering::SeqCst);
    }
}

impl Marshal for StubMarshal {
    type Ancestry = futures::stream::Empty<Arc<Block>>;

    async fn get_block(&self, height: Height) -> Option<Block> {
        self.reads.lock().unwrap().push(height);
        self.blocks.lock().unwrap().get(&height).cloned()
    }

    async fn ancestry<C>(
        &self,
        _clock: Arc<C>,
        _start: (DigestFallback, Digest),
        _fetch_duration: Timed,
    ) -> Option<Self::Ancestry>
    where
        C: Clock,
    {
        self.empty_ancestry
            .load(Ordering::SeqCst)
            .then(futures::stream::empty)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum EpochEvent {
    Enter {
        epoch: Epoch,
        public: Sharing<MinSig>,
        share: Option<Share>,
        participants: ordered::Set<PublicKey>,
    },
    Exit(Epoch),
}

#[derive(Clone, Default)]
pub(super) struct StubEpochManager {
    events: Arc<Mutex<Vec<EpochEvent>>>,
}

impl StubEpochManager {
    pub(super) fn events(&self) -> Vec<EpochEvent> {
        self.events.lock().unwrap().clone()
    }
}

impl EpochManager for StubEpochManager {
    fn enter(
        &mut self,
        epoch: Epoch,
        public: Sharing<MinSig>,
        share: Option<Share>,
        participants: ordered::Set<PublicKey>,
    ) -> eyre::Result<()> {
        self.events.lock().unwrap().push(EpochEvent::Enter {
            epoch,
            public,
            share,
            participants,
        });
        Ok(())
    }

    fn exit(&mut self, epoch: Epoch) -> eyre::Result<()> {
        self.events.lock().unwrap().push(EpochEvent::Exit(epoch));
        Ok(())
    }
}

pub(super) fn header(height: Height) -> TempoHeader {
    TempoHeader {
        inner: Header {
            number: height.get(),
            ..Default::default()
        },
        ..Default::default()
    }
}

pub(super) fn block(header: TempoHeader) -> Block {
    Block::from_execution_block_unchecked(
        SealedBlock::seal_slow(tempo_primitives::Block {
            header,
            body: BlockBody::default(),
        }),
        None,
    )
}

pub(super) fn outcome_header(height: Height, state: &State) -> TempoHeader {
    let outcome = OnchainDkgOutcome {
        epoch: state.epoch,
        output: state.output.clone(),
        next_players: state.players().clone(),
        is_next_full_dkg: state.is_full_dkg,
    };

    let mut header = header(height);
    header.inner.extra_data = outcome.encode().into();
    header
}

pub(super) fn dkg_state(
    rng: &mut impl CryptoRng,
    epoch: Epoch,
    players: usize,
    is_full_dkg: bool,
) -> (State, Vec<PrivateKey>) {
    // TestDkg uses the seed-0 key by default, so every generated state includes
    // that actor as a participant regardless of the ceremony mode.
    let keys = (0..players as u64)
        .map(PrivateKey::from_seed)
        .collect::<Vec<_>>();
    let players = ordered::Set::try_from_iter(keys.iter().map(|key| key.public_key()))
        .expect("test players should be unique");
    let (output, _) = dkg::deal::<MinSig, _, N3f1>(&mut *rng, Default::default(), players.clone())
        .expect("test DKG");

    (
        State {
            epoch,
            seed: Summary::random(rng),
            output,
            share: ShareState::Plaintext(None),
            players,
            is_full_dkg,
        },
        keys,
    )
}

pub(super) struct AckedRecoveryFixture {
    pub(super) ceremony_state: State,
    pub(super) expected_output: Output<MinSig, PublicKey>,
    pub(super) local_key: PrivateKey,
    pub(super) local_dealing: (PublicKey, DealerPubMsg<MinSig>, DealerPrivMsg),
    pub(super) recovered_share: Share,
}

pub(super) fn acked_recovery_fixture(
    rng: &mut impl CryptoRng,
    execution: &StubExecutionProvider,
    epoch_strategy: &FixedEpocher,
    ceremony_epoch: Epoch,
) -> AckedRecoveryFixture {
    // A single validator is enough to exercise the ACK/dealing invariant while
    // keeping the cryptographic setup small. It acts as both dealer and player.
    let (ceremony_state, keys) = dkg_state(rng, ceremony_epoch, 1, true);
    let round = Round::from_state(&ceremony_state, crate::config::NAMESPACE);
    let local_key = keys[0].clone();
    let local_public_key = local_key.public_key();

    let mut local_player = dkg::Player::new(round.info().clone(), local_key.clone()).unwrap();
    let (mut dealer, public_message, private_messages) =
        dkg::Dealer::start::<N3f1>(&mut *rng, round.info().clone(), local_key.clone(), None)
            .unwrap();
    let (_, private_message) = private_messages.into_iter().next().unwrap();

    // Have the player accept the private dealing and ACK it. The test persists
    // this dealing before restart, while the ACK is committed to the dealer log.
    let dkg::Verdict::Valid(ack) = local_player.dealer_message::<N3f1>(
        local_public_key.clone(),
        public_message.clone(),
        private_message.clone(),
    ) else {
        panic!("test dealing must be valid");
    };
    dealer.receive_player_ack(local_public_key, ack).unwrap();

    // Finalize the dealer side to produce the on-chain log containing the ACK.
    let signed_log: SignedDealerLog<MinSig, PrivateKey> = dealer.finalize::<N3f1>();
    let (dealer_public_key, log) = signed_log
        .clone()
        .check(round.info())
        .expect("test dealer log must verify");

    // Finalize the live player once to derive the output and share that startup
    // recovery must reconstruct after replaying the persisted dealing.
    let mut logs = Logs::<MinSig, PublicKey, N3f1>::new(round.info().clone());
    logs.record(dealer_public_key.clone(), log);
    let (output, recovered_share) = local_player
        .finalize::<N3f1, Batch>(&mut *rng, logs, &Sequential)
        .unwrap();

    let recovered_state = State {
        epoch: ceremony_state.epoch.next(),
        seed: Summary::random(&mut *rng),
        output,
        share: ShareState::Plaintext(None),
        players: ceremony_state.players().clone(),
        is_full_dkg: false,
    };

    // Model the finalized chain seen on restart: the ceremony input at the
    // preceding boundary, a dealer log during the ceremony, then its output.
    let previous_epoch = ceremony_epoch
        .previous()
        .expect("recovery fixture requires a non-genesis ceremony epoch");
    let ceremony_boundary = epoch_strategy
        .last(previous_epoch)
        .expect("test epoch must have a final height");
    execution.add_header(outcome_header(ceremony_boundary, &ceremony_state));

    let ceremony_start = epoch_strategy
        .first(ceremony_epoch)
        .expect("test epoch must have a first height");
    let mut log_header = header(ceremony_start);
    log_header.inner.extra_data = signed_log.encode().into();
    execution.add_header(log_header);

    let output_boundary = epoch_strategy
        .last(ceremony_epoch)
        .expect("test epoch must have a final height");
    execution.add_header(outcome_header(output_boundary, &recovered_state));

    AckedRecoveryFixture {
        ceremony_state,
        expected_output: recovered_state.output,
        local_key,
        local_dealing: (dealer_public_key, public_message, private_message),
        recovered_share,
    }
}
