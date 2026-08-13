//! Test doubles and construction helpers for the DKG manager actor.

use std::{
    collections::BTreeMap,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::SystemTime,
};

use alloy_consensus::Header;
use commonware_actor::{Feedback, Unreliable};
use commonware_consensus::{
    Heightable as _,
    marshal::core::DigestFallback,
    types::{Epoch, Height},
};
use commonware_cryptography::{
    Signer as _,
    bls12381::{
        dkg::feldman_desmedt as dkg,
        primitives::{group::Share, sharing::Sharing, variant::MinSig},
    },
    ed25519::{PrivateKey, PublicKey},
    transcript::Summary,
};
use commonware_math::algebra::Random as _;
use commonware_p2p::{CheckedSender, LimitedSender, Message as P2pMessage, Receiver, Recipients};
use commonware_runtime::{Clock, IoBufs, telemetry::metrics::histogram::Timed};
use commonware_utils::{N3f1, ordered::Set};
use futures::{StreamExt as _, channel::mpsc};
use rand_core::CryptoRng;
use reth_node_core::primitives::SealedBlock;
use tempo_primitives::{Block as TempoBlock, BlockBody, TempoHeader};

use super::super::{
    Block, Digest, EpochManager, ExecutionProvider, Marshal, State, state::ShareState,
};

#[derive(Debug)]
pub(super) struct InertReceiver;

impl Receiver for InertReceiver {
    type Error = io::Error;
    type PublicKey = PublicKey;

    async fn recv(&mut self) -> Result<P2pMessage<Self::PublicKey>, Self::Error> {
        std::future::pending().await
    }
}

#[derive(Clone, Default)]
pub(super) struct TestNetwork {
    state: Arc<NetworkState>,
}

#[derive(Default)]
struct NetworkState {
    routes: Mutex<BTreeMap<PublicKey, mpsc::UnboundedSender<P2pMessage<PublicKey>>>>,
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
    receiver: mpsc::UnboundedReceiver<P2pMessage<PublicKey>>,
}

impl Receiver for NetworkReceiver {
    type Error = io::Error;
    type PublicKey = PublicKey;

    async fn recv(&mut self) -> Result<P2pMessage<Self::PublicKey>, Self::Error> {
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
    next_players: Arc<Mutex<Set<PublicKey>>>,
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

    pub(super) fn set_next_players(&self, players: Set<PublicKey>) {
        *self.next_players.lock().unwrap() = players;
    }

    pub(super) fn fail_next_players(&self) {
        self.fail_next_players.store(true, Ordering::SeqCst);
    }

    pub(super) fn fail_next_full_dkg_epoch(&self) {
        self.fail_next_full_dkg_epoch.store(true, Ordering::SeqCst);
    }
}

impl ExecutionProvider for StubExecutionProvider {
    fn finalized_header(&self, height: Height) -> eyre::Result<Option<TempoHeader>> {
        self.reads.lock().unwrap().push(height);
        Ok(self.headers.lock().unwrap().get(&height).cloned())
    }

    fn next_players(&self, _digest: Digest) -> eyre::Result<Set<PublicKey>> {
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
}

impl StubMarshal {
    pub(super) fn add_block(&self, block: Block) {
        self.blocks.lock().unwrap().insert(block.height(), block);
    }

    pub(super) fn reads(&self) -> Vec<Height> {
        self.reads.lock().unwrap().clone()
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
        None
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum EpochEvent {
    Enter {
        epoch: Epoch,
        public: Sharing<MinSig>,
        has_share: bool,
        participants: Set<PublicKey>,
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
        participants: Set<PublicKey>,
    ) -> eyre::Result<()> {
        self.events.lock().unwrap().push(EpochEvent::Enter {
            epoch,
            public,
            has_share: share.is_some(),
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
        SealedBlock::seal_slow(TempoBlock {
            header,
            body: BlockBody::default(),
        }),
        None,
    )
}

pub(super) fn dkg_state(rng: &mut impl CryptoRng, epoch: Epoch) -> State {
    let fixture = crate::test_utils::dkg_fixture(rng, epoch);
    State {
        epoch: fixture.outcome.epoch,
        seed: Summary::random(rng),
        output: fixture.outcome.output,
        share: ShareState::Plaintext(None),
        players: fixture.outcome.next_players,
        is_full_dkg: fixture.outcome.is_next_full_dkg,
    }
}

pub(super) fn full_dkg_state(
    rng: &mut impl CryptoRng,
    epoch: Epoch,
    players: usize,
) -> (State, Vec<PrivateKey>) {
    let keys = (0..players as u64)
        .map(PrivateKey::from_seed)
        .collect::<Vec<_>>();
    let players = Set::from_iter_dedup(keys.iter().map(|key| key.public_key()));
    let (output, _) = dkg::deal::<MinSig, _, N3f1>(&mut *rng, Default::default(), players.clone())
        .expect("test DKG");

    (
        State {
            epoch,
            seed: Summary::random(rng),
            output,
            share: ShareState::Plaintext(None),
            players,
            is_full_dkg: true,
        },
        keys,
    )
}
