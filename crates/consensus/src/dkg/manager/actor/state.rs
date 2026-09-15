use std::{
    collections::{BTreeMap, HashMap},
    num::{NonZeroU16, NonZeroU32, NonZeroUsize},
};

use alloy_consensus::{BlockHeader as _, Sealable as _};
use commonware_codec::{EncodeSize, RangeCfg, Read, ReadExt, Write};
use commonware_consensus::{
    Block as _, Heightable as _,
    types::{Epoch, Height},
};
use commonware_cryptography::{
    Signer as _,
    bls12381::{
        dkg::feldman_desmedt::{
            self as dkg, DealerPrivMsg, DealerPubMsg, Info, Output, PlayerAck, Reveal,
            SignedDealerLog,
        },
        primitives::{
            group::Share,
            sharing::{Mode, ModeVersion},
            variant::{MinSig, Variant},
        },
    },
    ed25519::{PrivateKey, PublicKey},
    transcript::{Summary, Transcript, Version},
};
use commonware_parallel::Strategy;
use commonware_runtime::{BufferPooler, Clock, Metrics, ReadOptions, buffer::paged::CacheRef};
use commonware_storage::{journal::segmented, metadata};
use commonware_utils::{N3f1, NZU16, NZU32, NZUsize, futures::rebind, ordered};
use eyre::{OptionExt, WrapErr as _, bail};
use tempo_primitives::TempoHeader;
use tracing::{debug, info, instrument, warn};

use crate::consensus::{Digest, block::Block};

const PAGE_SIZE: NonZeroU16 = NZU16!(1 << 12);
const POOL_CAPACITY: NonZeroUsize = NZUsize!(1 << 13);
const WRITE_BUFFER: NonZeroUsize = NZUsize!(1 << 12);
const READ_BUFFER: NonZeroUsize = NZUsize!(1 << 20);

/// The maximum number of validators ever permitted in the DKG ceremony.
///
/// u16::MAX is 2^16-1 validators, i.e. 65536, which is probably more than
/// we will ever need. An alternative would be u8::MAX but that feels a bit
/// too limited. There is extremely little cost doing u16::MAX instead.
const MAXIMUM_VALIDATORS: NonZeroU32 = NZU32!(u16::MAX as u32);

pub(super) fn builder() -> Builder {
    Builder::default()
}

pub(super) struct Storage<TContext>
where
    TContext: BufferPooler + commonware_runtime::Storage + Clock + Metrics,
{
    // Rebind consuming commonware mutations through these slots. Write failures
    // panic, so an invalidated handle is never reused by the actor.
    states: Option<metadata::Metadata<TContext, u64, State>>,
    // Only runtime transitions populate this map; snapshot healing never does.
    observed_identities: Option<metadata::Metadata<TContext, u64, <MinSig as Variant>::Public>>,
    events: Option<segmented::variable::Journal<TContext, Event>>,

    current: Option<State>,
    cache: BTreeMap<Epoch, Events>,
}

/// Storage as read from disk, holding a state that has not yet been checked
/// against the finalized floor (or no state at all).
///
/// [`Unverified::init_verified`] persists the verified state and turns this
/// into a usable [`Storage`].
pub(super) struct Unverified<TContext>
where
    TContext: BufferPooler + commonware_runtime::Storage + Clock + Metrics,
{
    storage: Storage<TContext>,
}

impl<TContext> Unverified<TContext>
where
    TContext: BufferPooler + commonware_runtime::Storage + Clock + Metrics,
{
    pub(super) fn state(&self) -> Option<&State> {
        self.storage.current.as_ref()
    }

    pub(super) fn observed_identity(&self, epoch: Epoch) -> Option<<MinSig as Variant>::Public> {
        self.storage
            .observed_identities
            .as_ref()
            .unwrap()
            .get(&epoch.get())
            .copied()
    }

    pub(super) async fn init_verified(self, state: State) -> Storage<TContext> {
        if let Some(identity) = self.observed_identity(state.epoch) {
            assert_eq!(
                identity,
                *state.output.public().public(),
                "network identity mismatch while healing a runtime-observed DKG epoch",
            );
        }
        let Self { mut storage } = self;
        rebind(&mut storage.states, |states| {
            states.put_sync(state.epoch.get(), state.clone())
        })
        .await
        .expect("failed to persist initial DKG state");
        storage.current = Some(state);
        storage
    }
}

impl<TContext> Storage<TContext>
where
    TContext: BufferPooler + commonware_runtime::Storage + Clock + Metrics,
{
    /// Returns all player acknowledgments received during the given epoch.
    fn acks_for_epoch(
        &self,
        epoch: Epoch,
    ) -> impl Iterator<Item = (&PublicKey, &PlayerAck<PublicKey>)> {
        self.cache
            .get(&epoch)
            .into_iter()
            .flat_map(|cache| cache.acks.iter())
    }

    /// Returns all dealings received during the given epoch.
    fn dealings_for_epoch(
        &self,
        epoch: Epoch,
    ) -> impl Iterator<Item = (&PublicKey, &(DealerPubMsg<MinSig>, DealerPrivMsg))> {
        self.cache
            .get(&epoch)
            .into_iter()
            .flat_map(|cache| cache.dealings.iter())
    }

    /// Returns all dealings received during the given epoch.
    pub(super) fn logs_for_epoch(
        &self,
        epoch: Epoch,
    ) -> impl Iterator<Item = (&PublicKey, &dkg::DealerLog<MinSig, PublicKey>)> {
        self.cache
            .get(&epoch)
            .into_iter()
            .flat_map(|cache| cache.logs.iter())
    }

    /// Returns the DKG outcome for the current epoch.
    pub(super) fn current(&self) -> State {
        self.current.clone().expect("invariant: state must be set")
    }

    /// Persists the outcome of a DKG ceremony, panicking on write failure.
    pub(super) async fn set_state(&mut self, state: State) {
        let identity = *state.output.public().public();
        if let Some(existing) = self
            .observed_identities
            .as_ref()
            .unwrap()
            .get(&state.epoch.get())
        {
            assert_eq!(
                *existing, identity,
                "network identity mismatch in persisted DKG epoch"
            );
        }
        rebind(&mut self.states, |mut states| async {
            if let Some(old) = states.put(state.epoch.get(), state.clone()) {
                warn!(epoch = %old.epoch, "overwriting existing state");
            }
            states.sync().await
        })
        .await
        .expect("failed to persist DKG state");
        rebind(&mut self.observed_identities, |mut identities| async {
            identities.put(state.epoch.get(), identity);
            identities.sync().await
        })
        .await
        .expect("failed to persist runtime-observed DKG identity");
        self.current = Some(state);
    }

    /// Appends and durably syncs an event, panicking on write failure.
    async fn append_event(&mut self, epoch: Epoch, event: Event) {
        rebind(&mut self.events, |events| async move {
            let section = epoch.get();
            let (events, _, _) = events.append(section, &event).await?;
            events.sync(section).await
        })
        .await
        .expect("failed to persist DKG event");
    }

    /// Append a player ACK to the journal.
    #[instrument(
        skip_all,
        fields(
            %epoch,
            %player,
        ),
    )]
    async fn append_ack(&mut self, epoch: Epoch, player: PublicKey, ack: PlayerAck<PublicKey>) {
        if self
            .cache
            .get(&epoch)
            .is_some_and(|events| events.acks.contains_key(&player))
        {
            info!(%player, %epoch, "ack for player already found in cache, dropping");
            return;
        }

        self.append_event(
            epoch,
            Event::Ack {
                player: player.clone(),
                ack: ack.clone(),
            },
        )
        .await;

        self.cache
            .entry(epoch)
            .or_default()
            .acks
            .insert(player, ack);
    }

    /// Append a dealer's dealing to the journal.
    #[instrument(
        skip_all,
        fields(
            %epoch,
            %dealer,
        ),
    )]
    async fn append_dealing(
        &mut self,
        epoch: Epoch,
        dealer: PublicKey,
        pub_msg: DealerPubMsg<MinSig>,
        priv_msg: DealerPrivMsg,
    ) {
        if self
            .cache
            .get(&epoch)
            .is_some_and(|events| events.dealings.contains_key(&dealer))
        {
            info!(%dealer, %epoch, "dealing of dealer already found in cache, dropping");
            return;
        }

        self.append_event(
            epoch,
            Event::Dealing {
                dealer: dealer.clone(),
                public_msg: pub_msg.clone(),
                private_msg: priv_msg.clone(),
            },
        )
        .await;

        self.cache
            .entry(epoch)
            .or_default()
            .dealings
            .insert(dealer, (pub_msg, priv_msg));
    }

    /// Appends a dealer log to the journal
    pub(super) async fn append_dealer_log(
        &mut self,
        epoch: Epoch,
        dealer: PublicKey,
        log: dkg::DealerLog<MinSig, PublicKey>,
    ) {
        if self
            .cache
            .get(&epoch)
            .is_some_and(|events| events.logs.contains_key(&dealer))
        {
            info!(
                %dealer,
                %epoch,
                "dealer log already found in cache; dropping"
            );
            return;
        }

        self.append_event(
            epoch,
            Event::Log {
                dealer: dealer.clone(),
                log: log.clone(),
            },
        )
        .await;

        let cache = self.cache.entry(epoch).or_default();
        cache.logs.insert(dealer, log);
    }

    /// Appends the height, digest, and parent of the finalized header to the journal.
    pub(super) async fn append_finalized_header(&mut self, epoch: Epoch, header: TempoHeader) {
        let height = Height::new(header.number());
        let digest = Digest(header.hash_slow());
        let parent = Digest(header.parent_hash());
        if self
            .cache
            .get(&epoch)
            .is_some_and(|events| events.finalized.contains_key(&height))
        {
            info!(
                %height,
                %digest,
                %parent,
                "finalized block was already found in cache; dropping",
            );
            return;
        }

        self.append_event(
            epoch,
            Event::Finalized {
                digest,
                parent,
                height,
            },
        )
        .await;

        let cache = self.cache.entry(epoch).or_default();
        cache.finalized.insert(
            height,
            FinalizedBlockInfo {
                height,
                digest,
                parent,
            },
        );
    }

    pub(super) fn cache_dkg_outcome(
        &mut self,
        epoch: Epoch,
        digest: Digest,
        output: Output<MinSig, PublicKey>,
        share: ShareState,
    ) {
        self.cache
            .entry(epoch)
            .or_default()
            .dkg_outcomes
            .insert(digest, (output, share));
    }

    pub(super) fn get_dkg_outcome(
        &self,
        epoch: &Epoch,
        digest: &Digest,
    ) -> Option<&(Output<MinSig, PublicKey>, ShareState)> {
        self.cache
            .get(epoch)
            .and_then(|events| events.dkg_outcomes.get(digest))
    }

    /// Caches the notarized log in memory.
    ///
    /// Notably, this does not persist the dealer logs to disk! On restart, it
    /// is expected that the actor reads the dealer logs from the marshal actor
    /// and forwards them one-by-one to the state cache.
    pub(super) fn cache_notarized_block(&mut self, round: &Round, block: Block) {
        let cache = self.cache.entry(round.epoch).or_default();
        let log = ReducedBlock::from_block_for_round(&block, round);
        cache.notarized_blocks.insert(log.digest, log);
    }

    #[instrument(
        skip_all,
        fields(
            me = %me.public_key(),
            epoch = %round.epoch,
        )
        err,
    )]
    pub(super) fn create_dealer_for_round(
        &self,
        me: PrivateKey,
        round: Round,
        share: ShareState,
        seed: Summary,
    ) -> eyre::Result<Option<Dealer>> {
        if round.dealers.position(&me.public_key()).is_none() {
            return Ok(None);
        }

        let share = if round.is_full_dkg() {
            info!("running full DKG ceremony as dealer (new polynomial)");
            None
        } else {
            let inner = share.into_inner();
            if inner.is_none() {
                warn!(
                    "we are a dealer in this round, but we do not have a share, \
                    which means we likely lost it; will not instantiate a dealer \
                    instance and hope to get a new share in the next round if we \
                    are a player"
                );
                return Ok(None);
            }
            inner
        };

        let (mut dealer, pub_msg, priv_msgs) = dkg::Dealer::start::<N3f1>(
            Transcript::resume(seed, Version::V0).noise(b"dealer-rng"),
            round.info.clone(),
            me.clone(),
            share,
        )
        .wrap_err("unable to start cryptographic dealer instance")?;

        // Replay stored acks
        let mut unsent: BTreeMap<PublicKey, DealerPrivMsg> = priv_msgs.into_iter().collect();
        for (player, ack) in self.acks_for_epoch(round.epoch) {
            if unsent.contains_key(player)
                && dealer
                    .receive_player_ack(player.clone(), ack.clone())
                    .is_ok()
            {
                unsent.remove(player);
                debug!(%player, "replayed player ack");
            }
        }

        Ok(Some(Dealer::new(Some(dealer), pub_msg, unsent)))
    }

    /// Create a Player for the given epoch, replaying any stored dealer messages.
    #[instrument(
        skip_all,
        fields(
            epoch = %round.epoch,
            me = %me.public_key(),
        )
        err,
    )]
    pub(super) fn create_player_for_round(
        &self,
        me: PrivateKey,
        round: &Round,
    ) -> eyre::Result<Option<Player>> {
        if round.players.position(&me.public_key()).is_none() {
            return Ok(None);
        }

        let mut player = Player::new(
            dkg::Player::new(round.info.clone(), me)
                .wrap_err("unable to start cryptographic player instance")?,
        );

        // Replay persisted dealer messages
        for (dealer, (pub_msg, priv_msg)) in self.dealings_for_epoch(round.epoch()) {
            player.replay(dealer.clone(), pub_msg.clone(), priv_msg.clone());
            debug!(%dealer, "replayed committed dealer message");
        }

        Ok(Some(player))
    }

    pub(super) fn get_latest_finalized_block_for_epoch(
        &self,
        epoch: &Epoch,
    ) -> Option<(&Height, &FinalizedBlockInfo)> {
        self.cache
            .get(epoch)
            .and_then(|cache| cache.finalized.last_key_value())
    }

    pub(super) fn get_notarized_reduced_block(
        &mut self,
        epoch: &Epoch,
        digest: &Digest,
    ) -> Option<&ReducedBlock> {
        self.cache
            .get(epoch)
            .and_then(|cache| cache.notarized_blocks.get(digest))
    }

    #[instrument(skip_all, fields(%up_to_epoch))]
    pub(super) async fn prune(&mut self, up_to_epoch: Epoch) {
        rebind(&mut self.events, |events| events.prune(up_to_epoch.get()))
            .await
            .expect("failed to prune DKG events journal");
        rebind(&mut self.states, |mut states| async move {
            states.retain(|&key, _| key >= up_to_epoch.get());
            states.sync().await
        })
        .await
        .expect("failed to prune DKG state metadata");
        rebind(&mut self.observed_identities, |mut identities| async move {
            identities.retain(|&key, _| key >= up_to_epoch.get());
            identities.sync().await
        })
        .await
        .expect("failed to prune runtime-observed DKG identities");
        self.cache.retain(|&epoch, _| epoch >= up_to_epoch);
    }
}

#[derive(Default)]
pub(super) struct Builder {
    partition_prefix: Option<String>,
}

impl Builder {
    pub(super) fn partition_prefix(self, partition_prefix: &str) -> Self {
        Self {
            partition_prefix: Some(partition_prefix.to_string()),
        }
    }

    #[instrument(skip_all, err)]
    pub(super) async fn init_unverified<TContext>(
        self,
        context: TContext,
    ) -> eyre::Result<Unverified<TContext>>
    where
        TContext: BufferPooler + commonware_runtime::Storage + Clock + Metrics,
    {
        let Self { partition_prefix } = self;
        let partition_prefix =
            partition_prefix.ok_or_eyre("DKG actors state must have its partition prefix set")?;

        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, POOL_CAPACITY);

        let states_metadata_partition = format!("{partition_prefix}_states_metadata");
        let states: metadata::Metadata<TContext, u64, State> = metadata::Metadata::init(
            context.child("states"),
            metadata::Config {
                partition: states_metadata_partition,
                codec_config: MAXIMUM_VALIDATORS,
            },
        )
        .await
        .wrap_err("unable to initialize DKG states metadata")?;

        // Legacy storage has no provenance marker, so it falls back to the configured
        // identity until a runtime transition is observed; do not infer trust from states.
        let observed_identities = metadata::Metadata::init(
            context.child("observed_identities"),
            metadata::Config {
                partition: format!("{partition_prefix}_observed_identities"),
                codec_config: (),
            },
        )
        .await
        .wrap_err("unable to initialize runtime-observed DKG identities")?;

        let current = states.keys().max().map(|epoch| {
            states
                .get(epoch)
                .expect("state at keys iterator must exist")
                .clone()
        });

        let mut events = segmented::variable::Journal::init(
            context.child("events"),
            segmented::variable::Config {
                partition: format!("{partition_prefix}_events"),
                compression: None,
                codec_config: MAXIMUM_VALIDATORS,
                page_cache,
                write_buffer: WRITE_BUFFER,
            },
        )
        .await
        .expect("should be able to initialize events journal");

        // Replay msgs to populate epoch caches
        let mut cache = BTreeMap::<Epoch, Events>::new();
        {
            let mut replay = events
                .replay(0, 0, READ_BUFFER, ReadOptions::default())
                .await
                .wrap_err("unable to start a replay stream to populate events cache")?;

            while let Some(result) = replay.next().await {
                let (section, _, _, event) =
                    result.wrap_err("unable to read entry in replay stream")?;
                let epoch = Epoch::new(section);
                let events = cache.entry(epoch).or_default();
                events.insert(event);
            }
            events = replay
                .finish()
                .wrap_err("unable to finish replaying events journal")?;
        }

        eyre::ensure!(
            current.is_some() || cache.is_empty(),
            "DKG states metadata is empty, but events journal contains retained events",
        );
        Ok(Unverified {
            storage: Storage {
                states: Some(states),
                observed_identities: Some(observed_identities),
                events: Some(events),
                current,
                cache,
            },
        })
    }
}

/// Wrapper around a DKG share that tracks how it is stored at rest.
///
/// The `Option<Share>` is inside the enum so that a future encrypted variant
/// can hide whether a share is present at all.
///
/// Currently only plaintext storage is supported, but additional variants
/// (e.g. encrypted-at-rest) can be added in the future.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ShareState {
    Plaintext(Option<Share>),
}

impl ShareState {
    pub(super) fn unset_plaintext() -> Self {
        Self::Plaintext(None)
    }

    pub(super) fn into_inner(self) -> Option<Share> {
        match self {
            Self::Plaintext(share) => share,
        }
    }
}

impl EncodeSize for ShareState {
    fn encode_size(&self) -> usize {
        match self {
            Self::Plaintext(share) => 1 + share.encode_size(),
        }
    }
}

impl Write for ShareState {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Plaintext(share) => {
                0u8.write(buf);
                share.write(buf);
            }
        }
    }
}

impl Read for ShareState {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let tag = u8::read(buf)?;
        match tag {
            0 => Ok(Self::Plaintext(ReadExt::read(buf)?)),
            other => Err(commonware_codec::Error::InvalidEnum(other)),
        }
    }
}

/// The outcome of a DKG ceremony.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct State {
    pub(super) epoch: Epoch,
    pub(super) seed: Summary,
    pub(super) output: Output<MinSig, PublicKey>,
    pub(super) share: ShareState,
    pub(super) players: ordered::Set<PublicKey>,
    pub(super) is_full_dkg: bool,
}

impl State {
    /// Returns the dealers active in the DKG round tracked by this state.
    pub(super) fn dealers(&self) -> &ordered::Set<PublicKey> {
        self.output.players()
    }

    /// Returns the players active in the DKG round tracked by this state.
    pub(super) fn players(&self) -> &ordered::Set<PublicKey> {
        &self.players
    }

    /// Placeholder for the legacy `syncers` field.
    fn legacy_syncers(&self) -> ordered::Set<PublicKey> {
        ordered::Set::default()
    }
}

impl EncodeSize for State {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size()
            + self.seed.encode_size()
            + self.output.encode_size()
            + self.share.encode_size()
            + self.players.encode_size()
            // Until the next state migration, the unused syncers field must
            // still be written to remain backwards compatible.
            + self.legacy_syncers().encode_size()
            + self.is_full_dkg.encode_size()
    }
}

impl Write for State {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.epoch.write(buf);
        self.seed.write(buf);
        self.output.write(buf);
        self.share.write(buf);
        self.players.write(buf);
        // Until the next state migration, the unused syncers field must
        // still be written to remain backwards compatible.
        self.legacy_syncers().write(buf);
        self.is_full_dkg.write(buf);
    }
}

impl Read for State {
    type Cfg = NonZeroU32;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let epoch = ReadExt::read(buf)?;
        let seed = ReadExt::read(buf)?;
        let output = Read::read_cfg(buf, &(*cfg, ModeVersion::v0()))?;
        let share = ReadExt::read(buf)?;
        let players = Read::read_cfg(buf, &(RangeCfg::from(1..=(u16::MAX as usize)), ()))?;

        // Until the next state migration, the unused syncers field must still be read to remain backwards compatible.
        ordered::Set::<PublicKey>::read_cfg(buf, &(RangeCfg::from(0..=(u16::MAX as usize)), ()))?;

        let is_full_dkg = ReadExt::read(buf)?;

        Ok(Self {
            epoch,
            seed,
            output,
            share,
            players,
            is_full_dkg,
        })
    }
}

#[expect(
    dead_code,
    reason = "tracking this data is virtually free and might become useful later"
)]
#[derive(Clone, Debug)]
pub(super) struct FinalizedBlockInfo {
    pub(super) height: Height,
    pub(super) digest: Digest,
    pub(super) parent: Digest,
}

/// A cache of all events that transpired during a given epoch.
#[derive(Debug, Default)]
struct Events {
    acks: BTreeMap<PublicKey, PlayerAck<PublicKey>>,
    dealings: BTreeMap<PublicKey, (DealerPubMsg<MinSig>, DealerPrivMsg)>,
    logs: BTreeMap<PublicKey, dkg::DealerLog<MinSig, PublicKey>>,
    finalized: BTreeMap<Height, FinalizedBlockInfo>,

    notarized_blocks: HashMap<Digest, ReducedBlock>,
    dkg_outcomes: HashMap<Digest, (Output<MinSig, PublicKey>, ShareState)>,
}

impl Events {
    fn insert(&mut self, event: Event) {
        match event {
            Event::Dealing {
                dealer: public_key,
                public_msg,
                private_msg,
            } => {
                self.dealings.insert(public_key, (public_msg, private_msg));
            }
            Event::Ack {
                player: public_key,
                ack,
            } => {
                self.acks.insert(public_key, ack);
            }
            Event::Log { dealer, log } => {
                self.logs.insert(dealer, log);
            }
            Event::Finalized {
                digest,
                parent,
                height,
            } => {
                self.finalized.insert(
                    height,
                    FinalizedBlockInfo {
                        height,
                        digest,
                        parent,
                    },
                );
            }
        }
    }
}

enum Event {
    /// A message received from a dealer (as a player).
    Dealing {
        dealer: PublicKey,
        public_msg: DealerPubMsg<MinSig>,
        private_msg: DealerPrivMsg,
    },
    /// An ack (of a dealing) received from a player (as a dealer).
    Ack {
        player: PublicKey,
        ack: PlayerAck<PublicKey>,
    },
    /// A dealer log read from a finalized block.
    Log {
        dealer: PublicKey,
        log: dkg::DealerLog<MinSig, PublicKey>,
    },
    /// Information of finalized block observed by the actor.
    Finalized {
        digest: Digest,
        parent: Digest,
        height: Height,
    },
}

impl EncodeSize for Event {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Dealing {
                dealer: public_key,
                public_msg,
                private_msg,
            } => public_key.encode_size() + public_msg.encode_size() + private_msg.encode_size(),
            Self::Ack {
                player: public_key,
                ack,
            } => public_key.encode_size() + ack.encode_size(),
            Self::Log { dealer, log } => dealer.encode_size() + log.encode_size(),
            Self::Finalized {
                digest,
                parent,
                height,
            } => digest.encode_size() + parent.encode_size() + height.encode_size(),
        }
    }
}

impl Write for Event {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Dealing {
                dealer: public_key,
                public_msg,
                private_msg,
            } => {
                0u8.write(buf);
                public_key.write(buf);
                public_msg.write(buf);
                private_msg.write(buf);
            }
            Self::Ack {
                player: public_key,
                ack,
            } => {
                1u8.write(buf);
                public_key.write(buf);
                ack.write(buf);
            }
            Self::Log { dealer, log } => {
                2u8.write(buf);
                dealer.write(buf);
                log.write(buf);
            }
            Self::Finalized {
                digest,
                parent,
                height,
            } => {
                3u8.write(buf);
                digest.write(buf);
                parent.write(buf);
                height.write(buf);
            }
        }
    }
}

impl Read for Event {
    type Cfg = NonZeroU32;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let tag = u8::read(buf)?;
        match tag {
            0 => Ok(Self::Dealing {
                dealer: ReadExt::read(buf)?,
                public_msg: Read::read_cfg(buf, cfg)?,
                private_msg: ReadExt::read(buf)?,
            }),
            1 => Ok(Self::Ack {
                player: ReadExt::read(buf)?,
                ack: ReadExt::read(buf)?,
            }),
            2 => Ok(Self::Log {
                dealer: ReadExt::read(buf)?,
                log: Read::read_cfg(buf, &NZU32!(u32::from(u16::MAX)))?,
            }),
            3 => Ok(Self::Finalized {
                digest: ReadExt::read(buf)?,
                parent: ReadExt::read(buf)?,
                height: ReadExt::read(buf)?,
            }),
            other => Err(commonware_codec::Error::InvalidEnum(other)),
        }
    }
}

/// Internal state for a dealer in the current round.
pub(super) struct Dealer {
    /// The inner cryptographic dealer state. Is `None` if
    /// the dealer log was already finalized so that it is not finalized again.
    dealer: Option<dkg::Dealer<MinSig, PrivateKey>>,

    /// The message containing the generated commitment by this dealer, which
    /// is shared with all players and posted on chain.
    pub_msg: DealerPubMsg<MinSig>,

    /// A map of players that we have not yet successfully sent their private
    /// messages to (containing their share generated by this dealer).
    unsent: BTreeMap<PublicKey, DealerPrivMsg>,

    /// The finalized, signed log of this dealer. Initially `None` and set after
    /// the middle point of the epoch. Set to `None` again after this node
    /// observes it dealer log on chain to not post it again.
    finalized: Option<SignedDealerLog<MinSig, PrivateKey>>,
}

impl Dealer {
    pub(super) const fn new(
        dealer: Option<dkg::Dealer<MinSig, PrivateKey>>,
        pub_msg: DealerPubMsg<MinSig>,
        unsent: BTreeMap<PublicKey, DealerPrivMsg>,
    ) -> Self {
        Self {
            dealer,
            pub_msg,
            unsent,
            finalized: None,
        }
    }

    /// Handle an incoming ack from a player, persisting it before returning success.
    ///
    /// Returns protocol validation errors. Storage write failures panic.
    pub(super) async fn receive_ack<TContext>(
        &mut self,
        storage: &mut Storage<TContext>,
        epoch: Epoch,
        player: PublicKey,
        ack: PlayerAck<PublicKey>,
    ) -> eyre::Result<()>
    where
        TContext: BufferPooler + commonware_runtime::Storage + Clock + Metrics,
    {
        if !self.unsent.contains_key(&player) {
            bail!("already received an ack from `{player}`");
        }
        let Some(dealer) = &mut self.dealer else {
            bail!("dealer was already finalized, dropping ack of player `{player}`");
        };
        dealer
            .receive_player_ack(player.clone(), ack.clone())
            .wrap_err("unable to receive player ack")?;
        storage.append_ack(epoch, player.clone(), ack).await;
        self.unsent.remove(&player);
        Ok(())
    }

    /// Finalize the dealer and produce a signed log for inclusion in a block.
    pub(super) fn finalize(&mut self) {
        if self.finalized.is_some() {
            return;
        }

        // Even after the finalized_log is taken, we won't attempt to finalize
        // again because the dealer will be None.
        if let Some(dealer) = self.dealer.take() {
            let log = dealer.finalize::<N3f1>();
            self.finalized = Some(log);
        }
    }

    /// Returns a clone of the finalized log if it exists.
    pub(super) fn finalized(&self) -> Option<SignedDealerLog<MinSig, PrivateKey>> {
        self.finalized.clone()
    }

    /// Takes and returns the finalized log, leaving None in its place.
    pub(super) const fn take_finalized(&mut self) -> Option<SignedDealerLog<MinSig, PrivateKey>> {
        self.finalized.take()
    }

    /// Returns shares to distribute to players.
    ///
    /// Returns an iterator of (player, pub_msg, priv_msg) tuples for each player
    /// that hasn't yet acknowledged their share.
    pub(super) fn shares_to_distribute(
        &self,
    ) -> impl Iterator<Item = (PublicKey, DealerPubMsg<MinSig>, DealerPrivMsg)> + '_ {
        self.unsent
            .iter()
            .map(|(player, priv_msg)| (player.clone(), self.pub_msg.clone(), priv_msg.clone()))
    }
}

#[derive(Clone, Debug)]
pub(super) struct Round {
    epoch: Epoch,
    info: dkg::Info<MinSig, PublicKey>,
    dealers: ordered::Set<PublicKey>,
    players: ordered::Set<PublicKey>,
    is_full_dkg: bool,
}

impl Round {
    pub(super) fn from_state(state: &State, namespace: &[u8]) -> Self {
        // For full DKG, don't pass the previous output - this creates a new polynomial
        let previous_output = if state.is_full_dkg {
            None
        } else {
            Some(state.output.clone())
        };

        let dealers = state.dealers().clone();
        let players = state.players().clone();

        Self {
            epoch: state.epoch,
            info: Info::new::<N3f1>(
                namespace,
                state.epoch.get(),
                previous_output,
                Mode::NonZeroCounter,
                #[expect(
                    deprecated,
                    reason = "switching the revealed-share calculation to V1 changes the round \
                              summary and requires a coordinated protocol change"
                )]
                Reveal::V0,
                dealers.clone(),
                players.clone(),
            )
            .expect("a DKG round must always be initializable given some epoch state"),
            dealers,
            players,
            is_full_dkg: state.is_full_dkg,
        }
    }

    pub(super) fn info(&self) -> &dkg::Info<MinSig, PublicKey> {
        &self.info
    }

    pub(super) fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub(super) fn dealers(&self) -> &ordered::Set<PublicKey> {
        &self.dealers
    }

    pub(super) fn players(&self) -> &ordered::Set<PublicKey> {
        &self.players
    }

    pub(super) fn is_full_dkg(&self) -> bool {
        self.is_full_dkg
    }
}

/// Internal state for a player in the current round.
pub(super) struct Player {
    player: dkg::Player<MinSig, PrivateKey>,
    /// Acks we've generated, keyed by dealer. Once we generate an ack for a dealer,
    /// we will not generate a different one (to avoid conflicting votes).
    acks: BTreeMap<PublicKey, PlayerAck<PublicKey>>,
}

impl Player {
    pub(super) const fn new(player: dkg::Player<MinSig, PrivateKey>) -> Self {
        Self {
            player,
            acks: BTreeMap::new(),
        }
    }

    /// Handle an incoming dealer message, persisting it before returning its ack.
    ///
    /// Returns protocol validation errors. Storage write failures panic.
    pub(super) async fn receive_dealing<TContext>(
        &mut self,
        storage: &mut Storage<TContext>,
        epoch: Epoch,
        dealer: PublicKey,
        pub_msg: DealerPubMsg<MinSig>,
        priv_msg: DealerPrivMsg,
    ) -> eyre::Result<PlayerAck<PublicKey>>
    where
        TContext: BufferPooler + commonware_runtime::Storage + Clock + Metrics,
    {
        // Cached acks are backed by a persisted dealing.
        if let Some(ack) = self.acks.get(&dealer) {
            return Ok(ack.clone());
        }

        let ack = self
            .player
            .dealer_message::<N3f1>(dealer.clone(), pub_msg.clone(), priv_msg.clone())
            .wrap_err("applying dealer message to player instance failed")?
            .ok_or_eyre("dealer message was already processed without a cached acknowledgement")?;
        storage
            .append_dealing(epoch, dealer.clone(), pub_msg, priv_msg)
            .await;
        self.acks.insert(dealer, ack.clone());
        Ok(ack)
    }

    /// Replay an already-persisted dealer message (updates in-memory state only).
    fn replay(
        &mut self,
        dealer: PublicKey,
        pub_msg: DealerPubMsg<MinSig>,
        priv_msg: DealerPrivMsg,
    ) {
        if self.acks.contains_key(&dealer) {
            return;
        }
        if let Ok(Some(ack)) = self
            .player
            .dealer_message::<N3f1>(dealer.clone(), pub_msg, priv_msg)
        {
            self.acks.insert(dealer, ack);
        }
    }

    /// Finalize the player's participation in the DKG round.
    pub(super) fn finalize(
        self,
        rng: &mut impl rand_core::CryptoRng,
        logs: dkg::Logs<MinSig, PublicKey, N3f1>,
        strategy: &impl Strategy,
    ) -> Result<(Output<MinSig, PublicKey>, Share), dkg::FinalizeError<PublicKey>> {
        self.player
            .finalize::<N3f1, commonware_cryptography::ed25519::Batch>(rng, logs, strategy)
    }
}

/// Contains a block's height, parent, digest, and dealer log, if there was one.
#[derive(Clone, Debug)]
pub(super) struct ReducedBlock {
    // The block height.
    pub(super) height: Height,

    // The block parent.
    pub(super) parent: Digest,

    // The block digest (hash).
    pub(super) digest: Digest,

    // The (dealer, log) tuple, if a block contained a signed dealear log.
    pub(super) log: Option<(PublicKey, dkg::DealerLog<MinSig, PublicKey>)>,
}

impl ReducedBlock {
    pub(super) fn from_block_for_round(block: &Block, round: &Round) -> Self {
        let log = if block.header().extra_data().is_empty() {
            None
        } else {
            dkg::SignedDealerLog::<MinSig, PrivateKey>::read_cfg(
                &mut block.header().extra_data().as_ref(),
                &NZU32!(round.players.len() as u32),
            )
            .inspect(|_| {
                info!(
                    height = %block.height(),
                    digest = %block.digest(),
                    "found dealer log in block"
                )
            })
            .inspect_err(|error| {
                warn!(
                    %error,
                    "block header extraData had data, but it could not be read as \
                    a signed dealer log",
                )
            })
            .ok()
            .and_then(|log| match log.check(&round.info) {
                Some((dealer, log)) => Some((dealer, log)),
                None => {
                    // TODO(janis): some more fidelity here would be nice.
                    warn!("log failed check against current round");
                    None
                }
            })
        };
        Self {
            height: block.height(),
            parent: block.parent(),
            digest: block.digest(),
            log,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Encode as _;
    use commonware_cryptography::{
        bls12381::{dkg::feldman_desmedt as dkg, primitives::sharing::Mode},
        ed25519::PrivateKey,
        transcript::Summary,
    };
    use commonware_math::algebra::Random as _;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_utils::TryFromIterator as _;

    fn make_test_state(rng: &mut impl rand_core::CryptoRng, epoch: u64) -> State {
        let mut keys: Vec<_> = (0..3)
            .map(|i| PrivateKey::from_seed(i + epoch * 100))
            .collect();

        keys.sort_by_key(|k| k.public_key());

        let pubkeys = ordered::Set::try_from_iter(keys.iter().map(|k| k.public_key())).unwrap();

        let (output, _shares) =
            dkg::deal::<_, _, N3f1>(&mut *rng, Mode::NonZeroCounter, pubkeys.clone()).unwrap();

        State {
            epoch: Epoch::new(epoch),
            seed: Summary::random(rng),
            output,
            share: ShareState::Plaintext(None),
            players: pubkeys,
            is_full_dkg: false,
        }
    }

    #[test]
    fn state_codec_round_trip() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let state = make_test_state(&mut context, 0);
            let mut bytes = state.encode();
            let decoded = State::read_cfg(&mut bytes, &NZU32!(u32::MAX)).unwrap();
            assert_eq!(state, decoded);
        });
    }

    #[test]
    fn state_codec_read_ignores_legacy_populated_syncers() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let state = make_test_state(&mut context, 0);

            // Serialize using the legacy layout: same field order as today, but
            // with a non-empty syncers set in place of `legacy_syncers()`.
            let legacy_syncers = state.players.clone();
            let mut bytes = Vec::new();
            state.epoch.write(&mut bytes);
            state.seed.write(&mut bytes);
            state.output.write(&mut bytes);
            state.share.write(&mut bytes);
            state.players.write(&mut bytes);

            // Legacy slot that is still written/read but ignored
            legacy_syncers.write(&mut bytes);

            state.is_full_dkg.write(&mut bytes);

            let decoded = State::read_cfg(&mut bytes.as_slice(), &NZU32!(u32::MAX)).unwrap();
            assert_eq!(state, decoded);
        });
    }

    #[track_caller]
    fn assert_roundtrip(original: &ShareState) {
        use commonware_codec::Encode as _;
        let encoded = original.encode();
        let decoded = ShareState::read_cfg(&mut encoded.as_ref(), &()).unwrap();
        assert_eq!(original, &decoded);
    }

    #[test]
    fn share_state_roundtrip_plaintext_none() {
        assert_roundtrip(&ShareState::Plaintext(None));
    }

    #[test]
    fn share_state_roundtrip_plaintext_some() {
        use rand::SeedableRng as _;
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        let keys = std::iter::repeat_with(|| PrivateKey::random(&mut rng))
            .take(3)
            .collect::<Vec<_>>();
        let pubkeys = ordered::Set::try_from_iter(keys.iter().map(|k| k.public_key())).unwrap();

        let (_output, shares) =
            dkg::deal::<MinSig, _, N3f1>(&mut rng, Mode::NonZeroCounter, pubkeys).unwrap();

        let share = shares.into_iter().next().unwrap().1;
        assert_roundtrip(&ShareState::Plaintext(Some(share)));
    }

    #[test]
    fn empty_storage_requires_an_initial_state() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let unverified = builder()
                .partition_prefix("empty_storage_requires_an_initial_state")
                .init_unverified(context.child("initial"))
                .await
                .unwrap();
            assert!(
                unverified.state().is_none(),
                "new storage must not contain a state"
            );

            let state = make_test_state(&mut context, 0);
            let storage = unverified.init_verified(state.clone()).await;
            assert_eq!(storage.current(), state);
            drop(storage);

            let reopened = builder()
                .partition_prefix("empty_storage_requires_an_initial_state")
                .init_unverified(context.child("reopened"))
                .await
                .unwrap();
            assert_eq!(
                reopened.state(),
                Some(&state),
                "storage with an initial state must reopen with it"
            );
        });
    }

    #[test]
    fn healing_does_not_mark_identities_as_runtime_observed() {
        deterministic::Runner::default().start(|mut context| async move {
            let initial = make_test_state(&mut context, 1);
            let runtime = make_test_state(&mut context, 2);
            let healed = make_test_state(&mut context, 3);
            let mut storage = builder()
                .partition_prefix("identity_provenance")
                .init_unverified(context.child("initial"))
                .await
                .unwrap()
                .init_verified(initial.clone())
                .await;
            storage.set_state(runtime.clone()).await;
            drop(storage);

            let opened = builder()
                .partition_prefix("identity_provenance")
                .init_unverified(context.child("reopen"))
                .await
                .unwrap();
            assert_eq!(opened.observed_identity(initial.epoch), None);
            assert_eq!(
                opened.observed_identity(runtime.epoch),
                Some(*runtime.output.public().public())
            );
            let mut storage = opened.init_verified(healed.clone()).await;
            storage.prune(runtime.epoch).await;
            drop(storage);

            let opened = builder()
                .partition_prefix("identity_provenance")
                .init_unverified(context.child("after_healing"))
                .await
                .unwrap();
            assert_eq!(
                opened.observed_identity(runtime.epoch),
                Some(*runtime.output.public().public())
            );
            assert_eq!(opened.observed_identity(healed.epoch), None);
        });
    }

    #[test]
    fn metadata_write_failures_panic() {
        use commonware_utils::probability;
        use futures::FutureExt as _;
        use std::panic::AssertUnwindSafe;

        for (operation, expected) in [
            ("initialize", "failed to persist initial DKG state"),
            ("set_state", "failed to persist DKG state"),
            ("prune", "failed to prune DKG state metadata"),
        ] {
            deterministic::Runner::default().start(|mut context| async move {
                let unverified = builder()
                    .partition_prefix("metadata_write_failure")
                    .init_unverified(context.child("storage"))
                    .await
                    .unwrap();
                let state = make_test_state(&mut context, 1);
                let faults = context.storage_fault_config();
                let write = async {
                    if operation == "initialize" {
                        faults.write().sync_rate = Some(probability!(1.0));
                        unverified.init_verified(state).await;
                    } else {
                        let mut storage = unverified.init_verified(state.clone()).await;
                        faults.write().sync_rate = Some(probability!(1.0));
                        if operation == "set_state" {
                            storage
                                .set_state(State {
                                    epoch: state.epoch.next(),
                                    ..state
                                })
                                .await;
                        } else {
                            storage.prune(state.epoch.next()).await;
                        }
                    }
                };
                let panic = AssertUnwindSafe(write)
                    .catch_unwind()
                    .await
                    .expect_err("metadata write failures must panic");
                let message = panic
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| panic.downcast_ref::<&str>().copied())
                    .expect("panic must have an error message");
                assert!(message.starts_with(expected), "unexpected panic: {message}");
            });
        }
    }

    #[test]
    fn receive_methods_persist_dealings_and_acks() {
        deterministic::Runner::default().start(|mut context| async move {
            let mut state = make_test_state(&mut context, 1);
            state.is_full_dkg = true;
            let round = Round::from_state(&state, crate::config::NAMESPACE);
            let dealer_key = PrivateKey::from_seed(100);
            let player_key = PrivateKey::from_seed(101);
            let mut storage = builder()
                .partition_prefix("receive_methods_persist")
                .init_unverified(context.child("initial"))
                .await
                .unwrap()
                .init_verified(state.clone())
                .await;
            let mut dealer = storage
                .create_dealer_for_round(
                    dealer_key.clone(),
                    round.clone(),
                    state.share.clone(),
                    state.seed,
                )
                .unwrap()
                .unwrap();
            let mut player = storage
                .create_player_for_round(player_key.clone(), &round)
                .unwrap()
                .unwrap();
            let (_, public, private) = dealer
                .shares_to_distribute()
                .find(|(recipient, _, _)| *recipient == player_key.public_key())
                .unwrap();

            let ack = player
                .receive_dealing(
                    &mut storage,
                    state.epoch,
                    dealer_key.public_key(),
                    public,
                    private,
                )
                .await
                .unwrap();
            drop(storage);
            drop(player);

            let mut storage = builder()
                .partition_prefix("receive_methods_persist")
                .init_unverified(context.child("after_dealing"))
                .await
                .unwrap()
                .init_verified(state.clone())
                .await;
            let player = storage
                .create_player_for_round(player_key.clone(), &round)
                .unwrap()
                .unwrap();
            assert_eq!(player.acks.get(&dealer_key.public_key()), Some(&ack));

            dealer
                .receive_ack(&mut storage, state.epoch, player_key.public_key(), ack)
                .await
                .unwrap();
            drop(storage);
            drop(dealer);

            let storage = builder()
                .partition_prefix("receive_methods_persist")
                .init_unverified(context.child("after_ack"))
                .await
                .unwrap()
                .init_verified(state.clone())
                .await;
            let dealer = storage
                .create_dealer_for_round(dealer_key, round, state.share, state.seed)
                .unwrap()
                .unwrap();
            assert!(
                dealer
                    .shares_to_distribute()
                    .all(|(recipient, _, _)| recipient != player_key.public_key())
            );
        });
    }

    #[test]
    fn empty_states_reject_retained_events() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut unverified = builder()
                .partition_prefix("empty_states_reject_retained_events")
                .init_unverified(context.child("initial"))
                .await
                .unwrap();
            assert!(
                unverified.state().is_none(),
                "new storage must not contain a state"
            );

            unverified
                .storage
                .append_event(
                    Epoch::zero(),
                    Event::Finalized {
                        digest: Digest(alloy_primitives::B256::with_last_byte(1)),
                        parent: Digest(alloy_primitives::B256::ZERO),
                        height: Height::zero(),
                    },
                )
                .await;
            drop(unverified);

            let result = builder()
                .partition_prefix("empty_states_reject_retained_events")
                .init_unverified(context.child("reopened"))
                .await;
            let Err(error) = result else {
                panic!("retained events without state metadata must be rejected");
            };
            assert!(
                error
                    .to_string()
                    .contains("states metadata is empty, but events journal contains")
            );
        });
    }
}
