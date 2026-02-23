use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    num::{NonZeroU16, NonZeroU32, NonZeroUsize},
};

use alloy_consensus::BlockHeader as _;
use commonware_codec::{EncodeSize, RangeCfg, Read, ReadExt, Write};
use commonware_consensus::{
    Block as _, Heightable as _,
    types::{Epoch, Height},
};
use commonware_cryptography::{
    Signer as _,
    bls12381::{
        dkg::{self, DealerPrivMsg, DealerPubMsg, Info, Output, PlayerAck, SignedDealerLog},
        primitives::{group::Share, sharing::Mode, variant::MinSig},
    },
    ed25519::{PrivateKey, PublicKey},
    transcript::{Summary, Transcript},
};
use commonware_parallel::Strategy;
use commonware_runtime::{BufferPooler, Clock, Metrics, buffer::paged::CacheRef};
use commonware_storage::{
    journal::{contiguous, contiguous::Reader as _, segmented},
    metadata,
};
use commonware_utils::{N3f1, NZU16, NZU32, NZU64, NZUsize, ordered};
use eyre::{OptionExt, WrapErr as _, bail, eyre};
use futures::{FutureExt as _, StreamExt as _, future::BoxFuture};
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
    TContext: commonware_runtime::Storage + Clock + Metrics,
{
    states: metadata::Metadata<TContext, u64, State>,
    events: segmented::variable::Journal<TContext, Event>,

    current: State,
    cache: BTreeMap<Epoch, Events>,
}

impl<TContext> Storage<TContext>
where
    TContext: commonware_runtime::Storage + Clock + Metrics,
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
        self.current.clone()
    }

    /// Persists the outcome of a DKG ceremony to state
    pub(super) async fn set_state(&mut self, state: State) -> eyre::Result<()> {
        if let Some(old) = self.states.put(state.epoch.get(), state.clone()) {
            warn!(epoch = %old.epoch, "overwriting existing state");
        }
        self.states.sync().await.wrap_err("failed writing state")?;
        self.current = state;
        Ok(())
    }

    /// Append a player ACK to the journal.
    #[instrument(
        skip_all,
        fields(
            %epoch,
            %player,
        ),
        err,
    )]
    async fn append_ack(
        &mut self,
        epoch: Epoch,
        player: PublicKey,
        ack: PlayerAck<PublicKey>,
    ) -> eyre::Result<()> {
        if self
            .cache
            .get(&epoch)
            .is_some_and(|events| events.acks.contains_key(&player))
        {
            info!(%player, %epoch, "ack for player already found in cache, dropping");
            return Ok(());
        }

        let section = epoch.get();
        self.events
            .append(
                section,
                Event::Ack {
                    player: player.clone(),
                    ack: ack.clone(),
                },
            )
            .await
            .wrap_err("unable to write event to storage")?;

        self.events
            .sync(section)
            .await
            .wrap_err("unable to sync events journal")?;

        self.cache
            .entry(epoch)
            .or_default()
            .acks
            .insert(player, ack);

        Ok(())
    }

    /// Append a dealer's dealing to the journal.
    #[instrument(
        skip_all,
        fields(
            %epoch,
            %dealer,
        ),
        err,
    )]
    async fn append_dealing(
        &mut self,
        epoch: Epoch,
        dealer: PublicKey,
        pub_msg: DealerPubMsg<MinSig>,
        priv_msg: DealerPrivMsg,
    ) -> eyre::Result<()> {
        if self
            .cache
            .get(&epoch)
            .is_some_and(|events| events.dealings.contains_key(&dealer))
        {
            info!(%dealer, %epoch, "dealing of dealer already found in cache, dropping");
            return Ok(());
        }

        let section = epoch.get();
        self.events
            .append(
                section,
                Event::Dealing {
                    dealer: dealer.clone(),
                    public_msg: pub_msg.clone(),
                    private_msg: priv_msg.clone(),
                },
            )
            .await
            .wrap_err("unable to write event to storage")?;

        self.events
            .sync(section)
            .await
            .wrap_err("unable to sync events journal")?;

        self.cache
            .entry(epoch)
            .or_default()
            .dealings
            .insert(dealer, (pub_msg, priv_msg));

        Ok(())
    }

    /// Appends a dealer log to the journal
    pub(super) async fn append_dealer_log(
        &mut self,
        epoch: Epoch,
        dealer: PublicKey,
        log: dkg::DealerLog<MinSig, PublicKey>,
    ) -> eyre::Result<()> {
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
            return Ok(());
        }

        let section = epoch.get();
        self.events
            .append(
                section,
                Event::Log {
                    dealer: dealer.clone(),
                    log: log.clone(),
                },
            )
            .await
            .wrap_err("failed to append log to journal")?;
        self.events
            .sync(section)
            .await
            .wrap_err("unable to sync journal")?;

        let cache = self.cache.entry(epoch).or_default();
        cache.logs.insert(dealer, log);
        Ok(())
    }

    /// Appends the height, digest, and parent of the finalized block to the journal.
    pub(super) async fn append_finalized_block(
        &mut self,
        epoch: Epoch,
        block: Block,
    ) -> eyre::Result<()> {
        let height = block.height();
        let digest = block.digest();
        let parent = block.parent();
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
            return Ok(());
        }

        let section = epoch.get();
        self.events
            .append(
                section,
                Event::Finalized {
                    digest,
                    parent,
                    height,
                },
            )
            .await
            .wrap_err("failed to append finalized block to journal")?;
        self.events
            .sync(section)
            .await
            .wrap_err("unable to sync journal")?;

        let cache = self.cache.entry(epoch).or_default();
        cache.finalized.insert(
            height,
            FinalizedBlockInfo {
                height: block.height(),
                digest: block.digest(),
                parent: block.parent_digest(),
            },
        );
        Ok(())
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
        &mut self,
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
            Transcript::resume(seed).noise(b"dealer-rng"),
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

    #[instrument(skip_all, fields(%up_to_epoch), err)]
    pub(super) async fn prune(&mut self, up_to_epoch: Epoch) -> eyre::Result<()> {
        self.events
            .prune(up_to_epoch.get())
            .await
            .wrap_err("unable to prune events journal")?;
        self.states.retain(|&key, _| key >= up_to_epoch.get());
        self.states
            .sync()
            .await
            .wrap_err("unable to prune events metadata")?;
        self.cache.retain(|&epoch, _| epoch >= up_to_epoch);
        Ok(())
    }
}

#[derive(Default)]
pub(super) struct Builder {
    initial_state: Option<BoxFuture<'static, eyre::Result<State>>>,
    partition_prefix: Option<String>,
}

impl Builder {
    pub(super) fn initial_state(
        self,
        initial_state: impl Future<Output = eyre::Result<State>> + Send + 'static,
    ) -> Self {
        Self {
            initial_state: Some(initial_state.boxed()),
            ..self
        }
    }

    pub(super) fn partition_prefix(self, partition_prefix: &str) -> Self {
        Self {
            partition_prefix: Some(partition_prefix.to_string()),
            ..self
        }
    }

    #[instrument(skip_all, err)]
    pub(super) async fn init<TContext>(self, context: TContext) -> eyre::Result<Storage<TContext>>
    where
        TContext: BufferPooler + commonware_runtime::Storage + Clock + Metrics,
    {
        let Self {
            initial_state,
            partition_prefix,
        } = self;
        let partition_prefix =
            partition_prefix.ok_or_eyre("DKG actors state must have its partition prefix set")?;

        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, POOL_CAPACITY);

        let states_partition = format!("{partition_prefix}_states");
        let states_metadata_partition = format!("{partition_prefix}_states_metadata");

        let mut states = metadata::Metadata::init(
            context.with_label("states"),
            metadata::Config {
                partition: states_metadata_partition,
                codec_config: MAXIMUM_VALIDATORS,
            },
        )
        .await
        .wrap_err("unable to initialize DKG states metadata")?;

        migrate_journal_to_metadata_if_necessary(
            &context,
            &mut states,
            &states_partition,
            &page_cache,
        )
        .await
        .wrap_err("migrating legacy states journal failed")?;

        if states.keys().max().is_none() {
            let initial_state = match initial_state {
                None => {
                    return Err(eyre!(
                        "states metadata was empty, legacy journal was empty, \
                         and initializer was not set"
                    ));
                }
                Some(initial_state) => initial_state
                    .await
                    .wrap_err("failed constructing initial state to populate storage")?,
            };
            states
                .put_sync(initial_state.epoch.get(), initial_state)
                .await
                .wrap_err("unable to write initial state to metadata")?;
        }

        let current = states
            .keys()
            .max()
            .map(|epoch| {
                states
                    .get(epoch)
                    .expect("state at keys iterator must exist")
                    .clone()
            })
            .expect("states storage must contain a state after initialization");

        let events = segmented::variable::Journal::init(
            context.with_label("events"),
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
            let replay = events
                .replay(0, 0, READ_BUFFER)
                .await
                .wrap_err("unable to start a replay stream to populate events cache")?;
            futures::pin_mut!(replay);

            while let Some(result) = replay.next().await {
                let (section, _, _, event) =
                    result.wrap_err("unable to read entry in replay stream")?;
                let epoch = Epoch::new(section);
                let events = cache.entry(epoch).or_default();
                events.insert(event);
            }
        }

        Ok(Storage {
            states,
            events,
            current,
            cache,
        })
    }
}

async fn migrate_journal_to_metadata_if_necessary<TContext>(
    context: &TContext,
    states: &mut metadata::Metadata<TContext, u64, State>,
    states_partition: &str,
    page_cache: &CacheRef,
) -> eyre::Result<()>
where
    TContext: BufferPooler + commonware_runtime::Storage + Clock + Metrics,
{
    if states.keys().next().is_some() {
        debug!("states already exists in new format; not migrating");
        return Ok(());
    }

    let legacy_journal = contiguous::variable::Journal::<TContext, LegacyState>::init(
        context.with_label("states_legacy"),
        contiguous::variable::Config {
            partition: states_partition.to_string(),
            compression: None,
            codec_config: MAXIMUM_VALIDATORS,
            page_cache: page_cache.clone(),
            write_buffer: WRITE_BUFFER,
            items_per_section: NZU64!(1),
        },
    )
    .await
    .wrap_err("unable to initialize legacy DKG states journal for migration")?;

    if let Some(latest_segment) = legacy_journal.size().await.checked_sub(1) {
        info!(
            latest_segment,
            "legacy journal contains states; migrating last 2 segments",
        );

        let reader = legacy_journal.reader().await;
        for segment in latest_segment.saturating_sub(1)..=latest_segment {
            let legacy_state = reader
                .read(segment)
                .await
                .wrap_err("unable to read state from legacy journal")?;
            let state: State = legacy_state.into();
            let epoch = state.epoch;
            states.put(epoch.get(), state);
            info!(%epoch, "migrated state to new format");
        }
        states
            .sync()
            .await
            .wrap_err("unable to persist migrated states")?;

        info!("states migrated to new format, deleting journal");
    }

    legacy_journal
        .destroy()
        .await
        .wrap_err("unable to destroy legacy states journal")?;

    Ok(())
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
    pub(super) syncers: ordered::Set<PublicKey>,
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
}

impl EncodeSize for State {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size()
            + self.seed.encode_size()
            + self.output.encode_size()
            + self.share.encode_size()
            + self.players.encode_size()
            + self.syncers.encode_size()
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
        self.syncers.write(buf);
        self.is_full_dkg.write(buf);
    }
}

impl Read for State {
    type Cfg = NonZeroU32;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let range_cfg = RangeCfg::from(1..=(u16::MAX as usize));
        Ok(Self {
            epoch: ReadExt::read(buf)?,
            seed: ReadExt::read(buf)?,
            output: Read::read_cfg(buf, cfg)?,
            share: ReadExt::read(buf)?,
            players: Read::read_cfg(buf, &(range_cfg, ()))?,
            syncers: Read::read_cfg(buf, &(range_cfg, ()))?,
            is_full_dkg: ReadExt::read(buf)?,
        })
    }
}

/// Legacy state format used before the migration that removed peer address
/// mappings. Kept only to read existing data from disk during migration.
///
/// `Write` and `EncodeSize` are required by the journal's `Codec` bound even
/// though we only read from the journal during migration.
#[derive(Clone)]
struct LegacyState {
    epoch: Epoch,
    seed: Summary,
    output: Output<MinSig, PublicKey>,
    share: Option<Share>,
    dealers: ordered::Map<PublicKey, SocketAddr>,
    players: ordered::Map<PublicKey, SocketAddr>,
    syncers: ordered::Map<PublicKey, SocketAddr>,
    is_full_dkg: bool,
}

impl EncodeSize for LegacyState {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size()
            + self.seed.encode_size()
            + self.output.encode_size()
            + self.share.encode_size()
            + self.dealers.encode_size()
            + self.players.encode_size()
            + self.syncers.encode_size()
            + self.is_full_dkg.encode_size()
    }
}

impl Write for LegacyState {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.epoch.write(buf);
        self.seed.write(buf);
        self.output.write(buf);
        self.share.write(buf);
        self.dealers.write(buf);
        self.players.write(buf);
        self.syncers.write(buf);
        self.is_full_dkg.write(buf);
    }
}

impl Read for LegacyState {
    type Cfg = NonZeroU32;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            epoch: ReadExt::read(buf)?,
            seed: ReadExt::read(buf)?,
            output: Read::read_cfg(buf, cfg)?,
            share: ReadExt::read(buf)?,
            dealers: Read::read_cfg(buf, &(RangeCfg::from(1..=(u16::MAX as usize)), (), ()))?,
            players: Read::read_cfg(buf, &(RangeCfg::from(1..=(u16::MAX as usize)), (), ()))?,
            syncers: Read::read_cfg(buf, &(RangeCfg::from(1..=(u16::MAX as usize)), (), ()))?,
            is_full_dkg: ReadExt::read(buf)?,
        })
    }
}

impl From<LegacyState> for State {
    fn from(legacy: LegacyState) -> Self {
        Self {
            epoch: legacy.epoch,
            seed: legacy.seed,
            output: legacy.output,
            share: ShareState::Plaintext(legacy.share),
            players: legacy.players.keys().clone(),
            syncers: legacy.syncers.keys().clone(),
            is_full_dkg: legacy.is_full_dkg,
        }
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
                log: Read::read_cfg(buf, &NZU32!(u16::MAX as u32))?,
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

    /// Handle an incoming ack from a player.
    ///
    /// If the ack is valid and new, persists it to storage.
    /// Returns true if the ack was successfully processed.
    pub(super) async fn receive_ack<TContext>(
        &mut self,
        storage: &mut Storage<TContext>,
        epoch: Epoch,
        player: PublicKey,
        ack: PlayerAck<PublicKey>,
    ) -> eyre::Result<()>
    where
        TContext: commonware_runtime::Storage + Clock + Metrics,
    {
        if !self.unsent.contains_key(&player) {
            bail!("already received an ack from `{player}`");
        }
        match &mut self.dealer {
            Some(dealer) => {
                dealer
                    .receive_player_ack(player.clone(), ack.clone())
                    .wrap_err("unable to receive player ack")?;
                self.unsent.remove(&player);
                storage
                    .append_ack(epoch, player.clone(), ack.clone())
                    .await
                    .wrap_err("unable to append ack to journal")?;
            }
            None => bail!("dealer was already finalized, dropping ack of player `{player}`"),
        }
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

    /// Handle an incoming dealer message.
    ///
    /// If this is a new valid dealer message, persists it to storage before returning.
    pub(super) async fn receive_dealing<TContext>(
        &mut self,
        storage: &mut Storage<TContext>,
        epoch: Epoch,
        dealer: PublicKey,
        pub_msg: DealerPubMsg<MinSig>,
        priv_msg: DealerPrivMsg,
    ) -> eyre::Result<PlayerAck<PublicKey>>
    where
        TContext: commonware_runtime::Storage + Clock + Metrics,
    {
        // If we've already generated an ack, return the cached version
        if let Some(ack) = self.acks.get(&dealer) {
            return Ok(ack.clone());
        }

        // Otherwise generate a new ack
        let ack = self
            .player
            .dealer_message::<N3f1>(dealer.clone(), pub_msg.clone(), priv_msg.clone())
            // FIXME(janis): it would be great to know why exactly that is not the case.
            .ok_or_eyre(
                "applying dealer message to player instance did not result in a usable ack",
            )?;
        storage
            .append_dealing(epoch, dealer.clone(), pub_msg, priv_msg)
            .await
            .wrap_err("unable to append dealing to journal")?;
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
        if let Some(ack) = self
            .player
            .dealer_message::<N3f1>(dealer.clone(), pub_msg, priv_msg)
        {
            self.acks.insert(dealer, ack);
        }
    }

    /// Finalize the player's participation in the DKG round.
    pub(super) fn finalize(
        self,
        logs: BTreeMap<PublicKey, dkg::DealerLog<MinSig, PublicKey>>,
        strategy: &impl Strategy,
    ) -> Result<(Output<MinSig, PublicKey>, Share), dkg::Error> {
        self.player.finalize::<N3f1>(logs, strategy)
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
    use commonware_cryptography::{
        bls12381::{dkg, primitives::sharing::Mode},
        ed25519::PrivateKey,
        transcript::Summary,
    };
    use commonware_math::algebra::Random as _;
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::TryFromIterator as _;

    fn make_test_state(rng: &mut impl rand_core::CryptoRngCore, epoch: u64) -> State {
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
            players: pubkeys.clone(),
            syncers: pubkeys,
            is_full_dkg: false,
        }
    }

    fn make_legacy_state(rng: &mut impl rand_core::CryptoRngCore, epoch: u64) -> LegacyState {
        let mut keys: Vec<_> = (0..3)
            .map(|i| PrivateKey::from_seed(i + epoch * 100))
            .collect();
        keys.sort_by_key(|k| k.public_key());
        let pubkeys = ordered::Set::try_from_iter(keys.iter().map(|k| k.public_key())).unwrap();

        let (output, _shares) =
            dkg::deal::<_, _, N3f1>(&mut *rng, Mode::NonZeroCounter, pubkeys.clone()).unwrap();

        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let peers =
            ordered::Map::from_iter_dedup(pubkeys.iter().map(|k: &PublicKey| (k.clone(), addr)));

        LegacyState {
            epoch: Epoch::new(epoch),
            seed: Summary::random(rng),
            output,
            share: None,
            dealers: peers.clone(),
            players: peers.clone(),
            syncers: peers,
            is_full_dkg: false,
        }
    }

    #[test]
    fn states_migration_migrates_last_two() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let partition_prefix = "test_dkg";
            let states_partition = format!("{partition_prefix}_states");
            let states_metadata_partition = format!("{partition_prefix}_states_metadata");
            let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, POOL_CAPACITY);

            let ancient_legacy = make_legacy_state(&mut context, 1);
            let previous_legacy = make_legacy_state(&mut context, 2);
            let latest_legacy = make_legacy_state(&mut context, 3);
            let previous_expected: State = previous_legacy.clone().into();
            let latest_expected: State = latest_legacy.clone().into();

            // Populate the legacy journal with three entries.
            {
                let journal = contiguous::variable::Journal::<_, LegacyState>::init(
                    context.with_label("journal_setup"),
                    contiguous::variable::Config {
                        partition: states_partition.clone(),
                        compression: None,
                        codec_config: MAXIMUM_VALIDATORS,
                        page_cache: page_cache.clone(),
                        write_buffer: WRITE_BUFFER,
                        items_per_section: NZU64!(1),
                    },
                )
                .await
                .unwrap();

                journal.append(ancient_legacy).await.unwrap();
                journal.append(previous_legacy).await.unwrap();
                journal.append(latest_legacy).await.unwrap();
                journal.sync().await.unwrap();
            }

            let mut states = metadata::Metadata::init(
                context.with_label("states"),
                metadata::Config {
                    partition: states_metadata_partition.clone(),
                    codec_config: MAXIMUM_VALIDATORS,
                },
            )
            .await
            .unwrap();

            migrate_journal_to_metadata_if_necessary(
                &context,
                &mut states,
                &states_partition,
                &page_cache,
            )
            .await
            .unwrap();

            // Only the last two states should be migrated.
            assert!(
                states.get(&1).is_none(),
                "ancient state should not be migrated"
            );
            assert_eq!(
                &previous_expected,
                states.get(&previous_expected.epoch.get()).unwrap(),
            );
            assert_eq!(
                &latest_expected,
                states.get(&latest_expected.epoch.get()).unwrap(),
            );

            // Journal should be destroyed.
            let reopened = contiguous::variable::Journal::<_, LegacyState>::init(
                context.with_label("journal_verify"),
                contiguous::variable::Config {
                    partition: states_partition.clone(),
                    compression: None,
                    codec_config: MAXIMUM_VALIDATORS,
                    page_cache: page_cache.clone(),
                    write_buffer: WRITE_BUFFER,
                    items_per_section: NZU64!(1),
                },
            )
            .await
            .unwrap();

            assert_eq!(reopened.size().await, 0);

            // Metadata persists across reopens.
            drop(states);
            let states = metadata::Metadata::<_, u64, State>::init(
                context.with_label("states_reopen"),
                metadata::Config {
                    partition: states_metadata_partition,
                    codec_config: MAXIMUM_VALIDATORS,
                },
            )
            .await
            .unwrap();
            assert_eq!(
                &previous_expected,
                states.get(&previous_expected.epoch.get()).unwrap(),
            );
            assert_eq!(
                &latest_expected,
                states.get(&latest_expected.epoch.get()).unwrap(),
            );
        });
    }

    #[test]
    fn states_migration_single_entry() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let partition_prefix = "test_dkg_single";
            let states_partition = format!("{partition_prefix}_states");
            let states_metadata_partition = format!("{partition_prefix}_states_metadata");
            let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, POOL_CAPACITY);

            let only_legacy = make_legacy_state(&mut context, 5);
            let only_expected: State = only_legacy.clone().into();

            // Populate the legacy journal with a single entry.
            {
                let journal = contiguous::variable::Journal::<_, LegacyState>::init(
                    context.with_label("journal_setup"),
                    contiguous::variable::Config {
                        partition: states_partition.clone(),
                        compression: None,
                        codec_config: MAXIMUM_VALIDATORS,
                        page_cache: page_cache.clone(),
                        write_buffer: WRITE_BUFFER,
                        items_per_section: NZU64!(1),
                    },
                )
                .await
                .unwrap();

                journal.append(only_legacy).await.unwrap();
                journal.sync().await.unwrap();
            }

            let mut states = metadata::Metadata::init(
                context.with_label("states"),
                metadata::Config {
                    partition: states_metadata_partition,
                    codec_config: MAXIMUM_VALIDATORS,
                },
            )
            .await
            .unwrap();

            migrate_journal_to_metadata_if_necessary(
                &context,
                &mut states,
                &states_partition,
                &page_cache,
            )
            .await
            .unwrap();

            // Single entry: saturating_sub(1) == 0, range 0..=0, so only that one state.
            assert_eq!(states.keys().count(), 1);
            assert_eq!(
                &only_expected,
                states.get(&only_expected.epoch.get()).unwrap(),
            );
        });
    }

    #[test]
    fn states_migration_does_not_overwrite_existing_metadata() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let partition_prefix = "test_dkg_noop";
            let states_partition = format!("{partition_prefix}_states");
            let states_metadata_partition = format!("{partition_prefix}_states_metadata");
            let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, POOL_CAPACITY);

            let existing_state = make_test_state(&mut context, 10);
            let journal_legacy = make_legacy_state(&mut context, 20);
            let journal_expected_epoch = journal_legacy.epoch.get();

            // Pre-populate metadata.
            let mut states = metadata::Metadata::init(
                context.with_label("states"),
                metadata::Config {
                    partition: states_metadata_partition.clone(),
                    codec_config: MAXIMUM_VALIDATORS,
                },
            )
            .await
            .unwrap();
            states.put(existing_state.epoch.get(), existing_state.clone());
            states.sync().await.unwrap();

            // Populate a legacy journal with different data.
            {
                let journal = contiguous::variable::Journal::<_, LegacyState>::init(
                    context.with_label("journal_setup"),
                    contiguous::variable::Config {
                        partition: states_partition.clone(),
                        compression: None,
                        codec_config: MAXIMUM_VALIDATORS,
                        page_cache: page_cache.clone(),
                        write_buffer: WRITE_BUFFER,
                        items_per_section: NZU64!(1),
                    },
                )
                .await
                .unwrap();
                journal.append(journal_legacy).await.unwrap();
                journal.sync().await.unwrap();
            }

            // Run migration — should be a no-op since metadata is already populated.
            migrate_journal_to_metadata_if_necessary(
                &context,
                &mut states,
                &states_partition,
                &page_cache,
            )
            .await
            .unwrap();

            assert_eq!(states.keys().count(), 1);
            assert_eq!(
                &existing_state,
                states.get(&existing_state.epoch.get()).unwrap(),
            );
            assert!(
                states.get(&journal_expected_epoch).is_none(),
                "journal state must not be written into already-populated metadata"
            );
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
        use rand_08::SeedableRng as _;
        let mut rng = rand_08::rngs::StdRng::seed_from_u64(42);

        let keys = std::iter::repeat_with(|| PrivateKey::random(&mut rng))
            .take(3)
            .collect::<Vec<_>>();
        let pubkeys = ordered::Set::try_from_iter(keys.iter().map(|k| k.public_key())).unwrap();

        let (_output, shares) =
            dkg::deal::<MinSig, _, N3f1>(&mut rng, Mode::NonZeroCounter, pubkeys).unwrap();

        let share = shares.into_iter().next().unwrap().1;
        assert_roundtrip(&ShareState::Plaintext(Some(share)));
    }
}
