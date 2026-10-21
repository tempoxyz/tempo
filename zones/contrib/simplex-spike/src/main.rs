//! Type-check spike: the exact commonware 2026.9.0 composition proposed for Tempo Zones.
//!
//! ed25519 Simplex scheme + RoundRobin elector + marshal `Standard`/`Inline` + a mock block
//! whose digest/codec shape matches the zone `Block` wrapper (RLP-ish bytes, 32-byte digest).
//! Nothing here runs; `cargo check` is the deliverable.

#![allow(dead_code, unused_variables)]

use std::{num::NonZeroUsize, sync::Arc, time::Duration};

use bytes::{Buf, BufMut};
use commonware_actor::Feedback;
use commonware_broadcast::buffered;
use commonware_codec::{EncodeSize, Error as CodecError, Read, Write};
use commonware_consensus::{
    Application, Heightable, Reporter,
    marshal::{
        self, Update,
        ancestry::Ancestry,
        core::{Actor as MarshalActor, Mailbox as MarshalMailbox},
        resolver,
        standard::{Inline, Standard},
    },
    simplex::{
        self,
        config::{Floor, ForwardPolicy, SkipBudget, SkipPolicy},
        elector::RoundRobin,
        types::{Context, Finalization},
    },
    types::{Epoch, FixedEpocher, Height, ViewDelta},
};
use commonware_cryptography::{
    Committable, Digestible,
    certificate::ConstantProvider,
    ed25519::{PrivateKey, PublicKey},
    sha256::Digest,
};
use commonware_p2p::{Blocker, Provider, Receiver as P2pReceiver, Sender as P2pSender, TrackedPeers};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock, Metrics, Spawner, buffer::paged::CacheRef, tokio::Context as RtContext,
};
use commonware_storage::{
    archive::{immutable, prunable},
    translator::TwoCap,
};
use commonware_utils::{NZU64, NZUsize, acknowledgement::Exact, ordered::Set};
use rand_core::Rng;
use commonware_utils::Acknowledgement as _;
use futures::StreamExt as _;
use commonware_runtime::Supervisor as _;

// ---------------------------------------------------------------------------------------------
// Scheme and aliases exactly as proposed in simplex.md §6.1
// ---------------------------------------------------------------------------------------------

type Scheme = simplex::scheme::ed25519::Scheme;
type SchemeProvider = ConstantProvider<Scheme, Epoch>;
type Epocher = FixedEpocher;
type ZoneFinalization = Finalization<Scheme, Digest>;
type Certificates<E> = immutable::Archive<E, Digest, ZoneFinalization>;
type Blocks<E> = prunable::Archive<TwoCap, E, Digest, Block>;
type Marshal<E> = MarshalActor<
    E,
    Standard<Block>,
    SchemeProvider,
    Certificates<E>,
    Blocks<E>,
    Epocher,
    Sequential,
    Exact,
>;
type Mailbox = MarshalMailbox<Scheme, Standard<Block>>;
type App<E> = Inline<E, Scheme, ZoneApplication, Block, Epocher>;

// ---------------------------------------------------------------------------------------------
// Mock block: stands in for the zone `Block` wrapper (digest = EL hash, codec = raw bytes).
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
struct Block {
    height: u64,
    parent: Digest,
    payload: Vec<u8>,
}

impl Block {
    fn digest_bytes(&self) -> Digest {
        { use commonware_cryptography::Hasher as _; commonware_cryptography::Sha256::hash(&[&self.payload]) }
    }
}

impl Heightable for Block {
    fn height(&self) -> Height {
        Height::new(self.height)
    }
}

impl Digestible for Block {
    type Digest = Digest;
    fn digest(&self) -> Digest {
        self.digest_bytes()
    }
}

impl Committable for Block {
    type Commitment = Digest;
    fn commitment(&self) -> Digest {
        self.digest_bytes()
    }
}

impl Write for Block {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_u64(self.height);
        self.parent.write(buf);
        (self.payload.len() as u32).write(buf);
        buf.put_slice(&self.payload);
    }
}

impl EncodeSize for Block {
    fn encode_size(&self) -> usize {
        8 + 32 + 4 + self.payload.len()
    }
}

impl Read for Block {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _cfg: &()) -> Result<Self, CodecError> {
        let height = buf.get_u64();
        let parent = Digest::read_cfg(buf, &())?;
        let len = u32::read_cfg(buf, &())? as usize;
        let mut payload = vec![0; len];
        buf.copy_to_slice(&mut payload);
        Ok(Self { height, parent, payload })
    }
}

impl commonware_consensus::Block for Block {
    fn parent(&self) -> Digest {
        self.parent
    }
}

// ---------------------------------------------------------------------------------------------
// Application: the shape of `ZoneApplication` (propose / verify) from simplex.md §6.3.
// ---------------------------------------------------------------------------------------------

#[derive(Clone)]
struct ZoneApplication {
    local: PublicKey,
}

impl<E> Application<E> for ZoneApplication
where
    E: Rng + Spawner + Metrics + Clock,
{
    type SigningScheme = Scheme;
    type Context = Context<Digest, PublicKey>;
    type Block = Block;
    type Input = ();

    async fn propose(
        &mut self,
        (_rt, ctx): (E, Self::Context),
        mut ancestry: impl Ancestry<Block>,
        (): (),
    ) -> Option<Block> {
        let parent = ancestry.next().await?;
        // Real impl: read parent cursor, wait for the next finalized Tempo anchor, build
        // ZonePayloadAttributes, ask the executor to build on `parent`.
        Some(Block {
            height: parent.height + 1,
            parent: parent.digest(),
            payload: ctx.round.view().get().to_be_bytes().to_vec(),
        })
    }

    async fn verify(
        &mut self,
        (_rt, _ctx): (E, Self::Context),
        mut ancestry: impl Ancestry<Block>,
    ) -> bool {
        // Real impl: follower validations + executor new_payload; stay pending when unsure.
        ancestry.next().await.is_some()
    }
}

impl Reporter for ZoneApplication {
    type Activity = Update<Block>;
    fn report(&mut self, activity: Self::Activity) -> Feedback {
        // Real impl: observe tips for metrics; acks happen in the executor.
        if let Update::Block(_, ack) = activity {
            ack.acknowledge();
        }
        Feedback::Ok
    }
}

/// Stand-in for the zone executor's mailbox: it is the marshal reporter that acks finalized blocks.
#[derive(Clone)]
struct ExecutorMailbox;

impl Reporter for ExecutorMailbox {
    type Activity = Update<Block>;
    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match activity {
            Update::Tip(_, _, _) => {}
            Update::Block(_block, ack) => {
                // Real impl: ensure executed, collect witness, FCU head=safe=finalized, advance
                // deposit queue, then ack.
                ack.acknowledge();
            }
        }
        Feedback::Ok
    }
}

// ---------------------------------------------------------------------------------------------
// Static peer provider over the manifest (simplex.md §6.7).
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct StaticPeerProvider {
    peers: TrackedPeers<PublicKey>,
}

impl Provider for StaticPeerProvider {
    type PublicKey = PublicKey;

    async fn peer_set(&mut self, _id: u64) -> Option<TrackedPeers<PublicKey>> {
        Some(self.peers.clone())
    }

    async fn subscribe(&mut self) -> commonware_p2p::PeerSetSubscription<PublicKey> {
        // Static membership: the sender is dropped so the subscription never fires.
        let (_tx, rx) = tokio::sync::mpsc::unbounded_channel();
        rx
    }
}

// ---------------------------------------------------------------------------------------------
// Wiring (never executed; type-checked only).
// ---------------------------------------------------------------------------------------------

struct Timing {
    leader_timeout: Duration,
    certification_timeout: Duration,
    timeout_retry: Duration,
    skip_timeout: Duration,
    fetch_timeout: Duration,
    view_retention: u64,
}

async fn wire<B, VS, VR, CS, CR, RS, RR, BS, BR, MS, MR>(
    context: RtContext,
    namespace: &[u8],
    participants: Set<PublicKey>,
    private_key: PrivateKey,
    blocker: B,
    genesis: Block,
    timing: Timing,
    votes: (VS, VR),
    certificates: (CS, CR),
    simplex_resolver: (RS, RR),
    broadcast: (BS, BR),
    marshal_backfill: (MS, MR),
) where
    B: Blocker<PublicKey = PublicKey>,
    VS: P2pSender<PublicKey = PublicKey>,
    VR: P2pReceiver<PublicKey = PublicKey>,
    CS: P2pSender<PublicKey = PublicKey>,
    CR: P2pReceiver<PublicKey = PublicKey>,
    RS: P2pSender<PublicKey = PublicKey>,
    RR: P2pReceiver<PublicKey = PublicKey>,
    BS: P2pSender<PublicKey = PublicKey>,
    BR: P2pReceiver<PublicKey = PublicKey>,
    MS: P2pSender<PublicKey = PublicKey>,
    MR: P2pReceiver<PublicKey = PublicKey>,
{
    let public_key = commonware_cryptography::Signer::public_key(&private_key);

    // Signer when our key is in the set, verifier otherwise (rpc_only nodes).
    let scheme = Scheme::signer(namespace, participants.clone(), private_key)
        .unwrap_or_else(|| Scheme::verifier(namespace, participants.clone()));
    let provider = SchemeProvider::new(scheme.clone());
    let epocher = Epocher::new(NZU64!(1 << 40));
    let mailbox_size: NonZeroUsize = NZUsize!(16_384);
    let page_cache = CacheRef::from_pooler(&context, commonware_utils::NZU16!(4_096), NZUsize!(8_192));

    // Archives (same partitions as crates/consensus/src/storage/mod.rs).
    let certificates_store: Certificates<RtContext> = immutable::Archive::init(
        context.child("finalizations_by_height"),
        immutable::Config {
            metadata_partition: "engine-finalizations-by-height-metadata".into(),
            freezer_table_partition: "engine-finalizations-by-height-freezer-table".into(),
            freezer_table_initial_size: 1 << 20,
            freezer_table_resize_frequency: 4,
            freezer_table_resize_chunk_size: 1 << 16,
            freezer_key_partition: "engine-finalizations-by-height-freezer-key".into(),
            freezer_key_page_cache: page_cache.clone(),
            freezer_value_partition: "engine-finalizations-by-height-freezer-value".into(),
            freezer_value_target_size: 1 << 30,
            freezer_value_compression: Some(3),
            ordinal_partition: "engine-finalizations-by-height-ordinal".into(),
            items_per_section: NZU64!(262_144),
            codec_config: <Scheme as commonware_cryptography::certificate::Verifier>::certificate_codec_config_unbounded(),
            replay_buffer: NZUsize!(8 << 20),
            freezer_key_write_buffer: NZUsize!(1 << 20),
            freezer_value_write_buffer: NZUsize!(1 << 20),
            ordinal_write_buffer: NZUsize!(1 << 20),
        },
    )
    .await
    .expect("archive");
    let blocks_store: Blocks<RtContext> = prunable::Archive::init(
        context.child("finalized_blocks_prunable"),
        prunable::Config {
            translator: TwoCap,
            key_partition: "engine-finalized-blocks-prunable-key".into(),
            key_page_cache: page_cache.clone(),
            value_partition: "engine-finalized-blocks-prunable-value".into(),
            metadata_partition: "engine-finalized-blocks-prunable-metadata".into(),
            compression: Some(3),
            codec_config: (),
            items_per_section: NZU64!(4_096),
            key_write_buffer: NZUsize!(1 << 20),
            value_write_buffer: NZUsize!(1 << 20),
            replay_buffer: NZUsize!(8 << 20),
        },
    )
    .await
    .expect("archive");

    // Marshal.
    let (marshal_actor, marshal_mailbox, _floor): (Marshal<RtContext>, Mailbox, _) =
        MarshalActor::init(
            context.child("marshal"),
            certificates_store,
            blocks_store,
            marshal::Config {
                provider,
                epocher: epocher.clone(),
                start: marshal::Start::Genesis(genesis.clone()),
                partition_prefix: "engine".into(),
                mailbox_size,
                view_retention: ViewDelta::new(timing.view_retention * 10),
                prunable_items_per_section: NZU64!(4_096),
                page_cache: page_cache.clone(),
                replay_buffer: NZUsize!(8 << 20),
                key_write_buffer: NZUsize!(1 << 20),
                value_write_buffer: NZUsize!(1 << 20),
                block_codec_config: (),
                max_repair: NZUsize!(20),
                max_pending_acks: NZUsize!(1),
                strategy: Sequential,
            },
        )
        .await;

    // Application wrapper (Inline: verifies before notarize; no CertifiableBlock needed).
    let application: App<RtContext> = Inline::new(
        context.child("application"),
        ZoneApplication { local: public_key.clone() },
        marshal_mailbox.clone(),
        epocher.clone(),
    );

    // Peers, broadcast, resolver.
    let peer_provider = StaticPeerProvider {
        peers: TrackedPeers::primary(participants.clone()),
    };
    let (broadcast_engine, broadcast_mailbox) = buffered::Engine::<_, PublicKey, Block, _>::new(
        context.child("broadcast"),
        buffered::Config {
            public_key: public_key.clone(),
            mailbox_size,
            deque_size: 10,
            priority: true,
            codec_config: (),
            peer_provider: peer_provider.clone(),
        },
    );
    let (resolver_rx, resolver_mailbox) = resolver::p2p::init(
        context.child("resolver"),
        resolver::p2p::Config {
            public_key: public_key.clone(),
            peer_provider: peer_provider.clone(),
            blocker: blocker.clone(),
            mailbox_size,
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        },
        marshal_backfill,
    );

    // Simplex engine (one epoch, round-robin leaders).
    let engine = simplex::Engine::new(
        context.child("simplex"),
        simplex::Config {
            scheme,
            elector: RoundRobin::<commonware_cryptography::Sha256>::shuffled(namespace),
            blocker,
            automaton: application.clone(),
            relay: application.clone(),
            reporter: marshal_mailbox.clone(),
            track_historical_votes: true,
            strategy: Sequential,
            partition: "engine_simplex_epoch_0".into(),
            mailbox_size,
            epoch: Epoch::new(0),
            floor: Floor::<Scheme, Digest>::Genesis(genesis.digest()),
            replay_buffer: NZUsize!(8 << 20),
            write_buffer: NZUsize!(1 << 20),
            page_cache,
            leader_timeout: timing.leader_timeout,
            certification_timeout: timing.certification_timeout,
            timeout_retry: timing.timeout_retry,
            view_retention: ViewDelta::new(timing.view_retention),
            skip: SkipPolicy::Enabled {
                timeout: timing.skip_timeout,
                budget: SkipBudget::Participants,
            },
            fetch_timeout: timing.fetch_timeout,
            forward: ForwardPolicy::Disabled,
        },
    );

    // Start everything (L1 order): marshal, broadcast, simplex.
    let reporters = commonware_consensus::Reporters::from((application.clone(), ExecutorMailbox));
    let _marshal_handle = marshal_actor.start(reporters, broadcast_mailbox, (resolver_rx, resolver_mailbox));
    let _broadcast_handle = broadcast_engine.start(broadcast);
    let _engine_handle = engine.start(votes, certificates, simplex_resolver);
    let _ = Arc::new(());
}

fn main() {
    println!("type-check only");
}
