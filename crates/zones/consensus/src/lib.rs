//! Commonware Simplex consensus for multi-sequencer Tempo Zones.
//!
//! Every quorum member runs one Simplex instance with ed25519 votes and a round-robin elector over
//! the manifest's static participant set, in a single never-ending epoch. Marshal orders,
//! persists, and backfills finalized blocks; the executor applies them to reth and the deposit
//! queue. A crashed leader costs one view timeout: the next view's leader builds on the same
//! certified parent. No portal leadership, forced recovery, or role switching is involved.
//!
//! The wiring mirrors Tempo L1 (`tempo-consensus`) and reuses its block wrapper, digest, and
//! finalized-block storage. Blocks carry no consensus context because the Zone prover hard-codes
//! `consensus_context: None`, so the marshal `Inline` wrapper verifies before the notarize vote.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod application;
mod executor;
pub mod import;
mod provider;

use std::{collections::HashMap, num::NonZeroUsize, sync::Arc, time::Duration};

use alloy_primitives::Address;
use commonware_broadcast::buffered;
use commonware_consensus::{
    Reporters,
    marshal::{
        self, core, resolver,
        standard::{Inline, Standard},
    },
    simplex::{
        self,
        config::{Floor, ForwardPolicy, SkipBudget, SkipPolicy},
        elector::RoundRobin,
    },
    types::{Epoch, FixedEpocher, ViewDelta},
};
use commonware_cryptography::{Sha256, certificate::ConstantProvider, ed25519::PublicKey};
use commonware_parallel::Sequential;
use commonware_runtime::{Supervisor as _, buffer::paged::CacheRef};
use commonware_utils::{NZU64, NZUsize, ordered::Set};
use eyre::{OptionExt as _, WrapErr as _};
use reth_chainspec::EthChainSpec as _;
use reth_node_api::ConsensusEngineHandle;
use reth_payload_builder::PayloadBuilderHandle;
use reth_provider::BlockSource;
use tempo_consensus::{
    consensus::{Block, Digest},
    network::limit_channel,
    storage,
};
use tracing::info;
use zone_chainspec::ZoneChainSpec;
use zone_l1::{DepositQueue, EncryptionKeyRing, L1BlockTracker, TempoStateExt as _};
use zone_p2p::{
    BROADCASTER_CHANNEL, CERTIFICATES_CHANNEL, MARSHAL_CHANNEL, RESOLVER_CHANNEL, SimplexNetwork,
    VOTES_CHANNEL, ZoneManifest,
};
use zone_payload::ZonePayloadTypes;
use zone_sequencer::ProofCollectorHandle;

pub use provider::ConsensusProvider;

/// Simplex signing scheme: ed25519 votes signed with each node's P2P identity key.
pub type Scheme = simplex::scheme::ed25519::Scheme;

pub(crate) type MarshalMailbox = core::Mailbox<Scheme, Standard<Block>>;

/// Partition prefix of every consensus archive under the runtime storage directory.
const PARTITION_PREFIX: &str = "engine";
/// One epoch covers every height a Zone will ever reach; membership is static.
const EPOCH_LENGTH: std::num::NonZeroU64 = NZU64!(1 << 40);
const MAILBOX_SIZE: NonZeroUsize = NZUsize!(16_384);
const DEQUE_SIZE: usize = 10;
const VIEWS_TO_TRACK: u64 = 256;
/// Marshal retains view data longer than Simplex so lagging peers can still repair from it.
const MARSHAL_VIEW_RETENTION_MULTIPLIER: u64 = 10;
/// Marshal delivers finalized blocks strictly one at a time.
const MAX_PENDING_ACKS: NonZeroUsize = NZUsize!(1);
/// Finalized blocks kept in the prunable cache in front of reth (about nine hours at 500 ms).
const FINALIZED_BLOCKS_RETENTION: u64 = 64_800;
const FCU_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(300);

/// Execution-layer handles and Zone state the consensus engine drives.
pub struct Config<TProvider> {
    /// The Zone node's provider.
    pub provider: TProvider,
    /// Engine API handle for `new_payload` and forkchoice updates.
    pub engine: ConsensusEngineHandle<ZonePayloadTypes>,
    /// Payload builder resolved after a forkchoice update with attributes.
    pub payload_builder: PayloadBuilderHandle<ZonePayloadTypes>,
    /// Zone chain spec, for hardfork-dependent payload attributes and import rules.
    pub chain_spec: Arc<ZoneChainSpec>,
    /// Finalized L1 blocks; consumed only when a Zone block finalizes.
    pub deposit_queue: DepositQueue,
    /// L1 anchors independently observed by the subscriber.
    pub l1_block_tracker: L1BlockTracker,
    /// Keys that decrypt deposits in proposals.
    pub encryption_keys: EncryptionKeyRing,
    /// ZonePortal address, used in deposit decryption.
    pub portal_address: Address,
    /// Shared sequencer address; the beneficiary of every leader without a manifest override.
    pub fee_recipient: Address,
    /// Proof WAL writer invoked for every finalized block before reth finalizes it.
    pub proof_collector: Option<ProofCollectorHandle>,
    /// Static participant set and consensus parameters.
    pub manifest: Arc<ZoneManifest>,
}

/// Run Simplex consensus on the dedicated Commonware runtime until an actor stops.
///
/// Returns only on failure: one actor's exit stops all of them.
pub async fn run<TProvider: ConsensusProvider>(
    context: commonware_runtime::tokio::Context,
    network: SimplexNetwork,
    config: Config<TProvider>,
) -> eyre::Result<()> {
    let params = config.manifest.consensus().clone();
    let SimplexNetwork {
        private_key,
        participants,
        oracle,
        namespace,
        max_message_size,
        votes,
        certificates,
        resolver: simplex_resolver,
        broadcaster,
        marshal: marshal_network,
    } = network;
    let public_key = commonware_cryptography::Signer::public_key(&private_key);
    let participants = Set::try_from(participants)
        .map_err(|_| eyre::eyre!("manifest contains duplicate quorum identities"))?;
    let namespace = [namespace.as_slice(), b"_SIMPLEX"].concat();
    let scheme = Scheme::signer(&namespace, participants.clone(), private_key)
        .ok_or_eyre("this node's identity is not a Simplex participant")?;
    let epocher = FixedEpocher::new(EPOCH_LENGTH);
    let page_cache = CacheRef::from_pooler(
        &context,
        storage::BUFFER_POOL_PAGE_SIZE,
        storage::BUFFER_POOL_CAPACITY,
    );

    let genesis_hash = config.chain_spec.genesis_hash();
    let genesis = config
        .provider
        .find_sealed_or_recovered_block(genesis_hash, BlockSource::Any)?
        .ok_or_eyre("execution layer has no genesis block")?;
    let genesis = Block::from_execution_block_unchecked(genesis);
    let genesis_checkpoint = config
        .provider
        .history_by_block_number(0)?
        .tempo_num_hash()
        .wrap_err("cannot read the genesis Tempo checkpoint")?;

    let certificates_archive = storage::init_finalizations_archive::<_, Scheme>(
        &context,
        PARTITION_PREFIX,
        page_cache.clone(),
        &epocher,
    )
    .await
    .wrap_err("failed to initialize the finalizations archive")?;
    let blocks = storage::init_finalized_blocks(
        &context,
        PARTITION_PREFIX,
        page_cache.clone(),
        provider::FinalizedBlocks(config.provider.clone()),
        FINALIZED_BLOCKS_RETENTION,
    )
    .await?;

    // Marshal restores its processed height from its own metadata, so starting from genesis is
    // correct on every restart. Snapshot sync, which would need a non-genesis floor, is out of
    // scope.
    let (marshal, marshal_mailbox, marshal_floor) = core::Actor::init(
        context.child("marshal"),
        certificates_archive,
        blocks,
        marshal::Config {
            provider: ConstantProvider::<Scheme, Epoch>::new(scheme.clone()),
            epocher: epocher.clone(),
            start: marshal::Start::Genesis(genesis),
            partition_prefix: PARTITION_PREFIX.into(),
            mailbox_size: MAILBOX_SIZE,
            view_retention: ViewDelta::new(VIEWS_TO_TRACK * MARSHAL_VIEW_RETENTION_MULTIPLIER),
            prunable_items_per_section: storage::PRUNABLE_ITEMS_PER_SECTION,
            page_cache: page_cache.clone(),
            replay_buffer: storage::REPLAY_BUFFER,
            key_write_buffer: storage::WRITE_BUFFER,
            value_write_buffer: storage::WRITE_BUFFER,
            block_codec_config: (),
            max_repair: storage::MAX_REPAIR,
            max_pending_acks: MAX_PENDING_ACKS,
            strategy: Sequential,
        },
    )
    .await;
    let finalized_floor = marshal_floor.height().unwrap_or_default();
    info!(
        target: "zone::consensus",
        %public_key,
        participants = participants.len(),
        %finalized_floor,
        "Starting Zone Simplex consensus"
    );

    let (executor, executor_mailbox) = executor::init(executor::Config {
        provider: config.provider.clone(),
        engine: config.engine,
        payload_builder: config.payload_builder,
        deposit_queue: config.deposit_queue.clone(),
        l1_block_tracker: config.l1_block_tracker.clone(),
        proof_collector: config.proof_collector,
        marshal: marshal_mailbox.clone(),
        finalized_floor,
        fcu_heartbeat_interval: FCU_HEARTBEAT_INTERVAL,
    })?;

    let beneficiaries: HashMap<PublicKey, Address> = config
        .manifest
        .nodes()
        .iter()
        .filter_map(|node| Some((node.ed25519_public_key().clone(), node.beneficiary()?)))
        .collect();
    let application = application::Application::new(application::Config {
        provider: config.provider,
        executor: executor_mailbox.clone(),
        chain_spec: config.chain_spec,
        deposit_queue: config.deposit_queue,
        l1_block_tracker: config.l1_block_tracker,
        encryption_keys: config.encryption_keys,
        portal_address: config.portal_address,
        fee_recipient: config.fee_recipient,
        beneficiaries,
        proposal_anchor_wait: params.proposal_anchor_wait,
        genesis_checkpoint,
    });
    let application = Inline::new(
        context.child("application"),
        application,
        marshal_mailbox.clone(),
        epocher.clone(),
    );

    let (broadcast, broadcast_mailbox) = buffered::Engine::<_, PublicKey, Block, _>::new(
        context.child("broadcast"),
        buffered::Config {
            public_key: public_key.clone(),
            mailbox_size: MAILBOX_SIZE,
            deque_size: DEQUE_SIZE,
            priority: true,
            codec_config: (),
            peer_provider: oracle.clone(),
        },
    );
    let marshal_resolver = resolver::p2p::init(
        context.child("resolver"),
        resolver::p2p::Config {
            public_key,
            peer_provider: oracle.clone(),
            blocker: oracle.clone(),
            mailbox_size: MAILBOX_SIZE,
            timeout: params.fetch_timeout,
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        },
        limit_channel(&context, marshal_network, MARSHAL_CHANNEL, max_message_size),
    );

    let engine = simplex::Engine::new(
        context.child("simplex"),
        simplex::Config {
            scheme,
            // Shuffle by namespace so zones sharing a fleet do not share one leader order.
            elector: RoundRobin::<Sha256>::shuffled(&namespace),
            blocker: oracle,
            automaton: application.clone(),
            relay: application.clone(),
            reporter: marshal_mailbox,
            track_historical_votes: true,
            strategy: Sequential,
            partition: format!("{PARTITION_PREFIX}_simplex_epoch_0"),
            mailbox_size: MAILBOX_SIZE,
            epoch: Epoch::zero(),
            // The vote journal restores progress above the floor, as on L1.
            floor: Floor::Genesis(Digest(genesis_hash)),
            replay_buffer: storage::REPLAY_BUFFER,
            write_buffer: storage::WRITE_BUFFER,
            page_cache,
            leader_timeout: params.leader_timeout,
            certification_timeout: params.certification_timeout,
            timeout_retry: params.timeout_retry,
            view_retention: ViewDelta::new(VIEWS_TO_TRACK),
            skip: SkipPolicy::Enabled {
                timeout: params.skip_timeout,
                budget: SkipBudget::Participants,
            },
            fetch_timeout: params.fetch_timeout,
            forward: ForwardPolicy::Disabled,
        },
    );

    let marshal = marshal.start(
        Reporters::from((application, executor_mailbox)),
        broadcast_mailbox,
        marshal_resolver,
    );
    let broadcast = broadcast.start(limit_channel(
        &context,
        broadcaster,
        BROADCASTER_CHANNEL,
        max_message_size,
    ));
    let executor = executor.start(context.child("executor"));
    let engine = engine.start(
        limit_channel(&context, votes, VOTES_CHANNEL, max_message_size),
        limit_channel(
            &context,
            certificates,
            CERTIFICATES_CHANNEL,
            max_message_size,
        ),
        limit_channel(
            &context,
            simplex_resolver,
            RESOLVER_CHANNEL,
            max_message_size,
        ),
    );

    // Even a clean actor exit (for example marshal losing an acknowledgement) must stop
    // consensus.
    let actors = ["marshal", "broadcast", "executor", "simplex"];
    let (result, index, siblings) =
        futures::future::select_all([marshal, broadcast, executor, engine]).await;
    for sibling in siblings {
        sibling.abort();
    }
    let actor = actors[index];
    result.wrap_err_with(|| format!("Zone consensus actor `{actor}` failed"))?;
    Err(eyre::eyre!("Zone consensus actor `{actor}` stopped"))
}
