use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use alloy_consensus::Header;
use alloy_primitives::B256;
use alloy_rpc_types_engine::{ForkchoiceState, PayloadId, PayloadStatus, PayloadStatusEnum};
use commonware_codec::{Encode as _, FixedSize as _, Read as _};
use commonware_consensus::{
    marshal::{
        core::{self, Buffer},
        resolver::handler::{Handler, Request},
        standard::Standard,
    },
    simplex::{
        scheme::bls12381_threshold::vrf,
        types::{Finalization, Proposal},
    },
    types::{Epoch, FixedEpocher, Height, Round, View, ViewDelta},
};
use commonware_cryptography::bls12381::primitives::variant::MinSig;
use commonware_p2p::Recipients;
use commonware_parallel::Sequential;
use commonware_resolver::{Consumer as _, Resolver};
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::archive::{Archive as _, immutable};
use commonware_utils::{
    NZU64, NZUsize,
    acknowledgement::Exact,
    channel::{mpsc, oneshot},
    sync::Mutex,
    vec::NonEmptyVec,
};
use reth_ethereum::rpc::eth::primitives::BlockNumHash;
use reth_node_core::primitives::SealedBlock;
use reth_provider::ProviderResult;
use tempo_node::TempoExecutionData;
use tempo_payload_types::{TempoBuiltPayload, TempoPayloadAttributes};
use tempo_primitives::{
    Block as TempoBlock, BlockBody, TempoConsensusContext, TempoHeader,
    ed25519::PublicKey as TempoPublicKey,
};

use super::{
    Config,
    actor::{ExecutionLayer, ForkchoiceResponse},
};
use crate::{
    alias,
    consensus::{Digest, block::Block},
    epoch::SchemeProvider,
    storage::{self, FinalizedBlocksProvider, Hybrid},
};

#[derive(Clone, Default)]
struct MockExecutionLayer {
    blocks: Arc<Mutex<HashMap<B256, Block>>>,
    direct_lookup_failed: Arc<AtomicBool>,
    submitted_payloads: Arc<Mutex<Vec<Digest>>>,
    genesis: Arc<Mutex<Option<Block>>>,
}

impl MockExecutionLayer {
    fn with_genesis(genesis: Block) -> Self {
        let this = Self::default();
        this.blocks
            .lock()
            .insert(genesis.block_hash(), genesis.clone());
        *this.genesis.lock() = Some(genesis);
        this
    }

    fn direct_lookup_failed(&self) -> bool {
        self.direct_lookup_failed.load(Ordering::SeqCst)
    }

    fn submitted_payloads(&self) -> Vec<Digest> {
        self.submitted_payloads.lock().clone()
    }
}

impl FinalizedBlocksProvider for MockExecutionLayer {
    fn finalized_height(&self) -> Option<u64> {
        Some(0)
    }

    fn block_by_height(&self, height: u64) -> ProviderResult<Option<Block>> {
        Ok((height == 0).then(|| self.genesis.lock().clone()).flatten())
    }

    fn block_by_hash(&self, hash: B256) -> ProviderResult<Option<Block>> {
        Ok(self.blocks.lock().get(&hash).cloned())
    }
}

impl ExecutionLayer for MockExecutionLayer {
    fn initial_state(&self) -> eyre::Result<(BlockNumHash, BlockNumHash)> {
        let genesis = self.genesis.lock().clone().expect("genesis configured");
        let state = BlockNumHash::new(0, genesis.block_hash());
        Ok((state, state))
    }

    fn find_block(&self, digest: Digest) -> eyre::Result<Option<Block>> {
        let block = self.blocks.lock().get(&digest.0).cloned();
        if block.is_none() {
            self.direct_lookup_failed.store(true, Ordering::SeqCst);
        }
        Ok(block)
    }

    async fn fork_choice_updated(
        &self,
        state: ForkchoiceState,
        _attrs: Option<TempoPayloadAttributes>,
    ) -> eyre::Result<ForkchoiceResponse> {
        Ok(ForkchoiceResponse {
            payload_status: PayloadStatus::new(
                PayloadStatusEnum::Valid,
                Some(state.head_block_hash),
            ),
            payload_id: None,
        })
    }

    async fn new_payload(&self, data: TempoExecutionData) -> eyre::Result<PayloadStatus> {
        let block = Block::from_execution_block_unchecked(data.block, data.block_access_list);
        let digest = block.digest();
        self.blocks.lock().insert(digest.0, block);
        self.submitted_payloads.lock().push(digest);
        Ok(PayloadStatus::new(PayloadStatusEnum::Valid, Some(digest.0)))
    }

    async fn resolve_payload(
        &self,
        _payload_id: PayloadId,
    ) -> Option<eyre::Result<TempoBuiltPayload>> {
        None
    }
}

#[derive(Clone, Default)]
struct EmptyBuffer {
    subscriptions: Arc<Mutex<Vec<oneshot::Sender<Block>>>>,
}

impl Buffer<Standard<Block>> for EmptyBuffer {
    type PublicKey = commonware_cryptography::ed25519::PublicKey;
    type CachedBlock = Block;

    async fn find_by_digest(&self, _digest: Digest) -> Option<Block> {
        None
    }

    async fn find_by_commitment(&self, _commitment: Digest) -> Option<Block> {
        None
    }

    async fn subscribe_by_digest(&self, _digest: Digest) -> oneshot::Receiver<Block> {
        let (sender, receiver) = oneshot::channel();
        self.subscriptions.lock().push(sender);
        receiver
    }

    async fn subscribe_by_commitment(&self, _commitment: Digest) -> oneshot::Receiver<Block> {
        self.subscribe_by_digest(Digest(B256::ZERO)).await
    }

    async fn finalized(&self, _commitment: Digest) {}

    async fn send(&self, _round: Round, _block: Block, _recipients: Recipients<Self::PublicKey>) {}
}

#[derive(Clone)]
struct MockResolver {
    handler: Handler<Digest>,
    blocks: Arc<Mutex<HashMap<Digest, Block>>>,
    requests: Arc<Mutex<Vec<Request<Digest>>>>,
}

impl MockResolver {
    fn new(handler: Handler<Digest>, blocks: impl IntoIterator<Item = Block>) -> Self {
        Self {
            handler,
            blocks: Arc::new(Mutex::new(
                blocks
                    .into_iter()
                    .map(|block| (block.digest(), block))
                    .collect(),
            )),
            requests: Arc::default(),
        }
    }

    fn requested_block(&self, digest: Digest) -> bool {
        self.requests
            .lock()
            .iter()
            .any(|request| matches!(request, Request::Block(requested) if *requested == digest))
    }

    async fn deliver_block(&self, digest: Digest) -> bool {
        let block = self
            .blocks
            .lock()
            .get(&digest)
            .cloned()
            .expect("network block");
        self.handler
            .clone()
            .deliver(Request::Block(digest), block.encode())
            .await
    }
}

impl Resolver for MockResolver {
    type Key = Request<Digest>;
    type PublicKey = commonware_cryptography::ed25519::PublicKey;

    async fn fetch(&mut self, key: Self::Key) {
        self.requests.lock().push(key);
    }

    async fn fetch_all(&mut self, keys: Vec<Self::Key>) {
        self.requests.lock().extend(keys);
    }

    async fn fetch_targeted(&mut self, key: Self::Key, _targets: NonEmptyVec<Self::PublicKey>) {
        self.fetch(key).await;
    }

    async fn fetch_all_targeted(
        &mut self,
        requests: Vec<(Self::Key, NonEmptyVec<Self::PublicKey>)>,
    ) {
        self.fetch_all(requests.into_iter().map(|(key, _)| key).collect())
            .await;
    }

    async fn cancel(&mut self, _key: Self::Key) {}

    async fn clear(&mut self) {}

    async fn retain(&mut self, _predicate: impl Fn(&Self::Key) -> bool + Send + 'static) {}
}

fn make_block(height: u64, parent_hash: B256, context: Option<TempoConsensusContext>) -> Block {
    Block::from_execution_block_unchecked(
        SealedBlock::seal_slow(TempoBlock {
            header: TempoHeader {
                inner: Header {
                    parent_hash,
                    number: height,
                    ..Default::default()
                },
                consensus_context: context,
                ..Default::default()
            },
            body: BlockBody::default(),
        }),
        None,
    )
}

fn finalization(block: &Block, round: Round) -> Finalization<MarshalScheme, Digest> {
    let signature_bytes = vec![0; vrf::Certificate::<MinSig>::SIZE];
    let certificate = vrf::Certificate::<MinSig>::read_cfg(&mut signature_bytes.as_slice(), &())
        .expect("lazy certificate bytes");
    Finalization {
        proposal: Proposal {
            round,
            parent: View::zero(),
            payload: block.digest(),
        },
        certificate,
    }
}

type MarshalScheme = vrf::Scheme<commonware_cryptography::ed25519::PublicKey, MinSig>;

#[commonware_macros::test_traced]
fn falls_back_to_network_ancestry_when_direct_backfill_misses() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let genesis = make_block(0, B256::ZERO, None);
        let round = Round::new(Epoch::zero(), View::new(1));
        let missing = make_block(
            1,
            genesis.block_hash(),
            Some(TempoConsensusContext {
                epoch: 0,
                view: 1,
                parent_view: 0,
                proposer: TempoPublicKey::from_seed([1; 32]),
            }),
        );
        let mock_el = MockExecutionLayer::with_genesis(genesis);
        let page_cache = CacheRef::from_pooler(
            &context,
            storage::BUFFER_POOL_PAGE_SIZE,
            storage::BUFFER_POOL_CAPACITY,
        );
        let mut finalizations = storage::init_finalizations_archive(
            &context,
            "executor-backfill-test",
            page_cache.clone(),
        )
        .await
        .expect("init finalizations archive");
        let certificate = finalization(&missing, round);
        finalizations
            .put(1, missing.digest(), certificate)
            .await
            .expect("store finalization");
        finalizations.sync().await.expect("sync finalizations");

        let finalized_blocks = storage::init_finalized_blocks(
            &context,
            "executor-backfill-test",
            page_cache.clone(),
            mock_el.clone(),
            16,
        )
        .await
        .expect("init hybrid storage");
        let scheme_provider = SchemeProvider::new();
        type TestMarshal<TContext> = core::Actor<
            TContext,
            Standard<Block>,
            SchemeProvider,
            immutable::Archive<TContext, Digest, Finalization<MarshalScheme, Digest>>,
            Hybrid<TContext, MockExecutionLayer>,
            FixedEpocher,
            Sequential,
            Exact,
        >;
        let (marshal_actor, marshal_mailbox, _): (TestMarshal<_>, alias::marshal::Mailbox, Height) =
            core::Actor::init(
                context.with_label("marshal"),
                finalizations,
                finalized_blocks,
                commonware_consensus::marshal::Config {
                    provider: scheme_provider,
                    epocher: FixedEpocher::new(NZU64!(10)),
                    partition_prefix: "executor-backfill-test".into(),
                    mailbox_size: 16,
                    view_retention_timeout: ViewDelta::new(10),
                    prunable_items_per_section: NZU64!(16),
                    page_cache,
                    replay_buffer: storage::REPLAY_BUFFER,
                    key_write_buffer: storage::WRITE_BUFFER,
                    value_write_buffer: storage::WRITE_BUFFER,
                    block_codec_config: (),
                    max_repair: storage::MAX_REPAIR,
                    max_pending_acks: NZUsize!(16),
                    strategy: Sequential,
                },
            )
            .await;

        let (executor_actor, executor_mailbox) = super::init(
            context.with_label("executor"),
            Config {
                execution_node: mock_el.clone(),
                finalized_floor: Height::new(1),
                finalized_tip: (Height::new(1), missing.digest()),
                marshal: marshal_mailbox,
                fcu_heartbeat_interval: Duration::from_secs(30),
                public_key: None,
            },
        )
        .expect("init executor");

        let (resolver_tx, resolver_rx) = mpsc::channel(16);
        let resolver = MockResolver::new(Handler::new(resolver_tx), [missing.clone()]);
        let resolver_probe = resolver.clone();
        marshal_actor.start(
            executor_mailbox,
            EmptyBuffer::default(),
            (resolver_rx, resolver),
        );
        executor_actor.start();

        while !mock_el.direct_lookup_failed() {
            context.sleep(Duration::from_millis(10)).await;
        }
        while !resolver_probe.requested_block(missing.digest()) {
            context.sleep(Duration::from_millis(10)).await;
        }
        assert!(resolver_probe.deliver_block(missing.digest()).await);

        while !mock_el.submitted_payloads().contains(&missing.digest()) {
            context.sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(mock_el.submitted_payloads(), vec![missing.digest()]);
    });
}
