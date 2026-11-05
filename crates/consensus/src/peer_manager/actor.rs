use std::{
    collections::{HashMap, hash_map::Entry},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use alloy_consensus::{BlockHeader as _, Sealable as _};
use alloy_primitives::B256;
use commonware_codec::ReadExt as _;
use commonware_consensus::{
    Heightable as _,
    marshal::Update,
    types::{Epocher, FixedEpocher, Height},
};
use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::{Address, AddressableManager, AddressableTrackedPeers, Provider};
use commonware_runtime::{
    Clock, ContextCell, Metrics, Spawner, spawn_cell,
    telemetry::metrics::{Gauge, MetricsExt as _},
};
use commonware_utils::{Acknowledgement, ordered};
use eyre::{OptionExt as _, WrapErr as _, ensure};
use futures::{StreamExt as _, channel::mpsc};
use tempo_dkg_onchain_artifacts::OnchainDkgOutcomeV1;
use tempo_precompiles::validator_config_v2::ValidatorConfigV2;
use tempo_primitives::TempoHeader;
use tracing::{Span, debug, error, info_span, instrument, warn};

use crate::{
    consensus::Digest,
    utils::public_key_to_b256,
    validators::{
        DecodedValidatorV2, ExecutionNode, read_dkg_ceremony, read_validator_config_at_block_hash,
    },
};

/// The interval on which peer sets are refreshed during normal operation.
const HEARTBEAT_UPDATE_INTERVAL: Duration = Duration::from_secs(30);

use super::{
    ExecutionLayer,
    ingress::{Message, MessageWithCause},
};

pub(crate) struct Actor<TContext, TPeerManager, TExecutionNode>
where
    TPeerManager: AddressableManager<PublicKey = PublicKey>,
{
    context: ContextCell<TContext>,

    oracle: TPeerManager,
    execution_node: Arc<TExecutionNode>,
    epoch_strategy: FixedEpocher,
    latest_observed_finalized_tip: (Height, Digest),
    mailbox: mpsc::UnboundedReceiver<MessageWithCause>,

    peers: Gauge,

    last_tracked_peer_set: Option<LastTrackedPeerSet>,

    peer_update_timer: Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
}

impl<TContext, TPeerManager, TExecutionNode> Actor<TContext, TPeerManager, TExecutionNode>
where
    TContext: Clock + Metrics + Spawner,
    TPeerManager: AddressableManager<PublicKey = PublicKey>,
    TExecutionNode: ExecutionLayer,
{
    pub(super) fn new(
        context: TContext,
        super::Config {
            oracle,
            execution_node,
            epoch_strategy,
            finalized_tip,
        }: super::Config<TPeerManager, TExecutionNode>,
        mailbox: mpsc::UnboundedReceiver<MessageWithCause>,
    ) -> eyre::Result<Self> {
        let peers = context.gauge(
            "peers",
            "how many peers are registered overall for the latest epoch",
        );
        let context = ContextCell::new(context);
        let peer_update_timer = Box::pin(context.sleep(HEARTBEAT_UPDATE_INTERVAL));
        let mut actor = Self {
            context,
            oracle,
            execution_node,
            epoch_strategy,
            latest_observed_finalized_tip: finalized_tip,
            mailbox,
            peers,
            last_tracked_peer_set: None,

            peer_update_timer,
        };
        actor
            .refresh_peers()
            .wrap_err("failed registering initial peers from execution state")?;
        Ok(actor)
    }

    async fn run(mut self) {
        let reason = 'event_loop: loop {
            tokio::select!(
                biased;
                msg = self.mailbox.next() => {
                    match msg {
                        None => break 'event_loop eyre::eyre!("mailbox closed unexpectedly"),

                        Some(msg) => {
                            if let Err(error) = self.handle_message(msg.cause, msg.message).await {
                                break 'event_loop error;
                            }
                        }
                    }
                }
                _ = &mut self.peer_update_timer => {
                    let _ = self.refresh_peers();
                    self.reset_peer_update_timer();
                }
            )
        };
        info_span!("peer_manager").in_scope(|| error!(%reason,"agent shutting down"));
    }
    pub(crate) fn start(mut self) -> commonware_runtime::Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    #[instrument(parent = &cause, skip_all)]
    async fn handle_message(&mut self, cause: Span, message: Message) -> eyre::Result<()> {
        match message {
            Message::PeerSet { id, response } => {
                let result = Provider::peer_set(&mut self.oracle, id).await;
                let _ = response.send(result);
            }
            Message::Subscribe { response } => {
                let receiver = Provider::subscribe(&mut self.oracle).await;
                let _ = response.send(receiver);
            }
            Message::Finalized(update) => match *update {
                Update::Block(block, ack) => {
                    self.observe_finalized_tip((block.height(), block.digest()));
                    let _ = self.refresh_peers();
                    ack.acknowledge();
                    self.reset_peer_update_timer();
                }
                Update::Tip(_, height, digest) => {
                    self.observe_finalized_tip((height, digest));
                    let _ = self.refresh_peers();
                    self.reset_peer_update_timer();
                }
            },
        }
        Ok(())
    }

    /// Reads peers from the latest finalized state allowed by consensus.
    #[instrument(skip_all, err)]
    fn refresh_peers(&mut self) -> eyre::Result<()> {
        // Peer discovery must work before the executor can backfill to marshal's
        // floor: DKG may need these peers to recover and authenticate the tip
        // before it releases the executor. Use only state already finalized by EL,
        // capped by the latest consensus-observed tip. Genesis needs no marker.
        let highest_finalized = self
            .execution_node
            .finalized_block_number()
            .wrap_err("unable to read highest finalized block from execution layer")?
            .unwrap_or_default()
            .min(self.latest_observed_finalized_tip.0.get());

        // Short circuit - no need to read the same state if there is no new data.
        if self
            .last_tracked_peer_set
            .as_ref()
            .is_some_and(|tracked| tracked.height >= highest_finalized)
        {
            return Ok(());
        }

        let epoch_info = self
            .epoch_strategy
            .containing(Height::new(highest_finalized))
            .expect("epoch strategy covers all heights");

        // If we're exactly on a boundary, use it; otherwise use the previous
        // epoch's last block (or genesis).
        //
        // This height is guaranteed to be finalized.
        let latest_boundary = if epoch_info.last().get() == highest_finalized {
            highest_finalized
        } else {
            epoch_info
                .epoch()
                .previous()
                .map_or_else(Height::zero, |prev| {
                    self.epoch_strategy
                        .last(prev)
                        .expect("epoch strategy covers all epochs")
                })
                .get()
        };

        let latest_boundary_header =
            read_header_at_height(self.execution_node.as_ref(), latest_boundary)
                .wrap_err("failed reading latest boundary header")?;
        let highest_finalized_header =
            read_header_at_height(self.execution_node.as_ref(), highest_finalized)
                .wrap_err("failed reading highest finalized header")?;

        // From T15 (TIP-1123) the boundary block stored the ceremony of the epoch it starts in
        // the CurrentCommittee precompile, so every state since has it and the header is not
        // read. Before, the header carries it. The boundary decides, not the finalized tip: in
        // the first epoch after activation the latest boundary still predates it.
        let builder = if self
            .execution_node
            .stores_dkg_ceremony_at(latest_boundary_header.timestamp())
        {
            let boundary_epoch = if epoch_info.last().get() == highest_finalized {
                epoch_info.epoch().next()
            } else {
                epoch_info.epoch()
            };
            let (_, _, stored) = read_validator_config_at_block_hash(
                self.execution_node.as_ref(),
                highest_finalized_header.hash_slow(),
                read_dkg_ceremony,
            )
            .wrap_err("failed reading DKG ceremony from execution layer")?;
            let stored = stored.ok_or_eyre(
                "the boundary block stores the DKG ceremony in state (T15), but none is stored",
            )?;
            ensure!(
                stored.epoch == boundary_epoch.get(),
                "stored DKG ceremony is for epoch `{}`, but the boundary block at `{latest_boundary}` starts epoch `{boundary_epoch}`",
                stored.epoch,
            );
            PeersBuilder::new(stored.dealers, &stored.ceremony.players)
        } else {
            let outcome = OnchainDkgOutcomeV1::read(
                &mut latest_boundary_header.extra_data().as_ref(),
            )
            .wrap_err_with(|| {
                format!("boundary block at `{latest_boundary}` did not contain a valid DKG outcome")
            })?;
            PeersBuilder::new(
                outcome.output.players().clone(),
                &outcome.next_ceremony.players,
            )
        };

        let peers = builder
            .resolve_at_hash(
                self.execution_node.as_ref(),
                highest_finalized_header.hash_slow(),
            )
            .wrap_err("failed reading peer set from execution layer")?;

        debug!(
            boundary.height = latest_boundary_header.number(),
            boundary.hash = %latest_boundary_header.hash_slow(),
            highest_finalized.height = highest_finalized_header.number(),
            highest_finalized.hash = %highest_finalized_header.hash_slow(),
            ?peers.primary,
            ?peers.secondary,
            "read active peers from DKG outcome in latest available \
            boundary header (or the DKG ceremony stored at the highest \
            finalized block) and resolved p2p addresses against validator \
            config contract"
        );

        self.track_or_overwrite(highest_finalized_header.number(), peers);

        Ok(())
    }

    fn observe_finalized_tip(&mut self, tip: (Height, Digest)) {
        if tip.0 >= self.latest_observed_finalized_tip.0 {
            self.latest_observed_finalized_tip = tip;
        }
    }

    fn track_or_overwrite(&mut self, height: u64, peers: Peers) {
        if let Some(tracked) = &self.last_tracked_peer_set {
            match peers.what_has_changed_compared_to(&tracked.peers) {
                WhatHasChanged::Nothing => {}
                WhatHasChanged::Addresses => {
                    self.oracle.overwrite(peers.to_flat_map());
                }
                WhatHasChanged::Peers => {
                    self.oracle.track(height, peers.clone());
                }
            }
        } else {
            self.oracle.track(height, peers.clone());
        }

        // Always bump the last-tracked peer set. If the peers are unchanged
        // this only updates the height, but we use the height to determine if
        // state should be read or not.
        self.last_tracked_peer_set
            .replace(LastTrackedPeerSet { height, peers });

        if let Some(tracked) = &self.last_tracked_peer_set {
            self.peers.metric().set(tracked.peers.len() as i64);
        }

        debug!(
            last_tracked_peer_set = ?self.last_tracked_peer_set.as_ref().expect("just set it"),
            "latest tracked peerset",
        );
    }

    fn reset_peer_update_timer(&mut self) {
        self.peer_update_timer = Box::pin(self.context.sleep(HEARTBEAT_UPDATE_INTERVAL));
    }
}

enum WhatHasChanged {
    Nothing,
    Addresses,
    Peers,
}

#[derive(Clone, Debug)]
struct Peers {
    primary: ordered::Map<PublicKey, Address>,
    secondary: ordered::Map<PublicKey, Address>,
}

impl Peers {
    fn what_has_changed_compared_to(&self, old: &Self) -> WhatHasChanged {
        if old.primary.keys() == self.primary.keys()
            && old.secondary.keys() == self.secondary.keys()
        {
            if old.primary.values() == self.primary.values()
                && old.secondary.values() == self.secondary.values()
            {
                WhatHasChanged::Nothing
            } else {
                WhatHasChanged::Addresses
            }
        } else {
            WhatHasChanged::Peers
        }
    }

    fn len(&self) -> usize {
        self.primary.len().saturating_add(self.secondary.len())
    }

    fn to_flat_map(&self) -> ordered::Map<PublicKey, Address> {
        ordered::Map::from_iter_dedup(
            self.primary
                .iter_pairs()
                .chain(self.secondary.iter_pairs())
                .map(|(key, val)| (key.clone(), val.clone())),
        )
    }
}

impl From<Peers> for AddressableTrackedPeers<PublicKey> {
    fn from(value: Peers) -> Self {
        Self {
            primary: value.primary,
            secondary: value.secondary,
        }
    }
}

struct PeersBuilder {
    primary: ordered::Set<PublicKey>,
    secondary: ordered::Set<PublicKey>,
}

impl PeersBuilder {
    /// Makes `committee` primary and the `ceremony_players` outside it secondary.
    fn new(committee: ordered::Set<PublicKey>, ceremony_players: &ordered::Set<PublicKey>) -> Self {
        let primary = committee;
        let secondary = ordered::Set::from_iter_dedup(
            ceremony_players
                .iter()
                // Performs a binary search since `primary` is a sorted vec
                // under the hood - so performance of this is fine.
                .filter(|key| primary.position(key).is_none())
                .cloned(),
        );
        Self { primary, secondary }
    }

    #[instrument(skip_all, fields(%hash))]
    fn resolve_at_hash(self, node: impl ExecutionNode, hash: B256) -> eyre::Result<Peers> {
        let Self { primary, secondary } = self;
        let (_, _, (primary, secondary)) = read_validator_config_at_block_hash(
            node,
            hash,
            |config: &ValidatorConfigV2| {
                let mut active_validators = HashMap::new();
                for (i, raw) in config
                    .get_active_validators()
                    .wrap_err("failed reading active validator set from contract")?
                    .into_iter()
                    .enumerate()
                {
                    if let Ok(decoded) =
                        DecodedValidatorV2::decode_from_contract(raw).inspect_err(|error| {
                            warn!(
                                    %error,
                                    position = i,
                                    "failed decoding active validator in contract",
                            )
                        })
                        && active_validators
                            .insert(decoded.public_key().clone(), decoded.to_p2p_address())
                            .is_some()
                    {
                        warn!(
                            duplicate = %decoded.public_key(),
                            "found duplicate public keys",
                        );
                    }
                }
                debug!(
                    ?active_validators,
                    "read active validators from contract, now extending with \
                    historic peers that are still in the peer set but no \
                    longer marked active",
                );
                let primary = ordered::Map::from_iter_dedup(primary.into_iter().map(|peer| {
                    active_validators.remove_entry(&peer).unwrap_or_else(|| {
                        let decoded = config
                            .validator_by_public_key(public_key_to_b256(&peer))
                            .map_err(eyre::Report::new)
                            .and_then(DecodedValidatorV2::decode_from_contract)
                            .wrap_err_with(|| {
                                format!(
                                    "failed to read DKG peer `{peer}` from validator config contract"
                                )
                            })
                            .expect(
                                "invariant: DKG peers must have an entry in the \
                                smart contract and be well formed",
                            );
                        (decoded.public_key().clone(), decoded.to_p2p_address())
                    })
                }));

                for peer in secondary {
                    if let Entry::Vacant(slot) = active_validators.entry(peer.clone()) {
                        let decoded = config
                            .validator_by_public_key(public_key_to_b256(&peer))
                            .map_err(eyre::Report::new)
                            .and_then(DecodedValidatorV2::decode_from_contract)
                            .wrap_err_with(|| {
                                format!(
                                    "failed to read next DKG peer `{peer}` from validator config contract"
                                )
                            })
                            .expect(
                                "invariant: next DKG peers must have an entry in the \
                                smart contract and be well formed",
                            );
                        slot.insert_entry(decoded.to_p2p_address());
                    }
                }

                let secondary = ordered::Map::from_iter_dedup(active_validators.into_iter());

                Ok((primary, secondary))
            },
        )?;
        Ok(Peers { primary, secondary })
    }
}

#[derive(Debug)]
struct LastTrackedPeerSet {
    height: u64,
    peers: Peers,
}

#[instrument(skip_all, fields(height), err)]
fn read_header_at_height(
    execution_node: &impl ExecutionLayer,
    height: u64,
) -> eyre::Result<TempoHeader> {
    execution_node
        .header_by_number(height)
        .and_then(|h| h.ok_or_eyre("execution layer did not have a header at the requested height"))
        .wrap_err_with(|| format!("failed reading header at height `{height}`"))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Mutex,
    };

    use alloy_consensus::Header;
    use alloy_primitives::{Address as AlloyAddress, B256, Keccak256, U256};
    use commonware_actor::Feedback;
    use commonware_codec::Encode as _;
    use commonware_cryptography::{
        Signer as _,
        bls12381::{
            dkg::feldman_desmedt as dkg,
            primitives::{sharing::Mode, variant::MinSig},
        },
        ed25519::PrivateKey,
    };
    use commonware_p2p::{PeerSetSubscription, TrackedPeers};
    use commonware_runtime::{Runner as _, deterministic::Runner};
    use commonware_utils::{N3f1, TryFromIterator as _};
    use rand::SeedableRng as _;
    use reth_evm::{ConfigureEvm as _, database::StateProviderDatabase};
    use reth_provider::{
        EvmStateProviderBox, StateProvider as _,
        test_utils::{ExtendedAccount, MockEthProvider},
    };
    use tempo_chainspec::{
        TempoChainSpec,
        spec::{DEV, MODERATO},
    };
    use tempo_dkg_onchain_artifacts::{DkgCeremony, OnchainDkgOutcome};
    use tempo_node::evm::{TempoEvm, TempoEvmConfig};
    use tempo_precompiles::{
        current_committee::{CurrentCommittee, ICurrentCommittee},
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        validator_config_v2::{IValidatorConfigV2, VALIDATOR_NS_ADD},
    };

    use super::*;

    const VALIDATOR_CONFIG_V2_ADDRESS: AlloyAddress =
        alloy_primitives::address!("0xCCCCCCCC00000000000000000000000000000001");

    struct TestExecutionNode {
        hash: B256,
        height: u64,
        provider: MockEthProvider,
        finalized: Option<u64>,
        headers: HashMap<u64, TempoHeader>,
        header_reads: Mutex<Vec<u64>>,
        chain_spec: Arc<TempoChainSpec>,
    }

    impl ExecutionNode for TestExecutionNode {
        fn header(&self, block_hash: B256) -> eyre::Result<TempoHeader> {
            assert_eq!(block_hash, self.hash);
            Ok(self.headers[&self.height].clone())
        }

        fn state_by_block_hash(&self, block_hash: B256) -> eyre::Result<EvmStateProviderBox> {
            assert_eq!(block_hash, self.hash);
            Ok(Box::new(self.provider.clone().into_evm_state_provider()))
        }

        fn evm_for_block(
            &self,
            db: StateProviderDatabase<EvmStateProviderBox>,
            header: &TempoHeader,
        ) -> eyre::Result<TempoEvm<'static>> {
            TempoEvmConfig::new(self.chain_spec.clone())
                .evm_for_block(db, header)
                .map_err(eyre::Report::new)
        }
    }

    impl ExecutionLayer for TestExecutionNode {
        fn finalized_block_number(&self) -> eyre::Result<Option<u64>> {
            Ok(self.finalized)
        }

        fn header_by_number(&self, height: u64) -> eyre::Result<Option<TempoHeader>> {
            self.header_reads.lock().unwrap().push(height);
            Ok(self.headers.get(&height).cloned())
        }

        fn stores_dkg_ceremony_at(&self, timestamp: u64) -> bool {
            self.chain_spec.stores_dkg_ceremony_at(timestamp)
        }
    }

    fn execution_header(height: u64) -> TempoHeader {
        TempoHeader {
            general_gas_limit: 30_000_000,
            inner: Header {
                number: height,
                timestamp: 1,
                gas_limit: 30_000_000,
                base_fee_per_gas: Some(1),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[derive(Clone, Debug, Default)]
    struct RecordingOracle {
        tracked: Arc<Mutex<Vec<(u64, Peers)>>>,
    }

    impl Provider for RecordingOracle {
        type PublicKey = PublicKey;

        async fn peer_set(&mut self, _id: u64) -> Option<TrackedPeers<PublicKey>> {
            panic!("constructor must not wait for a peer set")
        }

        async fn subscribe(&mut self) -> PeerSetSubscription<PublicKey> {
            panic!("constructor must not wait for a subscription")
        }
    }

    impl AddressableManager for RecordingOracle {
        fn track<R>(&mut self, id: u64, peers: R) -> Feedback
        where
            R: Into<AddressableTrackedPeers<PublicKey>> + Send,
        {
            let peers = peers.into();
            self.tracked.lock().unwrap().push((
                id,
                Peers {
                    primary: peers.primary,
                    secondary: peers.secondary,
                },
            ));
            Feedback::Ok
        }

        fn overwrite(&mut self, _peers: ordered::Map<PublicKey, Address>) -> Feedback {
            panic!("test expects a peer membership change")
        }
    }

    struct ValidatorFixture {
        private_key: PrivateKey,
        public_key: PublicKey,
        validator_address: AlloyAddress,
        ingress: String,
        egress: String,
        p2p_address: Address,
    }

    fn peer(seed: u8) -> ValidatorFixture {
        let private_key = PrivateKey::from_seed(u64::from(seed));
        let public_key = private_key.public_key();
        let validator_address = AlloyAddress::repeat_byte(seed);
        let egress_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, seed));
        let ingress_socket = SocketAddr::new(egress_ip, 8000 + u16::from(seed));
        let p2p_address = Address::Asymmetric {
            ingress: commonware_p2p::Ingress::Socket(ingress_socket),
            egress: SocketAddr::new(egress_ip, 0),
        };

        ValidatorFixture {
            private_key,
            public_key,
            validator_address,
            ingress: ingress_socket.to_string(),
            egress: egress_ip.to_string(),
            p2p_address,
        }
    }

    impl ValidatorFixture {
        fn add_validator_call(&self) -> IValidatorConfigV2::addValidatorCall {
            let mut hasher = Keccak256::new();
            hasher.update(1u64.to_be_bytes());
            hasher.update(VALIDATOR_CONFIG_V2_ADDRESS.as_slice());
            hasher.update(self.validator_address.as_slice());
            hasher.update([self.ingress.len() as u8]);
            hasher.update(self.ingress.as_bytes());
            hasher.update([self.egress.len() as u8]);
            hasher.update(self.egress.as_bytes());
            hasher.update(self.validator_address.as_slice());
            let message = hasher.finalize();
            let signature = self
                .private_key
                .sign(VALIDATOR_NS_ADD, message.as_slice())
                .encode();

            IValidatorConfigV2::addValidatorCall {
                validatorAddress: self.validator_address,
                publicKey: public_key_to_b256(&self.public_key),
                ingress: self.ingress.clone(),
                egress: self.egress.clone(),
                feeRecipient: self.validator_address,
                signature: signature.into(),
            }
        }
    }

    fn execution_with_validators(
        validators: &[ValidatorFixture],
    ) -> eyre::Result<TestExecutionNode> {
        execution_with_state(MODERATO.clone(), validators, |_, _| Ok(()))
    }

    /// Adds `validators`, then runs `setup` with the config and its owner.
    fn execution_with_state(
        chain_spec: Arc<TempoChainSpec>,
        validators: &[ValidatorFixture],
        setup: impl FnOnce(&mut ValidatorConfigV2, AlloyAddress) -> eyre::Result<()>,
    ) -> eyre::Result<TestExecutionNode> {
        let mut storage = HashMapStorageProvider::new(1);
        storage.set_block_number(1);
        let owner = AlloyAddress::repeat_byte(0xAA);

        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut config = ValidatorConfigV2::new();
            config.initialize(owner)?;
            for validator in validators {
                config.add_validator(owner, validator.add_validator_call())?;
            }
            setup(&mut config, owner)
        })?;

        let mut storage_by_account = HashMap::<AlloyAddress, Vec<(B256, U256)>>::new();
        for (address, slot, value) in storage.into_storage() {
            storage_by_account
                .entry(address)
                .or_default()
                .push((B256::from(slot), value));
        }
        let provider = MockEthProvider::new();
        for (address, storage) in storage_by_account {
            provider.add_account(
                address,
                ExtendedAccount::new(0, U256::ZERO).extend_storage(storage),
            );
        }

        let header = execution_header(7);
        Ok(TestExecutionNode {
            hash: header.hash_slow(),
            height: header.number(),
            provider,
            finalized: Some(header.number()),
            headers: HashMap::from([(header.number(), header)]),
            header_reads: Mutex::default(),
            chain_spec,
        })
    }

    fn dkg_outcome(
        players: impl IntoIterator<Item = PublicKey>,
        next_players: impl IntoIterator<Item = PublicKey>,
    ) -> eyre::Result<OnchainDkgOutcome> {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let (output, _) = dkg::deal::<MinSig, _, N3f1>(
            &mut rng,
            Mode::NonZeroCounter,
            ordered::Set::try_from_iter(players)?,
        )?;

        Ok(OnchainDkgOutcomeV1 {
            epoch: 0,
            output,
            next_ceremony: DkgCeremony {
                players: ordered::Set::try_from_iter(next_players)?,
                is_full_dkg: false,
            },
        }
        .into())
    }

    fn keys(
        validators: impl IntoIterator<Item = ValidatorFixture>,
    ) -> eyre::Result<ordered::Set<PublicKey>> {
        Ok(ordered::Set::try_from_iter(
            validators.into_iter().map(|validator| validator.public_key),
        )?)
    }

    fn assert_peer(map: &ordered::Map<PublicKey, Address>, validator: &ValidatorFixture) {
        assert_eq!(
            map.get_value(&validator.public_key),
            Some(&validator.p2p_address),
        );
    }

    fn assert_no_peer(map: &ordered::Map<PublicKey, Address>, validator: &ValidatorFixture) {
        assert!(map.get_value(&validator.public_key).is_none());
    }

    fn bootstrap_execution(height: u64, primary: u8) -> TestExecutionNode {
        let execution = execution_with_validators(&[peer(1), peer(2)]).unwrap();
        let outcome = dkg_outcome([peer(primary).public_key], [peer(primary).public_key]).unwrap();
        with_boundary(execution, height, outcome)
    }

    /// Makes `height` the finalized tip of `execution`, with `outcome` (its epoch set to the
    /// one its boundary starts) in the latest boundary header at or below it.
    fn with_boundary(
        mut execution: TestExecutionNode,
        height: u64,
        outcome: OnchainDkgOutcome,
    ) -> TestExecutionNode {
        let boundary = if height % 10 == 9 {
            height
        } else {
            (height / 10 * 10).saturating_sub(1)
        };
        let outcome = crate::test_utils::with_epoch(outcome, (boundary + 1) / 10);
        let mut boundary_header = execution_header(boundary);
        boundary_header.inner.extra_data = outcome.encode().into();
        let tip_header = if boundary == height {
            boundary_header.clone()
        } else {
            execution_header(height)
        };
        execution.height = height;
        execution.hash = tip_header.hash_slow();
        execution.finalized = Some(height);
        execution.headers = HashMap::from([(boundary, boundary_header), (height, tip_header)]);
        execution
    }

    #[test]
    fn constructor_registers_available_execution_peers_before_actor_start() {
        // EL behind consensus, unset finalized marker at genesis, an exact
        // boundary, and EL ahead of the consensus tip (which still caps reads).
        for (finalized, available, consensus_tip) in [
            (Some(7), 7, 100),
            (None, 0, 100),
            (Some(19), 19, 100),
            (Some(27), 12, 12),
        ] {
            Runner::default().start(|context| async move {
                let mut execution = bootstrap_execution(available, 1);
                execution.finalized = finalized;
                let execution = Arc::new(execution);
                let oracle = RecordingOracle::default();
                let (_actor, _mailbox) = crate::peer_manager::init(
                    context,
                    crate::peer_manager::Config {
                        execution_node: execution.clone(),
                        oracle: oracle.clone(),
                        epoch_strategy: FixedEpocher::new(commonware_utils::NZU64!(10)),
                        finalized_tip: (
                            Height::new(consensus_tip),
                            Digest(B256::repeat_byte(0xFF)),
                        ),
                    },
                )
                .unwrap();
                // No actor has started and no marshal update has been delivered.
                let tracked = oracle.tracked.lock().unwrap();
                assert_eq!(tracked.len(), 1);
                assert_eq!(tracked[0].0, available);
                assert_peer(&tracked[0].1.primary, &peer(1));
                assert_peer(&tracked[0].1.secondary, &peer(2));
                assert!(
                    execution
                        .header_reads
                        .lock()
                        .unwrap()
                        .iter()
                        .all(|height| *height <= available)
                );
            });
        }
    }

    #[test]
    fn constructor_propagates_unavailable_execution_state() {
        Runner::default().start(|context| async move {
            let mut execution = bootstrap_execution(7, 1);
            execution.headers.remove(&7);
            let oracle = RecordingOracle::default();
            let result = crate::peer_manager::init(
                context,
                crate::peer_manager::Config {
                    execution_node: Arc::new(execution),
                    oracle: oracle.clone(),
                    epoch_strategy: FixedEpocher::new(commonware_utils::NZU64!(10)),
                    finalized_tip: (Height::new(100), Digest(B256::ZERO)),
                },
            );
            let error = result
                .err()
                .expect("unreadable EL state must fail initialization");
            assert!(format!("{error:#}").contains("failed reading highest finalized header"));
            assert!(oracle.tracked.lock().unwrap().is_empty());
        });
    }

    #[test]
    fn runtime_peer_refresh_waits_for_execution_progress() {
        Runner::default().start(|context| async move {
            let execution = Arc::new(bootstrap_execution(7, 1));
            let oracle = RecordingOracle::default();
            let (mut actor, _mailbox) = crate::peer_manager::init(
                context,
                crate::peer_manager::Config {
                    execution_node: execution.clone(),
                    oracle: oracle.clone(),
                    epoch_strategy: FixedEpocher::new(commonware_utils::NZU64!(10)),
                    finalized_tip: (Height::new(100), Digest(B256::ZERO)),
                },
            )
            .unwrap();
            let initial_reads = execution.header_reads.lock().unwrap().clone();
            actor.observe_finalized_tip((Height::new(110), Digest(B256::repeat_byte(1))));
            actor.refresh_peers().unwrap();
            assert_eq!(*execution.header_reads.lock().unwrap(), initial_reads);
            assert_eq!(oracle.tracked.lock().unwrap().len(), 1);

            actor.execution_node = Arc::new(bootstrap_execution(19, 2));
            actor.refresh_peers().unwrap();
            let tracked = oracle.tracked.lock().unwrap();
            assert_eq!(
                tracked
                    .iter()
                    .map(|(height, _)| *height)
                    .collect::<Vec<_>>(),
                vec![7, 19]
            );
            assert_peer(&tracked[1].1.primary, &peer(2));
            assert_peer(&tracked[1].1.secondary, &peer(1));
        });
    }

    #[test]
    fn resolve_at_hash_has_no_secondaries_when_players_are_next_players() -> eyre::Result<()> {
        let execution = execution_with_validators(&[peer(1), peer(2)])?;
        let peers = PeersBuilder::new(keys([peer(1), peer(2)])?, &keys([peer(1), peer(2)])?)
            .resolve_at_hash(&execution, execution.hash)?;

        assert_eq!(peers.primary.len(), 2);
        assert_eq!(peers.secondary.len(), 0);
        assert_peer(&peers.primary, &peer(1));
        assert_peer(&peers.primary, &peer(2));

        Ok(())
    }

    #[test]
    fn resolve_at_hash_keeps_dropped_player_primary() -> eyre::Result<()> {
        let execution = execution_with_validators(&[peer(1), peer(2)])?;
        let peers = PeersBuilder::new(keys([peer(1), peer(2)])?, &keys([peer(1)])?)
            .resolve_at_hash(&execution, execution.hash)?;

        assert_eq!(peers.primary.len(), 2);
        assert_eq!(peers.secondary.len(), 0);
        assert_peer(&peers.primary, &peer(1));
        assert_peer(&peers.primary, &peer(2));

        Ok(())
    }

    #[test]
    fn resolve_at_hash_adds_next_player_as_secondary() -> eyre::Result<()> {
        let execution = execution_with_validators(&[peer(1), peer(2)])?;
        let peers = PeersBuilder::new(keys([peer(1)])?, &keys([peer(1), peer(2)])?)
            .resolve_at_hash(&execution, execution.hash)?;

        assert_eq!(peers.primary.len(), 1);
        assert_eq!(peers.secondary.len(), 1);
        assert_peer(&peers.primary, &peer(1));
        assert_no_peer(&peers.secondary, &peer(1));
        assert_peer(&peers.secondary, &peer(2));

        Ok(())
    }

    #[test]
    fn resolve_at_hash_adds_active_non_dkg_validator_as_secondary() -> eyre::Result<()> {
        let execution = execution_with_validators(&[peer(1), peer(2)])?;
        let peers = PeersBuilder::new(keys([peer(1)])?, &keys([peer(1)])?)
            .resolve_at_hash(&execution, execution.hash)?;

        assert_eq!(peers.primary.len(), 1);
        assert_eq!(peers.secondary.len(), 1);
        assert_peer(&peers.primary, &peer(1));
        assert_no_peer(&peers.secondary, &peer(1));
        assert_peer(&peers.secondary, &peer(2));

        Ok(())
    }

    /// The state after the TIP-1123 boundary block at height 9, which stored the ceremony of
    /// `stored_epoch` (dealt by peer 1, played by the active peers 1 to 3), after which peer 3
    /// was deactivated.
    fn execution_with_stored_ceremony(stored_epoch: u64) -> eyre::Result<TestExecutionNode> {
        execution_with_state(
            DEV.clone(),
            &[peer(1), peer(2), peer(3)],
            |config, owner| {
                let mut committee = CurrentCommittee::new();
                committee.set_committee_members(
                    AlloyAddress::ZERO,
                    ICurrentCommittee::setCommitteeMembersCall {
                        epoch: stored_epoch,
                        publicKeys: vec![public_key_to_b256(&peer(1).public_key)],
                    },
                )?;
                committee.snapshot_dkg_ceremony(stored_epoch)?;
                config.deactivate_validator(
                    owner,
                    IValidatorConfigV2::deactivateValidatorCall { idx: 2 },
                )?;
                Ok(())
            },
        )
    }

    fn ceremony_in_state_outcome(
        players: impl IntoIterator<Item = PublicKey>,
    ) -> OnchainDkgOutcome {
        crate::test_utils::without_ceremony(&dkg_outcome(players, []).unwrap())
    }

    fn init_peer_manager(
        context: commonware_runtime::deterministic::Context,
        execution: TestExecutionNode,
        oracle: RecordingOracle,
    ) -> eyre::Result<()> {
        crate::peer_manager::init(
            context,
            crate::peer_manager::Config {
                execution_node: Arc::new(execution),
                oracle,
                epoch_strategy: FixedEpocher::new(commonware_utils::NZU64!(10)),
                finalized_tip: (Height::new(100), Digest(B256::ZERO)),
            },
        )
        .map(drop)
    }

    #[test]
    fn peers_come_from_stored_ceremony_after_tip_1123_boundary() {
        Runner::default().start(|context| async move {
            let execution = with_boundary(
                execution_with_stored_ceremony(1).unwrap(),
                12,
                ceremony_in_state_outcome([peer(1).public_key]),
            );
            let oracle = RecordingOracle::default();
            init_peer_manager(context, execution, oracle.clone()).unwrap();

            let tracked = oracle.tracked.lock().unwrap();
            assert_eq!(tracked.len(), 1);
            let peers = &tracked[0].1;
            assert_eq!(peers.primary.len(), 1);
            assert_peer(&peers.primary, &peer(1));
            // Peer 3 is no longer active, but still plays the ongoing ceremony.
            assert_eq!(peers.secondary.len(), 2);
            assert_peer(&peers.secondary, &peer(2));
            assert_peer(&peers.secondary, &peer(3));
        });
    }

    #[test]
    fn tip_1123_boundary_header_is_not_read() {
        Runner::default().start(|context| async move {
            let mut execution = with_boundary(
                execution_with_stored_ceremony(1).unwrap(),
                12,
                ceremony_in_state_outcome([peer(1).public_key]),
            );
            execution.headers.get_mut(&9).unwrap().inner.extra_data = Default::default();
            let oracle = RecordingOracle::default();
            init_peer_manager(context, execution, oracle.clone()).unwrap();

            let tracked = oracle.tracked.lock().unwrap();
            assert_eq!(tracked.len(), 1);
            assert_peer(&tracked[0].1.primary, &peer(1));
        });
    }

    #[test]
    fn tip_1123_genesis_starts_epoch_0() {
        Runner::default().start(|context| async move {
            let execution = with_boundary(
                execution_with_stored_ceremony(0).unwrap(),
                0,
                ceremony_in_state_outcome([peer(1).public_key]),
            );
            let oracle = RecordingOracle::default();
            init_peer_manager(context, execution, oracle.clone()).unwrap();

            let tracked = oracle.tracked.lock().unwrap();
            assert_eq!(tracked.len(), 1);
            assert_peer(&tracked[0].1.primary, &peer(1));
        });
    }

    #[test]
    fn tip_1123_boundary_rejects_ceremony_stored_for_another_epoch() {
        Runner::default().start(|context| async move {
            let execution = with_boundary(
                execution_with_stored_ceremony(2).unwrap(),
                12,
                ceremony_in_state_outcome([peer(1).public_key]),
            );
            let oracle = RecordingOracle::default();
            let error = init_peer_manager(context, execution, oracle.clone()).unwrap_err();
            assert!(
                format!("{error:#}").contains(
                    "stored DKG ceremony is for epoch `2`, but the boundary block at `9` starts epoch `1`"
                ),
                "{error:#}",
            );
            assert!(oracle.tracked.lock().unwrap().is_empty());
        });
    }

    #[test]
    fn tip_1123_boundary_requires_stored_ceremony() {
        Runner::default().start(|context| async move {
            let execution = with_boundary(
                execution_with_state(DEV.clone(), &[peer(1), peer(2)], |_, _| Ok(())).unwrap(),
                12,
                ceremony_in_state_outcome([peer(1).public_key]),
            );
            let oracle = RecordingOracle::default();
            let error = init_peer_manager(context, execution, oracle.clone()).unwrap_err();
            assert!(
                format!("{error:#}").contains(
                    "the boundary block stores the DKG ceremony in state (T15), but none is stored"
                ),
                "{error:#}",
            );
            assert!(oracle.tracked.lock().unwrap().is_empty());
        });
    }
}
