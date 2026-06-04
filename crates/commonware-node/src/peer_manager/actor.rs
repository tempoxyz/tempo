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
    marshal::Update,
    types::{Epocher, FixedEpocher, Height},
};
use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::{Address, AddressableManager, AddressableTrackedPeers, Provider};
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner, spawn_cell};
use commonware_utils::{Acknowledgement, ordered};
use eyre::{OptionExt as _, WrapErr as _};
use futures::{StreamExt as _, channel::mpsc};
use prometheus_client::metrics::gauge::Gauge;
use reth_provider::{BlockIdReader as _, HeaderProvider as _};
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_node::TempoFullNode;
use tempo_precompiles::validator_config_v2::ValidatorConfigV2;
use tempo_primitives::TempoHeader;
use tracing::{Span, debug, error, info_span, instrument, warn};

use crate::{
    utils::public_key_to_b256,
    validators::{DecodedValidatorV2, ExecutionNode, read_validator_config_at_block_hash},
};

/// The interval on which the peer set is update during bootstrapping.
/// Aggressive timing to get started.
const BOOTSTRAP_UPDATE_INTERVAL: Duration = Duration::from_secs(5);

/// The interval on which peer sets are freshed during normal operation.
/// Relaxed timing during normal operation.
const HEARTBEAT_UPDATE_INTERVAL: Duration = Duration::from_secs(30);

use super::ingress::{Message, MessageWithCause};

pub(crate) struct Actor<TContext, TPeerManager>
where
    TPeerManager: AddressableManager<PublicKey = PublicKey>,
{
    context: ContextCell<TContext>,

    oracle: TPeerManager,
    execution_node: Arc<TempoFullNode>,
    epoch_strategy: FixedEpocher,
    last_finalized_height: Height,
    mailbox: mpsc::UnboundedReceiver<MessageWithCause>,

    peers: Gauge,

    last_tracked_peer_set: Option<LastTrackedPeerSet>,

    peer_update_timer: Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
}

impl<TContext, TPeerManager> Actor<TContext, TPeerManager>
where
    TContext: Clock + Metrics + Spawner,
    TPeerManager: AddressableManager<PublicKey = PublicKey>,
{
    pub(super) fn new(
        context: TContext,
        super::Config {
            oracle,
            execution_node,
            epoch_strategy,
            last_finalized_height,
        }: super::Config<TPeerManager>,
        mailbox: mpsc::UnboundedReceiver<MessageWithCause>,
    ) -> Self {
        let peers = Gauge::default();
        context.register(
            "peers",
            "how many peers are registered overall for the latest epoch",
            peers.clone(),
        );
        let context = ContextCell::new(context);
        let peer_update_timer = Box::pin(context.sleep(BOOTSTRAP_UPDATE_INTERVAL));
        Self {
            context,
            oracle,
            execution_node,
            epoch_strategy,
            last_finalized_height,
            mailbox,
            peers,
            last_tracked_peer_set: None,

            peer_update_timer,
        }
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
                // Perform aggressive retries if no peer set is tracked yet.
                // Otherwise just do it every minute.
                _ = &mut self.peer_update_timer => {
                    let _ = self.refresh_peers().await;
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
            Message::Track { id, peers } => {
                AddressableManager::track(&mut self.oracle, id, peers).await;
            }
            Message::Overwrite { peers } => {
                AddressableManager::overwrite(&mut self.oracle, peers).await;
            }
            Message::PeerSet { id, response } => {
                let result = Provider::peer_set(&mut self.oracle, id).await;
                let _ = response.send(result);
            }
            Message::Subscribe { response } => {
                let receiver = Provider::subscribe(&mut self.oracle).await;
                let _ = response.send(receiver);
            }
            Message::Finalized(update) => match *update {
                Update::Block(_, ack) => {
                    let _ = self.refresh_peers().await;
                    ack.acknowledge();
                    self.reset_peer_update_timer();
                }
                Update::Tip { .. } => {}
            },
        }
        Ok(())
    }

    /// Reads the peers given the latest finalized state.
    /// and finalized state.
    #[instrument(skip_all, err)]
    async fn refresh_peers(&mut self) -> eyre::Result<()> {
        // Always take whatever is higher: the last finalized height as per
        // consensus layer (greater than 0 only on restarts with populated
        // consensus state), or the highest finalized block number from the
        // execution layer.
        //
        // This works even if the execution layer was replaced with a snapshot.
        //
        // There is no point taking an outdated state because the network has
        // moved on and there is no guarantee that older peers are even around.
        //
        // Compare this to the DKG actor, which boots into older DKG epochs
        // because it attempts to replay older rounds.
        let highest_finalized = self
            .execution_node
            .provider
            .finalized_block_number()
            .wrap_err("unable to read highest finalized block from execution layer")?
            .unwrap_or(self.last_finalized_height.get())
            .max(self.last_finalized_height.get());

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

        let latest_boundary_header = read_header_at_height(&self.execution_node, latest_boundary)
            .wrap_err("failed reading latest boundary header")?;
        let highest_finalized_header =
            read_header_at_height(&self.execution_node, highest_finalized)
                .wrap_err("failed reading highest finalized header")?;

        let onchain_outcome =
            OnchainDkgOutcome::read(&mut latest_boundary_header.extra_data().as_ref())
                .wrap_err_with(|| {
                    format!(
                        "boundary block at `{latest_boundary}` did not contain a valid DKG outcome"
                    )
                })?;

        let peers = PeersBuilder::with_dkg_outcome(&onchain_outcome)
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
            boundary header and resolved p2p addresses against validator \
            config contract"
        );

        self.track_or_overwrite(highest_finalized_header.number(), peers)
            .await;

        Ok(())
    }

    async fn track_or_overwrite(&mut self, height: u64, peers: Peers) {
        if let Some(tracked) = &self.last_tracked_peer_set {
            match peers.what_has_changed_compared_to(&tracked.peers) {
                WhatHasChanged::Nothing => {}
                WhatHasChanged::Addresses => self.oracle.overwrite(peers.to_flat_map()).await,
                WhatHasChanged::Peers => self.oracle.track(height, peers.clone()).await,
            }
        } else {
            self.oracle.track(height, peers.clone()).await;
        }

        // Always bump the last-tracked peer set. If the peers are unchanged
        // this only updates the height, but we use the height to determine if
        // state should be read or not.
        self.last_tracked_peer_set
            .replace(LastTrackedPeerSet { height, peers });

        if let Some(tracked) = &self.last_tracked_peer_set {
            self.peers.set(tracked.peers.len() as i64);
        }

        debug!(
            last_tracked_peer_set = ?self.last_tracked_peer_set.as_ref().expect("just set it"),
            "latest tracked peerset",
        );
    }

    fn reset_peer_update_timer(&mut self) {
        // Perform aggressive retries if no peer set is tracked yet.
        // Otherwise just do it every minute.
        self.peer_update_timer = Box::pin(
            self.context.sleep(
                self.last_tracked_peer_set
                    .as_ref()
                    .map_or(BOOTSTRAP_UPDATE_INTERVAL, |_| HEARTBEAT_UPDATE_INTERVAL),
            ),
        );
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
    fn with_dkg_outcome(outcome: &OnchainDkgOutcome) -> Self {
        let primary = outcome.players().clone();
        let secondary = ordered::Set::from_iter_dedup(
            outcome
                .next_players()
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
fn read_header_at_height(execution_node: &TempoFullNode, height: u64) -> eyre::Result<TempoHeader> {
    execution_node
        .provider
        .header_by_number(height)
        .map_err(eyre::Report::new)
        .and_then(|h| h.ok_or_eyre("execution layer did not have a header at the requested height"))
        .wrap_err_with(|| format!("failed reading header at height `{height}`"))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr, SocketAddr},
    };

    use alloy_consensus::Header;
    use alloy_primitives::{Address as AlloyAddress, B256, Keccak256, U256};
    use commonware_codec::Encode as _;
    use commonware_consensus::types::Epoch;
    use commonware_cryptography::{
        Signer as _,
        bls12381::{
            dkg,
            primitives::{sharing::Mode, variant::MinSig},
        },
        ed25519::PrivateKey,
    };
    use commonware_utils::{N3f1, TryFromIterator as _};
    use rand_08::SeedableRng as _;
    use reth_ethereum::evm::revm::{State, database::StateProviderDatabase};
    use reth_node_builder::ConfigureEvm as _;
    use reth_provider::{
        StateProviderBox,
        test_utils::{ExtendedAccount, MockEthProvider},
    };
    use tempo_node::evm::{TempoEvmConfig, evm::TempoEvm};
    use tempo_precompiles::{
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
    }

    impl ExecutionNode for TestExecutionNode {
        fn header(&self, block_hash: B256) -> eyre::Result<TempoHeader> {
            assert_eq!(block_hash, self.hash);
            Ok(TempoHeader {
                general_gas_limit: 30_000_000,
                inner: Header {
                    number: self.height,
                    timestamp: 1,
                    gas_limit: 30_000_000,
                    base_fee_per_gas: Some(1),
                    ..Default::default()
                },
                ..Default::default()
            })
        }

        fn state_by_block_hash(&self, block_hash: B256) -> eyre::Result<StateProviderBox> {
            assert_eq!(block_hash, self.hash);
            Ok(Box::new(self.provider.clone()))
        }

        fn evm_for_block(
            &self,
            db: State<StateProviderDatabase<StateProviderBox>>,
            header: &TempoHeader,
        ) -> eyre::Result<TempoEvm<State<StateProviderDatabase<StateProviderBox>>>> {
            TempoEvmConfig::moderato()
                .evm_for_block(db, header)
                .map_err(eyre::Report::new)
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
        let validator_address = AlloyAddress::from([seed; 20]);
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
                .encode()
                .to_vec();

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
        let mut storage = HashMapStorageProvider::new(1);
        let owner = AlloyAddress::from([0xAA; 20]);

        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut config = ValidatorConfigV2::new();
            config.initialize(owner)?;
            for validator in validators {
                config.add_validator(owner, validator.add_validator_call())?;
            }
            Ok(())
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

        Ok(TestExecutionNode {
            hash: B256::from([0x42; 32]),
            height: 7,
            provider,
        })
    }

    fn dkg_outcome(
        players: impl IntoIterator<Item = PublicKey>,
        next_players: impl IntoIterator<Item = PublicKey>,
    ) -> eyre::Result<OnchainDkgOutcome> {
        let mut rng = rand_08::rngs::StdRng::seed_from_u64(42);
        let (output, _) = dkg::deal::<MinSig, _, N3f1>(
            &mut rng,
            Mode::NonZeroCounter,
            ordered::Set::try_from_iter(players)?,
        )?;

        Ok(OnchainDkgOutcome {
            epoch: Epoch::new(0),
            output,
            next_players: ordered::Set::try_from_iter(next_players)?,
            is_next_full_dkg: false,
        })
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

    #[test]
    fn resolve_at_hash_has_no_secondaries_when_players_are_next_players() -> eyre::Result<()> {
        let execution = execution_with_validators(&[peer(1), peer(2)])?;
        let outcome = dkg_outcome(
            [peer(1).public_key, peer(2).public_key],
            [peer(1).public_key, peer(2).public_key],
        )?;
        let peers =
            PeersBuilder::with_dkg_outcome(&outcome).resolve_at_hash(&execution, execution.hash)?;

        assert_eq!(peers.primary.len(), 2);
        assert_eq!(peers.secondary.len(), 0);
        assert_peer(&peers.primary, &peer(1));
        assert_peer(&peers.primary, &peer(2));

        Ok(())
    }

    #[test]
    fn resolve_at_hash_keeps_dropped_player_primary() -> eyre::Result<()> {
        let execution = execution_with_validators(&[peer(1), peer(2)])?;
        let outcome = dkg_outcome(
            [peer(1).public_key, peer(2).public_key],
            [peer(1).public_key],
        )?;
        let peers =
            PeersBuilder::with_dkg_outcome(&outcome).resolve_at_hash(&execution, execution.hash)?;

        assert_eq!(peers.primary.len(), 2);
        assert_eq!(peers.secondary.len(), 0);
        assert_peer(&peers.primary, &peer(1));
        assert_peer(&peers.primary, &peer(2));

        Ok(())
    }

    #[test]
    fn resolve_at_hash_adds_next_player_as_secondary() -> eyre::Result<()> {
        let execution = execution_with_validators(&[peer(1), peer(2)])?;
        let outcome = dkg_outcome(
            [peer(1).public_key],
            [peer(1).public_key, peer(2).public_key],
        )?;
        let peers =
            PeersBuilder::with_dkg_outcome(&outcome).resolve_at_hash(&execution, execution.hash)?;

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
        let outcome = dkg_outcome([peer(1).public_key], [peer(1).public_key])?;
        let peers =
            PeersBuilder::with_dkg_outcome(&outcome).resolve_at_hash(&execution, execution.hash)?;

        assert_eq!(peers.primary.len(), 1);
        assert_eq!(peers.secondary.len(), 1);
        assert_peer(&peers.primary, &peer(1));
        assert_no_peer(&peers.secondary, &peer(1));
        assert_peer(&peers.secondary, &peer(2));

        Ok(())
    }
}
