use malachitebft_core_types::Round;

use reth_ethereum_engine_primitives::EthPayloadTypes;

use rand::SeedableRng;
use rand::rngs::StdRng;
use reth::payload::{PayloadBuilderHandle, PayloadServiceCommand};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use tokio::sync::mpsc;

use crate::context::MalachiteContext;
use crate::height::Height;
use crate::provider::Ed25519Provider;
use crate::utils::seed_from_address;
use crate::store::store::Store;

/// Represents the internal state of the application node
/// Contains information about current height, round, proposals and blocks
#[derive(Debug, Clone)]
pub struct State {
    pub ctx: MalachiteContext,
    pub config: Config,
    pub genesis: Genesis,
    pub address: Address,
    pub current_height: Height,
    pub current_round: Round,
    pub current_proposer: Option<Address>,
    pub current_role: Role,
    pub peers: HashSet<PeerId>,
    pub store: Store,

    pub signing_provider: Ed25519Provider,
    pub streams_map: PartStreamsMap,
    pub rng: StdRng,

    // Handle to the payload builder service
    pub engine_handle: PayloadBuilderHandle<EthPayloadTypes>,
}

impl State {
    pub fn new(ctx: MalachiteContext, config: Config, genesis: Genesis, address: Address) -> Self {
        let (tx, _rx) = mpsc::unbounded_channel();

        Self {
            ctx,
            config,
            genesis,
            address,
            current_height: Height::default(),
            current_round: Round::Nil,
            current_proposer: None,
            current_role: Role::None,
            peers: HashSet::new(),
            store: Store::new(),
            signing_provider: Ed25519Provider::new(),
            streams_map: PartStreamsMap::new(),
            rng: StdRng::seed_from_u64(seed_from_address(&address, std::process::id() as u64)),
            engine_handle: PayloadBuilderHandle::new(tx),
        }
    }

    pub fn signing_provider(&self) -> &Ed25519Provider {
        &self.signing_provider
    }

    pub fn rng(&mut self) -> &mut StdRng {
        &mut self.rng
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Address([u8; 20]);

impl Address {
    pub fn new(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 20 {
            let mut arr = [0u8; 20];
            arr.copy_from_slice(bytes);
            Some(Self(arr))
        } else {
            None
        }
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    pub const ZERO: Self = Self([0u8; 20]);
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({})", self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Genesis {
    pub chain_id: String,
    pub validators: Vec<ValidatorInfo>,
    pub app_state: Vec<u8>,
}

impl Genesis {
    pub fn new(chain_id: String) -> Self {
        Self {
            chain_id,
            validators: Vec::new(),
            app_state: Vec::new(),
        }
    }

    pub fn with_validators(mut self, validators: Vec<ValidatorInfo>) -> Self {
        self.validators = validators;
        self
    }

    pub fn with_app_state(mut self, app_state: Vec<u8>) -> Self {
        self.app_state = app_state;
        self
    }
}

impl Default for Genesis {
    fn default() -> Self {
        Self::new("malachite-test".to_string())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub address: Address,
    pub voting_power: u64,
    pub public_key: Vec<u8>,
}

impl ValidatorInfo {
    pub fn new(address: Address, voting_power: u64, public_key: Vec<u8>) -> Self {
        Self {
            address,
            voting_power,
            public_key,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub block_time: std::time::Duration,
    pub create_empty_blocks: bool,
}

impl Config {
    pub fn new() -> Self {
        Self {
            block_time: std::time::Duration::from_secs(1),
            create_empty_blocks: true,
        }
    }
}

/// The role that the node is playing in the consensus protocol during a round.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Role {
    /// The node is the proposer for the current round.
    Proposer,
    /// The node is a validator for the current round.
    Validator,
    /// The node is not participating in the consensus protocol for the current round.
    None,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PeerId([u8; 32]);

impl PeerId {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            Some(Self(arr))
        } else {
            None
        }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub const ZERO: Self = Self([0u8; 32]);
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({})", self)
    }
}

#[derive(Debug, Clone)]
pub struct PartStreamsMap {
    // Maps from peer ID to their partial stream state
    streams: HashMap<PeerId, PartialStreamState>,
}

impl PartStreamsMap {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
        }
    }

    pub fn get_stream(&self, peer_id: &PeerId) -> Option<&PartialStreamState> {
        self.streams.get(peer_id)
    }

    pub fn get_stream_mut(&mut self, peer_id: &PeerId) -> Option<&mut PartialStreamState> {
        self.streams.get_mut(peer_id)
    }

    pub fn insert_stream(&mut self, peer_id: PeerId, stream: PartialStreamState) {
        self.streams.insert(peer_id, stream);
    }

    pub fn remove_stream(&mut self, peer_id: &PeerId) -> Option<PartialStreamState> {
        self.streams.remove(peer_id)
    }
}

impl Default for PartStreamsMap {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct PartialStreamState {
    pub height: Height,
    pub round: Round,
    pub step: ConsensusStep,
    pub last_activity: std::time::Instant,
}

impl PartialStreamState {
    pub fn new(height: Height, round: Round) -> Self {
        Self {
            height,
            round,
            step: ConsensusStep::NewHeight,
            last_activity: std::time::Instant::now(),
        }
    }

    pub fn update_activity(&mut self) {
        self.last_activity = std::time::Instant::now();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusStep {
    NewHeight,
    NewRound,
    Propose,
    Prevote,
    Precommit,
    Commit,
}
