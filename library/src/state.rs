use malachite_core_types::Round;
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::context::MalachiteContext;
use crate::height::Height;
use crate::provider::Ed25519Provider;

/// Represents the internal state of the application node
/// Contains information about current height, round, proposals and blocks
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

    signing_provider: Ed25519Provider,
    streams_map: PartStreamsMap,
    rng: StdRng,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Address([u8; 20]);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Genesis {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {}

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

// Use reth store implementation
pub struct Store {}

pub struct PartStreamsMap {} // TODO
