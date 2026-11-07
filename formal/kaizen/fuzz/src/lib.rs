//! Differential fuzzing of the Lean-extracted Kaizen follower core (formal/kaizen/Kaizen/FFI.lean)
//! against an independent Rust reference written from commonware's codec and Tempo's verifier.

pub mod core;
pub mod diff;
pub mod generate;
pub mod oracle;
pub mod reference;

/// One step input, as the shim hands it to the core.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub height: u64,
    pub digest: Vec<u8>,
    pub parent: Vec<u8>,
    pub state_root: Vec<u8>,
    pub cert: Vec<u8>,
    pub dkg: Option<(u64, Vec<u8>)>,
}

/// Follower configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub epoch_length: u64,
    pub from_epoch: u64,
    pub network_key: Vec<u8>,
}

/// An accepted tip as both sides expose it: (height, digest, stateRoot).
pub type TipView = Option<(u64, Vec<u8>, Vec<u8>)>;
