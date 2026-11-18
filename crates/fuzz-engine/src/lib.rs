//! Tempo's stateless block executor, which fuzzing and replay harnesses build on.
//!
//! An input is a chain, a pre-state and blocks ([`tempo_fuzz_types`]). [`run`] executes the blocks
//! on an in-memory state and reports receipts, the resulting state, what changed, and which protocol
//! invariants broke. A panic inside the executor aborts the process: the node would crash on the
//! same block.
//!
//! The chain is an [`Engine`]: [`Tempo`] for Tempo L1, which `tempo-fuzz-harness` loads as a
//! cdylib, or a chain built on Tempo's EVM, such as a zone, which implements [`Engine`] and gets the
//! same inputs, outcomes and invariants. Each harness exports the shared C ABI with [`ffi`].

mod anchor;
mod chain;
pub mod engine;
mod execute;
pub mod ffi;
mod invariants;
mod state;
mod step;

pub use anchor::Anchor;
pub use chain::chain_spec_on;
pub use engine::{BlockConsensus, Chain, Engine, EvmConfig, Tempo};
pub use execute::{execute, execute_anchored, reject, run};
pub use invariants::{authority, observed};
pub use state::genesis as genesis_state;
pub use step::StepState;

#[cfg(test)]
mod tests;
