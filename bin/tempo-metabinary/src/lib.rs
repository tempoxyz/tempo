//! Era routing and process supervision for frozen historical Tempo executors.
//!
//! The live node executes the last era; earlier eras run in frozen `rpc-only` workers over the same
//! storage. Era boundaries are hardfork activations from `tempo-hardfork`, its only Tempo
//! dependency; the `tempo` binary implements [`routing::Backend`].

pub mod catalog;
pub mod decorate;
pub mod handshake;
pub mod process;
pub mod routing;
pub mod workers;
