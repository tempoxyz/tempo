//! A process supervisor and RPC router. It deliberately has no Tempo or Reth dependencies.
pub mod catalog;
pub mod decorate;
pub mod handshake;
pub mod manifest;
pub mod process;
pub mod routing;
pub mod server;
pub mod workers;
