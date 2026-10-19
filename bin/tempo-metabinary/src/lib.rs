//! Execution of frozen Tempo eras by their historical binaries, which share the node's storage.
//!
//! The `tempo` binary supplies the chain adapter. See the README for routing and operations.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod catalog;
pub mod decorate;
pub mod handshake;
pub mod process;
pub mod routing;
pub mod workers;
