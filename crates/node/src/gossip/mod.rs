//! The `tempo/1` RLPx subprotocol for gossiping consensus finalization
//! certificates between Tempo nodes.
//!
//! A follower with gossip ingest enabled processes this protocol alongside
//! upstream RPC. This provides a second finalization path, so an unavailable or
//! unresponsive RPC server does not by itself stop follower progress. The
//! follower can receive a certified tip from a `tempo/1` peer, verify it with the
//! threshold key for that epoch, and update its execution layer.
//!
//! This module contains the code that must live next to reth. This includes the
//! frame format and the per-connection stream polled by reth's session manager.
//! The consensus crate decides how to process frames. It handles coalescing,
//! fairness, rate limits, and certificate verification. The transport does not
//! inspect certificate payloads because the consensus crate already depends on
//! the node crate. The dependency cannot point in both directions.

pub mod wire;
