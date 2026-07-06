//! Monitor-owned durable store schema and commit API.
//!
//! This module is enabled by the `store` feature. `monitor_head` must advance
//! only through the eventual `commit_block` proof-path operation.
