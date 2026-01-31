//! Consensus indexer library.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod db;
pub mod feed;
pub mod identity;
pub mod indexer;
pub mod state;
pub mod store;

#[cfg(test)]
mod tests;
