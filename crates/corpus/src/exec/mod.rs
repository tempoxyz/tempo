//! Corpus execution on the EVM: capture an archive range ([`fill`], [`capture`]) and replay it
//! against its records ([`replay`]), or under a candidate hardfork's rules ([`shadow`]).

pub mod block;
pub mod capture;
pub mod db;
pub mod fill;
pub mod replay;
pub mod shadow;

pub use replay::{run, run_blocks};
