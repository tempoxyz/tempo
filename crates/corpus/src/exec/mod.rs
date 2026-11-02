//! Corpus execution on the EVM: capture an archive range ([`fill`], [`capture`]) and replay it
//! against its records ([`replay`]).

pub mod block;
pub mod capture;
pub mod db;
pub mod fill;
pub mod replay;

pub use replay::{run, run_blocks};
