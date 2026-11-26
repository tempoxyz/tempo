//! Corpus execution on the EVM: capture an archive range ([`fill`], [`capture`]), replay it
//! against its records ([`replay`]) or under a candidate hardfork's rules ([`shadow`]), and read
//! extra pre-state for inputs derived from its blocks ([`widen`]).

pub mod block;
pub mod capture;
pub mod db;
pub mod fill;
pub mod replay;
pub mod shadow;
pub mod widen;

pub use replay::{run, run_blocks};
