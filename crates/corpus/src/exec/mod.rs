//! Everything that executes corpus blocks on the EVM: capturing an archive range into a corpus
//! ([`fill`], [`capture`]) and replaying one against its records ([`replay`]).

pub mod block;
pub mod capture;
pub mod db;
pub mod fill;
pub mod replay;

pub use replay::{run, run_blocks};
