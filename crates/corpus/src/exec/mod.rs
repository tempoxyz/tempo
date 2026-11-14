//! Corpus execution on the EVM: capture an archive range ([`fill`], [`capture`]) and replay it
//! against its records ([`replay`]).

pub mod block;
pub mod capture;
pub mod chain;
pub mod db;
pub mod fill;
pub mod replay;

pub use replay::{run, run_blocks};

/// `workers`, defaulting to the available parallelism; at least one.
pub fn workers(workers: Option<usize>) -> usize {
    workers
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()))
        .max(1)
}
