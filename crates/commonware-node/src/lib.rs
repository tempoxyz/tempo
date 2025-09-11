//! A Tempo node using commonware's threshold simplex as consensus.
//!
//! The main (and currently only) intended entry point to this crate is
//! [`cli::run`].
pub mod cli;
pub mod config;
pub mod consensus;
