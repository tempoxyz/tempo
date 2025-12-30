//! Epoch logic used by tempo.
//!
//! All logic is written with the assumption that there are at least 3 heights
//! per epoch. Having less heights per epoch will not immediately break the
//! logic, but it might lead to strange behavior and is not supported.
//!
//! Note that either way, 3 blocks per epoch is a highly unreasonable number.

pub(crate) mod manager;
mod scheme_provider;

pub(crate) use manager::ingress::{EpochTransition, Exit};
pub(crate) use scheme_provider::SchemeProvider;
