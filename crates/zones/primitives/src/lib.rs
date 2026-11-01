//! Primitive types used by the zone.
//!
//! This crate is `no_std` compatible so it can be used inside SP1 (RISC-V) guest
//! programs and TEE enclaves, as well as in the host-side prover.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod constants;

#[cfg(feature = "serde")]
pub mod serde_rlp;
