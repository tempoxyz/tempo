//! BLS12-381 threshold signature implementations for `simplex`.
//!
//! This module provides two variants of threshold signing:
//!
//! - [`standard`]: Certificates contain only a vote signature (requires half the computation to verify
//!   partial signatures and recover threshold signatures as [`vrf`]).
//!
//! - [`vrf`]: Certificates contain a vote signature and a round signature (a seed that can be used
//!   as a VRF).
//!
//! # Non-Attributable Signatures
//!
//! Both variants are **non-attributable**: individual partial signatures cannot be
//! safely presented to third parties as evidence of liveness or faults. With threshold
//! signatures, any `t` valid partial signatures can forge a partial signature for any
//! other participant. Because peer connections are authenticated, evidence can be used
//! locally but cannot be used by external observers.

pub mod standard;
pub mod vrf;
