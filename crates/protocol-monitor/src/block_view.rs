//! Finalized block views consumed by invariant checks.
//!
//! A `BlockView` will compose finalized block facts `B[n]`, parent/current
//! state views `S[n-1]`/`S[n]`, and monitor history `H_view` using only
//! monitor-owned types.
