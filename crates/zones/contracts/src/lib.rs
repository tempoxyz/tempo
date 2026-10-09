//! Compatibility exports for the canonical Tempo Zone contract bindings.
//!
//! Bindings are declared once in [`tempo_contracts::zones`].

#![cfg_attr(not(feature = "std"), no_std)]

pub use tempo_contracts::zones::*;

/// Compatibility exports for the previous precompiles module path.
pub mod precompiles {
    pub use tempo_contracts::zones::*;
}
