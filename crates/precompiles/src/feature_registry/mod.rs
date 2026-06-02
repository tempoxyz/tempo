//! TIP-1063 protocol feature registry precompile.

pub mod dispatch;

use crate::{FEATURE_REGISTRY_ADDRESS, error::Result, storage::Handler};
use tempo_precompiles_macros::contract;

/// Protocol feature registry.
///
/// The first implementation exposes the active feature tip cursor. The cursor lives at storage
/// slot zero and represents the highest active protocol feature ID.
#[contract(addr = FEATURE_REGISTRY_ADDRESS)]
pub struct FeatureRegistry {
    /// Highest active protocol feature ID.
    features_tip: u64,
}

impl FeatureRegistry {
    /// Initializes the registry contract by setting its bytecode marker.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Returns the highest active protocol feature ID.
    pub fn features_tip(&self) -> Result<u64> {
        self.features_tip.read()
    }
}
