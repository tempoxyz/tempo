//! TIP-1063 protocol feature registry precompile.

pub mod dispatch;

use crate::{
    FEATURE_REGISTRY_ADDRESS,
    error::Result,
    storage::{Handler, Mapping},
};
use alloy::primitives::{Address, U256};
use tempo_contracts::precompiles::{FeatureRegistryError, IFeatureRegistry};
use tempo_precompiles_macros::contract;

// Activation requires 80% support from the active validator set, represented exactly as 4/5.
const ACTIVATION_QUORUM_NUMERATOR: u64 = 4;
const ACTIVATION_QUORUM_DENOMINATOR: u64 = 5;

/// Protocol feature registry.
///
/// The first implementation exposes feature tip cursors. The active feature tip cursor lives at
/// storage slot zero and represents the highest active protocol feature ID.
#[contract(addr = FEATURE_REGISTRY_ADDRESS)]
pub struct FeatureRegistry {
    /// Highest active protocol feature ID.
    features_tip: u64,
    /// Scheduled target feature tip, or zero when no target is scheduled.
    scheduled_features_tip: u64,
    /// Earliest activation epoch for the scheduled feature tip, or zero when none is scheduled.
    scheduled_activation_epoch: u64,
    /// Latest feature tip reported as supported by each validator.
    validator_supported_features_tip: Mapping<Address, u64>,
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

    /// Returns the fixed activation quorum threshold as an exact fraction: 4/5, or 80%.
    pub fn activation_quorum(&self) -> Result<IFeatureRegistry::activationQuorumReturn> {
        Ok((
            U256::from(ACTIVATION_QUORUM_NUMERATOR),
            U256::from(ACTIVATION_QUORUM_DENOMINATOR),
        )
            .into())
    }

    /// Returns the scheduled target feature tip and earliest activation epoch.
    pub fn scheduled_features_tip(&self) -> Result<IFeatureRegistry::scheduledFeaturesTipReturn> {
        Ok((
            self.scheduled_features_tip.read()?,
            self.scheduled_activation_epoch.read()?,
        )
            .into())
    }

    /// Returns the latest feature tip reported as supported by `validator`.
    pub fn validator_supported_features_tip(&self, validator: Address) -> Result<u64> {
        self.validator_supported_features_tip[validator].read()
    }

    /// Records the highest protocol feature tip reported as supported by a validator.
    pub fn set_supported_features_tip(
        &mut self,
        call: IFeatureRegistry::setSupportedFeaturesTipCall,
    ) -> Result<()> {
        let previous = self.validator_supported_features_tip[call.validator].read()?;
        if call.featuresTip < previous {
            return Err(FeatureRegistryError::supported_features_tip_decreased().into());
        }

        self.validator_supported_features_tip[call.validator].write(call.featuresTip)
    }
}
