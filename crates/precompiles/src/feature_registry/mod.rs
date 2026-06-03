//! TIP-1063 protocol feature registry precompile.

pub mod dispatch;

use crate::{
    FEATURE_REGISTRY_ADDRESS, SYSTEM_CALLER_ADDRESS,
    error::Result,
    storage::{Handler, Mapping},
    validator_config_v2::ValidatorConfigV2,
};
use alloy::primitives::{Address, U256};
use tempo_chainspec::epoch::block_to_epoch;
use tempo_contracts::precompiles::{FeatureRegistryError, FeatureRegistryEvent, IFeatureRegistry};
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

    pub fn owner(&self) -> Result<Address> {
        ValidatorConfigV2::new().owner()
    }

    fn check_owner(&self, msg_sender: Address) -> Result<()> {
        if self.owner()? != msg_sender {
            return Err(FeatureRegistryError::unauthorized().into());
        }

        Ok(())
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

    pub fn set_supported_features_tip(
        &mut self,
        msg_sender: Address,
        call: IFeatureRegistry::setSupportedFeaturesTipCall,
    ) -> Result<()> {
        let previous = self.validator_supported_features_tip[msg_sender].read()?;
        if call.featuresTip < previous {
            return Err(FeatureRegistryError::supported_features_tip_decreased().into());
        }

        self.validator_supported_features_tip[msg_sender].write(call.featuresTip)
    }

    pub fn schedule_features_tip(
        &mut self,
        msg_sender: Address,
        call: IFeatureRegistry::scheduleFeaturesTipCall,
    ) -> Result<()> {
        self.check_owner(msg_sender)?;

        if call.featuresTip <= self.features_tip.read()? {
            return Err(FeatureRegistryError::features_tip_not_increasing().into());
        }

        if self.scheduled_features_tip.read()? != 0 {
            return Err(FeatureRegistryError::features_tip_already_scheduled().into());
        }

        if call.activationEpoch <= block_to_epoch(self.storage.block_number()) {
            return Err(FeatureRegistryError::activation_epoch_not_future().into());
        }

        self.scheduled_features_tip.write(call.featuresTip)?;
        self.scheduled_activation_epoch
            .write(call.activationEpoch)?;
        self.emit_event(FeatureRegistryEvent::features_tip_scheduled(
            call.featuresTip,
            call.activationEpoch,
        ))
    }

    pub fn cancel_scheduled_features_tip(&mut self, msg_sender: Address) -> Result<()> {
        self.check_owner(msg_sender)?;

        let scheduled_features_tip = self.scheduled_features_tip.read()?;
        if scheduled_features_tip == 0 {
            return Err(FeatureRegistryError::features_tip_not_scheduled().into());
        }

        self.scheduled_features_tip.write(0)?;
        self.scheduled_activation_epoch.write(0)?;
        self.emit_event(FeatureRegistryEvent::features_tip_schedule_cancelled(
            scheduled_features_tip,
        ))
    }

    /// Activates the scheduled feature tip from the block-level system caller.
    pub fn activate_scheduled_features_tip_from_system(
        &mut self,
        msg_sender: Address,
        current_epoch: u64,
    ) -> Result<()> {
        if msg_sender != SYSTEM_CALLER_ADDRESS {
            return Err(FeatureRegistryError::unauthorized().into());
        }

        self.activate_scheduled_features_tip(current_epoch)?;
        Ok(())
    }

    /// Activates the scheduled feature tip if its target epoch has arrived.
    ///
    /// Quorum enforcement is intentionally not implemented in this scaffold. The full activation
    /// path should enforce validator support once TIP-1070 lands.
    pub fn activate_scheduled_features_tip(&mut self, current_epoch: u64) -> Result<bool> {
        let scheduled_features_tip = self.scheduled_features_tip.read()?;
        let scheduled_activation_epoch = self.scheduled_activation_epoch.read()?;

        if scheduled_features_tip == 0
            || scheduled_activation_epoch == 0
            || scheduled_activation_epoch > current_epoch
        {
            return Ok(false);
        }

        let active_features_tip = self.features_tip.read()?;
        if scheduled_features_tip > active_features_tip {
            self.features_tip.write(scheduled_features_tip)?;
        }

        self.scheduled_features_tip.write(0)?;
        self.scheduled_activation_epoch.write(0)?;

        Ok(scheduled_features_tip > active_features_tip)
    }
}
