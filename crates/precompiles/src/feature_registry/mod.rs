//! TIP-1063 protocol feature registry precompile.

pub mod dispatch;

use crate::{
    FEATURE_REGISTRY_ADDRESS, SYSTEM_CALLER_ADDRESS,
    error::Result,
    storage::{Handler, Mapping},
    validator_config_v2::ValidatorConfigV2,
};
use alloy::primitives::{Address, B256, U256};
use tempo_chainspec::{epoch::block_to_epoch, features::protocol_features_digest};
use tempo_contracts::precompiles::{
    FeatureRegistryError, FeatureRegistryEvent, IFeatureRegistry, ValidatorConfigV2Error,
};
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
    /// Digest of each ordered feature registry prefix reported by each validator.
    validator_supported_features_digest: Mapping<Address, Mapping<u64, B256>>,
    /// Number of validators that currently agree with a feature tip digest.
    features_tip_support_count: Mapping<u64, Mapping<B256, u64>>,
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

    /// Returns the feature registry prefix digest reported by `validator` for `features_tip`.
    pub fn validator_supported_features_digest(
        &self,
        validator: Address,
        features_tip: u64,
    ) -> Result<B256> {
        self.validator_supported_features_digest[validator][features_tip].read()
    }

    pub fn validator_supported_features_tip_by_public_key(&self, public_key: B256) -> Result<u64> {
        let validator = self.validator_address_by_public_key(public_key)?;
        self.validator_supported_features_tip(validator)
    }

    pub fn next_validator_support_update(
        &self,
        public_key: B256,
        supported_features_tip: u64,
    ) -> Result<Option<IFeatureRegistry::setSupportedFeaturesTipCall>> {
        let validator = self.validator_address_by_public_key(public_key)?;
        if self.validator_supported_features_tip(validator)? < supported_features_tip {
            return Ok(Some(IFeatureRegistry::setSupportedFeaturesTipCall {
                publicKey: public_key,
                featuresTip: supported_features_tip,
                featuresDigest: protocol_features_digest(supported_features_tip)
                    .ok_or_else(|| FeatureRegistryError::invalid_features_tip())?,
            }));
        }

        for features_tip in 1..=supported_features_tip {
            let expected_digest = protocol_features_digest(features_tip)
                .ok_or_else(|| FeatureRegistryError::invalid_features_tip())?;
            if self.validator_supported_features_digest(validator, features_tip)? != expected_digest
            {
                return Ok(Some(IFeatureRegistry::setSupportedFeaturesTipCall {
                    publicKey: public_key,
                    featuresTip: features_tip,
                    featuresDigest: expected_digest,
                }));
            }
        }

        Ok(None)
    }

    fn validator_address_by_public_key(&self, public_key: B256) -> Result<Address> {
        let validator = ValidatorConfigV2::new().validator_by_public_key(public_key)?;
        if validator.deactivatedAtHeight != 0 {
            return Err(ValidatorConfigV2Error::validator_already_deactivated().into());
        }

        Ok(validator.validatorAddress)
    }

    pub fn set_supported_features_tip(
        &mut self,
        msg_sender: Address,
        call: IFeatureRegistry::setSupportedFeaturesTipCall,
    ) -> Result<()> {
        if !msg_sender.is_zero() {
            return Err(FeatureRegistryError::unauthorized().into());
        }

        let validator = self.validator_address_by_public_key(call.publicKey)?;
        let previous = self.validator_supported_features_tip[validator].read()?;
        if call.featuresTip < previous {
            return Err(FeatureRegistryError::supported_features_tip_decreased().into());
        }

        let expected_digest = protocol_features_digest(call.featuresTip)
            .ok_or_else(|| FeatureRegistryError::invalid_features_tip())?;
        if call.featuresDigest != expected_digest {
            return Err(FeatureRegistryError::invalid_features_tip().into());
        }

        let previous_digest =
            self.validator_supported_features_digest[validator][call.featuresTip].read()?;
        let was_counted = previous >= call.featuresTip && previous_digest != B256::ZERO;

        if call.featuresTip > previous {
            self.validator_supported_features_tip[validator].write(call.featuresTip)?;
        }

        if was_counted && previous_digest != call.featuresDigest {
            let previous_support =
                self.features_tip_support_count[call.featuresTip][previous_digest].read()?;
            self.features_tip_support_count[call.featuresTip][previous_digest]
                .write(previous_support.saturating_sub(1))?;
        }

        if previous_digest != call.featuresDigest {
            self.validator_supported_features_digest[validator][call.featuresTip]
                .write(call.featuresDigest)?;
        }

        if !was_counted || previous_digest != call.featuresDigest {
            let support =
                self.features_tip_support_count[call.featuresTip][call.featuresDigest].read()?;
            self.features_tip_support_count[call.featuresTip][call.featuresDigest]
                .write(support + 1)?;
        }

        Ok(())
    }

    pub fn features_tip_support(
        &self,
        features_tip: u64,
    ) -> Result<IFeatureRegistry::featuresTipSupportReturn> {
        let expected_digest = protocol_features_digest(features_tip)
            .ok_or_else(|| FeatureRegistryError::invalid_features_tip())?;
        let active_validator_count = ValidatorConfigV2::new().active_validator_count()?;
        let support = self.features_tip_support_count[features_tip][expected_digest].read()?;

        Ok((
            U256::from(support),
            U256::from(required_support_count(active_validator_count)),
        )
            .into())
    }

    pub fn has_features_tip_quorum(&self, features_tip: u64) -> Result<bool> {
        let support = self.features_tip_support(features_tip)?;
        Ok(support.support >= support.required)
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

fn required_support_count(active_validator_count: u64) -> u64 {
    (ACTIVATION_QUORUM_NUMERATOR * active_validator_count).div_ceil(ACTIVATION_QUORUM_DENOMINATOR)
}
