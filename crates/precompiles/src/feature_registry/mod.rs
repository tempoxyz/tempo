//! TIP-1063 feature registry precompile.

pub mod dispatch;

use crate::{
    FEATURE_REGISTRY_ADDRESS,
    error::Result,
    storage::{Handler, Mapping},
    validator_config_v2::ValidatorConfigV2,
};
use alloy::primitives::{Address, B256, U256};
use tempo_contracts::precompiles::{
    FeatureRegistryError, FeatureRegistryEvent, IFeatureRegistry, ValidatorConfigV2Error,
};
use tempo_precompiles_macros::contract;

// Activation requires 80% support from the active validator set, represented exactly as 4/5.
const ACTIVATION_QUORUM_NUMERATOR: u64 = 4;
const ACTIVATION_QUORUM_DENOMINATOR: u64 = 5;

/// Feature registry.
///
/// The active feature head lives at storage slot zero and represents the hash-chain head
/// for the active feature stack.
#[contract(addr = FEATURE_REGISTRY_ADDRESS)]
pub struct FeatureRegistry {
    /// Active feature head.
    active_feature_head: B256,
    /// Scheduled target feature head, or zero when no target is scheduled.
    scheduled_feature_head: B256,
    /// Earliest activation epoch for the scheduled feature head, or zero when none is scheduled.
    scheduled_activation_epoch: u64,
    /// Latest feature head confirmed by each validator address.
    validator_confirmed_feature_head: Mapping<Address, B256>,
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

    /// Returns the active feature head.
    pub fn active_feature_head(&self) -> Result<B256> {
        self.active_feature_head.read()
    }

    /// Returns the fixed activation quorum threshold as an exact fraction: 4/5, or 80%.
    pub fn activation_quorum(&self) -> Result<IFeatureRegistry::activationQuorumReturn> {
        Ok((
            U256::from(ACTIVATION_QUORUM_NUMERATOR),
            U256::from(ACTIVATION_QUORUM_DENOMINATOR),
        )
            .into())
    }

    /// Returns the scheduled target feature head and earliest activation epoch.
    pub fn scheduled_feature_head(&self) -> Result<IFeatureRegistry::scheduledFeatureHeadReturn> {
        Ok((
            self.scheduled_feature_head.read()?,
            self.scheduled_activation_epoch.read()?,
        )
            .into())
    }

    /// Returns whether `validator` confirmed readiness for `feature_head`.
    pub fn validator_confirmed_feature_head(
        &self,
        validator: Address,
        feature_head: B256,
    ) -> Result<bool> {
        Ok(feature_head != B256::ZERO
            && self.validator_confirmed_feature_head[validator].read()? == feature_head)
    }

    pub fn validator_confirmed_feature_head_by_public_key(
        &self,
        public_key: B256,
        feature_head: B256,
    ) -> Result<bool> {
        let validator = self.validator_address_by_public_key(public_key)?;
        self.validator_confirmed_feature_head(validator, feature_head)
    }

    fn validator_address_by_public_key(&self, public_key: B256) -> Result<Address> {
        let validator = ValidatorConfigV2::new().validator_by_public_key(public_key)?;
        if validator.deactivatedAtHeight != 0 {
            return Err(ValidatorConfigV2Error::validator_already_deactivated().into());
        }

        Ok(validator.validatorAddress)
    }

    fn validator_address_by_epoch_public_key(&self, public_key: B256) -> Result<Address> {
        Ok(ValidatorConfigV2::new()
            .validator_by_public_key(public_key)?
            .validatorAddress)
    }

    pub fn confirm_feature_head_readiness(&mut self, msg_sender: Address) -> Result<()> {
        if !msg_sender.is_zero() {
            return Err(FeatureRegistryError::unauthorized().into());
        }

        let feature_head = self.scheduled_feature_head.read()?;
        if feature_head == B256::ZERO {
            return Err(FeatureRegistryError::feature_head_not_scheduled().into());
        }

        let Some(public_key) = self
            .storage
            .with_block_env(|block_env| block_env.proposer_public_key)
        else {
            return Err(FeatureRegistryError::proposer_public_key_unavailable().into());
        };
        let validator = self.validator_address_by_public_key(B256::from(public_key))?;
        self.validator_confirmed_feature_head[validator].write(feature_head)?;

        self.emit_event(FeatureRegistryEvent::feature_head_readiness_confirmed(
            validator,
            feature_head,
        ))
    }

    pub fn schedule_feature_head(
        &mut self,
        msg_sender: Address,
        call: IFeatureRegistry::scheduleFeatureHeadCall,
    ) -> Result<()> {
        self.check_owner(msg_sender)?;

        if call.featureHead == B256::ZERO {
            return Err(FeatureRegistryError::invalid_feature_head().into());
        }

        if call.featureHead == self.active_feature_head.read()? {
            return Err(FeatureRegistryError::feature_head_already_active().into());
        }

        if self.scheduled_feature_head.read()? != B256::ZERO {
            return Err(FeatureRegistryError::feature_head_already_scheduled().into());
        }

        let current_epoch = self.storage.epoch(self.storage.block_number());
        if call.activationEpoch <= current_epoch {
            return Err(FeatureRegistryError::activation_epoch_not_future().into());
        }

        self.scheduled_feature_head.write(call.featureHead)?;
        self.scheduled_activation_epoch
            .write(call.activationEpoch)?;
        self.emit_event(FeatureRegistryEvent::feature_head_scheduled(
            call.featureHead,
            call.activationEpoch,
        ))
    }

    pub fn cancel_scheduled_feature_head(&mut self, msg_sender: Address) -> Result<()> {
        self.check_owner(msg_sender)?;

        let scheduled_feature_head = self.scheduled_feature_head.read()?;
        if scheduled_feature_head == B256::ZERO {
            return Err(FeatureRegistryError::feature_head_not_scheduled().into());
        }

        self.scheduled_feature_head.write(B256::ZERO)?;
        self.scheduled_activation_epoch.write(0)?;
        self.emit_event(FeatureRegistryEvent::feature_head_schedule_cancelled(
            scheduled_feature_head,
        ))
    }

    /// Activates the scheduled feature head from the block-level system caller.
    pub fn activate_scheduled_feature_head_from_system(
        &mut self,
        msg_sender: Address,
        current_epoch: u64,
        active_validator_public_keys: &[B256],
    ) -> Result<()> {
        if msg_sender != Address::ZERO {
            return Err(FeatureRegistryError::unauthorized().into());
        }

        self.activate_scheduled_feature_head(current_epoch, active_validator_public_keys)?;
        Ok(())
    }

    /// Returns current active-validator readiness for a feature head.
    ///
    /// This uses the currently active validator-config set until the epoch-effective validator set
    /// from TIP-1070 is available to precompiles.
    pub fn feature_head_support(
        &self,
        feature_head: B256,
    ) -> Result<IFeatureRegistry::featureHeadSupportReturn> {
        let validators = ValidatorConfigV2::new().get_active_validators()?;
        let required = required_activation_count(validators.len());
        let mut support = 0usize;
        for validator in validators {
            if self.validator_confirmed_feature_head(validator.validatorAddress, feature_head)? {
                support += 1;
            }
        }

        Ok((U256::from(support), U256::from(required)).into())
    }

    /// Returns whether a feature head has enough active-validator readiness.
    pub fn has_feature_head_quorum(&self, feature_head: B256) -> Result<bool> {
        let support = self.feature_head_support(feature_head)?;
        Ok(!support.required.is_zero() && support.support >= support.required)
    }

    fn feature_head_support_for_public_keys(
        &self,
        feature_head: B256,
        active_validator_public_keys: &[B256],
    ) -> Result<(usize, usize)> {
        let required = required_activation_count(active_validator_public_keys.len());
        let mut support = 0usize;
        for public_key in active_validator_public_keys {
            let validator = self.validator_address_by_epoch_public_key(*public_key)?;
            if self.validator_confirmed_feature_head(validator, feature_head)? {
                support += 1;
            }
        }

        Ok((support, required))
    }

    /// Activates the scheduled feature head if its target epoch has arrived and has quorum.
    pub fn activate_scheduled_feature_head(
        &mut self,
        current_epoch: u64,
        active_validator_public_keys: &[B256],
    ) -> Result<bool> {
        let scheduled_feature_head = self.scheduled_feature_head.read()?;
        let scheduled_activation_epoch = self.scheduled_activation_epoch.read()?;

        if scheduled_feature_head == B256::ZERO
            || scheduled_activation_epoch == 0
            || scheduled_activation_epoch > current_epoch
        {
            return Ok(false);
        }

        let active_feature_head = self.active_feature_head.read()?;
        let (support, required) = self.feature_head_support_for_public_keys(
            scheduled_feature_head,
            active_validator_public_keys,
        )?;
        let activated =
            scheduled_feature_head != active_feature_head && required != 0 && support >= required;
        if activated {
            self.active_feature_head.write(scheduled_feature_head)?;
            self.emit_event(FeatureRegistryEvent::feature_head_activated(
                active_feature_head,
                scheduled_feature_head,
                scheduled_activation_epoch,
            ))?;
        }

        self.scheduled_feature_head.write(B256::ZERO)?;
        self.scheduled_activation_epoch.write(0)?;

        Ok(activated)
    }
}

fn required_activation_count(active_validator_count: usize) -> usize {
    (ACTIVATION_QUORUM_NUMERATOR as usize * active_validator_count)
        .div_ceil(ACTIVATION_QUORUM_DENOMINATOR as usize)
}
