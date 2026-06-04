//! ABI dispatch for the [`FeatureRegistry`] precompile.

use super::*;
use crate::{
    Precompile, charge_input_cost, dispatch_call, error::TempoPrecompileError, mutate_void,
    storage::StorageCtx, view,
};
use alloy::{
    primitives::Address,
    sol_types::{SolCall, SolInterface},
};
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::IFeatureRegistry::{self, IFeatureRegistryCalls};

fn unsupported<T: SolCall>() -> PrecompileResult {
    StorageCtx.error_result(TempoPrecompileError::UnknownFunctionSelector(T::SELECTOR))
}

impl Precompile for FeatureRegistry {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch_call(
            calldata,
            &[],
            IFeatureRegistryCalls::abi_decode,
            |call| match call {
                IFeatureRegistryCalls::featuresTip(call) => view(call, |_| self.features_tip()),
                IFeatureRegistryCalls::owner(call) => view(call, |_| self.owner()),
                IFeatureRegistryCalls::activationQuorum(call) => {
                    view(call, |_| self.activation_quorum())
                }
                IFeatureRegistryCalls::scheduledFeaturesTip(call) => {
                    view(call, |_| self.scheduled_features_tip())
                }
                IFeatureRegistryCalls::setSupportedFeaturesTip(call) => {
                    mutate_void(call, msg_sender, |sender, call| {
                        self.set_supported_features_tip(sender, call)
                    })
                }
                IFeatureRegistryCalls::scheduleFeaturesTip(call) => {
                    mutate_void(call, msg_sender, |sender, call| {
                        self.schedule_features_tip(sender, call)
                    })
                }
                IFeatureRegistryCalls::activateScheduledFeaturesTip(call) => {
                    mutate_void(call, msg_sender, |sender, call| {
                        self.activate_scheduled_features_tip_from_system(sender, call.currentEpoch)
                    })
                }
                IFeatureRegistryCalls::cancelScheduledFeaturesTip(call) => {
                    mutate_void(call, msg_sender, |sender, _| {
                        self.cancel_scheduled_features_tip(sender)
                    })
                }
                IFeatureRegistryCalls::validatorSupportedFeaturesTip(call) => view(call, |call| {
                    self.validator_supported_features_tip(call.validator)
                }),
                IFeatureRegistryCalls::featuresTipSupport(_) => {
                    unsupported::<IFeatureRegistry::featuresTipSupportCall>()
                }
                IFeatureRegistryCalls::hasFeaturesTipQuorum(_) => {
                    unsupported::<IFeatureRegistry::hasFeaturesTipQuorumCall>()
                }
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        FEATURE_REGISTRY_ADDRESS, SYSTEM_CALLER_ADDRESS,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        validator_config_v2::{VALIDATOR_NS_ADD, ValidatorConfigV2},
    };
    use alloy::{
        primitives::{B256, Keccak256, U256},
        sol_types::{SolCall, SolError, SolValue},
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{Signer, ed25519::PrivateKey};
    use tempo_chainspec::{
        epoch::EPOCH_LENGTH_BLOCKS, features::HIGHEST_ACTIVE_PROTOCOL_FEATURE_ID_SLOT,
    };
    use tempo_contracts::precompiles::{
        FeatureRegistryError, IValidatorConfigV2, UnknownFunctionSelector,
        VALIDATOR_CONFIG_V2_ADDRESS,
    };

    fn initialize_validator_config_owner(owner: Address) -> eyre::Result<()> {
        ValidatorConfigV2::new().initialize(owner)?;
        Ok(())
    }

    fn add_validator(owner: Address, validator: Address, seed: u64) -> eyre::Result<B256> {
        let private_key = PrivateKey::from_seed(seed);
        let public_key = B256::from_slice(&private_key.public_key().encode());
        let ingress = format!("127.0.0.1:{}", 9000 + seed);
        let egress = format!("127.0.0.{}", seed + 1);
        let fee_recipient = Address::repeat_byte(0x03);

        let mut hasher = Keccak256::new();
        hasher.update(1u64.to_be_bytes());
        hasher.update(VALIDATOR_CONFIG_V2_ADDRESS.as_slice());
        hasher.update(validator.as_slice());
        hasher.update([u8::try_from(ingress.len())?]);
        hasher.update(ingress.as_bytes());
        hasher.update([u8::try_from(egress.len())?]);
        hasher.update(egress.as_bytes());
        hasher.update(fee_recipient.as_slice());
        let message = hasher.finalize();
        let signature = private_key
            .sign(VALIDATOR_NS_ADD, message.as_slice())
            .encode()
            .to_vec();

        ValidatorConfigV2::new().add_validator(
            owner,
            IValidatorConfigV2::addValidatorCall {
                validatorAddress: validator,
                publicKey: public_key,
                ingress,
                egress,
                feeRecipient: fee_recipient,
                signature: signature.into(),
            },
        )?;

        Ok(public_key)
    }

    #[test]
    fn features_tip_defaults_to_zero() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let registry = FeatureRegistry::new();
            assert_eq!(registry.features_tip()?, 0);
            Ok(())
        })
    }

    #[test]
    fn features_tip_reads_cursor_slot() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut registry = FeatureRegistry::new();
            assert_eq!(
                registry.features_tip.slot(),
                HIGHEST_ACTIVE_PROTOCOL_FEATURE_ID_SLOT
            );

            registry.features_tip.write(7)?;
            assert_eq!(registry.features_tip()?, 7);

            Ok(())
        })
    }

    #[test]
    fn owner_defaults_to_zero() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let registry = FeatureRegistry::new();
            assert_eq!(registry.owner()?, Address::ZERO);
            Ok(())
        })
    }

    #[test]
    fn owner_reads_validator_config_owner() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::repeat_byte(0x01);
        StorageCtx::enter(&mut storage, || {
            initialize_validator_config_owner(owner)?;
            assert_eq!(FeatureRegistry::new().owner()?, owner);
            Ok(())
        })
    }

    #[test]
    fn activation_quorum_returns_fixed_threshold() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let registry = FeatureRegistry::new();
            let quorum = registry.activation_quorum()?;
            assert_eq!(quorum.numerator, U256::from(4));
            assert_eq!(quorum.denominator, U256::from(5));
            Ok(())
        })
    }

    #[test]
    fn scheduled_features_tip_defaults_to_zero() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let registry = FeatureRegistry::new();
            let scheduled = registry.scheduled_features_tip()?;
            assert_eq!(scheduled.featuresTip, 0);
            assert_eq!(scheduled.activationEpoch, 0);
            Ok(())
        })
    }

    #[test]
    fn scheduled_features_tip_reads_schedule_fields() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();
            registry.scheduled_features_tip.write(13)?;
            registry.scheduled_activation_epoch.write(21)?;

            let scheduled = registry.scheduled_features_tip()?;
            assert_eq!(scheduled.featuresTip, 13);
            assert_eq!(scheduled.activationEpoch, 21);

            Ok(())
        })
    }

    #[test]
    fn scheduled_features_tip_preserves_active_features_tip() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();
            registry.features_tip.write(7)?;
            registry.scheduled_features_tip.write(13)?;
            registry.scheduled_activation_epoch.write(21)?;

            assert_eq!(registry.features_tip()?, 7);
            let scheduled = registry.scheduled_features_tip()?;
            assert_eq!(scheduled.featuresTip, 13);
            assert_eq!(scheduled.activationEpoch, 21);

            Ok(())
        })
    }

    #[test]
    fn schedule_features_tip_dispatch_sets_schedule_from_owner() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::repeat_byte(0x01);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            initialize_validator_config_owner(owner)?;
            let mut registry = FeatureRegistry::new();
            registry.features_tip.write(7)?;

            let call = IFeatureRegistry::scheduleFeaturesTipCall {
                featuresTip: 13,
                activationEpoch: 21,
            };
            let result = registry.call(&call.abi_encode(), owner)?;
            assert!(!result.is_revert());

            let scheduled = registry.scheduled_features_tip()?;
            assert_eq!(scheduled.featuresTip, 13);
            assert_eq!(scheduled.activationEpoch, 21);

            Ok(())
        })?;

        assert_eq!(
            storage
                .events
                .get(&FEATURE_REGISTRY_ADDRESS)
                .map_or(0, Vec::len),
            1
        );
        Ok(())
    }

    #[test]
    fn schedule_features_tip_dispatch_requires_owner() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::repeat_byte(0x01);
        let stranger = Address::repeat_byte(0x02);
        StorageCtx::enter(&mut storage, || {
            initialize_validator_config_owner(owner)?;
            let mut registry = FeatureRegistry::new();

            let call = IFeatureRegistry::scheduleFeaturesTipCall {
                featuresTip: 13,
                activationEpoch: 21,
            };
            let result = registry.call(&call.abi_encode(), stranger)?;
            assert!(result.is_revert());
            let decoded = FeatureRegistryError::abi_decode(&result.bytes)?;
            assert_eq!(decoded, FeatureRegistryError::unauthorized());

            Ok(())
        })
    }

    #[test]
    fn schedule_features_tip_rejects_invalid_schedule() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::repeat_byte(0x01);
        StorageCtx::enter(&mut storage, || {
            initialize_validator_config_owner(owner)?;
            let mut registry = FeatureRegistry::new();
            registry.features_tip.write(7)?;

            let result = registry.schedule_features_tip(
                owner,
                IFeatureRegistry::scheduleFeaturesTipCall {
                    featuresTip: 0,
                    activationEpoch: 21,
                },
            );
            assert_eq!(
                result,
                Err(FeatureRegistryError::features_tip_not_increasing().into())
            );

            let result = registry.schedule_features_tip(
                owner,
                IFeatureRegistry::scheduleFeaturesTipCall {
                    featuresTip: 7,
                    activationEpoch: 21,
                },
            );
            assert_eq!(
                result,
                Err(FeatureRegistryError::features_tip_not_increasing().into())
            );

            let result = registry.schedule_features_tip(
                owner,
                IFeatureRegistry::scheduleFeaturesTipCall {
                    featuresTip: 13,
                    activationEpoch: 0,
                },
            );
            assert_eq!(
                result,
                Err(FeatureRegistryError::activation_epoch_not_future().into())
            );

            registry.scheduled_features_tip.write(13)?;
            registry.scheduled_activation_epoch.write(21)?;
            let result = registry.schedule_features_tip(
                owner,
                IFeatureRegistry::scheduleFeaturesTipCall {
                    featuresTip: 14,
                    activationEpoch: 22,
                },
            );
            assert_eq!(
                result,
                Err(FeatureRegistryError::features_tip_already_scheduled().into())
            );

            Ok(())
        })
    }

    #[test]
    fn schedule_features_tip_rejects_non_future_activation_epoch() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        storage.set_block_number(EPOCH_LENGTH_BLOCKS * 21);
        let owner = Address::repeat_byte(0x01);
        StorageCtx::enter(&mut storage, || {
            initialize_validator_config_owner(owner)?;
            let mut registry = FeatureRegistry::new();
            registry.features_tip.write(7)?;

            for activation_epoch in [20, 21] {
                let result = registry.schedule_features_tip(
                    owner,
                    IFeatureRegistry::scheduleFeaturesTipCall {
                        featuresTip: 13,
                        activationEpoch: activation_epoch,
                    },
                );
                assert_eq!(
                    result,
                    Err(FeatureRegistryError::activation_epoch_not_future().into())
                );
            }

            registry.schedule_features_tip(
                owner,
                IFeatureRegistry::scheduleFeaturesTipCall {
                    featuresTip: 13,
                    activationEpoch: 22,
                },
            )?;

            let scheduled = registry.scheduled_features_tip()?;
            assert_eq!(scheduled.featuresTip, 13);
            assert_eq!(scheduled.activationEpoch, 22);

            Ok(())
        })
    }

    #[test]
    fn cancel_scheduled_features_tip_dispatch_clears_schedule_from_owner() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::repeat_byte(0x01);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            initialize_validator_config_owner(owner)?;
            let mut registry = FeatureRegistry::new();
            registry.scheduled_features_tip.write(13)?;
            registry.scheduled_activation_epoch.write(21)?;

            let call = IFeatureRegistry::cancelScheduledFeaturesTipCall {};
            let result = registry.call(&call.abi_encode(), owner)?;
            assert!(!result.is_revert());

            let scheduled = registry.scheduled_features_tip()?;
            assert_eq!(scheduled.featuresTip, 0);
            assert_eq!(scheduled.activationEpoch, 0);

            Ok(())
        })?;

        assert_eq!(
            storage
                .events
                .get(&FEATURE_REGISTRY_ADDRESS)
                .map_or(0, Vec::len),
            1
        );
        Ok(())
    }

    #[test]
    fn cancel_scheduled_features_tip_dispatch_rejects_missing_schedule() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::repeat_byte(0x01);
        StorageCtx::enter(&mut storage, || {
            initialize_validator_config_owner(owner)?;
            let mut registry = FeatureRegistry::new();

            let call = IFeatureRegistry::cancelScheduledFeaturesTipCall {};
            let result = registry.call(&call.abi_encode(), owner)?;
            assert!(result.is_revert());
            let decoded = FeatureRegistryError::abi_decode(&result.bytes)?;
            assert_eq!(decoded, FeatureRegistryError::features_tip_not_scheduled());

            Ok(())
        })
    }

    #[test]
    fn owner_dispatch_returns_encoded_owner() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::repeat_byte(0x01);
        StorageCtx::enter(&mut storage, || {
            initialize_validator_config_owner(owner)?;
            let mut registry = FeatureRegistry::new();

            let call = IFeatureRegistry::ownerCall {};
            let result = registry.call(&call.abi_encode(), Address::ZERO)?;
            assert!(!result.is_revert());
            assert_eq!(Address::abi_decode(&result.bytes)?, owner);

            Ok(())
        })
    }

    #[test]
    fn activate_scheduled_features_tip_waits_for_activation_epoch() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();
            registry.features_tip.write(7)?;
            registry.scheduled_features_tip.write(13)?;
            registry.scheduled_activation_epoch.write(21)?;

            assert!(!registry.activate_scheduled_features_tip(20)?);
            assert_eq!(registry.features_tip()?, 7);

            let scheduled = registry.scheduled_features_tip()?;
            assert_eq!(scheduled.featuresTip, 13);
            assert_eq!(scheduled.activationEpoch, 21);

            Ok(())
        })
    }

    #[test]
    fn activate_scheduled_features_tip_activates_and_clears_schedule() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();
            registry.features_tip.write(7)?;
            registry.scheduled_features_tip.write(13)?;
            registry.scheduled_activation_epoch.write(21)?;

            assert!(registry.activate_scheduled_features_tip(21)?);
            assert_eq!(registry.features_tip()?, 13);

            let scheduled = registry.scheduled_features_tip()?;
            assert_eq!(scheduled.featuresTip, 0);
            assert_eq!(scheduled.activationEpoch, 0);

            Ok(())
        })
    }

    #[test]
    fn activate_scheduled_features_tip_dispatch_requires_system_caller() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();
            let call = IFeatureRegistry::activateScheduledFeaturesTipCall { currentEpoch: 21 };

            let result = registry.call(&call.abi_encode(), Address::ZERO)?;
            assert!(result.is_revert());
            let decoded = FeatureRegistryError::abi_decode(&result.bytes)?;
            assert_eq!(decoded, FeatureRegistryError::unauthorized());

            Ok(())
        })
    }

    #[test]
    fn activate_scheduled_features_tip_dispatch_allows_system_caller() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();
            registry.features_tip.write(7)?;
            registry.scheduled_features_tip.write(13)?;
            registry.scheduled_activation_epoch.write(21)?;

            let call = IFeatureRegistry::activateScheduledFeaturesTipCall { currentEpoch: 21 };
            let result = registry.call(&call.abi_encode(), SYSTEM_CALLER_ADDRESS)?;
            assert!(!result.is_revert());

            assert_eq!(registry.features_tip()?, 13);
            let scheduled = registry.scheduled_features_tip()?;
            assert_eq!(scheduled.featuresTip, 0);
            assert_eq!(scheduled.activationEpoch, 0);

            Ok(())
        })
    }

    #[test]
    fn validator_supported_features_tip_defaults_to_zero() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let registry = FeatureRegistry::new();
            let validator = Address::repeat_byte(0x01);

            assert_eq!(registry.validator_supported_features_tip(validator)?, 0);

            Ok(())
        })
    }

    #[test]
    fn validator_supported_features_tip_reads_validator_report() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();
            let validator = Address::repeat_byte(0x01);

            registry.validator_supported_features_tip[validator].write(13)?;

            assert_eq!(registry.validator_supported_features_tip(validator)?, 13);

            Ok(())
        })
    }

    #[test]
    fn set_supported_features_tip_sets_validator_report() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();
            let owner = Address::repeat_byte(0xaa);
            let validator = Address::repeat_byte(0x01);
            initialize_validator_config_owner(owner)?;
            let public_key = add_validator(owner, validator, 1)?;

            registry.set_supported_features_tip(
                Address::ZERO,
                IFeatureRegistry::setSupportedFeaturesTipCall {
                    publicKey: public_key,
                    featuresTip: 13,
                },
            )?;

            assert_eq!(registry.validator_supported_features_tip(validator)?, 13);

            Ok(())
        })
    }

    #[test]
    fn set_supported_features_tip_rejects_decreased_report() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();
            let owner = Address::repeat_byte(0xaa);
            let validator = Address::repeat_byte(0x01);
            initialize_validator_config_owner(owner)?;
            let public_key = add_validator(owner, validator, 1)?;
            registry.validator_supported_features_tip[validator].write(13)?;

            let result = registry.set_supported_features_tip(
                Address::ZERO,
                IFeatureRegistry::setSupportedFeaturesTipCall {
                    publicKey: public_key,
                    featuresTip: 12,
                },
            );
            assert_eq!(
                result,
                Err(FeatureRegistryError::supported_features_tip_decreased().into())
            );
            assert_eq!(registry.validator_supported_features_tip(validator)?, 13);

            Ok(())
        })
    }

    #[test]
    fn features_tip_dispatch_returns_encoded_cursor() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();
            registry.features_tip.write(11)?;

            let call = IFeatureRegistry::featuresTipCall {};
            let result = registry.call(&call.abi_encode(), Address::ZERO)?;
            assert!(!result.is_revert());
            assert_eq!(u64::abi_decode(&result.bytes)?, 11);

            Ok(())
        })
    }

    #[test]
    fn activation_quorum_dispatch_returns_encoded_threshold() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();

            let call = IFeatureRegistry::activationQuorumCall {};
            let result = registry.call(&call.abi_encode(), Address::ZERO)?;
            assert!(!result.is_revert());
            let decoded =
                IFeatureRegistry::activationQuorumCall::abi_decode_returns(&result.bytes)?;
            assert_eq!(decoded.numerator, U256::from(4));
            assert_eq!(decoded.denominator, U256::from(5));

            Ok(())
        })
    }

    #[test]
    fn scheduled_features_tip_dispatch_returns_encoded_schedule() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();
            registry.scheduled_features_tip.write(34)?;
            registry.scheduled_activation_epoch.write(55)?;

            let call = IFeatureRegistry::scheduledFeaturesTipCall {};
            let result = registry.call(&call.abi_encode(), Address::ZERO)?;
            assert!(!result.is_revert());
            let decoded =
                IFeatureRegistry::scheduledFeaturesTipCall::abi_decode_returns(&result.bytes)?;
            assert_eq!(decoded.featuresTip, 34);
            assert_eq!(decoded.activationEpoch, 55);

            Ok(())
        })
    }

    #[test]
    fn set_supported_features_tip_rejects_non_system_tx_sender() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();
            let validator = Address::repeat_byte(0x01);

            let result = registry.set_supported_features_tip(
                Address::repeat_byte(0x02),
                IFeatureRegistry::setSupportedFeaturesTipCall {
                    publicKey: B256::repeat_byte(0x03),
                    featuresTip: 13,
                },
            );
            assert_eq!(result, Err(FeatureRegistryError::unauthorized().into()));
            assert_eq!(registry.validator_supported_features_tip(validator)?, 0);

            Ok(())
        })
    }

    #[test]
    fn set_supported_features_tip_dispatch_sets_validator_report_from_system_tx_sender()
    -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();
            let owner = Address::repeat_byte(0xaa);
            let validator = Address::repeat_byte(0x01);
            initialize_validator_config_owner(owner)?;
            let public_key = add_validator(owner, validator, 1)?;

            let call = IFeatureRegistry::setSupportedFeaturesTipCall {
                publicKey: public_key,
                featuresTip: 34,
            };
            let result = registry.call(&call.abi_encode(), Address::ZERO)?;
            assert!(!result.is_revert());
            assert_eq!(registry.validator_supported_features_tip(validator)?, 34);

            Ok(())
        })
    }

    #[test]
    fn set_supported_features_tip_dispatch_rejects_non_system_tx_sender() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();
            let validator = Address::repeat_byte(0x01);

            let call = IFeatureRegistry::setSupportedFeaturesTipCall {
                publicKey: B256::repeat_byte(0x03),
                featuresTip: 34,
            };
            let result = registry.call(&call.abi_encode(), Address::repeat_byte(0x02))?;
            assert!(result.is_revert());
            let decoded = FeatureRegistryError::abi_decode(&result.bytes)?;
            assert_eq!(decoded, FeatureRegistryError::unauthorized());

            assert_eq!(registry.validator_supported_features_tip(validator)?, 0);

            Ok(())
        })
    }

    #[test]
    fn set_supported_features_tip_dispatch_rejects_decreased_report() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();
            let owner = Address::repeat_byte(0xaa);
            let validator = Address::repeat_byte(0x01);
            initialize_validator_config_owner(owner)?;
            let public_key = add_validator(owner, validator, 1)?;
            registry.validator_supported_features_tip[validator].write(34)?;

            let call = IFeatureRegistry::setSupportedFeaturesTipCall {
                publicKey: public_key,
                featuresTip: 33,
            };
            let result = registry.call(&call.abi_encode(), Address::ZERO)?;
            assert!(result.is_revert());
            let decoded = FeatureRegistryError::abi_decode(&result.bytes)?;
            assert_eq!(
                decoded,
                FeatureRegistryError::supported_features_tip_decreased()
            );
            assert_eq!(registry.validator_supported_features_tip(validator)?, 34);

            Ok(())
        })
    }

    #[test]
    fn validator_supported_features_tip_dispatch_returns_encoded_report() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();
            let validator = Address::repeat_byte(0x01);
            registry.validator_supported_features_tip[validator].write(34)?;

            let call = IFeatureRegistry::validatorSupportedFeaturesTipCall { validator };
            let result = registry.call(&call.abi_encode(), Address::ZERO)?;
            assert!(!result.is_revert());
            assert_eq!(u64::abi_decode(&result.bytes)?, 34);

            Ok(())
        })
    }

    #[test]
    fn unimplemented_selectors_remain_unknown() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();
            let call = IFeatureRegistry::hasFeaturesTipQuorumCall { featuresTip: 1 };
            let result = registry.call(&call.abi_encode(), Address::ZERO)?;
            assert!(result.is_revert());
            let decoded = UnknownFunctionSelector::abi_decode(&result.bytes)?;
            assert_eq!(
                decoded.selector.0,
                IFeatureRegistry::hasFeaturesTipQuorumCall::SELECTOR
            );

            Ok(())
        })
    }
}
