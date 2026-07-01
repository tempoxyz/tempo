//! ABI dispatch for the [`FeatureRegistry`] precompile.

use super::*;
use crate::{Precompile, charge_input_cost, dispatch, mutate, mutate_void, view};
use alloy::primitives::Address;
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::IFeatureRegistry;

impl Precompile for FeatureRegistry {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(
            calldata,
            |call| match call {
                IFeatureRegistry::IFeatureRegistryCalls {
                    activeFeatureHead(call) => view(call, |_| self.active_feature_head()),
                    owner(call) => view(call, |_| self.owner()),
                    activationQuorum(call) => view(call, |_| self.activation_quorum()),
                    scheduledFeatureHead(call) => {
                        view(call, |_| self.scheduled_feature_head())
                    },
                    reportFeatureReadiness(call) => {
                        mutate_void(call, msg_sender, |sender, call| {
                            self.report_feature_readiness(sender, call.ready)
                        })
                    },
                    scheduleFeatureHead(call) => {
                        mutate_void(call, msg_sender, |sender, call| {
                            self.schedule_feature_head(sender, call)
                        })
                    },
                    activateScheduledFeatureHead(call) => {
                        mutate(call, msg_sender, |sender, _| {
                            self.activate_scheduled_feature_head_from_system(sender)
                        })
                    },
                    cancelScheduledFeatureHead(call) => {
                        mutate_void(call, msg_sender, |sender, _| {
                            self.cancel_scheduled_feature_head(sender)
                        })
                    },
                    validatorConfirmedScheduledFeatureReadiness(call) => view(call, |call| {
                        self.validator_confirmed_scheduled_feature_readiness(call.publicKey)
                    }),
                    scheduledFeatureSupport(call) => {
                        view(call, |_| self.scheduled_feature_support())
                    },
                    hasScheduledFeatureQuorum(call) => {
                        view(call, |_| self.has_scheduled_feature_quorum())
                    }
                }
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        FEATURE_REGISTRY_ADDRESS,
        current_committee::CurrentCommittee,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        validator_config_v2::{VALIDATOR_NS_ADD, ValidatorConfigV2},
    };
    use alloy::{
        primitives::{B256, Keccak256, U256},
        sol_types::{SolCall, SolInterface, SolValue},
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{Signer, ed25519::PrivateKey};
    use std::num::NonZeroU64;
    use tempo_chainspec::features::Feature;
    use tempo_contracts::precompiles::{
        FeatureRegistryError, ICurrentCommittee, IValidatorConfigV2, VALIDATOR_CONFIG_V2_ADDRESS,
    };
    use tempo_primitives::ed25519::PublicKey as TempoPublicKey;

    const FEATURE_HEAD: B256 = B256::with_last_byte(0x01);
    const NEXT_FEATURE_HEAD: B256 = B256::with_last_byte(0x02);

    fn initialize_validator_config_owner(owner: Address) -> eyre::Result<()> {
        ValidatorConfigV2::new().initialize(owner)?;
        Ok(())
    }

    fn add_test_validator(owner: Address, validator: Address, seed: u64) -> eyre::Result<B256> {
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

    fn set_proposer_public_key(registry: &mut FeatureRegistry, public_key: B256) {
        registry.storage.set_proposer_public_key(Some(
            TempoPublicKey::try_from(public_key).expect("test public key is valid"),
        ));
    }

    fn set_current_committee(public_keys: Vec<B256>) -> eyre::Result<()> {
        CurrentCommittee::new().set_committee_members(
            Address::ZERO,
            ICurrentCommittee::setCommitteeMembersCall {
                publicKeys: public_keys,
            },
        )?;
        Ok(())
    }

    fn set_scheduled_feature(
        registry: &mut FeatureRegistry,
        feature_head: B256,
        activation_epoch: u64,
        schedule_nonce: u64,
    ) -> eyre::Result<()> {
        registry.scheduled_feature_head.write(feature_head)?;
        registry
            .scheduled_activation_epoch
            .write(activation_epoch)?;
        registry.schedule_nonce.write(schedule_nonce)?;
        Ok(())
    }

    #[test]
    fn active_feature_head_defaults_to_zero() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let registry = FeatureRegistry::new();
            assert_eq!(registry.active_feature_head()?, B256::ZERO);
            Ok(())
        })
    }

    #[test]
    fn active_feature_head_reads_slot_zero() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut registry = FeatureRegistry::new();
            assert_eq!(registry.active_feature_head.slot(), U256::ZERO);

            registry.active_feature_head.write(FEATURE_HEAD)?;
            assert_eq!(registry.active_feature_head()?, FEATURE_HEAD);

            Ok(())
        })
    }

    #[test]
    fn owner_and_activation_quorum_are_readable() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::repeat_byte(0x01);
        StorageCtx::enter(&mut storage, || {
            initialize_validator_config_owner(owner)?;
            let registry = FeatureRegistry::new();
            assert_eq!(registry.owner()?, owner);

            let quorum = registry.activation_quorum()?;
            assert_eq!(quorum.numerator, U256::from(4));
            assert_eq!(quorum.denominator, U256::from(5));
            Ok(())
        })
    }

    #[test]
    fn scheduled_feature_head_defaults_to_zero() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let scheduled = FeatureRegistry::new().scheduled_feature_head()?;
            assert_eq!(scheduled.featureHead, B256::ZERO);
            assert_eq!(scheduled.activationEpoch, 0);
            Ok(())
        })
    }

    #[test]
    fn schedule_feature_head_dispatch_sets_schedule_from_owner() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::repeat_byte(0x01);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            initialize_validator_config_owner(owner)?;
            let mut registry = FeatureRegistry::new();

            let call = IFeatureRegistry::scheduleFeatureHeadCall {
                featureHead: FEATURE_HEAD,
                activationEpoch: 21,
            };
            let result = registry.call(&call.abi_encode(), owner)?;
            assert!(!result.is_revert());

            let scheduled = registry.scheduled_feature_head()?;
            assert_eq!(scheduled.featureHead, FEATURE_HEAD);
            assert_eq!(scheduled.activationEpoch, 21);
            assert_eq!(registry.schedule_nonce.read()?, 1);

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
    fn schedule_feature_head_rejects_invalid_schedule() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::repeat_byte(0x01);
        StorageCtx::enter(&mut storage, || {
            initialize_validator_config_owner(owner)?;
            let mut registry = FeatureRegistry::new();
            registry.active_feature_head.write(FEATURE_HEAD)?;

            let result = registry.schedule_feature_head(
                owner,
                IFeatureRegistry::scheduleFeatureHeadCall {
                    featureHead: B256::ZERO,
                    activationEpoch: 21,
                },
            );
            assert_eq!(
                result,
                Err(FeatureRegistryError::invalid_feature_head().into())
            );

            let result = registry.schedule_feature_head(
                owner,
                IFeatureRegistry::scheduleFeatureHeadCall {
                    featureHead: FEATURE_HEAD,
                    activationEpoch: 21,
                },
            );
            assert_eq!(
                result,
                Err(FeatureRegistryError::feature_head_already_active().into())
            );

            let result = registry.schedule_feature_head(
                Address::repeat_byte(0x02),
                IFeatureRegistry::scheduleFeatureHeadCall {
                    featureHead: NEXT_FEATURE_HEAD,
                    activationEpoch: 21,
                },
            );
            assert_eq!(result, Err(FeatureRegistryError::unauthorized().into()));

            set_scheduled_feature(&mut registry, NEXT_FEATURE_HEAD, 21, 1)?;
            let result = registry.schedule_feature_head(
                owner,
                IFeatureRegistry::scheduleFeatureHeadCall {
                    featureHead: B256::repeat_byte(0x03),
                    activationEpoch: 22,
                },
            );
            assert_eq!(
                result,
                Err(FeatureRegistryError::feature_head_already_scheduled().into())
            );

            Ok(())
        })
    }

    #[test]
    fn schedule_feature_head_rejects_known_downgrade() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::repeat_byte(0x01);
        let feature_head = Feature::Tip1063FeatureRegistry.digest();
        StorageCtx::enter(&mut storage, || {
            initialize_validator_config_owner(owner)?;
            let mut registry = FeatureRegistry::new();
            registry.active_feature_head.write(feature_head)?;

            let result = registry.schedule_feature_head(
                owner,
                IFeatureRegistry::scheduleFeatureHeadCall {
                    featureHead: feature_head,
                    activationEpoch: 21,
                },
            );
            assert_eq!(
                result,
                Err(FeatureRegistryError::feature_head_already_active().into())
            );

            Ok(())
        })
    }

    #[test]
    fn schedule_feature_head_rejects_non_future_activation_epoch() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        storage.set_epoch_length(NonZeroU64::new(10).expect("non-zero epoch length"));
        storage.set_block_number(10 * 21);
        let owner = Address::repeat_byte(0x01);
        StorageCtx::enter(&mut storage, || {
            initialize_validator_config_owner(owner)?;
            let mut registry = FeatureRegistry::new();

            for activation_epoch in [20, 21] {
                let result = registry.schedule_feature_head(
                    owner,
                    IFeatureRegistry::scheduleFeatureHeadCall {
                        featureHead: FEATURE_HEAD,
                        activationEpoch: activation_epoch,
                    },
                );
                assert_eq!(
                    result,
                    Err(FeatureRegistryError::activation_epoch_not_future().into())
                );
            }

            registry.schedule_feature_head(
                owner,
                IFeatureRegistry::scheduleFeatureHeadCall {
                    featureHead: FEATURE_HEAD,
                    activationEpoch: 22,
                },
            )?;

            let scheduled = registry.scheduled_feature_head()?;
            assert_eq!(scheduled.featureHead, FEATURE_HEAD);
            assert_eq!(scheduled.activationEpoch, 22);
            assert_eq!(registry.schedule_nonce.read()?, 1);

            Ok(())
        })
    }

    #[test]
    fn cancel_scheduled_feature_head_clears_schedule_from_owner() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::repeat_byte(0x01);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            initialize_validator_config_owner(owner)?;
            let mut registry = FeatureRegistry::new();
            set_scheduled_feature(&mut registry, FEATURE_HEAD, 21, 3)?;

            let call = IFeatureRegistry::cancelScheduledFeatureHeadCall {};
            let result = registry.call(&call.abi_encode(), owner)?;
            assert!(!result.is_revert());

            let scheduled = registry.scheduled_feature_head()?;
            assert_eq!(scheduled.featureHead, B256::ZERO);
            assert_eq!(scheduled.activationEpoch, 0);
            assert_eq!(registry.schedule_nonce.read()?, 3);

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
    fn cancel_scheduled_feature_head_rejects_missing_schedule() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::repeat_byte(0x01);
        StorageCtx::enter(&mut storage, || {
            initialize_validator_config_owner(owner)?;
            let mut registry = FeatureRegistry::new();

            let call = IFeatureRegistry::cancelScheduledFeatureHeadCall {};
            let result = registry.call(&call.abi_encode(), owner)?;
            assert!(result.is_revert());
            let decoded = FeatureRegistryError::abi_decode(&result.bytes)?;
            assert_eq!(decoded, FeatureRegistryError::feature_head_not_scheduled());

            Ok(())
        })
    }

    #[test]
    fn report_feature_readiness_stores_latest_schedule_nonce() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::repeat_byte(0xaa);
        let validator = Address::repeat_byte(0x01);
        StorageCtx::enter(&mut storage, || {
            initialize_validator_config_owner(owner)?;
            let public_key = add_test_validator(owner, validator, 1)?;
            let mut registry = FeatureRegistry::new();
            set_scheduled_feature(&mut registry, FEATURE_HEAD, 21, 1)?;
            set_proposer_public_key(&mut registry, public_key);

            registry.report_feature_readiness(Address::ZERO, true)?;

            assert!(registry.validator_confirmed_scheduled_feature_readiness(public_key)?);

            set_scheduled_feature(&mut registry, NEXT_FEATURE_HEAD, 21, 2)?;
            assert!(!registry.validator_confirmed_scheduled_feature_readiness(public_key)?);
            registry.report_feature_readiness(Address::ZERO, true)?;

            assert!(registry.validator_confirmed_scheduled_feature_readiness(public_key)?);

            Ok(())
        })
    }

    #[test]
    fn report_feature_readiness_can_cancel_current_scheduled_head() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::repeat_byte(0xaa);
        let validator = Address::repeat_byte(0x01);
        StorageCtx::enter(&mut storage, || {
            initialize_validator_config_owner(owner)?;
            let public_key = add_test_validator(owner, validator, 1)?;
            let mut registry = FeatureRegistry::new();
            set_scheduled_feature(&mut registry, FEATURE_HEAD, 21, 1)?;
            set_proposer_public_key(&mut registry, public_key);

            registry.report_feature_readiness(Address::ZERO, true)?;
            assert!(registry.validator_confirmed_scheduled_feature_readiness(public_key)?);

            registry.report_feature_readiness(Address::ZERO, false)?;
            assert!(!registry.validator_confirmed_scheduled_feature_readiness(public_key)?);

            registry.validator_confirmed_schedule_nonce[public_key].write(2)?;
            registry.report_feature_readiness(Address::ZERO, false)?;
            assert_eq!(
                registry.validator_confirmed_schedule_nonce[public_key].read()?,
                2
            );

            Ok(())
        })
    }

    #[test]
    fn report_feature_readiness_rejects_non_system_or_missing_schedule() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();

            let result = registry.report_feature_readiness(Address::repeat_byte(0x02), true);
            assert_eq!(result, Err(FeatureRegistryError::unauthorized().into()));

            let result = registry.report_feature_readiness(Address::ZERO, true);
            assert_eq!(
                result,
                Err(FeatureRegistryError::feature_head_not_scheduled().into())
            );

            Ok(())
        })
    }

    #[test]
    fn report_feature_readiness_rejects_missing_proposer_public_key() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();
            set_scheduled_feature(&mut registry, FEATURE_HEAD, 21, 1)?;

            let result = registry.report_feature_readiness(Address::ZERO, true);
            assert_eq!(
                result,
                Err(FeatureRegistryError::proposer_public_key_unavailable().into())
            );

            Ok(())
        })
    }

    #[test]
    fn report_feature_readiness_dispatch_allows_system_caller() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::repeat_byte(0xaa);
        let validator = Address::repeat_byte(0x01);
        StorageCtx::enter(&mut storage, || {
            initialize_validator_config_owner(owner)?;
            let public_key = add_test_validator(owner, validator, 1)?;
            let mut registry = FeatureRegistry::new();
            set_scheduled_feature(&mut registry, FEATURE_HEAD, 21, 1)?;
            set_proposer_public_key(&mut registry, public_key);

            let call = IFeatureRegistry::reportFeatureReadinessCall { ready: true };
            let result = registry.call(&call.abi_encode(), Address::ZERO)?;
            assert!(!result.is_revert());
            assert!(registry.validator_confirmed_scheduled_feature_readiness(public_key)?);

            Ok(())
        })
    }

    #[test]
    fn report_feature_readiness_dispatch_allows_block_number_suffix() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::repeat_byte(0xaa);
        let validator = Address::repeat_byte(0x01);
        StorageCtx::enter(&mut storage, || {
            initialize_validator_config_owner(owner)?;
            let public_key = add_test_validator(owner, validator, 1)?;
            let mut registry = FeatureRegistry::new();
            set_scheduled_feature(&mut registry, FEATURE_HEAD, 21, 1)?;
            set_proposer_public_key(&mut registry, public_key);

            let mut input =
                IFeatureRegistry::reportFeatureReadinessCall { ready: true }.abi_encode();
            input.extend_from_slice(&U256::from(1u64).to_be_bytes::<32>());

            let result = registry.call(&input, Address::ZERO)?;
            assert!(!result.is_revert());
            assert!(registry.validator_confirmed_scheduled_feature_readiness(public_key)?);

            Ok(())
        })
    }

    #[test]
    fn scheduled_feature_support_counts_current_committee_readiness() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::repeat_byte(0xaa);
        StorageCtx::enter(&mut storage, || {
            initialize_validator_config_owner(owner)?;
            let mut registry = FeatureRegistry::new();
            set_scheduled_feature(&mut registry, FEATURE_HEAD, 21, 1)?;

            let mut validators = Vec::new();
            for seed in 1..=5 {
                let validator = Address::repeat_byte(seed as u8);
                let public_key = add_test_validator(owner, validator, seed)?;
                validators.push((validator, public_key));
            }
            set_current_committee(
                validators
                    .iter()
                    .map(|(_, public_key)| *public_key)
                    .collect(),
            )?;

            for (_, public_key) in validators.iter().take(3) {
                set_proposer_public_key(&mut registry, *public_key);
                registry.report_feature_readiness(Address::ZERO, true)?;
            }

            let support = registry.scheduled_feature_support()?;
            assert_eq!(support.support, U256::from(3));
            assert_eq!(support.required, U256::from(4));
            assert!(!registry.has_scheduled_feature_quorum()?);

            set_proposer_public_key(&mut registry, validators[3].1);
            registry.report_feature_readiness(Address::ZERO, true)?;
            assert!(registry.has_scheduled_feature_quorum()?);

            Ok(())
        })
    }

    #[test]
    fn rescheduled_feature_head_does_not_reuse_stale_readiness() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::repeat_byte(0xaa);
        let validator = Address::repeat_byte(0x01);
        StorageCtx::enter(&mut storage, || {
            initialize_validator_config_owner(owner)?;
            let public_key = add_test_validator(owner, validator, 1)?;
            set_current_committee(vec![public_key])?;
            let mut registry = FeatureRegistry::new();

            registry.schedule_feature_head(
                owner,
                IFeatureRegistry::scheduleFeatureHeadCall {
                    featureHead: FEATURE_HEAD,
                    activationEpoch: 21,
                },
            )?;
            set_proposer_public_key(&mut registry, public_key);
            registry.report_feature_readiness(Address::ZERO, true)?;
            assert!(registry.has_scheduled_feature_quorum()?);

            registry.cancel_scheduled_feature_head(owner)?;
            registry.schedule_feature_head(
                owner,
                IFeatureRegistry::scheduleFeatureHeadCall {
                    featureHead: FEATURE_HEAD,
                    activationEpoch: 21,
                },
            )?;

            assert_eq!(registry.schedule_nonce.read()?, 2);
            assert!(!registry.validator_confirmed_scheduled_feature_readiness(public_key)?);
            let support = registry.scheduled_feature_support()?;
            assert_eq!(support.support, U256::ZERO);
            assert_eq!(support.required, U256::from(1));
            assert!(!registry.has_scheduled_feature_quorum()?);

            Ok(())
        })
    }

    #[test]
    fn readiness_does_not_follow_reused_validator_address() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_block_number(1);
        let owner = Address::repeat_byte(0xaa);
        let validator = Address::repeat_byte(0x01);
        StorageCtx::enter(&mut storage, || {
            initialize_validator_config_owner(owner)?;
            let old_public_key = add_test_validator(owner, validator, 1)?;
            let mut registry = FeatureRegistry::new();
            set_scheduled_feature(&mut registry, FEATURE_HEAD, 21, 1)?;
            set_proposer_public_key(&mut registry, old_public_key);
            registry.report_feature_readiness(Address::ZERO, true)?;

            ValidatorConfigV2::new().deactivate_validator(
                owner,
                IValidatorConfigV2::deactivateValidatorCall { idx: 0 },
            )?;
            let new_public_key = add_test_validator(owner, validator, 2)?;
            set_current_committee(vec![new_public_key])?;

            assert_eq!(
                registry.validator_confirmed_schedule_nonce[old_public_key].read()?,
                1
            );
            assert_eq!(
                registry.validator_confirmed_schedule_nonce[new_public_key].read()?,
                0
            );

            let support = registry.scheduled_feature_support()?;
            assert_eq!(support.support, U256::ZERO);
            assert_eq!(support.required, U256::from(1));
            assert!(!registry.has_scheduled_feature_quorum()?);

            Ok(())
        })
    }

    #[test]
    fn deactivated_current_committee_key_can_still_report_readiness() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_block_number(1);
        let owner = Address::repeat_byte(0xaa);
        let validator = Address::repeat_byte(0x01);
        StorageCtx::enter(&mut storage, || {
            initialize_validator_config_owner(owner)?;
            let public_key = add_test_validator(owner, validator, 1)?;
            ValidatorConfigV2::new().deactivate_validator(
                owner,
                IValidatorConfigV2::deactivateValidatorCall { idx: 0 },
            )?;
            set_current_committee(vec![public_key])?;

            let mut registry = FeatureRegistry::new();
            set_scheduled_feature(&mut registry, FEATURE_HEAD, 21, 1)?;
            set_proposer_public_key(&mut registry, public_key);
            registry.report_feature_readiness(Address::ZERO, true)?;

            let support = registry.scheduled_feature_support()?;
            assert_eq!(support.support, U256::from(1));
            assert_eq!(support.required, U256::from(1));
            assert!(registry.has_scheduled_feature_quorum()?);

            Ok(())
        })
    }

    #[test]
    fn activate_scheduled_feature_head_waits_for_epoch_before_activation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_block_number(20);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();
            set_scheduled_feature(&mut registry, FEATURE_HEAD, 22, 1)?;

            assert_eq!(registry.activate_scheduled_feature_head()?, None);
            assert_eq!(registry.active_feature_head()?, B256::ZERO);

            let scheduled = registry.scheduled_feature_head()?;
            assert_eq!(scheduled.featureHead, FEATURE_HEAD);
            assert_eq!(scheduled.activationEpoch, 22);

            Ok(())
        })
    }

    #[test]
    fn activate_scheduled_feature_head_requires_quorum_and_clears_schedule() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_block_number(20);
        let owner = Address::repeat_byte(0xaa);
        StorageCtx::enter(&mut storage, || {
            initialize_validator_config_owner(owner)?;
            let public_key = add_test_validator(owner, Address::repeat_byte(0x01), 1)?;
            set_current_committee(vec![public_key])?;
            let mut registry = FeatureRegistry::new();
            set_scheduled_feature(&mut registry, FEATURE_HEAD, 21, 1)?;

            assert_eq!(registry.activate_scheduled_feature_head()?, None);
            assert_eq!(registry.active_feature_head()?, B256::ZERO);

            let scheduled = registry.scheduled_feature_head()?;
            assert_eq!(scheduled.featureHead, B256::ZERO);
            assert_eq!(scheduled.activationEpoch, 0);

            Ok(())
        })
    }

    #[test]
    fn activate_scheduled_feature_head_activates_with_quorum() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_block_number(20);
        let owner = Address::repeat_byte(0xaa);
        let validator = Address::repeat_byte(0x01);
        StorageCtx::enter(&mut storage, || {
            initialize_validator_config_owner(owner)?;
            let public_key = add_test_validator(owner, validator, 1)?;
            set_current_committee(vec![public_key])?;
            let mut registry = FeatureRegistry::new();
            set_scheduled_feature(&mut registry, FEATURE_HEAD, 21, 1)?;
            set_proposer_public_key(&mut registry, public_key);
            registry.report_feature_readiness(Address::ZERO, true)?;

            assert_eq!(
                registry.activate_scheduled_feature_head()?,
                Some(FEATURE_HEAD)
            );
            assert_eq!(registry.active_feature_head()?, FEATURE_HEAD);

            let scheduled = registry.scheduled_feature_head()?;
            assert_eq!(scheduled.featureHead, B256::ZERO);
            assert_eq!(scheduled.activationEpoch, 0);

            Ok(())
        })
    }

    #[test]
    fn feature_activation_dispatch_requires_system_caller() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();
            let call = IFeatureRegistry::activateScheduledFeatureHeadCall {};

            let result = registry.call(&call.abi_encode(), Address::repeat_byte(0x01))?;
            assert!(result.is_revert());
            let decoded = FeatureRegistryError::abi_decode(&result.bytes)?;
            assert_eq!(decoded, FeatureRegistryError::unauthorized());

            let result = registry.call(&call.abi_encode(), Address::ZERO)?;
            assert!(!result.is_revert());
            assert_eq!(
                IFeatureRegistry::activateScheduledFeatureHeadCall::abi_decode_returns(
                    &result.bytes
                )?,
                B256::ZERO
            );

            Ok(())
        })
    }

    #[test]
    fn view_dispatch_returns_encoded_values() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();
            registry.active_feature_head.write(FEATURE_HEAD)?;
            set_scheduled_feature(&mut registry, NEXT_FEATURE_HEAD, 55, 7)?;

            let result = registry.call(
                &IFeatureRegistry::activeFeatureHeadCall {}.abi_encode(),
                Address::ZERO,
            )?;
            assert!(!result.is_revert());
            assert_eq!(B256::abi_decode(&result.bytes)?, FEATURE_HEAD);

            let result = registry.call(
                &IFeatureRegistry::scheduledFeatureHeadCall {}.abi_encode(),
                Address::ZERO,
            )?;
            assert!(!result.is_revert());
            let decoded =
                IFeatureRegistry::scheduledFeatureHeadCall::abi_decode_returns(&result.bytes)?;
            assert_eq!(decoded.featureHead, NEXT_FEATURE_HEAD);
            assert_eq!(decoded.activationEpoch, 55);

            Ok(())
        })
    }

    #[test]
    fn scheduled_readiness_dispatch_returns_encoded_readiness() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let public_key = B256::repeat_byte(0x01);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();
            set_scheduled_feature(&mut registry, FEATURE_HEAD, 21, 1)?;
            registry.validator_confirmed_schedule_nonce[public_key].write(1)?;

            let call = IFeatureRegistry::validatorConfirmedScheduledFeatureReadinessCall {
                publicKey: public_key,
            };
            let result = registry.call(&call.abi_encode(), Address::ZERO)?;
            assert!(!result.is_revert());
            assert!(bool::abi_decode(&result.bytes)?);

            Ok(())
        })
    }
}
