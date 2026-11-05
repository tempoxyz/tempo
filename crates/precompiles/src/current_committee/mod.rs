//! Current committee precompile for TIP-1070, with the DKG ceremony of TIP-1123.

pub mod dispatch;

use commonware_codec::DecodeExt as _;
use commonware_cryptography::ed25519::PublicKey;
use tempo_contracts::precompiles::CurrentCommitteeError;
pub use tempo_contracts::precompiles::{CURRENT_COMMITTEE_ADDRESS, ICurrentCommittee};
use tempo_precompiles_macros::contract;

use crate::{
    error::{Result, TempoPrecompileError},
    storage::Handler,
    validator_config_v2::ValidatorConfigV2,
};
use alloy::primitives::{Address, B256};

/// The most keys either array holds: the limit of the DKG `Output` decoder.
const MAX_KEYS: usize = u16::MAX as usize;

#[contract(addr = CURRENT_COMMITTEE_ADDRESS)]
pub struct CurrentCommittee {
    epoch: u64,
    ids: Vec<B256>,
    /// Players of the ceremony running during `epoch`, strictly ascending. Empty until the first
    /// TIP-1123 boundary block.
    dkg_players: Vec<B256>,
    /// Whether the ceremony running during `epoch` is a full DKG that rotates the network
    /// identity, instead of a reshare.
    is_rotating_network_identity: bool,
}

impl CurrentCommittee {
    pub fn get_committee_members(&self) -> Result<ICurrentCommittee::getCommitteeMembersReturn> {
        Ok(ICurrentCommittee::getCommitteeMembersReturn {
            epoch: self.epoch.read()?,
            publicKeys: self.ids.read()?,
        })
    }

    /// Returns the DKG ceremony running during the stored epoch, with the committee as its
    /// dealers.
    ///
    /// Reverts with `Uninitialized` until the first TIP-1123 boundary block wrote the ceremony.
    pub fn get_dkg_ceremony(&self) -> Result<ICurrentCommittee::getDkgCeremonyReturn> {
        let players = self.dkg_players.read()?;
        if players.is_empty() {
            return Err(CurrentCommitteeError::uninitialized().into());
        }
        Ok(ICurrentCommittee::getDkgCeremonyReturn {
            epoch: self.epoch.read()?,
            dealers: self.ids.read()?,
            players,
            isRotatingNetworkIdentity: self.is_rotating_network_identity.read()?,
        })
    }

    /// Stores the next epoch's committee.
    ///
    /// Correctness assumes this system-only entrypoint is invoked only while
    /// processing the last block of an epoch.
    pub fn set_committee_members(
        &mut self,
        msg_sender: Address,
        call: ICurrentCommittee::setCommitteeMembersCall,
    ) -> Result<()> {
        if !msg_sender.is_zero() {
            return Err(CurrentCommitteeError::unauthorized().into());
        }

        // System writes are free and must not mint or consume TIP-1060 storage credits.
        self.storage.set_tip1060_storage_credits(false);
        self.epoch.write(call.epoch)?;
        self.ids.write(call.publicKeys)?;
        Ok(())
    }

    /// Snapshots the players and mode of the DKG ceremony running during `epoch` from the active
    /// validators of [`ValidatorConfigV2`] (TIP-1123).
    ///
    /// The block executor calls this at the end of each TIP-1123 boundary block, after its
    /// transactions and outside any call; no ABI entrypoint reaches it. `epoch` is the epoch of
    /// the boundary block's DKG outcome. An error means the boundary block is invalid.
    pub fn snapshot_dkg_ceremony(&mut self, epoch: u64) -> Result<()> {
        let config = ValidatorConfigV2::new();
        let mut players = config
            .get_active_validators()?
            .into_iter()
            .map(|validator| {
                PublicKey::decode(commonware_codec::Copying(validator.publicKey.as_slice()))
                    .map_err(|_| {
                        TempoPrecompileError::Fatal(format!(
                            "active validator key {} is not a valid Ed25519 public key",
                            validator.publicKey
                        ))
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        if players.is_empty() || players.len() > MAX_KEYS {
            return Err(TempoPrecompileError::Fatal(format!(
                "{} active validators cannot play a DKG ceremony; expected 1 to {MAX_KEYS}",
                players.len()
            )));
        }
        // Commonware orders a ceremony's players by their public keys.
        players.sort_unstable();
        if let Some(pair) = players.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(TempoPrecompileError::Fatal(format!(
                "active validators share the public key {}",
                pair[0]
            )));
        }
        let is_rotating_network_identity =
            config.get_next_network_identity_rotation_epoch()? == epoch;

        // System writes are free and must not mint or consume TIP-1060 storage credits.
        self.storage.set_tip1060_storage_credits(false);
        self.dkg_players.write(
            players
                .iter()
                .map(|key| B256::from_slice(key.as_ref()))
                .collect(),
        )?;
        self.is_rotating_network_identity
            .write(is_rotating_network_identity)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        storage_credits::StorageCredits,
        validator_config_v2::{IValidatorConfigV2, VALIDATOR_NS_ADD},
    };
    use alloy::primitives::{Keccak256, U256};
    use commonware_codec::Encode as _;
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::VALIDATOR_CONFIG_V2_ADDRESS;

    const OWNER: Address = Address::repeat_byte(0xAA);

    /// Initializes [`ValidatorConfigV2`] with a validator for each seed and returns their keys.
    fn add_validators(seeds: impl IntoIterator<Item = u8>) -> Result<Vec<B256>> {
        let mut config = ValidatorConfigV2::new();
        config.initialize(OWNER)?;
        let mut keys = Vec::new();
        for seed in seeds {
            let private_key = PrivateKey::from_seed(seed.into());
            let public_key = B256::from_slice(&private_key.public_key());
            let validator_address = Address::repeat_byte(seed);
            let ingress = format!("10.0.0.{seed}:8000");
            let egress = format!("10.0.0.{seed}");
            let mut hasher = Keccak256::new();
            hasher.update(1u64.to_be_bytes());
            hasher.update(VALIDATOR_CONFIG_V2_ADDRESS.as_slice());
            hasher.update(validator_address.as_slice());
            hasher.update([u8::try_from(ingress.len()).unwrap()]);
            hasher.update(ingress.as_bytes());
            hasher.update([u8::try_from(egress.len()).unwrap()]);
            hasher.update(egress.as_bytes());
            hasher.update(validator_address.as_slice());
            let signature = private_key.sign(VALIDATOR_NS_ADD, hasher.finalize().as_slice());
            config.add_validator(
                OWNER,
                IValidatorConfigV2::addValidatorCall {
                    validatorAddress: validator_address,
                    publicKey: public_key,
                    ingress,
                    egress,
                    feeRecipient: validator_address,
                    signature: signature.encode().to_vec().into(),
                },
            )?;
            keys.push(public_key);
        }
        Ok(keys)
    }

    fn sorted(mut keys: Vec<B256>) -> Vec<B256> {
        keys.sort_unstable();
        keys
    }

    #[test]
    fn test_storage_layout_matches_tip_1123() {
        assert_eq!(slots::EPOCH, U256::from(0));
        assert_eq!(slots::IDS, U256::from(1));
        assert_eq!(slots::DKG_PLAYERS, U256::from(2));
        assert_eq!(slots::IS_ROTATING_NETWORK_IDENTITY, U256::from(3));
        assert_eq!(slots::IS_ROTATING_NETWORK_IDENTITY_OFFSET, 0);
    }

    #[test]
    fn test_get_dkg_ceremony_reverts_until_snapshot() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
        StorageCtx::enter(&mut storage, || {
            let mut committee = CurrentCommittee::new();
            // A TIP-1070 committee alone does not initialize the ceremony.
            committee.set_committee_members(
                Address::ZERO,
                ICurrentCommittee::setCommitteeMembersCall {
                    epoch: 1,
                    publicKeys: vec![B256::repeat_byte(0x11)],
                },
            )?;
            assert_eq!(
                committee.get_dkg_ceremony().unwrap_err(),
                CurrentCommitteeError::uninitialized().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_snapshot_dkg_ceremony_sorts_active_validators_and_sets_mode() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
        storage.set_block_number(1);
        StorageCtx::enter(&mut storage, || {
            let keys = add_validators([3, 1, 2])?;
            ValidatorConfigV2::new().set_network_identity_rotation_epoch(
                OWNER,
                IValidatorConfigV2::setNetworkIdentityRotationEpochCall { epoch: 7 },
            )?;
            let dealers = vec![B256::repeat_byte(0x11), B256::repeat_byte(0x22)];

            let mut committee = CurrentCommittee::new();
            committee.set_committee_members(
                Address::ZERO,
                ICurrentCommittee::setCommitteeMembersCall {
                    epoch: 7,
                    publicKeys: dealers.clone(),
                },
            )?;
            committee.snapshot_dkg_ceremony(7)?;

            assert_eq!(
                committee.get_dkg_ceremony()?,
                ICurrentCommittee::getDkgCeremonyReturn {
                    epoch: 7,
                    dealers,
                    players: sorted(keys),
                    isRotatingNetworkIdentity: true,
                }
            );

            // A rotation scheduled for any other epoch selects a reshare.
            committee.snapshot_dkg_ceremony(8)?;
            assert!(!committee.get_dkg_ceremony()?.isRotatingNetworkIdentity);
            Ok(())
        })
    }

    #[test]
    fn test_snapshot_dkg_ceremony_zeroes_dropped_players() -> eyre::Result<()> {
        // Three players snapshotted for epoch 1.
        let snapshotted = || -> Result<(HashMapStorageProvider, Vec<B256>)> {
            let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
            storage.set_block_number(1);
            let keys = StorageCtx::enter(&mut storage, || -> Result<_> {
                let keys = add_validators([1, 2, 3])?;
                CurrentCommittee::new().snapshot_dkg_ceremony(1)?;
                Ok(keys)
            })?;
            Ok((storage, keys))
        };
        let used_slots = |storage: HashMapStorageProvider| {
            storage
                .into_storage()
                .filter(|(address, _, value)| {
                    *address == CURRENT_COMMITTEE_ADDRESS && !value.is_zero()
                })
                .count()
        };
        let before = used_slots(snapshotted()?.0);

        let (mut storage, keys) = snapshotted()?;
        StorageCtx::enter(&mut storage, || -> Result<()> {
            let mut config = ValidatorConfigV2::new();
            for _ in 0..2 {
                let first_active = config.get_active_validators()?[0].index;
                config.deactivate_validator(
                    OWNER,
                    IValidatorConfigV2::deactivateValidatorCall { idx: first_active },
                )?;
            }
            let remaining = config.get_active_validators()?[0].publicKey;
            assert!(keys.contains(&remaining));

            let mut committee = CurrentCommittee::new();
            committee.snapshot_dkg_ceremony(2)?;
            assert_eq!(committee.get_dkg_ceremony()?.players, vec![remaining]);
            Ok(())
        })?;

        // Two fewer player slots hold a value: the dropped elements were zeroed.
        assert_eq!(used_slots(storage), before - 2);
        Ok(())
    }

    #[test]
    fn test_snapshot_dkg_ceremony_rejects_empty_registry() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
        StorageCtx::enter(&mut storage, || {
            let mut committee = CurrentCommittee::new();
            // Uninitialized registry.
            assert!(matches!(
                committee.snapshot_dkg_ceremony(1),
                Err(TempoPrecompileError::Fatal(_))
            ));
            // Initialized registry without active validators.
            ValidatorConfigV2::new().initialize(OWNER)?;
            assert!(matches!(
                committee.snapshot_dkg_ceremony(1),
                Err(TempoPrecompileError::Fatal(_))
            ));
            assert_eq!(
                committee.get_dkg_ceremony().unwrap_err(),
                CurrentCommitteeError::uninitialized().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_snapshot_dkg_ceremony_does_not_mint_storage_credits() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
        storage.set_block_number(1);
        StorageCtx::enter(&mut storage, || {
            add_validators([1, 2])?;
            let mut committee = CurrentCommittee::new();
            committee.snapshot_dkg_ceremony(1)?;
            ValidatorConfigV2::new().deactivate_validator(
                OWNER,
                IValidatorConfigV2::deactivateValidatorCall { idx: 0 },
            )?;
            committee.snapshot_dkg_ceremony(2)?;

            assert_eq!(
                StorageCredits::new().balance_of(CURRENT_COMMITTEE_ADDRESS)?,
                0
            );
            Ok(())
        })
    }
}
