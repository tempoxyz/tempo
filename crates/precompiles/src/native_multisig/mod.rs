//! Native multisig account precompile.

pub mod dispatch;

pub use tempo_contracts::precompiles::INativeMultisig;
use tempo_contracts::precompiles::{
    NATIVE_MULTISIG_ADDRESS, NativeMultisigError, NativeMultisigEvent,
};
use tempo_precompiles_macros::{Storable, contract};
use tempo_primitives::transaction::{
    InitMultisig, MAX_MULTISIG_OWNERS, MultisigOwner, is_valid_multisig_account,
    validate_multisig_config,
};

use crate::{
    error::Result,
    storage::{Handler, Mapping},
};
use alloy::primitives::{Address, B256, U256};

#[derive(Debug, Clone, Default, PartialEq, Eq, Storable)]
struct StoredMultisigOwner {
    owner: Address,
    // One-byte weights leave spare bytes in this packed owner slot for future
    // owner metadata.
    weight: u8,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Storable)]
struct StoredMultisigHeader {
    // One-byte thresholds leave spare bytes in the packed account header slot
    // for future account metadata.
    threshold: u8,
    // One byte supports 1 through 255 owners while preserving 0 as the empty marker.
    owner_count: u8,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct StoredMultisigConfig {
    threshold: u8,
    owners: Vec<StoredMultisigOwner>,
}

/// Native multisig account storage.
#[contract(addr = NATIVE_MULTISIG_ADDRESS)]
pub struct NativeMultisig {
    // account -> packed threshold and owner count.
    accounts: Mapping<Address, StoredMultisigHeader>,
    // account -> owner index -> owner and weight.
    owners: Mapping<Address, Mapping<u32, StoredMultisigOwner>>,

    // WARNING: transient storage slots must remain at the end.
    tx_origin: Address,
    bootstrapped_account: Address,
}

impl NativeMultisig {
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    pub fn account_threshold_storage_slot(account: Address) -> (U256, Option<usize>) {
        let multisig = Self::new();
        let threshold = &multisig.accounts[account].threshold;
        (threshold.slot(), threshold.offset())
    }

    pub fn account_owners_len_storage_slot(account: Address) -> (U256, Option<usize>) {
        let multisig = Self::new();
        let owner_count = &multisig.accounts[account].owner_count;
        (owner_count.slot(), owner_count.offset())
    }

    pub fn config_owner_weight_storage_slot(
        account: Address,
        index: usize,
    ) -> (U256, Option<usize>) {
        let multisig = Self::new();
        let weight = &multisig.owners[account][index as u32].weight;
        (weight.slot(), weight.offset())
    }

    pub fn set_tx_origin(&mut self, origin: Address) -> Result<()> {
        self.tx_origin.t_write(origin)
    }

    fn set_bootstrapped_account(&mut self, account: Address) -> Result<()> {
        self.bootstrapped_account.t_write(account)
    }

    pub fn is_multisig_account(&self, account: Address) -> Result<bool> {
        let header = self.accounts[account].read()?;
        Ok(header.threshold != 0 || header.owner_count != 0)
    }

    pub fn get_multisig_config(&self, account: Address) -> Result<INativeMultisig::MultisigConfig> {
        if !self.is_multisig_account(account)? {
            return Ok(INativeMultisig::MultisigConfig {
                threshold: 0,
                owners: Vec::new(),
            });
        }

        let stored = self.load_stored_config(account)?;
        Ok(stored_config_to_abi(stored))
    }

    pub fn load_registered_config(&self, account: Address) -> Result<InitMultisig> {
        let stored = self.read_stored_config(account)?;
        stored_config_to_init(stored)
    }

    pub fn store_initial_config(&mut self, account: Address, config: &InitMultisig) -> Result<()> {
        if !is_valid_multisig_account(account) {
            return Err(NativeMultisigError::invalid_account().into());
        }
        if self.is_multisig_account(account)? {
            return Err(NativeMultisigError::account_already_initialized().into());
        }

        if config
            .account()
            .map_err(|_| NativeMultisigError::invalid_config())?
            != account
        {
            return Err(NativeMultisigError::invalid_account().into());
        }

        validate_multisig_config(config).map_err(|_| NativeMultisigError::invalid_config())?;
        let existing = self.accounts[account].read()?;
        if existing.threshold != 0 || existing.owner_count != 0 {
            return Err(NativeMultisigError::account_already_initialized().into());
        }

        self.write_stored_config(account, config)?;
        self.set_bootstrapped_account(account)?;
        self.emit_event(NativeMultisigEvent::multisig_initialized(account))
    }

    pub fn update_multisig_config(
        &mut self,
        msg_sender: Address,
        threshold: u8,
        owners: Vec<INativeMultisig::MultisigOwner>,
    ) -> Result<()> {
        let tx_origin = self.tx_origin.t_read()?;
        if tx_origin.is_zero() || tx_origin != msg_sender {
            return Err(NativeMultisigError::unauthorized_caller().into());
        }
        if self.bootstrapped_account.t_read()? == msg_sender {
            return Err(NativeMultisigError::same_transaction_update_not_allowed().into());
        }

        self.load_stored_config(msg_sender)?;
        let event_owners = owners.clone();
        let init_config = abi_config_to_init(threshold, owners)?;

        self.write_stored_config(msg_sender, &init_config)?;
        self.emit_event(NativeMultisigEvent::multisig_config_updated(
            msg_sender,
            threshold,
            event_owners,
        ))
    }

    fn require_initialized(&self, account: Address) -> Result<()> {
        if !self.is_multisig_account(account)? {
            return Err(NativeMultisigError::not_multisig_account().into());
        }
        Ok(())
    }

    fn load_stored_config(&self, account: Address) -> Result<StoredMultisigConfig> {
        self.require_initialized(account)?;
        let stored = self.read_stored_config(account)?;
        stored_config_to_init(stored.clone())?;
        Ok(stored)
    }

    fn read_stored_config(&self, account: Address) -> Result<StoredMultisigConfig> {
        let header = self.accounts[account].read()?;
        if header.threshold == 0 || header.owner_count == 0 {
            return Err(NativeMultisigError::config_not_found().into());
        }
        let owner_count = header.owner_count as usize;
        if owner_count > MAX_MULTISIG_OWNERS {
            return Err(NativeMultisigError::invalid_config().into());
        }

        let mut owners = Vec::new();
        for index in 0..owner_count {
            owners.push(self.owners[account][index as u32].read()?);
        }

        Ok(StoredMultisigConfig {
            threshold: header.threshold,
            owners,
        })
    }

    fn write_stored_config(&mut self, account: Address, config: &InitMultisig) -> Result<()> {
        let previous_owner_count = self.accounts[account]
            .read()?
            .owner_count
            .min(MAX_MULTISIG_OWNERS as u8);
        let owner_count =
            u8::try_from(config.owners.len()).map_err(|_| NativeMultisigError::invalid_config())?;

        self.accounts[account].write(StoredMultisigHeader {
            threshold: config.threshold,
            owner_count,
        })?;
        for (index, owner) in config.owners.iter().enumerate() {
            self.owners[account][index as u32].write(owner.into())?;
        }
        for index in owner_count..previous_owner_count {
            self.owners[account][u32::from(index)].delete()?;
        }

        Ok(())
    }
}

impl From<&MultisigOwner> for StoredMultisigOwner {
    fn from(value: &MultisigOwner) -> Self {
        Self {
            owner: value.owner,
            weight: value.weight,
        }
    }
}

fn abi_config_to_init(
    threshold: u8,
    owners: Vec<INativeMultisig::MultisigOwner>,
) -> Result<InitMultisig> {
    validate_abi_config_shape(threshold, &owners)?;
    let owners = owners
        .into_iter()
        .map(abi_owner_to_init)
        .collect::<Result<Vec<_>>>()?;
    let config = InitMultisig {
        salt: B256::ZERO,
        threshold,
        owners,
    };
    validate_multisig_config(&config).map_err(|_| NativeMultisigError::invalid_config())?;
    Ok(config)
}

fn abi_owner_to_init(value: INativeMultisig::MultisigOwner) -> Result<MultisigOwner> {
    Ok(MultisigOwner {
        owner: value.owner,
        weight: value.weight,
    })
}

fn validate_abi_config_shape(
    threshold: u8,
    owners: &[INativeMultisig::MultisigOwner],
) -> Result<()> {
    if owners.is_empty() {
        return Err(NativeMultisigError::invalid_owner().into());
    }
    if owners.len() > MAX_MULTISIG_OWNERS {
        return Err(NativeMultisigError::too_many_owners().into());
    }
    if threshold == 0 {
        return Err(NativeMultisigError::invalid_threshold().into());
    }

    let mut total_weight = 0u16;
    let mut prev_owner = None;
    for owner in owners {
        if owner.owner.is_zero() {
            return Err(NativeMultisigError::invalid_owner().into());
        }
        if owner.weight == 0 {
            return Err(NativeMultisigError::invalid_weight().into());
        }
        if let Some(prev) = prev_owner {
            if prev == owner.owner {
                return Err(NativeMultisigError::duplicate_owner().into());
            }
            if prev > owner.owner {
                return Err(NativeMultisigError::invalid_owner_order().into());
            }
        }
        prev_owner = Some(owner.owner);
        total_weight = total_weight
            .checked_add(u16::from(owner.weight))
            .ok_or_else(NativeMultisigError::invalid_weight)?;
    }

    if total_weight > u16::from(u8::MAX) {
        return Err(NativeMultisigError::invalid_weight().into());
    }
    if u16::from(threshold) > total_weight {
        return Err(NativeMultisigError::invalid_threshold().into());
    }

    Ok(())
}

fn stored_config_to_init(value: StoredMultisigConfig) -> Result<InitMultisig> {
    let owners = value
        .owners
        .into_iter()
        .map(stored_owner_to_init)
        .collect::<Vec<_>>();
    let config = InitMultisig {
        salt: B256::ZERO,
        threshold: value.threshold,
        owners,
    };
    validate_multisig_config(&config).map_err(|_| NativeMultisigError::invalid_config())?;
    Ok(config)
}

fn stored_owner_to_init(value: StoredMultisigOwner) -> MultisigOwner {
    MultisigOwner {
        owner: value.owner,
        weight: value.weight,
    }
}

fn stored_config_to_abi(value: StoredMultisigConfig) -> INativeMultisig::MultisigConfig {
    INativeMultisig::MultisigConfig {
        threshold: value.threshold,
        owners: value.owners.into_iter().map(stored_owner_to_abi).collect(),
    }
}

fn stored_owner_to_abi(value: StoredMultisigOwner) -> INativeMultisig::MultisigOwner {
    INativeMultisig::MultisigOwner {
        owner: value.owner,
        weight: value.weight,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::TempoPrecompileError,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
    };
    use alloy::primitives::address;
    use tempo_chainspec::hardfork::TempoHardfork;

    fn init_config() -> InitMultisig {
        InitMultisig {
            salt: B256::ZERO,
            threshold: 1,
            owners: vec![
                MultisigOwner {
                    owner: address!("0000000000000000000000000000000000000011"),
                    weight: 1,
                },
                MultisigOwner {
                    owner: address!("0000000000000000000000000000000000000022"),
                    weight: 1,
                },
            ],
        }
    }

    fn abi_owners() -> Vec<INativeMultisig::MultisigOwner> {
        vec![
            INativeMultisig::MultisigOwner {
                owner: address!("0000000000000000000000000000000000000011"),
                weight: 1,
            },
            INativeMultisig::MultisigOwner {
                owner: address!("0000000000000000000000000000000000000022"),
                weight: 1,
            },
        ]
    }

    fn indexed_owner(index: u16) -> Address {
        let mut bytes = [0u8; 20];
        bytes[18..].copy_from_slice(&index.to_be_bytes());
        Address::from(bytes)
    }

    fn max_abi_owners() -> Vec<INativeMultisig::MultisigOwner> {
        (1..=MAX_MULTISIG_OWNERS as u16)
            .map(|index| INativeMultisig::MultisigOwner {
                owner: indexed_owner(index),
                weight: 1,
            })
            .collect()
    }

    fn assert_config_unchanged(multisig: &NativeMultisig, account: Address) -> Result<()> {
        assert!(multisig.is_multisig_account(account)?);
        let stored = multisig.get_multisig_config(account)?;
        let expected_owners = abi_owners();
        assert_eq!(stored.threshold, 1);
        assert_eq!(stored.owners.len(), expected_owners.len());
        for (stored_owner, expected_owner) in stored.owners.iter().zip(expected_owners.iter()) {
            assert_eq!(stored_owner.owner, expected_owner.owner);
            assert_eq!(stored_owner.weight, expected_owner.weight);
        }
        Ok(())
    }

    #[test]
    fn store_read_and_update_config() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T8);
        let config = init_config();
        let account = config.account().unwrap();

        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.initialize()
        })?;
        storage.reset_counters();

        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.store_initial_config(account, &config)?;

            assert!(multisig.is_multisig_account(account)?);
            assert_eq!(multisig.get_multisig_config(account)?.threshold, 1);
            multisig.set_tx_origin(account)?;
            assert!(matches!(
                multisig.update_multisig_config(account, 2, abi_owners()),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::SameTransactionUpdateNotAllowed(_)
                ))
            ));

            Ok::<_, TempoPrecompileError>(())
        })?;
        assert_eq!(storage.counter_sstore(), 1 + config.owners.len() as u64);

        let (threshold_slot, threshold_offset) =
            NativeMultisig::account_threshold_storage_slot(account);
        let (owner_count_slot, owner_count_offset) =
            NativeMultisig::account_owners_len_storage_slot(account);
        assert_eq!(threshold_slot, owner_count_slot);
        assert_ne!(threshold_offset, owner_count_offset);

        let mut persistent_slots = std::collections::BTreeSet::from([threshold_slot]);
        for index in 0..config.owners.len() {
            let (owner_slot, _) = NativeMultisig::config_owner_weight_storage_slot(account, index);
            persistent_slots.insert(owner_slot);
        }
        assert_eq!(persistent_slots.len(), 1 + config.owners.len());

        storage.clear_transient();
        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.set_tx_origin(account)?;
            multisig.update_multisig_config(account, 2, abi_owners())?;
            assert_eq!(multisig.get_multisig_config(account)?.threshold, 2);
            Ok::<_, TempoPrecompileError>(())
        })?;

        Ok(())
    }

    #[test]
    fn store_and_read_255_owner_config() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T8);
        let owners = max_abi_owners();
        let config = InitMultisig {
            salt: B256::ZERO,
            threshold: u8::MAX,
            owners: owners
                .iter()
                .map(|owner| MultisigOwner {
                    owner: owner.owner,
                    weight: owner.weight,
                })
                .collect(),
        };
        let account = config.account().unwrap();

        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.initialize()?;
            multisig.store_initial_config(account, &config)?;

            let stored = multisig.get_multisig_config(account)?;
            assert_eq!(stored.threshold, u8::MAX);
            assert_eq!(stored.owners, owners);

            Ok::<_, TempoPrecompileError>(())
        })?;

        Ok(())
    }

    #[test]
    fn invalid_update_does_not_deactivate_multisig() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T8);
        let config = init_config();
        let account = config.account().unwrap();

        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.initialize()?;
            multisig.store_initial_config(account, &config)?;
            multisig.set_bootstrapped_account(Address::ZERO)?;
            multisig.set_tx_origin(account)?;

            assert!(matches!(
                multisig.update_multisig_config(account, 0, abi_owners()),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::InvalidThreshold(_)
                ))
            ));
            assert_config_unchanged(&multisig, account)?;

            assert!(matches!(
                multisig.update_multisig_config(account, 1, Vec::new()),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::InvalidOwner(_)
                ))
            ));
            assert_config_unchanged(&multisig, account)?;

            assert!(matches!(
                multisig.update_multisig_config(
                    account,
                    1,
                    vec![INativeMultisig::MultisigOwner {
                        owner: Address::ZERO,
                        weight: 1,
                    }],
                ),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::InvalidOwner(_)
                ))
            ));
            assert_config_unchanged(&multisig, account)?;

            assert!(matches!(
                multisig.update_multisig_config(
                    account,
                    1,
                    vec![INativeMultisig::MultisigOwner {
                        owner: address!("0000000000000000000000000000000000000011"),
                        weight: 0,
                    }],
                ),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::InvalidWeight(_)
                ))
            ));
            assert_config_unchanged(&multisig, account)?;

            Ok::<_, TempoPrecompileError>(())
        })?;

        Ok(())
    }

    #[test]
    fn update_config_returns_specific_config_errors() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T8);
        let config = init_config();
        let account = config.account().unwrap();

        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.initialize()?;
            multisig.store_initial_config(account, &config)?;
            multisig.set_bootstrapped_account(Address::ZERO)?;
            multisig.set_tx_origin(account)?;

            assert!(matches!(
                multisig.update_multisig_config(account, 0, abi_owners()),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::InvalidThreshold(_)
                ))
            ));

            let mut duplicate_owners = abi_owners();
            duplicate_owners[1].owner = duplicate_owners[0].owner;
            assert!(matches!(
                multisig.update_multisig_config(account, 1, duplicate_owners),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::DuplicateOwner(_)
                ))
            ));

            let mut unordered_owners = abi_owners();
            unordered_owners.swap(0, 1);
            assert!(matches!(
                multisig.update_multisig_config(account, 1, unordered_owners),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::InvalidOwnerOrder(_)
                ))
            ));

            let mut invalid_weight_owners = abi_owners();
            invalid_weight_owners[0].weight = 0;
            assert!(matches!(
                multisig.update_multisig_config(account, 1, invalid_weight_owners),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::InvalidWeight(_)
                ))
            ));

            let overweight_owners = vec![
                INativeMultisig::MultisigOwner {
                    owner: address!("0000000000000000000000000000000000000011"),
                    weight: 128,
                },
                INativeMultisig::MultisigOwner {
                    owner: address!("0000000000000000000000000000000000000022"),
                    weight: 128,
                },
            ];
            assert!(matches!(
                multisig.update_multisig_config(account, u8::MAX, overweight_owners),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::InvalidWeight(_)
                ))
            ));

            Ok::<_, TempoPrecompileError>(())
        })?;

        Ok(())
    }
}
