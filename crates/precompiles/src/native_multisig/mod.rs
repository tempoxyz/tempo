//! Native multisig account precompile.

pub mod dispatch;

pub use tempo_contracts::precompiles::INativeMultisig;
use tempo_contracts::precompiles::{
    NATIVE_MULTISIG_ADDRESS, NativeMultisigError, NativeMultisigEvent,
};
use tempo_precompiles_macros::{Storable, contract};
use tempo_primitives::transaction::{
    InitMultisig, MAX_MULTISIG_OWNERS, MultisigOwner, derive_multisig_account,
    derive_multisig_config_id, is_valid_multisig_account, validate_multisig_config,
};

use crate::{
    error::Result,
    storage::{Handler, Mapping},
};
use alloy::primitives::{Address, B256, U256};

#[derive(Debug, Clone, Default, PartialEq, Eq, Storable)]
struct StoredMultisigOwner {
    owner: Address,
    weight: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Storable)]
struct StoredMultisigHeader {
    threshold: u32,
    owner_count: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct StoredMultisigConfig {
    threshold: u32,
    owners: Vec<StoredMultisigOwner>,
}

/// Native multisig account storage.
#[contract(addr = NATIVE_MULTISIG_ADDRESS)]
pub struct NativeMultisig {
    // account -> permanent config_id.
    config_ids: Mapping<Address, B256>,
    // account -> config_id -> packed threshold and owner count.
    configs: Mapping<Address, Mapping<B256, StoredMultisigHeader>>,
    // account -> config_id -> owner index -> owner and weight.
    owners: Mapping<Address, Mapping<B256, Mapping<u32, StoredMultisigOwner>>>,

    // WARNING: transient storage slots must remain at the end.
    tx_origin: Address,
    bootstrapped_account: Address,
}

impl NativeMultisig {
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    pub fn config_id_storage_slot(account: Address) -> U256 {
        Self::new().config_ids[account].slot()
    }

    pub fn config_threshold_storage_slot(
        account: Address,
        config_id: B256,
    ) -> (U256, Option<usize>) {
        let multisig = Self::new();
        let threshold = &multisig.configs[account][config_id].threshold;
        (threshold.slot(), threshold.offset())
    }

    pub fn config_owners_len_storage_slot(
        account: Address,
        config_id: B256,
    ) -> (U256, Option<usize>) {
        let multisig = Self::new();
        let owner_count = &multisig.configs[account][config_id].owner_count;
        (owner_count.slot(), owner_count.offset())
    }

    pub fn config_owner_weight_storage_slot(
        account: Address,
        config_id: B256,
        index: usize,
    ) -> (U256, Option<usize>) {
        let multisig = Self::new();
        let weight = &multisig.owners[account][config_id][index as u32].weight;
        (weight.slot(), weight.offset())
    }

    pub fn set_tx_origin(&mut self, origin: Address) -> Result<()> {
        self.tx_origin.t_write(origin)
    }

    fn set_bootstrapped_account(&mut self, account: Address) -> Result<()> {
        self.bootstrapped_account.t_write(account)
    }

    pub fn is_multisig_account(&self, account: Address) -> Result<bool> {
        Ok(!self.config_ids[account].read()?.is_zero())
    }

    pub fn get_multisig_config_id(&self, account: Address) -> Result<B256> {
        self.config_ids[account].read()
    }

    pub fn get_multisig_config(
        &self,
        account: Address,
        config_id: B256,
    ) -> Result<INativeMultisig::MultisigConfig> {
        if !self.is_multisig_account(account)? {
            return Ok(INativeMultisig::MultisigConfig {
                threshold: 0,
                owners: Vec::new(),
            });
        }

        let stored = self.load_stored_config(account, config_id)?;
        Ok(stored_config_to_abi(stored))
    }

    pub fn load_registered_config(
        &self,
        account: Address,
        config_id: B256,
    ) -> Result<InitMultisig> {
        let canonical_config_id = self.config_ids[account].read()?;
        if canonical_config_id == B256::ZERO {
            return Err(NativeMultisigError::config_not_found().into());
        }
        if canonical_config_id != config_id {
            return Err(NativeMultisigError::invalid_config_id().into());
        }

        let stored = self.read_stored_config(account, config_id)?;
        stored_config_to_init(stored)
    }

    pub fn store_initial_config(
        &mut self,
        account: Address,
        config_id: B256,
        config: &InitMultisig,
    ) -> Result<()> {
        if !is_valid_multisig_account(account) {
            return Err(NativeMultisigError::invalid_account().into());
        }
        if config_id == B256::ZERO {
            return Err(NativeMultisigError::invalid_config_id().into());
        }
        if !self.config_ids[account].read()?.is_zero() {
            return Err(NativeMultisigError::account_already_initialized().into());
        }

        let expected_config_id =
            derive_multisig_config_id(config).map_err(|_| NativeMultisigError::invalid_config())?;
        if expected_config_id != config_id {
            return Err(NativeMultisigError::invalid_config_id().into());
        }
        if derive_multisig_account(config_id) != account {
            return Err(NativeMultisigError::invalid_account().into());
        }

        validate_multisig_config(config).map_err(|_| NativeMultisigError::invalid_config())?;
        let existing = self.configs[account][config_id].read()?;
        if existing.threshold != 0 || existing.owner_count != 0 {
            return Err(NativeMultisigError::account_already_initialized().into());
        }

        self.config_ids[account].write(config_id)?;
        self.write_stored_config(account, config_id, config)?;
        self.set_bootstrapped_account(account)?;
        self.emit_event(NativeMultisigEvent::multisig_initialized(
            account, config_id,
        ))
    }

    pub fn update_multisig_config(
        &mut self,
        msg_sender: Address,
        config_id: B256,
        threshold: u32,
        owners: Vec<INativeMultisig::MultisigOwner>,
    ) -> Result<()> {
        let tx_origin = self.tx_origin.t_read()?;
        if tx_origin.is_zero() || tx_origin != msg_sender {
            return Err(NativeMultisigError::unauthorized_caller().into());
        }
        if self.bootstrapped_account.t_read()? == msg_sender {
            return Err(NativeMultisigError::same_transaction_update_not_allowed().into());
        }

        if config_id == B256::ZERO {
            return Err(NativeMultisigError::invalid_config_id().into());
        }

        let canonical_config_id = self.require_initialized(msg_sender)?;
        if canonical_config_id != config_id {
            return Err(NativeMultisigError::invalid_config_id().into());
        }
        if derive_multisig_account(config_id) != msg_sender {
            return Err(NativeMultisigError::invalid_account().into());
        }

        self.load_stored_config(msg_sender, config_id)?;
        let event_owners = owners.clone();
        let init_config = abi_config_to_init(threshold, owners)?;

        self.write_stored_config(msg_sender, config_id, &init_config)?;
        self.emit_event(NativeMultisigEvent::multisig_config_updated(
            msg_sender,
            config_id,
            threshold,
            event_owners,
        ))
    }

    fn require_initialized(&self, account: Address) -> Result<B256> {
        let config_id = self.config_ids[account].read()?;
        if config_id == B256::ZERO {
            return Err(NativeMultisigError::not_multisig_account().into());
        }
        Ok(config_id)
    }

    fn load_stored_config(
        &self,
        account: Address,
        config_id: B256,
    ) -> Result<StoredMultisigConfig> {
        let canonical_config_id = self.require_initialized(account)?;
        if canonical_config_id != config_id {
            return Err(NativeMultisigError::invalid_config_id().into());
        }

        let stored = self.read_stored_config(account, config_id)?;
        stored_config_to_init(stored.clone())?;
        Ok(stored)
    }

    fn read_stored_config(
        &self,
        account: Address,
        config_id: B256,
    ) -> Result<StoredMultisigConfig> {
        let header = self.configs[account][config_id].read()?;
        if header.threshold == 0 || header.owner_count == 0 {
            return Err(NativeMultisigError::config_not_found().into());
        }
        let owner_count = header.owner_count as usize;
        if owner_count > MAX_MULTISIG_OWNERS {
            return Err(NativeMultisigError::invalid_config().into());
        }

        let mut owners = Vec::new();
        for index in 0..header.owner_count {
            owners.push(self.owners[account][config_id][index].read()?);
        }

        Ok(StoredMultisigConfig {
            threshold: header.threshold,
            owners,
        })
    }

    fn write_stored_config(
        &mut self,
        account: Address,
        config_id: B256,
        config: &InitMultisig,
    ) -> Result<()> {
        let previous_owner_count = self.configs[account][config_id]
            .read()?
            .owner_count
            .min(MAX_MULTISIG_OWNERS as u32);
        let owner_count = u32::try_from(config.owners.len())
            .map_err(|_| NativeMultisigError::invalid_config())?;

        self.configs[account][config_id].write(StoredMultisigHeader {
            threshold: config.threshold,
            owner_count,
        })?;
        for (index, owner) in config.owners.iter().enumerate() {
            self.owners[account][config_id][index as u32].write(owner.into())?;
        }
        for index in owner_count..previous_owner_count {
            self.owners[account][config_id][index].delete()?;
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
    threshold: u32,
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
    threshold: u32,
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

    let mut total_weight = 0u64;
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
            .checked_add(u64::from(owner.weight))
            .ok_or_else(NativeMultisigError::invalid_weight)?;
    }

    if total_weight > u64::from(u32::MAX) {
        return Err(NativeMultisigError::invalid_weight().into());
    }
    if u64::from(threshold) > total_weight {
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

    fn assert_config_unchanged(
        multisig: &NativeMultisig,
        account: Address,
        config_id: B256,
    ) -> Result<()> {
        assert!(multisig.is_multisig_account(account)?);
        assert_eq!(multisig.get_multisig_config_id(account)?, config_id);
        let stored = multisig.get_multisig_config(account, config_id)?;
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
        let config_id = config.config_id().unwrap();
        let account = config.account().unwrap();

        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.initialize()
        })?;
        storage.reset_counters();

        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.store_initial_config(account, config_id, &config)?;

            assert!(multisig.is_multisig_account(account)?);
            assert_eq!(multisig.get_multisig_config_id(account)?, config_id);
            assert_eq!(
                multisig.get_multisig_config(account, config_id)?.threshold,
                1
            );
            multisig.set_tx_origin(account)?;
            assert!(matches!(
                multisig.update_multisig_config(account, config_id, 2, abi_owners()),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::SameTransactionUpdateNotAllowed(_)
                ))
            ));

            Ok::<_, TempoPrecompileError>(())
        })?;
        assert_eq!(storage.counter_sstore(), 2 + config.owners.len() as u64);

        let config_id_slot = NativeMultisig::config_id_storage_slot(account);
        let (threshold_slot, threshold_offset) =
            NativeMultisig::config_threshold_storage_slot(account, config_id);
        let (owner_count_slot, owner_count_offset) =
            NativeMultisig::config_owners_len_storage_slot(account, config_id);
        assert_eq!(threshold_slot, owner_count_slot);
        assert_ne!(threshold_offset, owner_count_offset);

        let mut persistent_slots =
            std::collections::BTreeSet::from([config_id_slot, threshold_slot]);
        for index in 0..config.owners.len() {
            let (owner_slot, _) =
                NativeMultisig::config_owner_weight_storage_slot(account, config_id, index);
            persistent_slots.insert(owner_slot);
        }
        assert_eq!(persistent_slots.len(), 2 + config.owners.len());

        storage.clear_transient();
        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.set_tx_origin(account)?;
            multisig.update_multisig_config(account, config_id, 2, abi_owners())?;
            assert_eq!(
                multisig.get_multisig_config(account, config_id)?.threshold,
                2
            );
            Ok::<_, TempoPrecompileError>(())
        })?;

        Ok(())
    }

    #[test]
    fn invalid_update_does_not_deactivate_multisig() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T8);
        let config = init_config();
        let config_id = config.config_id().unwrap();
        let account = config.account().unwrap();

        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.initialize()?;
            multisig.store_initial_config(account, config_id, &config)?;
            multisig.set_bootstrapped_account(Address::ZERO)?;
            multisig.set_tx_origin(account)?;

            assert!(matches!(
                multisig.update_multisig_config(account, config_id, 0, abi_owners()),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::InvalidThreshold(_)
                ))
            ));
            assert_config_unchanged(&multisig, account, config_id)?;

            assert!(matches!(
                multisig.update_multisig_config(account, config_id, 1, Vec::new()),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::InvalidOwner(_)
                ))
            ));
            assert_config_unchanged(&multisig, account, config_id)?;

            assert!(matches!(
                multisig.update_multisig_config(
                    account,
                    config_id,
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
            assert_config_unchanged(&multisig, account, config_id)?;

            assert!(matches!(
                multisig.update_multisig_config(
                    account,
                    config_id,
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
            assert_config_unchanged(&multisig, account, config_id)?;

            Ok::<_, TempoPrecompileError>(())
        })?;

        Ok(())
    }

    #[test]
    fn update_config_validates_explicit_config_id() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T8);
        let config = init_config();
        let config_id = config.config_id().unwrap();
        let account = config.account().unwrap();

        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.initialize()?;
            multisig.store_initial_config(account, config_id, &config)?;
            multisig.set_bootstrapped_account(Address::ZERO)?;
            multisig.set_tx_origin(account)?;

            assert!(matches!(
                multisig.update_multisig_config(account, B256::repeat_byte(0x12), 2, abi_owners()),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::InvalidConfigId(_)
                ))
            ));

            Ok::<_, TempoPrecompileError>(())
        })?;

        Ok(())
    }

    #[test]
    fn update_config_returns_specific_config_errors() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T8);
        let config = init_config();
        let config_id = config.config_id().unwrap();
        let account = config.account().unwrap();

        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.initialize()?;
            multisig.store_initial_config(account, config_id, &config)?;
            multisig.set_bootstrapped_account(Address::ZERO)?;
            multisig.set_tx_origin(account)?;

            assert!(matches!(
                multisig.update_multisig_config(account, config_id, 0, abi_owners()),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::InvalidThreshold(_)
                ))
            ));

            let mut duplicate_owners = abi_owners();
            duplicate_owners[1].owner = duplicate_owners[0].owner;
            assert!(matches!(
                multisig.update_multisig_config(account, config_id, 1, duplicate_owners),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::DuplicateOwner(_)
                ))
            ));

            let mut unordered_owners = abi_owners();
            unordered_owners.swap(0, 1);
            assert!(matches!(
                multisig.update_multisig_config(account, config_id, 1, unordered_owners),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::InvalidOwnerOrder(_)
                ))
            ));

            let mut invalid_weight_owners = abi_owners();
            invalid_weight_owners[0].weight = 0;
            assert!(matches!(
                multisig.update_multisig_config(account, config_id, 1, invalid_weight_owners),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::InvalidWeight(_)
                ))
            ));

            Ok::<_, TempoPrecompileError>(())
        })?;

        Ok(())
    }
}
