//! Native multisig account precompile.

pub mod auth;
pub mod dispatch;

pub use auth::NativeMultisigAuthError;
pub use tempo_contracts::precompiles::INativeMultisig;
use tempo_contracts::precompiles::{
    NATIVE_MULTISIG_ADDRESS, NativeMultisigError, NativeMultisigEvent,
};
use tempo_precompiles_macros::{Storable, contract};
use tempo_primitives::transaction::{
    InitMultisig, MAX_MULTISIG_OWNERS, MultisigConfigError, MultisigOwner,
    is_valid_multisig_account,
};

use crate::{
    error::{Result, TempoPrecompileError},
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParsedMultisigHeader {
    Uninitialized,
    Initialized { threshold: u8, owner_count: usize },
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
        Ok(matches!(
            parse_multisig_header(header)?,
            ParsedMultisigHeader::Initialized { .. }
        ))
    }

    pub fn get_multisig_config_id(&self, account: Address) -> Result<B256> {
        if self.is_multisig_account(account)? {
            Ok(account.into_word())
        } else {
            Ok(B256::ZERO)
        }
    }

    pub fn get_multisig_config(&self, account: Address) -> Result<INativeMultisig::MultisigConfig> {
        let header = self.accounts[account].read()?;
        let config = self.load_stored_config_with_header(account, header)?;
        Ok(init_config_to_abi(config))
    }

    pub fn load_registered_config(&self, account: Address) -> Result<InitMultisig> {
        self.load_stored_config(account)
    }

    pub fn validate_config_id(&self, account: Address, config_id: B256) -> Result<()> {
        if config_id == B256::ZERO
            || config_id[..12].iter().any(|byte| *byte != 0)
            || Address::from_word(config_id) != account
            || self.get_multisig_config_id(account)? != config_id
        {
            return Err(NativeMultisigError::invalid_config().into());
        }
        Ok(())
    }

    pub fn store_initial_config(&mut self, account: Address, config: &InitMultisig) -> Result<()> {
        if !is_valid_multisig_account(account, self.storage.spec()) {
            return Err(NativeMultisigError::invalid_account().into());
        }
        let existing = self.accounts[account].read()?;
        match parse_multisig_header(existing)? {
            ParsedMultisigHeader::Uninitialized => {}
            ParsedMultisigHeader::Initialized { .. } => {
                return Err(NativeMultisigError::account_already_initialized().into());
            }
        }

        if config.account().map_err(map_multisig_config_error)? != account {
            return Err(NativeMultisigError::invalid_account().into());
        }

        self.write_stored_config(account, config, 0)?;
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

        let stored = self.load_stored_config(msg_sender)?;
        let previous_owner_count = stored.owners.len();
        let event_owners = owners.clone();
        let init_config = abi_config_to_init(threshold, owners)?;

        self.write_stored_config(msg_sender, &init_config, previous_owner_count)?;
        self.emit_event(NativeMultisigEvent::multisig_config_updated(
            msg_sender,
            threshold,
            event_owners,
        ))
    }

    fn load_stored_config(&self, account: Address) -> Result<InitMultisig> {
        let header = self.accounts[account].read()?;
        self.load_stored_config_with_header(account, header)
    }

    fn load_stored_config_with_header(
        &self,
        account: Address,
        header: StoredMultisigHeader,
    ) -> Result<InitMultisig> {
        match parse_multisig_header(header)? {
            ParsedMultisigHeader::Uninitialized => {
                Err(NativeMultisigError::not_multisig_account().into())
            }
            ParsedMultisigHeader::Initialized {
                threshold,
                owner_count,
            } => {
                let mut owners = Vec::new();
                for index in 0..owner_count {
                    owners.push(self.owners[account][index as u32].read()?.into());
                }

                let config = InitMultisig {
                    salt: B256::ZERO,
                    threshold,
                    owners,
                };
                config.validate().map_err(map_multisig_config_error)?;
                Ok(config)
            }
        }
    }

    fn write_stored_config(
        &mut self,
        account: Address,
        config: &InitMultisig,
        previous_owner_count: usize,
    ) -> Result<()> {
        let owner_count = u8::try_from(config.owners.len())
            .map_err(|_| NativeMultisigError::too_many_owners())?;

        self.accounts[account].write(StoredMultisigHeader {
            threshold: config.threshold,
            owner_count,
        })?;
        for (index, owner) in config.owners.iter().enumerate() {
            self.owners[account][index as u32].write(owner.into())?;
        }
        for index in usize::from(owner_count)..previous_owner_count {
            self.owners[account][index as u32].delete()?;
        }

        Ok(())
    }
}

fn parse_multisig_header(header: StoredMultisigHeader) -> Result<ParsedMultisigHeader> {
    match (header.threshold, header.owner_count) {
        (0, 0) => Ok(ParsedMultisigHeader::Uninitialized),
        (0, _) | (_, 0) => Err(NativeMultisigError::invalid_config().into()),
        (threshold, owner_count) => {
            let owner_count = usize::from(owner_count);
            if owner_count > MAX_MULTISIG_OWNERS {
                return Err(NativeMultisigError::invalid_config().into());
            }
            Ok(ParsedMultisigHeader::Initialized {
                threshold,
                owner_count,
            })
        }
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

impl From<StoredMultisigOwner> for MultisigOwner {
    fn from(value: StoredMultisigOwner) -> Self {
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
    let owners = owners.into_iter().map(Into::into).collect::<Vec<_>>();
    let config = InitMultisig {
        salt: B256::ZERO,
        threshold,
        owners,
    };
    config.validate().map_err(map_multisig_config_error)?;
    Ok(config)
}

fn map_multisig_config_error(err: MultisigConfigError) -> TempoPrecompileError {
    match err {
        MultisigConfigError::EmptyOwners | MultisigConfigError::ZeroOwner => {
            NativeMultisigError::invalid_owner().into()
        }
        MultisigConfigError::TooManyOwners => NativeMultisigError::too_many_owners().into(),
        MultisigConfigError::ZeroThreshold | MultisigConfigError::ThresholdExceedsWeight => {
            NativeMultisigError::invalid_threshold().into()
        }
        MultisigConfigError::ZeroWeight
        | MultisigConfigError::WeightOverflow
        | MultisigConfigError::TotalWeightExceedsMax => {
            NativeMultisigError::invalid_weight().into()
        }
        MultisigConfigError::DuplicateOwner => NativeMultisigError::duplicate_owner().into(),
        MultisigConfigError::OwnersNotAscending => {
            NativeMultisigError::invalid_owner_order().into()
        }
        MultisigConfigError::DerivedAccountZero => NativeMultisigError::invalid_account().into(),
    }
}

fn init_config_to_abi(value: InitMultisig) -> INativeMultisig::MultisigConfig {
    INativeMultisig::MultisigConfig {
        threshold: value.threshold,
        owners: value.owners.into_iter().map(Into::into).collect(),
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
    fn get_multisig_config_reads_header_once() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T8);
        let config = init_config();
        let account = config.account().unwrap();
        let empty_account = Address::repeat_byte(0x42);
        let partial_account = Address::repeat_byte(0x43);

        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.initialize()?;
            multisig.store_initial_config(account, &config)?;
            multisig.accounts[partial_account].write(StoredMultisigHeader {
                threshold: 1,
                owner_count: 0,
            })?;
            Ok::<_, TempoPrecompileError>(())
        })?;

        storage.reset_counters();
        StorageCtx::enter(&mut storage, || {
            let multisig = NativeMultisig::new();
            let stored = multisig.get_multisig_config(account)?;
            assert_eq!(stored.threshold, config.threshold);
            assert_eq!(stored.owners.len(), config.owners.len());
            Ok::<_, TempoPrecompileError>(())
        })?;
        assert_eq!(
            storage.counter_sload(),
            1 + config.owners.len() as u64,
            "registered config should read one header plus each owner"
        );

        storage.reset_counters();
        StorageCtx::enter(&mut storage, || {
            let multisig = NativeMultisig::new();
            assert!(matches!(
                multisig.get_multisig_config(empty_account),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::NotMultisigAccount(_)
                ))
            ));
            Ok::<_, TempoPrecompileError>(())
        })?;
        assert_eq!(
            storage.counter_sload(),
            1,
            "non-multisig config lookup should read only the account header"
        );

        storage.reset_counters();
        StorageCtx::enter(&mut storage, || {
            let multisig = NativeMultisig::new();
            assert!(matches!(
                multisig.get_multisig_config(partial_account),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::InvalidConfig(_)
                ))
            ));
            Ok::<_, TempoPrecompileError>(())
        })?;
        assert_eq!(
            storage.counter_sload(),
            1,
            "partial config lookup should read only the account header"
        );

        Ok(())
    }

    #[test]
    fn is_multisig_account_parses_header_state() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T8);
        let config = init_config();
        let account = config.account().unwrap();
        let empty_account = Address::repeat_byte(0x42);
        let partial_account = Address::repeat_byte(0x43);

        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.initialize()?;
            multisig.store_initial_config(account, &config)?;
            multisig.accounts[partial_account].write(StoredMultisigHeader {
                threshold: 1,
                owner_count: 0,
            })?;
            Ok::<_, TempoPrecompileError>(())
        })?;

        StorageCtx::enter(&mut storage, || {
            let multisig = NativeMultisig::new();
            assert!(multisig.is_multisig_account(account)?);
            assert!(!multisig.is_multisig_account(empty_account)?);
            assert!(matches!(
                multisig.is_multisig_account(partial_account),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::InvalidConfig(_)
                ))
            ));
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

    #[test]
    fn store_initial_config_returns_specific_config_errors() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T8);
        let account = Address::repeat_byte(0x44);
        let valid = init_config();

        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.initialize()?;

            let mut zero_threshold = valid.clone();
            zero_threshold.threshold = 0;
            assert!(matches!(
                multisig.store_initial_config(account, &zero_threshold),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::InvalidThreshold(_)
                ))
            ));

            let empty_owners = InitMultisig {
                salt: B256::ZERO,
                threshold: 1,
                owners: Vec::new(),
            };
            assert!(matches!(
                multisig.store_initial_config(account, &empty_owners),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::InvalidOwner(_)
                ))
            ));

            let mut duplicate_owners = valid.clone();
            duplicate_owners.owners[1].owner = duplicate_owners.owners[0].owner;
            assert!(matches!(
                multisig.store_initial_config(account, &duplicate_owners),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::DuplicateOwner(_)
                ))
            ));

            let mut unordered_owners = valid.clone();
            unordered_owners.owners.swap(0, 1);
            assert!(matches!(
                multisig.store_initial_config(account, &unordered_owners),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::InvalidOwnerOrder(_)
                ))
            ));

            let mut zero_weight = valid.clone();
            zero_weight.owners[0].weight = 0;
            assert!(matches!(
                multisig.store_initial_config(account, &zero_weight),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::InvalidWeight(_)
                ))
            ));

            let too_many_owners = InitMultisig {
                salt: B256::ZERO,
                threshold: u8::MAX,
                owners: (0..=MAX_MULTISIG_OWNERS as u16)
                    .map(|index| MultisigOwner {
                        owner: indexed_owner(index + 1),
                        weight: 1,
                    })
                    .collect(),
            };
            assert!(matches!(
                multisig.store_initial_config(account, &too_many_owners),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::TooManyOwners(_)
                ))
            ));

            Ok::<_, TempoPrecompileError>(())
        })?;

        Ok(())
    }
}
