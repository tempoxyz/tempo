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
    account_keychain::{AccountKeychain, getTransactionKeyCall},
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping, StorageCtx, packing},
};
use alloy::primitives::{Address, B256, U256};

const STORED_MULTISIG_HEADER_BYTES: usize = 10;
const STORED_MULTISIG_OWNER_BYTES: usize = 21;
const STORED_MULTISIG_WEIGHT_BYTES: usize = 1;

#[derive(Debug, Clone, Default, PartialEq, Eq, Storable)]
struct StoredMultisigOwner {
    owner: Address,
    // The remaining bytes are reserved and must be zero.
    weight: u8,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Storable)]
struct StoredMultisigHeader {
    // The remaining bytes in the packed header are reserved and must be zero.
    threshold: u8,
    // One byte supports 1 through 255 owners while preserving 0 as the empty marker.
    owner_count: u8,
    // Incremented after every successful owner configuration update.
    version: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParsedMultisigHeader {
    Uninitialized,
    Initialized {
        threshold: u8,
        owner_count: usize,
        version: u64,
    },
}

struct StoredMultisigConfig {
    config: InitMultisig,
    version: u64,
}

/// Registered configuration fields stored in the account header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisteredMultisigHeader {
    pub threshold: u8,
    pub version: u64,
    pub owner_count: usize,
}

/// Registered configuration fields needed during transaction authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredMultisigConfig {
    pub threshold: u8,
    pub version: u64,
    pub owners: Vec<MultisigOwner>,
}

/// Native multisig account storage.
#[contract(addr = NATIVE_MULTISIG_ADDRESS)]
pub struct NativeMultisig {
    // account -> packed threshold, owner count, and configuration version.
    accounts: Mapping<Address, StoredMultisigHeader>,
    // account -> owner index -> owner and weight.
    owners: Mapping<Address, Mapping<u32, StoredMultisigOwner>>,
    // account -> owner address -> owner weight.
    owner_weights: Mapping<Address, Mapping<Address, u8>>,

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

    pub fn account_version_storage_slot(account: Address) -> (U256, Option<usize>) {
        let multisig = Self::new();
        let version = &multisig.accounts[account].version;
        (version.slot(), version.offset())
    }

    pub fn config_owner_weight_storage_slot(
        account: Address,
        index: usize,
    ) -> (U256, Option<usize>) {
        let multisig = Self::new();
        let weight = &multisig.owners[account][index as u32].weight;
        (weight.slot(), weight.offset())
    }

    pub fn config_owner_address_storage_slot(
        account: Address,
        index: usize,
    ) -> (U256, Option<usize>) {
        let multisig = Self::new();
        let owner = &multisig.owners[account][index as u32].owner;
        (owner.slot(), owner.offset())
    }

    pub fn config_owner_lookup_weight_storage_slot(
        account: Address,
        owner: Address,
    ) -> (U256, Option<usize>) {
        let multisig = Self::new();
        let weight = &multisig.owner_weights[account][owner];
        (weight.slot(), weight.offset())
    }

    pub fn set_tx_origin(&mut self, origin: Address) -> Result<()> {
        self.tx_origin.t_write(origin)
    }

    fn set_bootstrapped_account(&mut self, account: Address) -> Result<()> {
        self.bootstrapped_account.t_write(account)
    }

    pub fn derive_account(
        &self,
        salt: B256,
        threshold: u8,
        owners: Vec<INativeMultisig::MultisigOwner>,
    ) -> Result<Address> {
        let config = InitMultisig {
            salt,
            threshold,
            owners: owners.into_iter().map(Into::into).collect(),
        };
        let account = config.account().map_err(map_multisig_config_error)?;
        if !is_valid_multisig_account(account, self.storage.spec()) {
            return Err(NativeMultisigError::invalid_account().into());
        }
        Ok(account)
    }

    pub fn is_multisig_account(&self, account: Address) -> Result<bool> {
        Ok(self.load_registered_header_if_present(account)?.is_some())
    }

    pub fn load_registered_header(&self, account: Address) -> Result<RegisteredMultisigHeader> {
        self.load_registered_header_if_present(account)?
            .ok_or_else(|| NativeMultisigError::not_multisig_account().into())
    }

    pub fn load_registered_header_if_present(
        &self,
        account: Address,
    ) -> Result<Option<RegisteredMultisigHeader>> {
        let header = self.read_stored_header(account)?;
        Ok(match parse_multisig_header(header)? {
            ParsedMultisigHeader::Uninitialized => None,
            ParsedMultisigHeader::Initialized {
                threshold,
                owner_count,
                version,
            } => Some(RegisteredMultisigHeader {
                threshold,
                version,
                owner_count,
            }),
        })
    }

    pub fn get_multisig_config(&self, account: Address) -> Result<INativeMultisig::MultisigConfig> {
        let header = self.read_stored_header(account)?;
        let stored = self.load_stored_config_with_header(account, header)?;
        Ok(init_config_to_abi(stored.config, stored.version))
    }

    #[cfg(test)]
    fn load_registered_init(&self, account: Address) -> Result<InitMultisig> {
        self.load_stored_config(account).map(|stored| stored.config)
    }

    pub fn load_registered_config(&self, account: Address) -> Result<RegisteredMultisigConfig> {
        self.load_registered_config_if_present(account)?
            .ok_or_else(|| NativeMultisigError::not_multisig_account().into())
    }

    pub fn load_registered_config_if_present(
        &self,
        account: Address,
    ) -> Result<Option<RegisteredMultisigConfig>> {
        let header = self.read_stored_header(account)?;
        match parse_multisig_header(header)? {
            ParsedMultisigHeader::Uninitialized => Ok(None),
            ParsedMultisigHeader::Initialized { .. } => self
                .load_stored_config_with_header(account, header)
                .map(|stored| {
                    let StoredMultisigConfig { config, version } = stored;
                    Some(RegisteredMultisigConfig {
                        threshold: config.threshold,
                        version,
                        owners: config.owners,
                    })
                }),
        }
    }

    #[cfg(test)]
    fn read_owner_weight(&self, account: Address, owner: Address) -> Result<u8> {
        self.read_stored_owner_weight(account, owner)
    }

    pub fn store_initial_config(&mut self, account: Address, config: &InitMultisig) -> Result<()> {
        if !is_valid_multisig_account(account, self.storage.spec()) {
            return Err(NativeMultisigError::invalid_account().into());
        }
        let existing = self.read_stored_header(account)?;
        match parse_multisig_header(existing)? {
            ParsedMultisigHeader::Uninitialized => {}
            ParsedMultisigHeader::Initialized { .. } => {
                return Err(NativeMultisigError::account_already_initialized().into());
            }
        }

        if config.account().map_err(map_multisig_config_error)? != account {
            return Err(NativeMultisigError::invalid_account().into());
        }

        self.write_stored_config(account, config, &[], 1)?;
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
        // Config updates are authorized only by the current native multisig owner threshold. Native
        // multisig accounts may authorize AccountKeychain access keys, but an access-key transaction
        // MUST NOT rotate the owner set, even when the key is unrestricted or scoped to this
        // precompile. Owner-threshold (multisig-signed) transactions leave the shared keychain
        // transaction key at zero; access-key transactions set it to the access key address.
        let transaction_key =
            AccountKeychain::new().get_transaction_key(getTransactionKeyCall {}, msg_sender)?;
        if !transaction_key.is_zero() {
            return Err(NativeMultisigError::unauthorized_caller().into());
        }
        if self.bootstrapped_account.t_read()? == msg_sender {
            return Err(NativeMultisigError::same_transaction_update_not_allowed().into());
        }

        let stored = self.load_stored_config(msg_sender)?;
        let version = stored
            .version
            .checked_add(1)
            .ok_or_else(NativeMultisigError::invalid_config)?;
        let event_owners = owners.clone();
        let init_config = abi_config_to_init(threshold, owners)?;

        self.write_stored_config(msg_sender, &init_config, &stored.config.owners, version)?;
        self.emit_event(NativeMultisigEvent::multisig_config_updated(
            msg_sender,
            threshold,
            event_owners,
        ))
    }

    fn load_stored_config(&self, account: Address) -> Result<StoredMultisigConfig> {
        let header = self.read_stored_header(account)?;
        self.load_stored_config_with_header(account, header)
    }

    fn load_stored_config_with_header(
        &self,
        account: Address,
        header: StoredMultisigHeader,
    ) -> Result<StoredMultisigConfig> {
        match parse_multisig_header(header)? {
            ParsedMultisigHeader::Uninitialized => {
                Err(NativeMultisigError::not_multisig_account().into())
            }
            ParsedMultisigHeader::Initialized {
                threshold,
                owner_count,
                version,
            } => {
                let mut owners = Vec::new();
                for index in 0..owner_count {
                    owners.push(self.read_stored_owner(account, index)?.into());
                }

                let config = InitMultisig {
                    salt: B256::ZERO,
                    threshold,
                    owners,
                };
                if config.validate().is_err() {
                    return Err(NativeMultisigError::invalid_config().into());
                }
                for owner in &config.owners {
                    if self.read_stored_owner_weight(account, owner.owner)? != owner.weight {
                        return Err(NativeMultisigError::invalid_config().into());
                    }
                }
                Ok(StoredMultisigConfig { config, version })
            }
        }
    }

    fn write_stored_config(
        &mut self,
        account: Address,
        config: &InitMultisig,
        previous_owners: &[MultisigOwner],
        version: u64,
    ) -> Result<()> {
        let owner_count = u8::try_from(config.owners.len())
            .map_err(|_| NativeMultisigError::too_many_owners())?;

        self.write_stored_header(
            account,
            StoredMultisigHeader {
                threshold: config.threshold,
                owner_count,
                version,
            },
        )?;
        for (index, owner) in config.owners.iter().enumerate() {
            self.write_stored_owner(account, index, owner.into())?;
            self.write_stored_owner_weight(account, owner.owner, owner.weight)?;
        }
        for previous_owner in previous_owners {
            if config.owner_weight(previous_owner.owner).is_none() {
                self.write_stored_owner_weight(account, previous_owner.owner, 0)?;
            }
        }
        for index in usize::from(owner_count)..previous_owners.len() {
            self.write_stored_owner(account, index, StoredMultisigOwner::default())?;
        }

        Ok(())
    }

    fn read_stored_header(&self, account: Address) -> Result<StoredMultisigHeader> {
        let (slot, _) = Self::account_threshold_storage_slot(account);
        let word = read_canonical_storage_word(slot, STORED_MULTISIG_HEADER_BYTES)?;
        Ok(StoredMultisigHeader {
            threshold: packing::extract_from_word(word, 0, 1)?,
            owner_count: packing::extract_from_word(word, 1, 1)?,
            version: packing::extract_from_word(word, 2, 8)?,
        })
    }

    fn read_stored_owner(&self, account: Address, index: usize) -> Result<StoredMultisigOwner> {
        let (slot, _) = Self::config_owner_address_storage_slot(account, index);
        let word = read_canonical_storage_word(slot, STORED_MULTISIG_OWNER_BYTES)?;
        Ok(StoredMultisigOwner {
            owner: packing::extract_from_word(word, 0, 20)?,
            weight: packing::extract_from_word(word, 20, 1)?,
        })
    }

    fn read_stored_owner_weight(&self, account: Address, owner: Address) -> Result<u8> {
        let (slot, _) = Self::config_owner_lookup_weight_storage_slot(account, owner);
        let word = read_canonical_storage_word(slot, STORED_MULTISIG_WEIGHT_BYTES)?;
        packing::extract_from_word(word, 0, 1)
    }

    fn write_stored_header(
        &mut self,
        account: Address,
        header: StoredMultisigHeader,
    ) -> Result<()> {
        let (slot, _) = Self::account_threshold_storage_slot(account);
        let word = packing::insert_into_word(U256::ZERO, &header.threshold, 0, 1)?;
        let word = packing::insert_into_word(word, &header.owner_count, 1, 1)?;
        let word = packing::insert_into_word(word, &header.version, 2, 8)?;
        write_canonical_storage_word(slot, word)
    }

    fn write_stored_owner(
        &mut self,
        account: Address,
        index: usize,
        owner: StoredMultisigOwner,
    ) -> Result<()> {
        let (slot, _) = Self::config_owner_address_storage_slot(account, index);
        let word = packing::insert_into_word(U256::ZERO, &owner.owner, 0, 20)?;
        let word = packing::insert_into_word(word, &owner.weight, 20, 1)?;
        write_canonical_storage_word(slot, word)
    }

    fn write_stored_owner_weight(
        &mut self,
        account: Address,
        owner: Address,
        weight: u8,
    ) -> Result<()> {
        let (slot, _) = Self::config_owner_lookup_weight_storage_slot(account, owner);
        write_canonical_storage_word(slot, U256::from(weight))
    }
}

fn read_canonical_storage_word(slot: U256, used_bytes: usize) -> Result<U256> {
    let word = StorageCtx.sload(NATIVE_MULTISIG_ADDRESS, slot)?;
    if word >> (used_bytes * 8) != U256::ZERO {
        return Err(NativeMultisigError::invalid_config().into());
    }
    Ok(word)
}

fn write_canonical_storage_word(slot: U256, word: U256) -> Result<()> {
    let mut storage = StorageCtx;
    storage.sstore(NATIVE_MULTISIG_ADDRESS, slot, word)
}

fn parse_multisig_header(header: StoredMultisigHeader) -> Result<ParsedMultisigHeader> {
    match (header.threshold, header.owner_count, header.version) {
        (0, 0, 0) => Ok(ParsedMultisigHeader::Uninitialized),
        (0, _, _) | (_, 0, _) | (_, _, 0) => Err(NativeMultisigError::invalid_config().into()),
        (threshold, owner_count, version) => {
            let owner_count = usize::from(owner_count);
            if owner_count > MAX_MULTISIG_OWNERS {
                return Err(NativeMultisigError::invalid_config().into());
            }
            Ok(ParsedMultisigHeader::Initialized {
                threshold,
                owner_count,
                version,
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
        MultisigConfigError::ZeroWeight | MultisigConfigError::TotalWeightExceedsMax => {
            NativeMultisigError::invalid_weight().into()
        }
        MultisigConfigError::DuplicateOwner => NativeMultisigError::duplicate_owner().into(),
        MultisigConfigError::OwnersNotAscending => {
            NativeMultisigError::invalid_owner_order().into()
        }
        MultisigConfigError::DerivedAccountZero => NativeMultisigError::invalid_account().into(),
    }
}

fn init_config_to_abi(value: InitMultisig, version: u64) -> INativeMultisig::MultisigConfig {
    INativeMultisig::MultisigConfig {
        version,
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
    use tempo_primitives::transaction::{MAX_MULTISIG_SIGNATURES, MAX_MULTISIG_THRESHOLD};

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
        assert_eq!(stored.version, 1);
        assert_eq!(stored.threshold, 1);
        assert_eq!(stored.owners.len(), expected_owners.len());
        for (stored_owner, expected_owner) in stored.owners.iter().zip(expected_owners.iter()) {
            assert_eq!(stored_owner.owner, expected_owner.owner);
            assert_eq!(stored_owner.weight, expected_owner.weight);
        }
        Ok(())
    }

    #[test]
    fn derive_account_matches_initial_config_without_storage_reads() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
        let config = init_config();
        let expected = config.account().unwrap();

        StorageCtx::enter(&mut storage, || {
            let multisig = NativeMultisig::new();
            assert_eq!(
                multisig.derive_account(config.salt, config.threshold, abi_owners())?,
                expected
            );
            Ok::<_, TempoPrecompileError>(())
        })?;

        assert_eq!(storage.counter_sload(), 0);
        assert_eq!(storage.counter_sstore(), 0);
        Ok(())
    }

    #[test]
    fn derive_account_returns_specific_config_errors() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);

        StorageCtx::enter(&mut storage, || {
            let multisig = NativeMultisig::new();
            assert!(matches!(
                multisig.derive_account(B256::ZERO, 1, Vec::new()),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::InvalidOwner(_)
                ))
            ));
            assert!(matches!(
                multisig.derive_account(B256::ZERO, 0, abi_owners()),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::InvalidThreshold(_)
                ))
            ));
            Ok::<_, TempoPrecompileError>(())
        })?;

        assert_eq!(storage.counter_sload(), 0);
        assert_eq!(storage.counter_sstore(), 0);
        Ok(())
    }

    #[test]
    fn store_read_and_update_config() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
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
            let stored = multisig.get_multisig_config(account)?;
            assert_eq!(stored.version, 1);
            assert_eq!(stored.threshold, 1);
            multisig.set_tx_origin(account)?;
            assert!(matches!(
                multisig.update_multisig_config(account, 2, abi_owners()),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::SameTransactionUpdateNotAllowed(_)
                ))
            ));

            Ok::<_, TempoPrecompileError>(())
        })?;
        assert_eq!(storage.counter_sstore(), 1 + 2 * config.owners.len() as u64);

        let (threshold_slot, threshold_offset) =
            NativeMultisig::account_threshold_storage_slot(account);
        let (owner_count_slot, owner_count_offset) =
            NativeMultisig::account_owners_len_storage_slot(account);
        let (version_slot, version_offset) = NativeMultisig::account_version_storage_slot(account);
        assert_eq!(threshold_slot, owner_count_slot);
        assert_eq!(threshold_slot, version_slot);
        assert_eq!(threshold_offset, Some(0));
        assert_eq!(owner_count_offset, Some(1));
        assert_eq!(version_offset, Some(2));

        let mut persistent_slots = std::collections::BTreeSet::from([threshold_slot]);
        for index in 0..config.owners.len() {
            let (owner_slot, _) = NativeMultisig::config_owner_weight_storage_slot(account, index);
            persistent_slots.insert(owner_slot);
        }
        for owner in &config.owners {
            let (owner_slot, _) =
                NativeMultisig::config_owner_lookup_weight_storage_slot(account, owner.owner);
            persistent_slots.insert(owner_slot);
        }
        assert_eq!(persistent_slots.len(), 1 + 2 * config.owners.len());

        storage.clear_transient();
        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.set_tx_origin(account)?;
            multisig.update_multisig_config(account, 2, abi_owners())?;
            let stored = multisig.get_multisig_config(account)?;
            assert_eq!(stored.version, 2);
            assert_eq!(stored.threshold, 2);
            Ok::<_, TempoPrecompileError>(())
        })?;

        Ok(())
    }

    #[test]
    fn update_config_rejects_access_key_authority() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
        let config = init_config();
        let account = config.account().unwrap();

        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.initialize()
        })?;
        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.store_initial_config(account, &config)
        })?;

        // A keychain access-key transaction (nonzero keychain transaction key) must not rotate the
        // owner set, even though tx_origin == msg_sender for a top-level keychain call.
        storage.clear_transient();
        StorageCtx::enter(&mut storage, || {
            AccountKeychain::new().set_transaction_key(Address::repeat_byte(0x77))?;
            let mut multisig = NativeMultisig::new();
            multisig.set_tx_origin(account)?;
            assert!(matches!(
                multisig.update_multisig_config(account, 2, abi_owners()),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::UnauthorizedCaller(_)
                ))
            ));
            Ok::<_, TempoPrecompileError>(())
        })?;

        // Owner-threshold authorization (keychain transaction key stays zero) still succeeds.
        storage.clear_transient();
        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.set_tx_origin(account)?;
            multisig.update_multisig_config(account, 2, abi_owners())?;
            let stored = multisig.get_multisig_config(account)?;
            assert_eq!(stored.version, 2);
            assert_eq!(stored.threshold, 2);
            Ok::<_, TempoPrecompileError>(())
        })?;

        Ok(())
    }

    #[test]
    fn update_config_rejects_version_overflow() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
        let config = init_config();
        let account = config.account().unwrap();

        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.initialize()?;
            multisig.store_initial_config(account, &config)?;
            multisig.accounts[account].write(StoredMultisigHeader {
                threshold: config.threshold,
                owner_count: config.owners.len() as u8,
                version: u64::MAX,
            })?;
            multisig.set_bootstrapped_account(Address::ZERO)?;
            multisig.set_tx_origin(account)?;

            assert!(matches!(
                multisig.update_multisig_config(account, 2, abi_owners()),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::InvalidConfig(_)
                ))
            ));
            assert_eq!(multisig.get_multisig_config(account)?.version, u64::MAX);
            Ok::<_, TempoPrecompileError>(())
        })?;

        Ok(())
    }

    #[test]
    fn store_and_read_max_owner_config() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
        let owners = max_abi_owners();
        let config = InitMultisig {
            salt: B256::ZERO,
            threshold: MAX_MULTISIG_SIGNATURES as u8,
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
            assert_eq!(stored.version, 1);
            assert_eq!(stored.threshold, MAX_MULTISIG_SIGNATURES as u8);
            assert_eq!(stored.owners, owners);
            for owner in &owners {
                assert_eq!(
                    multisig.read_owner_weight(account, owner.owner)?,
                    owner.weight
                );
            }

            Ok::<_, TempoPrecompileError>(())
        })?;

        Ok(())
    }

    #[test]
    fn store_and_read_max_threshold_config() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
        let owner = INativeMultisig::MultisigOwner {
            owner: address!("0000000000000000000000000000000000000011"),
            weight: MAX_MULTISIG_THRESHOLD,
        };
        let config = InitMultisig {
            salt: B256::ZERO,
            threshold: MAX_MULTISIG_THRESHOLD,
            owners: vec![owner.clone().into()],
        };
        let account = config.account().unwrap();

        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.initialize()?;
            multisig.store_initial_config(account, &config)?;

            let stored = multisig.get_multisig_config(account)?;
            assert_eq!(stored.threshold, MAX_MULTISIG_THRESHOLD);
            assert_eq!(stored.owners, vec![owner]);
            Ok::<_, TempoPrecompileError>(())
        })?;

        Ok(())
    }

    #[test]
    fn get_multisig_config_reads_header_once() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
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
                ..Default::default()
            })?;
            Ok::<_, TempoPrecompileError>(())
        })?;

        storage.reset_counters();
        StorageCtx::enter(&mut storage, || {
            let multisig = NativeMultisig::new();
            let stored = multisig.get_multisig_config(account)?;
            assert_eq!(stored.version, 1);
            assert_eq!(stored.threshold, config.threshold);
            assert_eq!(stored.owners.len(), config.owners.len());
            Ok::<_, TempoPrecompileError>(())
        })?;
        assert_eq!(
            storage.counter_sload(),
            1 + 2 * config.owners.len() as u64,
            "registered config should read one header plus each owner row and direct weight"
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
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
        let config = init_config();
        let account = config.account().unwrap();
        let empty_account = Address::repeat_byte(0x42);
        let partial_account = Address::repeat_byte(0x43);
        let version_only_account = Address::repeat_byte(0x44);
        let zero_version_account = Address::repeat_byte(0x45);

        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.initialize()?;
            multisig.store_initial_config(account, &config)?;
            multisig.accounts[partial_account].write(StoredMultisigHeader {
                threshold: 1,
                owner_count: 0,
                ..Default::default()
            })?;
            multisig.accounts[version_only_account].write(StoredMultisigHeader {
                version: 1,
                ..Default::default()
            })?;
            multisig.accounts[zero_version_account].write(StoredMultisigHeader {
                threshold: 1,
                owner_count: 1,
                version: 0,
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
            assert!(matches!(
                multisig.is_multisig_account(version_only_account),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::InvalidConfig(_)
                ))
            ));
            assert!(matches!(
                multisig.is_multisig_account(zero_version_account),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::InvalidConfig(_)
                ))
            ));
            Ok::<_, TempoPrecompileError>(())
        })?;

        Ok(())
    }

    #[test]
    fn is_multisig_account_reads_only_the_header() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
        let missing_owner_account = Address::repeat_byte(0x42);
        let mismatched_weight_account = Address::repeat_byte(0x43);
        let owner = StoredMultisigOwner {
            owner: Address::repeat_byte(0x11),
            weight: 1,
        };

        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.initialize()?;
            multisig.accounts[missing_owner_account].write(StoredMultisigHeader {
                threshold: 1,
                owner_count: 1,
                version: 1,
            })?;
            multisig.accounts[mismatched_weight_account].write(StoredMultisigHeader {
                threshold: 1,
                owner_count: 1,
                version: 1,
            })?;
            multisig.owners[mismatched_weight_account][0].write(owner.clone())?;
            multisig.owner_weights[mismatched_weight_account][owner.owner].write(2)?;
            Ok::<_, TempoPrecompileError>(())
        })?;

        StorageCtx::enter(&mut storage, || {
            let multisig = NativeMultisig::new();
            for account in [missing_owner_account, mismatched_weight_account] {
                assert!(multisig.is_multisig_account(account)?);
                assert!(matches!(
                    multisig.load_registered_init(account),
                    Err(TempoPrecompileError::NativeMultisigError(
                        NativeMultisigError::InvalidConfig(_)
                    ))
                ));
            }
            Ok::<_, TempoPrecompileError>(())
        })?;

        Ok(())
    }

    #[test]
    fn stored_config_rejects_nonzero_reserved_bits() -> eyre::Result<()> {
        let config = init_config();
        let account = config.account().unwrap();
        let owner = config.owners[0].owner;
        let corrupted_slots = [
            NativeMultisig::account_threshold_storage_slot(account).0,
            NativeMultisig::config_owner_address_storage_slot(account, 0).0,
            NativeMultisig::config_owner_lookup_weight_storage_slot(account, owner).0,
        ];

        for (index, corrupted_slot) in corrupted_slots.into_iter().enumerate() {
            let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
            StorageCtx::enter(&mut storage, || {
                let mut multisig = NativeMultisig::new();
                multisig.initialize()?;
                multisig.store_initial_config(account, &config)?;
                let word = StorageCtx.sload(NATIVE_MULTISIG_ADDRESS, corrupted_slot)?;
                let mut storage = StorageCtx;
                storage.sstore(
                    NATIVE_MULTISIG_ADDRESS,
                    corrupted_slot,
                    word | (U256::ONE << 255),
                )
            })?;

            StorageCtx::enter(&mut storage, || {
                let multisig = NativeMultisig::new();
                if index == 0 {
                    assert!(matches!(
                        multisig.is_multisig_account(account),
                        Err(TempoPrecompileError::NativeMultisigError(
                            NativeMultisigError::InvalidConfig(_)
                        ))
                    ));
                } else {
                    assert!(multisig.is_multisig_account(account)?);
                    assert!(matches!(
                        multisig.load_registered_init(account),
                        Err(TempoPrecompileError::NativeMultisigError(
                            NativeMultisigError::InvalidConfig(_)
                        ))
                    ));
                }
                Ok::<_, TempoPrecompileError>(())
            })?;
        }

        Ok(())
    }

    #[test]
    fn bootstrap_clears_reserved_bits_from_owner_storage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
        let config = init_config();
        let account = config.account().unwrap();
        let owner_slot = NativeMultisig::config_owner_address_storage_slot(account, 0).0;
        let weight_slot = NativeMultisig::config_owner_lookup_weight_storage_slot(
            account,
            config.owners[0].owner,
        )
        .0;

        StorageCtx::enter(&mut storage, || {
            let mut storage = StorageCtx;
            storage.sstore(NATIVE_MULTISIG_ADDRESS, owner_slot, U256::ONE << 255)?;
            storage.sstore(NATIVE_MULTISIG_ADDRESS, weight_slot, U256::ONE << 255)?;

            let mut multisig = NativeMultisig::new();
            multisig.initialize()?;
            multisig.store_initial_config(account, &config)?;
            assert!(multisig.is_multisig_account(account)?);
            assert_eq!(
                StorageCtx.sload(NATIVE_MULTISIG_ADDRESS, owner_slot)?
                    >> (STORED_MULTISIG_OWNER_BYTES * 8),
                U256::ZERO
            );
            assert_eq!(
                StorageCtx.sload(NATIVE_MULTISIG_ADDRESS, weight_slot)?
                    >> (STORED_MULTISIG_WEIGHT_BYTES * 8),
                U256::ZERO
            );
            Ok::<_, TempoPrecompileError>(())
        })?;

        Ok(())
    }

    #[test]
    fn invalid_update_does_not_deactivate_multisig() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
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
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
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
                multisig.update_multisig_config(account, MAX_MULTISIG_THRESHOLD, overweight_owners),
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
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
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
                threshold: MAX_MULTISIG_THRESHOLD,
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
