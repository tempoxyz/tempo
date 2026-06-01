//! Native multisig account precompile.

pub mod dispatch;

pub use tempo_contracts::precompiles::INativeMultisig;
use tempo_contracts::precompiles::{
    INativeMultisig::SignatureType as AbiSignatureType, NATIVE_MULTISIG_ADDRESS,
    NativeMultisigError, NativeMultisigEvent,
};
use tempo_precompiles_macros::{Storable, contract};
use tempo_primitives::transaction::{
    InitMultisig, MAX_MULTISIG_OWNERS, MultisigOwner, SignatureType, derive_multisig_account,
    derive_multisig_config_id, is_valid_multisig_account, validate_multisig_config,
};

use crate::{
    error::Result,
    storage::{Handler, Mapping},
};
use alloy::primitives::{Address, B256};

#[repr(u8)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Storable)]
pub enum StoredSignatureType {
    #[default]
    Secp256k1,
    P256,
    WebAuthn,
}

impl From<SignatureType> for StoredSignatureType {
    fn from(value: SignatureType) -> Self {
        match value {
            SignatureType::Secp256k1 => Self::Secp256k1,
            SignatureType::P256 => Self::P256,
            SignatureType::WebAuthn => Self::WebAuthn,
        }
    }
}

impl From<StoredSignatureType> for SignatureType {
    fn from(value: StoredSignatureType) -> Self {
        match value {
            StoredSignatureType::Secp256k1 => Self::Secp256k1,
            StoredSignatureType::P256 => Self::P256,
            StoredSignatureType::WebAuthn => Self::WebAuthn,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Storable)]
pub struct StoredMultisigOwner {
    pub signature_type: StoredSignatureType,
    pub owner: Address,
    pub weight: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Storable)]
pub struct StoredMultisigConfig {
    pub threshold: u32,
    pub owners: Vec<StoredMultisigOwner>,
}

/// Native multisig account storage.
#[contract(addr = NATIVE_MULTISIG_ADDRESS)]
pub struct NativeMultisig {
    // account -> permanent config_id.
    config_ids: Mapping<Address, B256>,
    // account -> config_id -> current config.
    configs: Mapping<Address, Mapping<B256, StoredMultisigConfig>>,
    // Explicit marker so a non-multisig address can return zero config_id without ambiguity.
    accounts: Mapping<Address, bool>,

    // WARNING: transient storage slots must remain at the end.
    tx_origin: Address,
    bootstrapped_account: Address,
}

impl NativeMultisig {
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    pub fn set_tx_origin(&mut self, origin: Address) -> Result<()> {
        self.tx_origin.t_write(origin)
    }

    pub fn set_bootstrapped_account(&mut self, account: Address) -> Result<()> {
        self.bootstrapped_account.t_write(account)
    }

    pub fn is_multisig_account(&self, account: Address) -> Result<bool> {
        self.accounts[account].read()
    }

    pub fn get_multisig_config_id(&self, account: Address) -> Result<B256> {
        if !self.is_multisig_account(account)? {
            return Ok(B256::ZERO);
        }

        let config_id = self.config_ids[account].read()?;
        if config_id == B256::ZERO {
            return Err(NativeMultisigError::config_not_found().into());
        }
        Ok(config_id)
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

    pub fn load_current_config(&self, account: Address, config_id: B256) -> Result<InitMultisig> {
        let stored = self.load_stored_config(account, config_id)?;
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
        if self.is_multisig_account(account)? {
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
        if existing.threshold != 0 {
            return Err(NativeMultisigError::account_already_initialized().into());
        }

        self.accounts[account].write(true)?;
        self.config_ids[account].write(config_id)?;
        self.configs[account][config_id].write(config.into())?;
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

        self.configs[msg_sender][config_id].write((&init_config).into())?;
        self.emit_event(NativeMultisigEvent::multisig_config_updated(
            msg_sender,
            config_id,
            threshold,
            event_owners,
        ))
    }

    fn require_initialized(&self, account: Address) -> Result<B256> {
        if !self.is_multisig_account(account)? {
            return Err(NativeMultisigError::not_multisig_account().into());
        }
        let config_id = self.config_ids[account].read()?;
        if config_id == B256::ZERO {
            return Err(NativeMultisigError::config_not_found().into());
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

        let stored = self.configs[account][config_id].read()?;
        if stored.threshold == 0 {
            return Err(NativeMultisigError::config_not_found().into());
        }
        Ok(stored)
    }
}

impl From<&InitMultisig> for StoredMultisigConfig {
    fn from(value: &InitMultisig) -> Self {
        Self {
            threshold: value.threshold,
            owners: value.owners.iter().map(Into::into).collect(),
        }
    }
}

impl From<&MultisigOwner> for StoredMultisigOwner {
    fn from(value: &MultisigOwner) -> Self {
        Self {
            signature_type: value.signature_type.into(),
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
    let config = InitMultisig { threshold, owners };
    validate_multisig_config(&config).map_err(|_| NativeMultisigError::invalid_config())?;
    Ok(config)
}

fn abi_owner_to_init(value: INativeMultisig::MultisigOwner) -> Result<MultisigOwner> {
    Ok(MultisigOwner {
        signature_type: abi_signature_type(value.signatureType)?,
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
        abi_signature_type(owner.signatureType)?;
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
            .ok_or_else(|| NativeMultisigError::invalid_weight())?;
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
        threshold: value.threshold,
        owners,
    };
    validate_multisig_config(&config).map_err(|_| NativeMultisigError::invalid_config())?;
    Ok(config)
}

fn stored_owner_to_init(value: StoredMultisigOwner) -> MultisigOwner {
    MultisigOwner {
        signature_type: value.signature_type.into(),
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
        signatureType: stored_signature_type(value.signature_type),
        owner: value.owner,
        weight: value.weight,
    }
}

fn abi_signature_type(value: AbiSignatureType) -> Result<SignatureType> {
    match value {
        AbiSignatureType::Secp256k1 => Ok(SignatureType::Secp256k1),
        AbiSignatureType::P256 => Ok(SignatureType::P256),
        AbiSignatureType::WebAuthn => Ok(SignatureType::WebAuthn),
        _ => Err(NativeMultisigError::invalid_signature_type().into()),
    }
}

fn stored_signature_type(value: StoredSignatureType) -> AbiSignatureType {
    match value {
        StoredSignatureType::Secp256k1 => AbiSignatureType::Secp256k1,
        StoredSignatureType::P256 => AbiSignatureType::P256,
        StoredSignatureType::WebAuthn => AbiSignatureType::WebAuthn,
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
            threshold: 1,
            owners: vec![
                MultisigOwner {
                    signature_type: SignatureType::Secp256k1,
                    owner: address!("0000000000000000000000000000000000000011"),
                    weight: 1,
                },
                MultisigOwner {
                    signature_type: SignatureType::Secp256k1,
                    owner: address!("0000000000000000000000000000000000000022"),
                    weight: 1,
                },
            ],
        }
    }

    fn abi_owners() -> Vec<INativeMultisig::MultisigOwner> {
        vec![
            INativeMultisig::MultisigOwner {
                signatureType: AbiSignatureType::Secp256k1,
                owner: address!("0000000000000000000000000000000000000011"),
                weight: 1,
            },
            INativeMultisig::MultisigOwner {
                signatureType: AbiSignatureType::Secp256k1,
                owner: address!("0000000000000000000000000000000000000022"),
                weight: 1,
            },
        ]
    }

    #[test]
    fn store_read_and_update_config() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        let config = init_config();
        let config_id = config.config_id().unwrap();
        let account = config.account().unwrap();

        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.initialize()?;
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
    fn update_config_validates_explicit_config_id() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
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
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
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
