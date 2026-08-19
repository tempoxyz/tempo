//! Native multisig account precompile.

pub mod auth;
pub mod dispatch;

pub use auth::NativeMultisigAuthError;
pub use tempo_contracts::precompiles::INativeMultisig;

use crate::{
    account_keychain::{AccountKeychain, getTransactionKeyCall},
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping, StorageCtx},
};
use alloy::primitives::{Address, B256, TxKind, U256};
use revm::interpreter::gas::{KECCAK256, KECCAK256WORD};
use tempo_contracts::precompiles::{
    NATIVE_MULTISIG_ADDRESS, NativeMultisigError, NativeMultisigEvent,
};
use tempo_precompiles_macros::contract;
use tempo_primitives::transaction::{
    MULTISIG_ACCOUNT_CREATE2_PREIMAGE_LEN, MultisigConfig, MultisigConfigError,
    multisig_account_address,
};

use crate::is_valid_multisig_account;

/// Gas for hashing the fixed-length native multisig CREATE2 preimage.
pub const MULTISIG_ACCOUNT_CREATE2_GAS: u64 =
    KECCAK256 + KECCAK256WORD * MULTISIG_ACCOUNT_CREATE2_PREIMAGE_LEN.div_ceil(32) as u64;

/// Native multisig account storage.
#[contract(addr = NATIVE_MULTISIG_ADDRESS)]
pub struct NativeMultisig {
    /// Latest nonzero configuration commitment. Zero means no update has occurred.
    config_commitments: Mapping<Address, B256>,

    // WARNING: transient storage slots must remain after persistent storage fields until the
    // `contract` macro supports independent persistent/transient layouts.
    tx_origin: Address,
    directly_authorized_account: Address,
}

impl NativeMultisig {
    /// Initializes the precompile storage layout.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Returns the persistent commitment slot for `account`.
    pub fn config_commitment_storage_slot(account: Address) -> U256 {
        Self::new().config_commitments[account].slot()
    }

    /// Seeds the enclosing transaction origin.
    pub fn set_tx_origin(&mut self, origin: Address) -> Result<()> {
        self.tx_origin.t_write(origin)
    }

    /// Records the account directly authorized by the outer multisig signature.
    pub fn set_directly_authorized_account(&mut self, account: Address) -> Result<()> {
        self.directly_authorized_account.t_write(account)
    }

    /// Derives an account from an initial configuration without reading persistent state.
    pub fn derive_account(
        &self,
        salt: B256,
        threshold: u8,
        owners: Vec<INativeMultisig::MultisigOwner>,
    ) -> Result<Address> {
        self.derive_account_from_config(&MultisigConfig {
            salt,
            version: 0,
            threshold,
            owners: owners.into_iter().map(Into::into).collect(),
        })
    }

    /// Returns the persisted configuration commitment, including zero before the first update.
    pub fn get_config_commitment(&self, account: Address) -> Result<B256> {
        self.config_commitments[account].read()
    }

    /// Commits to the caller's next owner configuration.
    pub fn update_multisig_config(
        &mut self,
        msg_sender: Address,
        current: INativeMultisig::MultisigConfig,
        threshold: u8,
        owners: Vec<INativeMultisig::MultisigOwner>,
    ) -> Result<()> {
        self.ensure_update_authorized(msg_sender)?;

        let current = MultisigConfig::from(current);
        current
            .validate_for_account(msg_sender)
            .map_err(map_multisig_config_error)?;
        let stored = self.get_config_commitment(msg_sender)?;
        if current.version == 0 {
            if !stored.is_zero() || self.derive_account_from_config(&current)? != msg_sender {
                return Err(NativeMultisigError::invalid_config().into());
            }
        } else if stored.is_zero() || self.hash_config_commitment(&current)? != stored {
            return Err(NativeMultisigError::invalid_config().into());
        }

        let version = current
            .version
            .checked_add(1)
            .ok_or_else(NativeMultisigError::invalid_config)?;
        let event_owners = owners.clone();
        let next = MultisigConfig {
            salt: current.salt,
            version,
            threshold,
            owners: owners.into_iter().map(Into::into).collect(),
        };
        next.validate_for_account(msg_sender)
            .map_err(map_multisig_config_error)?;
        let commitment = self.hash_config_commitment(&next)?;
        if commitment.is_zero() {
            return Err(NativeMultisigError::invalid_config().into());
        }

        self.config_commitments[msg_sender].write(commitment)?;
        self.emit_event(NativeMultisigEvent::multisig_config_updated(
            msg_sender,
            next.salt,
            next.version,
            next.threshold,
            event_owners,
        ))
    }

    fn ensure_update_authorized(&self, msg_sender: Address) -> Result<()> {
        if StorageCtx.tx_kind() != Some(TxKind::Call(NATIVE_MULTISIG_ADDRESS))
            || self.tx_origin.t_read()? != msg_sender
            || self.directly_authorized_account.t_read()? != msg_sender
        {
            return Err(NativeMultisigError::unauthorized_multisig_caller().into());
        }

        let transaction_key =
            AccountKeychain::new().get_transaction_key(getTransactionKeyCall {}, msg_sender)?;
        if !transaction_key.is_zero() {
            return Err(NativeMultisigError::unauthorized_multisig_caller().into());
        }
        Ok(())
    }

    fn derive_account_from_config(&self, config: &MultisigConfig) -> Result<Address> {
        config.validate().map_err(map_multisig_config_error)?;
        let preimage = config
            .account_salt_preimage()
            .map_err(map_multisig_config_error)?;
        let account_salt = self.storage.keccak256(&preimage)?;
        self.storage.deduct_gas(MULTISIG_ACCOUNT_CREATE2_GAS)?;
        let account = multisig_account_address(account_salt);
        if config.owner_weight(account).is_some() {
            return Err(NativeMultisigError::invalid_multisig_owner().into());
        }
        if !is_valid_multisig_account(account, self.storage.spec()) {
            return Err(NativeMultisigError::invalid_account().into());
        }
        Ok(account)
    }

    fn hash_config_commitment(&self, config: &MultisigConfig) -> Result<B256> {
        let preimage = config
            .commitment_preimage()
            .map_err(map_multisig_config_error)?;
        self.storage.keccak256(&preimage)
    }
}

fn map_multisig_config_error(err: MultisigConfigError) -> TempoPrecompileError {
    match err {
        MultisigConfigError::EmptyOwners
        | MultisigConfigError::ZeroOwner
        | MultisigConfigError::AccountIsOwner => {
            NativeMultisigError::invalid_multisig_owner().into()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::TempoPrecompileError,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
    };
    use alloy::primitives::{IntoLogData, address, keccak256};
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_primitives::transaction::MultisigOwner;

    fn initial_config() -> MultisigConfig {
        MultisigConfig {
            salt: B256::ZERO,
            version: 0,
            threshold: 1,
            owners: vec![MultisigOwner {
                owner: address!("0000000000000000000000000000000000000011"),
                weight: 1,
            }],
        }
    }

    fn abi_config(config: &MultisigConfig) -> INativeMultisig::MultisigConfig {
        config.clone().into()
    }

    fn abi_owners(owner: Address) -> Vec<INativeMultisig::MultisigOwner> {
        vec![INativeMultisig::MultisigOwner { owner, weight: 1 }]
    }

    #[test]
    fn commitment_slot_matches_tip_layout() {
        let account = Address::repeat_byte(0x11);
        let mut preimage = [0u8; 64];
        preimage[12..32].copy_from_slice(account.as_slice());

        assert_eq!(
            NativeMultisig::config_commitment_storage_slot(account),
            U256::from_be_bytes(keccak256(preimage).0)
        );
    }

    #[test]
    fn derive_account_is_stateless() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
        let config = initial_config();
        let expected = config.derive_account().unwrap();

        StorageCtx::enter(&mut storage, || {
            assert_eq!(
                NativeMultisig::new().derive_account(
                    config.salt,
                    config.threshold,
                    config.owners.clone().into_iter().map(Into::into).collect(),
                )?,
                expected
            );
            Ok::<_, TempoPrecompileError>(())
        })?;

        assert_eq!(storage.counter_sload(), 0);
        assert_eq!(storage.counter_sstore(), 0);
        Ok(())
    }

    #[test]
    fn updates_replace_one_commitment_and_emit_config() -> eyre::Result<()> {
        let config = initial_config();
        let account = config.derive_account().unwrap();
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11)
            .with_tx_kind(TxKind::Call(NATIVE_MULTISIG_ADDRESS));

        StorageCtx::enter(&mut storage, || NativeMultisig::new().initialize())?;
        storage.reset_counters();

        let first_owner = address!("0000000000000000000000000000000000000022");
        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.set_tx_origin(account)?;
            multisig.set_directly_authorized_account(account)?;
            multisig.update_multisig_config(
                account,
                abi_config(&config),
                1,
                abi_owners(first_owner),
            )?;
            Ok::<_, TempoPrecompileError>(())
        })?;

        assert_eq!(storage.counter_sstore(), 1);
        let first_event = NativeMultisigEvent::multisig_config_updated(
            account,
            config.salt,
            1,
            1,
            abi_owners(first_owner),
        )
        .into_log_data();
        assert_eq!(
            storage.get_events(NATIVE_MULTISIG_ADDRESS).as_slice(),
            std::slice::from_ref(&first_event)
        );
        let current = MultisigConfig {
            salt: config.salt,
            version: 1,
            threshold: 1,
            owners: vec![MultisigOwner {
                owner: first_owner,
                weight: 1,
            }],
        };
        StorageCtx::enter(&mut storage, || {
            assert_eq!(
                NativeMultisig::new().get_config_commitment(account)?,
                current.commitment().unwrap()
            );
            Ok::<_, TempoPrecompileError>(())
        })?;

        storage.clear_transient();
        storage.reset_counters();
        let second_owner = address!("0000000000000000000000000000000000000033");
        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.set_tx_origin(account)?;
            multisig.set_directly_authorized_account(account)?;
            multisig.update_multisig_config(
                account,
                abi_config(&current),
                1,
                abi_owners(second_owner),
            )
        })?;
        assert_eq!(storage.counter_sstore(), 1);

        let next = MultisigConfig {
            owners: vec![MultisigOwner {
                owner: second_owner,
                weight: 1,
            }],
            version: 2,
            ..current
        };
        StorageCtx::enter(&mut storage, || {
            assert_eq!(
                NativeMultisig::new().get_config_commitment(account)?,
                next.commitment().unwrap()
            );
            Ok::<_, TempoPrecompileError>(())
        })?;
        let second_event = NativeMultisigEvent::multisig_config_updated(
            account,
            next.salt,
            next.version,
            next.threshold,
            abi_owners(second_owner),
        )
        .into_log_data();
        assert_eq!(
            storage.get_events(NATIVE_MULTISIG_ADDRESS).as_slice(),
            &[first_event, second_event]
        );
        Ok(())
    }

    #[test]
    fn update_requires_root_authorized_direct_outer_call() -> eyre::Result<()> {
        let config = initial_config();
        let account = config.derive_account().unwrap();
        let other = Address::repeat_byte(0x44);
        let valid_target = Some(TxKind::Call(NATIVE_MULTISIG_ADDRESS));
        let cases = [
            (
                "missing transaction target",
                None,
                account,
                account,
                Address::ZERO,
            ),
            (
                "wrong transaction target",
                Some(TxKind::Call(other)),
                account,
                account,
                Address::ZERO,
            ),
            (
                "contract-creation transaction",
                Some(TxKind::Create),
                account,
                account,
                Address::ZERO,
            ),
            (
                "different transaction origin",
                valid_target,
                other,
                account,
                Address::ZERO,
            ),
            (
                "different outer authority",
                valid_target,
                account,
                other,
                Address::ZERO,
            ),
            (
                "access-key transaction",
                valid_target,
                account,
                account,
                other,
            ),
        ];

        for (case, tx_kind, origin, directly_authorized, transaction_key) in cases {
            let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
            if let Some(tx_kind) = tx_kind {
                storage = storage.with_tx_kind(tx_kind);
            }
            StorageCtx::enter(&mut storage, || {
                let mut multisig = NativeMultisig::new();
                multisig.set_tx_origin(origin)?;
                multisig.set_directly_authorized_account(directly_authorized)?;
                AccountKeychain::new().set_transaction_key(transaction_key)?;
                assert!(
                    matches!(
                        multisig.update_multisig_config(
                            account,
                            abi_config(&config),
                            1,
                            abi_owners(Address::repeat_byte(0x22)),
                        ),
                        Err(TempoPrecompileError::NativeMultisigError(
                            NativeMultisigError::UnauthorizedMultisigCaller(_)
                        ))
                    ),
                    "{case}"
                );
                Ok::<_, TempoPrecompileError>(())
            })?;
        }
        Ok(())
    }
}
