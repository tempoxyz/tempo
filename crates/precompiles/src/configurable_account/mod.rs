//! Configurable account management and protocol account code.

pub mod dispatch;
pub mod shim;

use crate::{
    error::{Result, TempoPrecompileError},
    storage::{ConfigCommitmentWriteGas, Handler, account_config_commitment},
};
use alloy::primitives::{Address, B256, Bytes, KECCAK256_EMPTY, b256};
pub use tempo_chainspec::is_valid_native_account as valid_account;
use tempo_contracts::precompiles::{
    CONFIGURABLE_ACCOUNT_ADDRESS, ConfigurableAccountError, ConfigurableAccountEvent,
    IConfigurableAccount,
};
use tempo_precompiles_macros::{Storable, contract};
use tempo_primitives::transaction::{
    ConfigurableAccountConfig, ConfigurableAccountOwner,
    configurable_account::CONFIGURABLE_ACCOUNT_UPGRADE_DOMAIN,
};

/// Shared protocol-installed code for registered configurable accounts.
pub const CONFIGURABLE_ACCOUNT_CODE: Bytes = Bytes::from_static(&[0xef]);

/// Keccak-256 of [`CONFIGURABLE_ACCOUNT_CODE`], compared without loading code bytes.
pub const CONFIGURABLE_ACCOUNT_CODE_HASH: B256 =
    b256!("309b8896ee4c1ff7ec1966155373dee42663b6b40c3fedc70ba501684848d2a3");

/// Configurable account precompile.
///
/// Every field is transient transaction context, seeded by the handler before execution.
#[contract(addr = CONFIGURABLE_ACCOUNT_ADDRESS)]
pub struct ConfigurableAccount {
    // WARNING: transient storage slots must always be placed at the very end until the `contract`
    // macro is refactored and has 2 independent layouts (persistent and transient).
    // If new (persistent) storage fields need to be added to the precompile, they must go above
    // the fields below.
    tx_origin: Address,
    directly_authorized_account: Address,
    upgrade_eligibility: UpgradeEligibility,
}

impl ConfigurableAccount {
    /// Seeds only the direct outer owner-quorum authority, never a delegate or sponsor, and
    /// whether the transaction may migrate its sender.
    pub fn set_authority(
        &mut self,
        origin: Address,
        directly_authorized: Address,
        upgrade_eligibility: UpgradeEligibility,
    ) -> Result<()> {
        self.tx_origin.t_write(origin)?;
        self.directly_authorized_account
            .t_write(directly_authorized)?;
        self.upgrade_eligibility.t_write(upgrade_eligibility)
    }

    fn derive_account(
        &self,
        salt: B256,
        threshold: u8,
        owners: &[IConfigurableAccount::ConfigurableAccountOwner],
    ) -> Result<Address> {
        let config = config(salt, 0, threshold, owners);
        // Reject an invalid configuration before charging the derivation gas.
        config.validate()?;
        self.storage.deduct_gas(
            config
                .derivation_gas()
                .ok_or(TempoPrecompileError::OutOfGas)?,
        )?;
        let account = config.derive_account()?;
        if !valid_account(account, self.storage.spec()) {
            return Err(ConfigurableAccountError::invalid_account().into());
        }
        Ok(account)
    }

    fn get_config_commitment(&self, account: Address) -> Result<B256> {
        self.storage.config_commitment(account)
    }

    fn update_config(
        &mut self,
        sender: Address,
        current: &IConfigurableAccount::ConfigurableAccountConfig,
        threshold: u8,
        owners: Vec<IConfigurableAccount::ConfigurableAccountOwner>,
    ) -> Result<()> {
        // The wrapper rejects delegatecall. `directly_authorized_account` is seeded only with the
        // account of the transaction's outer owner quorum, which validation binds to the
        // transaction caller, so a match with `sender` already implies `sender` is the origin.
        if sender.is_zero() || self.directly_authorized_account.t_read()? != sender {
            return Err(
                ConfigurableAccountError::unauthorized_configurable_account_caller().into(),
            );
        }
        let current = config(
            current.salt,
            current.version,
            current.threshold,
            &current.owners,
        );
        let stored = self.get_config_commitment(sender)?;
        // `current` is not validated: only validated configurations are stored, so an invalid one
        // cannot match the stored hash and is rejected as stale.
        let hash = self.storage.keccak256(
            &current
                .commitment_preimage()
                .map_err(|_| ConfigurableAccountError::invalid_config())?,
        )?;
        if stored != hash {
            return Err(ConfigurableAccountError::invalid_config().into());
        }
        let version = current
            .version
            .checked_add(1)
            .ok_or_else(ConfigurableAccountError::invalid_config)?;
        let next = config(current.salt, version, threshold, &owners);
        next.validate_for_account(sender)?;
        let hash = self.storage.keccak256(&next.commitment_preimage()?)?;
        if hash.is_zero() {
            return Err(ConfigurableAccountError::invalid_config().into());
        }
        self.storage
            .set_config_commitment(sender, hash, ConfigCommitmentWriteGas::Precompile)?;
        self.emit_event(
            ConfigurableAccountEvent::configurable_account_config_updated(
                sender, next.salt, version, threshold, owners,
            ),
        )
    }

    /// Installs a version-one configuration for `sender`, an EOA that signed with its root key.
    ///
    /// Checks fail in TIP-1113's order, so the first failing condition decides the error. The
    /// root key may also be listed as an owner.
    fn upgrade_account(
        &mut self,
        sender: Address,
        threshold: u8,
        owners: Vec<IConfigurableAccount::ConfigurableAccountOwner>,
    ) -> Result<B256> {
        // Only the transaction's own sender may migrate itself.
        if self.tx_origin.t_read()? != sender {
            return Err(ConfigurableAccountError::upgrade_must_be_only_call().into());
        }
        match self.upgrade_eligibility.t_read()? {
            UpgradeEligibility::NotSoleCall => {
                return Err(ConfigurableAccountError::upgrade_must_be_only_call().into());
            }
            UpgradeEligibility::NotPrimitiveRoot => {
                return Err(ConfigurableAccountError::primitive_root_required().into());
            }
            UpgradeEligibility::PrimitiveRoot => {}
        }
        let spec = self.storage.spec();
        let (invalid_code, commitment) = self.storage.with_account_info(sender, |info| {
            let commitment = account_config_commitment(info, spec)?;
            Ok((
                !info.is_empty_code_hash() && !valid_account_code(info.code_hash, commitment),
                commitment,
            ))
        })?;
        if invalid_code {
            return Err(ConfigurableAccountError::account_has_code().into());
        }
        if !commitment.is_zero() {
            return Err(ConfigurableAccountError::account_already_configurable().into());
        }
        let salt = self
            .storage
            .keccak256(&[CONFIGURABLE_ACCOUNT_UPGRADE_DOMAIN, sender.as_slice()].concat())?;
        let upgraded = config(salt, 1, threshold, &owners);
        upgraded
            .validate_for_account(sender)
            .map_err(|_| ConfigurableAccountError::invalid_config())?;
        let hash = self.storage.keccak256(
            &upgraded
                .commitment_preimage()
                .map_err(|_| ConfigurableAccountError::invalid_config())?,
        )?;
        if hash.is_zero() {
            return Err(ConfigurableAccountError::invalid_config().into());
        }
        self.storage
            .set_config_commitment(sender, hash, ConfigCommitmentWriteGas::Precompile)?;
        self.emit_event(ConfigurableAccountEvent::account_upgraded(
            sender, hash, salt, threshold, owners,
        ))?;
        Ok(hash)
    }

    /// One-time storage initialization.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }
}

/// What the transaction allows `upgradeAccount` to do, as decided by the handler before execution.
///
/// Variants are ordered from the most to the least restrictive, so the zero value of an unseeded
/// context rejects every migration.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Storable)]
pub enum UpgradeEligibility {
    /// The transaction is not a lone, direct call to this precompile without authorizations.
    NotSoleCall,
    /// The transaction is a sole call, but its outer signature is not a primitive root signature.
    NotPrimitiveRoot,
    /// The transaction is a sole call signed by a primitive root key.
    PrimitiveRoot,
}

/// Builds the configuration with the given `salt`, `version`, `threshold` and `owners`.
pub fn config(
    salt: B256,
    version: u64,
    threshold: u8,
    owners: &[IConfigurableAccount::ConfigurableAccountOwner],
) -> ConfigurableAccountConfig {
    ConfigurableAccountConfig {
        salt,
        version,
        threshold,
        owners: owners
            .iter()
            .map(|owner| ConfigurableAccountOwner {
                owner: owner.owner,
                weight: owner.weight,
            })
            .collect(),
    }
}

/// Whether code matches the account's registration state.
pub fn valid_account_code(code_hash: B256, commitment: B256) -> bool {
    code_hash
        == if commitment.is_zero() {
            KECCAK256_EMPTY
        } else {
            CONFIGURABLE_ACCOUNT_CODE_HASH
        }
}
