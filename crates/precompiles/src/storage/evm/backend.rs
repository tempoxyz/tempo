use alloy::primitives::{Address, Log, U256};
use alloy_evm::{Database, EvmInternals};
use revm::{
    context::{
        JournalTr,
        journaled_state::{JournalCheckpoint, JournalLoadError, account::JournaledAccountTr},
    },
    interpreter::{SStoreResult, StateLoad},
    state::{AccountInfo, Bytecode},
};
use std::fmt::Debug;

use crate::error::TempoPrecompileError;

/// Minimal journal-facing backend used by [`super::EvmPrecompileStorageProvider`].
pub(super) trait EvmJournalBackend {
    /// Sets account bytecode and returns whether the account was empty before the write.
    fn set_code(&mut self, address: Address, code: Bytecode) -> Result<bool, TempoPrecompileError>;

    /// Loads account info, charges account-access gas after account load but before code load,
    /// then invokes `f` with the loaded info.
    fn with_account_info(
        &mut self,
        address: Address,
        skip_cold_load: bool,
        charge_account_access: impl FnMut(bool) -> Result<(), TempoPrecompileError>,
        f: &mut dyn FnMut(&AccountInfo),
    ) -> Result<(), TempoPrecompileError>;

    /// Loads a storage slot, preserving revm's cold/warm access metadata for gas accounting.
    fn sload(
        &mut self,
        address: Address,
        key: U256,
        skip_cold_load: bool,
    ) -> Result<StateLoad<U256>, TempoPrecompileError>;

    /// Stores a storage slot and returns revm's storage-write metadata for gas accounting.
    fn sstore(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
        skip_cold_load: bool,
    ) -> Result<StateLoad<SStoreResult>, TempoPrecompileError>;

    /// Loads a transient storage slot.
    fn tload(&mut self, address: Address, key: U256) -> U256;

    /// Stores a transient storage slot.
    fn tstore(&mut self, address: Address, key: U256, value: U256);

    /// Appends an EVM log to the current journal.
    fn log(&mut self, log: Log);

    /// Creates a journal checkpoint for later commit or revert.
    fn checkpoint(&mut self) -> JournalCheckpoint;

    /// Commits the most recent journal checkpoint.
    fn checkpoint_commit(&mut self);

    /// Reverts the journal to `checkpoint`.
    fn checkpoint_revert(&mut self, checkpoint: JournalCheckpoint);
}

impl EvmJournalBackend for EvmInternals<'_> {
    #[inline]
    fn set_code(&mut self, address: Address, code: Bytecode) -> Result<bool, TempoPrecompileError> {
        let mut account = self.load_account_mut(address)?;
        let was_empty = account.data.account().info.is_empty();
        account.set_code_and_hash_slow(code);
        Ok(was_empty)
    }
    #[inline]
    fn with_account_info(
        &mut self,
        address: Address,
        skip_cold_load: bool,
        mut charge_account_access: impl FnMut(bool) -> Result<(), TempoPrecompileError>,
        f: &mut dyn FnMut(&AccountInfo),
    ) -> Result<(), TempoPrecompileError> {
        let mut account = self.load_account_mut_skip_cold_load(address, skip_cold_load)?;
        charge_account_access(account.is_cold)?;
        account.load_code()?;
        f(&account.data.account().info);
        Ok(())
    }
    #[inline]
    fn sload(
        &mut self,
        address: Address,
        key: U256,
        skip_cold_load: bool,
    ) -> Result<StateLoad<U256>, TempoPrecompileError> {
        let mut account = self.load_account_mut(address)?;
        Ok(account
            .sload(key, skip_cold_load)?
            .map(|slot| slot.present_value))
    }
    #[inline]
    fn sstore(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
        skip_cold_load: bool,
    ) -> Result<StateLoad<SStoreResult>, TempoPrecompileError> {
        Ok(self
            .load_account_mut(address)?
            .sstore(key, value, skip_cold_load)?)
    }
    #[inline]
    fn tload(&mut self, address: Address, key: U256) -> U256 {
        EvmInternals::tload(self, address, key)
    }
    #[inline]
    fn tstore(&mut self, address: Address, key: U256, value: U256) {
        EvmInternals::tstore(self, address, key, value);
    }
    #[inline]
    fn log(&mut self, log: Log) {
        EvmInternals::log(self, log);
    }
    #[inline]
    fn checkpoint(&mut self) -> JournalCheckpoint {
        EvmInternals::checkpoint(self)
    }
    #[inline]
    fn checkpoint_commit(&mut self) {
        EvmInternals::checkpoint_commit(self);
    }
    #[inline]
    fn checkpoint_revert(&mut self, checkpoint: JournalCheckpoint) {
        EvmInternals::checkpoint_revert(self, checkpoint);
    }
}

impl<J> EvmJournalBackend for &mut J
where
    J: JournalTr<Database: Database> + Debug,
{
    #[inline]
    fn set_code(&mut self, address: Address, code: Bytecode) -> Result<bool, TempoPrecompileError> {
        let mut account = self.load_account_mut(address).map_err(db_error)?;
        let was_empty = account.data.account().info.is_empty();
        account.set_code_and_hash_slow(code);
        Ok(was_empty)
    }
    #[inline]
    fn with_account_info(
        &mut self,
        address: Address,
        skip_cold_load: bool,
        mut charge_account_access: impl FnMut(bool) -> Result<(), TempoPrecompileError>,
        f: &mut dyn FnMut(&AccountInfo),
    ) -> Result<(), TempoPrecompileError> {
        let mut account = self
            .load_account_mut_skip_cold_load(address, skip_cold_load)
            .map_err(journal_load_error)?;
        charge_account_access(account.is_cold)?;
        account.load_code()?;
        f(&account.data.account().info);
        Ok(())
    }
    #[inline]
    fn sload(
        &mut self,
        address: Address,
        key: U256,
        skip_cold_load: bool,
    ) -> Result<StateLoad<U256>, TempoPrecompileError> {
        let mut account = self.load_account_mut(address).map_err(db_error)?;
        Ok(account
            .sload(key, skip_cold_load)?
            .map(|slot| slot.present_value))
    }
    #[inline]
    fn sstore(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
        skip_cold_load: bool,
    ) -> Result<StateLoad<SStoreResult>, TempoPrecompileError> {
        Ok(self
            .load_account_mut(address)
            .map_err(db_error)?
            .sstore(key, value, skip_cold_load)?)
    }
    #[inline]
    fn tload(&mut self, address: Address, key: U256) -> U256 {
        JournalTr::tload(*self, address, key)
    }
    #[inline]
    fn tstore(&mut self, address: Address, key: U256, value: U256) {
        JournalTr::tstore(*self, address, key, value);
    }
    #[inline]
    fn log(&mut self, log: Log) {
        JournalTr::log(*self, log);
    }
    #[inline]
    fn checkpoint(&mut self) -> JournalCheckpoint {
        JournalTr::checkpoint(*self)
    }
    #[inline]
    fn checkpoint_commit(&mut self) {
        JournalTr::checkpoint_commit(*self);
    }
    #[inline]
    fn checkpoint_revert(&mut self, checkpoint: JournalCheckpoint) {
        JournalTr::checkpoint_revert(*self, checkpoint);
    }
}

#[inline]
fn db_error(error: impl std::fmt::Display) -> TempoPrecompileError {
    TempoPrecompileError::Fatal(error.to_string())
}

#[inline]
fn journal_load_error<E: std::fmt::Display>(error: JournalLoadError<E>) -> TempoPrecompileError {
    match error {
        JournalLoadError::DBError(error) => db_error(error),
        JournalLoadError::ColdLoadSkipped => TempoPrecompileError::OutOfGas,
    }
}
