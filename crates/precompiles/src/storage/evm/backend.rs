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

pub(super) trait EvmJournalBackend {
    /// Sets bytecode and returns whether the account was empty before the write.
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

    fn sload(
        &mut self,
        address: Address,
        key: U256,
        skip_cold_load: bool,
    ) -> Result<StateLoad<U256>, TempoPrecompileError>;

    fn sstore(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
        skip_cold_load: bool,
    ) -> Result<StateLoad<SStoreResult>, TempoPrecompileError>;

    fn tload(&mut self, address: Address, key: U256) -> U256;
    fn tstore(&mut self, address: Address, key: U256, value: U256);
    fn log(&mut self, log: Log);
    fn checkpoint(&mut self) -> JournalCheckpoint;
    fn checkpoint_commit(&mut self);
    fn checkpoint_revert(&mut self, checkpoint: JournalCheckpoint);
}

impl EvmJournalBackend for EvmInternals<'_> {
    fn set_code(&mut self, address: Address, code: Bytecode) -> Result<bool, TempoPrecompileError> {
        let mut account = self.load_account_mut(address)?;
        let was_empty = account.data.account().info.is_empty();
        account.set_code_and_hash_slow(code);
        Ok(was_empty)
    }

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

    fn tload(&mut self, address: Address, key: U256) -> U256 {
        EvmInternals::tload(self, address, key)
    }

    fn tstore(&mut self, address: Address, key: U256, value: U256) {
        EvmInternals::tstore(self, address, key, value);
    }

    fn log(&mut self, log: Log) {
        EvmInternals::log(self, log);
    }

    fn checkpoint(&mut self) -> JournalCheckpoint {
        EvmInternals::checkpoint(self)
    }

    fn checkpoint_commit(&mut self) {
        EvmInternals::checkpoint_commit(self);
    }

    fn checkpoint_revert(&mut self, checkpoint: JournalCheckpoint) {
        EvmInternals::checkpoint_revert(self, checkpoint);
    }
}

impl<J> EvmJournalBackend for &mut J
where
    J: JournalTr<Database: Database> + Debug,
{
    fn set_code(&mut self, address: Address, code: Bytecode) -> Result<bool, TempoPrecompileError> {
        let mut account = self.load_account_mut(address).map_err(db_error)?;
        let was_empty = account.data.account().info.is_empty();
        account.set_code_and_hash_slow(code);
        Ok(was_empty)
    }

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

    fn tload(&mut self, address: Address, key: U256) -> U256 {
        JournalTr::tload(*self, address, key)
    }

    fn tstore(&mut self, address: Address, key: U256, value: U256) {
        JournalTr::tstore(*self, address, key, value);
    }

    fn log(&mut self, log: Log) {
        JournalTr::log(*self, log);
    }

    fn checkpoint(&mut self) -> JournalCheckpoint {
        JournalTr::checkpoint(*self)
    }

    fn checkpoint_commit(&mut self) {
        JournalTr::checkpoint_commit(*self);
    }

    fn checkpoint_revert(&mut self, checkpoint: JournalCheckpoint) {
        JournalTr::checkpoint_revert(*self, checkpoint);
    }
}

fn db_error(error: impl std::fmt::Display) -> TempoPrecompileError {
    TempoPrecompileError::Fatal(error.to_string())
}

fn journal_load_error<E: std::fmt::Display>(error: JournalLoadError<E>) -> TempoPrecompileError {
    match error {
        JournalLoadError::DBError(error) => db_error(error),
        JournalLoadError::ColdLoadSkipped => TempoPrecompileError::OutOfGas,
    }
}
