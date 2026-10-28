//! View calls against the harness's state after a step or, with its transitions undone, before it.

use std::fmt::{self, Debug, Display};

use alloy_evm::{Evm as _, EvmEnv};
use alloy_primitives::{Address, B256, Bytes, U256};
use invariants_core::Views;
use revm::{
    DatabaseRef, bytecode::Bytecode, database::TransitionState,
    database_interface::WrapDatabaseRef, state::AccountInfo,
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_evm::evm::TempoEvm;
use tempo_primitives::TempoBlockEnv;

use crate::state::{Db, PreStateDb};

/// Read-only calls against the state `D` holds, noting reads the seeded pre-state misses.
pub(super) struct EvmViews<'a, D: DatabaseRef + Debug> {
    evm: TempoEvm<WrapDatabaseRef<D>>,
    pre_state: &'a PreStateDb,
}

impl<'a, D: DatabaseRef + Debug> EvmViews<'a, D> {
    pub(super) fn new(
        db: D,
        env: &EvmEnv<TempoHardfork, TempoBlockEnv>,
        pre_state: &'a PreStateDb,
    ) -> Self {
        Self {
            evm: TempoEvm::new(WrapDatabaseRef(db), env.clone()),
            pre_state,
        }
    }

    fn pre_state(&self) -> &PreStateDb {
        self.pre_state
    }

    /// `input`'s output from `target`. `Ok(None)` when nothing answers: `target` has no code, or
    /// the call read a key the pre-state lacks. `Err` when the call reverts or halts.
    fn call_one(&mut self, target: Address, input: &Bytes) -> Result<Option<Bytes>, ViewFailed> {
        let selector = input
            .get(..4)
            .map(Bytes::copy_from_slice)
            .unwrap_or_default();
        self.pre_state().restore_missed(false);
        let result = self
            .evm
            .transact_system_call(Address::ZERO, target, input.clone());
        if self.pre_state().missed() {
            return Ok(None);
        }
        let failed = |reason| ViewFailed {
            selector: selector.clone(),
            target,
            reason,
        };
        let result = result.map_err(|err| failed(err.to_string()))?.result;
        if !result.is_success() {
            return Err(failed(format!("{result:?}")));
        }
        Ok(result.output().filter(|output| !output.is_empty()).cloned())
    }
}

impl<D: DatabaseRef + Debug> Views for EvmViews<'_, D> {
    type Error = ViewFailed;

    fn call(&mut self, calls: &[(Address, Bytes)]) -> Result<Vec<Option<Bytes>>, ViewFailed> {
        calls
            .iter()
            .map(|(target, input)| self.call_one(*target, input))
            .collect()
    }

    /// The seeded pre-state may hold only the accounts and slots execution touched.
    fn partial(&self) -> bool {
        true
    }
}

/// The state before a step: `db` with the step's `transitions` undone.
#[derive(Debug)]
pub(super) struct PreView<'a> {
    pub(super) db: &'a Db,
    pub(super) transitions: &'a TransitionState,
}

impl DatabaseRef for PreView<'_> {
    type Error = <Db as DatabaseRef>::Error;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        match self.transitions.transitions.get(&address) {
            Some(account) => Ok(account.previous_info.clone()),
            None => self.db.basic_ref(address),
        }
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.db.code_by_hash_ref(code_hash)
    }

    fn storage_ref(&self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        if let Some(account) = self.transitions.transitions.get(&address) {
            if let Some(value) = account.storage.get(&slot) {
                return Ok(value.original_value());
            }
            if account.previous_info.is_none() {
                return Ok(U256::ZERO);
            }
        }
        self.db.storage_ref(address, slot)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        self.db.block_hash_ref(number)
    }
}

/// A view call that reverted, halted or could not run.
#[derive(Debug)]
pub(super) struct ViewFailed {
    selector: Bytes,
    target: Address,
    reason: String,
}

impl Display for ViewFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} on {}: {}", self.selector, self.target, self.reason)
    }
}
