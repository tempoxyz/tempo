//! View calls against the harness's state after a step or, with its changes undone, before it.

use std::fmt::{self, Display};

use alloy_primitives::{Address, B256, Bytes, U256};
use evm2::{
    bytecode::Bytecode,
    evm::{AccountInfo, SystemTx},
};
use invariants_core::Views;
use reth_evm::{ConfigureEvm as _, Database};
use tempo_evm::{TempoEvm, TempoEvmConfig, TempoEvmEnv};

use crate::state::{Net, PreStateDb, Reader};

/// Read-only calls against the state an EVM reads, noting reads the seeded pre-state misses.
pub(super) struct EvmViews<'a> {
    evm: TempoEvm<'a>,
    pre_state: &'a PreStateDb,
}

impl<'a> EvmViews<'a> {
    pub(super) fn new(
        db: impl Database + 'a,
        evm_config: &TempoEvmConfig,
        env: TempoEvmEnv,
        pre_state: &'a PreStateDb,
    ) -> Self {
        Self {
            evm: evm_config.evm_with_env(db, env),
            pre_state,
        }
    }

    /// `input`'s output from `target`. `Ok(None)` when nothing answers: `target` has no code, or
    /// the call read a key the pre-state lacks. `Err` when the call reverts or halts.
    fn call_one(&mut self, target: Address, input: &Bytes) -> Result<Option<Bytes>, ViewFailed> {
        let selector = input
            .get(..4)
            .map(Bytes::copy_from_slice)
            .unwrap_or_default();
        self.pre_state.restore_missed(false);
        let result = self
            .evm
            .system_call(SystemTx::new(target, input.clone()).with_caller(Address::ZERO));
        if self.pre_state.missed() {
            return Ok(None);
        }
        let failed = |reason| ViewFailed {
            selector: selector.clone(),
            target,
            reason,
        };
        let executed = result.map_err(|err| failed(err.to_string()))?;
        let result = executed.result();
        if !result.is_success() {
            return Err(failed(format!("{result:?}")));
        }
        Ok(Some(result.output.clone()).filter(|output| !output.is_empty()))
    }
}

impl Views for EvmViews<'_> {
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

/// The state before a step: what `reader` reads, with the step's `net` changes undone.
pub(super) struct PreView<'a> {
    pub(super) reader: Reader<'a>,
    pub(super) net: &'a Net,
}

impl Database for PreView<'_> {
    type Error = <Reader<'static> as Database>::Error;

    fn is_fatal(_error: &Self::Error) -> bool {
        false
    }

    fn get_account(&mut self, address: &Address) -> Result<Option<AccountInfo>, Self::Error> {
        match self.net.get(address) {
            Some(account) => Ok(account.original().cloned()),
            None => self.reader.get_account(address),
        }
    }

    fn get_code_by_hash(&mut self, code_hash: &B256) -> Result<Bytecode, Self::Error> {
        self.reader.get_code_by_hash(code_hash)
    }

    fn get_storage(&mut self, address: &Address, key: &U256) -> Result<U256, Self::Error> {
        match self
            .net
            .get(address)
            .and_then(|account| account.original_slot(key))
        {
            Some(value) => Ok(value),
            None => self.reader.get_storage(address, key),
        }
    }

    fn get_block_hash(&mut self, number: &U256) -> Result<B256, Self::Error> {
        self.reader.get_block_hash(number)
    }
}

/// A view call that reverted, halted or could not run.
#[derive(Debug)]
pub(super) struct ViewFailed {
    selector: Bytes,
    target: Address,
    reason: String,
}

impl ViewFailed {
    /// The contract the call was made to.
    pub(super) fn target(&self) -> Address {
        self.target
    }
}

impl Display for ViewFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} on {}: {}", self.selector, self.target, self.reason)
    }
}
