//! View calls against the harness's state after a step or, with its changes undone, before it.

use std::{
    cell::RefCell,
    fmt::{self, Display},
};

use alloy_primitives::{Address, B256, Bytes, U256, map::HashMap};
use evm2::{
    bytecode::Bytecode,
    evm::{AccountInfo, SystemTx},
};
use invariants_core::Views;
use reth_evm::{ConfigureEvm as _, Database};
use tempo_evm::{TempoEvm, TempoEvmConfig, TempoEvmEnv};
use tempo_precompiles::{TempoPrecompiles, storage::StorageAction};

use crate::state::{MissingPreState, Net, PreStateDb, Reader};

/// Read-only calls against the state an EVM reads, noting reads the seeded pre-state misses, and
/// answered from `memo` where an earlier call on the same state did.
pub(super) struct EvmViews<'a> {
    evm: TempoEvm<'a>,
    pre_state: &'a PreStateDb,
    memo: &'a Memo,
    /// Whether the state is the one before the step.
    before: bool,
}

impl<'a> EvmViews<'a> {
    pub(super) fn new(
        db: impl Database + 'a,
        evm_config: &TempoEvmConfig,
        env: TempoEvmEnv,
        pre_state: &'a PreStateDb,
        memo: &'a Memo,
        before: bool,
    ) -> Self {
        let spec = env.spec;
        let mut evm = evm_config.evm_with_env(db, env);
        // Precompiles keep the recorder they were built with, so they are built again with one.
        let ext = evm.ext_mut();
        ext.actions.enable();
        let precompiles =
            TempoPrecompiles::new(spec, ext.actions.clone(), ext.non_creditable_slots.clone());
        evm.set_precompiles(precompiles);
        Self {
            evm,
            pre_state,
            memo,
            before,
        }
    }

    /// `input`'s output from `target`. `Ok(None)` when nothing answers: `target` has no code, or
    /// the call read a key the pre-state lacks. `Err` when the call reverts or halts.
    fn call_one(&mut self, target: Address, input: &Bytes) -> Result<Option<Bytes>, ViewFailed> {
        let key = (target, input.clone());
        if let Some(output) = self.memo.get(&key, self.before) {
            return output;
        }
        let selector = input
            .get(..4)
            .map(Bytes::copy_from_slice)
            .unwrap_or_default();
        self.pre_state.take_miss();
        let failed = |reason| ViewFailed {
            selector: selector.clone(),
            target,
            reason,
        };
        let output = match self
            .evm
            .system_call(SystemTx::new(target, input.clone()).with_caller(Address::ZERO))
        {
            Err(err) => Err(failed(err.to_string())),
            Ok(executed) if !executed.result().is_success() => {
                Err(failed(format!("{:?}", executed.result())))
            }
            Ok(executed) => Ok(Some(executed.result().output.clone()).filter(|o| !o.is_empty())),
        };
        // What the call read: its target's account, the slots it loaded and the key it missed.
        let mut reads = vec![(target, None)];
        let actions = self.evm.ext().actions.take().into_iter().flatten();
        reads.extend(actions.filter_map(|action| match action {
            StorageAction::Sload(address, slot, _) => Some((address, Some(slot))),
            _ => None,
        }));
        let output = match self.pre_state.take_miss() {
            None => output,
            Some(MissingPreState::Account(address)) => {
                reads.push((address, None));
                Ok(None)
            }
            Some(MissingPreState::Storage(address, slot)) => {
                reads.push((address, Some(slot)));
                Ok(None)
            }
            Some(_) => return Ok(None),
        };
        self.memo.insert(key, self.before, output.clone(), reads);
        output
    }
}

/// The view calls a block's steps made, with what each read: storage slots, and accounts as
/// `None`. A step's changes undo only the calls that read what they changed, so later steps make
/// only those again, however many tokens, pools and holders the block reaches.
#[derive(Default)]
pub(crate) struct Memo(RefCell<Calls>);

#[derive(Default)]
struct Calls {
    /// The transaction step being checked, counted from the block's first.
    step: u64,
    /// Calls as of the state after it.
    after: HashMap<(Address, Bytes), Call>,
    /// Calls that hold only before it: made before it, or made earlier and undone by it.
    before: HashMap<(Address, Bytes), Call>,
}

struct Call {
    step: u64,
    output: Result<Option<Bytes>, ViewFailed>,
    reads: Vec<(Address, Option<U256>)>,
}

impl Memo {
    /// Starts checking a transaction step that made `net`'s changes.
    pub(crate) fn step(&self, net: &Net) {
        let calls = &mut *self.0.borrow_mut();
        calls.step += 1;
        let undone = |call: &Call| {
            call.reads
                .iter()
                .any(|(address, slot)| net.get(address).is_some_and(|a| a.changed(slot.as_ref())))
        };
        calls.before = calls.after.extract_if(|_, call| undone(call)).collect();
    }

    fn get(
        &self,
        key: &(Address, Bytes),
        before: bool,
    ) -> Option<Result<Option<Bytes>, ViewFailed>> {
        let calls = self.0.borrow();
        let call = if before {
            let earlier = calls.after.get(key).filter(|call| call.step < calls.step);
            calls.before.get(key).or(earlier)
        } else {
            calls.after.get(key)
        };
        call.map(|call| call.output.clone())
    }

    fn insert(
        &self,
        key: (Address, Bytes),
        before: bool,
        output: Result<Option<Bytes>, ViewFailed>,
        reads: Vec<(Address, Option<U256>)>,
    ) {
        let calls = &mut *self.0.borrow_mut();
        let call = Call {
            step: calls.step,
            output,
            reads,
        };
        match before {
            true => calls.before.insert(key, call),
            false => calls.after.insert(key, call),
        };
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
#[derive(Debug, Clone)]
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
