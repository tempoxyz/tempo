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
        let mut slots: Vec<(Address, Option<U256>)> = (self.evm.ext().actions.take())
            .into_iter()
            .flatten()
            .filter_map(|action| match action {
                StorageAction::Sload(address, slot, _) => Some((address, Some(slot))),
                _ => None,
            })
            .collect();
        let miss = match self.pre_state.take_miss() {
            None => None,
            Some(MissingPreState::Account(address)) => Some((address, None)),
            Some(MissingPreState::Storage(address, slot)) => Some((address, Some(slot))),
            Some(_) => return Ok(None),
        };
        let output = if miss.is_some() { Ok(None) } else { output };
        slots.extend(miss);
        // A slot's call also reads its account, as a change to the account undoes it.
        let mut reads: Vec<_> = slots
            .iter()
            .flat_map(|&(address, slot)| [(address, None), (address, slot)])
            .chain([(target, None)])
            .collect();
        reads.sort_unstable();
        reads.dedup();
        self.memo.insert(key, self.before, output.clone(), reads);
        output
    }
}

/// The view calls a block's steps made, by what each read: storage slots, and accounts as `None`.
/// A step's changes undo only the calls that read what they changed, so later steps make only
/// those again, however many tokens, pools and holders the block reaches.
#[derive(Default)]
pub(crate) struct Memo(RefCell<Calls>);

type Call = (Address, Bytes);
type Output = Result<Option<Bytes>, ViewFailed>;

#[derive(Default)]
struct Calls {
    /// The transaction step being checked, counted from the block's first.
    step: u64,
    /// Outputs as of the state after it, with the step each was read at.
    after: HashMap<Call, (u64, Output)>,
    /// Outputs that hold only before it: read before it, or read earlier and undone by it.
    before: HashMap<Call, Output>,
    /// The calls that read each slot or account, possibly undone since.
    readers: HashMap<(Address, Option<U256>), Vec<Call>>,
}

impl Memo {
    /// Starts checking a transaction step that made `net`'s changes.
    pub(crate) fn step(&self, net: &Net) {
        let calls = &mut *self.0.borrow_mut();
        calls.step += 1;
        calls.before.clear();
        for address in net.addresses() {
            let account = net.get(address).expect("the span changed it");
            let slots = account.changed_slots().map(|(slot, _)| Some(*slot));
            for read in account.changed().then_some(None).into_iter().chain(slots) {
                for call in calls
                    .readers
                    .remove(&(*address, read))
                    .into_iter()
                    .flatten()
                {
                    if let Some((_, output)) = calls.after.remove(&call) {
                        calls.before.insert(call, output);
                    }
                }
            }
        }
    }

    fn get(&self, call: &Call, before: bool) -> Option<Output> {
        let calls = self.0.borrow();
        let after = calls.after.get(call);
        match before {
            true => (calls.before.get(call)).or(after
                .filter(|(step, _)| *step < calls.step)
                .map(|(_, output)| output)),
            false => after.map(|(_, output)| output),
        }
        .cloned()
    }

    fn insert(
        &self,
        call: Call,
        before: bool,
        output: Output,
        reads: Vec<(Address, Option<U256>)>,
    ) {
        let calls = &mut *self.0.borrow_mut();
        if before {
            calls.before.insert(call, output);
            return;
        }
        for read in reads {
            calls.readers.entry(read).or_default().push(call.clone());
        }
        calls.after.insert(call, (calls.step, output));
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
