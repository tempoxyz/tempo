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
/// answered from `view_cache` when the same call was made on the same state before.
pub(super) struct EvmViews<'a> {
    evm: TempoEvm<'a>,
    pre_state: &'a PreStateDb,
    view_cache: &'a ViewCache,
    /// Whether the state is the one before the step.
    before: bool,
}

impl<'a> EvmViews<'a> {
    pub(super) fn new(
        db: impl Database + 'a,
        evm_config: &TempoEvmConfig,
        env: TempoEvmEnv,
        pre_state: &'a PreStateDb,
        view_cache: &'a ViewCache,
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
            view_cache,
            before,
        }
    }

    /// The output of `call`. `Ok(None)` when nothing answers: its target has no code, or the call
    /// read a key the pre-state lacks. `Err` when the call reverts or halts.
    fn call_one(&mut self, call: &Call) -> Output {
        if let Some(output) = self.view_cache.get(call, self.before) {
            return output;
        }
        let (target, input) = call;
        self.pre_state.take_miss();
        let output = match self
            .evm
            .system_call(SystemTx::new(*target, input.clone()).with_caller(Address::ZERO))
        {
            Err(err) => Err(err.to_string()),
            Ok(executed) if !executed.result().is_success() => {
                Err(format!("{:?}", executed.result()))
            }
            Ok(executed) => Ok(Some(executed.result().output.clone()).filter(|o| !o.is_empty())),
        };
        let miss = match self.pre_state.take_miss() {
            None => None,
            Some(MissingPreState::Account(address)) => Some((address, None)),
            Some(MissingPreState::Storage(address, slot)) => Some((address, Some(slot))),
            Some(_) => return Ok(None),
        };
        let output = match miss {
            Some(_) => Ok(None),
            None => output.map_err(|reason| ViewFailed {
                selector: input
                    .get(..4)
                    .map(Bytes::copy_from_slice)
                    .unwrap_or_default(),
                target: *target,
                reason,
            }),
        };
        // What it read: the slots it loaded and the key it missed, each with its account, and its
        // target's account.
        let actions = self.evm.ext().actions.take().unwrap_or_default();
        let slots = actions.into_iter().filter_map(|action| match action {
            StorageAction::Sload(address, slot, _) => Some((address, Some(slot))),
            _ => None,
        });
        let mut reads: Vec<_> = slots
            .chain(miss)
            .flat_map(|(address, slot)| [(address, None), (address, slot)])
            .chain([(*target, None)])
            .collect();
        reads.sort_unstable();
        reads.dedup();
        self.view_cache
            .insert(call, self.before, output.clone(), reads);
        output
    }
}

impl Views for EvmViews<'_> {
    type Error = ViewFailed;

    fn call(&mut self, calls: &[Call]) -> Result<Vec<Option<Bytes>>, ViewFailed> {
        calls.iter().map(|call| self.call_one(call)).collect()
    }

    /// The seeded pre-state may hold only the accounts and slots execution touched.
    fn partial(&self) -> bool {
        true
    }
}

/// The view calls a block's steps made, with their outputs, indexed by what each read: storage
/// slots, and accounts as `None`. A transaction step undoes only the calls that read what it
/// changed, so only those and calls not made before are read again after it.
#[derive(Default)]
pub(crate) struct ViewCache(RefCell<Calls>);

impl ViewCache {
    /// Advances to the next transaction step, which made `net`'s changes, undoing the calls that
    /// read a slot or account it changed.
    pub(crate) fn advance(&self, net: &Net) {
        let calls = &mut *self.0.borrow_mut();
        calls.step += 1;
        calls.before.clear();
        for address in net.addresses() {
            let account = net.get(address).expect("the span changed it");
            let slots = account.changed_slots().map(|(slot, _)| Some(*slot));
            for read in account.changed().then_some(None).into_iter().chain(slots) {
                for call in calls.readers.remove(&(*address, read)).unwrap_or_default() {
                    if let Some((_, output)) = calls.after.remove(&call) {
                        calls.before.insert(call, output);
                    }
                }
            }
        }
    }

    /// The output `call` gave on the state after the step or, with `before`, before it.
    fn get(&self, call: &Call, before: bool) -> Option<Output> {
        let calls = self.0.borrow();
        let after = calls.after.get(call);
        let output = match before {
            // An output read after an earlier step holds before this one unless this step undid it.
            true => calls.before.get(call).or(after
                .filter(|(step, _)| *step < calls.step)
                .map(|(_, output)| output)),
            false => after.map(|(_, output)| output),
        };
        output.cloned()
    }

    fn insert(
        &self,
        call: &Call,
        before: bool,
        output: Output,
        reads: Vec<(Address, Option<U256>)>,
    ) {
        let calls = &mut *self.0.borrow_mut();
        if before {
            calls.before.insert(call.clone(), output);
            return;
        }
        for read in reads {
            calls.readers.entry(read).or_default().push(call.clone());
        }
        calls.after.insert(call.clone(), (calls.step, output));
    }
}

/// A view call: a target and its input.
type Call = (Address, Bytes);

type Output = Result<Option<Bytes>, ViewFailed>;

#[derive(Default)]
struct Calls {
    /// The transaction step being checked, counted from the block's first.
    step: u64,
    /// Outputs on the state after it, with the step each was read at.
    after: HashMap<Call, (u64, Output)>,
    /// Outputs that hold only before it: read before it, or read earlier and undone by it.
    before: HashMap<Call, Output>,
    /// The calls that read each slot or account, including some undone since.
    readers: HashMap<(Address, Option<U256>), Vec<Call>>,
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
