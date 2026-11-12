//! View calls against the harness's state after a step or, with its changes undone, before it.

use std::{
    cell::RefCell,
    fmt::{self, Display},
    rc::Rc,
};

use alloy_primitives::{Address, B256, Bytes, Signature, TxKind, U256, map::HashMap};
use evm2::{
    EvmFeatures,
    bytecode::Bytecode,
    evm::{AccountInfo, SystemTx},
};
use invariants_core::Views;
use reth_evm::{ConfigureEvm as _, Database};
use reth_primitives_traits::Recovered;
use tempo_contracts::precompiles::PATH_USD_ADDRESS;
use tempo_evm::{TempoEvm, TempoEvmConfig, TempoEvmEnv};
use tempo_primitives::{
    TempoTxEnvelope,
    transaction::{TempoSignature, TempoTransaction},
};
use zone_evm::ZoneEvmConfig;

use crate::{
    state::{Net, PreStateDb, Reader},
    zone::AnchorReader,
};

/// The gas each zone view's simulated transaction may use.
const ZONE_VIEW_GAS_LIMIT: u64 = 10_000_000;

/// Read-only calls against the state an EVM reads, noting reads the seeded pre-state misses, and
/// answered from `view_cache` when the same call was made on the same state before.
pub(super) struct EvmViews<'a> {
    evm: TempoEvm<'a>,
    /// What the call being made has read.
    reads: Rc<RefCell<Vec<Read>>>,
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
        let reads = Rc::default();
        let db = Recorder {
            db,
            reads: Rc::clone(&reads),
        };
        Self {
            evm: evm_config.evm_with_env(db, env),
            reads,
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
        // The EVM caches what it loads, so a call reaches the database for every key it reads
        // only on an empty cache.
        let cache = &mut self.evm.overlay_db_mut().cache;
        cache.accounts.clear();
        cache.storage.clear();
        self.pre_state.restore_missed(false);
        let result = self
            .evm
            .system_call(SystemTx::new(*target, input.clone()).with_caller(Address::ZERO));
        let output = if self.pre_state.missed() {
            Ok(None)
        } else {
            let failed = |reason| ViewFailed {
                selector: input
                    .get(..4)
                    .map(Bytes::copy_from_slice)
                    .unwrap_or_default(),
                target: *target,
                reason,
            };
            match result {
                Err(err) => Err(failed(err.to_string())),
                Ok(executed) if !executed.result().is_success() => {
                    Err(failed(format!("{:?}", executed.result())))
                }
                Ok(executed) => {
                    Ok(Some(executed.result().output.clone()).filter(|o| !o.is_empty()))
                }
            }
        };
        let mut reads = self.reads.take();
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

/// Read-only calls against zone state, each run as a simulated zone transaction from the zero
/// address without fees: Tempo's overlay applies only inside a zone transaction. A call that
/// returns nothing answers empty output, as a call to an account without code does.
pub(super) struct ZoneViews<'a> {
    evm: TempoEvm<'a>,
    chain_id: u64,
}

impl<'a> ZoneViews<'a> {
    /// Views of the zone state `db` holds, in the zone block environment `env`.
    pub(super) fn new(
        db: impl Database + 'a,
        config: &ZoneEvmConfig<AnchorReader>,
        mut env: TempoEvmEnv,
    ) -> Self {
        for feature in [
            EvmFeatures::FEE_CHARGE,
            EvmFeatures::BALANCE_CHECK,
            EvmFeatures::BALANCE_TOP_UP,
            EvmFeatures::NONCE_CHECK,
            EvmFeatures::BLOCK_GAS_LIMIT_CHECK,
        ] {
            env.version.features.remove(feature);
        }
        let chain_id = env.version.chain_id;
        Self {
            evm: config.evm_with_env(db, env),
            chain_id,
        }
    }
}

impl Views for ZoneViews<'_> {
    type Error = ViewFailed;

    fn call(&mut self, calls: &[Call]) -> Result<Vec<Option<Bytes>>, ViewFailed> {
        calls
            .iter()
            .map(|(target, input)| {
                let tx = TempoTransaction {
                    chain_id: self.chain_id,
                    fee_token: Some(PATH_USD_ADDRESS),
                    gas_limit: ZONE_VIEW_GAS_LIMIT,
                    calls: vec![tempo_primitives::transaction::Call {
                        to: TxKind::Call(*target),
                        value: U256::ZERO,
                        input: input.clone(),
                    }],
                    ..Default::default()
                };
                let signature = TempoSignature::from(Signature::test_signature());
                let envelope = TempoTxEnvelope::AA(tx.into_signed(signature));
                let tx = Recovered::new_unchecked(envelope, Address::ZERO);
                let failed = |reason| ViewFailed {
                    selector: input
                        .get(..4)
                        .map(Bytes::copy_from_slice)
                        .unwrap_or_default(),
                    target: *target,
                    reason,
                };
                match self
                    .evm
                    .call_tx(&Recovered::new_unchecked(tx.into(), Address::ZERO))
                {
                    Err(err) => Err(failed(err.to_string())),
                    Ok(result) if !result.status => {
                        Err(failed(format!("reverted with {}", result.output)))
                    }
                    Ok(result) => Ok(Some(result.output)),
                }
            })
            .collect()
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

    fn insert(&self, call: &Call, before: bool, output: Output, reads: Vec<Read>) {
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

/// A storage slot or, as `None`, an account, that a view call read.
type Read = (Address, Option<U256>);

#[derive(Default)]
struct Calls {
    /// The transaction step being checked, counted from the block's first.
    step: u64,
    /// Outputs on the state after it, with the step each was read at.
    after: HashMap<Call, (u64, Output)>,
    /// Outputs that hold only before it: read before it, or read earlier and undone by it.
    before: HashMap<Call, Output>,
    /// The calls that read each slot or account, including some undone since.
    readers: HashMap<Read, Vec<Call>>,
}

/// A database that notes every account and slot read through it.
struct Recorder<D> {
    db: D,
    reads: Rc<RefCell<Vec<Read>>>,
}

impl<D: Database> Database for Recorder<D> {
    type Error = D::Error;

    fn is_fatal(error: &Self::Error) -> bool {
        D::is_fatal(error)
    }

    fn get_account(&mut self, address: &Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.reads.borrow_mut().push((*address, None));
        self.db.get_account(address)
    }

    fn get_code_by_hash(&mut self, code_hash: &B256) -> Result<Bytecode, Self::Error> {
        self.db.get_code_by_hash(code_hash)
    }

    fn get_storage(&mut self, address: &Address, key: &U256) -> Result<U256, Self::Error> {
        self.reads
            .borrow_mut()
            .extend([(*address, None), (*address, Some(*key))]);
        self.db.get_storage(address, key)
    }

    fn get_block_hash(&mut self, number: &U256) -> Result<B256, Self::Error> {
        self.db.get_block_hash(number)
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
