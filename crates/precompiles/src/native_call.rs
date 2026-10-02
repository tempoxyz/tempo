//! Bounded EVM2 calls for native protocol handlers.
//!
//! EVM2 supplies the original transaction environment; a budget is shared
//! across the entire native operation. Invoke this outside `StorageCtx::enter`:
//! child contracts may enter another native storage context. This module does
//! not register an entrypoint or change payment-lane admission.

use alloy::primitives::{Address, B256, Bytes, U256};
use core::cell::{Cell, RefCell};
use evm2::{
    Evm, EvmFeatures, EvmTypes,
    env::TxEnv,
    evm::precompile::PrecompileOutput,
    interpreter::{GasTracker, Host, InstrStop, Message, MessageKind},
    precompiles::{PrecompileError, PrecompileHalt, PrecompileResult},
    version::GasId,
};
use std::rc::Rc;

/// Non-refundable work reservation shared by a native operation's child calls.
///
/// Reserving maximum forwarded execution and state gas prevents successful
/// storage restoration or reverted children from replenishing the operation's
/// work bound. Fee charging still uses the actual EVM gas tracker.
#[derive(Debug)]
pub struct NativeCallBudget {
    remaining_calls: Cell<u32>,
    remaining_work: Cell<u64>,
}

impl NativeCallBudget {
    /// Creates the operation budget from protocol-selected limits.
    pub const fn new(max_calls: u32, max_work: u64) -> Self {
        Self {
            remaining_calls: Cell::new(max_calls),
            remaining_work: Cell::new(max_work),
        }
    }

    fn reserve(&self, execution_gas: u64, state_gas: u64) -> Result<(), PrecompileError> {
        let work = execution_gas
            .checked_add(state_gas)
            .ok_or(PrecompileHalt::OutOfGas)?;
        if self.remaining_calls.get() == 0 || work > self.remaining_work.get() {
            return Err(PrecompileHalt::OutOfGas.into());
        }
        self.remaining_calls.set(self.remaining_calls.get() - 1);
        self.remaining_work.set(self.remaining_work.get() - work);
        Ok(())
    }
}

/// Runtime-owned transaction scope for native dependency work.
///
/// Each root handler obtains the same reservation object, including handlers
/// invoked through contract reentry and subsequent calls in an AA batch. Once
/// initialized, requesting another profile cannot replenish or enlarge it.
#[derive(Debug, Default)]
pub struct NativeCallContext {
    budget: RefCell<Option<Rc<NativeCallBudget>>>,
    verified_portal_deposit: Cell<bool>,
    verified_portal_settlement: Cell<bool>,
    verified_earn_payment: Cell<bool>,
}

impl Clone for NativeCallContext {
    fn clone(&self) -> Self {
        // Cloning EVM configuration creates an independent execution scope.
        // Reentry shares an Rc returned by `budget`, rather than cloning context.
        Self::default()
    }
}

impl NativeCallContext {
    /// Returns the transaction budget, initializing it once with protocol limits.
    ///
    /// Handlers must pass the transaction-wide limits selected by the protocol,
    /// rather than calldata-derived limits or a fresh per-handler allowance.
    pub fn budget(&self, max_calls: u32, max_work: u64) -> Rc<NativeCallBudget> {
        self.budget
            .borrow_mut()
            .get_or_insert_with(|| Rc::new(NativeCallBudget::new(max_calls, max_work)))
            .clone()
    }

    /// Clears the scope at the start of an independent transaction or simulation.
    /// This is a runtime hook and must never be called by a native handler.
    pub fn reset(&mut self) {
        *self.budget.get_mut() = None;
        self.verified_portal_deposit.set(false);
        self.verified_portal_settlement.set(false);
        self.verified_earn_payment.set(false);
    }

    /// Records that the top-level portal deposit passed its native identity checks.
    pub fn record_verified_portal_deposit(&self) {
        self.verified_portal_deposit.set(true);
    }

    /// Whether the current transaction entered a verified native portal deposit.
    pub fn verified_portal_deposit(&self) -> bool {
        self.verified_portal_deposit.get()
    }

    /// Records a top-level batch after portal and sequencer checks.
    pub fn record_verified_portal_settlement(&self) {
        self.verified_portal_settlement.set(true);
    }

    /// Whether the current transaction entered a verified native batch.
    pub fn verified_portal_settlement(&self) -> bool {
        self.verified_portal_settlement.get()
    }

    /// Records a top-level Earn payment after runtime and registry checks.
    pub fn record_verified_earn_payment(&self) {
        self.verified_earn_payment.set(true);
    }

    /// Whether this transaction entered an authenticated native Earn endpoint.
    pub fn verified_earn_payment(&self) -> bool {
        self.verified_earn_payment.get()
    }
}

/// Runtime extension exposing the transaction-owned native work scope.
pub trait NativeCallExt {
    /// Returns the scope shared by every native handler in the current transaction.
    fn native_call_context(&self) -> &NativeCallContext;
}

impl NativeCallExt for NativeCallContext {
    fn native_call_context(&self) -> &NativeCallContext {
        self
    }
}

/// Protocol-selected bounds on one contract call. They are not caller privileges.
#[derive(Clone, Copy, Debug)]
pub struct NativeCallLimits {
    /// Maximum forwarded execution gas, before the EIP-150 reduction.
    pub execution_gas: u64,
    /// Maximum state-gas reservoir exposed to this child.
    pub state_gas: u64,
    /// Maximum input bytes accepted before any target account is loaded.
    pub input_bytes: usize,
    /// Maximum success or revert bytes returned to native code.
    pub output_bytes: usize,
}

/// Result of an executed dependency frame, after its gas and journal have settled.
///
/// A native withdrawal may recover from a child revert or halt with a protocol
/// bounce. Adapter limit violations and fatal execution errors are returned
/// separately and must abort the native operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeCallOutcome {
    /// The dependency committed its child journal.
    Success(Bytes),
    /// The dependency reverted its child journal and returned bounded bytes.
    Revert(Bytes),
    /// The dependency halted; its child journal was reverted.
    Halt(InstrStop),
}

impl NativeCallOutcome {
    /// Propagates a dependency failure to the enclosing native frame.
    pub fn into_result(self) -> PrecompileResult {
        match self {
            Self::Success(output) => Ok(PrecompileOutput::new(output)),
            Self::Revert(output) => Err(PrecompileError::Revert(output)),
            Self::Halt(stop) => {
                Err(PrecompileHalt::Other(format!("native child halted: {stop:?}").into()).into())
            }
        }
    }
}

/// Calls `target` as the native account using the existing EVM journal.
///
/// Only zero-value CALL/STATICCALL is supported. Inherited static context always
/// wins. Cold/warm access and EIP-7702 resolution are charged with the active gas
/// table; gas is reserved before execution and reconciled through EVM2. A child
/// failure propagates to the caller. Oversized output reverts the child journal
/// even if its execution succeeded. Database/fatal errors remain fatal.
#[allow(clippy::too_many_arguments)]
pub fn native_call<T: EvmTypes>(
    evm: &mut Evm<'_, T>,
    parent: &Message<T>,
    gas: &mut GasTracker,
    budget: &NativeCallBudget,
    target: Address,
    input: Bytes,
    read_only: bool,
    limits: NativeCallLimits,
) -> PrecompileResult {
    native_call_outcome(evm, parent, gas, budget, target, input, read_only, limits)?.into_result()
}

/// Executes an approved implementation in the native account's storage context.
///
/// The caller and value are inherited from the parent message, exactly as EVM
/// `DELEGATECALL` does. Callers must authenticate the target code identity
/// before entry; the work and returned bytes use the same transaction budget.
#[allow(clippy::too_many_arguments)]
pub fn native_delegate_call<T: EvmTypes>(
    evm: &mut Evm<'_, T>,
    parent: &Message<T>,
    gas: &mut GasTracker,
    budget: &NativeCallBudget,
    implementation: Address,
    input: Bytes,
    limits: NativeCallLimits,
) -> PrecompileResult {
    let tx_env = evm.precompile_tx_env().cloned().ok_or_else(|| {
        PrecompileError::Fatal("native delegate call requires an active transaction context".into())
    })?;
    native_call_outcome_with_env_kind(
        evm,
        &tx_env,
        parent,
        gas,
        budget,
        implementation,
        input,
        false,
        limits,
        MessageKind::DelegateCall,
    )?
    .into_result()
}

/// Authenticates a fixed implementation before granting native payment capacity.
/// The account access and code-hash work are charged to the current frame.
pub fn verify_native_code<T: EvmTypes>(
    evm: &mut Evm<'_, T>,
    gas: &mut GasTracker,
    target: Address,
    expected_hash: B256,
) -> Result<(), PrecompileError> {
    let params = evm.version().gas_params;
    if !evm.version().features.contains(EvmFeatures::EIP2929) {
        return Err(PrecompileError::Fatal(
            "native code checks require Berlin gas rules".into(),
        ));
    }
    gas.spend(u64::from(params.get(GasId::WarmStorageReadCost)))?;
    let cold_cost = params.cold_account_additional_cost();
    let account = Host::load_account(evm, &target, true, gas.remaining() < cold_cost)?;
    if account.is_cold {
        gas.spend(cold_cost)?;
    }
    if account.code.eip7702_address().is_some() {
        return Err(PrecompileError::Revert(Bytes::new()));
    }
    gas.spend(params.keccak256_word_cost(account.code.len().div_ceil(32)))?;
    if account.code.hash_slow() != expected_hash {
        return Err(PrecompileError::Revert(Bytes::new()));
    }
    Ok(())
}

/// Executes a bounded dependency frame with recoverable child failure results.
///
/// Only the outcome of an executed child is recoverable. An `Err` here includes
/// adapter budget/size failures and host errors, which the native handler must
/// propagate instead of translating into a successful bounce.
#[allow(clippy::too_many_arguments)]
pub fn native_call_outcome<T: EvmTypes>(
    evm: &mut Evm<'_, T>,
    parent: &Message<T>,
    gas: &mut GasTracker,
    budget: &NativeCallBudget,
    target: Address,
    input: Bytes,
    read_only: bool,
    limits: NativeCallLimits,
) -> Result<NativeCallOutcome, PrecompileError> {
    let tx_env = evm.precompile_tx_env().cloned().ok_or_else(|| {
        PrecompileError::Fatal("native call requires an active transaction context".into())
    })?;
    native_call_outcome_with_env(
        evm, &tx_env, parent, gas, budget, target, input, read_only, limits,
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn native_call_with_env<T: EvmTypes>(
    evm: &mut Evm<'_, T>,
    tx_env: &TxEnv<T>,
    parent: &Message<T>,
    gas: &mut GasTracker,
    budget: &NativeCallBudget,
    target: Address,
    input: Bytes,
    read_only: bool,
    limits: NativeCallLimits,
) -> PrecompileResult {
    native_call_outcome_with_env(
        evm, tx_env, parent, gas, budget, target, input, read_only, limits,
    )?
    .into_result()
}

#[allow(clippy::too_many_arguments)]
fn native_call_outcome_with_env<T: EvmTypes>(
    evm: &mut Evm<'_, T>,
    tx_env: &TxEnv<T>,
    parent: &Message<T>,
    gas: &mut GasTracker,
    budget: &NativeCallBudget,
    target: Address,
    input: Bytes,
    read_only: bool,
    limits: NativeCallLimits,
) -> Result<NativeCallOutcome, PrecompileError> {
    native_call_outcome_with_env_kind(
        evm,
        tx_env,
        parent,
        gas,
        budget,
        target,
        input,
        read_only,
        limits,
        MessageKind::Call,
    )
}

#[allow(clippy::too_many_arguments)]
fn native_call_outcome_with_env_kind<T: EvmTypes>(
    evm: &mut Evm<'_, T>,
    tx_env: &TxEnv<T>,
    parent: &Message<T>,
    gas: &mut GasTracker,
    budget: &NativeCallBudget,
    target: Address,
    input: Bytes,
    read_only: bool,
    limits: NativeCallLimits,
    kind: MessageKind,
) -> Result<NativeCallOutcome, PrecompileError> {
    if input.len() > limits.input_bytes {
        return Err(PrecompileHalt::OutOfGas.into());
    }
    let depth = parent
        .depth
        .checked_add(1)
        .ok_or(PrecompileHalt::OutOfGas)?;
    let features = evm.version().features;
    let params = evm.version().gas_params;
    let copy_cost = |len: usize| -> Result<u64, PrecompileError> {
        u64::try_from(len.div_ceil(32))
            .ok()
            .and_then(|words| words.checked_mul(u64::from(params.get(GasId::CopyPerWord))))
            .ok_or_else(|| PrecompileHalt::OutOfGas.into())
    };
    gas.spend(copy_cost(input.len())?)?;
    // Native payment execution is introduced after Berlin, whose CALL base
    // charge is the warm account access price. Historical execution does not
    // dispatch through this adapter.
    if !features.contains(EvmFeatures::EIP2929) {
        return Err(PrecompileError::Fatal(
            "native calls require Berlin gas rules".into(),
        ));
    }
    gas.spend(u64::from(params.get(GasId::WarmStorageReadCost)))?;
    let cold_cost = params.cold_account_additional_cost();
    let account = Host::load_account(evm, &target, true, gas.remaining() < cold_cost)?;
    if account.is_cold {
        gas.spend(cold_cost)?;
    }
    let mut code = account.code;
    let mut code_address = target;
    if features.contains(EvmFeatures::EIP7702)
        && let Some(delegated) = code.eip7702_address()
    {
        gas.spend(u64::from(params.get(GasId::WarmStorageReadCost)))?;
        let account = Host::load_account(evm, &delegated, true, gas.remaining() < cold_cost)?;
        if account.is_cold {
            gas.spend(cold_cost)?;
        }
        code = account.code;
        code_address = delegated;
    }
    // An implementation address must contain its own code. In particular,
    // EIP-7702 cannot silently redirect an approved implementation identity.
    if kind == MessageKind::DelegateCall && (target == parent.destination || code_address != target)
    {
        return Err(PrecompileError::Revert(Bytes::new()));
    }
    let execution_gas = if features.contains(EvmFeatures::EIP150) {
        limits
            .execution_gas
            .min(params.call_stipend_reduction(gas.remaining()))
    } else {
        limits.execution_gas
    };
    let state_gas = limits.state_gas.min(gas.reservoir());
    budget.reserve(execution_gas, state_gas)?;
    gas.spend(execution_gas)?;
    let unforwarded_reservoir = gas.reservoir() - state_gas;
    let is_static = read_only || parent.caller_is_static || parent.kind == MessageKind::StaticCall;
    let mut child = Message::<T> {
        kind: if kind == MessageKind::DelegateCall {
            MessageKind::DelegateCall
        } else if is_static {
            MessageKind::StaticCall
        } else {
            MessageKind::Call
        },
        depth,
        gas_limit: execution_gas,
        reservoir: state_gas,
        destination: if kind == MessageKind::DelegateCall {
            parent.destination
        } else {
            target
        },
        call_target: target,
        caller: if kind == MessageKind::DelegateCall {
            parent.caller
        } else {
            parent.destination
        },
        input,
        value: if kind == MessageKind::DelegateCall {
            parent.value
        } else {
            U256::ZERO
        },
        code,
        code_address,
        disable_precompiles: kind == MessageKind::DelegateCall || code_address != target,
        caller_is_static: is_static,
        ..Message::<T>::default()
    };
    let checkpoint = evm.state().checkpoint();
    let mut result = Host::execute_message(evm, tx_env, &mut child)?;
    // The child only received part of the reservoir. Restore the untouched part
    // before using EVM2's spill/refund reconciliation.
    result.gas.set_reservoir(
        result
            .gas
            .reservoir()
            .checked_add(unforwarded_reservoir)
            .ok_or(PrecompileHalt::OutOfGas)?,
    );
    gas.merge_child_gas(result.gas, result.stop);
    if result.output.len() > limits.output_bytes {
        evm.state_mut().rollback(checkpoint, features);
        return Err(PrecompileHalt::OutOfGas.into());
    }
    if let Err(error) = gas.spend(copy_cost(result.output.len())?) {
        evm.state_mut().rollback(checkpoint, features);
        return Err(error.into());
    }
    match result.stop {
        stop if stop.is_success() => Ok(NativeCallOutcome::Success(result.output)),
        stop if stop.is_revert() => Ok(NativeCallOutcome::Revert(result.output)),
        stop => Ok(NativeCallOutcome::Halt(stop)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::bytes;
    use evm2::{
        BaseEvmTypes, Precompiles, SpecId,
        bytecode::Bytecode,
        env::BlockEnvExt,
        evm::{AccountInfo, InMemoryDB},
        precompiles::{Precompile, PrecompileId},
        registry::TxRegistry,
    };

    const NATIVE: Address = Address::with_last_byte(0x99);
    const TARGET: Address = Address::with_last_byte(0xaa);
    const ORIGIN: Address = Address::with_last_byte(0xbb);
    const LIMITS: NativeCallLimits = NativeCallLimits {
        execution_gas: 50_000,
        state_gas: 20_000,
        input_bytes: 256,
        output_bytes: 256,
    };

    fn evm(code: Bytes, spec: SpecId) -> Evm<'static, BaseEvmTypes> {
        let mut db = InMemoryDB::default();
        db.insert_account_info(
            &TARGET,
            AccountInfo::default().with_code(Bytecode::new_legacy(code)),
        );
        Evm::new(
            spec,
            BlockEnvExt::default(),
            TxRegistry::new(),
            db,
            Precompiles::base(spec),
        )
    }

    fn parent() -> Message {
        Message::<BaseEvmTypes> {
            destination: NATIVE,
            code_address: NATIVE,
            caller: ORIGIN,
            ..Message::<BaseEvmTypes>::default()
        }
    }

    fn tx_env() -> TxEnv {
        TxEnv::<BaseEvmTypes> {
            origin: ORIGIN,
            gas_price: U256::from(17),
            chain_id: U256::from(42431),
            ..TxEnv::<BaseEvmTypes>::default()
        }
    }

    fn invoke(
        evm: &mut Evm<'_, BaseEvmTypes>,
        parent: &Message,
        gas: &mut GasTracker,
        budget: &NativeCallBudget,
        limits: NativeCallLimits,
    ) -> PrecompileResult {
        native_call_with_env(
            evm,
            &tx_env(),
            parent,
            gas,
            budget,
            TARGET,
            Bytes::new(),
            false,
            limits,
        )
    }

    #[test]
    fn transaction_scope_cannot_be_replenished_by_another_root_or_reentry() {
        let mut context = NativeCallContext::default();
        let root = context.budget(2, 100_000);
        root.reserve(40_000, 10_000).unwrap();
        let reentry = context.budget(u32::MAX, u64::MAX);
        assert!(Rc::ptr_eq(&root, &reentry));
        reentry.reserve(50_000, 0).unwrap();
        let next_root = context.budget(2, 100_000);
        assert!(matches!(
            next_root.reserve(1, 0),
            Err(PrecompileError::Halt(_))
        ));
        assert_eq!(root.remaining_calls.get(), 0);
        assert_eq!(root.remaining_work.get(), 0);

        context.record_verified_portal_deposit();
        assert!(context.verified_portal_deposit());
        context.reset();
        assert!(!context.verified_portal_deposit());
        let next_transaction = context.budget(2, 100_000);
        assert!(!Rc::ptr_eq(&root, &next_transaction));
        next_transaction.reserve(100_000, 0).unwrap();
        assert_eq!(root.remaining_work.get(), 0);
    }

    #[test]
    fn cloned_runtime_context_starts_with_an_independent_budget() {
        let context = NativeCallContext::default();
        let budget = context.budget(1, 1);
        budget.reserve(1, 0).unwrap();
        let mut cloned = context.clone();
        let independent = cloned.budget(1, 1);
        assert!(!Rc::ptr_eq(&budget, &independent));
        independent.reserve(1, 0).unwrap();
        cloned.reset();
        assert!(Rc::ptr_eq(&budget, &context.budget(1, 1)));
        assert!(context.budget(1, 1).reserve(1, 0).is_err());
    }

    #[test]
    fn preserves_transaction_context_and_native_caller() {
        // CALLER, ORIGIN, GASPRICE, CHAINID, ADDRESS returned as ABI words.
        let mut evm = evm(
            bytes!("335f52326020523a604052466060523060805260a05ff3"),
            SpecId::OSAKA,
        );
        let mut gas = GasTracker::new(100_000);
        let result = invoke(
            &mut evm,
            &parent(),
            &mut gas,
            &NativeCallBudget::new(1, 70_000),
            LIMITS,
        )
        .unwrap();
        let output = result.into_bytes();
        let words = output
            .chunks_exact(32)
            .map(U256::from_be_slice)
            .collect::<Vec<_>>();
        assert_eq!(
            words,
            vec![
                U256::from_be_slice(NATIVE.as_slice()),
                U256::from_be_slice(ORIGIN.as_slice()),
                U256::from(17),
                U256::from(42431),
                U256::from_be_slice(TARGET.as_slice())
            ]
        );
        assert!(
            gas.spent() > 2600,
            "child execution and output copy must be charged"
        );
    }

    #[test]
    fn delegate_call_preserves_vault_context_and_charges_storage() {
        // CALLER, ADDRESS, CALLVALUE, then SSTORE in the native account.
        let mut evm = evm(
            bytes!("336000523060205234604052600160005560606000f3"),
            SpecId::OSAKA,
        );
        let mut parent = parent();
        parent.value = U256::from(9);
        let mut gas = GasTracker::new(150_000);
        let result = native_call_outcome_with_env_kind(
            &mut evm,
            &tx_env(),
            &parent,
            &mut gas,
            &NativeCallBudget::new(1, 70_000),
            TARGET,
            Bytes::new(),
            false,
            LIMITS,
            MessageKind::DelegateCall,
        )
        .unwrap();
        let NativeCallOutcome::Success(output) = result else {
            panic!("expected successful delegate call")
        };
        let words = output
            .chunks_exact(32)
            .map(U256::from_be_slice)
            .collect::<Vec<_>>();
        assert_eq!(
            words,
            vec![
                U256::from_be_slice(ORIGIN.as_slice()),
                U256::from_be_slice(NATIVE.as_slice()),
                U256::from(9),
            ]
        );
        assert_eq!(
            evm.state_mut()
                .storage_slot_untracked(&NATIVE, &U256::ZERO)
                .unwrap(),
            U256::from(1)
        );
        assert_eq!(
            evm.state_mut()
                .storage_slot_untracked(&TARGET, &U256::ZERO)
                .unwrap(),
            U256::ZERO
        );
        assert!(gas.spent() > 20_000);
    }

    #[test]
    fn delegate_call_inherits_static_context_and_rolls_back() {
        let mut evm = evm(bytes!("600160005500"), SpecId::OSAKA);
        let mut parent = parent();
        parent.caller_is_static = true;
        let mut gas = GasTracker::new(150_000);
        let result = native_call_outcome_with_env_kind(
            &mut evm,
            &tx_env(),
            &parent,
            &mut gas,
            &NativeCallBudget::new(1, 70_000),
            TARGET,
            Bytes::new(),
            false,
            LIMITS,
            MessageKind::DelegateCall,
        )
        .unwrap();
        assert!(matches!(result, NativeCallOutcome::Halt(_)));
        assert_eq!(
            evm.state_mut()
                .storage_slot_untracked(&NATIVE, &U256::ZERO)
                .unwrap(),
            U256::ZERO
        );
    }

    #[test]
    fn inherited_static_context_forbids_child_storage_write() {
        let mut evm = evm(bytes!("60015f5500"), SpecId::OSAKA);
        let mut parent = parent();
        parent.caller_is_static = true;
        let mut gas = GasTracker::new(100_000);
        let result = invoke(
            &mut evm,
            &parent,
            &mut gas,
            &NativeCallBudget::new(1, 70_000),
            LIMITS,
        );
        assert!(matches!(result, Err(PrecompileError::Halt(_))));
        assert_eq!(
            evm.state_mut()
                .storage_slot_untracked(&TARGET, &U256::ZERO)
                .unwrap(),
            U256::ZERO
        );
        assert_eq!(gas.spent(), 52_600);
    }

    #[test]
    fn reverted_child_restores_storage_and_returns_paid_revert_data() {
        // Write then revert with the word 42.
        let mut evm = evm(bytes!("60015f55602a5f5260205ffd"), SpecId::OSAKA);
        let mut gas = GasTracker::new(100_000);
        let result = invoke(
            &mut evm,
            &parent(),
            &mut gas,
            &NativeCallBudget::new(1, 70_000),
            LIMITS,
        );
        let Err(PrecompileError::Revert(output)) = result else {
            panic!("expected child revert")
        };
        assert_eq!(U256::from_be_slice(&output), U256::from(42));
        assert_eq!(
            evm.state_mut()
                .storage_slot_untracked(&TARGET, &U256::ZERO)
                .unwrap(),
            U256::ZERO
        );
        assert!(gas.spent() > 24_700);
    }

    #[test]
    fn recoverable_child_failure_is_distinct_from_adapter_limit_failure() {
        for (code, expected) in [
            (bytes!("00"), NativeCallOutcome::Success(Bytes::new())),
            (bytes!("5f5ffd"), NativeCallOutcome::Revert(Bytes::new())),
            (
                bytes!("fe"),
                NativeCallOutcome::Halt(InstrStop::InvalidFEOpcode),
            ),
        ] {
            let mut evm = evm(code, SpecId::OSAKA);
            let mut gas = GasTracker::new(200_000);
            let budget = NativeCallBudget::new(1, 70_000);
            let outcome = native_call_outcome_with_env(
                &mut evm,
                &tx_env(),
                &parent(),
                &mut gas,
                &budget,
                TARGET,
                Bytes::new(),
                false,
                LIMITS,
            )
            .unwrap();
            assert_eq!(outcome, expected);
            assert_eq!(budget.remaining_calls.get(), 0);
            // An exhausted native budget must abort the operation rather than
            // producing a recoverable dependency failure for a bounce handler.
            assert!(matches!(
                native_call_outcome_with_env(
                    &mut evm,
                    &tx_env(),
                    &parent(),
                    &mut gas,
                    &budget,
                    TARGET,
                    Bytes::new(),
                    false,
                    LIMITS,
                ),
                Err(PrecompileError::Halt(PrecompileHalt::OutOfGas))
            ));
        }
    }

    #[test]
    fn oversized_success_output_rolls_back_successful_child() {
        let mut evm = evm(bytes!("60015f5560205ff3"), SpecId::OSAKA);
        let mut gas = GasTracker::new(100_000);
        let limits = NativeCallLimits {
            output_bytes: 31,
            ..LIMITS
        };
        let result = invoke(
            &mut evm,
            &parent(),
            &mut gas,
            &NativeCallBudget::new(1, 70_000),
            limits,
        );
        assert!(matches!(
            result,
            Err(PrecompileError::Halt(PrecompileHalt::OutOfGas))
        ));
        assert_eq!(
            evm.state_mut()
                .storage_slot_untracked(&TARGET, &U256::ZERO)
                .unwrap(),
            U256::ZERO
        );
    }

    #[test]
    fn input_bound_rejects_before_work_and_account_load() {
        let mut evm = evm(bytes!("00"), SpecId::OSAKA);
        let mut gas = GasTracker::new(100_000);
        let result = native_call_with_env(
            &mut evm,
            &tx_env(),
            &parent(),
            &mut gas,
            &NativeCallBudget::new(1, 70_000),
            TARGET,
            Bytes::from(vec![0; 257]),
            false,
            LIMITS,
        );
        assert!(matches!(
            result,
            Err(PrecompileError::Halt(PrecompileHalt::OutOfGas))
        ));
        assert_eq!(gas.spent(), 0);
    }

    #[test]
    fn work_reservation_is_not_restored_by_success_or_revert() {
        for code in [bytes!("00"), bytes!("5f5ffd")] {
            let mut evm = evm(code, SpecId::OSAKA);
            let mut gas = GasTracker::new(200_000);
            let budget = NativeCallBudget::new(2, 50_000);
            let _ = invoke(&mut evm, &parent(), &mut gas, &budget, LIMITS);
            assert_eq!(budget.remaining_work.get(), 0);
            assert_eq!(budget.remaining_calls.get(), 1);
            assert!(matches!(
                invoke(&mut evm, &parent(), &mut gas, &budget, LIMITS),
                Err(PrecompileError::Halt(PrecompileHalt::OutOfGas))
            ));
        }
    }

    #[test]
    fn state_reservoir_is_capped_and_unforwarded_gas_is_retained() {
        let mut evm = evm(bytes!("60015f5500"), SpecId::AMSTERDAM);
        let mut gas = GasTracker::new_with_execution_gas_and_reservoir(500_000, 100_000);
        let initial = gas.remaining() + gas.reservoir();
        let limits = NativeCallLimits {
            execution_gas: 200_000,
            state_gas: 1000,
            ..LIMITS
        };
        let result = invoke(
            &mut evm,
            &parent(),
            &mut gas,
            &NativeCallBudget::new(1, 201_000),
            limits,
        );
        assert!(
            result.is_ok(),
            "state gas may spill into the capped execution allowance: {result:?}"
        );
        assert!(gas.state_gas_spent() > 1000);
        // EVM2 funds the child's state-gas spill from the parent's untouched
        // reservoir on merge, returning the corresponding execution gas.
        assert_eq!(
            gas.reservoir(),
            100_000 - u64::try_from(gas.state_gas_spent()).unwrap()
        );
        assert_eq!(gas.state_gas_spilled(), 0);
        assert!(gas.remaining() + gas.reservoir() < initial);
        assert_eq!(
            evm.state_mut()
                .storage_slot_untracked(&TARGET, &U256::ZERO)
                .unwrap(),
            U256::ONE
        );
    }

    #[test]
    fn eip150_retains_parent_gas_when_child_exhausts_allowance() {
        // Infinite JUMP loop.
        let mut evm = evm(bytes!("5b5f56"), SpecId::OSAKA);
        let mut gas = GasTracker::new(10_000);
        let result = invoke(
            &mut evm,
            &parent(),
            &mut gas,
            &NativeCallBudget::new(1, 70_000),
            LIMITS,
        );
        assert!(matches!(result, Err(PrecompileError::Halt(_))));
        assert_eq!(gas.remaining(), 7400 / 64);
    }

    #[test]
    fn delegated_code_runs_at_target_and_preserves_native_caller() {
        let delegated = Address::with_last_byte(0xcc);
        let mut db = InMemoryDB::default();
        db.insert_account_info(
            &TARGET,
            AccountInfo::default().with_code(Bytecode::new_eip7702(delegated)),
        );
        db.insert_account_info(
            &delegated,
            AccountInfo::default()
                .with_code(Bytecode::new_legacy(bytes!("335f523060205260405ff3"))),
        );
        let mut evm = Evm::<BaseEvmTypes>::new(
            SpecId::OSAKA,
            BlockEnvExt::default(),
            TxRegistry::new(),
            db,
            Precompiles::base(SpecId::OSAKA),
        );
        let mut gas = GasTracker::new(100_000);
        let output = invoke(
            &mut evm,
            &parent(),
            &mut gas,
            &NativeCallBudget::new(1, 70_000),
            LIMITS,
        )
        .unwrap()
        .into_bytes();
        assert_eq!(
            U256::from_be_slice(&output[..32]),
            U256::from_be_slice(NATIVE.as_slice())
        );
        assert_eq!(
            U256::from_be_slice(&output[32..]),
            U256::from_be_slice(TARGET.as_slice())
        );
        assert!(gas.spent() > 5200);
    }

    #[test]
    fn reservations_cannot_overflow() {
        let budget = NativeCallBudget::new(1, u64::MAX);
        assert!(budget.reserve(u64::MAX, 1).is_err());
        assert_eq!(budget.remaining_calls.get(), 1);
        assert_eq!(budget.remaining_work.get(), u64::MAX);
        assert!(NativeCallBudget::new(0, u64::MAX).reserve(0, 0).is_err());
    }

    #[test]
    fn native_entrypoint_uses_evm_transaction_context_for_contract_call() {
        let mut db = InMemoryDB::default();
        db.insert_account_info(
            &TARGET,
            AccountInfo::default().with_code(Bytecode::new_legacy(bytes!(
                "335f52326020523a6040524660605260805ff3"
            ))),
        );
        let mut precompiles = Precompiles::<BaseEvmTypes>::base(SpecId::OSAKA);
        precompiles.as_map_mut().insert(Precompile::new(
            NATIVE,
            PrecompileId::custom("native-context-test"),
            |evm, message, gas| {
                native_call(
                    evm,
                    message,
                    gas,
                    &NativeCallBudget::new(1, 70_000),
                    TARGET,
                    Bytes::new(),
                    false,
                    LIMITS,
                )
            },
        ));
        let mut evm = Evm::<BaseEvmTypes>::new(
            SpecId::OSAKA,
            BlockEnvExt::default(),
            TxRegistry::new(),
            db,
            precompiles,
        );
        let mut message = parent();
        message.gas_limit = 100_000;
        let result = Host::execute_message(&mut evm, &tx_env(), &mut message).unwrap();
        assert!(result.stop.is_success());
        let words = result
            .output
            .chunks_exact(32)
            .map(U256::from_be_slice)
            .collect::<Vec<_>>();
        assert_eq!(
            words,
            vec![
                U256::from_be_slice(NATIVE.as_slice()),
                U256::from_be_slice(ORIGIN.as_slice()),
                U256::from(17),
                U256::from(42431),
            ]
        );
        assert!(result.gas.spent() > 2600);
        assert!(evm.precompile_tx_env().is_none());
    }

    #[test]
    fn missing_runtime_context_is_fatal_instead_of_fabricating_origin() {
        let mut evm = evm(bytes!("00"), SpecId::OSAKA);
        let mut gas = GasTracker::new(100_000);
        let result = native_call(
            &mut evm,
            &parent(),
            &mut gas,
            &NativeCallBudget::new(1, 70_000),
            TARGET,
            Bytes::new(),
            false,
            LIMITS,
        );
        assert!(matches!(result, Err(PrecompileError::Fatal(_))));
        assert_eq!(gas.spent(), 0);
    }
}
