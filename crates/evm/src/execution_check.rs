//! The TIP-1180 execution check: which code a registered payment's frames ran.
//!
//! A transaction is classified as a registered payment before execution. During its execution a
//! [`FrameCheck`] inspector looks at every message frame as it starts, and the transaction keeps
//! its registered payment lane only if every frame ran a precompile, no code, a configurable
//! account marker or registered code ([`PaymentCallRegistry::is_registered_code`]). Otherwise it
//! counts against the general lane. The check reads the registry from the backing database, the
//! parent state, as classification does, and changes nothing the transaction observes.

use crate::{TempoEvmTypes, TxLane};
use alloy_primitives::{Address, Log, U256, map::AddressMap};
use evm2::{
    Evm, Inspector, InspectorConfig,
    evm::DynDatabase,
    interpreter::{Interpreter, Message, MessageResult},
};
use std::{cell::RefCell, rc::Rc};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{
    configurable_account::CONFIGURABLE_ACCOUNT_CODE, error::TempoPrecompileError,
    payment_call_registry::PaymentCallRegistry, storage::StorageActions,
};

/// Outcome of the execution check for the transaction being executed, with the registered code
/// lookups of the block.
#[derive(Debug, Default)]
pub(crate) struct ExecutionCheck {
    /// Whether every frame the transaction entered so far was allowed.
    allowed: bool,
    /// The first registry read that failed.
    error: Option<TempoPrecompileError>,
    /// [`PaymentCallRegistry::is_registered_code`] answers for this block, by address. The
    /// registry's effective state does not change within a block, nor does an instance's code.
    registered: AddressMap<bool>,
}

impl ExecutionCheck {
    /// Starts checking a new transaction.
    pub(crate) fn begin(&mut self) {
        self.allowed = true;
        self.error = None;
    }

    /// Returns whether every frame of the checked transaction was allowed.
    ///
    /// # Errors
    /// The registry read that failed.
    pub(crate) fn finish(&mut self) -> Result<bool, TempoPrecompileError> {
        match self.error.take() {
            Some(error) => Err(error),
            None => Ok(self.allowed),
        }
    }

    /// Returns whether every frame so far was allowed, and no registry read failed.
    fn passed(&self) -> bool {
        self.allowed && self.error.is_none()
    }

    /// Returns the lane a transaction classified into `lane` counts toward after the frames
    /// checked so far: a registered payment that entered other code counts toward the general
    /// lane. `None` when a registry read failed.
    pub(crate) fn lane(&self, lane: TxLane) -> Option<TxLane> {
        if self.error.is_some() {
            return None;
        }
        Some(if lane.is_registered_payment() && !self.allowed {
            TxLane::General
        } else {
            lane
        })
    }

    /// Checks a frame that is about to run under `evm`.
    fn check(&mut self, evm: &mut Evm<'_, TempoEvmTypes>, message: &Message<TempoEvmTypes>) {
        if !self.passed() {
            return;
        }
        // Native dispatch on the requested callee runs whatever code is stored there; an empty
        // account runs nothing; the configurable account marker runs Tempo's native shim.
        if evm.precompiles().contains(&message.call_target)
            || message.code.is_empty()
            || message.code.original_bytes() == CONFIGURABLE_ACCOUNT_CODE
        {
            return;
        }
        let address = message.code_address;
        let allowed = match self.registered.get(&address) {
            Some(&registered) => registered,
            None => {
                let spec = evm.config_spec_id();
                let block = evm.block().number.saturating_to::<u64>();
                match is_registered_code(evm.database_mut(), spec, address, block) {
                    Ok(registered) => {
                        self.registered.insert(address, registered);
                        registered
                    }
                    Err(error) => {
                        self.error = Some(error);
                        return;
                    }
                }
            }
        };
        self.allowed = allowed;
    }
}

/// Reads [`PaymentCallRegistry::is_registered_code`] from `parent_state`, bypassing the journal.
fn is_registered_code(
    mut parent_state: &mut dyn DynDatabase,
    spec: TempoHardfork,
    address: Address,
    block: u64,
) -> Result<bool, TempoPrecompileError> {
    crate::TempoStateAccess::<((), ())>::with_read_only_storage_ctx(
        &mut parent_state,
        spec,
        StorageActions::disabled(),
        || PaymentCallRegistry::new().is_registered_code(address, block),
    )
}

/// The inspector slot an execution check displaces, restored when the transaction ends.
pub(crate) type DisplacedInspector<'a> =
    Rc<RefCell<Option<Box<dyn Inspector<TempoEvmTypes> + 'a>>>>;

/// Inspector that runs the execution check on every frame of a registered payment, forwarding
/// every hook to the inspector it displaced, if any.
pub(crate) struct FrameCheck<'a> {
    pub(crate) check: Rc<RefCell<ExecutionCheck>>,
    pub(crate) inner: DisplacedInspector<'a>,
}

impl FrameCheck<'_> {
    /// Runs `f` on the displaced inspector. A hook of the displaced inspector that starts a
    /// message re-enters this inspector; that nested hook is not forwarded.
    fn forward<R>(
        &self,
        f: impl FnOnce(&mut (dyn Inspector<TempoEvmTypes> + '_)) -> R,
    ) -> Option<R> {
        let mut inner = self.inner.try_borrow_mut().ok()?;
        inner.as_mut().map(|inner| f(inner.as_mut()))
    }
}

impl Inspector<TempoEvmTypes> for FrameCheck<'_> {
    fn initialize_interp(&mut self, interp: &mut Interpreter<'_, '_, TempoEvmTypes>) {
        self.forward(|inner| inner.initialize_interp(interp));
    }

    fn inspector_config(&self) -> InspectorConfig {
        self.forward(|inner| inner.inspector_config())
            .unwrap_or_else(InspectorConfig::without_steps)
    }

    fn step(&mut self, interp: &mut Interpreter<'_, '_, TempoEvmTypes>) {
        self.forward(|inner| inner.step(interp));
    }

    fn step_end(&mut self, interp: &mut Interpreter<'_, '_, TempoEvmTypes>) {
        self.forward(|inner| inner.step_end(interp));
    }

    fn log(&mut self, log: &Log, host: &mut Evm<'_, TempoEvmTypes>) {
        self.forward(|inner| inner.log(log, host));
    }

    fn call(
        &mut self,
        interp: &mut Interpreter<'_, '_, TempoEvmTypes>,
        message: &mut Message<TempoEvmTypes>,
    ) -> Option<MessageResult<TempoEvmTypes>> {
        let result = self.forward(|inner| inner.call(interp, message)).flatten();
        // Checked after the displaced inspector, which may change the message.
        self.check.borrow_mut().check(interp.host(), message);
        result
    }

    fn call_end(
        &mut self,
        interp: &mut Interpreter<'_, '_, TempoEvmTypes>,
        message: &Message<TempoEvmTypes>,
        result: &mut MessageResult<TempoEvmTypes>,
    ) {
        self.forward(|inner| inner.call_end(interp, message, result));
    }

    fn create(
        &mut self,
        interp: &mut Interpreter<'_, '_, TempoEvmTypes>,
        message: &mut Message<TempoEvmTypes>,
    ) -> Option<MessageResult<TempoEvmTypes>> {
        // A creation runs initcode no template covers.
        self.check.borrow_mut().allowed = false;
        self.forward(|inner| inner.create(interp, message))
            .flatten()
    }

    fn create_end(
        &mut self,
        interp: &mut Interpreter<'_, '_, TempoEvmTypes>,
        message: &Message<TempoEvmTypes>,
        result: &mut MessageResult<TempoEvmTypes>,
    ) {
        self.forward(|inner| inner.create_end(interp, message, result));
    }

    fn selfdestruct(
        &mut self,
        contract: &Address,
        target: &Address,
        value: &U256,
        host: &mut Evm<'_, TempoEvmTypes>,
    ) {
        self.forward(|inner| inner.selfdestruct(contract, target, value, host));
    }
}
