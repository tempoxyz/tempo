use super::frame::TempoFrame;
use crate::{ProtocolFeeManager, TempoBlockEnv, TempoFeeManager, TempoTxEnv, instructions};
use alloy_evm::{Database, precompiles::PrecompilesMap};
use alloy_primitives::{Address, U256};
use revm::{
    Context, Inspector,
    context::{Cfg, CfgEnv, ContextError, Evm, FrameStack},
    handler::{EvmTr, FrameInitOrResult, FrameTr, ItemOrResult, instructions::EthInstructions},
    inspector::InspectorEvmTr,
    interpreter::{InitialAndFloorGas, interpreter::EthInterpreter},
};
use std::{cell::RefCell, rc::Rc, sync::Arc};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{storage::StorageActions, storage_credits::NonCreditableSlots};

/// The Tempo EVM context type.
pub type TempoContext<DB> = Context<TempoBlockEnv, TempoTxEnv, CfgEnv<TempoHardfork>, DB>;

/// TempoEvm extends the Evm with Tempo specific types and logic.
#[derive(Debug, derive_more::Deref, derive_more::DerefMut)]
#[expect(clippy::type_complexity)]
pub struct TempoEvm<DB: Database, I> {
    /// Inner EVM type.
    #[deref]
    #[deref_mut]
    pub inner: Evm<
        TempoContext<DB>,
        I,
        EthInstructions<EthInterpreter, TempoContext<DB>>,
        PrecompilesMap,
        TempoFrame,
    >,
    /// The fee collected in `collectFeePreTx` call.
    pub(crate) collected_fee: U256,
    /// The validator-credited amount (post-feeAMM haircut, in the validator's fee token) returned
    /// by the most recent `collectFeePostTx` call.
    ///
    /// Reset to zero before each transaction so it reflects only the current tx.
    pub validator_fee: U256,
    /// The fee token used to pay fees for the current transaction.
    pub(crate) fee_token: Option<Address>,
    /// The expiry timestamp of the access key used by the current transaction.
    /// Populated during validation for keychain-signed transactions or transactions carrying a KeyAuthorization.
    pub(crate) key_expiry: Option<u64>,
    /// When true, skips the `valid_after` time-window check during validation.
    ///
    /// The transaction pool sets this because it intentionally accepts transactions
    /// with a future `valid_after` (queued until executable).
    pub skip_valid_after_check: bool,
    /// When true, skips the AMM liquidity check in `collect_fee_pre_tx`.
    ///
    /// The transaction pool sets this because it performs its own liquidity
    /// validation against a cached view of the AMM state.
    pub skip_liquidity_check: bool,
    /// Set when the intrinsic gas ended up above the transaction gas limit.
    ///
    /// `validate_against_state_and_deduct_caller` can raise the intrinsic gas
    /// after `validate` already accepted the transaction (pre-T1B the keychain
    /// precompile running out of gas sets `initial_regular_gas` to `u64::MAX`).
    /// Recorded by `Handler::tx_gas` and consumed by `Handler::execution`,
    /// which then skips execution entirely.
    pub(crate) intrinsic_gas_exceeds_limit: bool,
    /// Recorded storage actions.
    pub(crate) actions: StorageActions,
    /// Transaction-local protocol slots whose clears must not mint storage credits.
    pub(crate) non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
    /// Internal protocol fee hooks.
    pub(crate) fee_manager: Arc<dyn ProtocolFeeManager<DB>>,
}

impl<DB: Database, I> TempoEvm<DB, I> {
    /// Create a new Tempo EVM.
    pub fn new(ctx: TempoContext<DB>, inspector: I) -> Self {
        let non_creditable_slots = Rc::new(RefCell::new(NonCreditableSlots::empty()));
        let actions = StorageActions::disabled();
        let precompiles = tempo_precompiles::tempo_precompiles(
            &ctx.cfg,
            actions.clone(),
            non_creditable_slots.clone(),
        );

        Self::new_inner(
            Evm {
                instruction: instructions::tempo_instructions(ctx.cfg.spec),
                ctx,
                inspector,
                precompiles,
                frame_stack: FrameStack::new(),
            },
            actions,
            non_creditable_slots,
            Arc::new(TempoFeeManager::new()),
        )
    }
}

impl<DB: Database, I> TempoEvm<DB, I> {
    /// Updates the protocol fee manager used by the EVM.
    pub fn with_fee_manager<F>(self, fee_manager: F) -> Self
    where
        F: ProtocolFeeManager<DB> + 'static,
    {
        self.with_fee_manager_arc(Arc::new(fee_manager))
    }

    /// Updates the protocol fee manager used by the EVM.
    pub fn with_fee_manager_arc(self, fee_manager: Arc<dyn ProtocolFeeManager<DB>>) -> Self {
        let Self {
            inner,
            collected_fee,
            validator_fee,
            fee_token,
            key_expiry,
            skip_valid_after_check,
            skip_liquidity_check,
            intrinsic_gas_exceeds_limit,
            actions,
            non_creditable_slots,
            ..
        } = self;

        Self {
            inner,
            collected_fee,
            validator_fee,
            fee_token,
            key_expiry,
            skip_valid_after_check,
            skip_liquidity_check,
            intrinsic_gas_exceeds_limit,
            actions,
            non_creditable_slots,
            fee_manager,
        }
    }

    /// Inner helper function to create a new Tempo EVM with empty logs.
    #[inline]
    #[expect(clippy::type_complexity)]
    fn new_inner(
        inner: Evm<
            TempoContext<DB>,
            I,
            EthInstructions<EthInterpreter, TempoContext<DB>>,
            PrecompilesMap,
            TempoFrame,
        >,
        actions: StorageActions,
        non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
        fee_manager: Arc<dyn ProtocolFeeManager<DB>>,
    ) -> Self {
        Self {
            inner,
            collected_fee: U256::ZERO,
            validator_fee: U256::ZERO,
            fee_token: None,
            key_expiry: None,
            skip_valid_after_check: false,
            skip_liquidity_check: false,
            intrinsic_gas_exceeds_limit: false,
            actions,
            non_creditable_slots,
            fee_manager,
        }
    }

    /// Computes initial gas limit and reservoir for a transaction given its initial gas spending.
    pub(crate) fn initial_gas_and_reservoir(
        &self,
        init_and_floor_gas: &InitialAndFloorGas,
    ) -> (u64, u64) {
        // Pre-T0 it could happen that the initial gas spending is greater than the gas limit due to faulty validation.
        //
        // Before that it would overflow, so we are reproducing this behavior here by setting the gas limit to u64::MAX and the reservoir to 0.
        if !self.cfg.spec.is_t0() && init_and_floor_gas.initial_total_gas() > self.tx.gas_limit {
            (u64::MAX, 0)
        } else {
            init_and_floor_gas
                .initial_gas_and_reservoir(self.tx.gas_limit, self.cfg.tx_gas_limit_cap())
        }
    }
}

impl<DB: Database, I> TempoEvm<DB, I> {
    /// Consumed self and returns a new Evm type with given Inspector.
    pub fn with_inspector<OINSP>(self, inspector: OINSP) -> TempoEvm<DB, OINSP> {
        let Self {
            inner,
            actions,
            non_creditable_slots,
            fee_manager,
            ..
        } = self;
        TempoEvm::new_inner(
            inner.with_inspector(inspector),
            actions,
            non_creditable_slots,
            fee_manager,
        )
    }

    /// Consumes self and returns a new Evm type with given storage actions.
    pub fn with_actions(mut self, actions: StorageActions) -> Self {
        self.inner.precompiles = tempo_precompiles::tempo_precompiles(
            &self.inner.ctx.cfg,
            actions.clone(),
            self.non_creditable_slots.clone(),
        );
        self.actions = actions;
        self
    }

    /// Consumes self and returns the inner Inspector.
    pub fn into_inspector(self) -> I {
        self.inner.into_inspector()
    }

    /// Returns a reference to the recorded storage actions.
    pub fn actions(&self) -> &StorageActions {
        &self.actions
    }

    /// Returns the transaction-local protocol slots whose clears must not mint storage credits.
    pub fn non_creditable_slots(&self) -> Rc<RefCell<NonCreditableSlots>> {
        self.non_creditable_slots.clone()
    }

    /// Clears all intermediate state from the EVM.
    pub fn clear(&mut self) {
        self.collected_fee = U256::ZERO;
        self.fee_token = None;
        self.key_expiry = None;
        self.non_creditable_slots.borrow_mut().clear();
    }
}

impl<DB, I> EvmTr for TempoEvm<DB, I>
where
    DB: Database,
{
    type Context = TempoContext<DB>;
    type Instructions = EthInstructions<EthInterpreter, TempoContext<DB>>;
    type Precompiles = PrecompilesMap;
    type Frame = TempoFrame;

    fn all(
        &self,
    ) -> (
        &Self::Context,
        &Self::Instructions,
        &Self::Precompiles,
        &FrameStack<Self::Frame>,
    ) {
        (
            &self.inner.ctx,
            &self.inner.instruction,
            &self.inner.precompiles,
            &self.inner.frame_stack,
        )
    }

    fn all_mut(
        &mut self,
    ) -> (
        &mut Self::Context,
        &mut Self::Instructions,
        &mut Self::Precompiles,
        &mut FrameStack<Self::Frame>,
    ) {
        (
            &mut self.inner.ctx,
            &mut self.inner.instruction,
            &mut self.inner.precompiles,
            &mut self.inner.frame_stack,
        )
    }

    fn frame_stack(&mut self) -> &mut FrameStack<Self::Frame> {
        &mut self.inner.frame_stack
    }

    fn frame_init(
        &mut self,
        frame_input: <Self::Frame as FrameTr>::FrameInit,
    ) -> Result<
        ItemOrResult<&mut Self::Frame, <Self::Frame as FrameTr>::FrameResult>,
        ContextError<DB::Error>,
    > {
        let first = self.inner.frame_stack.index().is_none();
        let mut slot = if first {
            self.inner.frame_stack.start_init()
        } else {
            self.inner.frame_stack.get_next()
        };
        let frame = slot.get(TempoFrame::default);
        let result = TempoFrame::init(
            frame,
            &mut self.inner.ctx,
            &mut self.inner.precompiles,
            frame_input,
        );
        let token = slot.consume();
        // Register the initialized slot even when initialization returns an immediate result or error.
        if first {
            unsafe { self.inner.frame_stack.end_init(token) };
        } else {
            unsafe { self.inner.frame_stack.push(token) };
        }
        match result {
            Ok(ItemOrResult::Item(())) => Ok(ItemOrResult::Item(self.inner.frame_stack.get())),
            other => {
                self.inner.frame_stack.pop();
                other.map(|result| result.map_item(|_| unreachable!()))
            }
        }
    }

    fn frame_run(&mut self) -> Result<FrameInitOrResult<Self::Frame>, ContextError<DB::Error>> {
        let frame = self.inner.frame_stack.get();
        let instructions = &self.inner.instruction;
        frame.run(
            &mut self.inner.ctx,
            instructions.gas_table(),
            |frame, ctx| {
                frame.interpreter.run_plain(
                    instructions.instruction_table(),
                    instructions.gas_table(),
                    ctx,
                )
            },
        )
    }

    fn frame_return_result(
        &mut self,
        result: <Self::Frame as FrameTr>::FrameResult,
    ) -> Result<Option<<Self::Frame as FrameTr>::FrameResult>, ContextError<DB::Error>> {
        if self.inner.frame_stack.get().is_finished() {
            self.inner.frame_stack.pop();
        }
        if self.inner.frame_stack.index().is_none() {
            return Ok(Some(result));
        }
        self.inner
            .frame_stack
            .get()
            .return_result(&mut self.inner.ctx, result)?;
        Ok(None)
    }
}

impl<DB, I> InspectorEvmTr for TempoEvm<DB, I>
where
    DB: Database,
    I: Inspector<TempoContext<DB>>,
{
    type Inspector = I;

    fn inspect_frame_run(
        &mut self,
    ) -> Result<FrameInitOrResult<Self::Frame>, ContextError<DB::Error>> {
        let frame = self.inner.frame_stack.get();
        let instructions = &self.inner.instruction;
        let inspector = &mut self.inner.inspector;
        let mut result = frame.run(
            &mut self.inner.ctx,
            instructions.gas_table(),
            |frame, ctx| {
                revm::inspector::inspect_instructions(
                    ctx,
                    &mut frame.interpreter,
                    &mut *inspector,
                    instructions.instruction_table(),
                    instructions.gas_table(),
                )
            },
        )?;
        if let ItemOrResult::Result(output) = &mut result {
            revm::inspector::handler::frame_end(
                &mut self.inner.ctx,
                inspector,
                frame.input(),
                output,
            );
        }
        Ok(result)
    }

    fn all_inspector(
        &self,
    ) -> (
        &Self::Context,
        &Self::Instructions,
        &Self::Precompiles,
        &FrameStack<Self::Frame>,
        &Self::Inspector,
    ) {
        (
            &self.inner.ctx,
            &self.inner.instruction,
            &self.inner.precompiles,
            &self.inner.frame_stack,
            &self.inner.inspector,
        )
    }

    fn all_mut_inspector(
        &mut self,
    ) -> (
        &mut Self::Context,
        &mut Self::Instructions,
        &mut Self::Precompiles,
        &mut FrameStack<Self::Frame>,
        &mut Self::Inspector,
    ) {
        (
            &mut self.inner.ctx,
            &mut self.inner.instruction,
            &mut self.inner.precompiles,
            &mut self.inner.frame_stack,
            &mut self.inner.inspector,
        )
    }
}

#[cfg(test)]
mod tests;
