use crate::{ProtocolFeeManager, TempoBlockEnv, TempoFeeManager, TempoTxEnv, instructions};
use alloy_evm::{Database, precompiles::PrecompilesMap};
use alloy_primitives::{Address, U256};
use revm::{
    Context, Inspector,
    context::{Cfg, CfgEnv, ContextError, Evm, FrameStack},
    handler::{
        EthFrame, EvmTr, FrameInitOrResult, FrameTr, ItemOrResult, instructions::EthInstructions,
    },
    inspector::InspectorEvmTr,
    interpreter::{InitialAndFloorGas, interpreter::EthInterpreter},
};
use std::{cell::RefCell, rc::Rc, sync::Arc};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{storage::StorageActions, storage_credits::NonCreditableSlots};

/// The Tempo EVM context type.
pub type TempoContext<DB> = Context<TempoBlockEnv, TempoTxEnv, CfgEnv<TempoHardfork>, DB>;

/// Builds an EVM's precompiles from its context and shared accounting state.
pub type PrecompilesBuilder<DB> =
    fn(&TempoContext<DB>, StorageActions, Rc<RefCell<NonCreditableSlots>>) -> PrecompilesMap;

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
        EthFrame<EthInterpreter>,
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
    /// Builds `inner.precompiles`.
    pub(crate) precompiles_builder: PrecompilesBuilder<DB>,
    /// Compiled dispatch and the Tempo gas schedule used to compile it.
    #[cfg(feature = "jit")]
    jit_backend: Option<(crate::jit::JitBackend, TempoHardfork)>,
    /// Dispatch decisions retained until the next root frame begins.
    #[cfg(feature = "jit")]
    jit_decisions: alloy_primitives::map::B256HashMap<crate::jit::LookupDecision>,
}

impl<DB: Database, I> TempoEvm<DB, I> {
    /// Create a new Tempo EVM.
    pub fn new(ctx: TempoContext<DB>, inspector: I) -> Self {
        Self::new_with_precompiles(ctx, inspector, |ctx, actions, non_creditable_slots| {
            tempo_precompiles::tempo_precompiles(&ctx.cfg, actions, non_creditable_slots)
        })
    }

    /// Create a new Tempo EVM with precompiles built from its context and shared accounting state.
    /// Unlike replacing the lookup afterwards, this keeps the Tempo set out of the binary.
    pub fn new_with_precompiles(
        ctx: TempoContext<DB>,
        inspector: I,
        builder: PrecompilesBuilder<DB>,
    ) -> Self {
        let non_creditable_slots = Rc::new(RefCell::new(NonCreditableSlots::empty()));
        let actions = StorageActions::disabled();
        let precompiles = builder(&ctx, actions.clone(), non_creditable_slots.clone());

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
            builder,
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
            precompiles_builder,
            #[cfg(feature = "jit")]
            jit_backend,
            #[cfg(feature = "jit")]
            jit_decisions,
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
            precompiles_builder,
            #[cfg(feature = "jit")]
            jit_backend,
            #[cfg(feature = "jit")]
            jit_decisions,
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
            EthFrame<EthInterpreter>,
        >,
        actions: StorageActions,
        non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
        fee_manager: Arc<dyn ProtocolFeeManager<DB>>,
        precompiles_builder: PrecompilesBuilder<DB>,
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
            precompiles_builder,
            #[cfg(feature = "jit")]
            jit_backend: None,
            #[cfg(feature = "jit")]
            jit_decisions: Default::default(),
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
            precompiles_builder,
            ..
        } = self;
        TempoEvm::new_inner(
            inner.with_inspector(inspector),
            actions,
            non_creditable_slots,
            fee_manager,
            precompiles_builder,
        )
    }

    /// Consumes self and returns a new Evm type with given storage actions.
    pub fn with_actions(mut self, actions: StorageActions) -> Self {
        self.inner.precompiles = (self.precompiles_builder)(
            &self.inner.ctx,
            actions.clone(),
            self.non_creditable_slots.clone(),
        );
        self.actions = actions;
        self
    }

    /// Enables compiled dispatch for bytecode using the backend's gas schedule.
    #[cfg(feature = "jit")]
    pub fn set_jit_backend(&mut self, backend: crate::jit::JitBackend, spec: TempoHardfork) {
        self.jit_backend = Some((backend, spec));
        self.jit_decisions.clear();
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
    type Frame = EthFrame<EthInterpreter>;

    fn all(
        &self,
    ) -> (
        &Self::Context,
        &Self::Instructions,
        &Self::Precompiles,
        &FrameStack<Self::Frame>,
    ) {
        self.inner.all()
    }

    fn all_mut(
        &mut self,
    ) -> (
        &mut Self::Context,
        &mut Self::Instructions,
        &mut Self::Precompiles,
        &mut FrameStack<Self::Frame>,
    ) {
        self.inner.all_mut()
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
        #[cfg(feature = "jit")]
        if self.inner.frame_stack.index().is_none() {
            self.jit_decisions.clear();
        }
        self.inner.frame_init(frame_input)
    }

    fn frame_run(&mut self) -> Result<FrameInitOrResult<Self::Frame>, ContextError<DB::Error>> {
        #[cfg(feature = "jit")]
        if let Some((backend, spec)) = &self.jit_backend
            && self.inner.ctx.cfg.spec == *spec
            && spec.is_t1c()
            && !self.inner.ctx.cfg.enable_amsterdam_eip8037
        {
            let frame = self.inner.frame_stack.get();
            let code_hash = frame.interpreter.bytecode.get_or_calculate_hash();
            // Compiled resume indices differ from interpreter PCs. Keep the original
            // decision and compiled handle alive across every CALL/CREATE suspension.
            let decision = self.jit_decisions.entry(code_hash).or_insert_with(|| {
                backend.lookup(crate::jit::LookupRequest {
                    key: crate::jit::RuntimeCacheKey {
                        code_hash,
                        spec_id: (*spec).into(),
                    },
                    code: frame.interpreter.bytecode.original_bytes(),
                })
            });
            if let crate::jit::LookupDecision::Compiled(program) = decision {
                tracing::trace!(target: "tempo::jit::execution", %code_hash, "Executing compiled bytecode");
                let (ctx, _, _, frames) = self.inner.all_mut();
                let frame = frames.get();
                // SAFETY: revmc is built against the same revm ABI; the program handle
                // keeps its code alive and the lookup key includes the compiled fork.
                let action = unsafe {
                    program
                        .func
                        .call_with_interpreter_with(&mut frame.interpreter, ctx, |ecx| {
                            if spec.is_t7() {
                                ecx.on_sstore = Some(crate::jit::sstore);
                            }
                        })
                };
                return frame
                    .process_next_action::<_, ContextError<DB::Error>>(ctx, action)
                    .inspect(|next| {
                        if next.is_result() {
                            frame.set_finished(true);
                        }
                    });
            }
        }
        self.inner.frame_run()
    }

    fn frame_return_result(
        &mut self,
        result: <Self::Frame as FrameTr>::FrameResult,
    ) -> Result<Option<<Self::Frame as FrameTr>::FrameResult>, ContextError<DB::Error>> {
        self.inner.frame_return_result(result)
    }
}

impl<DB, I> InspectorEvmTr for TempoEvm<DB, I>
where
    DB: Database,
    I: Inspector<TempoContext<DB>>,
{
    type Inspector = I;

    fn all_inspector(
        &self,
    ) -> (
        &Self::Context,
        &Self::Instructions,
        &Self::Precompiles,
        &FrameStack<Self::Frame>,
        &Self::Inspector,
    ) {
        self.inner.all_inspector()
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
        self.inner.all_mut_inspector()
    }
}

#[cfg(test)]
mod tests;
