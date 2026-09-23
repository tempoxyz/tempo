//! Native policy discovery coordinates ordinary static-call frames.

use crate::evm::TempoContext;
use alloy_evm::Database;
use alloy_primitives::{Bytes, U256};
use alloy_sol_types::{SolCall, SolError, SolValue};
use revm::{
    context_interface::{
        Cfg, ContextTr, JournalTr, context::ContextError, journaled_state::JournalCheckpoint,
    },
    handler::{EthFrame, FrameResult, FrameTr, ItemOrResult},
    inspector::InspectorFrame,
    interpreter::{
        CallInput, CallInputs, CallOutcome, CallScheme, CallValue, FrameInput, Gas,
        InstructionResult, InterpreterResult, SharedMemory,
        instructions::contract::load_account_delegated,
        interpreter::{EthInterpreter, resize_memory},
        interpreter_action::FrameInit,
    },
};
use tempo_contracts::precompiles::{
    FUNDING_POLICY_ADDRESS, IFundingPolicy, IFundingSource, ITIP20,
};
use tempo_precompiles::{
    funding_policy::FundingPolicy,
    storage::{StorageActions, StorageCtx},
    tip20::TIP20Token,
    tip20_funder::cost_budget,
};

/// Standard EVM execution or a native discovery continuation.
#[derive(Debug, Default)]
pub struct TempoFrame {
    pub(crate) eth: EthFrame<EthInterpreter>,
    pub(crate) discovery: Option<Box<DiscoveryFrame>>,
}
impl FrameTr for TempoFrame {
    type FrameInit = FrameInit;
    type FrameResult = FrameResult;
}
impl InspectorFrame for TempoFrame {
    type IT = EthInterpreter;
    fn eth_frame(&mut self) -> Option<&mut EthFrame<EthInterpreter>> {
        if self.discovery.is_some() {
            None
        } else {
            Some(&mut self.eth)
        }
    }
}
impl TempoFrame {
    pub(crate) fn is_finished(&self) -> bool {
        self.discovery
            .as_ref()
            .map_or(self.eth.is_finished(), |d| d.finished)
    }
}

#[derive(Debug)]
pub(crate) struct DiscoveryFrame {
    pub(crate) input: FrameInput,
    depth: usize,
    checkpoint: JournalCheckpoint,
    memory: SharedMemory,
    gas: Gas,
    request: IFundingPolicy::discoverCall,
    result: IFundingPolicy::Discovery,
    sources: Vec<IFundingPolicy::Source>,
    index: usize,
    return_bytes: usize,
    shortfall: U256,
    budget: U256,
    failure: Option<(InstructionResult, Bytes)>,
    pub(crate) finished: bool,
}

impl DiscoveryFrame {
    pub(crate) fn matches<DB: Database>(ctx: &TempoContext<DB>, init: &FrameInit) -> bool {
        let FrameInput::Call(call) = &init.frame_input else {
            return false;
        };
        ctx.cfg.spec.is_t13()
            && call.bytecode_address == FUNDING_POLICY_ADDRESS
            && call.target_address == FUNDING_POLICY_ADDRESS
            && matches!(call.scheme, CallScheme::Call | CallScheme::StaticCall)
            && call
                .input
                .bytes(ctx)
                .starts_with(&IFundingPolicy::discoverCall::SELECTOR)
    }

    pub(crate) fn new<DB: Database>(
        ctx: &mut TempoContext<DB>,
        init: FrameInit,
        actions: StorageActions,
    ) -> Result<Self, ContextError<DB::Error>> {
        let FrameInput::Call(call) = &init.frame_input else {
            unreachable!()
        };
        let gas_limit = call.gas_limit;
        let has_value = !call.value.get().is_zero();
        let checkpoint = ctx.journal_mut().checkpoint();
        let mut gas = Gas::new_with_regular_gas_and_reservoir(call.gas_limit, call.reservoir);
        let data = call.input.bytes(ctx).to_vec();
        let decoded = IFundingPolicy::discoverCall::abi_decode_validate(&data);
        let request = decoded.clone().unwrap_or(IFundingPolicy::discoverCall {
            policyId: 0,
            account: Default::default(),
            token: Default::default(),
            amount: U256::ZERO,
        });
        let mut frame = Self {
            depth: init.depth,
            checkpoint,
            memory: init.memory,
            gas,
            result: IFundingPolicy::Discovery {
                token: request.token,
                amount: request.amount,
                slippageBps: 0,
                sources: vec![],
            },
            request,
            sources: vec![],
            index: 0,
            // Dynamic tuple header, four fields, and the source-array length.
            return_bytes: 192,
            shortfall: U256::ZERO,
            budget: U256::ZERO,
            failure: None,
            finished: false,
            input: init.frame_input,
        };
        if frame.depth > revm::primitives::constants::CALL_STACK_LIMIT as usize {
            frame.failure = Some((InstructionResult::CallTooDeep, Bytes::new()));
            return Ok(frame);
        }
        if decoded.is_err() || has_value {
            frame.revert(IFundingPolicy::InvalidPolicy {}.abi_encode().into());
            return Ok(frame);
        }
        let (loaded, used) = StorageCtx::enter_ctx_with_gas_limit(
            ctx,
            gas.remaining(),
            gas.reservoir(),
            actions,
            || {
                StorageCtx.deduct_gas(tempo_precompiles::input_cost(
                    StorageCtx.spec(),
                    data.len(),
                )?)?;
                let policy = FundingPolicy::new(FUNDING_POLICY_ADDRESS)
                    .get_policy(frame.request.policyId)?;
                StorageCtx.deduct_gas((policy.routes.len() as u64).saturating_mul(3))?;
                let route = policy
                    .routes
                    .into_iter()
                    .find(|r| r.token == frame.request.token)
                    .ok_or(
                        tempo_contracts::precompiles::FundingPolicyError::TokenNotAllowed(
                            IFundingPolicy::TokenNotAllowed {
                                token: frame.request.token,
                            },
                        ),
                    )?;
                let token = TIP20Token::from_address(frame.request.token)?;
                let balance = token.balance_of(ITIP20::balanceOfCall {
                    account: frame.request.account,
                })?;
                Ok::<_, tempo_precompiles::error::TempoPrecompileError>((
                    policy.slippageBps,
                    route.sources,
                    balance,
                ))
            },
        );
        assert!(gas.record_regular_cost(used));
        frame.gas = gas;
        match loaded {
            Ok((slippage, sources, balance)) => {
                frame.result.slippageBps = slippage;
                frame.shortfall = frame.request.amount.saturating_sub(balance);
                if !frame.shortfall.is_zero() {
                    match cost_budget(frame.shortfall, slippage) {
                        Ok(budget) => {
                            frame.budget = budget;
                            frame.sources = sources;
                        }
                        Err(_) => {
                            frame.revert(IFundingPolicy::InvalidPolicy {}.abi_encode().into())
                        }
                    }
                }
            }
            Err(error) => {
                let output = error
                    .into_precompile_result(used, gas.reservoir())
                    .map_err(|e| ContextError::Custom(e.to_string()))?;
                let result =
                    revm::handler::precompile_output_to_interpreter_result(output, gas_limit);
                frame.gas = result.gas;
                frame.failure = Some((result.result, result.output));
            }
        }
        Ok(frame)
    }

    fn revert(&mut self, data: Bytes) {
        self.failure = Some((InstructionResult::Revert, data));
    }

    pub(crate) fn run<DB: Database>(
        &mut self,
        ctx: &mut TempoContext<DB>,
        static_base: u64,
    ) -> Result<ItemOrResult<FrameInit, FrameResult>, ContextError<DB::Error>> {
        if self.failure.is_none() && self.index < self.sources.len() {
            let source = &self.sources[self.index];
            let data = IFundingSource::discoverCall {
                account: self.request.account,
                assetOut: self.request.token,
                amountOut: self.shortfall,
                maxCost: self.budget,
                policyData: source.data.clone(),
            }
            .abi_encode();
            let setup = (|| {
                if !self.gas.record_regular_cost(static_base) {
                    return Err(InstructionResult::OutOfGas);
                }
                resize_memory(
                    &mut self.gas,
                    &mut self.memory,
                    ctx.cfg().gas_params(),
                    0,
                    data.len(),
                )?;
                let (cost, state_cost, bytecode, hash) = load_account_delegated(
                    ctx,
                    ctx.cfg.spec.into(),
                    self.gas.remaining(),
                    source.target,
                    false,
                    false,
                )?;
                if !self.gas.record_regular_cost(cost) || !self.gas.record_state_cost(state_cost) {
                    return Err(InstructionResult::OutOfGas);
                }
                Ok((bytecode, hash))
            })();
            revm::context_interface::context::take_error::<ContextError<DB::Error>, _>(
                ctx.error(),
            )?;
            match setup {
                Ok((bytecode, hash)) => {
                    let limit = self.gas.remaining() - self.gas.remaining() / 64;
                    assert!(self.gas.record_regular_cost(limit));
                    ctx.journal_mut().load_account(FUNDING_POLICY_ADDRESS)?;
                    return Ok(ItemOrResult::Item(FrameInit {
                        depth: self.depth + 1,
                        memory: self.memory.new_child_context(),
                        frame_input: FrameInput::Call(Box::new(CallInputs {
                            input: CallInput::Bytes(data.into()),
                            return_memory_offset: 0..0,
                            gas_limit: limit,
                            reservoir: self.gas.reservoir(),
                            bytecode_address: source.target,
                            known_bytecode: (hash, bytecode),
                            target_address: source.target,
                            caller: FUNDING_POLICY_ADDRESS,
                            value: CallValue::Transfer(U256::ZERO),
                            scheme: CallScheme::StaticCall,
                            is_static: true,
                            charged_new_account_state_gas: false,
                        })),
                    }));
                }
                Err(error) => self.failure = Some((error, Bytes::new())),
            }
        }
        let (result, mut output) = self
            .failure
            .take()
            .unwrap_or_else(|| (InstructionResult::Return, self.result.abi_encode().into()));
        // Native allocations and return data use the active fork's memory schedule.
        let result = if resize_memory(
            &mut self.gas,
            &mut self.memory,
            ctx.cfg().gas_params(),
            0,
            output.len(),
        )
        .is_err()
        {
            InstructionResult::OutOfGas
        } else {
            result
        };
        if result.is_halt() {
            output = Bytes::new();
        }
        if result.is_ok() {
            ctx.journal_mut().checkpoint_commit();
        } else {
            ctx.journal_mut().checkpoint_revert(self.checkpoint);
        }
        self.finished = true;
        let FrameInput::Call(call) = &self.input else {
            unreachable!()
        };
        let mut outcome = CallOutcome::new(
            InterpreterResult {
                result,
                gas: self.gas,
                output,
            },
            call.return_memory_offset.clone(),
        );
        outcome.was_precompile_called = true;
        outcome.charged_new_account_state_gas = call.charged_new_account_state_gas;
        Ok(ItemOrResult::Result(FrameResult::Call(outcome)))
    }

    pub(crate) fn accept<DB: Database>(&mut self, ctx: &mut TempoContext<DB>, result: FrameResult) {
        self.memory.free_child_context();
        // Static children cannot consume state gas or produce storage refunds.
        if result.instruction_result().is_ok_or_revert() {
            self.gas.erase_cost(result.gas().remaining());
        }
        if !result.instruction_result().is_ok() {
            self.revert(result.output().into_data());
            return;
        }
        let output = result.output().into_data();
        if resize_memory(
            &mut self.gas,
            &mut self.memory,
            ctx.cfg().gas_params(),
            0,
            output.len(),
        )
        .is_err()
            || !self
                .gas
                .record_regular_cost((output.len() as u64).div_ceil(32).saturating_mul(3))
        {
            self.failure = Some((InstructionResult::OutOfGas, Bytes::new()));
            return;
        }
        let source = self.sources[self.index].target;
        // ABI offsets may alias. Meter the expanded result before decoding allocates candidate data.
        let Some(return_bytes) = candidate_return_bytes(&output, self.return_bytes) else {
            self.revert(
                IFundingPolicy::InvalidCandidate { source }
                    .abi_encode()
                    .into(),
            );
            return;
        };
        if resize_memory(
            &mut self.gas,
            &mut self.memory,
            ctx.cfg().gas_params(),
            0,
            return_bytes,
        )
        .is_err()
        {
            self.failure = Some((InstructionResult::OutOfGas, Bytes::new()));
            return;
        }
        self.return_bytes = return_bytes;
        match IFundingSource::discoverCall::abi_decode_returns_validate(&output) {
            Ok(candidates)
                if candidates.iter().all(|c| {
                    !c.requestData.is_empty()
                        && !c.availableAmount.is_zero()
                        && c.availableAmount <= self.shortfall
                }) =>
            {
                self.result.sources.extend(candidates.into_iter().map(|c| {
                    IFundingPolicy::SourceCandidate {
                        target: source,
                        data: c.requestData,
                        availableAmount: c.availableAmount,
                    }
                }));
                self.index += 1;
            }
            _ => self.revert(
                IFundingPolicy::InvalidCandidate { source }
                    .abi_encode()
                    .into(),
            ),
        }
    }
}

// Read only offsets and lengths; full ABI and candidate validation follows metering.
fn candidate_return_bytes(output: &[u8], mut total: usize) -> Option<usize> {
    let word = |offset: usize| -> Option<usize> {
        U256::from_be_slice(output.get(offset..offset.checked_add(32)?)?)
            .try_into()
            .ok()
    };
    let array = word(0)?;
    let count = word(array)?;
    let base = array.checked_add(32)?;
    let end = base.checked_add(count.checked_mul(32)?)?;
    output.get(base..end)?;
    for index in 0..count {
        let tuple = base.checked_add(word(base + index * 32)?)?;
        output.get(tuple..tuple.checked_add(64)?)?;
        let data = tuple.checked_add(word(tuple)?)?;
        let len = word(data)?;
        let start = data.checked_add(32)?;
        output.get(start..start.checked_add(len)?)?;
        total = total
            .checked_add(160)?
            .checked_add(len.div_ceil(32).checked_mul(32)?)?;
    }
    Some(total)
}
