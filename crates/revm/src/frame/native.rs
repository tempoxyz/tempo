//! Zero-value CALL/STATICCALL transport. Funding sequencing lives in `funding`.

use super::{TempoFrame, funding::FundingContinuation};
use crate::evm::TempoContext;
use alloy_evm::Database;
use alloy_primitives::{Address, Bytes, U256};
use revm::{
    bytecode::opcode::{CALL, STATICCALL},
    context::{Cfg, ContextError, ContextTr, JournalTr},
    context_interface::{context::take_error, journaled_state::JournalCheckpoint},
    handler::{FrameInitOrResult, FrameResult, ItemOrResult, handle_reservoir_remaining_gas},
    interpreter::{
        CallInput, CallInputs, CallOutcome, CallScheme, CallValue, FrameInput, Gas,
        InstructionResult, InterpreterResult, SharedMemory,
        instructions::{GasTable, contract::load_account_delegated},
        interpreter::resize_memory,
        interpreter_action::FrameInit,
    },
};

pub(super) enum NativeAction {
    Call(NativeCall),
    Return(InstructionResult, Bytes),
}

pub(super) struct NativeCall {
    pub target: Address,
    pub data: Bytes,
    pub is_static: bool,
}

#[derive(Debug)]
pub(super) struct NativeFrame {
    pub input: FrameInput,
    pub finished: bool,
    depth: usize,
    checkpoint: JournalCheckpoint,
    gas: Gas,
    memory: SharedMemory,
    funding: FundingContinuation,
}

impl NativeFrame {
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "production funding admission is not enabled")
    )]
    pub(super) fn new<DB: Database>(
        ctx: &mut TempoContext<DB>,
        init: FrameInit,
        funding: FundingContinuation,
    ) -> ItemOrResult<Self, FrameResult> {
        let FrameInput::Call(inputs) = &init.frame_input else {
            unreachable!("native call admission")
        };
        let gas = Gas::new_with_regular_gas_and_reservoir(inputs.gas_limit, inputs.reservoir);
        let early = |status| {
            let mut result = CallOutcome::new(
                InterpreterResult {
                    result: status,
                    gas,
                    output: Bytes::new(),
                },
                inputs.return_memory_offset.clone(),
            );
            result.charged_new_account_state_gas = inputs.charged_new_account_state_gas;
            ItemOrResult::Result(FrameResult::Call(result))
        };
        if init.depth > revm::primitives::constants::CALL_STACK_LIMIT as usize {
            return early(InstructionResult::CallTooDeep);
        }
        if inputs.scheme != CallScheme::Call
            || inputs.is_static
            || !inputs.value.get().is_zero()
            || inputs.target_address != inputs.bytecode_address
        {
            return early(InstructionResult::Revert);
        }
        let checkpoint = ctx.journal_mut().checkpoint();
        if let Some(error) =
            ctx.journal_mut()
                .transfer_loaded(inputs.caller, inputs.target_address, U256::ZERO)
        {
            ctx.journal_mut().checkpoint_revert(checkpoint);
            return early(error.into());
        }
        ItemOrResult::Item(Self {
            input: init.frame_input,
            depth: init.depth,
            checkpoint,
            gas,
            memory: init.memory,
            funding,
            finished: false,
        })
    }

    pub(super) fn run<DB: Database>(
        &mut self,
        ctx: &mut TempoContext<DB>,
        gas_table: &GasTable,
    ) -> Result<FrameInitOrResult<TempoFrame>, ContextError<DB::Error>> {
        let (status, output) = match self.funding.action() {
            NativeAction::Call(call) => match self.call(ctx, gas_table, call) {
                Ok(init) => return Ok(ItemOrResult::Item(init)),
                Err(status) => (status, Bytes::new()),
            },
            NativeAction::Return(status, output) => (status, output),
        };
        take_error::<ContextError<DB::Error>, _>(ctx.error())?;
        if status.is_ok() {
            ctx.journal_mut().checkpoint_commit();
        } else {
            ctx.journal_mut().checkpoint_revert(self.checkpoint);
        }
        self.finished = true;
        let FrameInput::Call(inputs) = &self.input else {
            unreachable!()
        };
        let mut result = CallOutcome::new(
            InterpreterResult {
                result: status,
                output,
                gas: self.gas,
            },
            inputs.return_memory_offset.clone(),
        );
        result.charged_new_account_state_gas = inputs.charged_new_account_state_gas;
        Ok(ItemOrResult::Result(FrameResult::Call(result)))
    }

    fn call<DB: Database>(
        &mut self,
        ctx: &mut TempoContext<DB>,
        gas_table: &GasTable,
        call: NativeCall,
    ) -> Result<FrameInit, InstructionResult> {
        // Account loading assumes the instruction's static gas was charged separately.
        let opcode = if call.is_static { STATICCALL } else { CALL };
        if !self
            .gas
            .record_regular_cost(u64::from(gas_table[opcode as usize]))
        {
            return Err(InstructionResult::OutOfGas);
        }
        resize_memory(
            &mut self.gas,
            &mut self.memory,
            ctx.cfg().gas_params(),
            0,
            call.data.len(),
        )?;
        let (cost, state_cost, bytecode, hash) = load_account_delegated(
            ctx,
            ctx.cfg().spec().into(),
            self.gas.remaining(),
            call.target,
            false,
            !call.is_static,
        )?;
        if !self.gas.record_regular_cost(cost) || !self.gas.record_state_cost(state_cost) {
            return Err(InstructionResult::OutOfGas);
        }
        let gas_limit = ctx
            .cfg()
            .gas_params()
            .call_stipend_reduction(self.gas.remaining());
        if !self.gas.record_regular_cost(gas_limit) {
            return Err(InstructionResult::OutOfGas);
        }
        let FrameInput::Call(parent) = &self.input else {
            unreachable!()
        };
        Ok(FrameInit {
            depth: self.depth + 1,
            memory: self.memory.new_child_context(),
            frame_input: FrameInput::Call(Box::new(CallInputs {
                input: CallInput::Bytes(call.data),
                return_memory_offset: 0..0,
                gas_limit,
                reservoir: self.gas.reservoir(),
                bytecode_address: call.target,
                known_bytecode: (hash, bytecode),
                target_address: call.target,
                caller: parent.target_address,
                value: CallValue::Transfer(U256::ZERO),
                scheme: if call.is_static {
                    CallScheme::StaticCall
                } else {
                    CallScheme::Call
                },
                is_static: call.is_static,
                charged_new_account_state_gas: state_cost != 0,
            })),
        })
    }

    pub(super) fn resume<DB: Database>(
        &mut self,
        ctx: &mut TempoContext<DB>,
        mut result: FrameResult,
    ) -> Result<(), ContextError<DB::Error>> {
        self.memory.free_child_context();
        take_error::<ContextError<DB::Error>, _>(ctx.error())?;
        handle_reservoir_remaining_gas(
            result.instruction_result(),
            self.gas.tracker_mut(),
            result.gas_mut().tracker_mut(),
        );
        self.funding.resume(&result);
        Ok(())
    }
}
