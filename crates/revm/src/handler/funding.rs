//! Transaction-handler callbacks executed with ordinary EVM frames.

use super::*;
use alloy_primitives::Bytes;
use revm::{
    bytecode::opcode::{CALL, STATICCALL},
    context_interface::{LocalContextTr, context::take_error},
    interpreter::{
        CallInput, CallInputs, CallScheme, CallValue, InstructionResult, InterpreterResult,
        SharedMemory, instructions::contract::load_account_delegated, interpreter::resize_memory,
        interpreter_action::FrameInit,
    },
};
use tempo_precompiles::tip20_funder::permission::FundingPermission;

/// Protocol-provided callback context, never decoded from application calldata.
pub(super) struct FundingCall {
    pub caller: Address,
    pub source: Address,
    pub data: Bytes,
    pub is_static: bool,
    pub permission: Option<FundingPermission>,
}

impl<DB: alloy_evm::Database, I> TempoEvmHandler<DB, I> {
    /// Runs one callback; the transaction handler owns the surrounding funding and batch checkpoint.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "funding transaction admission is not enabled")
    )]
    pub(super) fn execute_funding_call_with<F>(
        &mut self,
        evm: &mut TempoEvm<DB, I>,
        gas: &mut GasTracker,
        call: FundingCall,
        mut run_loop: F,
    ) -> Result<FrameResult, EVMError<DB::Error, TempoInvalidTransaction>>
    where
        F: FnMut(
            &mut Self,
            &mut TempoEvm<DB, I>,
            FrameInit,
        ) -> Result<FrameResult, EVMError<DB::Error, TempoInvalidTransaction>>,
    {
        debug_assert!(evm.frame_stack().index().is_none());
        if let Some(permission) = &call.permission {
            if call.is_static
                || !permission.matches(call.caller, evm.ctx().tx().caller(), call.source)
            {
                return Err(EVMError::Custom(
                    "invalid native funding permission binding".into(),
                ));
            }
            let actions = evm.actions.clone();
            let limit = gas.remaining();
            let (initialized, used) = StorageCtx::enter_ctx_with_gas_limit(
                evm.ctx_mut(),
                limit,
                gas.reservoir(),
                actions,
                || permission.initialize(),
            );
            if let Err(error) = initialized {
                let output = error
                    .into_precompile_result(used, gas.reservoir())
                    .map_err(|error| EVMError::Custom(error.to_string()))?;
                let mut result = FrameResult::Call(CallOutcome::new(
                    precompile_output_to_interpreter_result(output, limit),
                    0..0,
                ));
                self.last_frame_result(evm, &mut result, gas)?;
                return Ok(result);
            }
            assert!(gas.record_regular_cost(used));
        }
        let opcode = if call.is_static { STATICCALL } else { CALL };
        let base_cost = u64::from(evm.inner.instruction.gas_table()[opcode as usize]);
        let ctx = evm.ctx_mut();
        let mut memory = SharedMemory::new_with_buffer(ctx.local().shared_memory_buffer().clone());
        memory.set_memory_limit(ctx.cfg().memory_limit());
        let mut setup_gas =
            Gas::new_with_regular_gas_and_reservoir(gas.remaining(), gas.reservoir());
        let setup = (|| {
            if !setup_gas.record_regular_cost(base_cost) {
                return Err(InstructionResult::OutOfGas);
            }
            resize_memory(
                &mut setup_gas,
                &mut memory,
                ctx.cfg().gas_params(),
                0,
                call.data.len(),
            )?;
            let (cost, state_cost, bytecode, hash) = load_account_delegated(
                ctx,
                ctx.cfg().spec().into(),
                setup_gas.remaining(),
                call.source,
                false,
                !call.is_static,
            )?;
            if !setup_gas.record_regular_cost(cost) || !setup_gas.record_state_cost(state_cost) {
                return Err(InstructionResult::OutOfGas);
            }
            Ok((state_cost, bytecode, hash))
        })();
        take_error::<EVMError<DB::Error, TempoInvalidTransaction>, _>(ctx.error())?;
        let mut result = match setup {
            Ok((state_cost, bytecode, hash)) => {
                ctx.journal_mut().load_account(call.caller)?;
                let input = FrameInit {
                    depth: 0,
                    memory,
                    frame_input: FrameInput::Call(Box::new(CallInputs {
                        input: CallInput::Bytes(call.data),
                        return_memory_offset: 0..0,
                        gas_limit: setup_gas.remaining(),
                        reservoir: setup_gas.reservoir(),
                        bytecode_address: call.source,
                        known_bytecode: (hash, bytecode),
                        target_address: call.source,
                        caller: call.caller,
                        value: CallValue::Transfer(U256::ZERO),
                        scheme: if call.is_static {
                            CallScheme::StaticCall
                        } else {
                            CallScheme::Call
                        },
                        is_static: call.is_static,
                        charged_new_account_state_gas: state_cost != 0,
                    })),
                };
                if let Some(permission) = &call.permission {
                    permission
                        .enter(|| run_loop(self, evm, input))
                        .map_err(|error| EVMError::Custom(error.to_string()))??
                } else {
                    run_loop(self, evm, input)?
                }
            }
            Err(result) => FrameResult::Call(CallOutcome::new(
                InterpreterResult {
                    result,
                    gas: setup_gas,
                    output: Bytes::new(),
                },
                0..0,
            )),
        };
        self.last_frame_result(evm, &mut result, gas)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
