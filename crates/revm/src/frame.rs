use alloy_primitives::Bytes;
use reth_evm::revm::{
    context::{result::FromStringError, Cfg, ContextTr, FrameToken, JournalTr, OutFrame},
    handler::{CallFrame, ContextTrDbError, EthFrame, FrameData, FrameResult, ItemOrResult, PrecompileProvider},
    interpreter::{
        interpreter::{EthInterpreter, ExtBytecode}, CallInputs, CallOutcome, CallValue, FrameInput, Gas, InputsImpl, InstructionResult, InterpreterResult, SharedMemory
    },
    primitives::CALL_STACK_LIMIT,
    state::Bytecode,
};

pub trait TempoFrameExt {
    /// Make call frame
    #[inline]
    fn make_call_frame<
        CTX: ContextTr,
        PRECOMPILES: PrecompileProvider<CTX, Output = InterpreterResult>,
        ERROR: From<ContextTrDbError<CTX>> + FromStringError,
    >(
        mut this: OutFrame<'_, EthFrame>,
        ctx: &mut CTX,
        precompiles: &mut PRECOMPILES,
        depth: usize,
        memory: SharedMemory,
        inputs: Box<CallInputs>,
    ) -> Result<ItemOrResult<FrameToken, FrameResult>, ERROR> {
        let gas = Gas::new(inputs.gas_limit);
        let return_result = |instruction_result: InstructionResult| {
            Ok(ItemOrResult::Result(FrameResult::Call(CallOutcome {
                result: InterpreterResult {
                    result: instruction_result,
                    gas,
                    output: Bytes::new(),
                },
                memory_offset: inputs.return_memory_offset.clone(),
            })))
        };

        // Check depth
        if depth > CALL_STACK_LIMIT as usize {
            return return_result(InstructionResult::CallTooDeep);
        }

        // Make account warm and loaded.
        let _ = ctx
            .journal_mut()
            .load_account_delegated(inputs.bytecode_address)?;

        // Create subroutine checkpoint
        let checkpoint = ctx.journal_mut().checkpoint();

        // Touch address. For "EIP-158 State Clear", this will erase empty accounts.
        if let CallValue::Transfer(value) = inputs.value {
            // Transfer value from caller to called account Target will get touched even if balance transferred is zero. if let Some(i) = ctx.journal_mut() .transfer(inputs.caller, inputs.target_address, value)? { ctx.journal_mut().checkpoint_revert(checkpoint); return return_result(i.into()); } } let interpreter_input = InputsImpl { target_address: inputs.target_address, caller_address: inputs.caller, bytecode_address: Some(inputs.bytecode_address), input: inputs.input.clone(), call_value: inputs.value.get(), }; let is_static = inputs.is_static; let gas_limit = inputs.gas_limit; if let Some(result) = precompiles.run(ctx, &inputs).map_err(ERROR::from_string)? { if result.result.is_ok() { ctx.journal_mut().checkpoint_commit(); } else { ctx.journal_mut().checkpoint_revert(checkpoint); } return Ok(ItemOrResult::Result(FrameResult::Call(CallOutcome { result, memory_offset: inputs.return_memory_offset.clone(), }))); } let account = ctx
            .journal_mut()
            .load_account_code(inputs.bytecode_address)?;

        let mut code_hash = account.info.code_hash();
        let mut bytecode = account.info.code.clone().unwrap_or_default();

        if let Bytecode::Eip7702(eip7702_bytecode) = bytecode {
            let account = &ctx
                .journal_mut()
                .load_account_code(eip7702_bytecode.delegated_address)?
                .info;
            bytecode = account.code.clone().unwrap_or_default();
            code_hash = account.code_hash();
        }

        // Returns success if bytecode is empty.
        if bytecode.is_empty() {
            ctx.journal_mut().checkpoint_commit();
            return return_result(InstructionResult::Stop);
        }

        // Create interpreter and executes call and push new CallStackFrame.
        this.get(EthFrame::invalid).clear(
            FrameData::Call(CallFrame {
                return_memory_range: inputs.return_memory_offset.clone(),
            }),
            FrameInput::Call(inputs),
            depth,
            memory,
            ExtBytecode::new_with_hash(bytecode, code_hash),
            interpreter_input,
            is_static,
            ctx.cfg().spec().into(),
            gas_limit,
            checkpoint,
        );
        Ok(ItemOrResult::Item(this.consume()))
    }

    }

    ///// Initializes a frame with the given context and precompiles.
    //pub fn init_with_context<
    //    CTX: ContextTr,
    //    PRECOMPILES: PrecompileProvider<CTX, Output = InterpreterResult>,
    //>(
    //    this: OutFrame<'_, Self>,
    //    ctx: &mut CTX,
    //    precompiles: &mut PRECOMPILES,
    //    frame_init: FrameInit,
    //) -> Result<
    //    ItemOrResult<FrameToken, FrameResult>,
    //    ContextError<<<CTX as ContextTr>::Db as Database>::Error>,
    //> {
    //    // TODO cleanup inner make functions
    //    let FrameInit {
    //        depth,
    //        memory,
    //        frame_input,
    //    } = frame_init;
    //
    //    match frame_input {
    //        FrameInput::Call(inputs) => {
    //            Self::make_call_frame(this, ctx, precompiles, depth, memory, inputs)
    //        }
    //        FrameInput::Create(inputs) => Self::make_create_frame(this, ctx, depth, memory, inputs),
    //        FrameInput::Empty => unreachable!(),
    //    }
    //}
}
