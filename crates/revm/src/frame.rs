//! Frame dispatch for bytecode execution and native continuations.

use crate::evm::TempoContext;
use alloy_evm::{Database, precompiles::PrecompilesMap};
use revm::{
    context::ContextError,
    context_interface::local::OutFrame,
    handler::{EthFrame, FrameInitOrResult, FrameResult, FrameTr, ItemOrResult},
    inspector::InspectorFrame,
    interpreter::{
        FrameInput, InterpreterAction, instructions::GasTable, interpreter::EthInterpreter,
        interpreter_action::FrameInit,
    },
};

mod funding;
mod native;
use native::NativeFrame;

/// A frame dispatched through Revm's execution loop.
#[derive(Debug)]
pub struct TempoFrame {
    kind: FrameKind,
}

#[derive(Debug)]
enum FrameKind {
    Bytecode(EthFrame<EthInterpreter>),
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "production funding admission is not enabled")
    )]
    Native(Box<NativeFrame>),
}

impl Default for TempoFrame {
    fn default() -> Self {
        Self {
            kind: FrameKind::Bytecode(EthFrame::invalid()),
        }
    }
}

impl FrameTr for TempoFrame {
    type FrameInit = FrameInit;
    type FrameResult = FrameResult;
}

impl InspectorFrame for TempoFrame {
    type IT = EthInterpreter;
    fn eth_frame(&mut self) -> Option<&mut EthFrame<EthInterpreter>> {
        match &mut self.kind {
            FrameKind::Bytecode(frame) => Some(frame),
            FrameKind::Native(_) => None,
        }
    }
}

impl TempoFrame {
    pub(crate) fn init<DB: Database>(
        &mut self,
        ctx: &mut TempoContext<DB>,
        precompiles: &mut PrecompilesMap,
        input: FrameInit,
    ) -> Result<ItemOrResult<(), FrameResult>, ContextError<DB::Error>> {
        // Production admission awaits funding authorization and input metering.
        #[cfg(test)]
        if let Some(funding) = tests::admit(ctx, &input) {
            return match NativeFrame::new(ctx, input, funding) {
                ItemOrResult::Item(frame) => {
                    self.kind = FrameKind::Native(Box::new(frame));
                    Ok(ItemOrResult::Item(()))
                }
                ItemOrResult::Result(result) => Ok(ItemOrResult::Result(result)),
            };
        }
        if !matches!(self.kind, FrameKind::Bytecode(_)) {
            *self = Self::default();
        }
        let FrameKind::Bytecode(frame) = &mut self.kind else {
            unreachable!()
        };
        EthFrame::init_with_context(OutFrame::new_init(frame), ctx, precompiles, input)
            .map(|result| result.map_item(|_| ()))
    }

    /// Only interpreter execution differs between the ordinary and inspected loops.
    pub(crate) fn run<DB: Database>(
        &mut self,
        ctx: &mut TempoContext<DB>,
        gas_table: &GasTable,
        execute: impl FnOnce(&mut EthFrame<EthInterpreter>, &mut TempoContext<DB>) -> InterpreterAction,
    ) -> Result<FrameInitOrResult<Self>, ContextError<DB::Error>> {
        match &mut self.kind {
            FrameKind::Bytecode(frame) => {
                let action = execute(frame, ctx);
                frame.process_next_action(ctx, action).inspect(|result| {
                    if result.is_result() {
                        frame.set_finished(true);
                    }
                })
            }
            FrameKind::Native(frame) => frame.run(ctx, gas_table),
        }
    }

    pub(crate) fn return_result<DB: Database>(
        &mut self,
        ctx: &mut TempoContext<DB>,
        result: FrameResult,
    ) -> Result<(), ContextError<DB::Error>> {
        match &mut self.kind {
            FrameKind::Bytecode(frame) => frame.return_result(ctx, result),
            FrameKind::Native(frame) => frame.resume(ctx, result),
        }
    }

    pub(crate) fn is_finished(&self) -> bool {
        match &self.kind {
            FrameKind::Bytecode(frame) => frame.is_finished(),
            FrameKind::Native(frame) => frame.finished,
        }
    }

    pub(crate) fn input(&self) -> &FrameInput {
        match &self.kind {
            FrameKind::Bytecode(frame) => &frame.input,
            FrameKind::Native(frame) => &frame.input,
        }
    }
}

#[cfg(test)]
mod tests;
