//! The call frames a transaction enters, recorded as it executes.

use std::{cell::RefCell, rc::Rc};

use evm2::{
    Inspector,
    interpreter::{Interpreter, Message, MessageKind, MessageResult},
};
use invariants_core::{CallKind, Frame};
use tempo_evm::TempoEvmTypes;

/// An inspector that records every frame an EVM enters, precompile calls included, in entry order.
/// Clones share what they record, so one can be installed in an EVM and another read.
#[derive(Debug, Clone, Default)]
pub(crate) struct Tracer(Rc<RefCell<Recorded>>);

#[derive(Debug, Default)]
struct Recorded {
    frames: Vec<Frame>,
    /// The frames entered but not yet exited, innermost last.
    open: Vec<usize>,
}

impl Tracer {
    /// The frames recorded since the last take, which are then forgotten. Depths count from the
    /// transaction's own calls, at depth 0, whatever depth the EVM starts at.
    pub(crate) fn take(&self) -> Vec<Frame> {
        let mut recorded = self.0.borrow_mut();
        recorded.open.clear();
        let mut frames = std::mem::take(&mut recorded.frames);
        let top = frames
            .iter()
            .map(|frame| frame.depth)
            .min()
            .unwrap_or_default();
        for frame in &mut frames {
            frame.depth -= top;
        }
        frames
    }

    fn enter(&self, message: &Message<TempoEvmTypes>) {
        let kind = match message.kind {
            MessageKind::StaticCall => CallKind::StaticCall,
            MessageKind::DelegateCall => CallKind::DelegateCall,
            MessageKind::CallCode => CallKind::CallCode,
            MessageKind::Create2 => CallKind::Create2,
            // `MessageKind` is non-exhaustive: a kind added later records as its family's plain one.
            kind if kind.is_create() => CallKind::Create,
            _ => CallKind::Call,
        };
        let mut recorded = self.0.borrow_mut();
        let index = recorded.frames.len();
        recorded.open.push(index);
        recorded.frames.push(Frame {
            depth: usize::from(message.depth),
            kind,
            caller: message.caller,
            target: message.destination,
            input: message.input.clone(),
            value: message.value,
            success: false,
            output: Default::default(),
        });
    }

    fn exit(&self, result: &MessageResult<TempoEvmTypes>) {
        let mut recorded = self.0.borrow_mut();
        let Some(index) = recorded.open.pop() else {
            return;
        };
        let frame = &mut recorded.frames[index];
        frame.success = result.is_success();
        frame.output = result.output.clone();
    }
}

impl Inspector<TempoEvmTypes> for Tracer {
    fn call(
        &mut self,
        _interp: &mut Interpreter<'_, '_, TempoEvmTypes>,
        message: &mut Message<TempoEvmTypes>,
    ) -> Option<MessageResult<TempoEvmTypes>> {
        self.enter(message);
        None
    }

    fn call_end(
        &mut self,
        _interp: &mut Interpreter<'_, '_, TempoEvmTypes>,
        _message: &Message<TempoEvmTypes>,
        result: &mut MessageResult<TempoEvmTypes>,
    ) {
        self.exit(result);
    }

    fn create(
        &mut self,
        _interp: &mut Interpreter<'_, '_, TempoEvmTypes>,
        message: &mut Message<TempoEvmTypes>,
    ) -> Option<MessageResult<TempoEvmTypes>> {
        self.enter(message);
        None
    }

    fn create_end(
        &mut self,
        _interp: &mut Interpreter<'_, '_, TempoEvmTypes>,
        _message: &Message<TempoEvmTypes>,
        result: &mut MessageResult<TempoEvmTypes>,
    ) {
        self.exit(result);
    }
}
