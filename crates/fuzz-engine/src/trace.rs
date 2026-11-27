//! The call frames of each transaction, recorded by an inspector on the block's EVM.

use std::{cell::RefCell, mem, rc::Rc};

use alloy_primitives::{Bytes, Log};
use evm2::{
    EvmTypesHost, Inspector, InspectorConfig,
    interpreter::{Interpreter, Message, MessageKind, MessageResult},
};
use invariants_core::{CallKind, Frame, Outcome};
use tempo_evm::{TempoEvm, TempoEvmTypes};
use tempo_fuzz_types::TxOutcome;

/// The frames of the transactions an EVM executes, read one transaction at a time.
pub(crate) struct Calls(Rc<RefCell<Trace>>);

impl Calls {
    /// Records the calls `evm` makes from now on, except its system calls.
    pub(crate) fn install(evm: &mut TempoEvm<'_>) -> Self {
        let trace = Rc::default();
        evm.set_inspector(Tracer(Rc::clone(&trace)));
        Self(trace)
    }

    /// The frames of the transaction executed since the last call, which ended with `outcome` and
    /// emitted `logs` logs, and starts the next transaction's. `None` when a frame never ended or a
    /// successful transaction's logs are not the ones the frames saw, as when the executor emitted
    /// some outside the inspector, so their log ranges would be wrong.
    pub(crate) fn take(&self, logs: usize, outcome: &TxOutcome) -> Option<Vec<Frame>> {
        let trace = mem::take(&mut *self.0.borrow_mut());
        let succeeded = *outcome == TxOutcome::Success;
        if !trace.open.is_empty() || succeeded && trace.logs != logs {
            return None;
        }
        let mut frames = trace.frames;
        // Parents come before their children, so each frame's parent is already settled. A failed
        // transaction undoes every call, even those a batch made before the one that failed.
        for index in 0..frames.len() {
            let parent_committed = frames[index]
                .parent
                .is_none_or(|parent| frames[parent].committed);
            let frame = &mut frames[index];
            frame.committed &= succeeded && parent_committed;
            if !frame.committed {
                frame.logs = frame.logs.start..frame.logs.start;
            }
        }
        Some(frames)
    }
}

/// What the inspector has seen of the current transaction.
#[derive(Default)]
struct Trace {
    frames: Vec<Frame>,
    /// The frames that have started and not ended, each with the log count when it started.
    open: Vec<(usize, usize)>,
    /// The logs emitted and not undone by a revert.
    logs: usize,
}

impl Trace {
    fn enter(&mut self, message: &Message<TempoEvmTypes>, input: Bytes) {
        let parent = self.open.last().map(|&(parent, _)| parent);
        self.open.push((self.frames.len(), self.logs));
        self.frames.push(Frame {
            parent,
            kind: match message.kind {
                MessageKind::StaticCall => CallKind::StaticCall,
                MessageKind::DelegateCall => CallKind::DelegateCall,
                MessageKind::CallCode => CallKind::CallCode,
                MessageKind::Create => CallKind::Create,
                MessageKind::Create2 => CallKind::Create2,
                _ => CallKind::Call,
            },
            caller: message.caller,
            target: message.destination,
            input,
            value: message.value,
            outcome: Outcome::Halt,
            committed: false,
            logs: self.logs..self.logs,
        });
    }

    fn exit(&mut self, result: &MessageResult<TempoEvmTypes>) {
        let Some((index, logs)) = self.open.pop() else {
            return;
        };
        let frame = &mut self.frames[index];
        frame.committed = result.is_success();
        frame.outcome = if result.is_success() {
            Outcome::Return(result.output.clone())
        } else if result.stop.is_revert() {
            Outcome::Revert(result.output.clone())
        } else {
            Outcome::Halt
        };
        // A frame that did not return undoes the logs it and its calls emitted.
        if !frame.committed {
            self.logs = logs;
        }
        frame.logs = logs..self.logs;
    }
}

struct Tracer(Rc<RefCell<Trace>>);

impl Inspector<TempoEvmTypes> for Tracer {
    fn inspector_config(&self) -> InspectorConfig {
        InspectorConfig::without_steps()
    }

    fn log(&mut self, _log: &Log, _host: &mut <TempoEvmTypes as EvmTypesHost>::Host<'_>) {
        self.0.borrow_mut().logs += 1;
    }

    fn call(
        &mut self,
        interp: &mut Interpreter<'_, '_, TempoEvmTypes>,
        message: &mut Message<TempoEvmTypes>,
    ) -> Option<MessageResult<TempoEvmTypes>> {
        let input = message.input.to_bytes(interp.memory());
        self.0.borrow_mut().enter(message, input);
        None
    }

    fn call_end(
        &mut self,
        _interp: &mut Interpreter<'_, '_, TempoEvmTypes>,
        _message: &Message<TempoEvmTypes>,
        result: &mut MessageResult<TempoEvmTypes>,
    ) {
        self.0.borrow_mut().exit(result);
    }

    fn create(
        &mut self,
        interp: &mut Interpreter<'_, '_, TempoEvmTypes>,
        message: &mut Message<TempoEvmTypes>,
    ) -> Option<MessageResult<TempoEvmTypes>> {
        self.call(interp, message)
    }

    fn create_end(
        &mut self,
        interp: &mut Interpreter<'_, '_, TempoEvmTypes>,
        message: &Message<TempoEvmTypes>,
        result: &mut MessageResult<TempoEvmTypes>,
    ) {
        self.call_end(interp, message, result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use alloy_primitives::{Address, U256};

    fn frame(parent: Option<usize>, returned: bool, logs: std::ops::Range<usize>) -> Frame {
        Frame {
            parent,
            kind: CallKind::Call,
            caller: Address::ZERO,
            target: Address::ZERO,
            input: Bytes::new(),
            value: U256::ZERO,
            outcome: if returned {
                Outcome::Return(Bytes::new())
            } else {
                Outcome::Revert(Bytes::new())
            },
            committed: returned,
            logs,
        }
    }

    fn calls(frames: Vec<Frame>, open: Vec<(usize, usize)>, logs: usize) -> Calls {
        Calls(Rc::new(RefCell::new(Trace { frames, open, logs })))
    }

    #[test]
    fn a_frame_commits_only_with_every_frame_above_it_and_a_trace_matches_its_receipt() {
        // A reverted call whose own call returned and logged, then a call that returned with two
        // logs.
        let frames = vec![
            frame(None, false, 0..0),
            frame(Some(0), true, 0..1),
            frame(None, true, 0..2),
        ];
        let taken = calls(frames.clone(), Vec::new(), 2)
            .take(2, &TxOutcome::Success)
            .unwrap();
        assert_eq!(
            taken
                .iter()
                .map(|f| (f.committed, f.logs.clone()))
                .collect::<Vec<_>>(),
            [(false, 0..0), (false, 0..0), (true, 0..2)]
        );

        assert_eq!(
            calls(frames.clone(), Vec::new(), 2).take(3, &TxOutcome::Success),
            None
        );
        assert_eq!(
            calls(frames.clone(), vec![(2, 0)], 2).take(2, &TxOutcome::Success),
            None
        );

        // A failed batch undoes the calls before the one that failed, which returned and logged.
        let taken = calls(frames, Vec::new(), 2)
            .take(0, &TxOutcome::Revert)
            .unwrap();
        assert!(taken.iter().all(|f| !f.committed && f.logs.is_empty()));
    }
}
