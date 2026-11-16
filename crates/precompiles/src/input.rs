//! Call input that is read only once gas covers its cost.

use crate::input_cost;
use evm2::{
    Evm, EvmTypesHost,
    interpreter::{GasTracker, InterpreterState, Message},
};
use tempo_chainspec::hardfork::TempoHardfork;

/// A call's input, whose bytes are readable only once gas covers their [`input_cost`].
pub struct CallInput<'a>(&'a [u8]);

impl<'a> CallInput<'a> {
    /// Wraps the input of `message`, a call to a precompile.
    #[inline]
    #[expect(clippy::disallowed_methods, reason = "the bytes stay behind `read`")]
    pub fn of_message<T: EvmTypesHost>(evm: &'a Evm<'_, T>, message: &'a Message<T>) -> Self {
        Self(evm.message_input(message))
    }

    /// Wraps the input of the frame that `state` runs.
    #[inline]
    #[expect(clippy::disallowed_methods, reason = "the bytes stay behind `read`")]
    pub fn of_frame<T: EvmTypesHost>(state: &'a InterpreterState<'_, '_, T>) -> Self {
        Self(state.input())
    }

    /// Returns the bytes if `gas` covers their [`input_cost`] at `spec`, and `None` otherwise.
    ///
    /// Charges nothing: the dispatcher that receives the bytes deducts the cost.
    #[inline]
    pub fn read(self, spec: TempoHardfork, gas: &GasTracker) -> Option<&'a [u8]> {
        input_cost(spec, self.0.len())
            .is_ok_and(|cost| gas.remaining() >= cost)
            .then_some(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_requires_input_cost() {
        let bytes = [0u8; 33];
        for (spec, cost) in [(TempoHardfork::T10, 12), (TempoHardfork::T11, 60)] {
            let read = |limit| CallInput(&bytes).read(spec, &GasTracker::new(limit));
            assert_eq!(read(cost - 1), None);
            assert_eq!(read(cost), Some(&bytes[..]));
        }
    }
}
