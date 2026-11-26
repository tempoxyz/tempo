//! Interpreter runner for the native benchmark experiment ([tempo_precompiles::native_bench]):
//! runs the frames a native entry replaces in Rust and every other frame as before, through the
//! JIT when one is configured.

use crate::TempoEvmTypes;
use evm2::{
    Evm, ExecutionError, InterpreterRunner,
    interpreter::{InstrStop, Interpreter},
    precompiles::{PrecompileError, PrecompileHalt},
};
use tempo_precompiles::native_bench;

/// Runs native entries in place of their bytecode, then defers to the JIT, if any.
#[derive(Clone, Debug, Default)]
pub struct NativeBenchRunner {
    #[cfg(feature = "jit")]
    pub(crate) jit: Option<crate::jit::JitBackend>,
}

impl InterpreterRunner<TempoEvmTypes> for NativeBenchRunner {
    #[inline]
    fn run<'frame, 'host>(
        &self,
        interpreter: &mut Interpreter<'frame, 'host, TempoEvmTypes>,
        host: &mut Evm<'host, TempoEvmTypes>,
    ) -> Option<InstrStop> {
        if let Some(stop) = run_native(interpreter, host) {
            return Some(stop);
        }
        #[cfg(feature = "jit")]
        if let Some(backend) = &self.jit {
            return evm2_jit::evm2_evm::run_interpreter(backend, interpreter, host);
        }
        None
    }
}

#[inline]
fn run_native<'frame, 'host>(
    interpreter: &mut Interpreter<'frame, 'host, TempoEvmTypes>,
    host: &mut Evm<'host, TempoEvmTypes>,
) -> Option<InstrStop> {
    let message = interpreter.message();
    let code = interpreter.original_bytecode_slice();
    let entry = native_bench::select::<TempoEvmTypes>(
        message,
        interpreter.input(),
        code,
        interpreter.is_static(),
    )?;
    let input = interpreter.input().to_vec();
    let spec = host.config_spec_id();
    let result = native_bench::run(
        host,
        spec,
        entry,
        message,
        &input,
        interpreter.gas_mut().tracker_mut(),
    );
    let (stop, output) = match result {
        Ok(output) => (InstrStop::Return, output.into_bytes()),
        Err(PrecompileError::Revert(output)) => (InstrStop::Revert, output),
        Err(PrecompileError::Halt(PrecompileHalt::OutOfGas)) => {
            return Some(InstrStop::OutOfGas);
        }
        Err(PrecompileError::Halt(_)) => return Some(InstrStop::PrecompileError),
        Err(PrecompileError::Database(error)) => return Some(interpreter.fail(error)),
        Err(PrecompileError::Fatal(error)) => {
            return Some(interpreter.fail(ExecutionError::Fatal(error)));
        }
    };
    if !output.is_empty() {
        if interpreter.memory_mut().resize(0, output.len()).is_err() {
            return Some(InstrStop::MemoryLimitOOG);
        }
        interpreter.memory_mut().set(0, &output);
    }
    interpreter.set_output(0..output.len() as u32);
    Some(stop)
}
