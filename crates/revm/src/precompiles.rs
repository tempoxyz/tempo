use alloy_evm::{
    Database, EvmInternals,
    precompiles::{Precompile, PrecompileInput, PrecompilesMap},
};
use alloy_primitives::{
    Address,
    map::AddressSet,
};
use revm::{
    Context, Journal,
    context::{Block, Cfg, ContextTr, Transaction},
    handler::{PrecompileProvider, precompile_output_to_interpreter_result},
    interpreter::{CallInputs, InterpreterResult},
};

/// Tempo precompile provider.
#[derive(Clone, Debug)]
pub struct TempoPrecompiles {
    inner: PrecompilesMap,
}

impl TempoPrecompiles {
    /// Creates a new provider from the given precompile map.
    pub const fn new(inner: PrecompilesMap) -> Self {
        Self { inner }
    }

    /// Returns the wrapped precompile map.
    pub const fn as_map(&self) -> &PrecompilesMap {
        &self.inner
    }

    /// Returns the wrapped precompile map mutably.
    pub const fn as_map_mut(&mut self) -> &mut PrecompilesMap {
        &mut self.inner
    }
}

impl From<PrecompilesMap> for TempoPrecompiles {
    fn from(inner: PrecompilesMap) -> Self {
        Self::new(inner)
    }
}

impl<BlockEnv, TxEnv, CfgEnv, DB, Chain>
    PrecompileProvider<Context<BlockEnv, TxEnv, CfgEnv, DB, Journal<DB>, Chain>>
    for TempoPrecompiles
where
    BlockEnv: Block,
    TxEnv: Transaction,
    CfgEnv: Cfg,
    DB: Database,
{
    type Output = InterpreterResult;

    fn set_spec(&mut self, _spec: CfgEnv::Spec) -> bool {
        false
    }

    fn run(
        &mut self,
        context: &mut Context<BlockEnv, TxEnv, CfgEnv, DB, Journal<DB>, Chain>,
        inputs: &CallInputs,
    ) -> Result<Option<InterpreterResult>, String> {
        let Some(precompile) = self.inner.get(&inputs.bytecode_address) else {
            return Ok(None);
        };

        let (block, tx, cfg, journaled_state, _, local) = context.all_mut();

        let precompile_output = {
            let _span = tracing::trace_span!(
                target: "alloy_evm::precompiles",
                "precompile",
                name = precompile.precompile_id().name()
            )
            .entered();
            precompile.call(PrecompileInput {
                data: inputs.input.as_bytes_local(local).as_ref(),
                gas: inputs.gas_limit,
                reservoir: inputs.reservoir,
                caller: inputs.caller,
                value: inputs.call_value(),
                is_static: inputs.is_static,
                internals: EvmInternals::new(journaled_state, block, cfg, tx),
                target_address: inputs.target_address,
                bytecode_address: inputs.bytecode_address,
            })
        }
        .map_err(precompile_error_to_string)?;

        Ok(Some(precompile_output_to_interpreter_result(
            precompile_output,
            inputs.gas_limit,
        )))
    }

    fn warm_addresses(&self) -> &AddressSet {
        <PrecompilesMap as PrecompileProvider<
            Context<BlockEnv, TxEnv, CfgEnv, DB, Journal<DB>, Chain>,
        >>::warm_addresses(&self.inner)
    }

    fn contains(&self, address: &Address) -> bool {
        <PrecompilesMap as PrecompileProvider<
            Context<BlockEnv, TxEnv, CfgEnv, DB, Journal<DB>, Chain>,
        >>::contains(&self.inner, address)
    }
}

#[cold]
#[inline(never)]
fn precompile_error_to_string(error: impl ToString) -> String {
    error.to_string()
}
