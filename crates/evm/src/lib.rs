use reth_evm::precompiles::PrecompilesMap;
use reth_revm::{
    Context, Database,
    context::{Block, Cfg, JournalTr},
    handler::{EthPrecompiles, instructions::EthInstructions},
    interpreter::interpreter::EthInterpreter,
    primitives::hardfork::SpecId,
    state::EvmState,
};

pub mod evm;
pub mod handler;

/// Type alias for default TempoEvm
pub type DefaultTempoEvm<CTX, INSP = ()> =
    tempo_revm::TempoEvm<CTX, INSP, EthInstructions<EthInterpreter, CTX>, EthPrecompiles>;

/// Trait that allows for TempoEvm to be built.
pub trait TempoEvmBuilder: Sized {
    /// Type of the context.
    type Context;

    /// Build the TempoEvm.
    fn build_tempo(self) -> DefaultTempoEvm<Self::Context>;

    /// Build the TempoEvm with an inspector
    fn build_tempo_with_inspector<INSP>(
        self,
        inspector: INSP,
    ) -> DefaultTempoEvm<Self::Context, INSP>;
}

impl<BLOCK, TX, CFG, DB, JOURNAL> TempoEvmBuilder for Context<BLOCK, TX, CFG, DB, JOURNAL>
where
    BLOCK: Block,
    TX: reth_revm::context::Transaction,
    CFG: Cfg<Spec = SpecId>,
    DB: Database,
    JOURNAL: JournalTr<Database = DB, State = EvmState>,
{
    type Context = Self;

    fn build_tempo(self) -> DefaultTempoEvm<Self::Context> {
        tempo_revm::TempoEvm::new(self, ())
    }

    fn build_tempo_with_inspector<INSP>(
        self,
        inspector: INSP,
    ) -> DefaultTempoEvm<Self::Context, INSP> {
        tempo_revm::TempoEvm::new(self, inspector)
    }
}
