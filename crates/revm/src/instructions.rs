use crate::evm::TempoContext;
use alloy_evm::Database;
use revm::{
    handler::instructions::EthInstructions,
    interpreter::{Instruction, InstructionContext, interpreter::EthInterpreter, push},
};

/// Instruction ID for opcode returning milliseconds timestamp.
const MILLIS_TIMESTAMP: u8 = 0x4F;

/// Gas cost for [`MILLIS_TIMESTAMP`] instruction. Same as other opcodes accessing block
/// information.
const MILLIS_TIMESTAMP_GAS_COST: u64 = 2;

/// Alias for Tempo-specific [`InstructionContext`].
type TempoInstructionContext<'a, DB> = InstructionContext<'a, TempoContext<DB>, EthInterpreter>;

/// Opcode returning current timestamp in milliseconds.
fn millis_timestamp<DB: Database>(context: TempoInstructionContext<'_, DB>) {
    push!(context.interpreter, context.host.block.timestamp_millis());
}

/// Returns configured instructions table for Tempo.
pub(crate) fn tempo_instructions<DB: Database>() -> EthInstructions<EthInterpreter, TempoContext<DB>>
{
    let mut instructions = EthInstructions::new_mainnet();
    instructions.insert_instruction(
        MILLIS_TIMESTAMP,
        Instruction::new(millis_timestamp, MILLIS_TIMESTAMP_GAS_COST),
    );
    instructions
}
