use crate::{evm::TempoContext, tip1060};
use alloy_evm::Database;
use revm::{
    bytecode::opcode::SSTORE,
    handler::instructions::EthInstructions,
    interpreter::{
        Instruction, InstructionContext, InstructionResult,
        instructions::{gas_table_spec, instruction_table},
        interpreter::EthInterpreter,
        push,
    },
};
use tempo_chainspec::hardfork::TempoHardfork;

/// Instruction ID for opcode returning milliseconds timestamp.
const MILLIS_TIMESTAMP: u8 = 0x4F;

/// Gas cost for [`MILLIS_TIMESTAMP`] instruction. Same as other opcodes accessing block information.
const MILLIS_TIMESTAMP_GAS_COST: u16 = 2;

/// Alias for Tempo-specific [`InstructionContext`].
type TempoInstructionContext<'a, DB> = InstructionContext<'a, TempoContext<DB>, EthInterpreter>;

/// Opcode returning current timestamp in milliseconds.
fn millis_timestamp<DB: Database>(
    context: TempoInstructionContext<'_, DB>,
) -> Result<(), InstructionResult> {
    push!(context.interpreter, context.host.block.timestamp_millis());
    Ok(())
}

/// Returns configured instructions table for Tempo.
pub(crate) fn tempo_instructions<DB: Database>(
    spec: TempoHardfork,
) -> EthInstructions<EthInterpreter, TempoContext<DB>> {
    let evm_spec = spec.into();

    // +T7: Enable TIP-1060 sstore hook
    let mut instructions = if spec.is_t7() {
        EthInstructions::new(
            {
                let mut table = instruction_table::<EthInterpreter, TempoContext<DB>>();
                table[SSTORE as usize] = Instruction::new(tip1060::sstore);
                table
            },
            gas_table_spec(evm_spec),
            evm_spec,
        )
    } else {
        EthInstructions::new_mainnet_with_spec(spec.into())
    };

    if !spec.is_t1c() {
        instructions.insert_instruction(
            MILLIS_TIMESTAMP,
            Instruction::new(millis_timestamp),
            MILLIS_TIMESTAMP_GAS_COST,
        );
    }
    instructions
}
