use crate::evm::TempoContext;
use alloy_evm::Database;
use revm::{
    handler::instructions::EthInstructions,
    interpreter::{
        Instruction, InstructionContext,
        instructions::{contract, host},
        interpreter::EthInterpreter,
        interpreter_types::InputsTr,
        push,
    },
};
use tempo_chainspec::hardfork::TempoHardfork;

/// Instruction ID for opcode returning milliseconds timestamp.
const MILLIS_TIMESTAMP: u8 = 0x4F;

/// Gas cost for [`MILLIS_TIMESTAMP`] instruction. Same as other opcodes accessing block information.
const MILLIS_TIMESTAMP_GAS_COST: u64 = 2;

/// Alias for Tempo-specific [`InstructionContext`].
type TempoInstructionContext<'a, DB> = InstructionContext<'a, TempoContext<DB>, EthInterpreter>;

/// Opcode returning current timestamp in milliseconds.
fn millis_timestamp<DB: Database>(context: TempoInstructionContext<'_, DB>) {
    push!(context.interpreter, context.host.block.timestamp_millis());
}

/// Only speculative workers pay for opcode access recording.
pub(crate) fn record_storage_accesses<DB: Database>(
    instructions: &mut EthInstructions<EthInterpreter, TempoContext<DB>>,
) {
    use revm::bytecode::opcode;
    for (opcode, instruction) in [
        (opcode::SLOAD, sload::<DB> as _),
        (opcode::SSTORE, sstore::<DB> as _),
        (opcode::CREATE, create::<DB> as _),
        (opcode::CREATE2, create2::<DB> as _),
        (opcode::SELFDESTRUCT, selfdestruct::<DB> as _),
    ] {
        let gas = instructions.instruction_table[opcode as usize].static_gas();
        instructions.insert_instruction(opcode, Instruction::new(instruction, gas));
    }
}

fn record_slot<DB: Database>(context: &TempoInstructionContext<'_, DB>) {
    if let Ok(key) = context.interpreter.stack.peek(0) {
        tempo_precompiles::storage::access::storage(
            context.interpreter.input.target_address(),
            key,
        );
    }
}

fn sload<DB: Database>(context: TempoInstructionContext<'_, DB>) {
    record_slot(&context);
    host::sload(context);
}

fn sstore<DB: Database>(context: TempoInstructionContext<'_, DB>) {
    record_slot(&context);
    host::sstore(context);
}

fn create<DB: Database>(context: TempoInstructionContext<'_, DB>) {
    tempo_precompiles::storage::access::unsupported();
    contract::create::<_, false, _>(context);
}

fn create2<DB: Database>(context: TempoInstructionContext<'_, DB>) {
    tempo_precompiles::storage::access::unsupported();
    contract::create::<_, true, _>(context);
}

fn selfdestruct<DB: Database>(context: TempoInstructionContext<'_, DB>) {
    tempo_precompiles::storage::access::unsupported();
    host::selfdestruct(context);
}

/// Returns configured instructions table for Tempo.
pub(crate) fn tempo_instructions<DB: Database>(
    spec: TempoHardfork,
) -> EthInstructions<EthInterpreter, TempoContext<DB>> {
    let mut instructions = EthInstructions::new_mainnet_with_spec(spec.into());
    if !spec.is_t1c() {
        instructions.insert_instruction(
            MILLIS_TIMESTAMP,
            Instruction::new(millis_timestamp, MILLIS_TIMESTAMP_GAS_COST),
        );
    }
    instructions
}
