use crate::{evm::TempoContext, gas_credits};
use alloy_evm::Database;
use revm::{
    bytecode::opcode::SSTORE,
    handler::instructions::EthInstructions,
    interpreter::{
        Instruction, InstructionContext, InstructionResult,
        instructions::{contract, gas_table_spec, host, instruction_table},
        interpreter::EthInterpreter,
        interpreter_types::InputsTr,
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
        let gas = instructions.gas_table()[opcode as usize];
        instructions.insert_instruction(opcode, Instruction::new(instruction), gas);
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

fn sload<DB: Database>(context: TempoInstructionContext<'_, DB>) -> Result<(), InstructionResult> {
    record_slot(&context);
    host::sload(context)
}

fn sstore<DB: Database>(context: TempoInstructionContext<'_, DB>) -> Result<(), InstructionResult> {
    record_slot(&context);
    if context.host.cfg.spec.is_t7() {
        gas_credits::sstore(context)
    } else {
        host::sstore(context)
    }
}

fn create<DB: Database>(context: TempoInstructionContext<'_, DB>) -> Result<(), InstructionResult> {
    tempo_precompiles::storage::access::unsupported();
    contract::create::<false, _, _>(context)
}

fn create2<DB: Database>(
    context: TempoInstructionContext<'_, DB>,
) -> Result<(), InstructionResult> {
    tempo_precompiles::storage::access::unsupported();
    contract::create::<true, _, _>(context)
}

fn selfdestruct<DB: Database>(
    context: TempoInstructionContext<'_, DB>,
) -> Result<(), InstructionResult> {
    tempo_precompiles::storage::access::unsupported();
    host::selfdestruct(context)
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
                table[SSTORE as usize] = Instruction::new(gas_credits::sstore);
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
