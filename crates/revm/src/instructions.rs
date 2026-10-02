use crate::{evm::TempoContext, gas_credits};
use alloy_evm::Database;
use revm::{
    bytecode::opcode::SSTORE,
    context_interface::Host as _,
    handler::instructions::EthInstructions,
    interpreter::{
        Instruction, InstructionContext, InstructionResult, as_usize_or_fail, gas,
        instructions::{contract, gas_table_spec, host, instruction_table},
        interpreter::{EthInterpreter, resize_memory},
        interpreter_types::InputsTr,
        popn_top, push,
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
        (opcode::KECCAK256, worker_keccak256::<DB> as _),
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

// A repeated short hash should not contend on alloy's process-wide cache.
// Keys are compared byte-for-byte, and retained memory is bounded per worker.
std::thread_local! {
    static LAST_HASH: std::cell::RefCell<([u8; 88], usize, alloy_primitives::B256)> =
        const { std::cell::RefCell::new(([0; 88], 0, alloy_primitives::B256::ZERO)) };
}

fn worker_hash(input: &[u8]) -> alloy_primitives::B256 {
    if input.is_empty() || input.len() > 88 {
        return alloy_primitives::keccak256(input);
    }
    LAST_HASH.with_borrow_mut(|(bytes, len, hash)| {
        if *len != input.len() || bytes[..*len] != *input {
            *hash = alloy_primitives::keccak256(input);
            bytes[..input.len()].copy_from_slice(input);
            *len = input.len();
        }
        *hash
    })
}

/// Matches revm's KECCAK256 stack, gas and memory operations; only the pure
/// digest computation uses a worker-local cache. Installed on workers only.
fn worker_keccak256<DB: Database>(
    context: TempoInstructionContext<'_, DB>,
) -> Result<(), InstructionResult> {
    popn_top!([offset], top, context.interpreter);
    let len = as_usize_or_fail!(context.interpreter, top);
    gas!(
        context.interpreter,
        context.host.gas_params().keccak256_cost(len)
    );
    let hash = if len == 0 {
        alloy_primitives::KECCAK256_EMPTY
    } else {
        let from = as_usize_or_fail!(context.interpreter, offset);
        resize_memory(
            &mut context.interpreter.gas,
            &mut context.interpreter.memory,
            context.host.gas_params(),
            from,
            len,
        )?;
        worker_hash(context.interpreter.memory.slice_len(from, len).as_ref())
    };
    *top = hash.into();
    Ok(())
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
