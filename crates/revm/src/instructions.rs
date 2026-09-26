use crate::{evm::TempoContext, gas_credits};
use alloy_evm::Database;
use revm::{
    bytecode::opcode::{DUPN, EXCHANGE, SSTORE, SWAPN},
    handler::instructions::EthInstructions,
    interpreter::{
        Instruction, InstructionContext, InstructionResult,
        instructions::{gas_table_spec, instruction_table},
        interpreter::EthInterpreter,
        interpreter_types::{Immediates, Jumps},
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
                table[SSTORE as usize] = Instruction::new(gas_credits::sstore);
                table
            },
            gas_table_spec(evm_spec),
            evm_spec,
        )
    } else {
        EthInstructions::new_mainnet_with_spec(spec.into())
    };

    if spec.is_t13() {
        // TIP-1122: enable EIP-8024 independently of Amsterdam.
        instructions.insert_instruction(DUPN, Instruction::new(dupn), 3);
        instructions.insert_instruction(SWAPN, Instruction::new(swapn), 3);
        instructions.insert_instruction(EXCHANGE, Instruction::new(exchange), 3);
    }

    if !spec.is_t1c() {
        instructions.insert_instruction(
            MILLIS_TIMESTAMP,
            Instruction::new(millis_timestamp),
            MILLIS_TIMESTAMP_GAS_COST,
        );
    }
    instructions
}

// EIP-8024's encoding preserves legacy JUMPDEST analysis. The upstream
// implementations are Amsterdam-gated, while Tempo adopts these opcodes at T13.
fn decode_single(x: u8) -> Result<usize, InstructionResult> {
    if x > 90 && x < 128 {
        return Err(InstructionResult::InvalidImmediateEncoding);
    }
    Ok(x.wrapping_add(145) as usize)
}

fn dupn<DB: Database>(context: TempoInstructionContext<'_, DB>) -> Result<(), InstructionResult> {
    let n = decode_single(context.interpreter.bytecode.read_u8())?;
    if context.interpreter.stack.len() < n {
        return Err(InstructionResult::StackUnderflow);
    }
    if !context.interpreter.stack.dup(n) {
        return Err(InstructionResult::StackOverflow);
    }
    context.interpreter.bytecode.relative_jump(1);
    Ok(())
}

fn swapn<DB: Database>(context: TempoInstructionContext<'_, DB>) -> Result<(), InstructionResult> {
    let n = decode_single(context.interpreter.bytecode.read_u8())?;
    if !context.interpreter.stack.exchange(0, n) {
        return Err(InstructionResult::StackUnderflow);
    }
    context.interpreter.bytecode.relative_jump(1);
    Ok(())
}

fn exchange<DB: Database>(
    context: TempoInstructionContext<'_, DB>,
) -> Result<(), InstructionResult> {
    let x = context.interpreter.bytecode.read_u8();
    if x > 81 && x < 128 {
        return Err(InstructionResult::InvalidImmediateEncoding);
    }
    let k = (x ^ 143) as usize;
    let (q, r) = (k / 16, k % 16);
    let (n, m) = if q < r {
        (q + 1, r + 1)
    } else {
        (r + 1, 29 - q)
    };
    if !context.interpreter.stack.exchange(n, m - n) {
        return Err(InstructionResult::StackUnderflow);
    }
    context.interpreter.bytecode.relative_jump(1);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Bytes, U256, hex};
    use revm::{
        Context, MainContext,
        bytecode::Bytecode,
        context::CfgEnv,
        database::EmptyDB,
        interpreter::{
            Interpreter,
            interpreter::{ExtBytecode, InputsImpl, SharedMemory},
        },
    };

    fn run(
        spec: TempoHardfork,
        code: &[u8],
        depth: usize,
        gas: u64,
    ) -> (Interpreter, InstructionResult) {
        let mut host = Context::mainnet()
            .with_db(EmptyDB::default())
            .with_block(crate::TempoBlockEnv::default())
            .with_tx(crate::TempoTxEnv::default())
            .with_cfg(CfgEnv::new_with_spec(spec));
        let table = tempo_instructions::<EmptyDB>(spec);
        let mut interpreter = Interpreter::new(
            SharedMemory::new(),
            ExtBytecode::new(Bytecode::new_raw(Bytes::copy_from_slice(code))),
            InputsImpl::default(),
            false,
            spec.into(),
            gas,
        );
        for value in 0..depth {
            assert!(interpreter.stack.push(U256::from(value)));
        }
        let result = interpreter.run_plain(table.instruction_table(), table.gas_table(), &mut host);
        (interpreter, result.instruction_result().unwrap())
    }

    #[test]
    fn tip1122_stack_vectors_and_gas() {
        // Published EIP-8024 encodings, with stack values identifying original positions.
        for (code, depth, expected) in [
            (hex!("e680").as_slice(), 17, (17, 0)),   // DUPN 17
            (hex!("e7db").as_slice(), 109, (108, 0)), // SWAPN 108
            (hex!("e89d").as_slice(), 4, (1, 0)),     // EXCHANGE 2 3
            (hex!("e82f").as_slice(), 20, (18, 0)),   // EXCHANGE 1 19
            (hex!("e850").as_slice(), 17, (2, 0)),    // EXCHANGE 14 16
            (hex!("e851").as_slice(), 16, (1, 0)),    // EXCHANGE 14 15
        ] {
            let (interpreter, result) = run(TempoHardfork::T13, code, depth, 3);
            assert_eq!(result, InstructionResult::Stop);
            assert_eq!(interpreter.stack.data()[expected.0], U256::from(expected.1));
            assert_eq!(interpreter.gas.remaining(), 0);
            assert!(!run(TempoHardfork::T12, code, depth, 3).1.is_ok());
            assert_eq!(
                run(TempoHardfork::T13, code, depth, 2).1,
                InstructionResult::OutOfGas
            );
        }
    }

    #[test]
    fn tip1122_all_immediate_encodings() {
        for opcode in [DUPN, SWAPN, EXCHANGE] {
            for immediate in 0..=u8::MAX {
                let (_, result) = run(TempoHardfork::T13, &[opcode, immediate], 256, 3);
                let invalid = if opcode == EXCHANGE { 82..128 } else { 91..128 };
                assert_eq!(
                    result,
                    if invalid.contains(&immediate) {
                        InstructionResult::InvalidImmediateEncoding
                    } else {
                        InstructionResult::Stop
                    },
                    "opcode {opcode:x}, immediate {immediate:x}"
                );
            }
        }
    }

    #[test]
    fn tip1122_stack_bounds_and_truncated_immediate() {
        for (code, depth, expected) in [
            (vec![DUPN, 0x80], 16, InstructionResult::StackUnderflow),
            (vec![DUPN, 0x80], 1024, InstructionResult::StackOverflow),
            (vec![SWAPN, 0x80], 17, InstructionResult::StackUnderflow),
            (vec![EXCHANGE, 0x8e], 2, InstructionResult::StackUnderflow),
            (vec![DUPN], 145, InstructionResult::Stop),
            (vec![SWAPN], 146, InstructionResult::Stop),
            (vec![EXCHANGE], 17, InstructionResult::Stop),
        ] {
            assert_eq!(run(TempoHardfork::T13, &code, depth, 3).1, expected);
        }
    }

    #[test]
    fn tip1122_preserves_jump_destinations() {
        for spec in [TempoHardfork::T12, TempoHardfork::T13] {
            // The JUMPDEST following an invalid DUPN immediate remains jumpable.
            assert_eq!(
                run(spec, &hex!("600456e65b00"), 0, 100).1,
                InstructionResult::Stop
            );
            // A JUMPDEST inside a PUSH immediate remains masked.
            assert_eq!(
                run(spec, &hex!("600556e6605b00"), 0, 100).1,
                InstructionResult::InvalidJump
            );
        }
    }
}
