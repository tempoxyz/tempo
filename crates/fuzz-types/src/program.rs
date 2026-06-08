use serde::{Deserialize, Serialize};
use std::fmt;

pub type VarId = u32;

#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Program {
    pub instructions: Vec<Instruction>,
}

impl Program {
    pub fn validate(&self) -> Result<(), ValidateError> {
        let mut outputs = Vec::with_capacity(self.instructions.len());
        let mut previous_was_boundary = false;

        for (index, instruction) in self.instructions.iter().enumerate() {
            if instruction
                .inputs
                .iter()
                .any(|input| *input as usize >= index)
            {
                return Err(ValidateError::ForwardReference { index });
            }

            validate_inputs(index, instruction, &outputs)?;

            let is_boundary = matches!(instruction.op, Op::BlockBoundary);
            if is_boundary && (index == 0 || previous_was_boundary) {
                return Err(ValidateError::MalformedBlockStructure { index });
            }
            previous_was_boundary = is_boundary;

            outputs.push(instruction.op.output_type());
        }

        if previous_was_boundary {
            return Err(ValidateError::MalformedBlockStructure {
                index: self.instructions.len().saturating_sub(1),
            });
        }

        Ok(())
    }
}

fn validate_inputs(
    index: usize,
    instruction: &Instruction,
    outputs: &[Type],
) -> Result<(), ValidateError> {
    match instruction.op {
        Op::BuildCalldata => {
            if instruction.inputs.is_empty() {
                return Err(ValidateError::Arity {
                    index,
                    expected: 1,
                    actual: 0,
                });
            }
            validate_input_type(index, instruction.inputs[0], Type::Selector, outputs)?;
            for input in &instruction.inputs[1..] {
                validate_input_type(index, *input, Type::U256, outputs)?;
            }
            Ok(())
        }
        _ => {
            let expected = instruction.op.input_types();
            if instruction.inputs.len() != expected.len() {
                return Err(ValidateError::Arity {
                    index,
                    expected: expected.len(),
                    actual: instruction.inputs.len(),
                });
            }
            for (input, ty) in instruction.inputs.iter().zip(expected) {
                validate_input_type(index, *input, *ty, outputs)?;
            }
            Ok(())
        }
    }
}

fn validate_input_type(
    index: usize,
    input: VarId,
    expected: Type,
    outputs: &[Type],
) -> Result<(), ValidateError> {
    let actual = outputs[input as usize];
    if actual != expected {
        return Err(ValidateError::TypeMismatch {
            index,
            input,
            expected,
            actual,
        });
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Instruction {
    pub op: Op,
    pub inputs: Vec<VarId>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum Op {
    LoadAddress([u8; 20]),
    LoadU256([u8; 32]),
    LoadU64(u64),
    LoadBytes(Vec<u8>),
    LoadSelector([u8; 4]),
    LoadRlpTx(Vec<u8>),
    ExtractReturnWord { offset: u16 },
    ExtractLogTopic { log: u8, topic: u8 },
    ExtractLogAddress { log: u8 },
    ExtractLogWord { log: u8, offset: u16 },
    ExtractCreatedAddress,
    BuildCalldata,
    CallTx,
    CreateTx,
    BlockBoundary,
}

impl Op {
    pub fn input_types(&self) -> &'static [Type] {
        match self {
            Self::LoadAddress(_)
            | Self::LoadU256(_)
            | Self::LoadU64(_)
            | Self::LoadBytes(_)
            | Self::LoadSelector(_)
            | Self::LoadRlpTx(_) => &[],
            Self::ExtractReturnWord { .. }
            | Self::ExtractLogTopic { .. }
            | Self::ExtractLogAddress { .. }
            | Self::ExtractLogWord { .. }
            | Self::ExtractCreatedAddress => &[Type::Receipt],
            Self::BuildCalldata => &[],
            Self::CallTx => &[
                Type::Address,
                Type::Address,
                Type::U256,
                Type::Bytes,
                Type::U64,
            ],
            Self::CreateTx => &[Type::Address, Type::U256, Type::Bytes, Type::U64],
            Self::BlockBoundary => &[Type::U64, Type::U64],
        }
    }

    pub fn output_type(&self) -> Type {
        match self {
            Self::LoadAddress(_) | Self::ExtractLogAddress { .. } | Self::ExtractCreatedAddress => {
                Type::Address
            }
            Self::LoadU256(_)
            | Self::ExtractReturnWord { .. }
            | Self::ExtractLogTopic { .. }
            | Self::ExtractLogWord { .. } => Type::U256,
            Self::LoadU64(_) => Type::U64,
            Self::LoadBytes(_) | Self::BuildCalldata => Type::Bytes,
            Self::LoadSelector(_) => Type::Selector,
            Self::LoadRlpTx(_) | Self::CallTx | Self::CreateTx => Type::Receipt,
            Self::BlockBoundary => Type::BlockMarker,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum Type {
    Address,
    U256,
    U64,
    Bytes,
    Selector,
    Receipt,
    BlockMarker,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidateError {
    ForwardReference {
        index: usize,
    },
    Arity {
        index: usize,
        expected: usize,
        actual: usize,
    },
    TypeMismatch {
        index: usize,
        input: VarId,
        expected: Type,
        actual: Type,
    },
    MalformedBlockStructure {
        index: usize,
    },
}

impl fmt::Display for ValidateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForwardReference { index } => {
                write!(f, "instruction {index} references itself or a future value")
            }
            Self::Arity {
                index,
                expected,
                actual,
            } => write!(
                f,
                "instruction {index} has {actual} inputs, expected {expected}"
            ),
            Self::TypeMismatch {
                index,
                input,
                expected,
                actual,
            } => write!(
                f,
                "instruction {index} input {input} has type {actual:?}, expected {expected:?}"
            ),
            Self::MalformedBlockStructure { index } => {
                write!(f, "instruction {index} has malformed block structure")
            }
        }
    }
}

impl std::error::Error for ValidateError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_valid_programs_round_trip_and_validate() {
        for seed in 0..128 {
            let program = generated_program(seed);
            let encoded = bincode::serialize(&program).expect("program encodes");
            let decoded: Program = bincode::deserialize(&encoded).expect("program decodes");
            decoded.validate().expect("generated program validates");
            assert_eq!(decoded, program);
        }
    }

    fn generated_program(seed: u8) -> Program {
        let mut word = [0u8; 32];
        word[31] = seed;
        let mut address = [0u8; 20];
        address[19] = seed;

        let instructions = vec![
            Instruction {
                op: Op::LoadAddress(address),
                inputs: Vec::new(),
            },
            Instruction {
                op: Op::LoadAddress([0x11; 20]),
                inputs: Vec::new(),
            },
            Instruction {
                op: Op::LoadU256(word),
                inputs: Vec::new(),
            },
            Instruction {
                op: Op::LoadSelector([0x70, 0xa0, 0x82, 0x31]),
                inputs: Vec::new(),
            },
            Instruction {
                op: Op::BuildCalldata,
                inputs: vec![3, 2],
            },
            Instruction {
                op: Op::LoadU64(30_000),
                inputs: Vec::new(),
            },
            Instruction {
                op: Op::CallTx,
                inputs: vec![0, 1, 2, 4, 5],
            },
            Instruction {
                op: Op::ExtractReturnWord { offset: 0 },
                inputs: vec![6],
            },
        ];

        Program { instructions }
    }
}
