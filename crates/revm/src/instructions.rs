use crate::{evm::TempoContext, gas_credits};
use alloy_evm::Database;
use revm::{
    bytecode::opcode::SSTORE,
    handler::instructions::EthInstructions,
    interpreter::{
        Instruction,
        instructions::{gas_table_spec, instruction_table},
        interpreter::EthInterpreter,
    },
};
use tempo_chainspec::hardfork::TempoHardfork;

/// Returns configured instructions table for Tempo.
pub(crate) fn tempo_instructions<DB: Database>(
    spec: TempoHardfork,
) -> EthInstructions<EthInterpreter, TempoContext<DB>> {
    let evm_spec = spec.into();

    // +T7: Enable TIP-1060 sstore hook

    {
        EthInstructions::new(
            {
                let mut table = instruction_table::<EthInterpreter, TempoContext<DB>>();
                table[SSTORE as usize] = Instruction::new(gas_credits::sstore);
                table
            },
            gas_table_spec(evm_spec),
            evm_spec,
        )
    }
}
