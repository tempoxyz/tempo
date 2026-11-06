//! Gas for the Tempo commitment reads of account-loading opcodes (TIP-1154).

use core::marker::PhantomData;

use alloy_primitives::KECCAK256_EMPTY;
use evm2::{
    LoadError, OpcodeConfig,
    interpreter::{
        InstrStop, InterpreterState, Pc, Result, StackMut, instructions, op,
        private::{Instruction, InstructionFlags, split_gas_state},
    },
    utils::WordExt,
};
use tempo_evm::TempoEvmTypes;
use tempo_precompiles::configurable_account::{l1_commitment_read_gas, record_l1_commitment_read};

/// Installs [`ChargeCommitmentRead`] around every opcode that loads an account named on the
/// stack, keeping each opcode's static gas.
pub(crate) const fn charge_commitment_reads(config: &mut OpcodeConfig<TempoEvmTypes>) {
    type Ty = TempoEvmTypes;
    macro_rules! wrap {
        ($($opcode:expr => $instruction:ty, $depth:literal;)+) => {$(
            config.set_instruction::<ChargeCommitmentRead<$instruction, $depth>>(
                $opcode,
                config.static_gas($opcode),
            );
        )+};
    }
    wrap! {
        op::BALANCE => instructions::balance<Ty>, 0;
        op::EXTCODESIZE => instructions::extcodesize<Ty>, 0;
        op::EXTCODECOPY => instructions::extcodecopy<Ty>, 0;
        op::EXTCODEHASH => instructions::extcodehash<Ty>, 0;
        op::CALL => instructions::call<Ty>, 1;
        op::CALLCODE => instructions::callcode<Ty>, 1;
        op::DELEGATECALL => instructions::delegatecall<Ty>, 1;
        op::STATICCALL => instructions::staticcall<Ty>, 1;
    }
}

/// Runs `I` after charging the first Tempo commitment read in the transaction of the account at
/// stack depth `DEPTH`.
struct ChargeCommitmentRead<I, const DEPTH: usize>(PhantomData<I>);

impl<I, const DEPTH: usize> Instruction<TempoEvmTypes> for ChargeCommitmentRead<I, DEPTH>
where
    I: Instruction<TempoEvmTypes>,
{
    const FLAGS: InstructionFlags = I::FLAGS.union(InstructionFlags::DYNAMIC_GAS);

    fn execute(
        pc: &mut Pc,
        stack: StackMut<'_>,
        state: &mut InterpreterState<'_, '_, TempoEvmTypes>,
    ) -> Result {
        let spec = state.host().config_spec_id();
        // A short stack is left for `I` to reject, and a read the transaction already paid for
        // leaves the load to `I`.
        if let Some(address) = stack.peek(DEPTH).map(|word| word.to_address())
            && let Some(read_gas) = l1_commitment_read_gas(state.host(), address, spec)
                .filter(|&read_gas| read_gas != 0)
        {
            // SAFETY: `gas` is only used directly, never through `state`, and both are dropped
            // before `I` runs.
            let (gas, state) = unsafe { split_gas_state(state) };
            // A load that cannot pay an unread commitment fails before reading Tempo, so no read
            // goes unpaid, even when the account turns out to hold contract code.
            if gas.remaining() < read_gas {
                return Err(InstrStop::OutOfGas);
            }
            let skip_cold_load =
                gas.remaining() < state.gas_params().cold_account_additional_cost() + read_gas;
            let code_hash = match state
                .host()
                .state_mut()
                .account_with_skip(&address, skip_cold_load)
                .map(|account| account.get().map_or(KECCAK256_EMPTY, |info| info.code_hash))
            {
                Ok(code_hash) => code_hash,
                Err(LoadError::ColdLoadSkipped) => return Err(InstrStop::OutOfGas),
                Err(LoadError::Database(error)) => return Err(state.fail(error)),
            };
            if record_l1_commitment_read(state.host(), address, code_hash) {
                gas.spend(read_gas)?;
            }
        }
        I::execute(pc, stack, state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone_evm::tests::{config, fee_free_env, transaction};
    use alloy_consensus::{SignableTransaction, TxLegacy};
    use alloy_primitives::{Address, B256, Bytes, Signature, TxKind, U256};
    use alloy_sol_types::{SolCall, SolError};
    use evm2::{
        TxResult,
        bytecode::Bytecode,
        evm::{AccountInfo, InMemoryDB},
    };
    use reth_evm::BlockExecutorFactory;
    use tempo_chainspec::{constants::gas::L1_COMMITMENT_READ_GAS, hardfork::TempoHardfork};
    use tempo_contracts::precompiles::{CONFIGURABLE_ACCOUNT_ADDRESS, IConfigurableAccount};
    use zone_precompiles::{ZONE_FEE_MANAGER_ADDRESS, test_utils::MockL1Reader, zone_fee_manager};

    const SENDER: Address = Address::repeat_byte(0x01);
    const PROBE: Address = Address::repeat_byte(0x02);
    const CONTRACT: Address = Address::repeat_byte(0x03);
    const ELIGIBLE: Address = Address::repeat_byte(0x04);
    const BENEFICIARY: Address = Address::repeat_byte(0x05);

    /// Code that loads each target with `opcode`, as `BALANCE` or `CALL` with all gas.
    fn probe(opcode: u8, targets: &[Address]) -> Bytes {
        let mut code = Vec::new();
        for target in targets {
            if opcode == op::CALL {
                code.extend([op::PUSH0; 5]);
            }
            code.push(op::PUSH20);
            code.extend_from_slice(target.as_slice());
            if opcode == op::CALL {
                code.push(op::GAS);
            }
            code.extend([opcode, op::POP]);
        }
        code.push(op::STOP);
        code.into()
    }

    /// Executes `tx` from [`SENDER`] at `spec`, with [`PROBE`] holding `code` and Tempo read
    /// through `l1`.
    fn execute(
        spec: TempoHardfork,
        tx: TxLegacy,
        code: Bytes,
        l1: &MockL1Reader,
    ) -> TxResult<TempoEvmTypes> {
        let mut db = InMemoryDB::default();
        db.insert_account_info(&ZONE_FEE_MANAGER_ADDRESS, AccountInfo::default());
        db.insert_account_storage(
            &ZONE_FEE_MANAGER_ADDRESS,
            &zone_fee_manager::slots::DEFAULT_FEE_TOKEN,
            &U256::from_be_slice(tempo_precompiles::DEFAULT_FEE_TOKEN.as_slice()),
        );
        db.insert_account_info(&SENDER, AccountInfo::default().with_nonce(1));
        db.insert_account_info(
            &PROBE,
            AccountInfo::default().with_code(Bytecode::new_raw(code)),
        );
        db.insert_account_info(
            &CONTRACT,
            AccountInfo::default().with_code(Bytecode::new_raw(Bytes::from_static(&[op::STOP]))),
        );
        let mut env = fee_free_env(spec);
        env.block.beneficiary = BENEFICIARY;
        let mut evm = BlockExecutorFactory::evm_with_env(&config(l1.clone()), db, env);
        let tx = transaction(
            SENDER,
            TxLegacy { nonce: 1, ..tx }.into_signed(Signature::test_signature()),
        );
        evm.transact(&tx).unwrap().discard()
    }

    /// Runs a call at `spec` to [`PROBE`] holding `code`, returning its result and the accounts
    /// whose commitments were read from Tempo.
    fn run(
        spec: TempoHardfork,
        code: Bytes,
        gas_limit: u64,
    ) -> (TxResult<TempoEvmTypes>, Vec<Address>) {
        let l1 = MockL1Reader::default();
        let tx = TxLegacy {
            gas_limit,
            to: TxKind::Call(PROBE),
            ..Default::default()
        };
        let result = execute(spec, tx, code, &l1);
        let reads = l1
            .commitment_requests()
            .into_iter()
            .map(|(account, _)| account)
            .collect();
        (result, reads)
    }

    fn gas_used(opcode: u8, targets: &[Address]) -> u64 {
        let (result, _) = run(TempoHardfork::T14, probe(opcode, targets), 1_000_000);
        assert!(result.status, "{result:?}");
        result.tx_gas_used()
    }

    #[test]
    fn first_cold_load_of_an_account_pays_its_tempo_read() {
        for opcode in [op::BALANCE, op::CALL] {
            assert_eq!(
                gas_used(opcode, &[ELIGIBLE]) - gas_used(opcode, &[CONTRACT]),
                L1_COMMITMENT_READ_GAS
            );
            // The warm reload reads nothing more.
            assert_eq!(
                gas_used(opcode, &[ELIGIBLE, ELIGIBLE]) - gas_used(opcode, &[CONTRACT, CONTRACT]),
                L1_COMMITMENT_READ_GAS
            );
        }
    }

    #[test]
    fn loads_read_nothing_from_tempo_before_t14() {
        let gas_used = |target| {
            let (result, reads) = run(TempoHardfork::T13, probe(op::BALANCE, &[target]), 1_000_000);
            assert!(result.status, "{result:?}");
            assert!(reads.is_empty(), "{reads:?}");
            result.tx_gas_used()
        };
        assert_eq!(gas_used(ELIGIBLE), gas_used(CONTRACT));
    }

    #[test]
    fn first_load_of_the_warm_beneficiary_pays_its_tempo_read() {
        // The sender's read is intrinsic, so its loads only pay warm access.
        assert_eq!(
            gas_used(op::BALANCE, &[BENEFICIARY, BENEFICIARY])
                - gas_used(op::BALANCE, &[SENDER, SENDER]),
            L1_COMMITMENT_READ_GAS
        );
    }

    #[test]
    fn cold_load_that_cannot_pay_its_tempo_read_reads_nothing() {
        let paid = gas_used(op::BALANCE, &[CONTRACT]) + L1_COMMITMENT_READ_GAS;
        // One gas short of the cold access and read, after the 2 of the trailing POP.
        let (result, reads) = run(
            TempoHardfork::T14,
            probe(op::BALANCE, &[ELIGIBLE]),
            paid - 3,
        );
        assert_eq!(result.stop, InstrStop::OutOfGas);
        assert!(!reads.contains(&ELIGIBLE), "{reads:?}");

        let (result, reads) = run(TempoHardfork::T14, probe(op::BALANCE, &[ELIGIBLE]), paid);
        assert!(result.status, "{result:?}");
        assert_eq!(result.tx_gas_used(), paid);
        assert!(reads.contains(&ELIGIBLE), "{reads:?}");
    }

    #[test]
    fn configurable_account_precompile_reads_tempo_and_rejects_writes() {
        let l1 = MockL1Reader::default();
        let commitment = B256::repeat_byte(7);
        l1.insert_commitment(ELIGIBLE, 0, commitment);
        let call = |input: Vec<u8>| TxLegacy {
            gas_limit: 1_000_000,
            to: TxKind::Call(CONFIGURABLE_ACCOUNT_ADDRESS),
            input: input.into(),
            ..Default::default()
        };

        let read = execute(
            TempoHardfork::T14,
            call(IConfigurableAccount::getConfigCommitmentCall { account: ELIGIBLE }.abi_encode()),
            Bytes::new(),
            &l1,
        );
        assert!(read.status, "{read:?}");
        assert_eq!(read.output[..], commitment[..]);

        for selector in [
            IConfigurableAccount::updateConfigCall::SELECTOR,
            IConfigurableAccount::upgradeAccountCall::SELECTOR,
        ] {
            let rejected = execute(
                TempoHardfork::T14,
                call(selector.to_vec()),
                Bytes::new(),
                &l1,
            );
            assert_eq!(rejected.stop, InstrStop::Revert);
            assert_eq!(
                rejected.output,
                IConfigurableAccount::UnsupportedOnZone {}.abi_encode()
            );
        }
    }
}
