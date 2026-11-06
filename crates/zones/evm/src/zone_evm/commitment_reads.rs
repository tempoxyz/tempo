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
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use alloy_sol_types::{SolCall, SolError};
    use evm2::{
        TxResult,
        bytecode::Bytecode,
        evm::{AccountInfo, InMemoryDB},
    };
    use reth_evm::BlockExecutorFactory;
    use tempo_chainspec::{constants::gas::L1_COMMITMENT_READ_GAS, hardfork::TempoHardfork};
    use tempo_contracts::precompiles::{
        CONFIGURABLE_ACCOUNT_ADDRESS, IConfigurableAccount, IConfigurableAccountShim,
        ISignatureVerifier, SIGNATURE_VERIFIER_ADDRESS,
    };
    use tempo_primitives::transaction::{
        ConfigurableAccountConfig, ConfigurableAccountOwner, ConfigurableAccountSignature,
        PrimitiveSignature, TempoSignature, configurable_account_digest,
    };
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

    /// A configurable account whose single owner is \`owner\`, at \`version\`.
    fn owned_config(owner: &PrivateKeySigner, version: u64) -> ConfigurableAccountConfig {
        ConfigurableAccountConfig {
            salt: B256::ZERO,
            version,
            threshold: 1,
            owners: vec![ConfigurableAccountOwner {
                owner: owner.address(),
                weight: 1,
            }],
        }
    }

    /// The \`0x05\` signature of \`account\` under \`config\` over \`hash\`, signed by \`owner\`.
    fn sign(
        owner: &PrivateKeySigner,
        account: Address,
        config: ConfigurableAccountConfig,
        hash: B256,
    ) -> Bytes {
        let digest = configurable_account_digest(hash, account, config.version);
        let approval = PrimitiveSignature::Secp256k1(owner.sign_hash_sync(&digest).unwrap());
        TempoSignature::ConfigurableAccount(
            ConfigurableAccountSignature::try_new(account, config, vec![approval]).unwrap(),
        )
        .to_bytes()
    }

    /// Calls \`to\` with \`input\` at T14, reading Tempo through \`l1\`.
    fn call(to: Address, input: Vec<u8>, l1: &MockL1Reader) -> TxResult<TempoEvmTypes> {
        let tx = TxLegacy {
            gas_limit: 1_000_000,
            to: TxKind::Call(to),
            input: input.into(),
            ..Default::default()
        };
        execute(TempoHardfork::T14, tx, Bytes::new(), l1)
    }

    fn verify(account: Address, hash: B256, signature: Bytes, l1: &MockL1Reader) -> bool {
        let result = call(
            SIGNATURE_VERIFIER_ADDRESS,
            ISignatureVerifier::verifyConfigurableAccountCall {
                account,
                hash,
                signature,
            }
            .abi_encode(),
            l1,
        );
        assert!(result.status, "{result:?}");
        ISignatureVerifier::verifyConfigurableAccountCall::abi_decode_returns(&result.output)
            .unwrap()
    }

    #[test]
    fn signature_verifier_checks_configurable_accounts_against_tempo() {
        let hash = B256::repeat_byte(0x42);
        let owner = PrivateKeySigner::random();
        let config = owned_config(&owner, 0);
        let account = config.derive_account().unwrap();
        let signature = sign(&owner, account, config, hash);

        // Unregistered on Tempo: the version-zero owners verify by derivation.
        let l1 = MockL1Reader::default();
        assert!(verify(account, hash, signature.clone(), &l1));
        assert_eq!(
            l1.commitment_requests()
                .into_iter()
                .filter(|(read, _)| *read == account)
                .count(),
            1
        );

        // Rotated on Tempo: only the owners at the anchor verify.
        let rotated_owner = PrivateKeySigner::random();
        let rotated = owned_config(&rotated_owner, 1);
        let l1 = MockL1Reader::default();
        l1.insert_commitment(account, 0, rotated.commitment().unwrap());
        assert!(!verify(account, hash, signature, &l1));
        assert!(verify(
            account,
            hash,
            sign(&rotated_owner, account, rotated, hash),
            &l1
        ));
    }

    #[test]
    fn registered_account_answers_erc1271_from_tempo() {
        let hash = B256::repeat_byte(0x42);
        let owner = PrivateKeySigner::random();
        let config = owned_config(&owner, 0);
        let account = config.derive_account().unwrap();
        let l1 = MockL1Reader::default();
        l1.insert_commitment(account, 0, config.commitment().unwrap());

        let is_valid = |signature: Bytes| {
            let result = call(
                account,
                IConfigurableAccountShim::isValidSignatureCall { hash, signature }.abi_encode(),
                &l1,
            );
            assert!(result.status, "{result:?}");
            IConfigurableAccountShim::isValidSignatureCall::abi_decode_returns(&result.output)
                .unwrap()
        };
        assert_eq!(
            is_valid(sign(&owner, account, config, hash)),
            IConfigurableAccountShim::isValidSignatureCall::SELECTOR
        );
        let stranger = PrivateKeySigner::random();
        assert_eq!(
            is_valid(sign(&stranger, account, owned_config(&stranger, 0), hash)),
            [0xff; 4]
        );
    }
}
