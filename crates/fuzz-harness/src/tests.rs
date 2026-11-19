use alloy_consensus::{SignableTransaction as _, TxLegacy};
use alloy_eips::Encodable2718 as _;
use alloy_primitives::{Address, Signature, TxKind, U256, address};
use alloy_sol_types::SolCall as _;
use bincode::Options as _;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{ITIP20, PATH_USD_ADDRESS};
use tempo_fuzz_engine::{Tempo, ffi::bincode_options};
use tempo_fuzz_types::{
    BlockContextInput, BlockHeaderInput, ChainSpecInput, ErrorClass, FUZZ_ACCEPT, FUZZ_REJECT,
    PreState, StateInput, TYPED_HARNESS_SCHEMA_VERSION, TempoBlock, TempoBlockchainInput,
    TempoHarnessCapabilities, TempoHarnessInput, TempoHarnessOutcome,
};
use tempo_primitives::TempoTxEnvelope;

/// Dev account 0, funded with pathUSD in the dev genesis.
const SENDER: Address = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

/// A T4 block of one pathUSD transfer from [`SENDER`], signed with a placeholder.
fn transfer_block(chain_id: u64) -> TempoBlock {
    let tx = TxLegacy {
        chain_id: Some(chain_id),
        gas_limit: 1_000_000,
        to: TxKind::Call(PATH_USD_ADDRESS),
        input: ITIP20::transferCall {
            to: Address::with_last_byte(0xaa),
            amount: U256::from(7),
        }
        .abi_encode()
        .into(),
        ..Default::default()
    };
    let tx = TempoTxEnvelope::Legacy(tx.into_signed(Signature::test_signature()));
    TempoBlock {
        header: BlockHeaderInput::Context(BlockContextInput {
            hardfork: TempoHardfork::T4,
            ..Default::default()
        }),
        txs: vec![tx.encoded_2718().into()],
        senders: vec![SENDER],
    }
}

/// Why the last input this thread executed stopped short, through the C ABI.
fn last_rejection() -> String {
    let mut out = vec![0; 1024];
    let mut written = 0;
    let status =
        unsafe { crate::tempo_fuzz_last_rejection_v1(out.as_mut_ptr(), out.len(), &mut written) };
    assert_eq!(status, FUZZ_ACCEPT);
    String::from_utf8(out[..written].to_vec()).unwrap()
}

#[test]
fn the_c_abi_round_trips_and_rejects_what_does_not_decode() {
    let chain_spec = ChainSpecInput::default();
    let input = TempoHarnessInput::Blockchain(TempoBlockchainInput {
        pre_state: PreState::Genesis(StateInput::default()),
        blocks: vec![transfer_block(chain_spec.chain_id)]
            .try_into()
            .unwrap(),
        chain_spec,
    });
    let bytes = bincode_options().serialize(&input).unwrap();
    let call = |input: &[u8], out: &mut Vec<u8>| {
        let mut written = 0;
        let status = unsafe {
            crate::tempo_fuzz_execute_with_result_v1(
                out.as_mut_ptr(),
                out.len(),
                &mut written,
                input.as_ptr(),
                input.len(),
            )
        };
        (status, written)
    };

    let (status, needed) = call(&bytes, &mut Vec::new());
    assert_eq!(status, FUZZ_REJECT);
    let mut out = vec![0; needed];
    assert_eq!(call(&bytes, &mut out), (FUZZ_ACCEPT, needed));
    let outcome: TempoHarnessOutcome = bincode_options().deserialize(&out).unwrap();
    assert_eq!(
        (outcome.clone(), None),
        tempo_fuzz_engine::run(&Tempo, input)
    );
    let TempoHarnessOutcome::Blockchain(outcome) = outcome else {
        panic!("a blockchain input has a blockchain outcome");
    };
    assert_eq!(
        (outcome.error, outcome.receipts.len()),
        (ErrorClass::None, 1)
    );
    assert_eq!(last_rejection(), "");

    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(call(&trailing, &mut out).0, FUZZ_REJECT);
    assert_eq!(
        last_rejection(),
        "InvalidInput/HarnessInput: harness input does not decode"
    );

    let mut out = vec![0; 1024];
    let mut written = 0;
    let status =
        unsafe { crate::tempo_fuzz_capabilities_v1(out.as_mut_ptr(), out.len(), &mut written) };
    assert_eq!(status, FUZZ_ACCEPT);
    let capabilities: TempoHarnessCapabilities =
        bincode_options().deserialize(&out[..written]).unwrap();
    assert_eq!(capabilities.schema_version, TYPED_HARNESS_SCHEMA_VERSION);
    assert_eq!(capabilities.implementation, "tempo");
    assert_eq!(
        capabilities.supported_hardforks.as_slice(),
        TempoHardfork::VARIANTS
    );
}
