use bincode::Options as _;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_fuzz_engine::{Tempo, ffi::bincode_options};
use tempo_fuzz_types::{
    BlockContextInput, BlockHeaderInput, ChainSpecInput, FUZZ_ACCEPT, FUZZ_REJECT, PreState,
    StateInput, TempoBlock, TempoBlockchainInput, TempoHarnessCapabilities, TempoHarnessInput,
    TempoHarnessOutcome,
};

#[test]
fn the_c_abi_round_trips_and_rejects_what_does_not_decode() {
    let input = TempoHarnessInput::Blockchain(TempoBlockchainInput {
        chain_spec: ChainSpecInput::default(),
        pre_state: PreState::Genesis(StateInput::default()),
        blocks: vec![TempoBlock {
            header: BlockHeaderInput::Context(BlockContextInput::default()),
            txs: vec![],
            senders: vec![],
        }]
        .try_into()
        .unwrap(),
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
    assert_eq!(outcome, tempo_fuzz_engine::run(&Tempo, input));

    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(call(&trailing, &mut out).0, FUZZ_REJECT);

    let mut out = vec![0; 1024];
    let mut written = 0;
    let status =
        unsafe { crate::tempo_fuzz_capabilities_v1(out.as_mut_ptr(), out.len(), &mut written) };
    assert_eq!(status, FUZZ_ACCEPT);
    let capabilities: TempoHarnessCapabilities =
        bincode_options().deserialize(&out[..written]).unwrap();
    assert_eq!(capabilities.schema_version, 4);
    assert_eq!(
        capabilities.supported_hardforks.as_slice(),
        TempoHardfork::VARIANTS
    );
}
