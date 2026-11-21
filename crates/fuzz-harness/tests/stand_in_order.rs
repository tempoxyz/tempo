//! Stand-ins can't switch on once an input has executed. A test binary of its own, so this process
//! starts with nothing executed.

use tempo_chainspec::hardfork::TempoHardfork;
use tempo_fuzz_harness::{tempo_fuzz_enable_stand_in_crypto_v1, tempo_fuzz_execute_with_result_v1};
use tempo_fuzz_types::{
    BlockContextInput, BlockHeaderInput, ChainSpecInput, PreState, StateInput, TempoBlock,
    TempoBlockchainInput, TempoHarnessInput,
};

#[test]
fn stand_ins_stay_off_once_an_input_has_executed() {
    let input = TempoHarnessInput::Blockchain(TempoBlockchainInput {
        chain_spec: ChainSpecInput::default(),
        pre_state: PreState::Genesis(StateInput::default()),
        blocks: vec![TempoBlock {
            header: BlockHeaderInput::Context(BlockContextInput {
                hardfork: TempoHardfork::T4,
                ..Default::default()
            }),
            senders: Vec::new(),
            txs: Vec::new(),
        }]
        .try_into()
        .unwrap(),
    });
    let input = bincode::serialize(&input).unwrap();
    let mut written = 0;
    // SAFETY: `input` is valid for its length, the output is empty and `written` is writable.
    unsafe {
        tempo_fuzz_execute_with_result_v1(
            core::ptr::null_mut(),
            0,
            &mut written,
            input.as_ptr(),
            input.len(),
        );
    }
    assert!(written > 0, "the input executed");
    assert_eq!(tempo_fuzz_enable_stand_in_crypto_v1(), 0);
    assert_eq!(tempo_fuzz_enable_stand_in_crypto_v1(), 0, "and stays off");
}
