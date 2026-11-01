//! Executes a block of pathUSD transfers on the dev genesis through the harness's C ABI, the path a
//! runner takes: decoding the input, executing it and encoding the outcome.

use alloy_consensus::{Signed, TxLegacy};
use alloy_eips::Encodable2718 as _;
use alloy_primitives::{Address, Bytes, Signature, TxKind, U256, address};
use alloy_sol_types::SolCall as _;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{ITIP20, PATH_USD_ADDRESS};
use tempo_fuzz_harness::tempo_fuzz_execute_with_result_v1;
use tempo_fuzz_types::{
    BlockContextInput, BlockHeaderInput, ChainSpecInput, ErrorClass, FUZZ_ACCEPT, PreState,
    StateInput, TempoBlock, TempoBlockchainInput, TempoHarnessInput, TempoHarnessOutcome,
    TxOutcome,
};
use tempo_primitives::TempoTxEnvelope;

/// Dev account 0, funded with pathUSD in the dev genesis.
const SENDER: Address = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

/// A bincode-encoded input of one T4 block holding `count` pathUSD transfers from [`SENDER`], with
/// placeholder signatures: the input gives the senders.
fn transfers(count: u64) -> Vec<u8> {
    let chain_spec = ChainSpecInput::default();
    let transfer = |nonce| -> Bytes {
        let input = ITIP20::transferCall {
            to: Address::with_last_byte(0xaa),
            amount: U256::from(1),
        };
        let tx = TxLegacy {
            chain_id: Some(chain_spec.chain_id),
            nonce,
            gas_limit: 1_000_000,
            to: TxKind::Call(PATH_USD_ADDRESS),
            input: input.abi_encode().into(),
            ..Default::default()
        };
        let tx = Signed::new_unhashed(tx, Signature::test_signature());
        TempoTxEnvelope::Legacy(tx).encoded_2718().into()
    };
    let txs: Vec<_> = (0..count).map(transfer).collect();
    let block = TempoBlock {
        header: BlockHeaderInput::Context(BlockContextInput {
            hardfork: TempoHardfork::T4,
            ..Default::default()
        }),
        senders: vec![SENDER; txs.len()],
        txs,
    };
    let input = TempoHarnessInput::Blockchain(TempoBlockchainInput {
        chain_spec,
        pre_state: PreState::Genesis(StateInput::default()),
        blocks: vec![block].try_into().unwrap(),
    });
    bincode::serialize(&input).unwrap()
}

/// Executes `input` into `out`. Returns the status and the outcome's length.
fn execute(input: &[u8], out: &mut [u8]) -> (i32, usize) {
    let mut written = 0;
    // SAFETY: `input` and `out` are valid for their lengths, and `written` is writable.
    let status = unsafe {
        tempo_fuzz_execute_with_result_v1(
            out.as_mut_ptr(),
            out.len(),
            &mut written,
            input.as_ptr(),
            input.len(),
        )
    };
    (status, written)
}

fn execute_transfers(c: &mut Criterion) {
    let mut group = c.benchmark_group("execute_transfers");
    // 500 transfers use ~26.7M gas, within the default 30M block gas limit.
    for count in [1, 100, 500] {
        let input = transfers(count);
        let (_, len) = execute(&input, &mut []);
        let mut out = vec![0; len];
        assert_eq!(execute(&input, &mut out), (FUZZ_ACCEPT, len));
        // Measure transfers that apply, not an input rejected early.
        let Ok(TempoHarnessOutcome::Blockchain(outcome)) = bincode::deserialize(&out) else {
            panic!("a blockchain input has a blockchain outcome");
        };
        assert_eq!(outcome.error, ErrorClass::None);
        assert_eq!(outcome.receipts.len() as u64, count);
        assert!(
            outcome
                .receipts
                .iter()
                .all(|r| r.outcome == TxOutcome::Success)
        );

        group.throughput(Throughput::Elements(count));
        group.bench_function(count.to_string(), |b| b.iter(|| execute(&input, &mut out)));
    }
    group.finish();
}

criterion_group!(benches, execute_transfers);
criterion_main!(benches);
