//! Fixed cases for each invariant, and a property test over arbitrary cases.

use arbitrary::{Arbitrary, Unstructured};
use proptest::prelude::*;
use zone_fuzz_harness::{
    input::{Amount, BlockInput, Call, Fork, L1Input, MasterInput, Recipient, Signer, ZoneCase},
    run,
};

fn case(fork: Fork, transfers_enabled: bool, paused: bool, calls: Vec<Call>) -> ZoneCase {
    ZoneCase {
        fork,
        l1: L1Input {
            transfers_enabled,
            path_usd_paused: paused,
            masters: vec![MasterInput {
                id: [0xaa, 1, 2, 3],
                owner: Signer(2),
            }],
        },
        blocks: vec![BlockInput { calls }],
    }
}

fn transfer(from: u8, to: Recipient, amount: u64) -> Call {
    Call::Transfer {
        from: Signer(from),
        to,
        amount: Amount(amount),
        memo: None,
    }
}

#[track_caller]
fn assert_passes(case: &ZoneCase) -> zone_fuzz_harness::Outcome {
    let outcome = run(case);
    assert!(outcome.result.is_ok(), "batch failed: {:?}", outcome.result);
    assert!(!outcome.failed(), "violations: {:#?}", outcome.violations);
    outcome
}

fn statuses(outcome: &zone_fuzz_harness::Outcome) -> Vec<bool> {
    use alloy_consensus::TxReceipt as _;
    let users = outcome.sent[0].len();
    outcome.blocks[0]
        .receipts
        .iter()
        .skip(1)
        .take(users)
        .map(|r| r.status())
        .collect()
}

#[test]
fn empty_batch_proves() {
    for fork in [Fork::T13, Fork::T14, Fork::T15] {
        assert_passes(&case(fork, true, false, vec![]));
    }
}

#[test]
fn t15_transfer_between_signers_succeeds() {
    let outcome = assert_passes(&case(
        Fork::T15,
        true,
        false,
        vec![transfer(0, Recipient::Signer(Signer(1)), 1_000)],
    ));
    assert_eq!(statuses(&outcome), [true]);
}

#[test]
fn paused_fee_token_transactions_are_refused() {
    let outcome = assert_passes(&case(
        Fork::T15,
        true,
        true,
        vec![transfer(0, Recipient::Signer(Signer(1)), 1_000)],
    ));
    // pathUSD also pays the fee, so the zone refuses the transaction rather than reverting it.
    assert!(outcome.sent[0].is_empty());
}

#[test]
fn transfers_revert_while_gated() {
    for (fork, enabled, paused) in [(Fork::T14, true, false), (Fork::T15, false, false)] {
        let outcome = assert_passes(&case(
            fork,
            enabled,
            paused,
            vec![transfer(0, Recipient::Signer(Signer(1)), 1_000)],
        ));
        assert_eq!(
            statuses(&outcome),
            [false],
            "{fork:?} enabled={enabled} paused={paused}"
        );
    }
}

#[test]
fn virtual_address_transfer_credits_master() {
    let outcome = assert_passes(&case(
        Fork::T15,
        true,
        false,
        vec![
            transfer(
                0,
                Recipient::Virtual {
                    master: 0,
                    tag: [7; 6],
                },
                5_000,
            ),
            transfer(
                1,
                Recipient::AnyVirtual {
                    id: [0xbb, 0, 0, 0],
                    tag: [1; 6],
                },
                5_000,
            ),
        ],
    ));
    assert_eq!(statuses(&outcome), [true, false]);
}

#[test]
fn multi_block_batch_proves() {
    let mut case = case(
        Fork::T15,
        true,
        false,
        vec![transfer(0, Recipient::Signer(Signer(1)), 1)],
    );
    case.blocks.push(BlockInput {
        calls: vec![transfer(1, Recipient::Signer(Signer(3)), 2)],
    });
    case.blocks.push(BlockInput { calls: vec![] });
    let outcome = assert_passes(&case);
    assert_eq!(outcome.blocks.len(), 3);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    #[test]
    fn arbitrary_cases_hold(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let Ok(case) = ZoneCase::arbitrary(&mut Unstructured::new(&bytes)) else {
            return Ok(());
        };
        let outcome = run(&case);
        prop_assert!(!outcome.failed(), "{case:#?}\n{:#?}", outcome.violations);
    }
}
