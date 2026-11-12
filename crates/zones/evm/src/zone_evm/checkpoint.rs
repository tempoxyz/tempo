//! Checkpoint discovery is charged by logical transaction preparation, not host cache misses.

use super::tests::{config, fee_free_env, sender_db, transaction};
use crate::{L1OverlayDB, ZoneDbError};
use alloy_consensus::{SignableTransaction, TxEip2930, TxLegacy, transaction::Recovered};
use alloy_eips::eip2930::{AccessList, AccessListItem};
use alloy_primitives::{Address, B256, Bytes, Signature, TxKind, U256};
use alloy_sol_types::SolCall;
use evm2::registry::HandlerError;
use reth_evm::BlockExecutorFactory;
use tempo_chainspec::{constants::gas::L1_COMMITMENT_READ_GAS, hardfork::TempoHardfork};
use tempo_contracts::zones::IZoneOutbox;
use tempo_evm::TempoTxEnv;
use tempo_primitives::{
    TempoTxEnvelope,
    transaction::{Call, TempoSignature, TempoTransaction},
};
use zone_precompiles::{tempo_state::TEMPO_BLOCK_NUMBER_SLOT, test_utils::MockL1Reader};
use zone_primitives::constants::{TEMPO_STATE_ADDRESS, ZONE_OUTBOX_ADDRESS};

const SENDER: Address = Address::repeat_byte(1);
const ANCHOR: u64 = 42;

fn tx(aa: bool, to: Address, input: Bytes, gas_limit: u64) -> Recovered<TempoTxEnv> {
    let envelope: TempoTxEnvelope = if aa {
        TempoTransaction {
            chain_id: 1,
            nonce: 1,
            gas_limit,
            calls: vec![Call {
                to: TxKind::Call(to),
                input,
                value: U256::ZERO,
            }],
            ..Default::default()
        }
        .into_signed(TempoSignature::default())
        .into()
    } else {
        TxLegacy {
            nonce: 1,
            gas_limit,
            to: TxKind::Call(to),
            input,
            ..Default::default()
        }
        .into_signed(Signature::test_signature())
        .into()
    };
    transaction(SENDER, envelope)
}

#[test]
fn checkpoint_gas_does_not_depend_on_discarded_or_rejected_attempts() {
    for spec in [TempoHardfork::T13, TempoHardfork::T14, TempoHardfork::T15] {
        for aa in [false, true] {
            let reader = MockL1Reader::default();
            reader.seed_active_sequencer(Address::ZERO, ANCHOR, SENDER);
            let make_evm = || {
                let mut db = sender_db(SENDER);
                db.insert_account_storage(
                    &TEMPO_STATE_ADDRESS,
                    &TEMPO_BLOCK_NUMBER_SLOT,
                    &U256::from(ANCHOR),
                );
                BlockExecutorFactory::evm_with_env(&config(reader.clone()), db, fee_free_env(spec))
            };
            let input: Bytes = IZoneOutbox::pendingWithdrawalsCountCall {}
                .abi_encode()
                .into();
            let query = tx(aa, ZONE_OUTBOX_ADDRESS, input.clone(), 1_000_000);
            let mut replay = make_evm();
            let expected = replay.transact(&query).unwrap().discard();
            assert!(expected.status, "{spec:?} aa={aa}: {expected:?}");
            assert_eq!(
                IZoneOutbox::pendingWithdrawalsCountCall::abi_decode_returns(&expected.output)
                    .unwrap(),
                U256::ZERO,
            );

            // Disable only the new intrinsic debit to isolate its exact cost.
            let mut uncharged = make_evm();
            uncharged.ext_mut().zone_checkpoint_slot = None;
            let uncharged = uncharged.transact(&query).unwrap().discard();
            assert_eq!(
                expected.tx_gas_used() - uncharged.tx_gas_used(),
                if spec.is_t14() { 2_100 } else { 0 },
                "{spec:?} aa={aa}",
            );

            for reject_first in [false, true] {
                let mut builder = make_evm();
                if reject_first {
                    let rejected = tx(aa, ZONE_OUTBOX_ADDRESS, input.clone(), 0);
                    assert!(matches!(
                        builder.transact(&rejected),
                        Err(HandlerError::IntrinsicGasTooLow { got: 0, .. })
                    ));
                } else {
                    let discarded = builder.transact(&query).unwrap().discard();
                    assert_eq!(discarded.tx_gas_used(), expected.tx_gas_used());
                }
                let commitment_reads = reader.commitment_requests();
                let built = builder.transact(&query).unwrap().discard();
                assert_eq!(built.status, expected.status);
                assert_eq!(built.output, expected.output);
                assert_eq!(built.tx_gas_used(), expected.tx_gas_used());
                assert_eq!(reader.commitment_requests(), commitment_reads);
                let l1 = builder
                    .database_as::<L1OverlayDB<evm2::evm::InMemoryDB, MockL1Reader>>()
                    .unwrap()
                    .l1_state();
                assert_eq!(l1.get_anchor(), None);
                assert_eq!(l1.initial_anchor(), None);
                assert_eq!(
                    builder
                        .state_mut()
                        .account_info_untracked(&SENDER)
                        .unwrap()
                        .unwrap()
                        .nonce,
                    1,
                );
            }
            assert!(
                reader
                    .storage_requests()
                    .iter()
                    .all(|(_, _, anchor)| *anchor == ANCHOR)
            );
            assert!(
                reader
                    .commitment_requests()
                    .iter()
                    .all(|(_, anchor)| *anchor == ANCHOR)
            );
        }
    }
}

#[test]
fn checkpoint_discovery_respects_access_list_warmth() {
    for spec in [TempoHardfork::T14, TempoHardfork::T15] {
        for aa in [false, true] {
            let reader = MockL1Reader::default();
            reader.seed_active_sequencer(Address::ZERO, 0, SENDER);
            let gas = |listed| {
                let mut evm = BlockExecutorFactory::evm_with_env(
                    &config(reader.clone()),
                    sender_db(SENDER),
                    fee_free_env(spec),
                );
                let access_list = AccessList(if listed {
                    vec![AccessListItem {
                        address: TEMPO_STATE_ADDRESS,
                        storage_keys: vec![B256::from(TEMPO_BLOCK_NUMBER_SLOT)],
                    }]
                } else {
                    vec![]
                });
                let input = IZoneOutbox::pendingWithdrawalsCountCall {}
                    .abi_encode()
                    .into();
                let envelope: TempoTxEnvelope = if aa {
                    TempoTransaction {
                        chain_id: 1,
                        nonce: 1,
                        gas_limit: 1_000_000,
                        access_list,
                        calls: vec![Call {
                            to: TxKind::Call(ZONE_OUTBOX_ADDRESS),
                            input,
                            value: U256::ZERO,
                        }],
                        ..Default::default()
                    }
                    .into_signed(TempoSignature::default())
                    .into()
                } else {
                    TxEip2930 {
                        chain_id: 1,
                        nonce: 1,
                        gas_limit: 1_000_000,
                        to: TxKind::Call(ZONE_OUTBOX_ADDRESS),
                        input,
                        access_list,
                        ..Default::default()
                    }
                    .into_signed(Signature::test_signature())
                    .into()
                };
                let result = evm
                    .transact(&transaction(SENDER, envelope))
                    .unwrap()
                    .discard();
                assert!(result.status, "{result:?}");
                result.tx_gas_used()
            };
            // Listing costs the account commitment premium plus 2,400 + 1,900.
            // Discovery changes from 2,100 to 100.
            assert_eq!(
                gas(true) - gas(false),
                L1_COMMITMENT_READ_GAS + 2_300,
                "{spec:?} aa={aa}"
            );
        }
    }
}

#[test]
fn checkpoint_discovery_is_included_in_intrinsic_gas_validation() {
    for spec in [TempoHardfork::T14, TempoHardfork::T15] {
        for aa in [false, true] {
            let mut evm = BlockExecutorFactory::evm_with_env(
                &config(MockL1Reader::default()),
                sender_db(SENDER),
                fee_free_env(spec),
            );
            let empty = tx(aa, SENDER, Bytes::new(), 0);
            let required = match evm.transact(&empty) {
                Err(HandlerError::IntrinsicGasTooLow { got: 0, required }) => required,
                result => panic!("expected intrinsic rejection: {result:?}"),
            };
            let short = tx(aa, SENDER, Bytes::new(), required - 1);
            assert!(matches!(
                evm.transact(&short),
                Err(HandlerError::IntrinsicGasTooLow { got, required: cost })
                    if got == required - 1 && cost == required
            ));
            let exact = tx(aa, SENDER, Bytes::new(), required);
            let result = evm.transact(&exact).unwrap().discard();
            assert!(result.status, "{spec:?} aa={aa}: {result:?}");
            assert_eq!(result.tx_gas_used(), required);
        }
    }
}

#[test]
fn invalid_checkpoint_clears_the_attempt_context() {
    let invalid = U256::from(u64::MAX) + U256::ONE;
    let mut db = sender_db(SENDER);
    db.insert_account_storage(&TEMPO_STATE_ADDRESS, &TEMPO_BLOCK_NUMBER_SLOT, &invalid);
    let mut evm = BlockExecutorFactory::evm_with_env(
        &config(MockL1Reader::default()),
        db,
        fee_free_env(TempoHardfork::T14),
    );
    let query = tx(false, SENDER, Bytes::new(), 1_000_000);
    match evm.transact(&query) {
        Err(HandlerError::Fatal(error)) => assert!(matches!(
            error.downcast_ref::<ZoneDbError>(),
            Some(ZoneDbError::AnchorOverflow(value)) if *value == invalid
        )),
        result => panic!("expected checkpoint overflow: {result:?}"),
    }
    let l1 = evm
        .database_as::<L1OverlayDB<evm2::evm::InMemoryDB, MockL1Reader>>()
        .unwrap()
        .l1_state();
    assert_eq!(l1.get_anchor(), None);
    assert_eq!(l1.initial_anchor(), None);
}
