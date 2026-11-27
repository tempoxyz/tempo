use std::collections::BTreeMap;

use alloy_consensus::{SignableTransaction as _, TxLegacy};
use alloy_eips::Encodable2718 as _;
use alloy_primitives::{Address, B256, Bytes, Signature, TxKind, U256, address, bytes};
use alloy_sol_types::SolCall as _;
use bincode::Options as _;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::{
    precompiles::{ITIP20, PATH_USD_ADDRESS},
    zones::{IZoneOutbox, ZONE_OUTBOX_ADDRESS},
};
use tempo_fuzz_engine::{Engine, ffi::bincode_options};
use tempo_fuzz_types::{
    AccountInput, BlockContextInput, BlockHeaderInput, ChainSpecInput, ErrorClass, FUZZ_ACCEPT,
    PreState, StateInput, TYPED_HARNESS_SCHEMA_VERSION, TempoBlock, TempoBlockchainInput,
    TempoExecutionOutcome, TempoHarnessCapabilities, TempoHarnessInput, TempoHarnessOutcome,
    TxIndex, TxOutcome, TxReceiptOutput,
};
use tempo_precompiles::{
    storage::{Handler as _, StorageCtx, StorageKey as _, hashmap::HashMapStorageProvider},
    tip20::slots::{BALANCES, TOTAL_SUPPLY},
    zone_factory::{ZonePortalStorage, portal::PortalTokenConfig, portal_address},
};
use tempo_primitives::TempoTxEnvelope;
use test_case::test_case;
use zone_precompiles::tempo_state::TEMPO_BLOCK_NUMBER_SLOT;
use zone_primitives::constants::{TEMPO_STATE_ADDRESS, zone_chain_id};

use crate::{L1StateInput, Zone, ZoneHarnessInput, engine::GENESIS, run};

const ZONE_ID: u32 = 1;
const SENDER: Address = address!("00000000000000000000000000000000000000a1");
const RECIPIENT: Address = address!("00000000000000000000000000000000000000b2");
const FUNDS: u64 = 1_000_000;

/// The receipt of the `advanceTempo` that opens a block whose header the harness built.
const ADVANCED: (TxIndex, TxOutcome) = (TxIndex::Synthesized(0), TxOutcome::Success);
/// The compressed secp256k1 generator, a key a withdrawal's sender can be revealed to.
const REVEAL_TO: Bytes =
    bytes!("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");

fn chain_id() -> u64 {
    zone_chain_id(1_337, ZONE_ID).unwrap()
}

/// Every hardfork up to `fork` at genesis, the rest long after.
fn chain(fork: TempoHardfork) -> ChainSpecInput {
    let hardforks = TempoHardfork::VARIANTS
        .iter()
        .map(|&hardfork| (hardfork, if hardfork <= fork { 0 } else { u64::MAX / 2 }))
        .collect();
    ChainSpecInput {
        chain_id: chain_id(),
        hardforks,
    }
}

fn genesis_account(address: Address) -> AccountInput {
    let account = &GENESIS.alloc[&address];
    AccountInput {
        balance: account.balance,
        nonce: account.nonce.unwrap_or_default(),
        code: account.code.clone().unwrap_or_default(),
        storage: account
            .storage
            .iter()
            .flatten()
            .map(|(slot, value)| ((*slot).into(), (*value).into()))
            .collect(),
    }
}

fn pre_state() -> StateInput {
    let mut path_usd = genesis_account(PATH_USD_ADDRESS);
    path_usd
        .storage
        .insert(SENDER.mapping_slot(BALANCES), U256::from(FUNDS));
    // Mint, rather than conjure, the sender's funds: TEMPO-TIP20-BALANCE-SUM holds of the pre-state.
    *path_usd.storage.entry(TOTAL_SUPPLY).or_default() += U256::from(FUNDS);
    StateInput {
        accounts: BTreeMap::from([(PATH_USD_ADDRESS, path_usd)]),
    }
}

fn l1(transfers_enabled: bool) -> L1StateInput {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
    StorageCtx::enter(&mut storage, || {
        let mut portal = ZonePortalStorage::new(portal_address(ZONE_ID));
        portal.transfers_enabled.write(transfers_enabled)?;
        portal.token_configs[PATH_USD_ADDRESS].write(PortalTokenConfig {
            enabled: true,
            deposits_active: true,
        })
    })
    .unwrap();
    let mut l1 = L1StateInput::default();
    for (account, slot, value) in storage.into_storage() {
        l1.storage.entry(account).or_default().insert(slot, value);
    }
    l1
}

fn call(nonce: u64, to: Address, input: Vec<u8>) -> Bytes {
    TempoTxEnvelope::Legacy(
        TxLegacy {
            chain_id: Some(chain_id()),
            nonce,
            gas_price: 0,
            gas_limit: 10_000_000,
            to: TxKind::Call(to),
            value: U256::ZERO,
            input: input.into(),
        }
        .into_signed(Signature::test_signature()),
    )
    .encoded_2718()
    .into()
}

fn transfer(nonce: u64, to: Address, amount: u64) -> Bytes {
    let amount = U256::from(amount);
    call(
        nonce,
        PATH_USD_ADDRESS,
        ITIP20::transferCall { to, amount }.abi_encode(),
    )
}

fn context(fork: TempoHardfork, index: u64) -> BlockContextInput {
    BlockContextInput {
        block_number: index + 1,
        timestamp: index + 1,
        hardfork: fork,
        ..Default::default()
    }
}

fn blockchain(fork: TempoHardfork, blocks: Vec<Vec<Bytes>>) -> TempoBlockchainInput {
    let blocks = blocks
        .into_iter()
        .enumerate()
        .map(|(index, txs)| TempoBlock {
            header: BlockHeaderInput::Context(context(fork, index as u64)),
            senders: vec![SENDER; txs.len()],
            txs,
        })
        .collect::<Vec<_>>()
        .try_into()
        .expect("at least one block");
    TempoBlockchainInput {
        chain_spec: chain(fork),
        pre_state: PreState::Genesis(pre_state()),
        blocks,
    }
}

fn execute(
    fork: TempoHardfork,
    l1: L1StateInput,
    blocks: Vec<Vec<Bytes>>,
) -> TempoExecutionOutcome {
    let input = TempoHarnessInput::Blockchain(blockchain(fork, blocks));
    let (TempoHarnessOutcome::Blockchain(outcome), rejection) = run(ZoneHarnessInput { l1, input })
    else {
        panic!("a blockchain input has a blockchain outcome");
    };
    assert_eq!(rejection, None);
    assert!(
        outcome.invariant_failures.is_empty(),
        "{:#?}",
        outcome.invariant_failures
    );
    outcome
}

fn receipts(outcome: &TempoExecutionOutcome) -> Vec<(TxIndex, TxOutcome)> {
    let receipt = |receipt: &TxReceiptOutput| (receipt.tx, receipt.outcome.clone());
    outcome.receipts.iter().map(receipt).collect()
}

#[test]
fn empty_blocks_execute_on_every_zone_hardfork() {
    for &fork in Zone::HARDFORKS {
        let outcome = execute(fork, l1(true), vec![vec![], vec![]]);
        // Each block opens with advanceTempo, whose receipt the outcome records.
        let blocks: Vec<_> = outcome
            .receipts
            .iter()
            .map(|receipt| receipt.block_index)
            .collect();
        assert_eq!(
            (receipts(&outcome), blocks),
            (vec![ADVANCED; 2], vec![0, 1]),
            "{fork:?}"
        );
    }
}

#[test]
fn t15_transfers_follow_the_portal_opt_in() {
    let outcome = execute(
        TempoHardfork::T15,
        l1(true),
        vec![vec![transfer(0, RECIPIENT, 100)]],
    );
    assert_eq!(
        receipts(&outcome),
        [ADVANCED, (TxIndex::Input(0), TxOutcome::Success)]
    );
    // The Tempo protocol invariants judge zone steps, not only Tempo L1's.
    for id in ["TEMPO-TIP20-TRANSFER-EVENTS", "TEMPO-TIP20-BALANCE-SUM"] {
        let counts = &outcome.invariant_counts[id];
        assert!(counts.armed > 0, "{id} never armed: {counts:?}");
    }
    // Zones run no fee AMM or DEX, so their invariants judge nothing.
    let counts = &outcome.invariant_counts;
    let mut judged = counts.iter().filter(|(id, counts)| {
        (id.contains("FEE-AMM") || id.contains("DEX")) && counts.evaluated > 0
    });
    assert!(judged.next().is_none(), "{counts:?}");
    // The zone's TIP-1154 account checks judge every step, and replace the TIP-1107 ones, since a
    // zone mirrors Tempo's commitments rather than keeping its own.
    for id in [
        "TEMPO-ZONE-ACCOUNT-COMMITMENT-MIRROR",
        "TEMPO-ZONE-ACCOUNT-ANCHOR-ADVANCE",
        "TEMPO-ZONE-ACCOUNT-NO-WRITE",
        "TEMPO-ZONE-ACCOUNT-CODE-SERVED",
        "TEMPO-ZONE-ACCOUNT-STATE-CLEAN",
    ] {
        let counts = &outcome.invariant_counts[id];
        assert!(counts.armed > 0, "{id} never armed: {counts:?}");
    }
    assert!(
        !counts.keys().any(|id| id.starts_with("TEMPO-ACCOUNT-")),
        "{counts:?}"
    );

    for (fork, enabled) in [(TempoHardfork::T14, true), (TempoHardfork::T15, false)] {
        let outcome = execute(fork, l1(enabled), vec![vec![transfer(0, RECIPIENT, 100)]]);
        let reverted = [ADVANCED, (TxIndex::Input(0), TxOutcome::Revert)];
        assert_eq!(receipts(&outcome), reverted, "{fork:?} enabled={enabled}");
    }
}

#[test]
fn a_withdrawal_is_finalized_with_its_sender_revealed_at_the_end_of_its_block() {
    let approve = ITIP20::approveCall {
        spender: ZONE_OUTBOX_ADDRESS,
        amount: U256::MAX,
    };
    let withdraw = IZoneOutbox::requestWithdrawal_0Call {
        token: PATH_USD_ADDRESS,
        to: SENDER,
        amount: 100,
        memo: B256::ZERO,
        gasLimit: 0,
        zoneFallbackRecipient: SENDER,
        data: Bytes::new(),
        revealTo: REVEAL_TO,
    };
    let outcome = execute(
        TempoHardfork::T15,
        l1(true),
        vec![vec![
            call(0, PATH_USD_ADDRESS, approve.abi_encode()),
            call(1, ZONE_OUTBOX_ADDRESS, withdraw.abi_encode()),
        ]],
    );

    assert_eq!(
        receipts(&outcome),
        [
            ADVANCED,
            (TxIndex::Input(0), TxOutcome::Success),
            (TxIndex::Input(1), TxOutcome::Success),
            (TxIndex::Synthesized(1), TxOutcome::Success),
        ]
    );
    let steps = &outcome.state_diff.blocks[0];
    assert_eq!((steps.synthesized.len(), steps.txs.len()), (2, 2));
}

/// An empty block on `fork`, its input edited by `edit`.
fn empty_block(
    fork: TempoHardfork,
    edit: impl FnOnce(&mut TempoBlockchainInput),
) -> TempoHarnessInput {
    let mut input = blockchain(fork, vec![vec![]]);
    edit(&mut input);
    TempoHarnessInput::Blockchain(input)
}

/// The zone genesis with TempoState at the last Tempo block number.
fn at_last_tempo_block() -> PreState {
    let mut tempo_state = genesis_account(TEMPO_STATE_ADDRESS);
    tempo_state
        .storage
        .insert(TEMPO_BLOCK_NUMBER_SLOT, U256::from(u64::MAX));
    let mut state = pre_state();
    state.accounts.insert(TEMPO_STATE_ADDRESS, tempo_state);
    PreState::Genesis(state)
}

#[test_case(empty_block(TempoHardfork::T15, |input| input.blocks.as_mut_slice()[0].header = BlockHeaderInput::Context(BlockContextInput { extra_data: Bytes::from_static(b"extra"), ..context(TempoHardfork::T15, 0) })) => (ErrorClass::Rejected, "Rejected/Other/ExtraData: zone header extra data must be empty".into()))]
#[test_case(empty_block(TempoHardfork::T15, |input| input.pre_state = at_last_tempo_block()) => (ErrorClass::Rejected, "Rejected/Other/AnyError: the next Tempo block number overflows".into()))]
#[test_case(empty_block(TempoHardfork::T12, |_| {}) => (ErrorClass::InvalidInput, "InvalidInput/UnsupportedHardfork: a block executes at unsupported hardfork T12".into()))]
fn inputs_the_zone_node_would_not_execute_are_stopped(
    input: TempoHarnessInput,
) -> (ErrorClass, String) {
    let (outcome, rejection) = run(ZoneHarnessInput {
        l1: l1(true),
        input,
    });
    let error = match outcome {
        TempoHarnessOutcome::Transaction(outcome) => outcome.error,
        TempoHarnessOutcome::State(outcome) | TempoHarnessOutcome::Blockchain(outcome) => {
            assert!(outcome.receipts.is_empty(), "{:?}", outcome.receipts);
            outcome.error
        }
    };
    (error, rejection.unwrap().reason().to_string())
}

#[test]
fn a_tempo_commitment_shows_on_the_zone_as_the_account_marker() {
    let mut l1 = l1(true);
    l1.commitments.insert(RECIPIENT, B256::repeat_byte(0x11));
    let outcome = execute(
        TempoHardfork::T15,
        l1,
        vec![vec![transfer(0, RECIPIENT, 100)]],
    );
    assert_eq!(
        receipts(&outcome),
        [ADVANCED, (TxIndex::Input(0), TxOutcome::Success)]
    );
    // The committed recipient is watched: the zone reads Tempo's commitment for it, answers as the
    // account marker, and serves the marker's code for it, all without storing either.
    for id in [
        "TEMPO-ZONE-ACCOUNT-COMMITMENT-MIRROR",
        "TEMPO-ZONE-ACCOUNT-MARKER-CALL",
        "TEMPO-ZONE-ACCOUNT-CODE-SERVED",
    ] {
        let counts = &outcome.invariant_counts[id];
        assert!(counts.armed > 0, "{id} never armed: {counts:?}");
    }
}

#[test]
fn zone_account_checks_start_at_t14() {
    let outcome = execute(
        TempoHardfork::T13,
        l1(true),
        vec![vec![transfer(0, RECIPIENT, 100)]],
    );
    let judged: Vec<_> = outcome
        .invariant_counts
        .keys()
        .filter(|id| id.starts_with("TEMPO-ZONE-ACCOUNT-"))
        .collect();
    assert!(judged.is_empty(), "{judged:?}");
}

#[test]
fn the_c_abi_takes_a_zone_input_and_reports_zone_capabilities() {
    let input = ZoneHarnessInput {
        l1: l1(true),
        input: TempoHarnessInput::Blockchain(blockchain(
            TempoHardfork::T15,
            vec![vec![transfer(0, RECIPIENT, 100)]],
        )),
    };
    let bytes = bincode_options().serialize(&input).unwrap();
    let mut out = vec![0; 1 << 20];
    let mut written = 0;
    let status = unsafe {
        crate::tempo_fuzz_execute_with_result_v1(
            out.as_mut_ptr(),
            out.len(),
            &mut written,
            bytes.as_ptr(),
            bytes.len(),
        )
    };
    assert_eq!(status, FUZZ_ACCEPT);
    let outcome: TempoHarnessOutcome = bincode_options().deserialize(&out[..written]).unwrap();
    assert_eq!((outcome, None), run(input));

    let status =
        unsafe { crate::tempo_fuzz_capabilities_v1(out.as_mut_ptr(), out.len(), &mut written) };
    assert_eq!(status, FUZZ_ACCEPT);
    let capabilities: TempoHarnessCapabilities =
        bincode_options().deserialize(&out[..written]).unwrap();
    assert_eq!(capabilities.schema_version, TYPED_HARNESS_SCHEMA_VERSION);
    assert_eq!(capabilities.implementation, "tempo-zone");
    let ids: Vec<&str> = capabilities
        .invariants
        .iter()
        .map(|info| info.id.as_str())
        .collect();
    for id in [
        "TEMPO-ZONE-ACCOUNT-COMMITMENT-MIRROR",
        "TEMPO-ZONE-ACCOUNT-CODE-SERVED",
        "TEMPO-ZONE-ACCOUNT-VIEW",
        "TEMPO-TIP20-BALANCE-SUM",
        "TEMPO-ACCOUNT-SENDER-QUORUM",
        "TEMPO-ACCOUNT-GRANT-TYPE",
    ] {
        assert!(ids.contains(&id), "{id} is in the catalog: {ids:?}");
    }
    // Zones run no fee AMM or DEX, and keep no configurable account commitments of their own: of
    // the account checks only those of a transaction's own signatures run.
    let signatures = tempo_invariants::configurable_account::TX_CHECKS;
    assert!(
        ids.iter().all(|id| !id.starts_with("TEMPO-FEE-")
            && !id.starts_with("TEMPO-DEX-")
            && (!id.starts_with("TEMPO-ACCOUNT-")
                || signatures.iter().any(|check| check.id == *id))),
        "{ids:?}"
    );
    assert!(
        capabilities
            .invariants
            .iter()
            .all(|info| !info.doc.is_empty())
    );
    assert_eq!(capabilities.supported_hardforks.as_slice(), Zone::HARDFORKS);
    assert_eq!(
        Zone::HARDFORKS.first(),
        Some(&TempoHardfork::T13),
        "zones launched on T13"
    );
}

#[test]
fn an_l1_commitment_on_an_address_the_zone_does_not_reserve_is_mirrored() {
    // 0x1c00..04 is no zone predeploy, and ZoneIdentity only becomes one at T15, so at T14 the
    // zone reads Tempo's commitment for both as for any account.
    let unused = address!("1c00000000000000000000000000000000000004");
    let identity = zone_primitives::constants::ZONE_IDENTITY_ADDRESS;
    for fork in [TempoHardfork::T14, TempoHardfork::T15] {
        let mut l1 = l1(true);
        l1.commitments.insert(unused, B256::repeat_byte(0x22));
        if fork == TempoHardfork::T14 {
            l1.commitments.insert(identity, B256::repeat_byte(0x33));
        }
        let outcome = execute(fork, l1, vec![vec![transfer(0, RECIPIENT, 100)]]);
        let counts = &outcome.invariant_counts["TEMPO-ZONE-ACCOUNT-COMMITMENT-MIRROR"];
        assert!(counts.armed > 0, "{fork:?}: {counts:?}");
    }
}
