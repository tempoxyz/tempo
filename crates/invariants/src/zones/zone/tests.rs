//! The zone-side checks, judged on states and blocks built by hand and read through stub views.

use std::collections::BTreeMap;

use alloy_primitives::{Address, B256, Bytes, Log, LogData, U256};
use alloy_sol_types::{SolCall, SolEvent};
use invariants_core::{CallKind, Check, Frame, Report};

use super::*;

const TOKEN: Address = Address::repeat_byte(0x20);
const ALICE: Address = Address::repeat_byte(0xa1);
const BOB: Address = Address::repeat_byte(0xb0);
const PORTAL: Address = Address::repeat_byte(0x90);

/// Views answering fixed calls, as any caller (\`call\`) or as a given one (\`call_from\`).
#[derive(Default)]
struct Stub {
    answers: BTreeMap<(Address, Bytes), Bytes>,
    from: BTreeMap<(Address, Address, Bytes), Outcome>,
}

impl Stub {
    fn answer<C: SolCall>(mut self, to: Address, call: C, value: C::Return) -> Self {
        self.answers.insert(
            (to, call.abi_encode().into()),
            C::abi_encode_returns(&value).into(),
        );
        self
    }

    fn answer_from(mut self, from: Address, to: Address, input: Bytes, outcome: Outcome) -> Self {
        self.from.insert((from, to, input), outcome);
        self
    }
}

impl Views for Stub {
    type Error = std::convert::Infallible;

    fn call(&mut self, calls: &[(Address, Bytes)]) -> Result<Vec<Option<Bytes>>, Self::Error> {
        Ok(calls
            .iter()
            .map(|key| self.answers.get(key).cloned())
            .collect())
    }

    fn call_from(
        &mut self,
        from: Address,
        calls: &[(Address, Bytes)],
    ) -> Result<Vec<Option<Outcome>>, Self::Error> {
        Ok(calls
            .iter()
            .map(|(to, input)| self.from.get(&(from, *to, input.clone())).cloned())
            .collect())
    }
}

/// A zone whose predeploys all answer: Tempo block \`tempo\`, \`processed\` deposits, batch \`batch\`
/// and \`supply\` of [\`TOKEN\`].
fn zone(tempo: u64, processed: u64, batch: u64, supply: u64) -> Zone {
    Zone {
        tempo: Some(TempoBlock {
            number: tempo,
            hash: tempo_hash(tempo),
        }),
        inbox: Some(Inbox {
            processed_deposit_number: processed,
            processed_deposit_queue_hash: queue_hash(processed),
            processed_token_enablement_hash: Some(B256::repeat_byte(0xee)),
        }),
        outbox: Some(IZoneOutbox::LastBatch {
            withdrawalQueueHash: batch_hash(batch),
            withdrawalBatchIndex: batch,
        }),
        supplies: BTreeMap::from([(TOKEN, U256::from(supply))]),
    }
}

fn tempo_hash(number: u64) -> B256 {
    B256::left_padding_from(&[0x7e, number as u8])
}

fn queue_hash(number: u64) -> B256 {
    if number == 0 {
        B256::ZERO
    } else {
        B256::left_padding_from(&[0xd0, number as u8])
    }
}

fn batch_hash(index: u64) -> B256 {
    B256::left_padding_from(&[0xba, index as u8])
}

fn log(address: Address, data: LogData) -> Log {
    Log { address, data }
}

fn tx(to: Option<Address>, input: Bytes, logs: std::ops::Range<usize>) -> ZoneTx {
    ZoneTx {
        sender: ALICE,
        to,
        input,
        success: true,
        logs,
    }
}

fn block(txs: Vec<ZoneTx>) -> ZoneBlock {
    ZoneBlock {
        number: 11,
        timestamp: 1_000,
        parent_number: 10,
        parent_timestamp: 999,
        txs,
        imported: Vec::new(),
    }
}

fn step(pre: Zone, post: Zone, logs: Vec<Log>, tx: ZoneBlock) -> Step<Zone, ZoneBlock> {
    Step {
        pre,
        post,
        changes: Vec::new(),
        logs,
        calls: Vec::new(),
        tx,
    }
}

fn advance_input() -> Bytes {
    IZoneInbox::advanceTempoCall {
        header: Bytes::new(),
        deposits: Vec::new(),
        decryptions: Vec::new(),
        enabledTokens: Vec::new(),
    }
    .abi_encode()
    .into()
}

fn mint_event(to: Address, amount: u64) -> Log {
    log(
        TOKEN,
        ITIP20::Transfer {
            from: Address::ZERO,
            to,
            amount: U256::from(amount),
        }
        .encode_log_data(),
    )
}

fn deposit_processed(to: Address, amount: u128) -> Log {
    log(
        ZONE_INBOX_ADDRESS,
        IZoneInbox::DepositProcessed {
            depositHash: B256::repeat_byte(1),
            sender: BOB,
            to,
            token: TOKEN,
            amount,
            memo: B256::ZERO,
        }
        .encode_log_data(),
    )
}

/// \`TempoAdvanced\` to Tempo block \`tempo\` having processed \`deposits\` up to \`last\`.
fn tempo_advanced(tempo: u64, deposits: u64, last: u64) -> Log {
    log(
        ZONE_INBOX_ADDRESS,
        IZoneInbox::TempoAdvanced_1 {
            tempoBlockHash: tempo_hash(tempo),
            tempoBlockNumber: tempo,
            depositsProcessed: U256::from(deposits),
            newProcessedDepositQueueHash: queue_hash(last),
            lastProcessedDepositNumber: last,
            lastProcessedEnabledTokenCount: 1,
        }
        .encode_log_data(),
    )
}

fn tempo_finalized(number: u64) -> Log {
    log(
        TEMPO_STATE_ADDRESS,
        TempoState::TempoBlockFinalized {
            blockHash: tempo_hash(number),
            blockNumber: number,
            stateRoot: B256::ZERO,
        }
        .encode_log_data(),
    )
}

fn batch_finalized(index: u64) -> Log {
    log(
        ZONE_OUTBOX_ADDRESS,
        IZoneOutbox::BatchFinalized {
            withdrawalQueueHash: batch_hash(index),
            withdrawalBatchIndex: index,
        }
        .encode_log_data(),
    )
}

/// What \`checks\` found on \`ctx\`: how often \`id\` armed, and its violations' details.
fn judge<C>(checks: &[Check<C>], ctx: &C, id: &str) -> (u64, Vec<String>) {
    let mut report = Report::default();
    report.run(checks, ctx);
    let armed = report.counts.get(id).map_or(0, |c| c.armed);
    let fired = report
        .violations
        .into_iter()
        .filter(|v| v.id == id)
        .map(|v| v.detail)
        .collect();
    (armed, fired)
}

#[test]
fn observe_reads_every_predeploy_and_supply() {
    let mut views = Stub::default()
        .answer(TEMPO_STATE_ADDRESS, TempoState::tempoBlockNumberCall {}, 3)
        .answer(
            TEMPO_STATE_ADDRESS,
            TempoState::tempoBlockHashCall {},
            tempo_hash(3),
        )
        .answer(
            ZONE_INBOX_ADDRESS,
            IZoneInbox::processedDepositNumberCall {},
            2,
        )
        .answer(
            ZONE_INBOX_ADDRESS,
            IZoneInbox::processedDepositQueueHashCall {},
            queue_hash(2),
        )
        .answer(
            ZONE_INBOX_ADDRESS,
            IZoneInbox::processedTokenEnablementHashCall {},
            B256::repeat_byte(0xee),
        )
        .answer(
            ZONE_OUTBOX_ADDRESS,
            IZoneOutbox::lastBatchCall {},
            IZoneOutbox::LastBatch {
                withdrawalQueueHash: batch_hash(1),
                withdrawalBatchIndex: 1,
            },
        )
        .answer(TOKEN, ITIP20::totalSupplyCall {}, U256::from(7));
    let observed = Zone::observe(&mut views, &[TOKEN]).unwrap();
    assert_eq!(observed, zone(3, 2, 1, 7));
    assert_eq!(judge(CHECKS, &observed, PREDEPLOY_ADDRESSES), (1, vec![]));
}

#[test]
fn predeploy_addresses_fires_when_a_predeploy_answers_nothing() {
    // Only TempoState answers: the inbox and outbox have no code.
    let mut views = Stub::default()
        .answer(TEMPO_STATE_ADDRESS, TempoState::tempoBlockNumberCall {}, 3)
        .answer(
            TEMPO_STATE_ADDRESS,
            TempoState::tempoBlockHashCall {},
            tempo_hash(3),
        );
    let observed = Zone::observe(&mut views, &[]).unwrap();
    let (_, fired) = judge(CHECKS, &observed, PREDEPLOY_ADDRESSES);
    assert_eq!(fired, ["no answer from ZoneInbox, ZoneOutbox"]);
}

#[test]
fn block_timestamp_monotonic() {
    let ok = step(zone(1, 0, 0, 0), zone(1, 0, 0, 0), vec![], block(vec![]));
    assert_eq!(
        judge(STEP_CHECKS, &ok, BLOCK_TIMESTAMP_MONOTONIC),
        (1, vec![])
    );

    let mut earlier = ok.clone();
    earlier.tx.timestamp = 998;
    assert_eq!(
        judge(STEP_CHECKS, &earlier, BLOCK_TIMESTAMP_MONOTONIC)
            .1
            .len(),
        1
    );

    let mut skipped = ok;
    skipped.tx.number = 12;
    assert_eq!(
        judge(STEP_CHECKS, &skipped, BLOCK_TIMESTAMP_MONOTONIC)
            .1
            .len(),
        1
    );
}

#[test]
fn advance_tempo_first() {
    let transfer = tx(Some(TOKEN), Bytes::new(), 0..0);
    let advance = tx(Some(ZONE_INBOX_ADDRESS), advance_input(), 0..0);
    let none = step(
        zone(1, 0, 0, 0),
        zone(1, 0, 0, 0),
        vec![],
        block(vec![transfer.clone()]),
    );
    assert_eq!(judge(STEP_CHECKS, &none, ADVANCE_TEMPO_FIRST).0, 0);

    let first = step(
        zone(1, 0, 0, 0),
        zone(1, 0, 0, 0),
        vec![],
        block(vec![advance.clone(), transfer.clone()]),
    );
    assert_eq!(judge(STEP_CHECKS, &first, ADVANCE_TEMPO_FIRST), (1, vec![]));

    // Reverted user lookalikes of either call advance nothing, wherever they sit.
    let mut lookalike = tx(Some(ZONE_INBOX_ADDRESS), advance_input(), 0..0);
    lookalike.success = false;
    let mut headers_lookalike = tx(
        Some(ZONE_INBOX_ADDRESS),
        IZoneInbox::advanceTempoHeadersCall { headers: vec![] }
            .abi_encode()
            .into(),
        0..0,
    );
    headers_lookalike.success = false;
    let reverted = step(
        zone(1, 0, 0, 0),
        zone(1, 0, 0, 0),
        vec![],
        block(vec![
            advance.clone(),
            transfer.clone(),
            lookalike.clone(),
            headers_lookalike.clone(),
        ]),
    );
    assert_eq!(
        judge(STEP_CHECKS, &reverted, ADVANCE_TEMPO_FIRST),
        (1, vec![])
    );
    let only_lookalikes = step(
        zone(1, 0, 0, 0),
        zone(1, 0, 0, 0),
        vec![],
        block(vec![transfer.clone(), lookalike, headers_lookalike]),
    );
    assert_eq!(
        judge(STEP_CHECKS, &only_lookalikes, ADVANCE_TEMPO_FIRST).0,
        0
    );

    let second = step(
        zone(1, 0, 0, 0),
        zone(1, 0, 0, 0),
        vec![],
        block(vec![transfer, advance]),
    );
    assert_eq!(
        judge(STEP_CHECKS, &second, ADVANCE_TEMPO_FIRST).1,
        ["Tempo advanced by transactions [1]"]
    );
}

#[test]
fn contract_creation_disabled() {
    let mut reverted = tx(None, Bytes::new(), 0..0);
    reverted.success = false;
    let mut s = step(
        zone(1, 0, 0, 0),
        zone(1, 0, 0, 0),
        vec![],
        block(vec![reverted]),
    );
    assert_eq!(
        judge(STEP_CHECKS, &s, CONTRACT_CREATION_DISABLED),
        (1, vec![])
    );

    s.tx.txs[0].success = true;
    assert_eq!(
        judge(STEP_CHECKS, &s, CONTRACT_CREATION_DISABLED).1.len(),
        1
    );

    s.tx.txs[0].success = false;
    s.calls.push(Frame {
        depth: 1,
        kind: CallKind::Create2,
        caller: BOB,
        target: Address::repeat_byte(0xcc),
        input: Bytes::new(),
        value: U256::ZERO,
        success: true,
        output: Bytes::new(),
    });
    let (_, fired) = judge(STEP_CHECKS, &s, CONTRACT_CREATION_DISABLED);
    assert_eq!(fired.len(), 1);
    assert!(fired[0].contains("Create2"), "{fired:?}");
}

#[test]
fn mint_burn_authority() {
    // A mint announced by the inbox's DepositProcessed holds.
    let announced = step(
        zone(1, 0, 0, 0),
        zone(1, 0, 0, 5),
        vec![mint_event(ALICE, 5), deposit_processed(ALICE, 5)],
        block(vec![tx(Some(ZONE_INBOX_ADDRESS), advance_input(), 0..2)]),
    );
    assert_eq!(
        judge(STEP_CHECKS, &announced, MINT_BURN_AUTHORITY),
        (1, vec![])
    );

    // The same mint without it fires.
    let unannounced = step(
        zone(1, 0, 0, 0),
        zone(1, 0, 0, 5),
        vec![mint_event(ALICE, 5)],
        block(vec![tx(Some(TOKEN), Bytes::new(), 0..1)]),
    );
    assert_eq!(
        judge(STEP_CHECKS, &unannounced, MINT_BURN_AUTHORITY)
            .1
            .len(),
        1
    );

    // A burn from anyone but the outbox fires.
    let burn = log(
        TOKEN,
        ITIP20::Transfer {
            from: ALICE,
            to: Address::ZERO,
            amount: U256::from(3),
        }
        .encode_log_data(),
    );
    let burned = step(
        zone(1, 0, 0, 5),
        zone(1, 0, 0, 2),
        vec![burn],
        block(vec![tx(Some(TOKEN), Bytes::new(), 0..1)]),
    );
    assert_eq!(judge(STEP_CHECKS, &burned, MINT_BURN_AUTHORITY).1.len(), 1);

    // With traces, a mint frame entered by anyone but the inbox fires.
    let mut traced = step(zone(1, 0, 0, 0), zone(1, 0, 0, 0), vec![], block(vec![]));
    traced.calls.push(Frame {
        depth: 1,
        kind: CallKind::Call,
        caller: BOB,
        target: TOKEN,
        input: ITIP20::mintCall {
            to: BOB,
            amount: U256::from(1),
        }
        .abi_encode()
        .into(),
        value: U256::ZERO,
        success: true,
        output: Bytes::new(),
    });
    assert_eq!(judge(STEP_CHECKS, &traced, MINT_BURN_AUTHORITY).1.len(), 1);
    traced.calls[0].caller = ZONE_INBOX_ADDRESS;
    assert_eq!(
        judge(STEP_CHECKS, &traced, MINT_BURN_AUTHORITY),
        (1, vec![])
    );
}

#[test]
fn tempo_header_continuity() {
    let header = |number: u64| TempoHeader {
        number,
        hash: tempo_hash(number),
        parent_hash: tempo_hash(number - 1),
    };
    // One call importing two headers finalizes once, at the last.
    let advance = tx(Some(ZONE_INBOX_ADDRESS), advance_input(), 0..1);
    let mut s = step(
        zone(1, 0, 0, 0),
        zone(3, 0, 0, 0),
        vec![tempo_finalized(3)],
        block(vec![advance]),
    );
    s.tx.imported = vec![header(2), header(3)];
    assert_eq!(judge(STEP_CHECKS, &s, TEMPO_HEADER_CONTINUITY), (1, vec![]));

    // The same import when the runner did not decode the headers.
    let mut undecoded = s.clone();
    undecoded.tx.imported.clear();
    assert_eq!(
        judge(STEP_CHECKS, &undecoded, TEMPO_HEADER_CONTINUITY),
        (1, vec![])
    );

    // Calls importing one header each finalize once per header.
    let mut each = s.clone();
    each.logs = vec![tempo_finalized(2), tempo_finalized(3)];
    assert_eq!(
        judge(STEP_CHECKS, &each, TEMPO_HEADER_CONTINUITY),
        (1, vec![])
    );

    // A header whose parent is not the one finalized before.
    let mut forked = s.clone();
    forked.tx.imported[1].parent_hash = B256::repeat_byte(0x66);
    assert_eq!(
        judge(STEP_CHECKS, &forked, TEMPO_HEADER_CONTINUITY).1.len(),
        1
    );

    // A header that skips one.
    let mut gap = s.clone();
    gap.tx.imported = vec![TempoHeader {
        parent_hash: tempo_hash(1),
        ..header(3)
    }];
    assert_eq!(judge(STEP_CHECKS, &gap, TEMPO_HEADER_CONTINUITY).1.len(), 1);

    // A finalized block that is none of the imported headers.
    let mut stray = s;
    stray.logs = vec![
        log(
            TEMPO_STATE_ADDRESS,
            TempoState::TempoBlockFinalized {
                blockHash: B256::repeat_byte(0x66),
                blockNumber: 2,
                stateRoot: B256::ZERO,
            }
            .encode_log_data(),
        ),
        tempo_finalized(3),
    ];
    assert_eq!(
        judge(STEP_CHECKS, &stray, TEMPO_HEADER_CONTINUITY).1.len(),
        1
    );

    // A finalized block that does not move past the one before.
    let back = step(
        zone(1, 0, 0, 0),
        zone(1, 0, 0, 0),
        vec![tempo_finalized(1)],
        block(vec![]),
    );
    assert_eq!(
        judge(STEP_CHECKS, &back, TEMPO_HEADER_CONTINUITY).1.len(),
        1
    );

    // A block that leaves Tempo alone is not judged.
    let idle = step(zone(1, 0, 0, 0), zone(1, 0, 0, 0), vec![], block(vec![]));
    assert_eq!(judge(STEP_CHECKS, &idle, TEMPO_HEADER_CONTINUITY).0, 0);
}

#[test]
fn deposit_cursor_moves_by_what_tempo_advanced_reports() {
    let ok = step(
        zone(1, 2, 0, 0),
        zone(2, 4, 0, 0),
        vec![tempo_advanced(2, 2, 4)],
        block(vec![]),
    );
    assert_eq!(
        judge(STEP_CHECKS, &ok, DEPOSIT_NUMBER_MONOTONIC),
        (1, vec![])
    );
    assert_eq!(
        judge(STEP_CHECKS, &ok, DEPOSIT_PROCESSED_PREFIX),
        (1, vec![])
    );

    // The cursor moves by one more than the event reports.
    let skipped = step(
        zone(1, 2, 0, 0),
        zone(2, 5, 0, 0),
        vec![tempo_advanced(2, 2, 4)],
        block(vec![]),
    );
    assert_eq!(
        judge(STEP_CHECKS, &skipped, DEPOSIT_NUMBER_MONOTONIC)
            .1
            .len(),
        1
    );
    assert_eq!(
        judge(STEP_CHECKS, &skipped, DEPOSIT_PROCESSED_PREFIX)
            .1
            .len(),
        1
    );

    // The cursor falls.
    let fell = step(zone(1, 4, 0, 0), zone(1, 3, 0, 0), vec![], block(vec![]));
    assert_eq!(
        judge(STEP_CHECKS, &fell, DEPOSIT_NUMBER_MONOTONIC).1.len(),
        1
    );

    // The hash moves without the number.
    let mut rehashed = step(zone(1, 4, 0, 0), zone(1, 4, 0, 0), vec![], block(vec![]));
    rehashed
        .post
        .inbox
        .as_mut()
        .unwrap()
        .processed_deposit_queue_hash = B256::repeat_byte(9);
    assert_eq!(
        judge(STEP_CHECKS, &rehashed, DEPOSIT_PROCESSED_PREFIX)
            .1
            .len(),
        1
    );
}

#[test]
fn withdrawal_batch_index() {
    let ok = step(
        zone(1, 0, 4, 0),
        zone(1, 0, 5, 0),
        vec![batch_finalized(5)],
        block(vec![]),
    );
    assert_eq!(judge(STEP_CHECKS, &ok, WITHDRAWAL_BATCH_INDEX), (1, vec![]));

    let idle = step(zone(1, 0, 4, 0), zone(1, 0, 4, 0), vec![], block(vec![]));
    assert_eq!(
        judge(STEP_CHECKS, &idle, WITHDRAWAL_BATCH_INDEX),
        (1, vec![])
    );

    // Two indices for one finalized batch.
    let jumped = step(
        zone(1, 0, 4, 0),
        zone(1, 0, 6, 0),
        vec![batch_finalized(6)],
        block(vec![]),
    );
    assert_eq!(
        judge(STEP_CHECKS, &jumped, WITHDRAWAL_BATCH_INDEX).1.len(),
        1
    );

    // A batch finalized without moving the index.
    let stuck = step(
        zone(1, 0, 4, 0),
        zone(1, 0, 4, 0),
        vec![batch_finalized(5)],
        block(vec![]),
    );
    assert_eq!(
        judge(STEP_CHECKS, &stuck, WITHDRAWAL_BATCH_INDEX).1.len(),
        1
    );
}

#[test]
fn supply_solvency_folds_bridge_events() {
    let withdrawal = log(
        ZONE_OUTBOX_ADDRESS,
        IZoneOutbox::WithdrawalRequested {
            withdrawalIndex: 0,
            sender: ALICE,
            token: TOKEN,
            to: ALICE,
            amount: 3,
            fee: 1,
            memo: B256::ZERO,
            gasLimit: 0,
            fallbackNonce: 0,
            data: Bytes::new(),
            revealTo: Bytes::new(),
        }
        .encode_log_data(),
    );
    let mut history = History::<Bridged>::default();
    // Block 1 mints 10 on a processed deposit.
    let deposit = step(
        zone(1, 0, 0, 100),
        zone(1, 1, 0, 110),
        vec![deposit_processed(ALICE, 10)],
        block(vec![]),
    );
    history.push(&deposit);
    assert_eq!(
        judge(
            HISTORY_CHECKS,
            &history.at(deposit.post.clone()),
            SUPPLY_SOLVENCY
        ),
        (1, vec![])
    );
    // Block 2 burns 3 plus a fee of 1 for a withdrawal.
    let withdraw = step(
        zone(1, 1, 0, 110),
        zone(1, 1, 0, 106),
        vec![withdrawal],
        block(vec![]),
    );
    history.push(&withdraw);
    assert_eq!(
        judge(
            HISTORY_CHECKS,
            &history.at(withdraw.post.clone()),
            SUPPLY_SOLVENCY
        ),
        (1, vec![])
    );
    // A supply the events do not account for fires.
    let (_, fired) = judge(
        HISTORY_CHECKS,
        &history.at(zone(1, 1, 0, 107)),
        SUPPLY_SOLVENCY,
    );
    assert_eq!(fired, ["totalSupply 107, bridge events account for 106"]);
}

/// A token enabled in a block reads no supply before it; its first mints still count.
#[test]
fn supply_solvency_judges_a_token_from_the_block_that_enabled_it() {
    let mut pre = zone(1, 0, 0, 0);
    pre.supplies.clear();
    let mut history = History::<Bridged>::default();
    let enabled = step(
        pre.clone(),
        zone(1, 1, 0, 10),
        vec![deposit_processed(ALICE, 10)],
        block(vec![]),
    );
    history.push(&enabled);
    assert_eq!(
        judge(
            HISTORY_CHECKS,
            &history.at(enabled.post.clone()),
            SUPPLY_SOLVENCY
        ),
        (1, vec![])
    );

    let mut history = History::<Bridged>::default();
    let unbacked = step(
        pre,
        zone(1, 1, 0, 11),
        vec![deposit_processed(ALICE, 10)],
        block(vec![]),
    );
    history.push(&unbacked);
    let (_, fired) = judge(
        HISTORY_CHECKS,
        &history.at(unbacked.post.clone()),
        SUPPLY_SOLVENCY,
    );
    assert_eq!(fired, ["totalSupply 11, bridge events account for 10"]);
}

#[test]
fn privacy_getters_asked_as_a_third_party() {
    let balance = Getter::Balance { account: ALICE };
    let input = ITIP20::balanceOfCall { account: ALICE }.abi_encode().into();
    let value = Bytes::from(U256::from(42).to_be_bytes_vec());
    let at = PrivacyAt {
        asker: THIRD_PARTY,
        getters: &[(TOKEN, balance)],
    };

    // The owner reads 42 and the third party a revert: private.
    let mut views = Stub::default()
        .answer_from(
            ALICE,
            TOKEN,
            Bytes::clone(&input),
            Outcome::Return(value.clone()),
        )
        .answer_from(
            THIRD_PARTY,
            TOKEN,
            Bytes::clone(&input),
            Outcome::Revert(Bytes::new()),
        );
    let privacy = Privacy::observe(&mut views, at).unwrap();
    assert_eq!(
        judge(PRIVACY_CHECKS, &privacy, BALANCE_ALLOWANCE_PRIVACY),
        (1, vec![])
    );

    // The third party reads the owner's 42: revealed.
    let mut views = Stub::default()
        .answer_from(
            ALICE,
            TOKEN,
            Bytes::clone(&input),
            Outcome::Return(value.clone()),
        )
        .answer_from(THIRD_PARTY, TOKEN, input, Outcome::Return(value));
    let privacy = Privacy::observe(&mut views, at).unwrap();
    assert_eq!(
        judge(PRIVACY_CHECKS, &privacy, BALANCE_ALLOWANCE_PRIVACY)
            .1
            .len(),
        1
    );

    // Views that cannot set the caller judge nothing.
    let privacy = Privacy::observe(&mut Stub::default(), at).unwrap();
    assert_eq!(
        judge(PRIVACY_CHECKS, &privacy, BALANCE_ALLOWANCE_PRIVACY).0,
        0
    );
}

#[test]
fn privacy_getters_the_third_party_is_a_party_to_are_not_judged() {
    let value = Bytes::from(U256::from(42).to_be_bytes_vec());
    // Each getter with the owner who reads it and whether the third party may read it too.
    let getters = [
        (
            Getter::Allowance {
                owner: ALICE,
                spender: THIRD_PARTY,
            },
            ALICE,
            true,
        ),
        (
            Getter::Balance {
                account: THIRD_PARTY,
            },
            THIRD_PARTY,
            true,
        ),
        (
            Getter::Allowance {
                owner: ALICE,
                spender: BOB,
            },
            ALICE,
            false,
        ),
    ];
    for (getter, owner, party) in getters {
        let mut views = Stub::default()
            .answer_from(owner, TOKEN, getter.input(), Outcome::Return(value.clone()))
            .answer_from(
                THIRD_PARTY,
                TOKEN,
                getter.input(),
                Outcome::Return(value.clone()),
            );
        let at = PrivacyAt {
            asker: THIRD_PARTY,
            getters: &[(TOKEN, getter)],
        };
        let privacy = Privacy::observe(&mut views, at).unwrap();
        let (armed, fired) = judge(PRIVACY_CHECKS, &privacy, BALANCE_ALLOWANCE_PRIVACY);
        assert_eq!(
            (armed, fired.is_empty()),
            (u64::from(!party), party),
            "{getter}"
        );
    }
}

#[test]
fn anchored_checks_compare_the_zone_with_the_portal() {
    let imported = step(
        zone(1, 0, 0, 0),
        zone(2, 3, 0, 0),
        vec![],
        block(vec![tx(Some(ZONE_INBOX_ADDRESS), advance_input(), 0..0)]),
    );
    let portal = PortalAnchor {
        portal: PORTAL,
        token_enablement_hash: Some(B256::repeat_byte(0xee)),
        deposit_count: Some(3),
        current_deposit_queue_hash: Some(queue_hash(3)),
    };
    let ok = Pair {
        left: imported,
        right: portal,
    };
    assert_eq!(
        judge(ANCHOR_CHECKS, &ok, TOKEN_ENABLEMENT_BINDING),
        (1, vec![])
    );
    assert_eq!(
        judge(ANCHOR_CHECKS, &ok, DEPOSIT_PROCESSED_PREFIX),
        (1, vec![])
    );

    let mut diverged = ok.clone();
    diverged.right.token_enablement_hash = Some(B256::repeat_byte(0xef));
    diverged.right.deposit_count = Some(2);
    assert_eq!(
        judge(ANCHOR_CHECKS, &diverged, TOKEN_ENABLEMENT_BINDING)
            .1
            .len(),
        1
    );
    assert_eq!(
        judge(ANCHOR_CHECKS, &diverged, DEPOSIT_PROCESSED_PREFIX)
            .1
            .len(),
        1
    );

    // At the queue's end the hash chains must agree.
    let mut other_chain = ok;
    other_chain.right.current_deposit_queue_hash = Some(B256::repeat_byte(0x01));
    assert_eq!(
        judge(ANCHOR_CHECKS, &other_chain, DEPOSIT_PROCESSED_PREFIX)
            .1
            .len(),
        1
    );

    // A block that does not import Tempo is not judged.
    let idle = Pair {
        left: step(zone(1, 0, 0, 0), zone(1, 0, 0, 0), vec![], block(vec![])),
        right: portal,
    };
    assert_eq!(judge(ANCHOR_CHECKS, &idle, TOKEN_ENABLEMENT_BINDING).0, 0);
}

#[test]
fn batch_withdrawal_commitment() {
    let event = ZonePortal::BatchSubmitted_1 {
        withdrawalBatchIndex: 5,
        withdrawalQueueIndex: U256::from(5),
        nextProcessedDepositQueueHash: B256::ZERO,
        nextBlockHash: B256::repeat_byte(0x11),
        withdrawalQueueHash: batch_hash(5),
        lastProcessedDepositNumber: 0,
        lastProcessedEnabledTokenCount: 1,
    };
    let submission = Submission::from_log(&log(PORTAL, event.encode_log_data())).unwrap();
    assert_eq!(submission.withdrawal_queue_hash, batch_hash(5));
    let proven = Pair {
        left: zone(1, 0, 5, 0),
        right: submission,
    };
    assert_eq!(
        judge(BATCH_CHECKS, &proven, BATCH_WITHDRAWAL_COMMITMENT),
        (1, vec![])
    );

    // The portal accepted a hash the proven block's outbox never finalized.
    let forged = Pair {
        left: zone(1, 0, 4, 0),
        right: submission,
    };
    assert_eq!(
        judge(BATCH_CHECKS, &forged, BATCH_WITHDRAWAL_COMMITMENT)
            .1
            .len(),
        1
    );

    // A block that never finalized batch 5 still holds batch 4; with zero withdrawals both commit
    // to the zero hash, so only the index tells them apart.
    let mut stale = zone(1, 0, 4, 0);
    stale.outbox.as_mut().unwrap().withdrawalQueueHash = B256::ZERO;
    let empty = Submission {
        withdrawal_queue_hash: B256::ZERO,
        ..submission
    };
    let (_, fired) = judge(
        BATCH_CHECKS,
        &Pair {
            left: stale,
            right: empty,
        },
        BATCH_WITHDRAWAL_COMMITMENT,
    );
    assert_eq!(fired.len(), 1, "{fired:?}");
}
