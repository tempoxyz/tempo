//! The zone-side invariants.

use std::fmt;

use alloy_primitives::{Address, B256, Log, U256};
use alloy_sol_types::{SolCall, SolEvent};
use invariants_core::{CallKind, Folded, Outcome, Severity, check, ensure};

use super::{
    Anchored, Bridged, Getter, ITIP20, IZoneInbox, IZoneOutbox, Privacy, PrivateRead, Proven,
    TEMPO_STATE_ADDRESS, TempoState, ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS, Zone, ZoneBlock,
    inbox_mint,
};
use crate::{Check, Step, Verdict};

pub const PREDEPLOY_ADDRESSES: &str = "TEMPO-ZONE-PREDEPLOY-ADDRESSES";
pub const MINT_BURN_AUTHORITY: &str = "TEMPO-ZONE-MINT-BURN-AUTHORITY";
pub const TEMPO_HEADER_CONTINUITY: &str = "TEMPO-ZONE-TEMPO-HEADER-CONTINUITY";
pub const BLOCK_TIMESTAMP_MONOTONIC: &str = "TEMPO-ZONE-BLOCK-TIMESTAMP-MONOTONIC";
pub const ADVANCE_TEMPO_FIRST: &str = "TEMPO-ZONE-ADVANCE-TEMPO-FIRST";
pub const CONTRACT_CREATION_DISABLED: &str = "TEMPO-ZONE-CONTRACT-CREATION-DISABLED";
pub const DEPOSIT_PROCESSED_PREFIX: &str = "TEMPO-ZONE-DEPOSIT-PROCESSED-PREFIX";
pub const DEPOSIT_NUMBER_MONOTONIC: &str = "TEMPO-ZONE-DEPOSIT-NUMBER-MONOTONIC";
pub const WITHDRAWAL_BATCH_INDEX: &str = "TEMPO-ZONE-WITHDRAWAL-BATCH-INDEX";
pub const SUPPLY_SOLVENCY: &str = "TEMPO-ZONE-SUPPLY-SOLVENCY";
pub const BALANCE_ALLOWANCE_PRIVACY: &str = "TEMPO-ZONE-BALANCE-ALLOWANCE-PRIVACY";
pub const ACCOUNT_GETTER_PRIVACY: &str = "TEMPO-ZONE-ACCOUNT-GETTER-PRIVACY";
pub const REFUND_READ_PRIVACY: &str = "TEMPO-ZONE-REFUND-READ-PRIVACY";
pub const TOKEN_ENABLEMENT_BINDING: &str = "TEMPO-ZONE-TOKEN-ENABLEMENT-BINDING";
pub const BATCH_WITHDRAWAL_COMMITMENT: &str = "TEMPO-ZONE-BATCH-WITHDRAWAL-COMMITMENT";

/// Shared by the zone-side and portal-side halves of the invariant, so both state it alike.
const DEPOSIT_PROCESSED_PREFIX_DOC: &str = "The inbox processes only a prefix of the portal queue, oldest first, and never skips, reorders, or duplicates deposits.";

/// One zone state.
pub const CHECKS: &[Check<Zone>] = &[
    // A predeploy without code answers nothing, so every getter answering means each one runs at
    // its address.
    check! {
        id: PREDEPLOY_ADDRESSES,
        doc: "`TempoState`, `ZoneInbox`, and `ZoneOutbox` answer their views at their fixed predeploy addresses.",
        severity: Severity::Critical,
        judge: |z: &Zone| {
            let missing: Vec<&str> = [
                ("TempoState", z.tempo.is_none()),
                ("ZoneInbox", z.inbox.is_none()),
                ("ZoneOutbox", z.outbox.is_none()),
            ]
            .into_iter()
            .filter_map(|(name, missing)| missing.then_some(name))
            .collect();
            ensure!(missing.is_empty(), "no answer from {}", missing.join(", "))
        },
    },
];

/// One zone block: the states around it, its logs and its [`ZoneBlock`].
pub const STEP_CHECKS: &[Check<Step<Zone, ZoneBlock>>] = &[
    check! {
        id: BLOCK_TIMESTAMP_MONOTONIC,
        doc: "Zone block timestamps are non-decreasing and block numbers increment by one.",
        severity: Severity::Medium,
        over: |s: &Step<Zone, ZoneBlock>| [&s.tx],
        judge: |_, b| {
            ensure!(
                b.parent_number.checked_add(1) == Some(b.number) && b.timestamp >= b.parent_timestamp,
                "block {} at {} follows block {} at {}",
                b.number,
                b.timestamp,
                b.parent_number,
                b.parent_timestamp
            )
        },
    },
    // Judged on blocks that advance Tempo at all: only a successful call advances it, so a
    // reverted lookalike (any sender but the system one reverts) does not count.
    check! {
        id: ADVANCE_TEMPO_FIRST,
        doc: "When present, `advanceTempo` is the first transaction in a zone block.",
        severity: Severity::High,
        over: |s: &Step<Zone, ZoneBlock>| [&s.tx],
        judge: |_, b| {
            let advancing: Vec<usize> = b
                .txs
                .iter()
                .enumerate()
                .filter(|(_, tx)| {
                    tx.success
                        && tx.to == Some(ZONE_INBOX_ADDRESS)
                        && tx.selector().is_some_and(|s| {
                            s == IZoneInbox::advanceTempoCall::SELECTOR
                                || s == IZoneInbox::advanceTempoHeadersCall::SELECTOR
                        })
                })
                .map(|(index, _)| index)
                .collect();
            if advancing.is_empty() {
                return None;
            }
            ensure!(advancing == [0], "Tempo advanced by transactions {advancing:?}")
        },
    },
    // Without call traces only top-level creations are seen; with them, every creation frame.
    check! {
        id: CONTRACT_CREATION_DISABLED,
        doc: "User `CREATE` and `CREATE2` always revert on zones.",
        severity: Severity::High,
        over: |s: &Step<Zone, ZoneBlock>| [&s.tx],
        judge: |s, b| {
            let mut created: Vec<String> = b
                .txs
                .iter()
                .enumerate()
                .filter(|(_, tx)| tx.to.is_none() && tx.success)
                .map(|(index, tx)| format!("tx {index} from {}", tx.sender))
                .collect();
            created.extend(
                s.calls
                    .iter()
                    .filter(|f| matches!(f.kind, CallKind::Create | CallKind::Create2) && f.success)
                    .map(|f| format!("{:?} by {} at depth {}", f.kind, f.caller, f.depth)),
            );
            ensure!(created.is_empty(), "contracts created: {}", created.join("; "))
        },
    },
    // A mint must come with the inbox outcome that announces it (a processed deposit, withdrawal
    // bounce-back or refund claim) in the same transaction, and a burn must burn the outbox's own
    // escrow. With call traces, every mint and burn frame must come from the inbox or outbox.
    check! {
        id: MINT_BURN_AUTHORITY,
        doc: "Only `ZoneInbox` can mint zone tokens and only `ZoneOutbox` can burn zone tokens.",
        severity: Severity::Critical,
        over: |s: &Step<Zone, ZoneBlock>| {
            (0..s.tx.txs.len())
                .filter(|&index| supply_moves(s, index).next().is_some())
                .map(Moves::Tx)
                .chain(s.traced().then_some(Moves::Frames))
                .collect::<Vec<_>>()
        },
        judge: |s, moves| {
            let Moves::Tx(index) = *moves else {
                return frames_authorized(s);
            };
            let logs = s.tx.logs_of(index, &s.logs);
            let mut outcomes: Vec<(Address, U256)> = logs
                .iter()
                .filter(|log| log.address == ZONE_INBOX_ADDRESS)
                .filter_map(|log| inbox_mint(&log.data))
                .collect();
            let mut wrong = Vec::new();
            for (token, t) in supply_moves(s, index) {
                if t.from.is_zero() {
                    match outcomes.iter().position(|o| *o == (token, t.amount)) {
                        Some(found) => {
                            outcomes.swap_remove(found);
                        }
                        None => wrong.push(format!("mint of {} {token} to {} without an inbox outcome", t.amount, t.to)),
                    }
                } else if t.from != ZONE_OUTBOX_ADDRESS {
                    wrong.push(format!("burn of {} {token} from {}", t.amount, t.from));
                }
            }
            ensure!(wrong.is_empty(), "{}", wrong.join("; "))
        },
    },
    // Judged on blocks that move the finalized Tempo block. Each imported header must continue
    // the previous header by parent hash and number, from the block finalized before to the one
    // finalized after. One `TempoBlockFinalized` reports a whole call's headers by its last, so
    // each must move past the previous one and, when the headers were decoded, land on one of
    // them.
    check! {
        id: TEMPO_HEADER_CONTINUITY,
        doc: "`TempoState.finalizeTempo` only accepts headers whose parent hash and block number continue from the previous finalized Tempo header.",
        severity: Severity::Critical,
        over: |s: &Step<Zone, ZoneBlock>| [&s.tx],
        judge: |s, b| {
            let (pre, post) = (s.pre.tempo?, s.post.tempo?);
            let finalized = s.events::<TempoState::TempoBlockFinalized>(TEMPO_STATE_ADDRESS);
            if pre == post && finalized.is_empty() {
                return None;
            }
            let mut number = pre.number;
            for e in &finalized {
                let landed = b.imported.is_empty()
                    || b.imported
                        .iter()
                        .any(|h| h.number == e.blockNumber && h.hash == e.blockHash);
                if e.blockNumber <= number || !landed {
                    return Some(Verdict::Broken(format!(
                        "finalized Tempo block {} ({}) after {number}",
                        e.blockNumber, e.blockHash
                    )));
                }
                number = e.blockNumber;
            }
            let mut parent = pre;
            for header in &b.imported {
                if header.parent_hash != parent.hash || parent.number.checked_add(1) != Some(header.number) {
                    return Some(Verdict::Broken(format!(
                        "imported header {} (parent {}) after Tempo block {} ({})",
                        header.number, header.parent_hash, parent.number, parent.hash
                    )));
                }
                parent = super::TempoBlock { number: header.number, hash: header.hash };
            }
            let last = finalized.last().map(|e| (e.blockNumber, e.blockHash));
            ensure!(
                last == Some((post.number, post.hash))
                    && (b.imported.is_empty() || parent == post),
                "TempoState moved from {} ({}) to {} ({}); last finalized {last:?}, last imported {} ({})",
                pre.number,
                pre.hash,
                post.number,
                post.hash,
                parent.number,
                parent.hash
            )
        },
    },
    // The zone half: `processedDepositNumber` never falls and moves by exactly the deposits the
    // block's `TempoAdvanced` events report, ending at the last one's cursor.
    check! {
        id: DEPOSIT_NUMBER_MONOTONIC,
        doc: "`depositCount` and `processedDepositNumber` are monotonic and match the number of queue entries enqueued or proven processed.",
        severity: Severity::Medium,
        over: |s: &Step<Zone, ZoneBlock>| [&s.tx],
        judge: |s, _| {
            let (pre, post) = (s.pre.inbox?, s.post.inbox?);
            let advanced = tempo_advanced(&s.logs);
            let reported = advanced
                .iter()
                .try_fold(U256::ZERO, |sum, a| sum.checked_add(a.deposits));
            let moved = post.processed_deposit_number.checked_sub(pre.processed_deposit_number);
            let cursor = advanced.last().map(|a| a.last_number);
            ensure!(
                moved.is_some()
                    && reported == moved.map(U256::from)
                    && cursor.is_none_or(|c| c == post.processed_deposit_number),
                "processedDepositNumber {} -> {}; TempoAdvanced reports {reported:?} deposits, cursor {cursor:?}",
                pre.processed_deposit_number,
                post.processed_deposit_number
            )
        },
    },
    // The zone half: the processed queue hash moves exactly when the processed number does, to
    // the hash the last `TempoAdvanced` reports.
    check! {
        id: DEPOSIT_PROCESSED_PREFIX,
        doc: DEPOSIT_PROCESSED_PREFIX_DOC,
        severity: Severity::Critical,
        over: |s: &Step<Zone, ZoneBlock>| [&s.tx],
        judge: |s, _| {
            let (pre, post) = (s.pre.inbox?, s.post.inbox?);
            let number_moved = pre.processed_deposit_number != post.processed_deposit_number;
            let hash_moved = pre.processed_deposit_queue_hash != post.processed_deposit_queue_hash;
            let reported = tempo_advanced(&s.logs).last().map(|a| a.queue_hash);
            ensure!(
                number_moved == hash_moved
                    && (!number_moved || reported == Some(post.processed_deposit_queue_hash)),
                "processed deposits {} ({}) -> {} ({}); TempoAdvanced reports {reported:?}",
                pre.processed_deposit_number,
                pre.processed_deposit_queue_hash,
                post.processed_deposit_number,
                post.processed_deposit_queue_hash
            )
        },
    },
    // The zone half: `lastBatch.withdrawalBatchIndex` moves by one per `BatchFinalized`, each
    // naming the next index, and `lastBatch` ends at the last one's hash.
    check! {
        id: WITHDRAWAL_BATCH_INDEX,
        doc: "`finalizeWithdrawalBatch` advances `withdrawalBatchIndex` exactly once per submitted batch, including zero-withdrawal batches.",
        severity: Severity::Critical,
        over: |s: &Step<Zone, ZoneBlock>| [&s.tx],
        judge: |s, _| {
            let (pre, post) = (s.pre.outbox.as_ref()?, s.post.outbox.as_ref()?);
            let finalized = s.events::<IZoneOutbox::BatchFinalized>(ZONE_OUTBOX_ADDRESS);
            let consecutive = finalized
                .iter()
                .enumerate()
                .all(|(i, e)| u64::try_from(i + 1).ok().and_then(|i| pre.withdrawalBatchIndex.checked_add(i)) == Some(e.withdrawalBatchIndex));
            let end = finalized
                .last()
                .map_or((pre.withdrawalBatchIndex, pre.withdrawalQueueHash), |e| {
                    (e.withdrawalBatchIndex, e.withdrawalQueueHash)
                });
            ensure!(
                consecutive && end == (post.withdrawalBatchIndex, post.withdrawalQueueHash),
                "lastBatch {} ({}) -> {} ({}) with {} BatchFinalized: {:?}",
                pre.withdrawalBatchIndex,
                pre.withdrawalQueueHash,
                post.withdrawalBatchIndex,
                post.withdrawalQueueHash,
                finalized.len(),
                finalized.iter().map(|e| e.withdrawalBatchIndex).collect::<Vec<_>>()
            )
        },
    },
];

/// A zone state beside the bridge events folded over every block observed before it.
pub const HISTORY_CHECKS: &[Check<Folded<Bridged, Zone>>] = &[
    // Accepted deposits mint on processing (`DepositProcessed`); withdrawal bounce-backs mint on
    // processing or on a refund claim; requested withdrawals burn amount and fee; a deposit
    // bounce-back burns nothing, its deposit never having minted. The history starts at the
    // first block the runner observed, from the supply then.
    check! {
        id: SUPPLY_SOLVENCY,
        doc: "For each token, zone-side total supply equals accepted deposits plus withdrawal bounce-backs minus requested withdrawals minus deposit bounce-backs.",
        severity: Severity::Critical,
        over: |f: &Folded<Bridged, Zone>| f.now.supplies.keys(),
        judge: |f, token| {
            let expected = *f.history.expected.get(*token)?;
            let supply = f.now.supplies.get(*token)?;
            ensure!(
                expected == Some(*supply),
                "totalSupply {supply}, bridge events account for {}",
                expected.map_or_else(|| "a sum outside U256".to_string(), |e| e.to_string())
            )
        },
    },
];

/// Account-scoped getters asked as a third party.
pub const PRIVACY_CHECKS: &[Check<Privacy>] = &[
    check! {
        id: BALANCE_ALLOWANCE_PRIVACY,
        doc: "`balanceOf(account)` reveals values only to `account`; `allowance(owner, spender)` reveals values only to `owner` or `spender`.",
        severity: Severity::High,
        over: |p: &Privacy| p.reads.iter().filter(|r| matches!(r.getter, Getter::Balance { .. } | Getter::Allowance { .. })),
        judge: |p, read| private(p, read),
    },
    check! {
        id: REFUND_READ_PRIVACY,
        doc: "`ZoneInbox.refunds(token, owner)` reveals a value only when its immediate caller is `owner` or an active sequencer.",
        severity: Severity::High,
        over: |p: &Privacy| p.reads.iter().filter(|r| matches!(r.getter, Getter::Refund { .. })),
        judge: |p, read| private(p, read),
    },
    check! {
        id: ACCOUNT_GETTER_PRIVACY,
        doc: "Account-indexed `NonceManager` and `AccountKeychain` getters reveal values only when their immediate caller owns the queried account.",
        severity: Severity::High,
        over: |p: &Privacy| p.reads.iter().filter(|r| matches!(r.getter, Getter::Nonce { .. } | Getter::Key { .. })),
        judge: |p, read| private(p, read),
    },
];

/// A zone block that imports Tempo, paired with the portal at the Tempo block it imported.
pub const ANCHOR_CHECKS: &[Check<Anchored>] = &[
    check! {
        id: TOKEN_ENABLEMENT_BINDING,
        doc: "Every non-genesis `advanceTempo` hashes the exact ordered token-address and metadata delta from `ZoneInbox.processedTokenEnablementHash`, requires equality with `ZonePortal.tokenEnablementHash` at the final imported Tempo state, and initializes all entries before processing deposits.",
        severity: Severity::Critical,
        when: |p: &Anchored| p.left.tx.imports_tempo(),
        over: |p: &Anchored| [&p.right],
        judge: |p, _| {
            let zone = p.left.post.inbox?.processed_token_enablement_hash?;
            let portal = p.right.token_enablement_hash?;
            ensure!(zone == portal, "processedTokenEnablementHash {zone}, portal tokenEnablementHash {portal}")
        },
    },
    // The cross-domain half: the processed cursor never passes the portal's queue, and once it
    // reaches the queue's end it has the same hash chain.
    check! {
        id: DEPOSIT_PROCESSED_PREFIX,
        doc: DEPOSIT_PROCESSED_PREFIX_DOC,
        severity: Severity::Critical,
        when: |p: &Anchored| p.left.tx.imports_tempo(),
        over: |p: &Anchored| [&p.right],
        judge: |p, _| {
            let inbox = p.left.post.inbox?;
            let count = p.right.deposit_count?;
            let head = p.right.current_deposit_queue_hash?;
            let processed = inbox.processed_deposit_number;
            ensure!(
                processed < count || (processed == count && inbox.processed_deposit_queue_hash == head),
                "processed {processed} ({}) of {count} deposits (queue head {head})",
                inbox.processed_deposit_queue_hash
            )
        },
    },
];

/// A batch the portal accepted, paired with the zone block it proves.
pub const BATCH_CHECKS: &[Check<Proven>] = &[check! {
    id: BATCH_WITHDRAWAL_COMMITMENT,
    doc: "Submitted `withdrawalQueueHash` equals `ZoneOutbox.lastBatch.withdrawalQueueHash` from the proven post-state.",
    severity: Severity::Critical,
    over: |p: &Proven| [&p.right],
    judge: |p, submitted| {
        let batch = p.left.outbox.as_ref()?;
        ensure!(
            batch.withdrawalQueueHash == submitted.withdrawal_queue_hash,
            "submitted {}, lastBatch {} (index {})",
            submitted.withdrawal_queue_hash,
            batch.withdrawalQueueHash,
            batch.withdrawalBatchIndex
        )
    },
}];

/// Where a block's supply moves are judged.
#[derive(Debug, Clone, Copy)]
enum Moves {
    /// The mints and burns in the logs of the transaction at this position.
    Tx(usize),
    /// Every traced mint and burn call frame.
    Frames,
}

impl fmt::Display for Moves {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tx(index) => write!(f, "tx {index}"),
            Self::Frames => f.write_str("call frames"),
        }
    }
}

/// Every successful mint frame on an observed token is called by the inbox, and every burn
/// frame by the outbox.
fn frames_authorized(s: &Step<Zone, ZoneBlock>) -> Option<Verdict> {
    let mints = [
        ITIP20::mintCall::SELECTOR,
        ITIP20::mintWithMemoCall::SELECTOR,
    ];
    let burns = [
        ITIP20::burnCall::SELECTOR,
        ITIP20::burnWithMemoCall::SELECTOR,
        ITIP20::burnBlockedCall::SELECTOR,
    ];
    let wrong: Vec<String> = s
        .post
        .supplies
        .keys()
        .flat_map(|&token| s.calls_to(token).map(move |frame| (token, frame)))
        .filter(|(_, frame)| frame.success)
        .filter_map(|(token, frame)| {
            let selector = frame.selector()?;
            let allowed = if mints.contains(&selector) {
                ZONE_INBOX_ADDRESS
            } else if burns.contains(&selector) {
                ZONE_OUTBOX_ADDRESS
            } else {
                return None;
            };
            (frame.caller != allowed).then(|| {
                format!(
                    "{} on {token} called by {}",
                    frame
                        .input
                        .get(..4)
                        .map(alloy_primitives::hex::encode)
                        .unwrap_or_default(),
                    frame.caller
                )
            })
        })
        .collect();
    ensure!(wrong.is_empty(), "{}", wrong.join("; "))
}

/// One `TempoAdvanced` event, of either version.
struct Advanced {
    deposits: U256,
    queue_hash: B256,
    last_number: u64,
}

/// The inbox's `TempoAdvanced` events in `logs`, in order.
fn tempo_advanced(logs: &[Log]) -> Vec<Advanced> {
    logs.iter()
        .filter(|log| log.address == ZONE_INBOX_ADDRESS)
        .filter_map(|log| {
            if let Ok(e) = IZoneInbox::TempoAdvanced_1::decode_log_data(&log.data) {
                return Some(Advanced {
                    deposits: e.depositsProcessed,
                    queue_hash: e.newProcessedDepositQueueHash,
                    last_number: e.lastProcessedDepositNumber,
                });
            }
            let e = IZoneInbox::TempoAdvanced_0::decode_log_data(&log.data).ok()?;
            Some(Advanced {
                deposits: e.depositsProcessed,
                queue_hash: e.newProcessedDepositQueueHash,
                last_number: e.lastProcessedDepositNumber,
            })
        })
        .collect()
}

/// The mints (from the zero address) and burns (to it) of observed zone tokens in transaction
/// `index`.
fn supply_moves(
    s: &Step<Zone, ZoneBlock>,
    index: usize,
) -> impl Iterator<Item = (Address, ITIP20::Transfer)> + '_ {
    s.tx.logs_of(index, &s.logs)
        .iter()
        .filter(|log| s.post.supplies.contains_key(&log.address))
        .filter_map(|log| Some((log.address, crate::tip20::transfer(&log.data)?)))
        .filter(|(_, t)| t.from.is_zero() || t.to.is_zero())
}

/// A third party's read reveals nothing when it reverts, returns zero, or returns other than
/// what the owner reads.
fn private(p: &Privacy, read: &PrivateRead) -> Option<Verdict> {
    let asked = read.asked.as_ref()?;
    let Outcome::Return(value) = asked else {
        return Some(Verdict::Holds);
    };
    let revealed = value.iter().any(|&byte| byte != 0)
        && read.owned.as_ref() == Some(&Outcome::Return(value.clone()));
    ensure!(
        !revealed,
        "{} read {value} as {}, the value {} reads",
        p.asker,
        read.to,
        read.owner
    )
}
