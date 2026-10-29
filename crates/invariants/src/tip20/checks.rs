//! The TIP-20 invariants.

use std::fmt;

use alloy_primitives::{Address, U256};
use invariants_core::{check, ensure};

use super::{ITIP20, Ledger, Transfer, transfer};
use crate::{Check, Checked, Replay, Severity, Step, StepChecked, Tx, Verdict, kept, or_text};

/// A TIP-20's views answer. Counted by runners that read the model, not judged by a check here.
pub const VIEW: &str = "TEMPO-TIP20-VIEW";
pub const SUPPLY_CAP: &str = "TEMPO-TIP20-SUPPLY-CAP";
pub const BALANCE_SUM: &str = "TEMPO-TIP20-BALANCE-SUM";
pub const TRANSFER_EVENTS: &str = "TEMPO-TIP20-TRANSFER-EVENTS";
pub const TRANSFER_CALL: &str = "TEMPO-TIP20-TRANSFER-CALL";

/// A token's supply and the balances read of it.
pub const CHECKS: &[Check<Ledger>] = &[
    // A zero cap is not exempt: minting checks the cap with no exception, and `setSupplyCap`
    // rejects a cap below the supply.
    check! {
        id: SUPPLY_CAP,
        doc: "A TIP-20 token's total supply never exceeds its supply cap.",
        tip: "TIP-20",
        severity: Severity::Critical,
        judge: |l: &Ledger| {
            let cap = l.supply_cap?;
            ensure!(l.supply <= cap, "totalSupply {} exceeds supplyCap {cap}", l.supply)
        },
    },
    // The balances read may be any subset of the holders, so their sum is a lower bound.
    check! {
        id: BALANCE_SUM,
        doc: "The balances of any set of a TIP-20 token's holders sum to at most its total supply.",
        tip: "TIP-20",
        severity: Severity::Critical,
        judge: |l: &Ledger| {
            let sum = l.balance_sum();
            ensure!(
                sum.is_some_and(|sum| sum <= l.supply),
                "balances sum to {}, totalSupply {}: {:?}",
                or_text(sum, "more than 2^256"),
                l.supply,
                l.balances
            )
        },
    },
];

/// A step's effect on one token, its ledgers read over the same accounts before and after it.
pub const STEP_CHECKS: &[Check<Step<Ledger, Option<Tx>>>] = &[
    // Each observed balance moves by exactly the step's `Transfer` events into and out of it,
    // never going negative, and the supply by the mints (from the zero address) and burns (to
    // it). A transfer between an observed and an unobserved account moves only the observed side.
    check! {
        id: TRANSFER_EVENTS,
        doc: "A step moves each TIP-20 balance by exactly its `Transfer` events into and out of it, and the total supply by its mints from and burns to the zero address.",
        tip: "TIP-20",
        severity: Severity::Medium,
        over: |step: &Step<Ledger, Option<Tx>>| [&step.post],
        judge: |s, _| {
            let transfers: Vec<Transfer> = s
                .logs_from(s.post.token)
                .filter_map(|log| transfer(&log.data))
                .collect();
            let (pre, post) = s.pre.common(&s.post);
            let detail = match pre.replay(&transfers) {
                // `Transfer` events say nothing of the cap.
                Ok(want) if want.balances == post.balances && want.supply == post.supply => {
                    return Some(Verdict::Holds);
                }
                Ok(want) => format!("expected -> read: {}", want.diff(&post)),
                Err(e) => format!("on the earlier balances: {e}"),
            };
            Some(Verdict::Broken(format!("{} transfers; {detail}", transfers.len())))
        },
    },
    // Each call that moves the token (`transfer`, `transferWithMemo`, `transferFrom`,
    // `transferFromWithMemo`) that the step kept (it returned, as did every frame it was called from
    // and the transaction) emitted a `Transfer` from the account it debits for its amount. Every
    // such call counts, so another call's event cannot stand in for a missing one. The
    // recipient is not compared: a virtual address (TIP-1022) forwards to its master, and a receive
    // policy (TIP-1028) redirects a blocked transfer to the guard.
    check! {
        id: TRANSFER_CALL,
        doc: "Each `transfer`, `transferWithMemo`, `transferFrom` or `transferFromWithMemo` call to a TIP-20 token that returns emits its own `Transfer` event from the account it debits for the amount it names.",
        tip: "TIP-20",
        severity: Severity::Medium,
        over: |step: &Step<Ledger, Option<Tx>>| transfer_calls(step),
        judge: |s, call| {
            let calls = transfer_calls(s)
                .into_iter()
                .filter(|other| other.from == call.from && other.amount == call.amount)
                .count();
            let events = s
                .logs_from(s.post.token)
                .filter_map(|log| transfer(&log.data))
                .filter(|event| event.from == call.from && event.amount == call.amount)
                .count();
            ensure!(
                events >= calls,
                "{calls} such calls returned, {events} matching Transfer events"
            )
        },
    },
];

/// A `transfer` call to a token, as its frame shows it.
struct TransferCall {
    from: Address,
    to: Address,
    amount: U256,
}

impl fmt::Display for Ledger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "token={}", self.token)
    }
}

impl fmt::Display for TransferCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "transfer of {} from {} to {}",
            self.amount, self.from, self.to
        )
    }
}

impl Checked for Ledger {
    const CHECKS: &'static [Check<Self>] = CHECKS;
}

impl StepChecked<Option<Tx>> for Ledger {
    const STEP_CHECKS: &'static [Check<Step<Self, Option<Tx>>>] = STEP_CHECKS;
}

/// The step's calls to its token that move a balance (`transfer`, `transferWithMemo`,
/// `transferFrom`, `transferFromWithMemo`) and whose logs it kept, each with the account it debits.
fn transfer_calls(step: &Step<Ledger, Option<Tx>>) -> Vec<TransferCall> {
    if !step.tx.is_some_and(|tx| tx.success) {
        return Vec::new();
    }
    let token = step.post.token;
    kept(&step.calls)
        .filter(|frame| frame.enters(token))
        .filter_map(|frame| {
            let (from, to, amount) = if let Some(c) = frame.decode::<ITIP20::transferCall>() {
                (frame.caller, c.to, c.amount)
            } else if let Some(c) = frame.decode::<ITIP20::transferWithMemoCall>() {
                (frame.caller, c.to, c.amount)
            } else if let Some(c) = frame.decode::<ITIP20::transferFromCall>() {
                (c.from, c.to, c.amount)
            } else {
                let c = frame.decode::<ITIP20::transferFromWithMemoCall>()?;
                (c.from, c.to, c.amount)
            };
            Some(TransferCall { from, to, amount })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use alloy_primitives::{Bytes, Log};
    use alloy_sol_types::{SolCall, SolEvent};
    use invariants_core::Report;

    use super::*;
    use crate::{CallKind, Frame};

    const TOKEN: Address = Address::repeat_byte(0x20);
    const SENDER: Address = Address::repeat_byte(0x01);
    const OUTER: Address = Address::repeat_byte(0x02);
    const INNER: Address = Address::repeat_byte(0x03);
    const TO: Address = Address::repeat_byte(0x04);
    const AMOUNT: u64 = 5;

    /// A frame at `depth` that `caller` entered in `target`, returning when `success`.
    fn frame(depth: usize, caller: Address, target: Address, success: bool) -> Frame {
        Frame {
            depth,
            kind: CallKind::Call,
            caller,
            target,
            input: Bytes::new(),
            value: U256::ZERO,
            success,
            output: Bytes::new(),
        }
    }

    /// A `transfer` of [`AMOUNT`] to [`TO`] that `caller` made to the token at `depth`.
    fn transfer_call(depth: usize, caller: Address, success: bool) -> Frame {
        let call = ITIP20::transferCall {
            to: TO,
            amount: U256::from(AMOUNT),
        };
        Frame {
            input: call.abi_encode().into(),
            ..frame(depth, caller, TOKEN, success)
        }
    }

    /// The token's `Transfer` of [`AMOUNT`] from `from` to [`TO`].
    fn transfer_event(from: Address) -> Log {
        let event = Transfer {
            from,
            to: TO,
            amount: U256::from(AMOUNT),
        };
        Log {
            address: TOKEN,
            data: event.encode_log_data(),
        }
    }

    /// How many transfer calls [`TRANSFER_CALL`] was armed for in a transaction that entered
    /// `calls` and logged `logs`, and its violations.
    fn check(calls: Vec<Frame>, logs: Vec<Log>, success: bool) -> (u64, Vec<String>) {
        let ledger = Ledger {
            token: TOKEN,
            supply: U256::from(100),
            supply_cap: None,
            balances: BTreeMap::new(),
        };
        let step = Step {
            pre: ledger.clone(),
            post: ledger,
            changes: Vec::new(),
            logs,
            calls,
            tx: Some(Tx {
                sender: SENDER,
                success,
            }),
        };
        let mut report = Report::default();
        report.run(STEP_CHECKS, &step);
        let violations = report
            .violations
            .iter()
            .filter(|violation| violation.id == TRANSFER_CALL)
            .map(|violation| format!("{} {}", violation.subject, violation.detail))
            .collect();
        (report.counts[TRANSFER_CALL].armed, violations)
    }

    #[test]
    fn a_kept_transfer_call_needs_its_event() {
        let calls = || vec![transfer_call(0, SENDER, true)];
        assert_eq!(
            check(calls(), vec![transfer_event(SENDER)], true),
            (1, vec![])
        );
        let (armed, violations) = check(calls(), vec![], true);
        assert_eq!(armed, 1);
        assert_eq!(violations.len(), 1);
        assert!(
            violations[0].contains("1 such calls returned, 0 matching Transfer events"),
            "{violations:?}"
        );
        // The event names the transaction's sender, but the call came from a contract.
        let nested = vec![frame(0, SENDER, OUTER, true), transfer_call(1, OUTER, true)];
        assert_eq!(check(nested, vec![transfer_event(SENDER)], true).1.len(), 1);
    }

    #[test]
    fn a_transfer_call_that_was_undone_is_not_judged() {
        // The transaction reverted.
        assert_eq!(
            check(vec![transfer_call(0, SENDER, true)], vec![], false).0,
            0
        );
        // The transfer returned inside a frame that reverted.
        let undone = vec![
            frame(0, SENDER, OUTER, true),
            frame(1, OUTER, INNER, false),
            transfer_call(2, INNER, true),
        ];
        assert_eq!(check(undone, vec![], true).0, 0);
        // A sibling after the reverted frame is kept.
        let sibling = vec![
            frame(0, SENDER, OUTER, true),
            frame(1, OUTER, INNER, false),
            transfer_call(2, INNER, true),
            transfer_call(1, OUTER, true),
        ];
        assert_eq!(
            check(sibling, vec![transfer_event(OUTER)], true),
            (1, vec![])
        );
        // A runner that does not trace calls arms nothing.
        assert_eq!(check(vec![], vec![], true).0, 0);
    }
}

#[cfg(test)]
mod transfer_call_tests {
    use std::collections::BTreeMap;

    use alloy_primitives::{Bytes, Log, address};
    use alloy_sol_types::{SolCall, SolEvent};
    use invariants_core::{CallKind, Frame, Report};

    use super::*;

    const TOKEN: Address = address!("0x20c0000000000000000000000000000000000001");
    const CALLER: Address = address!("0x00000000000000000000000000000000000000c0");

    fn frame(input: Vec<u8>) -> Frame {
        Frame {
            depth: 1,
            kind: CallKind::Call,
            caller: CALLER,
            target: TOKEN,
            input: input.into(),
            value: U256::ZERO,
            success: true,
            output: Bytes::new(),
        }
    }

    fn step(calls: Vec<Frame>, transfers: &[(Address, U256)]) -> Step<Ledger, Option<Tx>> {
        let ledger = Ledger {
            token: TOKEN,
            supply: U256::from(100),
            supply_cap: None,
            balances: BTreeMap::new(),
        };
        let logs = transfers
            .iter()
            .map(|&(to, amount)| {
                let event = Transfer {
                    from: CALLER,
                    to,
                    amount,
                };
                Log {
                    address: TOKEN,
                    data: event.encode_log_data(),
                }
            })
            .collect();
        Step {
            pre: ledger.clone(),
            post: ledger,
            changes: vec![],
            logs,
            calls,
            tx: Some(Tx {
                sender: CALLER,
                success: true,
            }),
        }
    }

    fn fired(step: &Step<Ledger, Option<Tx>>) -> u64 {
        let mut report = Report::default();
        report.run(STEP_CHECKS, step);
        report.counts[TRANSFER_CALL].fired
    }

    /// A memo transfer's event cannot stand in for a plain transfer that emitted none.
    #[test]
    fn every_transfer_call_needs_its_own_event() {
        let five = U256::from(5);
        let (b, c) = (Address::with_last_byte(0xb), Address::with_last_byte(0xc));
        let memo = ITIP20::transferWithMemoCall {
            to: c,
            amount: five,
            memo: Default::default(),
        };
        let plain = ITIP20::transferCall {
            to: b,
            amount: five,
        };
        let calls = vec![frame(memo.abi_encode()), frame(plain.abi_encode())];
        assert_eq!(fired(&step(calls.clone(), &[(c, five), (b, five)])), 0);
        assert!(fired(&step(calls, &[(c, five)])) > 0);
    }
}
