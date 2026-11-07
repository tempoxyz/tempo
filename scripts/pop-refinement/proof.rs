use vstd::prelude::*;

verus! {
// Boundary: the creation-mode match only, after successful state decoding. Neither
// preceding clear handling nor the following persistent sstore is in this model.
// Backend calls are abstract: charge may fail even with sufficient gas, and tstore
// may return any backend error. Failed charges preserve gas in this abstract
// contract; backend internals are not verified. Trace records attempted calls,
// including failures.
const MAX: u64 = u64::MAX;
const COST: u64 = 245000;

#[derive(PartialEq, Eq)]
enum Mode { Direct, Preserve, Refund }
#[derive(PartialEq, Eq)]
enum Error { None, Gas, Store, Arithmetic }
#[derive(PartialEq, Eq)]
enum Event { Charge(nat), Store(nat, nat) }

// A deeply embedded, fixed-shape instruction language for this policy. Each field
// selects an operator, instruction, or instruction order; it is not a source hash.
#[derive(PartialEq, Eq)]
struct Program {
    credit_positive: bool,
    budget_positive: bool,
    decrement_credit: bool,
    finite_only: bool,
    charge_amount: u64,
    refund_charge_first: bool,
    saturating_refund: bool,
    store_finite: bool,
    store_refund: bool,
    checked_credit: bool,
}
struct Input {
    mode: Mode,
    credit: nat,
    budget: nat,
    pending: nat,
    gas: nat,
    changed: bool,
    charge_fails: bool,
    store_fails: bool,
    payload: Seq<u8>,
}
struct Output {
    credit: nat,
    budget: nat,
    pending: nat,
    gas: nat,
    changed: bool,
    error: Error,
    trace: Seq<Event>,
}

spec fn valid(i: Input) -> bool {
    i.credit <= MAX && i.budget <= MAX && i.pending <= MAX && i.gas <= MAX
}
spec fn initial(i: Input) -> Output {
    Output { credit: i.credit, budget: i.budget, pending: i.pending,
        gas: i.gas, changed: i.changed, error: Error::None, trace: seq![] }
}
spec fn charge(o: Output, amount: nat, fails: bool) -> Output {
    if o.error != Error::None { o } else {
        Output { gas: if o.gas < amount || fails { o.gas } else { (o.gas - amount) as nat },
            error: if o.gas < amount || fails { Error::Gas } else { Error::None },
            trace: o.trace.push(Event::Charge(amount)), ..o }
    }
}
spec fn store(o: Output, fails: bool) -> Output {
    if o.error != Error::None { o } else {
        Output { error: if fails { Error::Store } else { Error::None },
            trace: o.trace.push(Event::Store(o.budget, o.pending)), ..o }
    }
}
spec fn increment(o: Output, saturating: bool) -> Output {
    if o.error != Error::None { o }
    else if o.pending == MAX {
        if saturating { o } else { Output { error: Error::Arithmetic, ..o } }
    } else { Output { pending: o.pending + 1, ..o } }
}

spec fn production_program() -> Program {
    Program { credit_positive: true, budget_positive: true, decrement_credit: true,
        finite_only: true, charge_amount: COST, refund_charge_first: true,
        saturating_refund: true, store_finite: true, store_refund: true,
        checked_credit: false }
}

spec fn interpret(p: Program, i: Input) -> Output {
    let o = initial(i);
    if i.mode == Mode::Direct
        && (if p.credit_positive { i.credit > 0 } else { i.credit >= 0 })
        && (if p.budget_positive { i.budget > 0 } else { i.budget >= 0 }) {
        let o = if p.decrement_credit {
            if i.credit == 0 {
                if p.checked_credit { o } else { Output { error: Error::Arithmetic, ..o } }
            } else { Output { credit: (i.credit - 1) as nat, changed: true, ..o } }
        } else { o };
        if o.error != Error::None { o }
        else if !p.finite_only || i.budget != MAX {
            if i.budget == 0 { Output { error: Error::Arithmetic, ..o } }
            else {
                let o = Output { budget: (i.budget - 1) as nat, ..o };
                if p.store_finite { store(o, i.store_fails) } else { o }
            }
        } else { o }
    } else if i.mode == Mode::Refund {
        if p.refund_charge_first {
            let o = increment(charge(o, p.charge_amount as nat, i.charge_fails), p.saturating_refund);
            if p.store_refund { store(o, i.store_fails) } else { o }
        } else {
            let o = increment(o, p.saturating_refund);
            let o = if p.store_refund { store(o, i.store_fails) } else { o };
            charge(o, p.charge_amount as nat, i.charge_fails)
        }
    } else { charge(o, p.charge_amount as nat, i.charge_fails) }
}

// Independent policy relation: direct use burns exactly one credit; finite
// budgets alone are written. Refund mode pays before any pending mutation.
spec fn policy(i: Input) -> Output {
    if i.mode == Mode::Direct && i.credit > 0 && i.budget > 0 {
        let o = Output { credit: (i.credit - 1) as nat, changed: true, ..initial(i) };
        if i.budget == MAX { o }
        else { store(Output { budget: (i.budget - 1) as nat, ..o }, i.store_fails) }
    } else {
        let o = charge(initial(i), COST as nat, i.charge_fails);
        if i.mode == Mode::Refund && o.error == Error::None {
            store(Output { pending: if i.pending == MAX { i.pending } else { i.pending + 1 }, ..o }, i.store_fails)
        } else { o }
    }
}
spec fn resources(i: Input, o: Output) -> bool {
    o.gas <= i.gas && o.credit <= i.credit && o.budget <= i.budget
        && o.pending <= MAX && o.trace.len() <= 2
}
spec fn p0(p: Program) -> bool {
    forall|i: Input| #![auto] valid(i) ==> interpret(p, i) == policy(i) && resources(i, interpret(p, i))
}
// P1 restricts instruction structure but admits a checked decrement, equivalent
// under the positive guard. P2 then selects the exact source program.
spec fn p1(p: Program) -> bool {
    p.credit_positive && p.budget_positive && p.decrement_credit && p.finite_only
        && p.charge_amount == COST && p.refund_charge_first && p.saturating_refund
        && p.store_finite && p.store_refund
}
spec fn p2(p: Program) -> bool { p == production_program() }

proof fn policy_resources(i: Input)
    requires valid(i)
    ensures resources(i, policy(i))
{
    reveal(policy); reveal(resources); reveal(initial); reveal(store); reveal(charge);
}
proof fn structural_correct(p: Program, i: Input)
    requires p1(p), valid(i)
    ensures interpret(p, i) == policy(i)
{
    reveal(p1); reveal(interpret); reveal(policy); reveal(initial);
    reveal(charge); reveal(store); reveal(increment);
}
proof fn refinement_steps()
    ensures
        forall|p: Program| p1(p) ==> p0(p),
        forall|p: Program| p2(p) ==> p1(p),
{
    assert forall|p: Program| p1(p) implies p0(p) by {
        assert forall|i: Input| #![auto] valid(i) implies
            interpret(p, i) == policy(i) && resources(i, interpret(p, i)) by {
            structural_correct(p, i);
            policy_resources(i);
        }
    }
}
proof fn witness_satisfiable()
    ensures p0(production_program()), p1(production_program()), p2(production_program())
{
    refinement_steps();
}
// Concrete counterexamples establish that instruction choices are semantic, not
// decorative fields. They use valid states and the same interpreter as P0.
spec fn example(mode: Mode, credit: nat, budget: nat, pending: nat, gas: nat) -> Input {
    Input { mode, credit, budget, pending, gas, changed: false,
        charge_fails: false, store_fails: false, payload: seq![] }
}
proof fn reject_nonpositive_credit_guard()
    ensures !p0(Program { credit_positive: false, ..production_program() })
{
    let p = Program { credit_positive: false, ..production_program() };
    let i = example(Mode::Direct, 0, 1, 0, COST as nat);
    assert(valid(i));
    assert(interpret(p, i) != policy(i));
}
proof fn reject_nonpositive_budget_guard()
    ensures !p0(Program { budget_positive: false, ..production_program() })
{
    let p = Program { budget_positive: false, ..production_program() };
    let i = example(Mode::Direct, 1, 0, 0, COST as nat);
    assert(valid(i));
    assert(interpret(p, i) != policy(i));
}
proof fn reject_unlimited_decrement()
    ensures !p0(Program { finite_only: false, ..production_program() })
{
    let p = Program { finite_only: false, ..production_program() };
    let i = example(Mode::Direct, 1, MAX as nat, 0, 0);
    assert(valid(i));
    assert(interpret(p, i) != policy(i));
}
proof fn reject_charge_after_refund_write()
    ensures !p0(Program { refund_charge_first: false, ..production_program() })
{
    let p = Program { refund_charge_first: false, ..production_program() };
    let i = example(Mode::Refund, 0, 0, 0, 0);
    assert(valid(i));
    assert(interpret(p, i) != policy(i));
}
proof fn reject_nonsaturating_refund()
    ensures !p0(Program { saturating_refund: false, ..production_program() })
{
    let p = Program { saturating_refund: false, ..production_program() };
    let i = example(Mode::Refund, 0, 0, MAX as nat, COST as nat);
    assert(valid(i));
    assert(interpret(p, i) != policy(i));
}
// The selected block never reads the newly created slot's payload. This says
// nothing about owner/slot selection outside the block or protocol security.
proof fn payload_noninterference(p: Program, i: Input, payload: Seq<u8>)
    ensures interpret(p, i) == interpret(p, Input { payload, ..i })
{}
}
fn main() {}
