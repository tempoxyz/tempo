# Storage-credit pop-refinement prototype

This standalone experiment applies [Coglio's pop-refinement](https://www.isa-afp.org/entries/Pop_Refinement.html)
to the storage-creation `match transient_state.mode` in
`crates/precompiles/src/storage_credits/accounting.rs`. It does not change production code. Pop-refinement narrows predicates over
programs, proving each new predicate implies the previous one, until exactly one
implementation remains. Tempo is a Rust blockchain node; this targets one policy
inside its execution layer. The frontend below is the Rust source-reading tool
in `frontend/`; Verus is the proof checker, and Charon extracts compiler instructions.

The policy chooses how to pay for a newly occupied storage slot (a key/value
entry belonging to an account). `Direct` mode can spend one per-account stored credit (a token covering one creation charge) instead
of gas, but only when both the credit balance and transaction spending budget (the permitted number of credits to spend) are
positive. A budget of `u64::MAX` means unlimited. `Preserve` mode pays gas without
spending credits. `Refund` mode pays gas first, then increments a count of creations
eligible for later refunds at transaction settlement, which is outside this proof. Gas is the protocol's execution charge, not wall-clock
time. A backend provides gas charging and transient, transaction-local writes.

It proves properties of a small, explicitly represented program, not of the entire
Rust language or Tempo node. The represented instructions select the spending
guards, credit decrement, finite-budget handling, gas charge, refund arithmetic,
write operations and their order.

## Run

Linux x86_64 requires Rust/rustup, git, curl, unzip, jq and a C linker.
Install the pinned tools outside the repository:

```sh
scripts/pop-refinement/setup.sh /tmp/tempo-pop-tools
source /tmp/tempo-pop-tools/env.sh
scripts/pop-refinement/run.sh /tmp/tempo-pop-results
```

The results directory must be empty. The runner preserves generated Rust,
compiler-extracted intermediate representation, tool versions and proof logs there.
The frontend is an isolated Cargo workspace; building the node is unnecessary.

Verus is pinned to `0.2026.11.02.8bf68ee` with a checked archive SHA-256 and Rust
1.99.1, also used to build the frontend. Charon is built from `c04983bc802b402d9f81407317a8fba8e15044d8`
(`0.1.314`) with `nightly-2026-09-17`. These are installed sequentially to avoid
concurrent rustup updates. Verus uses its bundled Z3 solver; this is not an entirely
Rust-only trusted stack.

## What is checked

The Rust frontend parses the actual source block, resolves `STORAGE_CREDIT_VALUE`
from `crates/hardfork/src/constants.rs` (currently 245,000 gas), and rejects unsupported syntax or instruction ordering.
It emits a program representation and a standalone Rust fixture containing the
extracted match. Charon translates that fixture to its compiler-derived LLBC
intermediate representation, a structured form of Rust compiler instructions.
The fixture wraps the extracted match in a function named `creation`. The runner requires an error-free extraction with
a nonempty `creation` body; it also tests rejection of broken extraction artifacts.
**The LLBC artifact is not the input to the proof:** the trusted source frontend
emits the Verus representation separately.

`proof.rs` defines an interpreter for the represented spending, charging and
writing instructions. Its state contains the credit balance, spending budget,
pending-refund count, gas balance, a flag indicating whether the credit balance
changed, booleans indicating gas-charge/write failure, and an arbitrary payload.
Three predicates constrain programs of this same type:

- `p0`: all valid unsigned-64-bit input states obey the mode-based policy above and
  resource bounds: gas, credit and budget never increase, pending refunds stay
  bounded, and at most two backend calls are attempted.
- `p1`: require positive credit/budget guards, a one-credit decrement,
  finite-only budget writes, and charge-before-increment/write refund handling.
  A checked or ordinary credit
  decrement is permitted because the positive-credit guard makes them equivalent.
- `p2`: equality to exactly one explicit program.

Verus proves `p2 => p1 => p0`. The explicit program selected by `p2` is also a
witness satisfying all three, so the predicates are not vacuous. The generated
source candidate must equal that program and satisfy these predicates. The trace records attempted gas
charges and transient writes, including failures. Refund charging precedes any
pending-refund update or write; unlimited budgets are not decremented.

The runner also requires five invalid program variants to fail their semantic
proof obligations: a nonpositive credit guard, a nonpositive budget guard, decrementing unlimited
budgets, charging after refund writes, and nonsaturating refund overflow.
Frontend tests reject source mutations and compare the extracted Rust block with
the lowered interpreter on 432 boundary cases: three modes, three credit values,
three budgets, four pending-refund counts and four gas balances. Values include
zero, one, saturation boundaries, the unlimited-budget sentinel, and gas just
below or exactly at the charge. These finite bridge tests are
separate from Verus's universally quantified proof.

## Proof boundary

The source parser, its lowering, the fixture wrappers, Rust compiler, Verus and
solver are trusted, not verified here. Charon extraction only confirms the generated fixture is accepted and has a translated body,
not a proof that LLBC and the interpreter agree. Backend calls use an abstract
contract: a gas charge either fails without consuming gas or deducts the specified
amount; a transient write records an attempted budget/refund-state write and may
fail. Backend failures stop subsequent modeled instructions; actual gas-tracker
and storage implementations are outside the proof.

The enclosing hook also loads/decodes state, may mint credits when slots are
deleted, selects an account and slot, and later persists changed credit balances.
All of those operations, transaction rollback and protocol-version activation
are excluded.
The model also has an arbitrary byte-sequence payload representing the new slot's
stored value. An auxiliary two-execution theorem shows that changing only this
payload leaves the interpreter's result and attempted-call trace unchanged; it is not a protocol confidentiality claim. No runtime, wall-clock or
cryptographic security bound follows from the backend-call bound. This prototype
is source-linked verification with a tested bridge, not an end-to-end theorem
about the production binary.
