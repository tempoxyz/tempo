# tempo-invariants

Shared invariant library: a self-registering catalog of protocol checks that any
process can run over chain state — a live monitor, a periodic audit cron, a
fuzzer asserting invariants between mutations, or a test. A check is a pure
function over a snapshot that was read up front; storage layout and typed
accessors come from `tempo-precompiles` (no parallel slot/type definitions).
Adding a check is a single `invariant!` block — it self-registers, so no central
dispatch table, registry, or enum changes.

Consumers differ only in which `PrecompileStorageProvider` they hand to `run`
and which entities they pass: a monitor reads the touched entities each block, an
audit cron enumerates all of them, a fuzzer points at its in-memory state after
each step. The checks are identical.

## Authoring a check

Drop an `invariant!` block anywhere under `src/<scope>/`. The check is a pure
function of the scope's snapshot — no provider, no `Result`, no `?`:

```rust
invariant! {
    id: "TEMPO-TIP20-SUPPLY-CAP",
    severity: P1,
    description: "totalSupply must not exceed supplyCap when a cap is set",
    fn supply_cap(t: &Tip20Snapshot, out: &mut Report<'_>) {
        if !t.supply_cap.is_zero() && t.total_supply > t.supply_cap {
            out.fail(format!("totalSupply ({}) > supplyCap ({})", t.total_supply, t.supply_cap));
        }
    }
}
```

Fields:

- `id` — stable identifier (used by the catalog, history, and alert routing).
- `severity` — `P0` (fund loss / insolvency), `P1` (core invariant broken),
  `P2` (config / hygiene).
- `since` — optional hardfork gate (see below); defaults to `Genesis`.
- `description` — one line; surfaced in the catalog and alerts.
- `fn` — the check. The snapshot type in its signature (here `Tip20Snapshot`)
  determines the scope; call `out.fail(detail)` per violation, tagged with the
  current id, scope, and entity automatically.

Group related checks in one file (e.g. both supply checks live in
`src/tip20/supply.rs`).

### Gating a check on a hardfork

Add `since:` to run a check only from a given fork onward — useful for shipping
T-N invariants before T-N activates on mainnet. `run` reads the chain's active
fork once per pass and skips any check whose `since` isn't active yet. Omitting
`since:` defaults to `Genesis` (always on).

```rust
invariant! {
    id: "TEMPO-TIP20-SOMETHING-T6",
    severity: P1,
    since: T6, // only runs once the chain is on T6 or later
    description: "...",
    fn something(t: &Tip20Snapshot, out: &mut Report<'_>) { /* ... */ }
}
```

Gating is applied per-run (not baked into the catalog): a long-lived delta runner
picks a check up the moment its fork activates, and an audit runner replaying
older blocks leaves it off.

## How `run` works (read once, check many)

`run` is entity-outer: for each entity it calls the scope's `read` step **once**
to load state into a plain-data snapshot, then runs *every* check for that scope
over the snapshot with no further I/O. State is read once per entity, not once
per (invariant, entity).

```
for entity in entities:
    snap = read(entity)            # the only place state is read (batchable)
    for check in scope_checks:
        check(&snap, &mut report)  # pure CPU, no storage access
```

- `read` calls the real `TIP20Token` accessors, so it stays the single I/O point
  and the place to add a batched multi-slot read later.
- A snapshot is its scope's read set. Most checks reuse existing fields; one that
  needs a new scalar extends the snapshot + `read`. Unbounded keyed data
  (per-holder balances) doesn't go in a snapshot — that needs enumeration (see
  `reserve/`).

## API surface

- `registry() -> Vec<InvariantMeta>` — the catalog, derived from the registered
  set (partitioned by scope and sorted once into a process-lifetime cache).
  Backs the catalog UI, history schema, and docs.
- `run<S: PrecompileStorageProvider>(provider, entities) -> RunOutput` — evaluate
  the registered checks over `entities`.
- `RunEntities` — the entities to check this pass (touched entities in the delta
  tier, all enumerated entities in the audit tier).
- `RunOutput { failures, errors }` — `failures` are violations; `errors` are
  entities whose checks were skipped because `read` failed, so "couldn't check"
  is never reported as "passed".

`provider` is any `PrecompileStorageProvider`: a reth `StateProvider` adapter
in-process, an RPC/stream provider in a sidecar, an archive provider in an audit
cron, or `HashMapStorageProvider` in tests.

## Adding a scope

A new entity class (e.g. AMM pool) is a deliberate change, not a routine check:

1. Add the entity + snapshot types and a `read` under `src/<scope>/`.
2. Register the scope (add a `ScopeKind` variant), then in the module:
   ```rust
   impl Scope for YourSnapshot { const KIND: ScopeKind = ScopeKind::YourScope; }
   inventory::collect!(Check<YourSnapshot>);
   ```
3. Add a runner arm in `run` and a field on `RunEntities`.

Adding a scope does touch `ScopeKind`, but there's no central *invariant* enum or
per-scope macro arm to edit — checks for the new scope self-register through its
own `inventory` collection, and the `invariant!` macro infers the scope from the
snapshot type.

## Try it

```bash
cargo run -p tempo-invariants --example demo   # prints the catalog + runs the checks
cargo test -p tempo-invariants                 # registry + behaviour tests
```

A check that reuses existing snapshot fields needs no edits outside its
`invariant!` block — it shows up in the demo output, the registry, and the tests
automatically.

## Workspace integration

`read` goes through `tempo-precompiles`, the authoritative storage layout, so a
layout change there breaks these checks in the same CI run. That keeps invariant
coverage part of the release rather than a separate downstream repo.
