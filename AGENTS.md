# Tempo

Tempo is a blockchain node built on [Reth SDK](https://github.com/paradigmxyz/reth). Rust workspace, `cargo` for builds, `just` for task automation.

## Commands

```bash
cargo fmt --all --check                                    # Check formatting
cargo clippy --workspace --all-targets -- -D warnings      # Lint
cargo test                                                 # Run all tests
cargo test -p <crate-name>                                 # Run tests for a specific crate
```

## Pull Requests

### Titles

Use [Conventional Commits](https://www.conventionalcommits.org/) with an optional scope:

```
<type>(<scope>): <short description>
```

**Types**: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `chore`

**Scope** (optional): crate or area, e.g. `evm`, `consensus`, `rpc`, `tip-1017`

Examples:
- `fix(rpc): correct gas estimation for TIP-20 transfers`
- `perf: batch trie updates to reduce cursor overhead`
- `feat(consensus): add checkpoint guard for batched state ops`

### Descriptions

Keep it short. Say what changed and why — nothing more.

**Do:**
- Write 1–3 sentences summarizing the change
- Explain _why_ if the diff doesn't make it obvious
- Link related issues or TIPs
- Include benchmark numbers for perf changes

**Don't:**
- List every file changed — that's what the diff is for
- Repeat the title in the body
- Add "Files changed" or "Changes" sections
- Write walls of text that go stale when the diff is updated
- Use filler like "This PR introduces...", "comprehensive", "robust", "enhance", "leverage"

**Template:**

```
<what changed, 1-3 sentences>

<why, if not obvious from the diff>

Closes #<issue>
```

**Good example:**

```
Adds `valid_before` upper bound for all AA transactions. Transactions past
their expiry are rejected at validation time and cleaned up from the pool
via a periodic sweep.

Closes #2901
```

**Bad example:**

```
## Summary
This PR introduces comprehensive validation checks for the valid_before field.

## Changes
- Modified `crates/pool/src/validate.rs` to add validation
- Modified `crates/pool/src/pool.rs` to add cleanup
- Added tests in `crates/pool/src/tests/valid_before.rs`

## Files Changed
- crates/pool/src/validate.rs
- crates/pool/src/pool.rs
- crates/pool/src/tests/valid_before.rs
```
