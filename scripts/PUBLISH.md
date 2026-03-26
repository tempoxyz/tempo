# Publishing Crates

Publishes `tempo-contracts`, `tempo-primitives`, and `tempo-alloy` to crates.io with all reth-specific code and dependencies removed.

## Usage

```bash
./scripts/publish-crates.sh                # dry-run (default)
./scripts/publish-crates.sh --publish      # actually publish
./scripts/publish-crates.sh --semver-check # dry-run + check for breaking changes
```

## Architecture

All Reth-specific code in `tempo-primitives` lives in `crates/primitives/src/reth_compat/`, gated behind `#[cfg(feature = "reth")]`. This creates a clean deletion boundary — the publish script deletes that directory, strips remaining `cfg_attr` annotations from struct definitions, sanitizes `Cargo.toml` files, and publishes.

In `tempo-alloy`, reth-specific code lives in `rpc/compat.rs` (reth RPC trait impls and related tests). The publish script deletes `compat.rs`, removes the `mod compat;` declaration from `rpc/mod.rs`, strips reth/internal dependencies from `Cargo.toml`, and publishes. No feature gates are needed — the file deletion boundary is sufficient.

## Pipeline

1. copy to tmpdir
2. delete reth_compat/ & rpc/compat.rs
3. sanitize_source.py ── strip reth/tempo cfg attrs from .rs files
4. sanitize_toml.py ──── strip reth deps/features from Cargo.toml
5. cargo check + cargo check --all-features
6. pre-resolve validation ── grep for forbidden leftovers while workspace/path markers are still visible
7. sanitize_toml.py resolve_deps ── replace workspace refs with versions
8. post-resolve validation ── no workspace/path/git refs remain
9. final cargo check + cargo check --all-features (on resolved manifests)
10. cargo publish --dry-run (preflight all 3 crates)
11. cargo-semver-checks against last published version (`--semver-check` only)
12. cargo publish (contracts → primitives → alloy, with retry; `--publish` only)

NOTE: the working tree is never modified — all mutations happen on temp copies.

## Scripts

### `publish-crates.sh`

Orchestrator. Copies the 3 crates to a temp directory, runs the sanitization pipeline, verifies compilation, validates invariants, and publishes in dependency order.

**Pre-resolve validation** (while workspace/path markers still visible):
- No `reth-*` dependencies in any published manifest
- No internal path-only workspace crates (dynamically discovered from workspace root)
- No forbidden feature definitions (`reth`, `reth-codec`, `serde-bincode-compat`, `rpc`)
- No reth-gated `cfg` attrs in `tempo-primitives` source

**Post-resolve validation** (after concrete versions replace workspace refs):
- No `workspace = true`, `path =`, or `git =` in any published `Cargo.toml`

**Publish behavior:**
- Preflight: runs `cargo publish --dry-run` for all 3 crates before any real publish
- Publishes in dependency order (contracts → primitives → alloy)
- Skips already-published crates (detects "already exists" from crates.io)
- Retry: 10 attempts × 15s backoff to handle crates.io indexing delays

### `sanitize_source.py`

Strips reth/node-specific code from `.rs` files using two strategies:

- **Directory-wide scan** for `cfg_attr` patterns — walks all `.rs` files under `src/` and strips matching attributes wherever they appear. No hardcoded file lists; adding a new struct with reth derives requires no script update. Pre-scans to count expected matches, then asserts exact deletion counts post-mutation.
- **Simple line deletion** for alloy — removes the `mod compat;` declaration from `rpc/mod.rs` (the file itself is already deleted by the shell script).

**`tempo-primitives` edits:**
- Removes `#[cfg(feature = "reth")] mod reth_compat;` and `pub use reth_compat::TempoReceipt;` from `lib.rs`
- Removes `#[cfg(not(feature = "reth"))]` gate from the `TempoReceipt` type alias in `lib.rs`
- Removes `#[cfg_attr(feature = "reth-codec", derive(reth_codecs::Compact))]` from any file
- Removes `#[cfg_attr(test, reth_codecs::add_arbitrary_tests(...))]` from any file (single- and multi-line)
- Removes `#[cfg(feature = "rpc")]` impl blocks from `envelope.rs`

**`tempo-alloy` edits:**
- Deletes the `mod compat;` declaration from `rpc/mod.rs` (file already deleted by shell script)

### `sanitize_toml.py`

Transforms `Cargo.toml` files. Uses depth-aware brace/bracket tracking for robust multi-line dependency and feature block handling. String-aware comment stripping to avoid corrupting lines with `#` in quoted values. Six actions:

**`sanitize_base <toml> <version> [ws_toml]`** — Resolves workspace package fields (`version`, `edition`, `rust-version`, `license`) to concrete values read from the workspace root `Cargo.toml`. Removes `[lints]` section and `publish.workspace = true`.

**`sanitize_primitives <toml>`** — Removes reth-specific content from `tempo-primitives` manifest:
- Feature blocks: `reth`, `reth-codec`, `serde-bincode-compat`, `rpc`
- Dependencies: `reth-*`, `modular-bitfield`, `alloy-rpc-types-eth`, `alloy-network` (including dot-notation like `reth-codecs.workspace = true`)
- Auto-strips orphaned feature entries (`"dep?/feature"`, `"dep/feature"`, `"dep:dep"`) referencing any removed dependency — no manual regex needed when adding new reth-gated deps

**`sanitize_alloy <toml> <ws_toml>`** — Removes reth/internal content from `tempo-alloy` manifest:
- Dependencies: `reth-*`, all internal path-only workspace crates (dynamically discovered from workspace root, except `tempo-contracts`/`tempo-primitives`/`tempo-alloy`)
- Strips `"rpc"` from `tempo-primitives` features (the `rpc` feature is stripped from primitives during publish)

**`resolve_deps <toml> <ws_toml>`** — Replaces `workspace = true` references with concrete versions parsed from the workspace root. Preserves `default-features = false` (from both workspace and local specs), `features`, `optional`, and `package` flags. Uses depth-aware multi-line collection. Fails immediately if a dep has no version (git-only or missing).

**`gen_workspace <ws_toml> <out_toml> [crate1,crate2,...]`** — Generates a temporary workspace `Cargo.toml` for the compilation check step. Dynamically discovers internal path-only crates from the workspace root (no hardcoded list) and filters them out along with `reth-*` deps. Re-adds the specified publish crates as local path overrides.

**`get_version <ws_toml>`** — Prints the workspace package version to stdout. Used by `publish-crates.sh` to avoid duplicating version extraction logic.

## CI Workflows

### `publish-check.yml`

Runs the dry-run pipeline (`publish-crates.sh`) on every PR touching the published crates or scripts. Catches sanitization regressions before merge.

### `semver-check.yml`

Runs `publish-crates.sh --semver-check` on PRs touching published crates. Sanitizes the crates, then runs `cargo-semver-checks` against the last published version on crates.io. Fails the PR if breaking changes are detected without an appropriate version bump. Skips crates that haven't been published yet.

### `changelog.yml`

Uses `wevm/changelogs/check` to comment on PRs with changelog status. If no changelog entry exists, generates one using AI (Amp) and pre-fills the "Add changelog" link. Changelog entries are staged in `.changelog/`.

### `release-pr.yml`

Triggered on push to `main`. Uses `wevm/changelogs` to create/update a "Version Packages" RC PR with version bumps and changelog updates when pending changelogs exist.

### `publish.yml`

Triggered when the RC PR (from `changelog-release/*` branch) is merged. Runs `publish-crates.sh --publish` to sanitize and publish crates to crates.io via the `CARGO_REGISTRY_TOKEN` secret. The sanitize pipeline is the only publisher — `wevm/changelogs` handles versioning only.
