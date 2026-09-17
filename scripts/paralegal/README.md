# Paralegal trial

Verdict: useful for scoped check-wiring regression experiments, but **not ready
as a strict Tempo CI security gate** at the tested upstream revision. The three
policies pass on the actual Tempo dependence graph in diagnostic mode. Strict
analysis rejects unsupported constants and tracing pointers before enforcement
can complete. Disabling strict mode silently drops those unsupported values.

This is an opt-in trial; it adds no runtime dependencies or annotations to Tempo.

## Tested revisions

- Tempo: [`07761a78`](https://github.com/tempoxyz/tempo/commit/07761a78a4ac00988533aa8acbcb6667786b625d).
- Paralegal: [`c96efb34`](https://github.com/brownsys/paralegal/commit/c96efb341aba35c16b02e5746681d9c8fb74fe9c).
- Analyzer: `nightly-2026-04-20`, rustc `1.97.0-nightly`.
- Initial checker build: stable `1.98.1`; final runner and Clippy pin `nightly-2026-04-20`.
- Trial date: 2026-09-17; Linux x86-64 sandbox, 4 CPU quota, 32 GiB memory limit.

## Three policies

| Property | Entrypoints | Required dependence |
| --- | --- | --- |
| Role changes require authorization | `grant_role`, `revoke_role`, `renounce_role`, `set_role_admin` | `check_role_internal` result controls each grant, revoke, or admin-update helper call |
| Ordinary transfers respect pause state | `transfer`, `transfer_from`, and both memo variants | `check_not_paused` result controls each `_transfer` call |
| Ordinary transfers enforce TIP-403 | Same four transfer entrypoints | `ensure_transfer_authorized` result controls each `_transfer` call |

The transfer analysis crosses `validate_transfer` and `validate_inbound_or_block`,
so the marked effects include the receive-policy guard transfer branch.
Initialization, privileged system transfers, fee settlement, minting, and other
entrypoints are outside this trial. In particular, an unrestricted rule over
every `_transfer` caller would misstate intended fee-refund behavior.

External markers in `markers.toml` identify trusted check/effect boundaries.
The checker requires all eight roots, nonempty check/effect sets in each root,
and coverage of every marked effect node. Its relation is zero or more data
edges from a check result followed by control edges to an effect.

This detects missing or ignored checks; it does **not** prove that the check
implementation is correct, that the correct account/role was supplied, that a
branch accepts the correct boolean value, or that authorization holds on every
possible execution path. Control influence is weaker than an all-path proof.
It also does not prove balance conservation or arithmetic safety. Changes to
the trusted helpers or ABI entrypoints require marker/scope review.

## Observed results

The final diagnostic runner exits successfully: **3 policies, 8 entrypoints,
3,120 marked-node control-dependence obligations passed**. These are graph nodes,
not 3,120 distinct token operations: the role policy contributes 624 obligations
and each transfer policy contributes 1,248. The graph is approximately 147 MiB.
The run traversed 10 function bodies (204 source lines) into the selected graphs;
this is not whole-node coverage.

With downloaded dependencies and a fresh analysis profile, the Cargo analysis
took 78 seconds. With cached compilation, Cargo took 0.36 seconds, graph loading
3.018 seconds, and the final batched checker 3.122 seconds. These are single
observations in the shared sandbox, not a controlled performance benchmark.

Strict fixture checks passed: the valid fixture was accepted; independently
ignoring each of the role, pause, and TIP-403 check results was rejected by the
corresponding control-dependence policy. Renaming the authorization marker was
also rejected. These are isolated policy tests, not vulnerable Tempo builds or
transaction-level exploit tests. The final checker passes pinned-nightly Clippy,
Rust formatting checks, and shell syntax checks.

## Reproduce

Build the pinned analyzer in a separate checkout:

```sh
git clone https://github.com/brownsys/paralegal.git /tmp/paralegal-tempo-trial
git -C /tmp/paralegal-tempo-trial checkout c96efb341aba35c16b02e5746681d9c8fb74fe9c
cd /tmp/paralegal-tempo-trial
cargo build --locked -p cargo-paralegal-flow -p paralegal-flow --jobs 4
export PARALEGAL_BIN_DIR=/tmp/paralegal-tempo-trial/target/debug
```

The upstream toolchain file installs the pinned nightly and compiler components
through rustup. The standalone checker uses the same pinned nightly.
From the Tempo checkout:

```sh
# Fail-closed mode: currently fails on upstream representation gaps.
bash scripts/paralegal/analyze.sh

# Explicit diagnostic mode: permits the unsupported-value omissions.
bash scripts/paralegal/analyze.sh --diagnostic

# Independent fixture controls: baseline passes; each ignored check fails.
bash scripts/paralegal/test-policies.sh

cargo +nightly-2026-04-20 clippy --locked \
  --manifest-path scripts/paralegal/Cargo.toml -- -D warnings
```

Both analysis modes compile the real `tempo-precompiles` library with
`--no-default-features`, using Tempo's unchanged lockfile. The only profile
override is `profile.dev.debug=0`, for artifact-parser compatibility. Raw graphs,
marker statistics, and timing statistics are generated under this directory's
`target/`; the artifact manifest is in the repository root. All are ignored by
Git. Fixture logs remain in `fixture/`.

## Integration findings

1. **Strict constant handling blocks the real crate.** The initial strict run
   reached all eight roots, then failed with nine diagnostics: six unevaluated
   constants and three tracing callsite reference/pointer values. The receive
   policy guard address is among the unsupported constants. Upstream
   [`constants.rs`](https://github.com/brownsys/paralegal/blob/c96efb341aba35c16b02e5746681d9c8fb74fe9c/crates/plugin/src/constants.rs)
   rejects unevaluated values before trying evaluation; its non-strict warning
   emission is commented out. Including more dependency bodies cannot fix that
   conversion rule. The diagnostic pass is therefore not a strict validation.
2. **Cargo artifact parsing needs the profile override.** The analyzer generated
   a graph, but returned `{"targets":[]}` with Tempo's `line-tables-only`
   debuginfo. Its `cargo_metadata 0.14.2` parser expects `Option<u32>` there.
   The runner uses numeric debug info and passes the hyphenated Cargo package
   name to `--target` so both driver selection and artifact collection agree.
3. **An unused check crashes the convenience query.** Upstream
   [`has_ctrl_influence`](https://github.com/brownsys/paralegal/blob/c96efb341aba35c16b02e5746681d9c8fb74fe9c/crates/policy/src/context.rs#L847)
   unwraps an empty set of data successors. The checker expresses the same
   reachability relation through batched graph queries, handling empty sets
   without accepting them. All three ignored-result fixtures fail for policy
   violations, not crashes or missing markers.
4. **Pin the analysis toolchain.** Latest installed nightly (`1.100.0-nightly`)
   failed checker Clippy in upstream dependency `allocative 0.3.6` because of
   overlapping `Infallible`/`!` implementations. The analyzer's pinned nightly
   passes Clippy. Upstream compiler coupling creates maintenance work.
5. **Strictness is absent from upstream's Cargo cache key.** A strict command
   after a diagnostic build reused the diagnostic graph and incorrectly passed
   without rerunning strict analysis. Upstream `ClapArgs::hash_config` hashes the
   deprecated `relaxed` flag but not `strict` or the entrypoint/inlining options.
   The runner now puts its mode and script-content hash into `result_path`, which
   upstream does hash. Changing modes or runner configuration therefore forces
   separate compilation artifacts. This workaround is essential for fail-closed
   behavior; merely adding `--strict` to an existing cache is insufficient.
   With isolated strict configuration, the runner again fails with the same nine
   unsupported-value diagnostics and never runs the policy checker.

The next adoption step is upstream constant/pointer modeling and modern Cargo
metadata support plus complete configuration hashing, followed by a passing
strict run and a review of the trusted check boundaries. Until then, keep this
as an opt-in experiment rather than a required merge check or a claim that
Tempo's security properties are proven.
