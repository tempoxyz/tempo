# TIP dashboard data contract (v1)

All reports and evidence envelopes have `schema_version: 1`. `report.json` is the single source for the static dashboard and `summary.md`.

## Sources and identities

`protocolVersion` in TIP frontmatter is the canonical scheduled fork. Blank, `TBD` and unrecognised values report unknown. Current/next fork hints come from `tips/verify/foundry.toml`'s `profile.default` and `profile.next`; these are test profiles, not network activation approvals. `latest_forks` lists next, current and the preceding scheduled fork (up to three), including empty upgrade groups. Implementation PR associations come from `implementation:` frontmatter or existing `**PR**:` / `**PRs**:` paragraphs. Related-work links are not implementation associations. GitHub states are observations at report generation, independent of code inclusion at the selected revision.

Stable labels:

```markdown
<!-- @requirement TIP-1006:R21 from=T12 kind=activation cases=selectors_t11,selectors_t12,selectors_t13 -->
The normative statement follows.
```

An existing table ID can retain its name, with a label inside that table row. IDs are namespaced, such as `TIP-1098:ZV1`. A requirement has named, unique required cases. Use distinct case names for each required fork boundary: passing one fork must not satisfy a different fork obligation. Use `from=T12 until=T13 superseded_by=TIP-1234:E2` to express an inclusive start, exclusive end and replacement. Supersession requires a unique replacement and an explicit end fork; invalid scope is unknown. Omitted start scope is unknown, not an assertion about historical forks. Earlier requirements remain in the inventory.

```rust
// @implements TIP-1006:R21 gate=schedule(since=T12)
#[schedule(since = T12)]
burnAt(call) => mutate(call, msg_sender, |sender, c| self.burn_at(sender, c)),
// @asserts TIP-1006:R21 case=selectors_t12 test=tip20::tests::spec_dashboard_burn_at_activation_t12 fork=T12
spec_evidence!("TIP-1006:R21", "selectors_t12", "tip20::tests::spec_dashboard_burn_at_activation_t12", "T12", assert!(condition));
```

Consecutive implementation labels can share one expression. The scanner records the adjacent expression, compares recognised `is_tN()` predicates or exact `#[schedule(since = TN)]` dispatch attributes with the declared gate, and leaves unsupported guards unresolved. Attributes with additional conditions remain unresolved. `gate=always` declares an unconditional expression; review must inspect its enclosing control flow. A matching comment is only a link. Review must inspect real code, helper dependencies, assertion meaning and actual fork setup.

A snapshot contains all tracked files and nonignored source files in `WORKTREE`, or the selected Git tree for a revision. Source identity binds SHA, relevant dirty state, Git modes, paths, content and submodule pins. Outputs, build/cache directories and symlink targets are excluded from scanning; modified submodules invalidate execution verification. A dirty report displays the base commit plus its source digest and omits misleading immutable source links.

## Report

Top level: `schema_version`, `generated_at`, `repository`, `revision`, `collection`, `current_fork`, `next_fork`, `latest_forks`, `summary`, `tips`, `evidence_context`.

Each TIP includes specification identity, schedule, observed implementation PRs and aggregate merge status, inventory/review status, implementation coverage, assertion-case coverage, warnings and requirements. A requirement includes its stable ID, normative statement/location, applicability map, implementation expressions/gates, assertion selectors/cases/forks, digests, review, matching test attempts and completion evidence. Missing labels mean unmapped implementation, not proof that protocol code is absent.

Implementation status is `missing`, `linked` or `reviewed`. Reviewed source can still lack assertion links; these gaps remain separate and cannot verify the requirement. One case annotated at multiple different forks is ambiguous and cannot establish verification. Verification status is `not_run`, `unexercised`, `partial`, `verified`, `failed`, `skipped`, `stale` or `unknown`. Case counts use unique declared cases. Test success with no matching assertion marker is `unexercised`; missing cases remain listed. A failed attempt prevents verified status even if another attempt passes. Empty or unreviewed inventories never establish complete coverage. Collection failure writes a fresh error report, replacing any prior report at that output path.

## Execution evidence

An assertion helper checks its condition and only then emits:

```text
TIP_EVIDENCE {"requirement":"TIP-1006:R21","case":"selectors_t12","test":"tip20::tests::spec_dashboard_burn_at_activation_t12","fork":"T12"}
```

The external collector owns test outcome. An envelope contains:

- `identity`, `tool_digest`, `manifest_digest`, `checks_digest` from `evidence_context()`.
- `runner: {name, version}`, `provenance: {kind: "local" | "ci", run_url}`.
- `attempts: [{id, test, outcome, exit_code, timed_out, markers, errors}]` and collection `errors`.
- Optional build command/outcome and start/finish times for diagnostics.

Each marker joins a declared requirement, case, exact test selector and expected fork in the same attempt. Passing requires a completed successful test, zero exit status, no timeout or collector error, matching source/spec/test/tool identities, reviewed links and reviewed nonempty inventory. No cross-run stitching or automatic retries. Skipped tests, failures after markers, changed sources, wrong forks and malformed evidence cannot verify a requirement. CI URLs include the run attempt. The pilot executes ignored Rust tests separately; it does not ingest arbitrary nextest/Foundry success summaries.

`run_pilot.py` uses the existing `test-utils` feature. Assertion markers go to bounded deterministic test output, never per-assertion files or production execution. Foundry's `SpecEvidence.assertEvidence` emits the same marker format; a Foundry outcome collector remains future work and its results are not claimed by the Rust pilot.

## Reviews

`tips/verification/reviews.json` holds `inventories` and `requirements` arrays. Every record identifies `reviewer`, `reviewer_kind: "agent" | "human"`, and a `source` review reference. Inventory records bind `tip` and `spec_digest`; requirement records bind `id`, `spec_digest`, `source_digest`, `test_digest`. Review records attest meaning and completeness, not a network release approval. Duplicate, stale or incomplete records do not count. Never refresh hashes automatically without reviewing changed meaning.

Digests are SHA256. JSON uses UTF-8 `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`; files use raw bytes. Requirement identity includes complete spec and linked source/test files, conservatively invalidating review when helpers in the same file change. The full candidate and actual running collector/report code additionally bind execution. Reviewers must inspect dependencies in other files; execution becomes stale on any candidate change.

## Python API

- `identity(repo, revision="WORKTREE")` returns `{requested, sha, dirty, source_digest}`.
- `build_report(repo, revision="WORKTREE", evidence=None, github=False)` accepts a decoded evidence envelope or file path.
- `evidence_context(repo, revision="WORKTREE")` returns the four binding fields. Capture before and after execution; changes invalidate collection.
- `tool_digest(repo)` hashes the actual running Python reporter/collector, even when candidate and tooling checkouts differ.

`HEAD` and `WORKTREE` evidence can match when SHA, source digest and dirty state are identical; the requested selector and source-link presentation are not execution identities.

## GitHub people

`collect_people(sha, tips, cache=None)` adds `people` to each TIP. It requires the full selected commit SHA. `people` contains `status` (`complete`, `partial`, `unavailable`, or `not_requested` when GitHub collection is disabled), `observed_at`, `revision`, string `warnings`, and `spec` / `implementation` groups. Each group has `status`, `contributors`, and `pull_requests`. `complete` means the bounded API traversal finished successfully, not that approval or implementation completeness has been established. Empty successful collections differ from unavailable or truncated collections. Disabled collection is supplied by the report caller.

Specification history uses GitHub `Commit.history(path:)` at `revision`; its associated PRs can concern other files too. Specification group contributors contain only file-history commit authors and committers at the selected revision. Associated PR commits may concern other files or future PR heads and never contribute to this revision-bound group. Implementation group contributors aggregate the associated implementation PRs' commits. Each PR separately exposes its live `contributors` and `observed_at`, preserving PR-wide attribution and observation time even when cached across revision collections. PR associations and contributor roles are evidence of activity, not line-level review or semantic verification. Frontmatter `declared_authors` remain separate unverified declarations. PR metadata and reviews are live observations, not a historical snapshot at `revision`.

Contributors contain `login`, `name`, `url`, `account_type`, deduplicated `roles` (`author`, `committer`), and `commits: [{sha, url}]`. An unmapped Git signature preserves its raw name with null GitHub identity fields; it must not become a fabricated login. Unmapped signatures remain separate by commit and role; equal raw names do not establish common identity. GitHub `User` does not establish that an actor is human (automation can use ordinary user accounts). No emails are collected.

PRs contain `number`, `url`, `title`, `author: {login, name, url, account_type}`, `state`, `head_sha`, `review_decision`, `reviews`, `contributors`, `observed_at`, `status`, and string `warnings`. Reviews contain `author`, GitHub `state`, `submitted_at`, `commit_sha`, `url`, and `on_current_head`. Only submitted approved, changes-requested, commented, and dismissed reviews are included. Pending reviews and review requests do not count. `on_current_head` is null when either commit identity is unavailable. Old-head approval remains explicitly old-head; dismissed and commented reviews are never approval. Missing or deleted actors retain null identities.

The collector uses six workers and a per-run shared PR cache, with no persistent cache. Pass the same initially empty dictionary as `cache` for sequential candidate and main collections within one report run; PR successes and failures are reused, while file history remains independently bound to each selected SHA. Do not persist this cache between report runs. History is bounded to three pages of 30 commits, reviews and PR commits to three pages of 100 each, and commit-associated PRs to 10. Limits, malformed responses, timeouts, and API failures produce warnings and partial/unavailable status while retaining evidence already collected. PR review decisions remain GitHub's observed aggregate rather than being reconstructed from individual reviews.
