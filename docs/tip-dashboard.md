# TIP implementation dashboard

A read-only view of network upgrades: scheduled TIPs, code links, activation rules, implementation PRs and assertion results. It opens on the latest upgrades: the Foundry `next` and default profiles, followed by the preceding scheduled fork. These profiles describe test targets, not approved network activation dates. Select **All upgrades** for older and unscheduled TIPs.

## Read a report

```sh
python3 scripts/tip_dashboard/report.py --revision WORKTREE --output output/tip-dashboard --github
python3 -m http.server 8765 --bind 127.0.0.1 --directory output/tip-dashboard
```

Open `http://127.0.0.1:8765`, or open the generated self-contained `dashboard.html` directly. The hosted page reads adjacent `report.json`; it has no upload/import flow. `summary.md` consumes the same report data. `--github` reads PR states through `gh`; without access they stay unknown.

Pass `--revision main`, a release tag or a commit to inspect that Git tree. `WORKTREE` includes local edits and displays its base SHA and source digest. A hosted collection can offer revision selection through adjacent `index.json`:

```json
{"reports":[{"label":"main","url":"main/report.json","sha":"FULL_COMMIT_SHA"},{"label":"release candidate","url":"release/report.json","sha":"FULL_COMMIT_SHA"}]}
```

Generate each report from its selected revision. The page displays the report's resolved commit. Host these static files together or use the CI artifact. Tempo already publishes Rust documentation through GitHub Pages; do not replace that deployment with a dashboard-only site.

## Label one TIP

Keep `protocolVersion` as the single scheduled-fork field. Missing, `TBD` or unrecognised values remain unknown. Add explicit implementation PR URLs to `implementation:` frontmatter; existing `**PRs**:` metadata is also supported. Related-work links alone do not establish implementation.

Place a stable ID before each normative requirement, preserving existing IDs:

```markdown
<!-- @requirement TIP-1088:R1 from=T12 kind=activation cases=activation_fragmented_bid_t11,activation_fragmented_bid_t12,activation_fragmented_bid_t13 -->
The normative activation rule follows.
```

Link the real guard and the actual assertion:

```rust
// @implements TIP-1088:R1 gate=self.storage.spec().is_t12()
if self.storage.spec().is_t12() {
    // Existing implementation.
}
// @asserts TIP-1088:R1 case=activation_fragmented_bid_t12 test=stablecoin_dex::tests::spec_dashboard_dex_t12 fork=T12
spec_evidence!("TIP-1088:R1", "activation_fragmented_bid_t12", "stablecoin_dex::tests::spec_dashboard_dex_t12", "T12", actual == expected);
```

Cases are distinct obligations; use separate names when both sides of a fork boundary must execute. Use `from=T12 until=T13 superseded_by=TIP-1234:E2` for replaced rules (`until` is exclusive). `gate=always` links an unconditional helper; review must inspect its callers and enclosing guards. Comments establish links, not semantic correctness.

## Collect execution evidence

```sh
python3 scripts/tip_dashboard/run_pilot.py --output output/tip-dashboard/evidence.json
python3 scripts/tip_dashboard/report.py --output output/tip-dashboard --evidence output/tip-dashboard/evidence.json --github
```

The pilot builds `tempo-precompiles` with its existing `test-utils` feature and runs each explicitly ignored `spec_dashboard` test separately. Its test-only macro asserts before emitting a marker; there are no production hooks or per-assertion files. Markers join the outcome of that same test attempt. An early return, skipped test, later failure, wrong fork or stale source cannot produce verified coverage. Build/collection failures remain unavailable evidence.

TIP-1088 is the T12 showcase. Its inventory includes declared gaps for transient writes/refunds, all write-path traversal, ABI shapes and flip-error outcomes. Finite passing examples do not prove parity for every input. Other TIPs remain visible from their real schedule metadata even before labelling. Missing protocol implementation is a finding, not scope to change protocol behaviour.

The matching Foundry helper is `tips/verify/test/helpers/SpecEvidence.sol`. A Foundry outcome collector is not included; the Rust collector does not claim Foundry execution.

## Review and CI

`tips/verification/reviews.json` binds reviewed inventories and source/assertion links to their content digests, with reviewer, automated/human kind and review reference. Review meaning before recording hashes; never refresh hashes automatically. Empty or incomplete inventories cannot establish complete coverage. Historical merged PRs cannot substitute for current code. See [the schema](../scripts/tip_dashboard/SCHEMA.md) for the full contract.

The separate advisory workflow runs on relevant changes and supports explicit release revisions. It publishes the JSON, static UI, summary and evidence as a run/attempt artifact. New completeness checks are warnings, not required gates. A failed report publishes a fresh unavailable result, never an old green result.

Validate tooling with:

```sh
python3 -m unittest discover -s scripts/tip_dashboard/tests -p 'test_*.py'
python3 -m unittest discover -s scripts/tip_dashboard -p 'test_runner.py'
node --test scripts/tip_dashboard/web/app.test.cjs
```

For real-browser regression, install Playwright outside source and run `web/browser.test.cjs` with `NODE_PATH` pointing there. `TIP_DASHBOARD_REPORT`, `TIP_DASHBOARD_BASELINE` and optional `PLAYWRIGHT_CHROMIUM_EXECUTABLE` select fixtures and browser.
