# PR description checks

## Structure check

Use `## Problem`, `## Changes`, and `## Validation`. One or two sentences per
section is enough. `## Rollout` is optional. A truthful explanation of why tests
were not run is valid; a bare `N/A`, `TODO`, or empty template is not.

`PR description structure` reads the current GitHub description on PR creation,
reopening, body edits, pushes, and readiness changes. It also checks PRs associated
with merge-group commits. It checks section presence and common placeholders,
not whether the prose is accurate, useful, or complete.

The workflow executes only the helper from the trusted base revision, never code
from the PR branch. It uses no AI credentials and posts no comments.

### Enable merge enforcement

1. Merge this change. The trusted-base workflow cannot use its new helper before
   it exists on the base branch.
2. Open or edit a small test PR and confirm the status appears. Check an empty
   template fails, a completed body passes, and editing the body reruns the check.
3. Add **PR description structure** (source: GitHub Actions) to the existing
   required status checks in the `main branch` ruleset. Preserve all other rules.
4. If enabling a merge queue, verify a real merge-group run before depending on
   this status. Failure to identify the group's PRs produces an error, never a pass.

This PR does not change repository rulesets. The status is advisory until an
administrator makes it required. Existing PRs need an edit or push to run it.
GitHub statuses belong to commits, not PR-body revisions: body edits retrigger
the workflow, but this is not an atomic guarantee against edits immediately before
merging. The same head commit reused across multiple PRs also shares statuses.

Run helper tests with `node --test .github/assets/pr-description.test.cjs`.

## Accuracy check: separate follow-up

The structure check does not implement AI accuracy review. Tempo's current Cyclops
integration starts audits via labels or explicit audit requests; it is not a
body-change subscription. Do not describe its existing completed-audit status as
proof that a current PR description matches the implementation.

The accuracy integration should:

- Compare the saved description with the complete diff against the actual base,
  relevant surrounding code, and available test results.
- Flag concrete contradictions, material omissions, stale explanations, and
  validation claims contradicted by evidence. Missing evidence is unverified.
- Quote each claim, cite the supporting code or result, and suggest a correction.
- Treat all PR text and code as untrusted input, not agent instructions.
- Record the head SHA, base SHA, and description hash. Invalidate results when
  any of them changes and discard results from outdated runs.
- Rerun on creation, new commits, base changes, and description edits, with
  deduplication and a bounded runtime/cost. Avoid launching a full security audit
  solely because someone edits a description.
- Remain advisory during the pilot. Report unavailable or incomplete coverage
  explicitly; never turn a failed or truncated review into a clean result.

Choose the integration and deployment owner before adding an AI provider or
changing Cyclops. Keep human-written descriptions intact; suggest edits rather
than overwriting them automatically.
