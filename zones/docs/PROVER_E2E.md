# Prover E2E

The publisher resolves exact commit SHAs without executing candidate code.
The full suite runs on nightly Zones images, not on each push to `main`.

| Trigger | Coverage | GitHub status |
| --- | --- | --- |
| Merge queue, shared Rust crates, prover binaries, packaging, dependency graph or toolchain changes | `prover-tests`: hardfork, settlement, fallback, recovery | `Tempo Zone Prover E2E` |
| Merge queue, no matching changes | No build or devnet; immediate success | `Tempo Zone Prover E2E` |
| Each successful scheduled (nightly) `Zones Docker Build` on `main` | `prover-tests-full`: the four fast plans plus ancestry | `Tempo Zone Prover E2E (full)` |
| Manual dispatch | Exact SHA and selected fast/full suite, regardless of changed paths | Corresponding suite status |

Merge-queue detection compares the event's base SHA with its head SHA using the
same pinned changed-paths action as the Tempo CI Image workflow. Detection or dispatch errors
fail the check. Nightly runs use the image build's head SHA, not a later resolution
of `main`; newer nightlies do not cancel earlier ancestry runs. T14 remains a separate opt-in
scenario requiring distinct prover versions.

The publisher requires the matching `prover-tests`, `prover-tests-full` and
provisioning templates and event sensor to be deployed. The sensor pins the
workflow code and prebuilt Tempo image. Configure `Tempo Zone Prover E2E` as the
merge-queue required status after verifying both dispatch and irrelevant-change
success. The full status is post-merge and must not be a merge-queue requirement.

Argo reports the selected tests' result before deletion, checks cleanup separately,
and updates only the publisher-owned status for that suite. No Slack notifications
are sent. Delivery is idempotent per Actions run/attempt; HTTP acceptance alone is
not confirmation of workflow submission. Verify event-to-workflow delivery during
rollout. Full ancestry retains its long history-window outage and a six-hour suite
ceiling. Successful workflow evidence is retained for seven days, failures for 30.
