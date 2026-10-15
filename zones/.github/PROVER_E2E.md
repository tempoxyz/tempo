# Prover E2E

The publisher resolves exact commit SHAs without executing candidate code.
There is no cron schedule or rollout-variable gate.

| Trigger | Coverage | GitHub status |
| --- | --- | --- |
| Merge queue, changes in `crates/sequencer`, `prover`, `precompiles`, `spf` or `evm` | `prover-tests`: hardfork, settlement, fallback, recovery | `Tempo Zone Prover E2E` |
| Merge queue, no matching changes | No build or devnet; immediate success | `Tempo Zone Prover E2E` |
| Every push to `main`, including each merged PR | `prover-tests-full`: the four fast plans plus ancestry | `Tempo Zone Prover E2E (full)` |
| Manual dispatch | Exact SHA and selected fast/full suite, regardless of changed paths | Corresponding suite status |

Merge-queue detection compares the event's base SHA with its head SHA using the
same pinned changed-paths action as Tempo Network E2E. Detection or dispatch errors
fail the check. Main runs use the pushed SHA, not a later resolution of `main`;
newer merges do not cancel earlier ancestry runs. T14 remains a separate opt-in
scenario requiring distinct prover versions.

Deploy the matching `prover-tests`, `prover-tests-full` and provisioning templates,
then the event sensor, before merging this publisher. The sensor pins the workflow
code and prebuilt Tempo image. Configure `Tempo Zone Prover E2E` as the merge-queue
required status after verifying both dispatch and irrelevant-change success. The
full status is post-merge and must not be a merge-queue requirement.

Argo reports the selected tests' result before deletion, checks cleanup separately,
and updates only the publisher-owned status for that suite. No Slack notifications
are sent. Delivery is idempotent per Actions run/attempt; HTTP acceptance alone is
not confirmation of workflow submission. Verify event-to-workflow delivery during
rollout. Full ancestry retains its long history-window outage and a six-hour suite
ceiling. Successful workflow evidence is retained for seven days, failures for 30.
