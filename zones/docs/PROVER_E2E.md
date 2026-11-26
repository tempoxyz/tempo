# Prover E2E

The publisher resolves exact commit SHAs without executing candidate code.

| Trigger | Coverage | GitHub status |
| --- | --- | --- |
| Merge queue, shared Rust crates, prover binaries, packaging, dependency graph or toolchain changes | `prover-tests`: hardfork, settlement, fallback, recovery | `Tempo Zone Prover E2E` |
| Merge queue, no matching changes | No build or devnet; immediate success | `Tempo Zone Prover E2E` |
| Manual dispatch | Exact SHA and selected fast or compat suite, regardless of changed paths | Corresponding suite status |

Merge-queue detection compares the event's base SHA with its head SHA using the
same pinned changed-paths action as the Tempo CI Image workflow. Detection or dispatch errors
fail the check. Ancestry recovery against the real EIP-2935 window is covered by the
`zone-node` integration tests. T14 remains a separate opt-in
scenario requiring distinct prover versions.

The publisher requires the matching `prover-tests` and provisioning templates and event sensor to be deployed. The sensor pins the
workflow code and prebuilt Tempo image. Configure `Tempo Zone Prover E2E` as the
merge-queue required status after verifying both dispatch and irrelevant-change
success.

Argo reports the selected tests' result before deletion, checks cleanup separately,
and updates only the publisher-owned status. No Slack notifications
are sent. Delivery is idempotent per Actions run/attempt; HTTP acceptance alone is
not confirmation of workflow submission. Verify event-to-workflow delivery during
rollout. Successful workflow evidence is retained for seven days, failures for 30.
