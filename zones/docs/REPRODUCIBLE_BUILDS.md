# Reproducible candidate image verification

The Docker Build workflow can compare the `tempo-zone` binary in a Depot-built
candidate image with an independent clean rebuild of the same source commit.
The orchestration lives in `tempoxyz/gh-actions`; Zones owns the Dockerfile, Bake
target, Cargo profile, and `scripts/reproducible-build.sh`.

After the shared workflow and Zones caller are merged, dispatch from `main`:

```sh
gh workflow run docker.yml --repo tempoxyz/zones --ref main \
  -f reproducible_verify=true -f ref=<source-commit-sha>
gh run list --repo tempoxyz/zones --workflow docker.yml \
  --event workflow_dispatch --limit 5
gh run watch <run-id> --repo tempoxyz/zones --exit-status
```

Alternatively, open **Actions → Docker Build → Run workflow**, select `main`,
enable `reproducible_verify`, and enter the source ref. Omitting the ref builds
that workflow run's commit. The verification option skips normal image publishing
and publishes only a run-specific candidate under
`ghcr.io/tempoxyz/tempo-zone-repro`.

Successful runs complete all four shared jobs: resolve, candidate, rebuild, and
compare. A skipped verification job is not verification. The published image's
binary must match the clean rebuild; a mismatch fails the run.

Download and inspect the comparison manifest:

```sh
gh run download <run-id> --repo tempoxyz/zones \
  -n reproducible-candidate-binary-verification -D verification
jq -e '.binary_comparison_result == "success" and
       .depot_sha256 == .clean_build_sha256' \
  verification/reproducible-image-verification.json
```

The manifest records the source commit, trusted recipe commit (`verifier_sha`),
shared workflow commit, image digest, binary path, and both checksums. Artifacts
expire after seven days. Candidate tags include the run ID, attempt, and source
short SHA; extraction uses the immutable image digest.

The requested source ref is resolved once. Both builds use recipe files from
Zones' trusted workflow commit, which can differ from the source commit. Keep the
caller's `build-definition-paths` list complete if recipes gain new helpers.
Depot OIDC must allow the Zones caller, and its GitHub token needs write access to
the candidate GHCR package.

This checks the reproducible-profile candidate's binary only. It does not verify
the normal profiling image, the full container filesystem, or the prover EIF.
