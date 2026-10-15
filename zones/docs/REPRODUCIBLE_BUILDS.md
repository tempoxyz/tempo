# Reproducible build verification

## Candidate binary

The Docker Build workflow can compare the `tempo-zone` binary in a Depot-built
candidate image with an independent clean rebuild of the same source commit.
The orchestration lives in `tempoxyz/gh-actions`; Zones owns the Dockerfile, Bake
target, Cargo profile, and `zones/scripts/reproducible-build.sh`.

After the migration PRs are merged and `ZONES_PUBLISH_ENABLED=true` is set
following the external cutover in [MIGRATION.md](../MIGRATION.md), dispatch from `main`:

```sh
gh workflow run zones-docker.yml --repo tempoxyz/tempo --ref main \
  -f reproducible_verify=true -f ref=<source-commit-sha>
gh run list --repo tempoxyz/tempo --workflow zones-docker.yml \
  --event workflow_dispatch --limit 5
gh run watch <run-id> --repo tempoxyz/tempo --exit-status
```

Alternatively, open **Actions → Zones Docker Build → Run workflow**, select `main`,
enable `reproducible_verify`, and enter the source ref. Omitting the ref builds
that workflow run's commit. The verification option skips normal image publishing
and publishes only a run-specific candidate under
`ghcr.io/tempoxyz/tempo-zone-repro`.

Successful runs complete all four shared jobs: resolve, candidate, rebuild, and
compare. A skipped verification job is not verification. The published image's
binary must match the clean rebuild; a mismatch fails the run.

Download and inspect the comparison manifest:

```sh
gh run download <run-id> --repo tempoxyz/tempo \
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
Depot OIDC must allow the Tempo caller, and its GitHub token needs write access to
the candidate GHCR package.

This checks the reproducible-profile candidate's binary only. It does not verify
the normal profiling image, the full container filesystem, or the prover EIF.

For normal production publishing, the Docker Build workflow builds the same
`tempo-zone` Bake target with Depot and independently on a clean GitHub runner.
It loads both image archives and requires identical Docker image IDs before
staging and promoting Depot's candidate. The image ID covers the image config
and its ordered layer contents. A `production_image_verify_only` dispatch runs
this comparison without publishing production tags.
Companion image tags publish only after this production check succeeds. This
check gates their publication; it does not independently reproduce companion
image contents.

The Zones Release workflow uses `zones/vX.Y.Z` tags, slash-free asset versions,
and `--latest=false` to preserve Tempo release ownership. It accepts only tags whose commits are already reachable
from `main`, including for manual dry runs. This check runs before either
OIDC-enabled binary build checks out and executes the tagged build script.

## Prover EIF

The separate `reproducible_eif_verify` dispatch option compares unsigned prover
EIFs built through Depot and independently on a fresh GitHub runner without Docker
cache. The shared workflow is in `tempoxyz/gh-actions`; Zones supplies the enclave
Dockerfile, `zones/scripts/reproducible-eif-build.sh`, genesis input and Nitro toolchain.

Pin the exact Tempo genesis bytes before dispatching. For example:

```sh
genesis_url=https://devnet-assets.tempoxyz.dev/tempo-devnet-nextfork.json
curl --proto '=https' --proto-redir '=https' --fail --location \
  "$genesis_url" -o /tmp/prover-genesis.json
genesis_sha256=$(sha256sum /tmp/prover-genesis.json | cut -d' ' -f1)
gh workflow run zones-docker.yml --repo tempoxyz/tempo --ref main \
  -f reproducible_eif_verify=true -f ref=<source-commit-sha> \
  -f tempo_genesis_url="$genesis_url" -f tempo_genesis_sha256="$genesis_sha256"
```

Each build downloads that URL and rejects bytes that do not match the checksum.
The source ref resolves once; both builds use recipes from the trusted workflow
commit, the `zones-reproducible` Cargo profile, pinned Rust/Debian images and normalized
rootfs timestamps. The source must contain the `zones-reproducible` Cargo profile.

The toolchain job checks out `tempoxyz/tempo` main and hashes the toolchain
Dockerfile plus its resolved Bake dependency graph, including the pinned kernel
source. It reuses `ghcr.io/tempoxyz/tempo-zone-eif-toolchain:inputs-<recipe-hash>`
or builds it on a cache miss. Identical recipes reuse one tag instead of producing
one tag per run. The resolved digest is recorded and used for both EIF builds and
measurement; dispatch cannot supply an arbitrary toolchain image. These recipe
hash tags are retained for reproduction. Changing a toolchain input creates a new
hash; changing only application source does not.

This fixes Nitro CLI, Linux 6.6.79, NSM and bootstrap binaries as toolchain inputs;
the comparison does not independently rebuild or verify the toolchain itself.
Verification requests from any branch other than `main`, or requests enabling
both verification modes, fail the validation job instead of silently succeeding.

Production uses the same `Dockerfile.reproducible` prover compiler and
`Dockerfile.prover-package` runtime as verification. Both paths call
`zones/scripts/package-prover-eif.sh` to normalize genesis and binary permissions and
filesystem timestamps, export the container, and construct the EIF with the
recorded toolchain digest. Production still compiles before fetching the deferred
genesis. Its measurement identity artifact records the source, genesis checksum,
binary checksum and toolchain digest. To reproduce the published PCRs, verify
that same source and genesis with those recipe and toolchain revisions. Adoption
of the reproducible profile changes production measurements on the next build.

Inspect the result after all jobs finish:

```sh
gh run watch <run-id> --repo tempoxyz/tempo --exit-status
gh run download <run-id> --repo tempoxyz/tempo \
  -n reproducible-prover-eif-verification -D eif-verification
jq -e '.comparison_result == "success" and
       .builds.depot.measurements == .builds.docker.measurements' \
  eif-verification/manifest.json
```

Success requires valid, unsigned EIFs with identical PCR0/PCR1/PCR2. These
measurements are outputs, not input pins. The manifest records both EIF SHA-256
values and `byte_identical` separately; unmeasured EIF metadata can differ without
changing the PCRs. It also records the source, trusted recipe and shared workflow
commits, toolchain digest and genesis checksum. The two raw `describe-eif` reports
are included for inspection.

Artifacts `reproducible-prover-eif-verification-depot` and
`reproducible-prover-eif-verification-docker` contain the actual `enclave.eif`
files. All verification artifacts expire after seven days. A skipped job is not
verification. Matching PCRs require the production source, genesis bytes, recipes
and toolchain digest; the comparison does not perform runtime Nitro attestation.
Normal image publishing is skipped for the verification dispatch.

For a local rebuild on Linux x86-64 with Docker/Buildx, Git, jq and registry access,
check out `source_sha`, initialize submodules, and overlay the five files listed
in `build_definition_paths` from `build_definitions_sha`. Download the genesis
file and verify its recorded SHA-256, then run:

```sh
EIF_BUILDER_IMAGE=$(jq -r .eif_builder_image eif-verification/manifest.json) \
BUILD_INPUT_FILE=/tmp/prover-genesis.json \
NO_CACHE=1 OUT_DIR=/tmp/prover-eif zones/scripts/reproducible-eif-build.sh
docker run --rm --platform linux/amd64 --network none \
  -v /tmp/prover-eif:/input:ro \
  "$(jq -r .eif_builder_image eif-verification/manifest.json)" \
  describe-eif --eif-path /input/enclave.eif
```
