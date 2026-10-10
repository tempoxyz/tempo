# Workflow ownership after the Zones import

Repository-wide policy lives in the root workflows: `dependency-scan.yml`,
`label-pr.yml`, `pr-audit.yml`, `scan-github-actions.yml`, and
`sync-from-upstream.yml`. These apply to Tempo and Zones changes in this repository;
the imported copies are redundant. The fork sync continues to follow Tempo.
The old Zones-to-Tempo runtime-sync publisher is retired with the cross-repository
workflow; this does not establish that embedded runtime bytecode is up to date.

`zones-contracts.yml` covers `crates/zones/contracts`: builds and deployment sizes,
formatting, tests, symbolic properties, coverage thresholds, and the ZonePortal
storage-layout compatibility check. The latter is now part of the contracts
success gate. Root `.gitmodules` owns the imported Solidity dependencies. Tempo's
`specs.yml` still tests `tips/verify` with its own Foundry/Tempo revisions.

## Remaining migration prerequisites

The root Cargo workspace now owns the imported Zones crates, prover binaries,
and lockfile. `cargo zone-xtask` runs Zones tooling; `cargo xtask` continues to run
Tempo tooling. Zones crates retain version 0.3.5 independently of Tempo.

Root lint and test jobs cover the unified workspace. The build matrix includes
Zones and prover binaries, and root nextest configuration preserves Zones’
integration-test concurrency limits. Imported lint/test/build workflows are retired.

The remaining workflow and publication prerequisites are:


The root Dependabot configuration also needs the final workspace layout before
retiring the imported dependency configuration.

The root Test workflow builds Earn before Zones and distributes
`crates/zones/contracts/out` to each Rust test shard. The merged
[tempoxyz/earn#365](https://github.com/tempoxyz/earn/pull/365) authorizes Tempo
through Earn’s `zones-read` STS policy.

## Product workflow cutover

Zones releases use `zones/vX.Y.Z` tags and keep version 0.3.5 in their manifests;
Tempo keeps `vX.Y.Z` tags and the root workspace version. Zones release assets
use the slash-free `vX.Y.Z` version and never become the repository's latest
release. Docker recipes live under `zones/docker` and build the root workspace.
The Zones tooling image keeps its `tempo-xtask` entrypoint but contains the
`tempo-zone-xtask` executable.

External consumers must be migrated before enabling the corresponding repository
variable (each is disabled unless set to `true`):

| Variable | Required external cutover |
| --- | --- |
| `ZONES_PUBLISH_ENABLED` | Authorize Tempo in Depot project `0c6tg19qsp`, transfer GHCR/Docker Hub package access and secrets, and verify the prover genesis/artifact consumers against the new workflow paths. |
| `ZONES_EVENTS_ENABLED` | Transfer event credentials and update `registry_package` sensors to accept `repository: tempoxyz/tempo` and fetch Tempo commit SHAs. |
| `ZONES_BENCHMARK_ENABLED` | Provision the benchmark runner and ClickHouse credentials for Tempo, and verify the imported benchmark helper paths. |
| `ZONES_PROVER_BENCHMARK_ENABLED` | Update the benchmark repository's STS policy and AWS `benchmark-runner` trust, and migrate `scripts/zones_prover/run.sh` to Tempo checkouts, `crates/zones/contracts`, and `tempo-zone-xtask`. |
| `ZONES_PROVER_E2E_ENABLED` | Deploy the prover event sensor and pinned templates for Tempo commit/status ownership, workflow filenames, and imported source paths; transfer event credentials. |

The gates deliberately separate repository changes from external cutover. These
PRs do not deploy sensors, alter AWS/Depot trust, or enable publishing variables.

The Zones reproducible workflow invokes `zones/scripts/reproducible-build.sh`
with the root workspace as context. Its `zones-reproducible` profile preserves
Zones' unwind behavior while Tempo's `reproducible` profile keeps abort behavior.
The workflows retain separate concurrency groups. Independent Linux rebuilds are
still required to establish byte-for-byte reproducibility after the import.
