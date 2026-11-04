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

## Workspace and CI

The root Cargo workspace now owns the imported Zones crates, prover binaries,
and lockfile. `cargo zone-xtask` runs Zones tooling; `cargo xtask` continues to run
Tempo tooling. Zones crates retain version 0.3.7 independently of Tempo.

Root lint and test jobs cover the unified workspace. The build matrix includes
Zones and prover binaries, and root nextest configuration preserves Zones’
integration-test concurrency limits. Imported lint/test/build workflows are retired.

Root Dependabot covers the shared Cargo workspace and GitHub Actions workflows,
plus Docker recipes at `/` and `/zones/docker`, each with its own one-PR limit.
The imported dependency configuration and redundant lint/Cross configs are retired.
`zones/Justfile` remains the documented local recipe collection; prover E2E rollout
documentation lives in [docs/PROVER_E2E.md](docs/PROVER_E2E.md).

The root Test workflow builds Earn before Zones and distributes
`crates/zones/contracts/out` to each Rust test shard. Earn is public, so the
workflows check it out without a token.

## Product workflow cutover

Zones releases use `zones/vX.Y.Z` tags and keep version 0.3.7 in their manifests;
Tempo uses `tempo/vX.Y.Z` tags (earlier releases used `vX.Y.Z`) and the root
workspace version. Zones release assets
use the slash-free `vX.Y.Z` version and never become the repository's latest
release. Docker recipes live under `zones/docker` and build the root workspace.
The Zones tooling image keeps its `tempo-xtask` entrypoint but contains the
`tempo-zone-xtask` executable.

Prover images (`tempo-zone-prover` and `tempo-zone-prover-utils`) are versioned
separately by `prover/vX.Y.Z` tags, which must match the `bin/prover/enclave`
version. The Prover Release workflow publishes them and drafts a release with the
enclave's PCRs and image digest; `zones/vX.Y.Z` tags no longer add version tags
to prover images.

Zones workflows no longer require repository enablement variables. External
consumers must maintain the following integrations:

| Workflow | External integration |
| --- | --- |
| CI events | Event credentials and Zones sensors accepting `event: zones_registry_package` and `repository: tempoxyz/tempo` and fetching Tempo commit SHAs. |
| Benchmarks | The benchmark runner, ClickHouse credentials for Tempo, and imported benchmark helper paths. |
| Prover benchmarks | The benchmark repository's STS policy, AWS `benchmark-runner` trust, and `scripts/zones_prover/run.sh` using Tempo checkouts, `crates/zones/contracts`, and `tempo-zone-xtask`. |

The workflows do not deploy sensors or alter AWS/Depot trust. Docker publishing,
automatic reproducible builds and prover E2E also run without enablement variables.

The Zones reproducible workflow invokes `zones/scripts/reproducible-build.sh`
with the root workspace as context. Its `zones-reproducible` profile preserves
Zones' unwind behavior while Tempo's `reproducible` profile keeps abort behavior.
The workflows retain separate concurrency groups. Independent Linux rebuilds are
still required to establish byte-for-byte reproducibility after the import.

Reproducible builds run automatically on pushes to `main`; manual dispatch
remains available. The separate profile enables SPF's `catch_unwind` recovery
for invalid MPT proofs.

The final reproducible publication pipeline from
[tempoxyz/zones#1264](https://github.com/tempoxyz/zones/pull/1264) builds and compares
complete production node image IDs before promotion, delays companion tags until
verification succeeds, and verifies archived Linux x86_64 release binaries against
an independent clean rebuild. Production and verification share the canonical
prover compiler and timestamp-normalizing EIF packager. The Docker pipeline
publishes downstream CI events on `main` without an enablement variable.
See [reproduction instructions](docs/REPRODUCIBLE_BUILDS.md).
