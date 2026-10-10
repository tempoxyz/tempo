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

- Docker, release, benchmarks, and prover workflows retain distinct product
  behavior. Their legacy paths, repository guards, tag/release ownership, and
  external event/STS/AWS consumers need a coordinated migration. The Zones
  Docker build is gated to `tempoxyz/zones` until then, since its recipe still
  expects `docker/`, `crates/contracts`, and the Zones Cargo workspace. The Zones
  release workflow is gated the same way because Tempo and Zones tags share the
  `v*.*.*` namespace. Tempo already has `v0.1.0`, `v0.2.0`, and `v0.3.0`, so Zones
  releases need their own tag scheme before that gate is lifted.
- Zones reproducible builds have a separate concurrency group so they cannot
  cancel Tempo builds, and are gated to `tempoxyz/zones` because the shared recipe
  would run Tempo's `scripts/reproducible-build.sh`. Their recipe/script and Cargo
  layout still need migration.

The root Dependabot configuration also needs the final workspace layout before
retiring the imported dependency configuration.

The root Test workflow builds Earn before Zones and distributes
`crates/zones/contracts/out` to each Rust test shard. The merged
[tempoxyz/earn#365](https://github.com/tempoxyz/earn/pull/365) authorizes Tempo
through Earn’s `zones-read` STS policy.
