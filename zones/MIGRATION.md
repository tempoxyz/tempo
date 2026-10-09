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

The history-import branch has moved source files without integrating their build
configuration. Do not interpret this workflow cleanup as working Zones Rust or
publication coverage:

- `zones/Cargo.toml` still names nonexistent `zones/bin` and `zones/crates` members.
  Integrate the moved `bin/tempo-zone`, `bin/prover`, `crates/zones`, and xtask
  sources/dependencies/lockfile before adding Zones to root Cargo jobs.
- The inactive `zones/.github/workflows/{lint,test,build}.yml` remain as coverage
  references until that integration lands. Then extend the existing root jobs,
  preserve the Zones nextest concurrency limits, and retire these definitions.
- Zones Rust tests need Earn artifacts built before Zones artifacts, plus artifact
  paths remapped to `crates/zones/contracts/out`. Earn's `zones-read` STS policy
  currently permits Zones repository identities, not Tempo; it needs an upstream
  trust-policy update before those tests can authenticate here.
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
