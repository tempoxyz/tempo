# Zones integration notes

Imported from `tempoxyz/zones` revision `d2687681`. The existing Tempo workspace is
canonical: there is one root Cargo manifest, dependency graph, and lockfile.
Zone crate sources live in `crates/zones/<name>`, the node in `bin/tempo-zone`, and
prover binaries in `bin/prover`. Support files live here; no second repository,
Cargo workspace, license set, or independent CI configuration is embedded here.

Run commands from the Tempo repository root. `cargo xtask zones <command>` and
`tempo-xtask zones <command>` dispatch zone tooling. Recipes use
`just zones::<recipe>`; generated zone metadata (including local keys) lives in
`zones/generated/`. Move existing `generated/` deployments there explicitly when
switching checkouts. Existing node datadirs and chain state are not migrated by
this source import.

Zone binary package versions remain independently specified at `0.3.5`; Tempo's
workspace version does not control Zone releases. Zone releases use
`zones-v<version>` tags in `tempoxyz/tempo`, separate from Tempo tags. Build Docker
images from the repository root using `zones/docker/docker-bake.hcl`; paths in
that file and Docker COPY directives are root-relative. The zone tooling image
adds `zones` to its entrypoint, so its caller still passes the zone subcommand.
The `zones-reproducible` Cargo profile preserves panic unwinding independently of
Tempo's aborting reproducible profile. Both use the shared root lockfile.

The benchmark scripts resolve the shared repository root from their own location.
Both `TEMPO_XTASK_BIN` and `ZONES_XTASK_BIN` can point to the same root-workspace
binary; the latter is invoked with `zones`. `TEMPO_ROOT` remains explicit for
benchmark baseline selection. The benchmark uses the shared workspace revision
and its native mnemonic-file support.
The L1 snapshot cache fingerprints the current genesis and state-bloat tooling.

## External operational cutover

Merging source does not transfer service configuration. Operators must update
GitHub repository permissions/environments/secrets, Depot OIDC allowlists and
projects, GHCR package publishing access, reusable workflow recipe paths, docs
hosting, and deployment automation to `tempoxyz/tempo` and the zone workflow/tag
namespace. Registry image names remain zone-specific. Update pinned release
URLs and tags in downstream consumers and verify published artifacts before
switching production jobs. Existing Nitro PCR measurements and verifier
allowlists require a newly built EIF and independent verification; relocation
alone does not preserve reproducible hashes or authorize an enclave measurement.

Local developer metadata, standalone workspace manifests/locks, duplicate
licenses, workflows, Nix workspace configuration, and nonexistent docs-site
recipes were omitted. Markdown documentation and specs are retained here.

Earn-backed Rust tests and benchmarks mint a token using Earn's `zones-read` STS
policy. Before enabling these jobs, Earn maintainers must allow Tempo's immutable
repository identity (`repo:tempoxyz@211589300/tempo@994992847`) in
`.github/sts/zones-read.sts.yaml`; the existing policy only allows the Zones
repositories. The migration preserves the required Earn tests; token failure
remains a failing check until that external policy is updated.

Contract tests now share the patched Forge artifact from Tempo's Specs workflow
and test against the current local Tempo crates. Prover E2E publication remains
manually dispatched until its external sensor/templates are updated for Tempo.
