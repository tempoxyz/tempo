# Zones in Tempo

Zones was imported from `tempoxyz/zones` at
`d48214a6110b33e9be6d35dfd4e3729541a2378a` (2026-10-06).
Every original path is under `zones/`. Crate names, public APIs, dependency
revisions, lockfile, Solidity sources, and the internal directory layout are
preserved. This is a source import, not a Git submodule of the Zones repository.
The original history remains available from `tempoxyz/zones`.

## Working on Zones

From the Tempo repository root:

```sh
git submodule update --init --recursive -- \
  zones/crates/contracts/lib/forge-std \
  zones/crates/contracts/lib/tempo-std
cd zones
cargo build --locked --bin tempo-zone
cargo test --locked -p zone-primitives
cargo +nightly fmt --all -- --check
```

Run the existing `cargo`, `just`, Forge, Docker, and script commands from
`zones/`. Select `zones/` as the project directory for agent setup and Amp
services as well. Its `.cargo/config.toml`, `.config/nextest.toml`, `Justfile`, build
profiles, and `target/` remain local to that workspace. For example:

```sh
cargo xtask --help
forge build --root crates/contracts --skip test
# Build context is zones/, not the parent Tempo directory.
docker build -f docker/Dockerfile.chef .
```

Tempo and Zones intentionally remain separate Cargo workspaces. Both have a
`tempo-xtask` package; Zones also pins a different Tempo/Reth dependency revision.
A root `cargo test --workspace` only tests Tempo. Keeping these boundaries avoids
mixing dependency upgrades and API changes into the repository move. Use `cd
zones` rather than only `--manifest-path` so Cargo loads the Zones configuration.

Solidity dependencies remain Git submodules, registered in the root
`.gitmodules`. The imported `zones/.gitmodules` is retained for patch portability;
Git reads the root file. If a port changes a submodule declaration, update the
root file too, with the `zones/` prefix. Existing pinned gitlinks are unchanged.

## Moving an open PR

Start a branch from the Tempo commit containing this import. For a squash-style
transfer, download a PR diff and apply the single path prefix from the repository
root (replace `123` with the PR number):

```sh
gh pr diff 123 --repo tempoxyz/zones > ../zones-pr-123.patch
git apply --check --directory=zones ../zones-pr-123.patch
git apply --index --directory=zones ../zones-pr-123.patch
git diff --cached
```

To retain individual commits and authors, fetch the original history first:

```sh
git remote add zones-source https://github.com/tempoxyz/zones.git
git fetch --no-tags zones-source main pull/123/head:zones-pr-123
base=$(git merge-base zones-source/main zones-pr-123)
git format-patch --stdout "$base"..zones-pr-123 > ../zones-pr-123.mbox
git am --3way --directory=zones ../zones-pr-123.mbox
```

Add the remote only once. `--no-tags` keeps the original Zones release tags out
of Tempo's tag namespace. For a stacked PR, port its base PR first and use that
PR's original branch as the merge-base input instead of `zones-source/main`.
Resolve ordinary upstream drift in the same files, then `git am --continue`;
`git am --abort` cancels a failed transfer. Fetching the source history supplies
the original blobs used by three-way application.

Use the fetched-history route for binary changes; a GitHub PR diff may omit
applicable binary data. `git format-patch` omits merge commits, so PRs containing
merges need deliberate flattening or reconstruction before replay.

Changes to `.github/workflows/*`, `.github/CODEOWNERS`, or
`.github/dependabot.yml` need a second step: port them to the active equivalents
in Tempo's root `.github/`, adjusting action paths as well as shell working
directories. GitHub does not execute nested workflows. Do not rename crates,
move internal modules, format unrelated source, or replace the pinned
Tempo/Reth dependencies while transferring PRs.

## CI and operational cutover

The root `zones-*.yml` workflows validate Zones separately. The original
`zones/.github/` tree is retained as the reference for existing CI PRs and for
operational cutover. Root CODEOWNERS and Dependabot cover the imported paths.

This import does not switch production release automation, container publishing,
benchmark infrastructure, runtime-sync bots, hosted documentation, or repository
settings away from `tempoxyz/zones`. Before retiring that repository, migrate the
corresponding workflows and repository/OIDC policies, select a Zones-specific tag
namespace to avoid Tempo's `v*` release triggers, and verify the new workflows in
GitHub. Earn integration tests are currently blocked: the live
[`tempoxyz/earn` read policy](https://github.com/tempoxyz/earn/blob/main/.github/sts/zones-read.sts.yaml)
does not accept Tempo's immutable OIDC subject. Its read-only subject allowlist
needs the following alternative while retaining the existing Zones entries:

```text
repo:tempoxyz@211589300/tempo@994992847:((ref:refs/heads/.+)|pull_request)
```

Have the Earn maintainers review this access change, then verify token minting,
Earn checkout, and tests before making `zones test success` a required check.
The original `zones-read` policy keeps `contents: read`; no policy was changed
as part of this import. Zones build metadata now reflects Tempo's enclosing Git
SHA/tags; check version detection when moving release automation. Keep the original repository available
until those external services and open PRs have moved.
