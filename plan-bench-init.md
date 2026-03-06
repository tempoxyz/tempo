# Plan: Separate Bench Init from Bench Run

## Problem

Every CI run wastes time on setup that's already been done:

1. **Genesis generation** (~30s): `cargo run -p tempo-xtask -- generate-genesis` — built from scratch every run because `actions/checkout` wipes `localnet/`
2. **Bloat file generation** (~2-5 min for 1024 MiB): `cargo run -p tempo-xtask -- generate-state-bloat` — same reason
3. **DB init + bloat load** (~2-3 min): `tempo init` + `init-from-binary-dump` — only runs on first invocation (when schelk virgin has no db), but genesis/bloat generation still happens every time

The virgin snapshot on schelk persists across runs. Once initialized, `needs_init=false` skips step 3. But steps 1-2 are re-executed every run because their outputs live in the workspace.

## Approach

Follow reth's pattern: use a **metadata marker** to track what's in the virgin snapshot. Store it at `$HOME/.tempo-bench-meta.json` (survives both checkout wipes and schelk operations). The bench command checks the marker and skips init entirely if the snapshot matches the requested config.

### Metadata Marker

```json
{
  "bloat_mib": 1024,
  "genesis_hash": "sha256 of genesis.json",
  "accounts": 1001,
  "initialized_at": "2026-03-06T09:00:00Z"
}
```

Stored at: `$HOME/.tempo-bench-meta.json`

Additionally, persist **genesis.json** and **state_bloat.bin** on the schelk volume itself at `/reth-bench/.bench-meta/` so they're available for node startup (the node needs genesis.json as `--chain` arg) without rebuilding `tempo-xtask`.

### New Command: `main bench-init`

```
nu tempo.nu bench-init --bloat 1024 --accounts 1001 [--force] [--bench-datadir /reth-bench]
```

Does:
1. Build `tempo-xtask` (from current tree or specified ref)
2. Generate genesis → save to `/reth-bench/.bench-meta/genesis.json`
3. Generate bloat file → save to `/reth-bench/.bench-meta/state_bloat.bin`
4. `tempo init --chain <genesis> --datadir <datadir>`
5. `tempo init-from-binary-dump --chain <genesis> --datadir <datadir> <bloat_file>`
6. `schelk promote` (save as virgin)
7. `schelk mount` (remount for subsequent use)
8. Write metadata marker to `$HOME/.tempo-bench-meta.json`

`--force` skips the marker check and re-initializes.

### Modified `main bench` (comparison mode)

Current init block (~lines 1259-1324) becomes:

```
1. Read metadata marker from $HOME/.tempo-bench-meta.json
2. If marker exists AND marker.bloat_mib == $bloat AND marker.accounts == $accounts:
   a. Copy genesis from /reth-bench/.bench-meta/genesis.json → localnet/genesis.json
      (node needs it as --chain arg during bench runs)
   b. Skip bloat generation, skip db init, skip promote
   c. bench-mount (ensure volume is mounted)
   d. Print "Using existing virgin snapshot (initialized at <date>)"
3. Else:
   a. Run full init (current behavior) or error with "Run bench-init first"
```

### Workflow Changes

Add a conditional init step before the bench run:

```yaml
- name: Check if snapshot needs init
  id: snapshot-check
  run: |
    META="$HOME/.tempo-bench-meta.json"
    if [ -f "$META" ]; then
      CURRENT_BLOAT=$(jq -r '.bloat_mib' "$META")
      if [ "$CURRENT_BLOAT" = "$BENCH_BLOAT" ]; then
        echo "needed=false" >> "$GITHUB_OUTPUT"
        echo "Snapshot already initialized (bloat=${CURRENT_BLOAT} MiB)"
        exit 0
      fi
    fi
    echo "needed=true" >> "$GITHUB_OUTPUT"

- name: Initialize snapshot
  if: steps.snapshot-check.outputs.needed == 'true'
  run: |
    nu tempo.nu bench-init --bloat "$BENCH_BLOAT" --bench-datadir /reth-bench
```

## What Changes

| File | Change |
|------|--------|
| `tempo.nu` | Add `main bench-init` command |
| `tempo.nu` | Modify comparison mode in `main bench` to check metadata marker and skip init |
| `.github/workflows/bench.yml` | Add snapshot check + conditional init step before bench run |

## What Doesn't Change

- B-F-F-B loop, `run-bench-single`, `generate-summary` — untouched
- `bench-recover`, `bench-mount`, `bench-promote` — untouched (bench-init calls them)
- Local workflow (`tempo.nu bench --baseline X --feature Y`) — still works, auto-inits if needed
- Binary caching via MinIO — unrelated, stays as-is

## Edge Cases

1. **Bloat size changes**: Marker has `bloat_mib`. If user requests different bloat, marker won't match → re-init.
2. **Genesis format changes**: If a commit changes genesis structure, the cached genesis is stale. The marker includes `genesis_hash` but this only catches changes within the same binary. Cross-commit genesis changes require `--force` or a smarter invalidation (e.g., hash the genesis generator source — probably overkill, `--force` is fine).
3. **Schelk virgin manually wiped**: The metadata marker at `$HOME/` will say "initialized" but the volume is empty. Fix: `bench-init` also checks that `$datadir/db` exists on the mounted volume as a sanity check.
4. **Multiple concurrent runs**: Not an issue — `BENCH_RUNNERS: 1`, and each runner has its own `$HOME`.

## Expected Speedup

| Step | Before (every CI run) | After (steady state) |
|------|-----------------------|---------------------|
| Genesis generation | ~30s (build xtask + generate) | 0s (copy from volume) |
| Bloat file generation | ~2-5 min | 0s (already on volume) |
| DB init + load | 0s (needs_init=false) | 0s (same) |
| Promote | 0s (needs_init=false) | 0s (same) |
| **Total init overhead** | **~3-6 min** | **~0s** |

First run after bloat size change still pays the full cost.
