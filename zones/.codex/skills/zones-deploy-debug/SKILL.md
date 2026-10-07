---
name: zones-deploy-debug
description: Deploy Tempo Zones, start zone nodes, validate router swap-and-deposit flows, and debug zone sync, portal ingestion, withdrawal, sequencer key, and generated zone artifact issues in this repository. Use when working with just deploy-zone, zone-up, deploy-router, demo-swap-and-deposit, or generated/<name>/zone.json.
---

# Zones Deploy Debug

Use this skill for repo-local zone deployment, smoke tests, and sync debugging.

## Start here

1. If the zone already exists, read `generated/<name>/zone.json` first.
2. For real smoke tests, prefer `release` for `tempo-zone`.
3. Use the `Justfile` and `docs/ZONES.md` as the source of truth for user-facing commands.
4. Read `references/commands.md` for concrete command patterns and troubleshooting checks.

## Preferred workflow

1. Build `tempo-zone` in release before judging sync speed.
2. Deploy a fresh zone if you need a clean test surface.
3. Start the zone node and confirm `http://localhost:8546` is answering.
4. For a direct bridge smoke test, run `just max-approve-portal`, `just send-deposit`, `just max-approve-outbox`, then `just send-withdrawal`.
5. Deploy the router for that zone.
6. Run the same-zone swap-and-deposit demo.
7. If the demo stalls, compare the L1 block of the relevant tx with the latest `l1_block=` in the zone log before assuming the router flow is broken.

## What to inspect

- `generated/<name>/zone.json`
- `Justfile`
- `docs/ZONES.md`
- `/tmp/tempo-zone-<name>*/logs/*/reth.log`

## Known sharp edges

- Fresh `dev` nodes can look broken because they are still compiling and replaying L1; use `release` for meaningful validation.
- Direct deposit/withdraw validation needs both approvals: `just max-approve-portal` before depositing and `just max-approve-outbox` before withdrawing.
- Admin-only portal calls (`enable-token`, deposit pause/resume, and demos that enable temporary tokens) need `ADMIN_KEY` or a saved `adminKey`; `SEQUENCER_KEY` only works on zones where admin equals sequencer.
- The demo's first real wait point is token enablement on L2. If the zone is still replaying older L1 blocks, `demo-swap-and-deposit` can time out before the `TokenEnabled` event appears.
- The current `just demo-swap-and-deposit` recipe takes optional overrides positionally, not as `amount=... tick=...`.
- If a restarted zone crashes while seeding `transferPolicyId` for a temporary token, check `crates/tempo-zone/src/l1_state/tip403/cache.rs` and consider retesting with a fresh zone.
