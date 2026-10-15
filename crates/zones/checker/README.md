# zone-checker

An observe-only bridge-accounting checker that runs as a Reth execution
extension (ExEx) inside a Tempo Zone node. It independently derives token
balances and bridge liabilities from authenticated protocol activity, then
compares them with exact Zone and Tempo state.

See [DESIGN.md](DESIGN.md) for the accounting model and block invariants.

## What it verifies

For every canonical Zone block, the checker independently derives:

- TIP-20 entitlements for every account named by authenticated transfer and
  bridge events.
- Each enabled token's expected Zone supply from those entitlements.
- Portal liabilities for circulating supply, pending deposits, pending
  withdrawals, and pending refunds.
- The recipient and amount of every Inbox mint from its authenticated bridge
  lifecycle event.
- Every user withdrawal's exact TIP-20 debit and burn, including sponsored
  fees.

Canonical Portal creation and enablement events establish which tokens the
checker tracks. Membership in the accounting token map is the authenticated
enablement record; other accounting effects cannot introduce tokens.

Beyond establishing membership, token enablement is not otherwise modeled: the
checker does not compare L1 and L2 enablement calldata or validate token metadata
and Inbox/Outbox issuer roles.

The accounting model also does not correlate individual L1 deposits with L2
outcomes by deposit hash or authenticate cross-layer withdrawal batch identity.
Those protocol events are still strictly decoded, but only value movements that
affect the aggregate solvency model are retained. Genesis bridge cursors are
checked only to establish the empty bootstrap baseline.

It then reads affected balances and every enabled token's supply from the exact
Zone post-state and reads Portal custody at the exact imported Tempo block. The
required invariants are:

```text
Zone balance(account, token) == derived entitlement(account, token)
Zone totalSupply(token)      == sum of derived entitlements(token)
Portal custody(token)        >= supply + deposits + withdrawals + refunds
```

The checker reads all enabled-token supplies every block and reads balances for
accounts touched by that block. Its durable entitlement ledger carries earlier
accounts forward and verifies their aggregate against total supply. It does not
scan arbitrary Zone storage changes or reread every historical account balance
on every block.

Tempo consensus and execution are trust boundaries. For live blocks, the checker
reuses Portal logs whose receipts and headers the node's L1 subscriber already
authenticated. It independently decodes those logs and verifies the exact block
and parent coordinates. Bootstrap and old recovery ranges fall back to fetching
and authenticating the same evidence from the configured archival Tempo RPC. It
does not re-execute Tempo. Zone post-state is read through Reth's exact-block
storage provider.

Checkpoint-only blocks must contain only `advanceTempoHeaders` and its successful
`TempoBlockFinalized` event. They advance the verified Zone height and verify
unchanged token supply, while retaining the last full import's accounting state
and Tempo custody anchor. The next full import authenticates every Tempo block
since that anchor and applies their Portal events in order before its Zone
events. This includes deposits and token enablements deferred across any number
of checkpoint-only blocks. The retained accounting anchor survives restarts;
`imported_tempo_height` reports that anchor rather than header-only progress.

## Startup and recovery

With `--checker.mode observe`, startup is self-contained:

1. Read the Zone ID, Portal, chain ID, and node data directory from the normal
   node configuration.
2. Read the Tempo anchor, bridge cursors, initial token, and supply from exact
   local Zone genesis state, rejecting a genesis with prior bridge progress.
3. Discover the unique matching `ZoneCreated` through Tempo's log index, then
   authenticate its canonical block, receipts, Zone identity, Portal, and
   initial token.
4. Require the genesis anchor to precede Portal creation and initialize empty
   accounting. Normal Zone replay then derives token membership when it reaches
   the creation block.
5. Create `<node datadir>/checker` atomically if it is missing, or validate and
   open it if it exists.
6. Ask Reth to replay canonical Zone history after the durable verified tip.

The database is created in `<node datadir>/checker`; no separate checkpoint
command is required. An existing database is opened only when its Zone, Tempo,
Portal, and creation identity matches the authenticated bootstrap result.

MDBX stores current nonzero account rows, per-token accounting, metadata, and
the active finding. Storage therefore scales with the current number of nonzero
derived entitlements rather than Zone history. Zones are append-only; if the
saved checker tip is absent from local Zone history or Reth reports an
unexpected revert, the checker atomically resets to authenticated genesis and
replays local history.

On normal restart, Reth replays notifications after the last durably verified
Zone block. Each block transition is persisted before the ExEx acknowledges its
height.

## Failure behavior

Temporary Tempo RPC or local-state acquisition failures retry without advancing
or acknowledging the block. Each retry budget is bounded. Tempo retries use
exponential backoff, while unavailable local Zone state retries once per second.
Pruned state disables immediately because it cannot recover.

Tempo RPC codes `-32001` (resource not found), `-32002` (resource unavailable),
and `-32603` (internal error) are retried regardless of message text.

A deterministic mismatch records one durable finding, freezes the verified tip,
and continues acknowledging subsequent notifications while recording how far the
unchecked range extends. A finding remains active until the checker is rebuilt
from authenticated genesis.

An exhausted retry budget or an unrecoverable checker-local error disables the
checker and drains ExEx notifications so it cannot terminate or stall Zone
execution. Verification then stays disabled for the life of the process; since
the checker runs as an ExEx inside the node, restarting the node attempts to
resume from the last durably verified Zone block. Observe mode never changes
block execution or consensus behavior; operators must alert on lag or an active
divergence.

The node's existing metrics endpoint exports:

- `reth_tempo_zone_checker_verified_zone_height`
- `reth_tempo_zone_checker_imported_tempo_height`
- `reth_tempo_zone_checker_observed_zone_height`
- `reth_tempo_zone_checker_verification_lag_blocks`
- `reth_tempo_zone_checker_divergence_active`
- `reth_tempo_zone_checker_disabled`
- `reth_tempo_zone_checker_acquisition_retries_total`
- `reth_tempo_zone_checker_verified_zone_blocks_total`
- `reth_tempo_zone_checker_recovery_rebuilds_total`

At minimum, alert when `disabled` or `divergence_active` is `1`, verification
lag continues to grow, or the verified height stops advancing while the Zone
head advances.

### Verified activity logs

After a Zone block is durably verified, the checker emits structured
`zone::checker` INFO logs for authenticated bridge activity. Zero-value Portal
refund claims are accounting no-ops and are omitted. Within that block,
`authenticated` denotes canonical protocol evidence, `accounted` denotes a
ghost-liability change, and `verified` denotes additional reconciliation
against TIP-20 movements and exact post-block state.

Activity logs contain only the fields needed by log-backed activity dashboards:

- `activity_event`: the stable event name from the table below.
- `activity_id`: `v<schema_version>:<zone_hash>:<activity_source>:<activity_index>`,
  which remains stable if recovery replays the same canonical block under the
  same schema. The ID retains version `1`, the verified Zone block hash, source
  (`tempo` or `zone`), and zero-based canonical index within that source.
- `callback_success`: emitted only for `portal_withdrawal_processed`, allowing
  dashboards to distinguish successful and failed withdrawal callbacks.

The ID components are not repeated as separate fields. Activity logs omit
descriptive messages, block heights, Tempo hashes, token and account addresses,
amounts, fees, and deposit/withdrawal numbers. Kubernetes pod and namespace
metadata supplied by the log collector still identify the verifier and Zone.
Operational warnings and errors retain their diagnostic fields.

| `activity_event` | Meaning |
| --- | --- |
| `portal_deposit_accounted` | Authenticated Portal deposit entered accounting. |
| `portal_token_enabled` | Authenticated Portal token entered accounting coverage. |
| `portal_withdrawal_processed` | Authenticated Portal withdrawal and callback result. |
| `portal_withdrawal_bounce_back` | Authenticated Portal withdrawal bounce-back entered accounting. |
| `portal_deposit_bounce_back` | Authenticated processed Portal deposit bounce-back entered accounting. |
| `portal_deposit_bounce_back_pending` | Authenticated pending Portal deposit bounce-back entered accounting. |
| `portal_refund_accounted` | Authenticated Portal refund entered accounting. |
| `zone_deposit_minted` | Verified Zone deposit mint. |
| `zone_deposit_failed` | Authenticated failed Zone deposit. |
| `zone_deposit_bounce_back_requested` | Authenticated Zone deposit bounce-back request. |
| `zone_withdrawal_burned` | Verified user withdrawal debit and burn. |
| `zone_withdrawal_bounce_back_minted` | Verified Zone withdrawal bounce-back mint. |
| `zone_withdrawal_bounce_back_pending` | Authenticated pending Zone withdrawal bounce-back. |
| `zone_refund_minted` | Verified Zone refund mint. |

`activity_id` lets a log consumer deduplicate replayed activities, but logs are
still retention-bound diagnostic evidence rather than the canonical accounting
ledger.

## Modes

| Mode | Behavior |
| --- | --- |
| `off` | Default. The checker is not installed. |
| `observe` | Verify, persist findings, expose metrics, and leave Zone execution unchanged. |

Use `--checker.mode observe` or `CHECKER_MODE=observe`. The checker reuses the
node's authenticated L1 observations, Tempo RPC URL, Portal address, Zone ID,
chain specification, and data directory. No checker-specific anchor, Portal, or
database argument is needed.

## Source organization

```text
src/
  bootstrap.rs       genesis identity and authenticated Portal discovery
  l1/                shared/fallback Tempo evidence and Portal event decoding
  l2/                Zone events and exact post-state reads
  accounting/        pure account and liability transitions
  persistence/       row-oriented MDBX state and exact verified coordinates
  runtime.rs         recovery, verification, retry, and divergence handling
  telemetry.rs       operational metrics and verified-activity logs
```

## Validation

```bash
cargo test -p zone-checker
cargo clippy -p zone-checker --all-targets -- -D warnings
```
