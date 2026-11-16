# Disabled features

Code that is still in the tree but is switched off on live networks. Most of it stays only so nodes can
replay blocks from before the fork that turned it off; a few paths have never been switched on. Each entry
says how it is turned off and what still counts as a bug there.

For security reviewers and automated scanners, a report against one of these paths is in scope only if it shows
one of:

- a way to reach it on a fork where it is turned off (the gate fails or can be bypassed);
- a historical block that replays to a different result than when it was produced;
- a way to turn on a feature that has never been enabled.

Anything else in these paths, including bugs that only mattered while the feature was live, is out of scope.

When you turn a feature off, add it here in the same pull request, with its gate and a test that asserts it.

## Retired at a hardfork

| Feature | Off from | Gate | Still reachable by |
|---|---|---|---|
| Subblocks (end-of-block subblock system transactions) | T4 | [`crates/evm/src/block.rs`](../crates/evm/src/block.rs) rejects them with `subblocks are disabled in T4+` | Replay of pre-T4 blocks |
| ValidatorConfig V1 precompile, every selector | T15 | `#[schedule(until = T15)]` on each selector in [`validator_config/dispatch.rs`](../crates/precompiles/src/validator_config/dispatch.rs) | Replay of pre-T15 blocks. Before T15, V1 writes have no effect: consensus reads only ValidatorConfigV2 once it is initialized |
| ValidatorConfigV2 `migrateValidator` and `initializeIfMigrated` (V1 to V2 migration) | T15 | `#[schedule(until = T15)]` in [`validator_config_v2/dispatch.rs`](../crates/precompiles/src/validator_config_v2/dispatch.rs) | Replay of pre-T15 blocks. V2 is already initialized on mainnet and Moderato, so both calls revert there before T15 too |
| Legacy V1 keychain signatures (user address not bound into the signature hash) | T1C | `validate_version` in [`tt_signature.rs`](../crates/primitives/src/transaction/tt_signature.rs) returns `LegacyPostT1C` | Replay of pre-T1C blocks |
| AccountKeychain `getRemainingLimit` | T3 | `#[schedule(until = T3)]` in [`account_keychain/dispatch.rs`](../crates/precompiles/src/account_keychain/dispatch.rs), replaced by `getRemainingLimitWithPeriod` | Replay of pre-T3 blocks |
| AccountKeychain `authorizeAdminKey` | T14 (live T6 to T14) | `#[schedule(since = T6, until = T14)]` in [`account_keychain/dispatch.rs`](../crates/precompiles/src/account_keychain/dispatch.rs) | Replay of T6 to T14 blocks |
| Zones `TempoState.finalizeTempo(header)` (single header) | T13 | `#[schedule(until = T13)]` in [`zones/precompiles/src/tempo_state.rs`](../crates/zones/precompiles/src/tempo_state.rs), replaced by `finalizeTempo(headers)` | Replay of pre-T13 zone blocks |

## Never enabled

| Feature | How it is off | What still matters |
|---|---|---|
| TIP-1016 state gas (storage creation outside gas limits, EIP-8037) | The execution handler passes `amsterdam = false` to `gas_params::version` in [`crates/evm/src/handler/config.rs`](../crates/evm/src/handler/config.rs); [TIP-1016](../tips/tip-1016.md) is in Backlog | The code is not dead. Any path that turns the flag on for a live network is a valid report |

## Disabled in zones

| Feature | How it is off | What still matters |
|---|---|---|
| TIP-20 rewards, public mint and burn, and admin methods on zone tokens | Rejected for every caller in [`crates/zones/precompiles/src/ztip20/mod.rs`](../crates/zones/precompiles/src/ztip20/mod.rs); the zone inbox and outbox mint and burn internally | Any public call that reaches them on a zone |
