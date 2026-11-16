# Disabled features

Code that is still in the tree but is switched off, or will be at a scheduled hardfork. Most of it stays only so
nodes can replay blocks from before the fork that turned it off; a few paths have never been switched on. Each
entry says how it is turned off and what still counts as a bug there.

A fork-gated path is off on a network only once that fork has activated there. Check the network's activation
time in [`crates/chainspec/src/genesis/`](../crates/chainspec/src/genesis/) (`presto.json` is mainnet,
`moderato.json` the testnet): until then the path is live on that network and fully in scope.

For security reviewers and automated scanners, once a path is off on every live network, a report against it is in
scope only if it shows one of:

- a way to reach it on a fork where it is turned off (the gate fails or can be bypassed);
- a historical block that replays to a different result than when it was produced;
- a way to turn on a feature that has never been enabled.

Anything else in these paths, including bugs that only mattered while the feature was live, is out of scope.

When you turn a feature off, add it here in the same pull request, with its gate and a test that asserts it. Put it
under "Retiring at an upcoming hardfork" and move it to "Retired" once the fork is active on mainnet and Moderato.

## Retired (off on mainnet and Moderato)

| Feature | Off from | Gate | Still reachable by |
|---|---|---|---|
| Subblocks (end-of-block subblock system transactions) | T4 | [`crates/evm/src/block.rs`](../crates/evm/src/block.rs) rejects them with `subblocks are disabled in T4+` | Replay of pre-T4 blocks |
| Legacy V1 keychain signatures (user address not bound into the signature hash) | T1C | `validate_version` in [`tt_signature.rs`](../crates/primitives/src/transaction/tt_signature.rs) returns `LegacyPostT1C` | Replay of pre-T1C blocks |
| AccountKeychain `getRemainingLimit` | T3 | `#[schedule(until = T3)]` in [`account_keychain/dispatch.rs`](../crates/precompiles/src/account_keychain/dispatch.rs), replaced by `getRemainingLimitWithPeriod` | Replay of pre-T3 blocks |
| TIP-20 rewards ([TIP-1075](../tips/tip-1075.md)): `distributeReward`, `setRewardRecipient` and reward accrual on balance changes | T7 (distribution and opt-in), T8 (accrual) | From T7 `distributeReward` and `setRewardRecipient` succeed as no-ops rather than reverting; from T8 transfers, mints, burns and fee refunds no longer update reward accumulators ([`tip20/rewards.rs`](../crates/precompiles/src/tip20/rewards.rs)) | Replay of pre-T8 blocks. `claimRewards` stays live for already-settled balances, so a claim that pays more than the settled balance, or pays twice, is a valid report |
| Zones `TempoState.finalizeTempo(header)` (single header) | T13 | `#[schedule(until = T13)]` in [`zones/precompiles/src/tempo_state.rs`](../crates/zones/precompiles/src/tempo_state.rs), replaced by `finalizeTempo(headers)` | Replay of pre-T13 zone blocks |

## Retiring at an upcoming hardfork (still live on mainnet and Moderato)

These gates exist in code, but their fork has no activation time on mainnet or Moderato yet. Until it does, treat
them as live code: every bug in them is in scope on those networks.

| Feature | Off from | Gate | Until the fork activates |
|---|---|---|---|
| Admin access keys ([TIP-1137](../tips/tip-1137.md)): `authorizeAdminKey`, inline `is_admin` key authorizations, and admin powers of stored admin keys | T14 (live since T6) | `#[schedule(since = T6, until = T14)]` on `authorizeAdminKey` in [`account_keychain/dispatch.rs`](../crates/precompiles/src/account_keychain/dispatch.rs); `authorize_admin_key` rejects from T14 (inline authorizations go through it), and loading a key clears `is_admin` from T14 in [`account_keychain/mod.rs`](../crates/precompiles/src/account_keychain/mod.rs) | Fully live. After T14: replay of T6 to T14 blocks, and keys stored as admin still sign, as regular access keys without limits, so that path is live: any way for one to pass `isAdminKey`, `verifyKeychainAdmin` or a key-management check is a valid report |
| ValidatorConfig V1 precompile, every selector | T15 | `#[schedule(until = T15)]` on each selector in [`validator_config/dispatch.rs`](../crates/precompiles/src/validator_config/dispatch.rs) | Fully live. V1 writes have no effect on consensus, which reads only ValidatorConfigV2 once it is initialized, but any way they could is in scope. After T15: replay of pre-T15 blocks |
| ValidatorConfigV2 `migrateValidator` and `initializeIfMigrated` (V1 to V2 migration) | T15 | `#[schedule(until = T15)]` in [`validator_config_v2/dispatch.rs`](../crates/precompiles/src/validator_config_v2/dispatch.rs) | Live, but V2 is already initialized on mainnet and Moderato, so both calls revert there. After T15: replay of pre-T15 blocks |

## Never enabled

| Feature | How it is off | What still matters |
|---|---|---|
| TIP-1016 state gas (storage creation outside gas limits, EIP-8037) | The execution handler passes `amsterdam = false` to `gas_params::version` in [`crates/evm/src/handler/config.rs`](../crates/evm/src/handler/config.rs); [TIP-1016](../tips/tip-1016.md) is in Backlog | The code is not dead. Any path that turns the flag on for a live network is a valid report |

## Disabled in zones

| Feature | How it is off | What still matters |
|---|---|---|
| TIP-20 rewards, public mint and burn, and admin methods on zone tokens | Rejected for every caller in [`crates/zones/precompiles/src/ztip20/mod.rs`](../crates/zones/precompiles/src/ztip20/mod.rs); the zone inbox and outbox mint and burn internally | Any public call that reaches them on a zone |
