---
id: TIP-XXXX
title: Protocol Feature Rollout and Activation
description: Defines a source-controlled protocol feature model that lets Tempo ship reviewed TIP behavior independently from named hardfork bundles.
authors: Emma (@emmajam)
status: Draft
related: N/A
protocolVersion: TBD
---

# TIP-XXXX: Protocol Feature Rollout and Activation

## Abstract

This TIP sets up a cleaner way for Tempo to ship protocol features. Instead of making every behavior change live inside a named hardfork bundle, each feature gets its own reviewed record with an ID, owner, TIP link, dependencies, activation metadata, and generated artifacts for `tempo`.

The first rollout does not change chain behavior. `tempo` still uses the existing hardfork schedule, and `TempoHardfork` remains the way we decide what is active.

## Motivation

Tempo currently ships protocol behavior in hardfork bundles such as T1, T2, T3, and T4, and those bundles are tied to `tempo` releases. That means a named hardfork becomes the main way to activate protocol behavior, even when a TIP is small, independent, or safer to roll out on its own.

That has a few problems:

- unrelated TIPs are bundled into one activation boundary
- small protocol-behavior changes still need hardfork activation coordination
- code release and protocol activation happen at the same time, so rolling upgrades are harder than they need to be
- `tempo` code tends to accumulate broad `is_tN()` gates instead of feature-specific checks
- operators and integrators cannot easily inspect which protocol features are active without knowing the hardfork bundle contents
- approval and activation are not easy to inspect as data

This TIP introduces a feature model so we can review, ship, observe, and eventually activate TIP behavior without always waiting for the next hardfork bundle.

It also separates shipping code from activating behavior. `tempo` can release binaries that include inactive TIP implementations, operators can upgrade over a rollout window, and the feature can activate only after the relevant operators are running a `tempo` version that supports it. Nodes do not need to run the same exact release, but any node validating blocks after activation needs a release that understands every active feature.

The near-term goal is release-free activation for features already supported by the running `tempo` version. Scheduling and cancellation may stay tied to reviewed repo changes at first, and can become release-free in a later phase.

This is not per-node feature flagging where each operator picks their own behavior. A protocol feature is a network-level rule. For a given chain and activation data, `tempo` nodes need to calculate the same active feature set.

## Assumptions

- `tempo` can add the feature-query interface before we change how activation works.
- For a given chain, timestamp, and activation record, all nodes should get the same answer.
- A TIP implementation can ship in a `tempo` release before that feature is active.
- Activation is only safe once validators, RPC operators, builders, and other operators that need to follow the new rules are running a `tempo` version that supports the feature. The manifest records that requirement as `min_tempo_version`.
- Feature records can live in Git and go through normal review.

---

# Specification

## Definitions

### Protocol feature

A protocol feature is one named unit of protocol behavior. Each feature has a stable ID.

Feature IDs should:

- be globally unique
- be lowercase ASCII
- use dot-separated namespaces
- stay stable after publication
- identify behavior, not implementation location

Examples:

```text
t1.expiring_nonce
t2.nonce_key_gas
t3.address_registry_precompile
t4.no_subblock_metadata_tx
```

### Feature set

A feature set is the list of protocol features active for a given block or simulation. `tempo` can query it like this:

```rust
features.is_active(ProtocolFeature::T3AddressRegistryPrecompile)
```

Over time, feature checks should replace broad hardfork checks. Existing `is_t1()`, `is_t2()`, `is_t3()`, and similar methods stay around until the migration is done.

### Activation source

An activation source is where `tempo` gets the answer for which features are active.

The initial activation source is the existing hardfork schedule:

```text
chain + timestamp -> TempoHardfork -> FeatureSet
```

## Repository boundaries

Protocol execution code stays in `tempo`. Feature records, review metadata, and the review UI live in `tempo-protocol-features`.

### `tempo`

`tempo` owns the code that affects execution:

- `ProtocolFeature`
- `FeatureSet`
- the legacy `TempoHardfork` to `FeatureSet` mapper
- activation source reading and validation
- EVM, precompile, transaction-pool, RPC simulation, and observability integration
- tests proving hardfork behavior is preserved

`tempo` does not own reviewed feature records, approval metadata, or the feature review UI.

### `tempo-protocol-features`

`tempo-protocol-features` owns the records and tooling around feature rollout:

- feature IDs
- TIP links
- owners and approvers
- dependencies
- activation groups
- legacy hardfork mappings
- minimum `tempo` versions
- activation metadata
- manifest hashes
- the `app/` feature review UI

`tempo-protocol-features` does not own protocol execution logic.

A feature manifest can say when behavior is ready to activate, but the behavior itself is implemented and reviewed in `tempo`. The UI can help review feature rollout, but it is not where protocol activation is decided.

During the first rollout, `tempo` can define `ProtocolFeature` and the legacy mappings directly while `tempo-protocol-features` mirrors the same records as the feature catalog. Later, `tempo` should consume generated artifacts from `tempo-protocol-features` instead of hand-maintaining duplicated feature metadata.

## Release and activation separation

Feature-gated TIP code can ship in `tempo` before it is active on any production network.

Shipping inactive code is not activation. A shipped feature should not affect block validity, transaction validity, state transitions, or RPC simulation results until that feature is active for the chain and block being evaluated.

This allows `tempo` releases to include multiple TIP implementations without requiring all operators to move to one exact binary at one hardfork boundary. Instead, a feature can declare the minimum `tempo` version that understands it, operators can upgrade during a rollout window, and activation can be scheduled after the network is ready.

For features that affect block validity or state transitions, activation should be delayed or cancelled if the operators that validate or produce blocks after activation are not running a `tempo` version that supports the feature. If activation data marks a feature active but the running `tempo` binary does not support that feature, `tempo` should error clearly and stop following that activation path instead of treating the feature as inactive.

## Feature manifest

Each feature manifest entry should include:

- `id`: feature ID
- `title`: short human-readable title
- `status`: lifecycle state
- `owner`: accountable owner or team
- `tips`: one or more TIP IDs
- `dependencies`: feature IDs that must be active first, or active in the same checkpoint
- `activation_group`: optional list of feature IDs that must activate together
- `legacy.hardfork`: historical hardfork mapping, if any
- `activation`: chain- or zone-specific activation metadata
- `min_tempo_version`: minimum `tempo` version that knows the feature
- `manifest_hash`: hash of the manifest entry

Example:

```toml
[[feature]]
id = "t3.address_registry_precompile"
title = "T3 address registry precompile"
status = "legacy"
owner = "protocol"
tips = ["TIP-1022"]
min_tempo_version = "1.6.0"
dependencies = []
activation_group = []
manifest_hash = "sha256:..."

[feature.legacy]
hardfork = "T3"

[feature.activation.mainnet]
timestamp = 1777298400
```

## Feature lifecycle

Feature records should use this lifecycle:

```text
draft -> approved -> scheduled -> active
scheduled -> cancelled
active -> superseded
```

Legacy features that already shipped through a hardfork can use status `legacy`.

Status meanings:

- `draft`: proposed but not accepted
- `approved`: accepted but not scheduled
- `scheduled`: assigned activation metadata
- `active`: active on at least one production network
- `cancelled`: stopped before activation
- `superseded`: replaced by a later feature or fix
- `legacy`: already shipped through a historical hardfork

Status changes should go through review. Moving a feature to `scheduled` or `active` should require the feature owner and protocol approvers.

## Dependency rules

Feature records should hold the ordering rules. We should not rely on multisig signers or release owners remembering the right feature order by hand.

If feature `B` depends on feature `A`, then `B` should not activate unless `A` is already active for the same chain or zone, or the same checkpoint activates both.

Some changes may need to move together. Those features can list each other in `activation_group`. If a checkpoint activates one feature in the group, it needs to activate the full group for the same chain or zone and activation point.

Multisig approval is necessary for the suggested checkpoint flow, but it is not the only guard. `tempo` should validate every activation checkpoint against the generated feature records before accepting it. If a signed checkpoint tries to activate feature `C` without its required features, or only activates half of an activation group, `tempo` rejects it.

The checkpoint should reference the reviewed manifest hash. It should not carry its own alternate dependency graph that signers have to remember or audit by hand. `tempo` validates the checkpoint against the feature records for that hash.

Manifest validation should reject:

- unknown dependencies
- dependency cycles
- incomplete activation groups
- activation metadata where a dependency activates later than its dependent on the same chain or zone
- scheduled features whose minimum `tempo` version is not known by supported releases

## Generated artifacts

The feature repository should define generated artifact targets for at least:

- `tempo` Rust integration
- machine-readable JSON for dashboards, release tooling, deployment automation, monitoring, and documentation generators

Generated Rust artifacts should include:

- `ProtocolFeature`
- feature IDs
- dependencies
- activation groups
- legacy hardfork mappings
- manifest hashes

Generated JSON artifacts should include:

- feature IDs
- statuses
- TIP links
- owners
- dependencies
- activation groups
- activation metadata
- legacy hardfork mappings
- manifest hashes

During the first rollout, generated artifacts can be checked in and updated manually. Later CI should regenerate and verify artifacts from manifests.

## `tempo` interface

`tempo` should expose an internal feature-query interface:

```rust
pub enum ProtocolFeature {
    T1ExpiringNonce,
    T2NonceKeyGas,
    T3AddressRegistryPrecompile,
    T4NoSubblockMetadataTx,
}

pub struct FeatureSet { /* implementation defined */ }

impl FeatureSet {
    pub fn is_active(&self, feature: ProtocolFeature) -> bool;
}
```

The interface needs to support deriving the active feature set from the legacy hardfork schedule:

```rust
FeatureSet::from_hardfork(hardfork)
FeatureSet::from_chain_and_timestamp(chain, timestamp)
```

The legacy mapping is cumulative. If T3 is active, all features mapped to T1, T1A, T1B, T1C, T2, and T3 are active.

## Runtime integration

Execution surfaces should derive both:

- the active historical hardfork
- the active feature set

The following internal surfaces should be able to query features:

- EVM configuration
- precompile dispatch
- precompile storage context
- transaction pool validation
- RPC simulation
- internal schedule and status observability

Each surface derives the feature set from the same hardfork and timestamp source it already uses. That keeps this as an interface change, not a behavior change.

## Observability

`tempo` should define internal types for:

- feature schedule inspection
- feature status inspection

Those types should be able to answer:

- which features are active for a chain or zone at a block or timestamp
- which features are scheduled next
- which activation source produced the answer
- the manifest hash and generated artifact version being used
- the minimum `tempo` version required for scheduled features
- observed validator readiness, when that data is available
- dependencies, activation groups, and blocked reasons
- unsupported active features or invalid activation data

These types should support future RPC methods such as:

```text
tempo_featureSchedule
tempo_featureStatus
```

The first rollout should not expose a public RPC method yet. Internal types are fine so the node, UI, Grafana, release tooling, and runbooks can line up around the same data before we commit to a public API.

## Feature review UI

The `tempo-protocol-features` repository should include a UI in `app/` for reviewing and operating the feature lifecycle.

The UI should show:

- feature status, owner, TIP links, dependencies, activation groups, manifest hash, and activation metadata
- generated artifact status and validation results
- open PRs that add, update, schedule, or activate features
- review state
- current and scheduled feature sets by network and zone where relevant
- validator readiness for scheduled features that affect block validity or state transitions
- blocked reasons that prevent scheduling or activation

Validator readiness can start from the version and git SHA metrics `tempo` already exposes, such as the existing Grafana dashboards built from `reth_info`. A later phase can add stronger readiness proofs if the activation source needs them.

The UI can help users draft manifest changes and open PRs against `tempo-protocol-features`.

The UI is only an operational and review surface. It should not directly change activation state or define activation behavior separately from the source consumed by `tempo`.

## Rollback and cancellation

Rollback depends on whether the feature has activated.

Before activation, rollback is cancellation. A feature can move from `scheduled` back to `approved`, or to `cancelled`, through a reviewed PR in `tempo-protocol-features`. The activation metadata should be removed or replaced, and the UI should show the feature as blocked or cancelled.

After activation, rollback is a new protocol change. `tempo` should not silently turn off an active feature through local config or an unreviewed manifest edit, because that can split nodes on block validity or state transitions.

This is enforced in a few ways:

- production `tempo` does not expose a local config flag that changes the active protocol feature set
- activation data is read and validated by `tempo`, not applied directly by the UI
- activation data that marks an unsupported feature active causes `tempo` to error clearly instead of treating the feature as inactive

If an active feature needs to be rolled back, the rollback should be handled as one of:

- a new corrective feature that restores or changes behavior from a later activation point
- an emergency `tempo` release plus a reviewed activation record
- a network upgrade if the fix cannot be represented safely as a feature activation

The old feature record should stay in history. If a later feature replaces it, the old feature can move to `superseded`, but it should still describe what was active and when. This keeps old block execution explainable.

The feature review UI should make this distinction clear: cancelling a scheduled feature is safe review workflow, but rolling back an active feature needs a new reviewed rollout plan.

## Activation beyond hardforks

This TIP sets up the feature model, but the first rollout still uses the existing hardfork schedule for activation. Activating features without a hardfork is left for a later phase.

Before any feature activates independently from a named hardfork, a future TIP or TIP update needs to specify:

- activation source
- validation rules
- replay protection
- chain- and zone-specific behavior
- transaction pool behavior for features that change transaction validity
- RPC simulation and `eth_call` behavior for dynamic feature context
- `tempo` bootstrap behavior
- failure behavior when activation metadata is unavailable
- minimum supported `tempo` version and readiness requirements
- approval requirements
- observability requirements
- rollback or cancellation process before activation

The suggested long-term approach is a hybrid multisig-approved checkpoint model:

- feature records, review state, and readiness live in `tempo-protocol-features`
- the UI helps review the feature and prepare activation
- final activation is published as a multisig-approved checkpoint that `tempo` can verify
- the checkpoint includes feature IDs, chain or zone ID, activation block or timestamp, manifest hash, minimum `tempo` version, readiness evidence, dependency and activation-group data, multisig approval data, and replay protection
- `tempo` validates the checkpoint against the feature records before using it, so a signed but invalid checkpoint is still rejected
- later, multisig-approved checkpoints can be anchored on-chain for auditability without making an on-chain registry the first dependency

### Zones

Zones are a named requirement for Phase 6, not a follow-up after activation is designed.

Zones should be treated as explicit activation scopes. A checkpoint for Tempo L1 should not accidentally activate behavior on a Zone unless that Zone is included in the checkpoint. A Zone checkpoint should also say which L1 network or anchor it depends on. The follow-up activation design should decide which features Zones inherit from Tempo automatically and which ones need their own Zone-scoped activation, but the records should make that choice explicit.

Other activation source options are:

- **Bundled manifest artifact**: `tempo` releases include a reviewed generated schedule from `tempo-protocol-features`. This is simple and keeps activation data tied to releases, but still requires a new `tempo` release to change the schedule.
- **Multisig-approved checkpoint**: `tempo` reads an activation file and verifies approval from the configured multisig. This allows activation without a full release, but needs replay protection, multisig configuration, feature-record validation, and a clear failure mode when approvals or files are missing.
- **On-chain registry**: `tempo` reads activation state from a chain contract or system registry. This gives a strong shared source, but it is the most complex option and needs bootstrap rules for how `tempo` validates the registry before the feature system itself is live.

The implementation that reads, verifies, and applies the activation source lives in `tempo`. Source-controlled feature records and scheduled activation metadata should live in `tempo-protocol-features` unless a later TIP replaces them with another agreed protocol source.

Until then, `TempoHardfork` remains the source of historical activation behavior.

## Compatibility

This TIP is initially backward compatible.

During the first rollout:

- hardfork schedules do not change
- block validity does not change
- transaction validity does not change
- existing `is_tN()` APIs remain available
- feature queries come from existing hardfork state
- already-shipped T1 through T4 behavior maps to features at the same legacy activation points

Before activation, different `tempo` versions can run at the same time as long as they produce the same chain behavior. Once a feature activates, validators need to be running a `tempo` version that supports that feature.

Tooling that currently displays or tracks hardfork names can keep doing so. Over time, dashboards, docs, release tooling, and monitoring should prefer feature IDs because they describe the active behavior more clearly than hardfork bundle names.

The exact initial feature list lives in `tempo-protocol-features`.

## Security considerations

Feature activation can control consensus behavior, so it needs to be treated carefully.

Before hardfork-independent activation is used in production, the design needs a threat model covering:

- bad or stale activation metadata
- generated artifacts that do not match manifests
- unknown active features
- dependency mistakes
- incomplete activation groups
- activation before the required validators/operators are on a compatible `tempo` version
- activation data replayed across the wrong chain or zone
- multisig approval of a checkpoint that does not match the feature records
- validator readiness data that is missing, stale, or wrong
- UI actions that bypass review
- rollback and cancellation paths

The feature repository needs review controls. At minimum, scheduled or active feature changes require owner approval and protocol approval.

Generated artifacts should be reproducible from manifests. CI should fail if generated artifacts do not match the manifests.

`tempo` should surface manifest hashes and feature IDs through observability tooling so operators can verify the feature set they are running.

# Invariants

- For the first rollout, feature queries behave the same as the existing hardfork checks.
- For a fixed chain or zone and timestamp, `tempo` nodes produce the same feature set.
- Legacy hardfork mappings are cumulative.
- A feature cannot become active unless all of its dependencies are already active, or become active in the same validated checkpoint.
- Features in an activation group become active together, or not at all.
- A feature cannot be scheduled for activation until the required validators/operators are on a compatible `tempo` version or the reviewed activation design explicitly defines another rule.
- Activation data is scoped to a chain or zone and cannot replay across scopes.
- Feature IDs are stable after publication.
- Generated artifacts match the manifests.
- Local node configuration cannot enable or disable production protocol features.
- `TempoHardfork` remains the source of activation behavior until a later approved activation source replaces it.

The test coverage should include:

- T0 through T4 hardforks mapping to expected feature sets
- representative equivalence between existing hardfork checks and feature queries
- duplicate feature ID rejection
- invalid dependency rejection
- incomplete activation group rejection
- invalid activation checkpoint rejection
- chain or zone replay-scope validation
- missing TIP link rejection
- invalid legacy hardfork mapping rejection
- unchanged precompile selector behavior
- unchanged transaction pool validation behavior

## Rollout plan

### Phase 1: Feature repository

Create the source-controlled feature repository with:

- manifest schema
- legacy T1 through T4 feature manifests
- validation tooling
- CODEOWNERS draft
- documentation for owners, approval, and activation metadata

### Phase 2: `tempo` feature-query plumbing

Add `tempo` feature plumbing while preserving hardfork behavior:

- define `ProtocolFeature`
- define `FeatureSet`
- map legacy hardforks to cumulative feature sets
- expose feature queries through execution and precompile contexts
- migrate representative hardfork gates to feature queries where behavior is unchanged

### Phase 3: Observability

Expose read-only schedule and status data after internal types and tests are proven. This should include active and scheduled features, manifest hashes, activation source, minimum `tempo` version, validator readiness, dependency or activation-group blockers, and chain or zone scope.

### Phase 4: Feature review UI

Build the `tempo-protocol-features/app/` UI described above so feature review, readiness, and rollout state are easy to inspect from one place.

### Phase 5: Security review and threat model

Threat model the activation flow before using hardfork-independent activation in production. This should cover activation metadata, generated artifacts, validator readiness inputs, UI permissions, unknown feature handling, dependency and activation-group validation, chain or zone replay protection, multisig failure modes, and rollback paths.

### Phase 6: Activation source

Decide the activation source through a follow-up TIP or focused design review. The suggested path is the hybrid multisig-approved checkpoint model described above: feature records stay in `tempo-protocol-features`, final activation is a multisig-approved checkpoint, and `tempo` verifies the checkpoint against dependency rules, activation groups, manifest hashes, minimum versions, and chain or zone scope before using it.

This phase also needs to close the dynamic-context risks for transaction pool and RPC simulation. The transaction pool should not accept transactions under one feature set if they become invalid at the activation point, and `eth_call` or other simulations should use the same chain, zone, and block-specific feature set as execution.

This phase is out of scope until the preceding phases are complete.
