//! # `tempo-invariants`
//!
//! Shared invariant library: a self-registering catalog of protocol checks that
//! any process can run over chain state — a live monitor, an audit cron, a
//! fuzzer asserting invariants between mutations, or a test. Consumers differ
//! only in the [`PrecompileStorageProvider`] they pass to [`run`] and which
//! entities they enumerate; the checks are identical.
//!
//! ## Model
//! - An invariant is **data + a pure function**: a [`Check<S>`]
//!   `{ meta, check: fn(&S, &mut Report) }` over a snapshot `S` read up front.
//!   Checks do no I/O and can't fail — no trait object, no `Result`.
//! - Checks self-register per *entity scope* (TIP20 token, block, reserve, …):
//!   each scope's snapshot `impl`s [`Scope`] and has its own `inventory`
//!   collection of `Check<Snapshot>`, so adding one is a single [`invariant!`].
//! - [`run`] is **entity-outer**: per entity it calls the scope's `read` once —
//!   the single I/O point, backed by the real `tempo-precompiles` typed
//!   accessors (e.g. `TIP20Token::total_supply`) — then runs every check for
//!   that scope over the snapshot. State is read once per entity, not once per
//!   (invariant, entity). The backend is any `PrecompileStorageProvider`
//!   (in-node SLOAD, sidecar RPC, audit archive, or `HashMapStorageProvider`).
//! - [`registry`] and [`run`] are derived from the registered set.
//!
//! ## Extending
//! - **Add a check:** write one [`invariant!`] block in the relevant `<scope>/`
//!   module. It self-registers; nothing central changes.
//! - **Add a scope:** add a [`ScopeKind`] variant, an entity + snapshot type
//!   that implements [`Scope`] with `inventory::collect!(Check<Snapshot>)`, a
//!   `read`, a runner arm in [`run`], and a [`RunEntities`] field. No central
//!   *invariant* enum or per-scope macro arm to touch — the macro infers the
//!   scope from the snapshot type.
//!
//! See `examples/demo.rs` and the `tip20/`, `block/`, and `reserve/` modules.

use std::sync::LazyLock;

use alloy_primitives::Address;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{
    error::TempoPrecompileError,
    storage::{PrecompileStorageProvider, StorageCtx},
};

pub mod block;
pub mod reserve;
pub mod tip20;

use block::BlockView;
use reserve::{ReserveSnapshot, ReserveView};
use tip20::Tip20Snapshot;

// Re-exports so the `invariant!` macro can reference these without the
// downstream module needing explicit `inventory` / `tempo-chainspec` deps.
#[doc(hidden)]
pub use inventory;
#[doc(hidden)]
pub use tempo_chainspec;

/// Alert severity / escalation tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    /// Fund loss or protocol insolvency.
    P0,
    /// Core protocol invariant broken, no direct fund loss.
    P1,
    /// Configuration or hygiene violation.
    P2,
}

/// Coarse protocol area, used for routing/labelling. Derived from [`ScopeKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InvariantModule {
    Tip20,
    Amm,
    Dex,
    Registry,
    Keychain,
    Validator,
    Block,
    Zone,
    Reserve,
}

/// The entity scope a check runs over. Adding a scope is a deliberate, central
/// change (new variant + entity/snapshot type + `Scope` impl + runner arm +
/// [`RunEntities`] field); adding a *check* to an existing scope is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScopeKind {
    Tip20Token,
    Block,
    Reserve,
}

impl ScopeKind {
    /// The module each scope rolls up into.
    pub const fn module(self) -> InvariantModule {
        match self {
            Self::Tip20Token => InvariantModule::Tip20,
            Self::Block => InvariantModule::Block,
            Self::Reserve => InvariantModule::Reserve,
        }
    }
}

/// Metadata for a single invariant — the single source of truth for its
/// identity. When built via [`InvariantMeta::new`] (and therefore [`invariant!`])
/// `module` is derived from `scope`, so the two can't disagree.
#[derive(Debug, Clone, Copy)]
pub struct InvariantMeta {
    pub id: &'static str,
    pub scope: ScopeKind,
    pub module: InvariantModule,
    pub severity: Severity,
    pub description: &'static str,
    /// First hardfork at which this invariant is active. A check is only run
    /// when the chain's active fork is `>= since`, so T-N invariants can ship
    /// (and sit dormant) before T-N activates on mainnet. Defaults to
    /// [`TempoHardfork::Genesis`] (always on) via the [`invariant!`] macro.
    pub since: TempoHardfork,
}

impl InvariantMeta {
    pub const fn new(
        id: &'static str,
        scope: ScopeKind,
        severity: Severity,
        description: &'static str,
        since: TempoHardfork,
    ) -> Self {
        Self {
            id,
            scope,
            module: scope.module(),
            severity,
            description,
            since,
        }
    }

    /// Whether this invariant is active under `active` — i.e. the chain has
    /// reached its `since` fork. Fork ordering is by declaration order in
    /// [`TempoHardfork`].
    pub fn is_active(&self, active: TempoHardfork) -> bool {
        active.variant_index() >= self.since.variant_index()
    }
}

/// Identifies the entity a failure was found on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityId {
    Address(Address),
    Block(u64),
}

/// A single invariant violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub id: &'static str,
    pub scope: ScopeKind,
    pub entity: EntityId,
    pub detail: String,
}

/// A scope's checks were skipped for an entity because its state could not be
/// **read** (e.g. a storage read failed). Reads happen once per entity in the
/// `read` step, so a read failure is an entity-level event, reported once per
/// entity rather than per check. Tracked separately from [`Failure`] so
/// "couldn't check" never looks like "passed".
#[derive(Debug, Clone)]
pub struct CheckError {
    pub scope: ScopeKind,
    pub entity: EntityId,
    pub message: String,
}

/// Error returned from a scope's `read` step; carries only the message, the
/// runner adds scope/entity context. State-read errors convert via `?`.
#[derive(Debug)]
pub struct EvalError {
    pub message: String,
}

impl From<TempoPrecompileError> for EvalError {
    fn from(e: TempoPrecompileError) -> Self {
        Self {
            message: e.to_string(),
        }
    }
}

/// Per-invariant sink handed to a check. `fail` tags every record with the
/// current invariant id, scope, and entity automatically.
pub struct Report<'a> {
    id: &'static str,
    scope: ScopeKind,
    entity: EntityId,
    failures: &'a mut Vec<Failure>,
}

impl Report<'_> {
    /// Record a violation of the current invariant.
    pub fn fail(&mut self, detail: impl Into<String>) {
        self.failures.push(Failure {
            id: self.id,
            scope: self.scope,
            entity: self.entity,
            detail: detail.into(),
        });
    }
}

/// The typed unit for one invariant: metadata plus a **pure** function pointer
/// over a snapshot `S` read up front. Checks do no I/O — all reads happen once
/// per entity in the scope's `read` step — so they take no provider and can't
/// fail. Not the authoring surface — use [`invariant!`].
pub struct Check<S> {
    pub meta: InvariantMeta,
    pub check: fn(&S, &mut Report<'_>),
}

impl<S> Check<S> {
    pub const fn new(meta: InvariantMeta, check: fn(&S, &mut Report<'_>)) -> Self {
        Self { meta, check }
    }
}

/// Links a snapshot type to its [`ScopeKind`]. Each scope module implements this
/// for its snapshot and calls `inventory::collect!(Check<Snapshot>)`, so checks
/// self-register per type — no central enum or scope-mapping macro to extend.
/// The [`invariant!`] macro reads `KIND` from the snapshot in the check
/// signature, so the scope can't be stated wrong.
pub trait Scope {
    const KIND: ScopeKind;
}

/// Authoring macro: emits a normal named function plus its registration. The
/// check is a **pure** function of a snapshot read up front — no provider, no
/// `Result`, no `?`. The body is ordinary Rust; the macro only removes mechanical
/// repetition.
///
/// An optional `since:` line gates the check on a hardfork — it only runs once
/// the chain's active fork is `>= since`, so T-N invariants can ship before T-N
/// activates. Omitting it defaults to [`TempoHardfork::Genesis`] (always on).
///
/// The check's scope is inferred from the snapshot type in its signature (via
/// its [`Scope`] impl), so there's no `scope:` line to keep in sync.
///
/// ```ignore
/// invariant! {
///     id: "TEMPO-TIP20-SUPPLY-CAP",
///     severity: P1,
///     since: T6, // optional; defaults to Genesis (always active)
///     description: "totalSupply must not exceed supplyCap when a cap is set",
///     fn supply_cap(t: &Tip20Snapshot, out: &mut Report<'_>) {
///         if !t.supply_cap.is_zero() && t.total_supply > t.supply_cap {
///             out.fail(format!("totalSupply ({}) > supplyCap ({})", t.total_supply, t.supply_cap));
///         }
///     }
/// }
/// ```
#[macro_export]
macro_rules! invariant {
    // With explicit `since:` fork gate.
    (
        id: $id:literal,
        severity: $severity:ident,
        since: $since:ident,
        description: $description:literal,
        fn $name:ident ( $ent:ident : & $ent_ty:ty , $out:ident : &mut Report<'_> )
        $body:block
    ) => {
        $crate::__invariant_impl!(
            $id,
            $severity,
            $crate::tempo_chainspec::hardfork::TempoHardfork::$since,
            $description,
            $name,
            $ent,
            $ent_ty,
            $out,
            $body
        );
    };
    // No `since:` — defaults to Genesis (always active).
    (
        id: $id:literal,
        severity: $severity:ident,
        description: $description:literal,
        fn $name:ident ( $ent:ident : & $ent_ty:ty , $out:ident : &mut Report<'_> )
        $body:block
    ) => {
        $crate::__invariant_impl!(
            $id,
            $severity,
            $crate::tempo_chainspec::hardfork::TempoHardfork::Genesis,
            $description,
            $name,
            $ent,
            $ent_ty,
            $out,
            $body
        );
    };
}

/// Shared expansion for [`invariant!`]; not called directly. Submits the check
/// to the per-snapshot `inventory` collection; the scope is `<$ent_ty as
/// Scope>::KIND`.
#[doc(hidden)]
#[macro_export]
macro_rules! __invariant_impl {
    (
        $id:literal, $severity:ident, $since:expr,
        $description:literal, $name:ident, $ent:ident, $ent_ty:ty, $out:ident, $body:block
    ) => {
        fn $name($ent: &$ent_ty, $out: &mut $crate::Report<'_>) $body

        $crate::inventory::submit! {
            $crate::Check::<$ent_ty>::new(
                $crate::InvariantMeta::new(
                    $id,
                    <$ent_ty as $crate::Scope>::KIND,
                    $crate::Severity::$severity,
                    $description,
                    $since,
                ),
                $name,
            )
        }
    };
}

/// Entities to run each scope over for one pass. The delta tier fills these
/// with touched entities; the audit tier with all enumerated entities.
#[derive(Default)]
pub struct RunEntities<'a> {
    pub tip20_tokens: &'a [Address],
    pub block: Option<&'a BlockView>,
    pub reserves: &'a [ReserveView],
}

/// Output of a [`run`]: violations plus any entities whose checks were skipped
/// because their state couldn't be read.
#[derive(Debug, Default)]
pub struct RunOutput {
    pub failures: Vec<Failure>,
    pub errors: Vec<CheckError>,
}

impl RunOutput {
    /// Record that a scope's checks were skipped for an entity (its `read`
    /// failed). All checks for that entity are skipped together.
    fn skip(&mut self, scope: ScopeKind, entity: EntityId, e: EvalError) {
        self.errors.push(CheckError {
            scope,
            entity,
            message: e.message,
        });
    }
}

/// The registry, partitioned by scope and sorted by id, built **once** from the
/// `inventory` set and cached for the process lifetime. `inventory` link order
/// is non-deterministic, so we sort here; doing it per-`run` would re-walk and
/// re-sort the whole catalog on every block / cron tick.
struct Registry {
    tip20: Vec<&'static Check<Tip20Snapshot>>,
    block: Vec<&'static Check<BlockView>>,
    reserve: Vec<&'static Check<ReserveSnapshot>>,
}

static REGISTRY: LazyLock<Registry> = LazyLock::new(|| {
    // Each scope has its own `inventory` collection (`Check<Snapshot>`), so the
    // build just gathers and sorts each one — no central enum to match on.
    fn sorted<S: 'static>() -> Vec<&'static Check<S>>
    where
        Check<S>: inventory::Collect,
    {
        let mut v: Vec<_> = inventory::iter::<Check<S>>.into_iter().collect();
        v.sort_by_key(|c| c.meta.id);
        v
    }
    Registry {
        tip20: sorted::<Tip20Snapshot>(),
        block: sorted::<BlockView>(),
        reserve: sorted::<ReserveSnapshot>(),
    }
});

/// The machine-readable registry, derived (and sorted) from the registered set.
/// Backs the catalog UI, history schema, docs, etc.
pub fn registry() -> Vec<InvariantMeta> {
    let r = &*REGISTRY;
    let mut metas: Vec<InvariantMeta> = r
        .tip20
        .iter()
        .map(|c| c.meta)
        .chain(r.block.iter().map(|c| c.meta))
        .chain(r.reserve.iter().map(|c| c.meta))
        .collect();
    metas.sort_by_key(|m| m.id);
    metas
}

/// Run every registered invariant over the given entities.
///
/// The loop is **entity-outer**: for each entity we `read` its snapshot
/// once (the single place state is read — and the place a future batched
/// multi-slot read would live), then run *all* of that scope's checks over the
/// snapshot with zero further I/O. State is therefore read once per entity, not
/// once per (invariant, entity).
///
/// Checks run against a pre-built, process-lifetime registry cache (no per-call
/// walk/sort), and a check is skipped unless its `since` fork is `<=` the chain's
/// currently active fork (read once per pass).
pub fn run<S: PrecompileStorageProvider>(
    provider: &mut S,
    entities: &RunEntities<'_>,
) -> RunOutput {
    let mut out = RunOutput::default();
    let reg = &*REGISTRY;

    StorageCtx::enter(provider, || {
        // Read the chain's active fork once; checks whose `since` is later are
        // skipped this pass. Gating is per-run (not baked into the cached
        // registry) because the delta tier crosses activations while the
        // process stays alive, and the audit tier may replay older blocks.
        let active = StorageCtx.spec();

        for &address in entities.tip20_tokens {
            let id = EntityId::Address(address);
            match tip20::read(address) {
                Ok(snap) => run_checks(&reg.tip20, active, &snap, id, &mut out),
                Err(e) => out.skip(ScopeKind::Tip20Token, id, e),
            }
        }

        if let Some(view) = entities.block {
            // Block snapshots are pure data (no storage), so there's nothing to read.
            run_checks(
                &reg.block,
                active,
                view,
                EntityId::Block(view.number),
                &mut out,
            );
        }

        for view in entities.reserves {
            let id = EntityId::Address(view.token);
            match reserve::read(view) {
                Ok(snap) => run_checks(&reg.reserve, active, &snap, id, &mut out),
                Err(e) => out.skip(ScopeKind::Reserve, id, e),
            }
        }
    });

    out
}

/// Run a scope's pure checks over one already-read snapshot, skipping any whose
/// `since` fork is not yet active.
fn run_checks<S>(
    checks: &[&Check<S>],
    active: TempoHardfork,
    snap: &S,
    entity: EntityId,
    out: &mut RunOutput,
) {
    for check in checks {
        if !check.meta.is_active(active) {
            continue;
        }
        let mut report = Report {
            id: check.meta.id,
            scope: check.meta.scope,
            entity,
            failures: &mut out.failures,
        };
        (check.check)(snap, &mut report);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Metadata lives with the check and registration is automatic, so id
    /// uniqueness is the only registry invariant that needs a test.
    #[test]
    fn registry_ids_are_unique() {
        let mut ids: Vec<&str> = registry().iter().map(|m| m.id).collect();
        let total = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), total, "duplicate invariant id in registry");
    }

    #[test]
    fn samples_registered_across_scopes() {
        let ids: Vec<&str> = registry().iter().map(|m| m.id).collect();
        assert!(ids.contains(&"TEMPO-TIP20-SUPPLY-CAP"));
        assert!(ids.contains(&"TEMPO-TIP20-OPTIN-SUPPLY"));
        assert!(ids.contains(&"TEMPO-BLOCK-GAS-LIMIT"));
        assert!(ids.contains(&"TEMPO-RESERVE-CHANNEL-SOLVENCY"));
    }

    /// Invariants that omit `since:` must default to always-on so shipping the
    /// library never silently disables an existing check.
    #[test]
    fn invariants_default_to_genesis() {
        assert!(
            registry().iter().all(|m| m.since == TempoHardfork::Genesis),
            "a registered invariant set `since:` — update this test intentionally"
        );
    }

    #[test]
    fn is_active_is_inclusive_from_since() {
        let m = InvariantMeta::new("T", ScopeKind::Block, Severity::P2, "d", TempoHardfork::T6);
        assert!(!m.is_active(TempoHardfork::T5));
        assert!(m.is_active(TempoHardfork::T6));
        assert!(m.is_active(TempoHardfork::T7));
    }

    /// `since` gating is applied in `run_checks`: a check is skipped until its
    /// fork is active, then runs unchanged. Block checks are pure (no storage),
    /// so this exercises the filter without a provider.
    #[test]
    fn run_checks_skips_until_fork_active() {
        fn always_fail(_b: &BlockView, out: &mut Report<'_>) {
            out.fail("x");
        }
        let now = Check::new(
            InvariantMeta::new(
                "NOW",
                ScopeKind::Block,
                Severity::P2,
                "d",
                TempoHardfork::Genesis,
            ),
            always_fail,
        );
        let future = Check::new(
            InvariantMeta::new(
                "FUTURE",
                ScopeKind::Block,
                Severity::P2,
                "d",
                TempoHardfork::T6,
            ),
            always_fail,
        );
        let checks = [&now, &future];
        let view = BlockView {
            number: 1,
            gas_used: 0,
            gas_limit: 0,
        };

        let mut before = RunOutput::default();
        run_checks(
            &checks,
            TempoHardfork::T5,
            &view,
            EntityId::Block(1),
            &mut before,
        );
        let fired: Vec<_> = before.failures.iter().map(|f| f.id).collect();
        assert_eq!(
            fired,
            vec!["NOW"],
            "future-fork check must be skipped pre-activation"
        );

        let mut after = RunOutput::default();
        run_checks(
            &checks,
            TempoHardfork::T6,
            &view,
            EntityId::Block(1),
            &mut after,
        );
        assert_eq!(
            after.failures.len(),
            2,
            "both checks run once the fork is active"
        );
    }
}
