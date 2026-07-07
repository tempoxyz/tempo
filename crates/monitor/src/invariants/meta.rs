//! Invariant metadata and deterministic catalog.

use serde::{Deserialize, Serialize};
use std::{borrow::Cow, collections::BTreeMap};
use tempo_hardfork::TempoHardfork;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct InvariantId(pub Cow<'static, str>);

impl InvariantId {
    pub const fn borrowed(id: &'static str) -> Self {
        Self(Cow::Borrowed(id))
    }

    pub fn new(id: impl Into<Cow<'static, str>>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvariantCategory {
    Stateless,
    CurrentState,
    StateChange,
    RunningRecord,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReadNeed {
    Block,
    ParentState,
    CurrentState,
    History,
    Replay,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectSpec {
    pub source: String,
    pub predicate: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencySpec {
    pub entity: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateNeed {
    pub boundary: String,
    pub table: String,
    pub keyset: String,
    pub complete: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageSpec {
    pub complete: String,
    pub partial: String,
    pub inconclusive: String,
    pub degraded: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayNeed {
    pub required: bool,
    pub description: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantMetadata {
    pub id: InvariantId,
    pub statement: String,
    pub category: InvariantCategory,
    pub severity: Severity,
    pub gate: TempoHardfork,
    pub select: SelectSpec,
    pub depends: Vec<DependencySpec>,
    pub reads: Vec<ReadNeed>,
    pub assertion: String,
    pub state: Vec<StateNeed>,
    pub coverage: CoverageSpec,
    pub replay: Option<ReplayNeed>,
    pub examples: Vec<String>,
}

impl InvariantMetadata {
    pub fn is_complete(&self) -> bool {
        !self.id.as_str().is_empty()
            && !self.statement.is_empty()
            && !self.select.source.is_empty()
            && !self.assertion.is_empty()
            && !self.coverage.complete.is_empty()
            && !self.coverage.inconclusive.is_empty()
            && !self.coverage.degraded.is_empty()
    }
}

#[derive(Clone, Debug, Default)]
pub struct InvariantCatalog {
    by_id: BTreeMap<InvariantId, InvariantMetadata>,
}

impl InvariantCatalog {
    pub fn new(metas: impl IntoIterator<Item = InvariantMetadata>) -> Result<Self, InvariantId> {
        let mut by_id = BTreeMap::new();
        for meta in metas {
            if by_id.insert(meta.id.clone(), meta).is_some() {
                return Err(by_id.keys().next_back().expect("inserted").clone());
            }
        }
        Ok(Self { by_id })
    }

    pub fn get(&self, id: &InvariantId) -> Option<&InvariantMetadata> {
        self.by_id.get(id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &InvariantMetadata> {
        self.by_id.values()
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

pub mod ids {
    pub const BLOCK_TOTAL_GAS: &str = "TEMPO-BLOCK-TOTAL-GAS";
    pub const TIP20_SUPPLY_CAP: &str = "TEMPO-TIP20-SUPPLY-CAP";
    pub const TIP20_SUPPLY_DELTA: &str = "TEMPO-TIP20-SUPPLY-DELTA";
    pub const TX_EXPNONCE_REPLAY: &str = "TEMPO-TX-EXPNONCE-REPLAY";
}

pub fn initial_catalog() -> InvariantCatalog {
    InvariantCatalog::new(initial_metadata()).expect("unique static invariant ids")
}

pub fn initial_metadata() -> Vec<InvariantMetadata> {
    vec![
        metadata(
            ids::BLOCK_TOTAL_GAS,
            "Block total gas derived from receipts must match header gas used and not exceed the block gas limit.",
            InvariantCategory::Stateless,
            Severity::Critical,
            "finalized block",
            "all blocks",
            vec![ReadNeed::Block],
            vec![],
            vec![DependencySpec {
                entity: "Block".into(),
                reason: "candidate is the finalized block itself".into(),
            }],
            "receipt_total_gas == gas_used && gas_used <= gas_limit",
            vec![],
        ),
        metadata(
            ids::TIP20_SUPPLY_CAP,
            "TIP20 total supply must not exceed configured token cap.",
            InvariantCategory::CurrentState,
            Severity::Critical,
            "dirty TIP20 token",
            "tokens touched by transfers or policy updates",
            vec![ReadNeed::CurrentState],
            vec![StateNeed {
                boundary: "S[n]".into(),
                table: "tip20_supply, tip20_cap".into(),
                keyset: "dirty token addresses".into(),
                complete: true,
            }],
            vec![DependencySpec {
                entity: "Tip20Token".into(),
                reason: "candidate token dirties supply and cap state reads".into(),
            }],
            "total_supply <= supply_cap",
            vec![],
        ),
        metadata(
            ids::TIP20_SUPPLY_DELTA,
            "TIP20 supply delta must match mint and burn transfer events.",
            InvariantCategory::StateChange,
            Severity::High,
            "dirty TIP20 token",
            "tokens with Transfer mint/burn logs",
            vec![
                ReadNeed::ParentState,
                ReadNeed::CurrentState,
                ReadNeed::Block,
            ],
            vec![StateNeed {
                boundary: "S[n-1], S[n]".into(),
                table: "tip20_supply".into(),
                keyset: "dirty token addresses".into(),
                complete: true,
            }],
            vec![DependencySpec {
                entity: "Tip20Token".into(),
                reason: "mint/burn transfer logs require parent and current supply reads".into(),
            }],
            "supply_after - supply_before == minted - burned",
            vec![],
        ),
        metadata(
            ids::TX_EXPNONCE_REPLAY,
            "Expiring nonces must not be replayed within their validity window.",
            InvariantCategory::RunningRecord,
            Severity::Critical,
            "transactions with expiring nonce",
            "Tempo txs carrying expiring nonce metadata",
            vec![ReadNeed::Block, ReadNeed::History],
            vec![StateNeed {
                boundary: "H_view".into(),
                table: "expiring_nonce_seen".into(),
                keyset: "nonce identity".into(),
                complete: true,
            }],
            vec![DependencySpec {
                entity: "Tx".into(),
                reason:
                    "sender-scoped unique intent and validity window update expiring nonce history"
                        .into(),
            }],
            "nonce identity is unseen or expired before reuse",
            vec![ReplayNeed {
                required: false,
                description: "Replay facts may strengthen evidence but are optional.".into(),
            }],
        ),
    ]
}

#[allow(clippy::too_many_arguments)]
fn metadata(
    id: &'static str,
    statement: &str,
    category: InvariantCategory,
    severity: Severity,
    source: &str,
    predicate: &str,
    reads: Vec<ReadNeed>,
    state: Vec<StateNeed>,
    depends: Vec<DependencySpec>,
    assertion: &str,
    replay: Vec<ReplayNeed>,
) -> InvariantMetadata {
    InvariantMetadata {
        id: InvariantId::borrowed(id),
        statement: statement.into(),
        category,
        severity,
        gate: TempoHardfork::Genesis,
        select: SelectSpec {
            source: source.into(),
            predicate: predicate.into(),
        },
        depends,
        reads,
        assertion: assertion.into(),
        state,
        coverage: CoverageSpec {
            complete: "All declared inputs and candidate keysets are complete.".into(),
            partial: "Only selected candidates are covered; global absence is not proven.".into(),
            inconclusive: "A required block, state, history, or decoder input is missing.".into(),
            degraded: "A required table/keyset is tainted, stale, or incomplete.".into(),
        },
        replay: replay.into_iter().next(),
        examples: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_iterates_by_id() -> eyre::Result<()> {
        let ids = initial_catalog()
            .iter()
            .map(|m| m.id.as_str().to_owned())
            .collect::<Vec<_>>();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
        Ok(())
    }

    #[test]
    fn static_metadata_is_complete_and_unique() -> eyre::Result<()> {
        let catalog = initial_catalog();
        assert_eq!(catalog.len(), 4);
        for meta in catalog.iter() {
            assert!(
                meta.is_complete(),
                "incomplete metadata for {}",
                meta.id.as_str()
            );
        }
        Ok(())
    }
}
