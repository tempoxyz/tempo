//! Entity keys and dirty-set metadata.

use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};

use crate::{diagnostics::evidence::EvidenceRef, input::facts::BlockNumHash};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EntityKind {
    Block,
    Tx,
    Address,
    Tip20Token,
    Account,
    Policy,
    AmmPool,
    DexBook,
    DexOrder,
    Validator,
    Channel,
    Zone,
    ActivityRule,
    ActivityEntity,
}

/// Stable monitor-owned key identifying the subject of a check, dirty-set row, finding, or evidence.
///
/// String keys are the initial representation. Store schemas may replace these with typed
/// encodings while preserving the same entity semantics.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EntityKey {
    pub kind: EntityKind,
    pub key: String,
}

impl EntityKey {
    pub fn block(block: BlockNumHash) -> Self {
        Self {
            kind: EntityKind::Block,
            key: format!("#{}@{}", block.number, block.hash),
        }
    }

    pub fn tx(hash: B256) -> Self {
        Self {
            kind: EntityKind::Tx,
            key: hash.to_string(),
        }
    }

    pub fn address(address: Address) -> Self {
        Self {
            kind: EntityKind::Address,
            key: address.to_string(),
        }
    }

    pub fn tip20(token: Address) -> Self {
        Self {
            kind: EntityKind::Tip20Token,
            key: token.to_string(),
        }
    }

    pub fn account(account: Address) -> Self {
        Self {
            kind: EntityKind::Account,
            key: account.to_string(),
        }
    }

    pub fn policy(policy_id: U256) -> Self {
        Self {
            kind: EntityKind::Policy,
            key: policy_id.to_string(),
        }
    }

    pub fn amm_pool(token0: Address, token1: Address) -> Self {
        Self {
            kind: EntityKind::AmmPool,
            key: format!("{token0}/{token1}"),
        }
    }

    pub fn dex_book(base: Address, quote: Address) -> Self {
        Self {
            kind: EntityKind::DexBook,
            key: format!("{base}/{quote}"),
        }
    }

    pub fn dex_order(order_id: U256) -> Self {
        Self {
            kind: EntityKind::DexOrder,
            key: order_id.to_string(),
        }
    }

    pub fn validator(validator: Address) -> Self {
        Self {
            kind: EntityKind::Validator,
            key: validator.to_string(),
        }
    }

    pub fn channel(channel_id: B256) -> Self {
        Self {
            kind: EntityKind::Channel,
            key: channel_id.to_string(),
        }
    }

    pub fn zone(zone: Address) -> Self {
        Self {
            kind: EntityKind::Zone,
            key: zone.to_string(),
        }
    }

    pub fn activity_rule(rule_id: impl Into<String>) -> Self {
        Self {
            kind: EntityKind::ActivityRule,
            key: rule_id.into(),
        }
    }

    pub fn activity_entity(entity_id: impl Into<String>) -> Self {
        Self {
            kind: EntityKind::ActivityEntity,
            key: entity_id.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DirtyReason {
    BlockBoundary,
    TxMutation,
    LogMutation,
    StateMutation(String),
    DependencyExpansion { from: EntityKey, reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirtyEntity {
    pub entity: EntityKey,
    pub reason: DirtyReason,
    pub evidence: Vec<EvidenceRef>,
}
