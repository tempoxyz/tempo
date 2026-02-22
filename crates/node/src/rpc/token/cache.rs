use alloy::{consensus::TxReceipt, primitives::Log, sol_types::SolEvent};
use alloy_primitives::{Address, B256, TxHash};
use std::sync::{Arc, RwLock};
use tempo_precompiles::{
    TIP20_FACTORY_ADDRESS,
    tip20::{IRolesAuth, is_tip20_prefix},
    tip20_factory::ITIP20Factory,
};

use super::token_id_from_address;

/// In-memory cache for `TokenCreated` and `RoleMembershipUpdated` events.
///
/// Stores immutable event data extracted from block receipts. Dynamic token
/// state (paused, supply, etc.) is always read fresh from the state provider.
///
/// Thread-safe via `Arc<RwLock<..>>` - the background indexer writes and RPC
/// methods read concurrently.
#[derive(Debug, Clone)]
pub struct TokenEventCache {
    inner: Arc<RwLock<TokenEventCacheInner>>,
}

#[derive(Debug, Default)]
struct TokenEventCacheInner {
    /// All discovered tokens, ordered by (block_number, log_index).
    tokens: Vec<CachedToken>,
    /// All role change events, ordered by (block_number, log_index).
    role_changes: Vec<CachedRoleChange>,
    /// Last fully indexed block number. `None` means no blocks indexed yet.
    last_indexed_block: Option<u64>,
}

/// Immutable token creation data extracted from a `TokenCreated` event.
#[derive(Debug, Clone)]
pub struct CachedToken {
    pub address: Address,
    pub name: String,
    pub symbol: String,
    pub currency: String,
    pub creator: Address,
    pub created_at: u64,
    pub token_id: u64,
    pub block_number: u64,
    pub log_index: usize,
}

/// Immutable role change data extracted from a `RoleMembershipUpdated` event.
#[derive(Debug, Clone)]
pub struct CachedRoleChange {
    pub role: B256,
    pub account: Address,
    pub sender: Address,
    pub granted: bool,
    pub token: Address,
    pub block_number: u64,
    pub timestamp: u64,
    pub transaction_hash: TxHash,
    pub log_index: usize,
}

impl Default for TokenEventCache {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenEventCache {
    /// Creates a new empty cache.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(TokenEventCacheInner::default())),
        }
    }

    /// Process a single block's receipts and extract token events.
    ///
    /// Called by the indexer for both historical scanning and new block processing.
    /// `tx_hashes` must correspond 1:1 with the receipts (same ordering).
    pub fn index_block(
        &self,
        block_number: u64,
        timestamp: u64,
        receipts: &[impl TxReceipt<Log = Log>],
        tx_hashes: &[TxHash],
    ) {
        let mut new_tokens = Vec::new();
        let mut new_role_changes = Vec::new();

        let mut global_log_idx = 0usize;
        for (tx_idx, receipt) in receipts.iter().enumerate() {
            let tx_hash = tx_hashes.get(tx_idx).copied().unwrap_or_default();

            for log in receipt.logs() {
                if log.address == TIP20_FACTORY_ADDRESS
                    && let Ok(event) = ITIP20Factory::TokenCreated::decode_log(log)
                {
                    new_tokens.push(CachedToken {
                        address: event.token,
                        name: event.name.clone(),
                        symbol: event.symbol.clone(),
                        currency: event.currency.clone(),
                        creator: event.admin,
                        created_at: timestamp,
                        token_id: token_id_from_address(event.token),
                        block_number,
                        log_index: global_log_idx,
                    });
                } else if is_tip20_prefix(log.address)
                    && let Ok(event) = IRolesAuth::RoleMembershipUpdated::decode_log(log)
                {
                    new_role_changes.push(CachedRoleChange {
                        role: event.role,
                        account: event.account,
                        sender: event.sender,
                        granted: event.hasRole,
                        token: log.address,
                        block_number,
                        timestamp,
                        transaction_hash: tx_hash,
                        log_index: global_log_idx,
                    });
                }

                global_log_idx += 1;
            }
        }

        let mut inner = self.inner.write().expect("cache lock poisoned");
        inner.tokens.extend(new_tokens);
        inner.role_changes.extend(new_role_changes);
        inner.last_indexed_block = Some(block_number);
    }

    /// Marks a block as indexed without adding any events.
    ///
    /// Used for blocks with no receipts or no relevant events.
    pub fn mark_indexed(&self, block_number: u64) {
        let mut inner = self.inner.write().expect("cache lock poisoned");
        match inner.last_indexed_block {
            Some(last) if last >= block_number => {}
            _ => inner.last_indexed_block = Some(block_number),
        }
    }

    /// Remove all cached events at or after `block_number`.
    ///
    /// Used for reorg handling: rollback to the fork point, then re-index the
    /// new canonical chain.
    pub fn rollback_after(&self, block_number: u64) {
        let mut inner = self.inner.write().expect("cache lock poisoned");
        inner.tokens.retain(|t| t.block_number < block_number);
        inner.role_changes.retain(|r| r.block_number < block_number);
        inner.last_indexed_block = if block_number > 0 {
            Some(block_number - 1)
        } else {
            None
        };
    }

    /// Returns a snapshot of cached tokens and the last indexed block.
    pub fn snapshot_tokens(&self) -> (Vec<CachedToken>, Option<u64>) {
        let inner = self.inner.read().expect("cache lock poisoned");
        (inner.tokens.clone(), inner.last_indexed_block)
    }

    /// Returns a snapshot of cached role changes and the last indexed block.
    pub fn snapshot_role_changes(&self) -> (Vec<CachedRoleChange>, Option<u64>) {
        let inner = self.inner.read().expect("cache lock poisoned");
        (inner.role_changes.clone(), inner.last_indexed_block)
    }
}
