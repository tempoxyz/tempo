use alloy::{consensus::TxReceipt, primitives::Log, sol_types::SolEvent};
use alloy_primitives::{Address, B256, TxHash};
use parking_lot::RwLock;
use std::sync::Arc;
use tempo_precompiles::{
    TIP20_FACTORY_ADDRESS,
    tip20::{IRolesAuth, is_tip20_prefix},
    tip20_factory::ITIP20Factory,
};

use super::token_id_from_address;

/// Maximum number of role change events to keep in memory.
/// Oldest entries are evicted when this limit is exceeded.
/// 100K events at ~200 bytes each ≈ 20 MB.
const MAX_CACHED_ROLE_CHANGES: usize = 100_000;

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

        let mut inner = self.inner.write();
        inner.tokens.extend(new_tokens);
        inner.role_changes.extend(new_role_changes);

        // Evict oldest role changes if cache exceeds capacity
        if inner.role_changes.len() > MAX_CACHED_ROLE_CHANGES {
            let excess = inner.role_changes.len() - MAX_CACHED_ROLE_CHANGES;
            inner.role_changes.drain(..excess);
        }

        inner.last_indexed_block = Some(block_number);
    }

    /// Marks a block as indexed without adding any events.
    ///
    /// Used for blocks with no receipts or no relevant events.
    pub fn mark_indexed(&self, block_number: u64) {
        let mut inner = self.inner.write();
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
        let mut inner = self.inner.write();
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
        let inner = self.inner.read();
        (inner.tokens.clone(), inner.last_indexed_block)
    }

    /// Returns a snapshot of cached role changes and the last indexed block.
    pub fn snapshot_role_changes(&self) -> (Vec<CachedRoleChange>, Option<u64>) {
        let inner = self.inner.read();
        (inner.role_changes.clone(), inner.last_indexed_block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::consensus::Receipt;

    /// Creates an address with the TIP20 prefix (`0x20C0...`) so
    /// `is_tip20_prefix()` returns true. The last 8 bytes encode `suffix`.
    fn tip20_address(suffix: u64) -> Address {
        let mut bytes = [0u8; 20];
        bytes[0] = 0x20;
        bytes[1] = 0xC0;
        // bytes[2..12] are zero, matching TIP20_TOKEN_PREFIX
        bytes[12..20].copy_from_slice(&suffix.to_be_bytes());
        Address::from(bytes)
    }

    /// Builds a `TokenCreated` log emitted by `TIP20_FACTORY_ADDRESS`.
    fn token_created_log(
        token: Address,
        name: &str,
        symbol: &str,
        currency: &str,
        admin: Address,
    ) -> Log {
        let event = ITIP20Factory::TokenCreated {
            token,
            name: name.to_string(),
            symbol: symbol.to_string(),
            currency: currency.to_string(),
            quoteToken: Address::ZERO,
            admin,
            salt: B256::ZERO,
        };
        Log {
            address: TIP20_FACTORY_ADDRESS,
            data: event.encode_log_data(),
        }
    }

    /// Builds a `RoleMembershipUpdated` log for a TIP20 token address.
    fn role_membership_log(
        token: Address,
        role: B256,
        account: Address,
        sender: Address,
        has_role: bool,
    ) -> Log {
        let event = IRolesAuth::RoleMembershipUpdated {
            role,
            account,
            sender,
            hasRole: has_role,
        };
        Log {
            address: token,
            data: event.encode_log_data(),
        }
    }

    /// Wraps logs into a single successful `Receipt`.
    fn receipt_with_logs(logs: Vec<Log>) -> Receipt<Log> {
        Receipt {
            status: true.into(),
            cumulative_gas_used: 0,
            logs,
        }
    }

    #[test]
    fn new_cache_is_empty() {
        let cache = TokenEventCache::new();
        let (tokens, last) = cache.snapshot_tokens();
        assert!(tokens.is_empty());
        assert_eq!(last, None);
        let (roles, last) = cache.snapshot_role_changes();
        assert!(roles.is_empty());
        assert_eq!(last, None);
    }

    #[test]
    fn index_block_extracts_token_created() {
        let cache = TokenEventCache::new();
        let token = tip20_address(1);
        let admin = Address::repeat_byte(0xAA);
        let log = token_created_log(token, "Alpha", "ALP", "USD", admin);
        let receipt = receipt_with_logs(vec![log]);
        let tx = TxHash::repeat_byte(0x01);

        cache.index_block(10, 1000, &[receipt], &[tx]);

        let (tokens, last) = cache.snapshot_tokens();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].address, token);
        assert_eq!(tokens[0].name, "Alpha");
        assert_eq!(tokens[0].symbol, "ALP");
        assert_eq!(tokens[0].currency, "USD");
        assert_eq!(tokens[0].creator, admin);
        assert_eq!(tokens[0].created_at, 1000);
        assert_eq!(tokens[0].block_number, 10);
        assert_eq!(tokens[0].log_index, 0);
        assert_eq!(last, Some(10));
    }

    #[test]
    fn index_block_extracts_role_change() {
        let cache = TokenEventCache::new();
        let token = tip20_address(1);
        let role = B256::repeat_byte(0x01);
        let account = Address::repeat_byte(0xBB);
        let sender = Address::repeat_byte(0xCC);
        let log = role_membership_log(token, role, account, sender, true);
        let receipt = receipt_with_logs(vec![log]);
        let tx = TxHash::repeat_byte(0x02);

        cache.index_block(20, 2000, &[receipt], &[tx]);

        let (changes, last) = cache.snapshot_role_changes();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].role, role);
        assert_eq!(changes[0].account, account);
        assert_eq!(changes[0].sender, sender);
        assert!(changes[0].granted);
        assert_eq!(changes[0].token, token);
        assert_eq!(changes[0].block_number, 20);
        assert_eq!(changes[0].timestamp, 2000);
        assert_eq!(changes[0].transaction_hash, tx);
        assert_eq!(last, Some(20));
    }

    #[test]
    fn index_block_extracts_both_events() {
        let cache = TokenEventCache::new();
        let token = tip20_address(1);
        let admin = Address::repeat_byte(0xAA);
        let role = B256::repeat_byte(0x01);
        let account = Address::repeat_byte(0xBB);

        let t_log = token_created_log(token, "Token", "TK", "EUR", admin);
        let r_log = role_membership_log(token, role, account, admin, true);
        let receipt = receipt_with_logs(vec![t_log, r_log]);

        cache.index_block(30, 3000, &[receipt], &[TxHash::ZERO]);

        let (tokens, _) = cache.snapshot_tokens();
        let (changes, _) = cache.snapshot_role_changes();
        assert_eq!(tokens.len(), 1);
        assert_eq!(changes.len(), 1);
        assert_eq!(tokens[0].log_index, 0);
        assert_eq!(changes[0].log_index, 1);
    }

    #[test]
    fn index_block_ignores_irrelevant_logs() {
        let cache = TokenEventCache::new();
        let admin = Address::repeat_byte(0xAA);

        // Valid TokenCreated event but wrong emitter address
        let mut wrong_emitter = token_created_log(tip20_address(99), "X", "X", "X", admin);
        wrong_emitter.address = Address::repeat_byte(0xFF);

        // Valid RoleMembershipUpdated but from a non-TIP20 address
        let mut wrong_prefix = role_membership_log(
            tip20_address(1),
            B256::repeat_byte(0x01),
            Address::repeat_byte(0xBB),
            admin,
            true,
        );
        wrong_prefix.address = Address::repeat_byte(0xEE);

        // Factory address with wrong event topic
        let wrong_topic = Log {
            address: TIP20_FACTORY_ADDRESS,
            data: alloy_primitives::LogData::new_unchecked(
                vec![B256::repeat_byte(0xDE)],
                Default::default(),
            ),
        };

        let receipt = receipt_with_logs(vec![wrong_emitter, wrong_prefix, wrong_topic]);
        cache.index_block(40, 4000, &[receipt], &[TxHash::ZERO]);

        let (tokens, last) = cache.snapshot_tokens();
        let (changes, _) = cache.snapshot_role_changes();
        assert!(tokens.is_empty());
        assert!(changes.is_empty());
        assert_eq!(last, Some(40));
    }

    #[test]
    fn index_block_updates_last_indexed() {
        let cache = TokenEventCache::new();
        let empty: &[Receipt<Log>] = &[];

        cache.index_block(1, 100, empty, &[]);
        assert_eq!(cache.snapshot_tokens().1, Some(1));

        cache.index_block(5, 500, empty, &[]);
        assert_eq!(cache.snapshot_tokens().1, Some(5));
    }

    #[test]
    fn mark_indexed_advances_block() {
        let cache = TokenEventCache::new();
        cache.mark_indexed(10);
        assert_eq!(cache.snapshot_tokens().1, Some(10));
    }

    #[test]
    fn mark_indexed_does_not_regress() {
        let cache = TokenEventCache::new();
        cache.mark_indexed(5);
        cache.mark_indexed(3);
        assert_eq!(cache.snapshot_tokens().1, Some(5));
    }

    #[test]
    fn rollback_after_removes_events() {
        let cache = TokenEventCache::new();
        let admin = Address::repeat_byte(0xAA);

        for block in [10u64, 20, 30] {
            let token = tip20_address(block);
            let log = token_created_log(token, &format!("T{block}"), "T", "USD", admin);
            cache.index_block(
                block,
                block * 100,
                &[receipt_with_logs(vec![log])],
                &[TxHash::ZERO],
            );
        }
        assert_eq!(cache.snapshot_tokens().0.len(), 3);

        // Rollback after block 20 removes blocks 20 and 30
        cache.rollback_after(20);

        let (tokens, _) = cache.snapshot_tokens();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].block_number, 10);
    }

    #[test]
    fn rollback_after_resets_last_indexed() {
        let cache = TokenEventCache::new();
        cache.mark_indexed(50);
        cache.rollback_after(30);
        assert_eq!(cache.snapshot_tokens().1, Some(29));
    }

    #[test]
    fn rollback_after_zero_clears_all() {
        let cache = TokenEventCache::new();
        let admin = Address::repeat_byte(0xAA);
        let log = token_created_log(tip20_address(1), "T", "T", "USD", admin);
        cache.index_block(10, 1000, &[receipt_with_logs(vec![log])], &[TxHash::ZERO]);

        cache.rollback_after(0);

        let (tokens, last) = cache.snapshot_tokens();
        assert!(tokens.is_empty());
        assert_eq!(last, None);
    }

    #[test]
    fn snapshot_tokens_clones_data() {
        let cache = TokenEventCache::new();
        let admin = Address::repeat_byte(0xAA);

        let log1 = token_created_log(tip20_address(1), "T1", "T1", "USD", admin);
        cache.index_block(10, 1000, &[receipt_with_logs(vec![log1])], &[TxHash::ZERO]);

        let (snapshot, _) = cache.snapshot_tokens();
        assert_eq!(snapshot.len(), 1);

        let log2 = token_created_log(tip20_address(2), "T2", "T2", "EUR", admin);
        cache.index_block(20, 2000, &[receipt_with_logs(vec![log2])], &[TxHash::ZERO]);

        // Original snapshot is unchanged
        assert_eq!(snapshot.len(), 1);
        assert_eq!(cache.snapshot_tokens().0.len(), 2);
    }

    #[test]
    fn multiple_blocks_ordering() {
        let cache = TokenEventCache::new();
        let admin = Address::repeat_byte(0xAA);

        for block in [10u64, 20] {
            let token = tip20_address(block);
            let log = token_created_log(token, &format!("T{block}"), "T", "USD", admin);
            cache.index_block(
                block,
                block * 100,
                &[receipt_with_logs(vec![log])],
                &[TxHash::ZERO],
            );
        }

        let (tokens, _) = cache.snapshot_tokens();
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[0].block_number, 10);
        assert_eq!(tokens[1].block_number, 20);
    }

    #[test]
    fn log_index_global_across_receipts() {
        let cache = TokenEventCache::new();
        let admin = Address::repeat_byte(0xAA);

        let receipt1 = receipt_with_logs(vec![token_created_log(
            tip20_address(1),
            "T1",
            "T1",
            "USD",
            admin,
        )]);
        let receipt2 = receipt_with_logs(vec![token_created_log(
            tip20_address(2),
            "T2",
            "T2",
            "EUR",
            admin,
        )]);

        let tx1 = TxHash::repeat_byte(0x01);
        let tx2 = TxHash::repeat_byte(0x02);

        cache.index_block(10, 1000, &[receipt1, receipt2], &[tx1, tx2]);

        let (tokens, _) = cache.snapshot_tokens();
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[0].log_index, 0);
        assert_eq!(tokens[1].log_index, 1);
    }
}
