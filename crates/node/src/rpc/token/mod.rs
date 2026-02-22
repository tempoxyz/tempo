use crate::rpc::token::{
    role_history::{RoleChange, RoleHistoryFilters, RoleHistoryResponse},
    tokens::{Token, TokensFilters, TokensResponse},
    tokens_by_address::{AccountToken, TokensByAddressParams, TokensByAddressResponse},
};
use alloy::{
    consensus::{TxReceipt, transaction::TxHashRef},
    sol_types::SolEvent,
};
use alloy_primitives::{Address, B256};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth_node_core::rpc::result::internal_rpc_err;
use reth_primitives_traits::{AlloyBlockHeader, Block, BlockBody};
use reth_provider::{
    BlockNumReader, BlockReader, HeaderProvider, ReceiptProvider, StateProviderFactory,
};
use reth_rpc_eth_api::RpcNodeCore;
use reth_tracing::tracing::warn;
use tempo_alloy::rpc::pagination::PaginationParams;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_evm::TempoStateAccess;
use tempo_precompiles::{
    TIP20_FACTORY_ADDRESS,
    storage::Handler,
    tip20::{
        BURN_BLOCKED_ROLE, IRolesAuth, ISSUER_ROLE, PAUSE_ROLE, TIP20Token, UNPAUSE_ROLE,
        is_tip20_prefix, roles::DEFAULT_ADMIN_ROLE,
    },
    tip20_factory::ITIP20Factory,
};

pub mod cache;
pub mod indexer;
pub mod role_history;
pub mod tokens;
pub mod tokens_by_address;

#[rpc(server, namespace = "token")]
pub trait TempoTokenApi {
    /// Gets paginated role change history for TIP-20 tokens on Tempo.
    ///
    /// Tracks role grants and revocations from the RoleMembershipUpdated event for audit trails and compliance monitoring.
    ///
    /// Uses cursor-based pagination for stable iteration through role changes.
    #[method(name = "getRoleHistory")]
    async fn role_history(
        &self,
        params: PaginationParams<RoleHistoryFilters>,
    ) -> RpcResult<RoleHistoryResponse>;

    /// Gets paginated TIP-20 tokens on Tempo.
    ///
    /// Uses cursor-based pagination for stable iteration through tokens.
    #[method(name = "getTokens")]
    async fn tokens(&self, params: PaginationParams<TokensFilters>) -> RpcResult<TokensResponse>;

    /// Gets paginated TIP-20 tokens associated with an account address on Tempo.
    ///
    /// Returns tokens where the account has a balance or specific roles.
    ///
    /// Uses cursor-based pagination for stable iteration through tokens.
    #[method(name = "getTokensByAddress")]
    async fn tokens_by_address(
        &self,
        params: TokensByAddressParams,
    ) -> RpcResult<TokensByAddressResponse>;
}

/// The JSON-RPC handlers for the `token_` namespace.
#[derive(Debug, Clone)]
pub struct TempoToken<EthApi> {
    eth_api: EthApi,
    cache: cache::TokenEventCache,
}

impl<EthApi> TempoToken<EthApi> {
    pub fn new(eth_api: EthApi, cache: cache::TokenEventCache) -> Self {
        Self { eth_api, cache }
    }
}

/// Maximum number of blocks to scan in the fallback gap.
/// Matches the typical reorg depth limit. Beyond this, the indexer is assumed
/// to be too far behind and only cached data is returned.
const MAX_FALLBACK_SCAN_BLOCKS: u64 = 64;

/// Resolves pagination limit, default 10, max 100.
fn resolve_limit(limit: Option<usize>) -> usize {
    limit.unwrap_or(10).min(100)
}

/// Parses a cursor string of the form "block_number:log_index".
fn parse_cursor(cursor: &str) -> Result<(u64, usize), jsonrpsee::types::ErrorObject<'static>> {
    let parts: Vec<&str> = cursor.split(':').collect();
    if parts.len() != 2 {
        return Err(internal_rpc_err(
            "invalid cursor format, expected 'block_number:log_index'",
        ));
    }
    let block_number = parts[0]
        .parse::<u64>()
        .map_err(|_| internal_rpc_err("invalid cursor: bad block_number"))?;
    let log_index = parts[1]
        .parse::<usize>()
        .map_err(|_| internal_rpc_err("invalid cursor: bad log_index"))?;
    Ok((block_number, log_index))
}

/// Checks if a token matches the given filters.
fn matches_token_filters(token: &Token, filters: &TokensFilters) -> bool {
    if let Some(ref currency) = filters.currency
        && !token.currency.eq_ignore_ascii_case(currency)
    {
        return false;
    }
    if let Some(creator) = filters.creator
        && token.creator != creator
    {
        return false;
    }
    if let Some(ref created_at) = filters.created_at
        && !created_at.in_range(token.created_at)
    {
        return false;
    }
    if let Some(ref name) = filters.name
        && !token.name.to_lowercase().contains(&name.to_lowercase())
    {
        return false;
    }
    if let Some(paused) = filters.paused
        && token.paused != paused
    {
        return false;
    }
    if let Some(quote_token) = filters.quote_token
        && token.quote_token != quote_token
    {
        return false;
    }
    if let Some(ref supply_cap) = filters.supply_cap
        && !supply_cap.in_range(token.supply_cap)
    {
        return false;
    }
    if let Some(ref symbol) = filters.symbol
        && !token.symbol.eq_ignore_ascii_case(symbol)
    {
        return false;
    }
    if let Some(ref total_supply) = filters.total_supply
        && !total_supply.in_range(token.total_supply)
    {
        return false;
    }
    true
}

/// Extracts a u64 token_id from the last 8 bytes of a token address.
fn token_id_from_address(address: Address) -> u64 {
    let bytes = address.as_slice();
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[12..20]);
    u64::from_be_bytes(buf)
}

/// Known TIP20 roles to check for `token_getTokensByAddress`.
fn known_roles() -> [B256; 5] {
    [
        DEFAULT_ADMIN_ROLE,
        *PAUSE_ROLE,
        *UNPAUSE_ROLE,
        *ISSUER_ROLE,
        *BURN_BLOCKED_ROLE,
    ]
}

#[async_trait::async_trait]
impl<EthApi> TempoTokenApiServer for TempoToken<EthApi>
where
    EthApi: RpcNodeCore + Send + Sync + 'static,
    EthApi::Provider:
        BlockReader + HeaderProvider + StateProviderFactory + ReceiptProvider + BlockNumReader,
{
    async fn tokens(&self, params: PaginationParams<TokensFilters>) -> RpcResult<TokensResponse> {
        let provider = self.provider();
        let limit = resolve_limit(params.limit);
        let filters = params.filters.unwrap_or_default();

        let latest = provider
            .best_block_number()
            .map_err(|e| internal_rpc_err(e.to_string()))?;

        let (cursor_block, cursor_log_idx) = match params.cursor {
            Some(ref c) => parse_cursor(c)?,
            None => (0, 0),
        };

        // Snapshot cached tokens and determine the scan gap
        let (cached_tokens, last_cached) = self.cache.snapshot_tokens();
        let scan_start = last_cached.map(|b| b + 1).unwrap_or(0);

        // Collect all token creation events: cached + scanned gap
        let mut all_events: Vec<cache::CachedToken> = cached_tokens;

        // Scan any remaining blocks the cache hasn't indexed yet (capped)
        if scan_start <= latest {
            let gap = latest - scan_start + 1;
            if gap <= MAX_FALLBACK_SCAN_BLOCKS {
                for block_num in scan_start..=latest {
                    let receipts = provider
                        .receipts_by_block(block_num.into())
                        .map_err(|e| internal_rpc_err(e.to_string()))?;

                    let Some(receipts) = receipts else {
                        continue;
                    };

                    let header = provider
                        .header_by_number(block_num)
                        .map_err(|e| internal_rpc_err(e.to_string()))?;
                    let timestamp = header.map(|h| h.timestamp()).unwrap_or(0);

                    let mut global_log_idx = 0usize;
                    for receipt in &receipts {
                        for log in receipt.logs() {
                            if log.address == TIP20_FACTORY_ADDRESS
                                && let Ok(event) = ITIP20Factory::TokenCreated::decode_log(log)
                            {
                                all_events.push(cache::CachedToken {
                                    address: event.token,
                                    name: event.name.clone(),
                                    symbol: event.symbol.clone(),
                                    currency: event.currency.clone(),
                                    creator: event.admin,
                                    created_at: timestamp,
                                    token_id: token_id_from_address(event.token),
                                    block_number: block_num,
                                    log_index: global_log_idx,
                                });
                            }
                            global_log_idx += 1;
                        }
                    }
                }
            } else {
                warn!(
                    target: "token_rpc",
                    gap,
                    "Cache is behind, skipping fallback scan"
                );
            }
        }

        // Apply cursor: skip events before cursor position
        let mut results: Vec<Token> = Vec::new();
        let mut next_cursor: Option<String> = None;

        let mut state = provider
            .latest()
            .map_err(|e| internal_rpc_err(e.to_string()))?;

        for cached in &all_events {
            // Skip events before cursor position
            if (cached.block_number, cached.log_index) < (cursor_block, cursor_log_idx) {
                continue;
            }

            // Read dynamic state from provider
            let token_data = state
                .with_read_only_storage_ctx(TempoHardfork::default(), || {
                    let t = TIP20Token::from_address(cached.address)?;
                    Ok::<_, tempo_precompiles::error::TempoPrecompileError>((
                        t.paused()?,
                        t.quote_token()?,
                        t.supply_cap()?,
                        t.total_supply()?,
                        t.transfer_policy_id()?,
                    ))
                })
                .map_err(|e| internal_rpc_err(e.to_string()))?;

            let (paused, quote_token, supply_cap, total_supply, transfer_policy_id) = token_data;

            let token = Token {
                address: cached.address,
                created_at: cached.created_at,
                creator: cached.creator,
                currency: cached.currency.clone(),
                decimals: 6,
                name: cached.name.clone(),
                paused,
                quote_token,
                supply_cap: supply_cap.try_into().unwrap_or(u128::MAX),
                symbol: cached.symbol.clone(),
                token_id: cached.token_id,
                total_supply: total_supply.try_into().unwrap_or(u128::MAX),
                transfer_policy_id,
            };

            if matches_token_filters(&token, &filters) {
                if results.len() >= limit {
                    next_cursor = Some(format!("{}:{}", cached.block_number, cached.log_index));
                    break;
                }
                results.push(token);
            }
        }

        Ok(TokensResponse {
            next_cursor,
            tokens: results,
        })
    }

    async fn role_history(
        &self,
        params: PaginationParams<RoleHistoryFilters>,
    ) -> RpcResult<RoleHistoryResponse> {
        let provider = self.provider();
        let limit = resolve_limit(params.limit);
        let filters = params.filters.unwrap_or_default();

        let latest = provider
            .best_block_number()
            .map_err(|e| internal_rpc_err(e.to_string()))?;

        let (cursor_block, cursor_log_idx) = match params.cursor {
            Some(ref c) => parse_cursor(c)?,
            None => (0, 0),
        };

        // Snapshot cached role changes and determine the scan gap
        let (cached_changes, last_cached) = self.cache.snapshot_role_changes();
        let scan_start = last_cached.map(|b| b + 1).unwrap_or(0);

        // Collect all role change events: cached + scanned gap
        let mut all_events: Vec<cache::CachedRoleChange> = cached_changes;

        // Scan any remaining blocks the cache hasn't indexed yet (capped)
        if scan_start <= latest {
            let gap = latest - scan_start + 1;
            if gap <= MAX_FALLBACK_SCAN_BLOCKS {
                for block_num in scan_start..=latest {
                    let receipts = provider
                        .receipts_by_block(block_num.into())
                        .map_err(|e| internal_rpc_err(e.to_string()))?;

                    let Some(receipts) = receipts else {
                        continue;
                    };

                    let header = provider
                        .header_by_number(block_num)
                        .map_err(|e| internal_rpc_err(e.to_string()))?;
                    let timestamp = header.map(|h| h.timestamp()).unwrap_or(0);

                    let block = provider
                        .block_by_number(block_num)
                        .map_err(|e| internal_rpc_err(e.to_string()))?;

                    let mut global_log_idx = 0usize;

                    for (tx_idx, receipt) in receipts.iter().enumerate() {
                        for log in receipt.logs() {
                            if is_tip20_prefix(log.address)
                                && let Ok(event) =
                                    IRolesAuth::RoleMembershipUpdated::decode_log(log)
                            {
                                let tx_hash = block
                                    .as_ref()
                                    .and_then(|b| {
                                        b.body().transactions().get(tx_idx).map(|tx| *tx.tx_hash())
                                    })
                                    .unwrap_or_default();

                                all_events.push(cache::CachedRoleChange {
                                    role: event.role,
                                    account: event.account,
                                    sender: event.sender,
                                    granted: event.hasRole,
                                    token: log.address,
                                    block_number: block_num,
                                    timestamp,
                                    transaction_hash: tx_hash,
                                    log_index: global_log_idx,
                                });
                            }
                            global_log_idx += 1;
                        }
                    }
                }
            } else {
                warn!(
                    target: "token_rpc",
                    gap,
                    "Cache is behind, skipping fallback scan"
                );
            }
        }

        // Apply cursor and filters, then paginate
        let mut results: Vec<RoleChange> = Vec::new();
        let mut next_cursor: Option<String> = None;

        for cached in &all_events {
            // Skip events before cursor position
            if (cached.block_number, cached.log_index) < (cursor_block, cursor_log_idx) {
                continue;
            }

            // Apply block_number range filter
            if let Some(ref block_range) = filters.block_number
                && !block_range.in_range(cached.block_number)
            {
                continue;
            }

            // Apply timestamp range filter
            if let Some(ref ts_range) = filters.timestamp
                && !ts_range.in_range(cached.timestamp)
            {
                continue;
            }

            // Apply token filter
            if let Some(token_filter) = filters.token
                && cached.token != token_filter
            {
                continue;
            }

            // Apply account filter
            if let Some(account) = filters.account
                && cached.account != account
            {
                continue;
            }

            // Apply granted filter
            if let Some(granted) = filters.granted
                && cached.granted != granted
            {
                continue;
            }

            // Apply role filter
            if let Some(role) = filters.role
                && cached.role != role
            {
                continue;
            }

            // Apply sender filter
            if let Some(sender) = filters.sender
                && cached.sender != sender
            {
                continue;
            }

            if results.len() >= limit {
                next_cursor = Some(format!("{}:{}", cached.block_number, cached.log_index));
                break;
            }

            results.push(RoleChange {
                account: cached.account,
                block_number: cached.block_number,
                granted: cached.granted,
                role: cached.role,
                sender: cached.sender,
                timestamp: cached.timestamp,
                token: cached.token,
                transaction_hash: cached.transaction_hash,
            });
        }

        Ok(RoleHistoryResponse {
            next_cursor,
            role_changes: results,
        })
    }

    async fn tokens_by_address(
        &self,
        params: TokensByAddressParams,
    ) -> RpcResult<TokensByAddressResponse> {
        let provider = self.provider();
        let account = params.address;
        let limit = resolve_limit(params.params.limit);
        let filters = params.params.filters.unwrap_or_default();

        let latest = provider
            .best_block_number()
            .map_err(|e| internal_rpc_err(e.to_string()))?;

        let (cursor_block, cursor_log_idx) = match params.params.cursor {
            Some(ref c) => parse_cursor(c)?,
            None => (0, 0),
        };

        let roles_to_check = known_roles();

        // Snapshot cached tokens and determine the scan gap
        let (cached_tokens, last_cached) = self.cache.snapshot_tokens();
        let scan_start = last_cached.map(|b| b + 1).unwrap_or(0);

        // Collect all token creation events: cached + scanned gap
        let mut all_events: Vec<cache::CachedToken> = cached_tokens;

        // Scan any remaining blocks the cache hasn't indexed yet (capped)
        if scan_start <= latest {
            let gap = latest - scan_start + 1;
            if gap <= MAX_FALLBACK_SCAN_BLOCKS {
                for block_num in scan_start..=latest {
                    let receipts = provider
                        .receipts_by_block(block_num.into())
                        .map_err(|e| internal_rpc_err(e.to_string()))?;

                    let Some(receipts) = receipts else {
                        continue;
                    };

                    let header = provider
                        .header_by_number(block_num)
                        .map_err(|e| internal_rpc_err(e.to_string()))?;
                    let timestamp = header.map(|h| h.timestamp()).unwrap_or(0);

                    let mut global_log_idx = 0usize;
                    for receipt in &receipts {
                        for log in receipt.logs() {
                            if log.address == TIP20_FACTORY_ADDRESS
                                && let Ok(event) = ITIP20Factory::TokenCreated::decode_log(log)
                            {
                                all_events.push(cache::CachedToken {
                                    address: event.token,
                                    name: event.name.clone(),
                                    symbol: event.symbol.clone(),
                                    currency: event.currency.clone(),
                                    creator: event.admin,
                                    created_at: timestamp,
                                    token_id: token_id_from_address(event.token),
                                    block_number: block_num,
                                    log_index: global_log_idx,
                                });
                            }
                            global_log_idx += 1;
                        }
                    }
                }
            } else {
                warn!(
                    target: "token_rpc",
                    gap,
                    "Cache is behind, skipping fallback scan"
                );
            }
        }

        // Apply cursor, read state, filter, and paginate
        let mut results: Vec<AccountToken> = Vec::new();
        let mut next_cursor: Option<String> = None;

        let mut state = provider
            .latest()
            .map_err(|e| internal_rpc_err(e.to_string()))?;

        for cached in &all_events {
            // Skip events before cursor position
            if (cached.block_number, cached.log_index) < (cursor_block, cursor_log_idx) {
                continue;
            }

            let token_address = cached.address;

            // Read state: balance + roles + dynamic token data
            let read_result = state
                .with_read_only_storage_ctx(TempoHardfork::default(), || {
                    let t = TIP20Token::from_address(token_address)?;
                    let balance = t.balances[account].read()?;

                    let mut account_roles = Vec::new();
                    for &role in &roles_to_check {
                        if t.roles[account][role].read()? {
                            account_roles.push(role);
                        }
                    }

                    Ok::<_, tempo_precompiles::error::TempoPrecompileError>((
                        balance,
                        account_roles,
                        t.paused()?,
                        t.quote_token()?,
                        t.supply_cap()?,
                        t.total_supply()?,
                        t.transfer_policy_id()?,
                    ))
                })
                .map_err(|e| internal_rpc_err(e.to_string()))?;

            let (
                balance,
                account_roles,
                paused,
                quote_token,
                supply_cap,
                total_supply,
                transfer_policy_id,
            ) = read_result;

            // Only include if account has balance or roles
            if balance.is_zero() && account_roles.is_empty() {
                continue;
            }

            let token = Token {
                address: token_address,
                created_at: cached.created_at,
                creator: cached.creator,
                currency: cached.currency.clone(),
                decimals: 6,
                name: cached.name.clone(),
                paused,
                quote_token,
                supply_cap: supply_cap.try_into().unwrap_or(u128::MAX),
                symbol: cached.symbol.clone(),
                token_id: cached.token_id,
                total_supply: total_supply.try_into().unwrap_or(u128::MAX),
                transfer_policy_id,
            };

            if !matches_token_filters(&token, &filters) {
                continue;
            }

            if results.len() >= limit {
                next_cursor = Some(format!("{}:{}", cached.block_number, cached.log_index));
                break;
            }

            results.push(AccountToken {
                balance,
                roles: account_roles,
                token,
            });
        }

        Ok(TokensByAddressResponse {
            next_cursor,
            tokens: results,
        })
    }
}

impl<EthApi: RpcNodeCore> TempoToken<EthApi> {
    /// Access the underlying provider.
    pub fn provider(&self) -> &EthApi::Provider {
        self.eth_api.provider()
    }
}
