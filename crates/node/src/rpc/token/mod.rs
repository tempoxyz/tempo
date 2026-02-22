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
#[derive(Debug, Clone, Default)]
pub struct TempoToken<EthApi> {
    eth_api: EthApi,
}

impl<EthApi> TempoToken<EthApi> {
    pub fn new(eth_api: EthApi) -> Self {
        Self { eth_api }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// TempoTokenApiServer impl
// ---------------------------------------------------------------------------

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

        let (start_block, start_log_idx) = match params.cursor {
            Some(ref c) => parse_cursor(c)?,
            None => (0, 0),
        };

        let mut results: Vec<Token> = Vec::new();
        let mut next_cursor: Option<String> = None;

        'outer: for block_num in start_block..=latest {
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
                    // Skip logs before cursor position
                    if block_num == start_block && global_log_idx < start_log_idx {
                        global_log_idx += 1;
                        continue;
                    }

                    // Only look at logs from the factory
                    if log.address != TIP20_FACTORY_ADDRESS {
                        global_log_idx += 1;
                        continue;
                    }

                    // Try to decode as TokenCreated
                    let Ok(event) = ITIP20Factory::TokenCreated::decode_log(log) else {
                        global_log_idx += 1;
                        continue;
                    };

                    let token_address = event.token;

                    // Read current state
                    let mut state = provider
                        .latest()
                        .map_err(|e| internal_rpc_err(e.to_string()))?;
                    let token_data = state
                        .with_read_only_storage_ctx(TempoHardfork::default(), || {
                            let t = TIP20Token::from_address(token_address)?;
                            Ok::<_, tempo_precompiles::error::TempoPrecompileError>((
                                t.paused()?,
                                t.quote_token()?,
                                t.supply_cap()?,
                                t.total_supply()?,
                                t.transfer_policy_id()?,
                            ))
                        })
                        .map_err(|e| internal_rpc_err(e.to_string()))?;

                    let (paused, quote_token, supply_cap, total_supply, transfer_policy_id) =
                        token_data;

                    let token = Token {
                        address: token_address,
                        created_at: timestamp,
                        creator: event.admin,
                        currency: event.currency.clone(),
                        decimals: 6,
                        name: event.name.clone(),
                        paused,
                        quote_token,
                        supply_cap: supply_cap.try_into().unwrap_or(u128::MAX),
                        symbol: event.symbol.clone(),
                        token_id: token_id_from_address(token_address),
                        total_supply: total_supply.try_into().unwrap_or(u128::MAX),
                        transfer_policy_id,
                    };

                    if matches_token_filters(&token, &filters) {
                        if results.len() >= limit {
                            next_cursor = Some(format!("{block_num}:{global_log_idx}"));
                            break 'outer;
                        }
                        results.push(token);
                    }

                    global_log_idx += 1;
                }
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

        let (start_block, start_log_idx) = match params.cursor {
            Some(ref c) => parse_cursor(c)?,
            None => (0, 0),
        };

        let mut results: Vec<RoleChange> = Vec::new();
        let mut next_cursor: Option<String> = None;

        'outer: for block_num in start_block..=latest {
            // Apply block_number range filter early
            if let Some(ref block_range) = filters.block_number
                && !block_range.in_range(block_num)
            {
                continue;
            }

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

            // Apply timestamp range filter early
            if let Some(ref ts_range) = filters.timestamp
                && !ts_range.in_range(timestamp)
            {
                continue;
            }

            // Get the block to access transaction hashes
            let block = provider
                .block_by_number(block_num)
                .map_err(|e| internal_rpc_err(e.to_string()))?;

            let mut global_log_idx = 0usize;
            let mut tx_idx = 0usize;

            for receipt in &receipts {
                for log in receipt.logs() {
                    if block_num == start_block && global_log_idx < start_log_idx {
                        global_log_idx += 1;
                        continue;
                    }

                    // Filter by token address if specified
                    if let Some(token_filter) = filters.token {
                        if log.address != token_filter {
                            global_log_idx += 1;
                            continue;
                        }
                    } else {
                        // Only check logs from TIP20 addresses
                        if !is_tip20_prefix(log.address) {
                            global_log_idx += 1;
                            continue;
                        }
                    }

                    let Ok(event) = IRolesAuth::RoleMembershipUpdated::decode_log(log) else {
                        global_log_idx += 1;
                        continue;
                    };

                    // Determine transaction hash
                    let tx_hash = block
                        .as_ref()
                        .and_then(|b| b.body().transactions().get(tx_idx).map(|tx| *tx.tx_hash()))
                        .unwrap_or_default();

                    let role_change = RoleChange {
                        account: event.account,
                        block_number: block_num,
                        granted: event.hasRole,
                        role: event.role,
                        sender: event.sender,
                        timestamp,
                        token: log.address,
                        transaction_hash: tx_hash,
                    };

                    // Apply remaining filters
                    if let Some(account) = filters.account
                        && role_change.account != account
                    {
                        global_log_idx += 1;
                        continue;
                    }
                    if let Some(granted) = filters.granted
                        && role_change.granted != granted
                    {
                        global_log_idx += 1;
                        continue;
                    }
                    if let Some(role) = filters.role
                        && role_change.role != role
                    {
                        global_log_idx += 1;
                        continue;
                    }
                    if let Some(sender) = filters.sender
                        && role_change.sender != sender
                    {
                        global_log_idx += 1;
                        continue;
                    }

                    if results.len() >= limit {
                        next_cursor = Some(format!("{block_num}:{global_log_idx}"));
                        break 'outer;
                    }
                    results.push(role_change);

                    global_log_idx += 1;
                }

                tx_idx += 1;
            }
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

        let (start_block, start_log_idx) = match params.params.cursor {
            Some(ref c) => parse_cursor(c)?,
            None => (0, 0),
        };

        let roles_to_check = known_roles();

        let mut results: Vec<AccountToken> = Vec::new();
        let mut next_cursor: Option<String> = None;

        'outer: for block_num in start_block..=latest {
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
                    if block_num == start_block && global_log_idx < start_log_idx {
                        global_log_idx += 1;
                        continue;
                    }

                    if log.address != TIP20_FACTORY_ADDRESS {
                        global_log_idx += 1;
                        continue;
                    }

                    let Ok(event) = ITIP20Factory::TokenCreated::decode_log(log) else {
                        global_log_idx += 1;
                        continue;
                    };

                    let token_address = event.token;

                    // Read state: balance + roles + token data
                    let mut state = provider
                        .latest()
                        .map_err(|e| internal_rpc_err(e.to_string()))?;

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
                        global_log_idx += 1;
                        continue;
                    }

                    let token = Token {
                        address: token_address,
                        created_at: timestamp,
                        creator: event.admin,
                        currency: event.currency.clone(),
                        decimals: 6,
                        name: event.name.clone(),
                        paused,
                        quote_token,
                        supply_cap: supply_cap.try_into().unwrap_or(u128::MAX),
                        symbol: event.symbol.clone(),
                        token_id: token_id_from_address(token_address),
                        total_supply: total_supply.try_into().unwrap_or(u128::MAX),
                        transfer_policy_id,
                    };

                    if !matches_token_filters(&token, &filters) {
                        global_log_idx += 1;
                        continue;
                    }

                    if results.len() >= limit {
                        next_cursor = Some(format!("{block_num}:{global_log_idx}"));
                        break 'outer;
                    }

                    results.push(AccountToken {
                        balance,
                        roles: account_roles,
                        token,
                    });

                    global_log_idx += 1;
                }
            }
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
