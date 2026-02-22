use alloy::{
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::MnemonicBuilder,
};
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_contracts::precompiles::IRolesAuth;
use tempo_node::rpc::{
    eth_ext::transactions::{TransactionsFilter, TransactionsResponse},
    token::{
        role_history::{RoleHistoryFilters, RoleHistoryResponse},
        tokens::{TokensFilters, TokensResponse},
        tokens_by_address::{TokensByAddressParams, TokensByAddressResponse},
    },
};
use tempo_alloy::rpc::pagination::{PaginationParams, Sort, SortOrder};
use tempo_precompiles::tip20::{ISSUER_ROLE, roles::DEFAULT_ADMIN_ROLE};

use crate::utils::{TEST_MNEMONIC, TestNodeBuilder, setup_test_token};

// ---------------------------------------------------------------------------
// token_getTokens
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn test_get_tokens_basic() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url);

    // Create 2 tokens
    let _token1 = setup_test_token(provider.clone(), caller).await?;
    let _token2 = setup_test_token(provider.clone(), caller).await?;

    let params = PaginationParams::<TokensFilters> {
        cursor: None,
        filters: None,
        limit: None,
        sort: None,
    };

    let response: TokensResponse = provider
        .raw_request("token_getTokens".into(), (params,))
        .await?;

    // PATH_USD is also a TIP20 token created at genesis, so we expect >= 2
    assert!(
        response.tokens.len() >= 2,
        "expected at least 2 tokens, got {}",
        response.tokens.len()
    );

    // Verify the tokens we created are present
    for token in &response.tokens {
        assert_eq!(token.decimals, 6);
        assert!(!token.address.is_zero());
        assert!(token.token_id > 0);
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_tokens_with_filters() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url);

    // Create a token with known name
    let _token = setup_test_token(provider.clone(), caller).await?;

    // Filter by symbol "TEST"
    let params = PaginationParams {
        cursor: None,
        filters: Some(TokensFilters {
            symbol: Some("TEST".to_string()),
            ..Default::default()
        }),
        limit: None,
        sort: None,
    };

    let response: TokensResponse = provider
        .raw_request("token_getTokens".into(), (params,))
        .await?;

    assert!(
        !response.tokens.is_empty(),
        "expected at least 1 token with symbol TEST"
    );
    for token in &response.tokens {
        assert_eq!(token.symbol, "TEST");
        assert_eq!(token.currency, "USD");
        assert_eq!(token.name, "Test");
    }

    // Filter by creator
    let params_creator = PaginationParams {
        cursor: None,
        filters: Some(TokensFilters {
            creator: Some(caller),
            ..Default::default()
        }),
        limit: None,
        sort: None,
    };

    let response_creator: TokensResponse = provider
        .raw_request("token_getTokens".into(), (params_creator,))
        .await?;

    for token in &response_creator.tokens {
        assert_eq!(token.creator, caller);
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_tokens_pagination() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url);

    // Create 3 tokens
    let _t1 = setup_test_token(provider.clone(), caller).await?;
    let _t2 = setup_test_token(provider.clone(), caller).await?;
    let _t3 = setup_test_token(provider.clone(), caller).await?;

    // Only fetch our TEST tokens (exclude genesis tokens) with limit=2
    let params = PaginationParams {
        cursor: None,
        filters: Some(TokensFilters {
            symbol: Some("TEST".to_string()),
            ..Default::default()
        }),
        limit: Some(2),
        sort: None,
    };

    let page1: TokensResponse = provider
        .raw_request("token_getTokens".into(), (params,))
        .await?;

    assert_eq!(page1.tokens.len(), 2, "first page should have 2 tokens");
    assert!(
        page1.next_cursor.is_some(),
        "next_cursor should exist for more results"
    );

    // Fetch next page using cursor
    let params2 = PaginationParams {
        cursor: page1.next_cursor.clone(),
        filters: Some(TokensFilters {
            symbol: Some("TEST".to_string()),
            ..Default::default()
        }),
        limit: Some(2),
        sort: None,
    };

    let page2: TokensResponse = provider
        .raw_request("token_getTokens".into(), (params2,))
        .await?;

    assert!(
        !page2.tokens.is_empty(),
        "second page should have at least 1 token"
    );

    // Ensure no duplicates between pages
    let page1_addrs: Vec<_> = page1.tokens.iter().map(|t| t.address).collect();
    for token in &page2.tokens {
        assert!(
            !page1_addrs.contains(&token.address),
            "second page should not repeat tokens from first page"
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// token_getRoleHistory
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn test_get_role_history_basic() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url);

    // setup_test_token creates a token AND grants ISSUER_ROLE to caller
    let token = setup_test_token(provider.clone(), caller).await?;

    let params = PaginationParams::<RoleHistoryFilters> {
        cursor: None,
        filters: Some(RoleHistoryFilters {
            token: Some(*token.address()),
            ..Default::default()
        }),
        limit: None,
        sort: None,
    };

    let response: RoleHistoryResponse = provider
        .raw_request("token_getRoleHistory".into(), (params,))
        .await?;

    // Token creation grants DEFAULT_ADMIN_ROLE, then we grant ISSUER_ROLE
    assert!(
        response.role_changes.len() >= 2,
        "expected at least 2 role changes (admin + issuer), got {}",
        response.role_changes.len()
    );

    // All role changes should be for this token
    for rc in &response.role_changes {
        assert_eq!(rc.token, *token.address());
        assert!(rc.granted, "all initial role changes should be grants");
        assert!(!rc.transaction_hash.is_zero());
        assert!(rc.timestamp > 0);
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_role_history_with_filters() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url);

    let token = setup_test_token(provider.clone(), caller).await?;

    // Grant a role to a random account
    let target = Address::random();
    let roles = IRolesAuth::new(*token.address(), provider.clone());
    roles
        .grantRole(*ISSUER_ROLE, target)
        .gas(1_000_000)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Revoke the role
    roles
        .revokeRole(*ISSUER_ROLE, target)
        .gas(1_000_000)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Filter: only grants
    let params_grants = PaginationParams {
        cursor: None,
        filters: Some(RoleHistoryFilters {
            token: Some(*token.address()),
            granted: Some(true),
            ..Default::default()
        }),
        limit: None,
        sort: None,
    };

    let grants_response: RoleHistoryResponse = provider
        .raw_request("token_getRoleHistory".into(), (params_grants,))
        .await?;

    for rc in &grants_response.role_changes {
        assert!(rc.granted, "expected only grant events");
    }

    // Filter: only revocations
    let params_revokes = PaginationParams {
        cursor: None,
        filters: Some(RoleHistoryFilters {
            token: Some(*token.address()),
            granted: Some(false),
            ..Default::default()
        }),
        limit: None,
        sort: None,
    };

    let revokes_response: RoleHistoryResponse = provider
        .raw_request("token_getRoleHistory".into(), (params_revokes,))
        .await?;

    assert!(
        !revokes_response.role_changes.is_empty(),
        "expected at least 1 revocation"
    );
    for rc in &revokes_response.role_changes {
        assert!(!rc.granted, "expected only revoke events");
    }

    // Filter: by account
    let params_account = PaginationParams {
        cursor: None,
        filters: Some(RoleHistoryFilters {
            token: Some(*token.address()),
            account: Some(target),
            ..Default::default()
        }),
        limit: None,
        sort: None,
    };

    let account_response: RoleHistoryResponse = provider
        .raw_request("token_getRoleHistory".into(), (params_account,))
        .await?;

    assert!(
        account_response.role_changes.len() >= 2,
        "expected grant + revoke for target"
    );
    for rc in &account_response.role_changes {
        assert_eq!(rc.account, target);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// token_getTokensByAddress
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn test_get_tokens_by_address_basic() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url);

    // Create a token - caller gets DEFAULT_ADMIN_ROLE and ISSUER_ROLE
    let token = setup_test_token(provider.clone(), caller).await?;

    // Mint some balance to caller
    token
        .mint(caller, U256::from(1000u64))
        .gas(1_000_000)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;

    let params = TokensByAddressParams {
        address: caller,
        params: PaginationParams {
            cursor: None,
            filters: None,
            limit: None,
            sort: None,
        },
    };

    let response: TokensByAddressResponse = provider
        .raw_request("token_getTokensByAddress".into(), (params,))
        .await?;

    // Caller should have at least the token we created (has balance + roles)
    assert!(
        !response.tokens.is_empty(),
        "expected at least 1 token for caller"
    );

    // Find our specific token
    let our_token = response
        .tokens
        .iter()
        .find(|at| at.token.address == *token.address());
    assert!(our_token.is_some(), "our token should be in the response");

    let our_token = our_token.unwrap();
    assert_eq!(our_token.balance, U256::from(1000u64));
    assert!(
        !our_token.roles.is_empty(),
        "caller should have roles on the token"
    );
    // Caller should have DEFAULT_ADMIN_ROLE and ISSUER_ROLE
    assert!(our_token.roles.contains(&DEFAULT_ADMIN_ROLE));
    assert!(our_token.roles.contains(&*ISSUER_ROLE));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_tokens_by_address_no_association() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url);

    // Create a token so there's something in the chain
    let _token = setup_test_token(provider.clone(), caller).await?;

    // Query for a random address that has no association
    let random_addr = Address::random();
    let params = TokensByAddressParams {
        address: random_addr,
        params: PaginationParams {
            cursor: None,
            filters: None,
            limit: None,
            sort: None,
        },
    };

    let response: TokensByAddressResponse = provider
        .raw_request("token_getTokensByAddress".into(), (params,))
        .await?;

    assert!(
        response.tokens.is_empty(),
        "random address should have no token associations"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// eth_getTransactions
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn test_get_transactions_basic() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url);

    // Create a token (generates transactions)
    let token = setup_test_token(provider.clone(), caller).await?;

    // Mint to generate another transaction
    token
        .mint(caller, U256::from(500u64))
        .gas(1_000_000)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;

    let params = PaginationParams::<TransactionsFilter> {
        cursor: None,
        filters: None,
        limit: None,
        sort: None,
    };

    let response: TransactionsResponse = provider
        .raw_request("eth_getTransactions".into(), (params,))
        .await?;

    assert!(
        !response.transactions.is_empty(),
        "expected at least 1 transaction"
    );

    // Default sort is DESC, verify block numbers are non-increasing
    for window in response.transactions.windows(2) {
        let a = window[0].block_number.unwrap_or(0);
        let b = window[1].block_number.unwrap_or(0);
        assert!(a >= b, "expected DESC order: block {} >= {}", a, b);
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_transactions_with_from_filter() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url);

    // Create token and mint
    let token = setup_test_token(provider.clone(), caller).await?;
    token
        .mint(caller, U256::from(100u64))
        .gas(1_000_000)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Filter by sender
    let params = PaginationParams {
        cursor: None,
        filters: Some(TransactionsFilter {
            from: Some(caller),
            to: None,
            type_: None,
        }),
        limit: None,
        sort: Some(Sort {
            on: "blockNumber".to_string(),
            order: SortOrder::Asc,
        }),
    };

    let response: TransactionsResponse = provider
        .raw_request("eth_getTransactions".into(), (params,))
        .await?;

    assert!(
        !response.transactions.is_empty(),
        "expected transactions from caller"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_transactions_pagination() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url);

    // Create a token and mint a few times to generate transactions
    let token = setup_test_token(provider.clone(), caller).await?;
    for i in 0..3 {
        token
            .mint(caller, U256::from(100u64 + i))
            .gas(1_000_000)
            .gas_price(TEMPO_T1_BASE_FEE as u128)
            .send()
            .await?
            .get_receipt()
            .await?;
    }

    // Use ascending order and limit=1 so we can paginate
    let params = PaginationParams {
        cursor: None,
        filters: Some(TransactionsFilter {
            from: Some(caller),
            to: None,
            type_: None,
        }),
        limit: Some(1),
        sort: Some(Sort {
            on: "blockNumber".to_string(),
            order: SortOrder::Asc,
        }),
    };

    let page1: TransactionsResponse = provider
        .raw_request("eth_getTransactions".into(), (params,))
        .await?;

    assert_eq!(
        page1.transactions.len(),
        1,
        "first page should have 1 transaction"
    );
    assert!(
        page1.next_cursor.is_some(),
        "should have next_cursor for more results"
    );

    // Fetch second page
    let params2 = PaginationParams {
        cursor: page1.next_cursor.clone(),
        filters: Some(TransactionsFilter {
            from: Some(caller),
            to: None,
            type_: None,
        }),
        limit: Some(1),
        sort: Some(Sort {
            on: "blockNumber".to_string(),
            order: SortOrder::Asc,
        }),
    };

    let page2: TransactionsResponse = provider
        .raw_request("eth_getTransactions".into(), (params2,))
        .await?;

    assert_eq!(
        page2.transactions.len(),
        1,
        "second page should have 1 transaction"
    );

    // Transactions should be different
    let hash1 = page1.transactions[0].block_number;
    let hash2 = page2.transactions[0].block_number;
    // In ASC order, second page block should be >= first page
    assert!(
        hash2 >= hash1,
        "ascending: second page block should be >= first"
    );

    Ok(())
}
