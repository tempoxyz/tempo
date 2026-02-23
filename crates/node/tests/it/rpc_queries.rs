use alloy::{
    primitives::{Address, B256, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::MnemonicBuilder,
};
use tempo_alloy::rpc::pagination::{FilterRange, PaginationParams, Sort, SortOrder};
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
use tempo_precompiles::{
    PATH_USD_ADDRESS,
    tip20::{ISSUER_ROLE, PAUSE_ROLE, roles::DEFAULT_ADMIN_ROLE},
};
use tempo_primitives::TempoTxType;

use crate::utils::{TEST_MNEMONIC, TestNodeBuilder, setup_test_token};

#[tokio::test(flavor = "multi_thread")]
async fn test_get_tokens_basic() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

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
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

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
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

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

#[tokio::test(flavor = "multi_thread")]
async fn test_get_role_history_basic() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

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
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

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

#[tokio::test(flavor = "multi_thread")]
async fn test_get_tokens_by_address_basic() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

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
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

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

#[tokio::test(flavor = "multi_thread")]
async fn test_get_transactions_basic() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

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
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

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
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

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

#[tokio::test(flavor = "multi_thread")]
async fn test_get_transactions_desc_pagination() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

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

    // Use DESC order and limit=1 so we can paginate
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
            order: SortOrder::Desc,
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
            order: SortOrder::Desc,
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

    // In DESC order, second page block should be <= first page
    let block1 = page1.transactions[0].block_number;
    let block2 = page2.transactions[0].block_number;
    assert!(
        block2 <= block1,
        "descending: second page block {:?} should be <= first {:?}",
        block2,
        block1
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_tokens_filter_currency() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let _token = setup_test_token(provider.clone(), caller).await?;

    // Filter by currency "USD" (setup_test_token uses "USD")
    let params = PaginationParams {
        cursor: None,
        filters: Some(TokensFilters {
            currency: Some("USD".to_string()),
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
        "expected tokens with currency USD"
    );
    for token in &response.tokens {
        assert_eq!(token.currency, "USD");
    }

    // Filter by non-existent currency
    let params_none = PaginationParams {
        cursor: None,
        filters: Some(TokensFilters {
            currency: Some("XYZ_NONEXISTENT".to_string()),
            ..Default::default()
        }),
        limit: None,
        sort: None,
    };

    let response_none: TokensResponse = provider
        .raw_request("token_getTokens".into(), (params_none,))
        .await?;

    assert!(
        response_none.tokens.is_empty(),
        "no tokens should match non-existent currency"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_tokens_filter_name() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let _token = setup_test_token(provider.clone(), caller).await?;

    // Name filter is case-insensitive contains
    let params = PaginationParams {
        cursor: None,
        filters: Some(TokensFilters {
            name: Some("test".to_string()), // lowercase should match "Test"
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
        "case-insensitive name filter should match"
    );
    for token in &response.tokens {
        assert!(
            token.name.to_lowercase().contains("test"),
            "token name should contain 'test'"
        );
    }

    // Non-matching name
    let params_none = PaginationParams {
        cursor: None,
        filters: Some(TokensFilters {
            name: Some("ZZZZZ_NO_MATCH".to_string()),
            ..Default::default()
        }),
        limit: None,
        sort: None,
    };

    let response_none: TokensResponse = provider
        .raw_request("token_getTokens".into(), (params_none,))
        .await?;

    assert!(
        response_none.tokens.is_empty(),
        "non-matching name should return empty"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_tokens_filter_paused() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url.clone());

    let token = setup_test_token(provider.clone(), caller).await?;

    // Grant PAUSE_ROLE to caller and pause the token
    let roles = IRolesAuth::new(*token.address(), provider.clone());
    roles
        .grantRole(*PAUSE_ROLE, caller)
        .gas(1_000_000)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;

    use tempo_contracts::precompiles::ITIP20;
    let tip20 = ITIP20::new(*token.address(), provider.clone());
    tip20
        .pause()
        .gas(1_000_000)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Filter paused=true
    let params_paused = PaginationParams {
        cursor: None,
        filters: Some(TokensFilters {
            paused: Some(true),
            symbol: Some("TEST".to_string()),
            ..Default::default()
        }),
        limit: None,
        sort: None,
    };

    let response_paused: TokensResponse = provider
        .raw_request("token_getTokens".into(), (params_paused,))
        .await?;

    assert!(
        !response_paused.tokens.is_empty(),
        "expected at least 1 paused token"
    );
    let paused_token = response_paused
        .tokens
        .iter()
        .find(|t| t.address == *token.address());
    assert!(paused_token.is_some(), "our paused token should appear");
    assert!(paused_token.unwrap().paused);

    // Filter paused=false should NOT return our paused token
    let params_not_paused = PaginationParams {
        cursor: None,
        filters: Some(TokensFilters {
            paused: Some(false),
            ..Default::default()
        }),
        limit: None,
        sort: None,
    };

    let response_not_paused: TokensResponse = provider
        .raw_request("token_getTokens".into(), (params_not_paused,))
        .await?;

    let our_token = response_not_paused
        .tokens
        .iter()
        .find(|t| t.address == *token.address());
    assert!(
        our_token.is_none(),
        "paused token should not appear in paused=false results"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_tokens_filter_quote_token() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    // setup_test_token sets quote_token to PATH_USD_ADDRESS
    let _token = setup_test_token(provider.clone(), caller).await?;

    let params = PaginationParams {
        cursor: None,
        filters: Some(TokensFilters {
            quote_token: Some(PATH_USD_ADDRESS),
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
        "expected tokens with PATH_USD quote_token"
    );
    for token in &response.tokens {
        assert_eq!(token.quote_token, PATH_USD_ADDRESS);
    }

    // Filter by non-existent quote token
    let params_none = PaginationParams {
        cursor: None,
        filters: Some(TokensFilters {
            quote_token: Some(Address::random()),
            ..Default::default()
        }),
        limit: None,
        sort: None,
    };

    let response_none: TokensResponse = provider
        .raw_request("token_getTokens".into(), (params_none,))
        .await?;

    assert!(
        response_none.tokens.is_empty(),
        "no tokens should match random quote_token"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_tokens_filter_supply_ranges() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let token = setup_test_token(provider.clone(), caller).await?;

    // Mint some supply
    let mint_amount = U256::from(5000u64);
    token
        .mint(caller, mint_amount)
        .gas(1_000_000)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Filter total_supply range that includes our token
    let params = PaginationParams {
        cursor: None,
        filters: Some(TokensFilters {
            symbol: Some("TEST".to_string()),
            total_supply: Some(FilterRange {
                min: Some(1000),
                max: Some(10000),
            }),
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
        "expected tokens with total_supply in range"
    );

    let our_token = response
        .tokens
        .iter()
        .find(|t| t.address == *token.address());
    assert!(our_token.is_some());
    assert_eq!(our_token.unwrap().total_supply, 5000);

    // Filter total_supply range that excludes our token
    let params_exclude = PaginationParams {
        cursor: None,
        filters: Some(TokensFilters {
            symbol: Some("TEST".to_string()),
            total_supply: Some(FilterRange {
                min: Some(100_000),
                max: None,
            }),
            ..Default::default()
        }),
        limit: None,
        sort: None,
    };

    let response_exclude: TokensResponse = provider
        .raw_request("token_getTokens".into(), (params_exclude,))
        .await?;

    let our_token_excluded = response_exclude
        .tokens
        .iter()
        .find(|t| t.address == *token.address());
    assert!(
        our_token_excluded.is_none(),
        "our token should be excluded by total_supply range"
    );

    // Filter by supply_cap range (default is u128::MAX)
    let params_cap = PaginationParams {
        cursor: None,
        filters: Some(TokensFilters {
            symbol: Some("TEST".to_string()),
            supply_cap: Some(FilterRange {
                min: Some(1),
                max: None,
            }),
            ..Default::default()
        }),
        limit: None,
        sort: None,
    };

    let response_cap: TokensResponse = provider
        .raw_request("token_getTokens".into(), (params_cap,))
        .await?;

    assert!(
        !response_cap.tokens.is_empty(),
        "tokens should have supply_cap > 0"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_tokens_filter_created_at() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let _token = setup_test_token(provider.clone(), caller).await?;

    // All tokens should be created with timestamp > 0
    let params_all = PaginationParams {
        cursor: None,
        filters: Some(TokensFilters {
            symbol: Some("TEST".to_string()),
            created_at: Some(FilterRange {
                min: Some(1),
                max: None,
            }),
            ..Default::default()
        }),
        limit: None,
        sort: None,
    };

    let response: TokensResponse = provider
        .raw_request("token_getTokens".into(), (params_all,))
        .await?;

    assert!(
        !response.tokens.is_empty(),
        "tokens with created_at > 0 should exist"
    );

    // Filter with a far-future timestamp should return nothing
    let params_future = PaginationParams {
        cursor: None,
        filters: Some(TokensFilters {
            created_at: Some(FilterRange {
                min: Some(u64::MAX - 1),
                max: None,
            }),
            ..Default::default()
        }),
        limit: None,
        sort: None,
    };

    let response_future: TokensResponse = provider
        .raw_request("token_getTokens".into(), (params_future,))
        .await?;

    assert!(
        response_future.tokens.is_empty(),
        "no tokens should exist with far-future created_at"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_role_history_filter_role() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let token = setup_test_token(provider.clone(), caller).await?;

    // Filter by ISSUER_ROLE specifically
    let params = PaginationParams {
        cursor: None,
        filters: Some(RoleHistoryFilters {
            token: Some(*token.address()),
            role: Some(*ISSUER_ROLE),
            ..Default::default()
        }),
        limit: None,
        sort: None,
    };

    let response: RoleHistoryResponse = provider
        .raw_request("token_getRoleHistory".into(), (params,))
        .await?;

    assert!(
        !response.role_changes.is_empty(),
        "expected ISSUER_ROLE grants"
    );
    for rc in &response.role_changes {
        assert_eq!(rc.role, *ISSUER_ROLE, "all results should be ISSUER_ROLE");
    }

    // Filter by DEFAULT_ADMIN_ROLE
    let params_admin = PaginationParams {
        cursor: None,
        filters: Some(RoleHistoryFilters {
            token: Some(*token.address()),
            role: Some(DEFAULT_ADMIN_ROLE),
            ..Default::default()
        }),
        limit: None,
        sort: None,
    };

    let response_admin: RoleHistoryResponse = provider
        .raw_request("token_getRoleHistory".into(), (params_admin,))
        .await?;

    assert!(
        !response_admin.role_changes.is_empty(),
        "expected DEFAULT_ADMIN_ROLE grants"
    );
    for rc in &response_admin.role_changes {
        assert_eq!(rc.role, DEFAULT_ADMIN_ROLE);
    }

    // Filter by a role that was never granted
    let params_none = PaginationParams {
        cursor: None,
        filters: Some(RoleHistoryFilters {
            token: Some(*token.address()),
            role: Some(B256::random()),
            ..Default::default()
        }),
        limit: None,
        sort: None,
    };

    let response_none: RoleHistoryResponse = provider
        .raw_request("token_getRoleHistory".into(), (params_none,))
        .await?;

    assert!(
        response_none.role_changes.is_empty(),
        "random role should have no history"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_role_history_filter_sender() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let token = setup_test_token(provider.clone(), caller).await?;

    // Filter by sender (caller sent the role grants)
    let params = PaginationParams {
        cursor: None,
        filters: Some(RoleHistoryFilters {
            token: Some(*token.address()),
            sender: Some(caller),
            ..Default::default()
        }),
        limit: None,
        sort: None,
    };

    let response: RoleHistoryResponse = provider
        .raw_request("token_getRoleHistory".into(), (params,))
        .await?;

    assert!(
        !response.role_changes.is_empty(),
        "caller should be sender of role changes"
    );
    for rc in &response.role_changes {
        assert_eq!(rc.sender, caller);
    }

    // Filter by random sender should return empty
    let params_random = PaginationParams {
        cursor: None,
        filters: Some(RoleHistoryFilters {
            token: Some(*token.address()),
            sender: Some(Address::random()),
            ..Default::default()
        }),
        limit: None,
        sort: None,
    };

    let response_random: RoleHistoryResponse = provider
        .raw_request("token_getRoleHistory".into(), (params_random,))
        .await?;

    assert!(
        response_random.role_changes.is_empty(),
        "random sender should have no role changes"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_role_history_pagination() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let token = setup_test_token(provider.clone(), caller).await?;

    // Grant additional roles to generate more events
    let roles = IRolesAuth::new(*token.address(), provider.clone());
    let target1 = Address::random();
    let target2 = Address::random();

    roles
        .grantRole(*ISSUER_ROLE, target1)
        .gas(1_000_000)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;

    roles
        .grantRole(*ISSUER_ROLE, target2)
        .gas(1_000_000)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Paginate with limit=1
    let params = PaginationParams {
        cursor: None,
        filters: Some(RoleHistoryFilters {
            token: Some(*token.address()),
            ..Default::default()
        }),
        limit: Some(1),
        sort: None,
    };

    let page1: RoleHistoryResponse = provider
        .raw_request("token_getRoleHistory".into(), (params,))
        .await?;

    assert_eq!(page1.role_changes.len(), 1);
    assert!(
        page1.next_cursor.is_some(),
        "should have next_cursor for more results"
    );

    // Fetch second page
    let params2 = PaginationParams {
        cursor: page1.next_cursor.clone(),
        filters: Some(RoleHistoryFilters {
            token: Some(*token.address()),
            ..Default::default()
        }),
        limit: Some(1),
        sort: None,
    };

    let page2: RoleHistoryResponse = provider
        .raw_request("token_getRoleHistory".into(), (params2,))
        .await?;

    assert_eq!(page2.role_changes.len(), 1);

    // Pages should be different events (different role or different account or different block)
    let rc1 = &page1.role_changes[0];
    let rc2 = &page2.role_changes[0];
    assert!(
        rc1.role != rc2.role || rc1.account != rc2.account || rc1.block_number != rc2.block_number,
        "pages should contain distinct role change events"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_tokens_by_address_only_balance() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let token = setup_test_token(provider.clone(), caller).await?;

    // Mint to a random address that has no roles
    let holder = Address::random();
    token
        .mint(holder, U256::from(500u64))
        .gas(1_000_000)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;

    let params = TokensByAddressParams {
        address: holder,
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

    let our_token = response
        .tokens
        .iter()
        .find(|at| at.token.address == *token.address());
    assert!(our_token.is_some(), "holder should see the token");

    let at = our_token.unwrap();
    assert_eq!(at.balance, U256::from(500u64));
    assert!(
        at.roles.is_empty(),
        "holder should have no roles, got {:?}",
        at.roles
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_tokens_by_address_only_roles() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let token = setup_test_token(provider.clone(), caller).await?;

    // Grant ISSUER_ROLE to a target but don't mint any balance
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

    let params = TokensByAddressParams {
        address: target,
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

    let our_token = response
        .tokens
        .iter()
        .find(|at| at.token.address == *token.address());
    assert!(our_token.is_some(), "target with role should see the token");

    let at = our_token.unwrap();
    assert_eq!(at.balance, U256::ZERO, "target should have zero balance");
    assert!(
        at.roles.contains(&*ISSUER_ROLE),
        "target should have ISSUER_ROLE"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_tokens_by_address_pagination() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    // Create 3 tokens and mint to the same holder
    let holder = Address::random();
    for _ in 0..3 {
        let token = setup_test_token(provider.clone(), caller).await?;
        token
            .mint(holder, U256::from(100u64))
            .gas(1_000_000)
            .gas_price(TEMPO_T1_BASE_FEE as u128)
            .send()
            .await?
            .get_receipt()
            .await?;
    }

    // Paginate with limit=2
    let params = TokensByAddressParams {
        address: holder,
        params: PaginationParams {
            cursor: None,
            filters: None,
            limit: Some(2),
            sort: None,
        },
    };

    let page1: TokensByAddressResponse = provider
        .raw_request("token_getTokensByAddress".into(), (params,))
        .await?;

    assert_eq!(page1.tokens.len(), 2, "first page should have 2 tokens");
    assert!(page1.next_cursor.is_some(), "should have next_cursor");

    // Fetch second page
    let params2 = TokensByAddressParams {
        address: holder,
        params: PaginationParams {
            cursor: page1.next_cursor.clone(),
            filters: None,
            limit: Some(2),
            sort: None,
        },
    };

    let page2: TokensByAddressResponse = provider
        .raw_request("token_getTokensByAddress".into(), (params2,))
        .await?;

    assert!(
        !page2.tokens.is_empty(),
        "second page should have at least 1 token"
    );

    // No duplicates
    let page1_addrs: Vec<_> = page1.tokens.iter().map(|t| t.token.address).collect();
    for at in &page2.tokens {
        assert!(
            !page1_addrs.contains(&at.token.address),
            "no duplicate tokens across pages"
        );
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_transactions_filter_to() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let token = setup_test_token(provider.clone(), caller).await?;

    // Mint sends a transaction TO the token address
    token
        .mint(caller, U256::from(100u64))
        .gas(1_000_000)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Filter by to=token_address
    let params = PaginationParams {
        cursor: None,
        filters: Some(TransactionsFilter {
            from: None,
            to: Some(*token.address()),
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
        "expected transactions sent to token address"
    );

    // Filter by random to address should return empty
    let params_empty = PaginationParams {
        cursor: None,
        filters: Some(TransactionsFilter {
            from: None,
            to: Some(Address::random()),
            type_: None,
        }),
        limit: None,
        sort: None,
    };

    let response_empty: TransactionsResponse = provider
        .raw_request("eth_getTransactions".into(), (params_empty,))
        .await?;

    assert!(
        response_empty.transactions.is_empty(),
        "no transactions should be sent to random address"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_transactions_filter_type() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let _token = setup_test_token(provider.clone(), caller).await?;

    // First, get all transactions to determine what types exist
    let params_all = PaginationParams::<TransactionsFilter> {
        cursor: None,
        filters: Some(TransactionsFilter {
            from: Some(caller),
            to: None,
            type_: None,
        }),
        limit: None,
        sort: None,
    };

    let all_response: TransactionsResponse = provider
        .raw_request("eth_getTransactions".into(), (params_all,))
        .await?;

    assert!(
        !all_response.transactions.is_empty(),
        "should have transactions"
    );

    // Filter by Eip2930 - we never send these, should be empty
    let params_eip2930 = PaginationParams {
        cursor: None,
        filters: Some(TransactionsFilter {
            from: Some(caller),
            to: None,
            type_: Some(TempoTxType::Eip2930),
        }),
        limit: None,
        sort: None,
    };

    let response_eip2930: TransactionsResponse = provider
        .raw_request("eth_getTransactions".into(), (params_eip2930,))
        .await?;

    assert!(
        response_eip2930.transactions.is_empty(),
        "no Eip2930 transactions should exist"
    );

    // Filter by Eip7702 - we also never send these
    let params_eip7702 = PaginationParams {
        cursor: None,
        filters: Some(TransactionsFilter {
            from: Some(caller),
            to: None,
            type_: Some(TempoTxType::Eip7702),
        }),
        limit: None,
        sort: None,
    };

    let response_eip7702: TransactionsResponse = provider
        .raw_request("eth_getTransactions".into(), (params_eip7702,))
        .await?;

    assert!(
        response_eip7702.transactions.is_empty(),
        "no Eip7702 transactions should exist"
    );

    // The total of filtered-by-type counts should be less than or equal to all_from_caller
    // (This verifies the filter is actually restricting results)
    let count_eip2930 = response_eip2930.transactions.len();
    let count_eip7702 = response_eip7702.transactions.len();
    assert!(
        count_eip2930 + count_eip7702 < all_response.transactions.len(),
        "type filter should reduce result count"
    );

    Ok(())
}
