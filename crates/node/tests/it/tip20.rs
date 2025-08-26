use alloy::{
    primitives::{Address, FixedBytes, U256},
    providers::ProviderBuilder,
    signers::local::{MnemonicBuilder, coins_bip39::English},
    sol_types::SolEvent,
    transports::http::reqwest::Url,
};
use futures::future::try_join_all;
use reth_ethereum::tasks::TaskManager;
use reth_node_builder::{NodeBuilder, NodeConfig, NodeHandle};
use reth_node_core::args::RpcServerArgs;
use std::sync::Arc;
use tempo_chainspec::spec::TempoChainSpec;
use tempo_node::node::{TEMPO_BASE_FEE, TempoNode};
use tempo_precompiles::{
    TIP403_REGISTRY_ADDRESS,
    contracts::{
        ITIP20::{self},
        types::ITIP403Registry,
    },
};

use crate::utils::setup_test_token;

#[tokio::test(flavor = "multi_thread")]
async fn test_tip20_transfer() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let tasks = TaskManager::current();
    let executor = tasks.executor();
    let chain_spec = TempoChainSpec::from_genesis(serde_json::from_str(include_str!(
        "../assets/test-genesis.json"
    ))?);

    let node_config = NodeConfig::new(Arc::new(chain_spec))
        .with_unused_ports()
        .dev()
        .with_rpc(RpcServerArgs::default().with_unused_ports().with_http());

    let NodeHandle {
        node,
        node_exit_future: _,
    } = NodeBuilder::new(node_config.clone())
        .testing_node(executor.clone())
        .node(TempoNode::default())
        .launch_with_debug_capabilities()
        .await?;

    let http_url: Url = node
        .rpc_server_handle()
        .http_url()
        .unwrap()
        .parse()
        .unwrap();

    let wallet = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url.clone());
    let token = setup_test_token(provider.clone(), caller).await?;

    // Create accounts with random balances
    // NOTE: The tests-genesis.json pre allocates feeToken balances for gas fees
    let account_data: Vec<_> = (1..100)
        .map(|i| {
            let signer = MnemonicBuilder::<English>::default()
                .phrase("test test test test test test test test test test test junk")
                .index(i as u32)
                .unwrap()
                .build()
                .unwrap();
            let account = signer.address();
            let balance = U256::from(rand::random::<u32>());
            (account, signer, balance)
        })
        .collect();

    // Mint tokens to each account
    let mut pending_txs = vec![];
    for (account, _, balance) in &account_data {
        pending_txs.push(
            token
                .mint(*account, *balance)
                .gas_price(TEMPO_BASE_FEE as u128)
                .send()
                .await?,
        );
    }

    for tx in pending_txs.drain(..) {
        tx.get_receipt().await?;
    }

    // Verify initial balances
    for (account, _, expected_balance) in &account_data {
        let balance = token.balanceOf(*account).call().await?;
        assert_eq!(balance, *expected_balance);
    }

    // Transfer all balances to target address
    let mut tx_data = vec![];
    for (account, wallet, _) in account_data.iter() {
        let recipient = Address::random();
        let account_provider = ProviderBuilder::new()
            .wallet(wallet.clone())
            .connect_http(http_url.clone());
        let token = ITIP20::new(*token.address(), account_provider);

        let sender_balance = token.balanceOf(*account).call().await?;
        let recipient_balance = token.balanceOf(recipient).call().await?;

        // Simulate the tx and send
        let success = token.transfer(recipient, sender_balance).call().await?;
        assert!(success);
        let pending_tx = token
            .transfer(recipient, sender_balance)
            .gas_price(TEMPO_BASE_FEE as u128)
            .send()
            .await?;

        tx_data.push((pending_tx, sender_balance, recipient, recipient_balance));
    }

    for (pending_tx, sender_balance, recipient, receipient_balance) in tx_data.into_iter() {
        let receipt = pending_tx.get_receipt().await?;

        // Verify Transfer event was emitted
        let transfer_events: Vec<_> = receipt
            .logs()
            .iter()
            .filter_map(|log| ITIP20::Transfer::decode_log(&log.inner).ok())
            .collect();
        assert!(
            !transfer_events.is_empty(),
            "Transfer event should be emitted"
        );
        let transfer_event = &transfer_events[0];
        assert_eq!(transfer_event.from, receipt.from);
        assert_eq!(transfer_event.to, recipient);
        assert_eq!(transfer_event.amount, sender_balance);

        // Check balances after transfer
        let sender_balance_after = token.balanceOf(receipt.from).call().await?;
        let recipient_balance_after = token.balanceOf(recipient).call().await?;

        assert_eq!(sender_balance_after, U256::ZERO);
        assert_eq!(recipient_balance_after, receipient_balance + sender_balance);
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tip20_mint() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let tasks = TaskManager::current();
    let executor = tasks.executor();
    let chain_spec = TempoChainSpec::from_genesis(serde_json::from_str(include_str!(
        "../assets/test-genesis.json"
    ))?);

    let node_config = NodeConfig::new(Arc::new(chain_spec))
        .with_unused_ports()
        .dev()
        .with_rpc(RpcServerArgs::default().with_unused_ports().with_http());

    let NodeHandle {
        node,
        node_exit_future: _,
    } = NodeBuilder::new(node_config.clone())
        .testing_node(executor.clone())
        .node(TempoNode::default())
        .launch_with_debug_capabilities()
        .await?;

    let http_url: Url = node
        .rpc_server_handle()
        .http_url()
        .unwrap()
        .parse()
        .unwrap();

    let wallet = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url.clone());

    // Deploy and setup token
    let token = setup_test_token(provider.clone(), caller).await?;

    // Create accounts with random balances
    let account_data: Vec<_> = (1..100)
        .map(|_| {
            let account = Address::random();
            let balance = U256::from(rand::random::<u32>());
            (account, balance)
        })
        .collect();

    // Mint tokens to each account
    let mut pending_txs = vec![];
    for (account, balance) in &account_data {
        pending_txs.push(
            token
                .mint(*account, *balance)
                .gas_price(TEMPO_BASE_FEE as u128)
                .send()
                .await?,
        );
    }

    for (tx, (account, expected_balance)) in pending_txs.drain(..).zip(account_data.iter()) {
        let receipt = tx.get_receipt().await?;

        // Verify Mint event was emitted
        let mint_event = receipt
            .logs()
            .iter()
            .filter_map(|log| ITIP20::Mint::decode_log(&log.inner).ok())
            .next()
            .expect("Mint event should be emitted");

        assert_eq!(mint_event.to, *account);
        assert_eq!(mint_event.amount, *expected_balance);
    }

    // Verify balances after minting
    for (account, expected_balance) in &account_data {
        let balance = token.balanceOf(*account).call().await?;
        assert_eq!(balance, *expected_balance);
    }

    // Try to mint U256::MAX and assert it causes a SupplyCapExceeded error
    let max_mint_result = token.mint(Address::random(), U256::MAX).call().await;
    assert!(max_mint_result.is_err(), "Minting U256::MAX should fail");

    // TODO: Update to assert the actual error once Precompile errors are propagated through revm
    let err = max_mint_result.unwrap_err();
    assert!(err.to_string().contains("PrecompileError"));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tip20_transfer_from() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let tasks = TaskManager::current();
    let executor = tasks.executor();
    let chain_spec = TempoChainSpec::from_genesis(serde_json::from_str(include_str!(
        "../assets/test-genesis.json"
    ))?);

    let node_config = NodeConfig::new(Arc::new(chain_spec))
        .with_unused_ports()
        .dev()
        .with_rpc(RpcServerArgs::default().with_unused_ports().with_http());

    let NodeHandle {
        node,
        node_exit_future: _,
    } = NodeBuilder::new(node_config.clone())
        .testing_node(executor.clone())
        .node(TempoNode::default())
        .launch_with_debug_capabilities()
        .await?;

    let http_url: Url = node
        .rpc_server_handle()
        .http_url()
        .unwrap()
        .parse()
        .unwrap();

    let owner = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .build()?;
    let caller = owner.address();
    let provider = ProviderBuilder::new()
        .wallet(owner)
        .connect_http(http_url.clone());

    // Deploy and setup token
    let token = setup_test_token(provider.clone(), caller).await?;
    let account_data: Vec<_> = (1..20)
        .map(|i| {
            let signer = MnemonicBuilder::<English>::default()
                .phrase("test test test test test test test test test test test junk")
                .index(i as u32)
                .unwrap()
                .build()
                .unwrap();
            let balance = U256::from(rand::random::<u32>());
            (signer, balance)
        })
        .collect();

    // Mint the total balance for the caller
    let total_balance: U256 = account_data.iter().map(|(_, balance)| *balance).sum();
    token
        .mint(caller, total_balance)
        .gas_price(TEMPO_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Update allowance for each sender account
    let mut pending_txs = vec![];
    for (signer, balance) in account_data.iter() {
        let allowance = token.allowance(caller, signer.address()).call().await?;
        assert_eq!(allowance, U256::ZERO);
        pending_txs.push(
            token
                .approve(signer.address(), *balance)
                .gas_price(TEMPO_BASE_FEE as u128)
                .send()
                .await?,
        );
    }

    for tx in pending_txs.drain(..) {
        tx.get_receipt().await?;
    }

    // Verify allowances are set
    for (account, expected_balance) in account_data.iter() {
        let allowance = token.allowance(caller, account.address()).call().await?;
        assert_eq!(allowance, *expected_balance);
    }

    // Test transferFrom for each account
    let mut pending_tx_data = vec![];
    for (wallet, allowance) in account_data.iter() {
        let recipient = Address::random();
        let spender_provider = ProviderBuilder::new()
            .wallet(wallet.clone())
            .connect_http(http_url.clone());
        let spender_token = ITIP20::new(*token.address(), spender_provider);

        // Expect transferFrom to fail if it exceeds balance
        let excess_result = spender_token
            .transferFrom(caller, recipient, *allowance + U256::ONE)
            .call()
            .await;

        // TODO: update to expect the exact error once PrecompileError is propagated through revm
        assert!(
            excess_result.is_err(),
            "Transfer should fail when exceeding allowance"
        );

        let pending_tx = spender_token
            .transferFrom(caller, recipient, *allowance)
            .gas_price(TEMPO_BASE_FEE as u128)
            .send()
            .await?;

        pending_tx_data.push((pending_tx, recipient, allowance));
    }

    for (tx, recipient, allowance) in pending_tx_data {
        let receipt = tx.get_receipt().await?;

        // Verify allowance is decremented
        let remaining_allowance = token.allowance(caller, receipt.from).call().await?;
        assert_eq!(remaining_allowance, U256::ZERO);

        // Verify recipient received tokens
        let recipient_balance = token.balanceOf(recipient).call().await?;
        assert_eq!(recipient_balance, *allowance);
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tip20_transfer_with_memo() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let tasks = TaskManager::current();
    let executor = tasks.executor();
    let chain_spec = TempoChainSpec::from_genesis(serde_json::from_str(include_str!(
        "../assets/test-genesis.json"
    ))?);

    let node_config = NodeConfig::new(Arc::new(chain_spec))
        .with_unused_ports()
        .dev()
        .with_rpc(RpcServerArgs::default().with_unused_ports().with_http());

    let NodeHandle {
        node,
        node_exit_future: _,
    } = NodeBuilder::new(node_config.clone())
        .testing_node(executor.clone())
        .node(TempoNode::default())
        .launch_with_debug_capabilities()
        .await?;

    let http_url: Url = node
        .rpc_server_handle()
        .http_url()
        .unwrap()
        .parse()
        .unwrap();

    let wallet = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url.clone());

    let token = setup_test_token(provider.clone(), caller).await?;

    let transfer_amount = U256::from(500u32);
    let recipient = Address::random();
    token
        .mint(caller, transfer_amount)
        .gas_price(TEMPO_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Test transfer with memo
    let memo = FixedBytes::<32>::random();
    let receipt = token
        .transferWithMemo(recipient, transfer_amount, memo)
        .gas_price(TEMPO_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Verify TransferWithMemo event was emitted
    let memo_event = receipt
        .logs()
        .iter()
        .filter_map(|log| ITIP20::TransferWithMemo::decode_log(&log.inner).ok())
        .next()
        .unwrap();
    assert_eq!(memo_event.from, caller);
    assert_eq!(memo_event.to, recipient);
    assert_eq!(memo_event.amount, transfer_amount);
    assert_eq!(memo_event.memo, memo);

    let sender_balance = token.balanceOf(caller).call().await?;
    let recipient_balance = token.balanceOf(recipient).call().await?;
    assert_eq!(sender_balance, U256::ZERO);
    assert_eq!(recipient_balance, transfer_amount);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tip20_blacklist() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let tasks = TaskManager::current();
    let executor = tasks.executor();
    let chain_spec = TempoChainSpec::from_genesis(serde_json::from_str(include_str!(
        "../assets/test-genesis.json"
    ))?);

    let node_config = NodeConfig::new(Arc::new(chain_spec))
        .with_unused_ports()
        .dev()
        .with_rpc(RpcServerArgs::default().with_unused_ports().with_http());

    let NodeHandle {
        node,
        node_exit_future: _,
    } = NodeBuilder::new(node_config.clone())
        .testing_node(executor.clone())
        .node(TempoNode::default())
        .launch_with_debug_capabilities()
        .await?;

    let http_url: Url = node
        .rpc_server_handle()
        .http_url()
        .unwrap()
        .parse()
        .unwrap();

    let wallet = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .build()?;
    let admin = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url.clone());

    let token = setup_test_token(provider.clone(), admin).await?;
    let registry = ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, provider.clone());

    // Create a blacklist policy
    let policy_receipt = registry
        .createPolicy(admin, ITIP403Registry::PolicyType::BLACKLIST)
        .gas_price(TEMPO_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;

    let policy_id = policy_receipt
        .logs()
        .iter()
        .filter_map(|log| ITIP403Registry::PolicyCreated::decode_log(&log.inner).ok())
        .next()
        .expect("PolicyCreated event should be emitted")
        .policyId;

    // Update the token policy to the blacklist
    token
        .changeTransferPolicyId(policy_id)
        .gas_price(TEMPO_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;

    let accounts: Vec<_> = (1..100)
        .map(|i| {
            MnemonicBuilder::<English>::default()
                .phrase("test test test test test test test test test test test junk")
                .index(i)
                .unwrap()
                .build()
                .unwrap()
        })
        .collect();

    let (allowed_accounts, blacklisted_accounts) = accounts.split_at(accounts.len() / 2);

    // Add accounts to blacklist
    try_join_all(blacklisted_accounts.iter().map(|account| async {
        registry
            .modifyPolicyBlacklist(policy_id, account.address(), true)
            .gas_price(TEMPO_BASE_FEE as u128)
            .send()
            .await
            .expect("Could not send tx")
            .get_receipt()
            .await
    }))
    .await?;

    // Mint tokens to all accounts
    try_join_all(accounts.iter().map(|account| async {
        token
            .mint(account.address(), U256::from(1000))
            .gas_price(TEMPO_BASE_FEE as u128)
            .send()
            .await
            .expect("Could not send tx")
            .get_receipt()
            .await
    }))
    .await?;

    // Ensure blacklisted accounts can't send tokens
    for account in blacklisted_accounts {
        let provider = ProviderBuilder::new()
            .wallet(account.clone())
            .connect_http(http_url.clone());
        let token = ITIP20::new(*token.address(), provider);

        let transfer_result = token.transfer(Address::random(), U256::ONE).call().await;
        // TODO: assert the actual error once PrecompileError is propagated through revm
        assert!(transfer_result.is_err(),);
    }

    // Ensure non blacklisted accounts can send tokens
    try_join_all(allowed_accounts.iter().zip(blacklisted_accounts).map(
        |(allowed, blacklisted)| async {
            let provider = ProviderBuilder::new()
                .wallet(allowed.clone())
                .connect_http(http_url.clone());
            let token = ITIP20::new(*token.address(), provider);

            // Ensure that blacklisted accounts can not receive tokens
            let transfer_result = token
                .transfer(blacklisted.address(), U256::ONE)
                .call()
                .await;
            // TODO: assert the actual error once PrecompileError is propagated through revm
            assert!(transfer_result.is_err(),);

            token
                .transfer(Address::random(), U256::ONE)
                .gas_price(TEMPO_BASE_FEE as u128)
                .send()
                .await
                .expect("Could not send tx")
                .get_receipt()
                .await
        },
    ))
    .await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tip20_whitelist() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let tasks = TaskManager::current();
    let executor = tasks.executor();
    let chain_spec = TempoChainSpec::from_genesis(serde_json::from_str(include_str!(
        "../assets/test-genesis.json"
    ))?);

    let node_config = NodeConfig::new(Arc::new(chain_spec))
        .with_unused_ports()
        .dev()
        .with_rpc(RpcServerArgs::default().with_unused_ports().with_http());

    let NodeHandle {
        node,
        node_exit_future: _,
    } = NodeBuilder::new(node_config.clone())
        .testing_node(executor.clone())
        .node(TempoNode::default())
        .launch_with_debug_capabilities()
        .await?;

    let http_url: Url = node
        .rpc_server_handle()
        .http_url()
        .unwrap()
        .parse()
        .unwrap();

    let wallet = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .build()?;
    let admin = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url.clone());

    let token = setup_test_token(provider.clone(), admin).await?;
    let registry = ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, provider.clone());

    // Create a whitelist policy
    let policy_receipt = registry
        .createPolicy(admin, ITIP403Registry::PolicyType::WHITELIST)
        .gas_price(TEMPO_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;

    let policy_id = policy_receipt
        .logs()
        .iter()
        .filter_map(|log| ITIP403Registry::PolicyCreated::decode_log(&log.inner).ok())
        .next()
        .expect("PolicyCreated event should be emitted")
        .policyId;

    // Update the token policy to the whitelist
    token
        .changeTransferPolicyId(policy_id)
        .gas_price(TEMPO_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;

    let accounts: Vec<_> = (1..100)
        .map(|i| {
            MnemonicBuilder::<English>::default()
                .phrase("test test test test test test test test test test test junk")
                .index(i)
                .unwrap()
                .build()
                .unwrap()
        })
        .collect();

    let (whitelisted_senders, non_whitelisted_accounts) = accounts.split_at(accounts.len() / 2);
    let whitelisted_receivers: Vec<Address> = (0..whitelisted_senders.len())
        .map(|_| Address::random())
        .collect();

    let whitelisted_accounts: Vec<Address> = whitelisted_senders
        .iter()
        .map(|acct| acct.address())
        .chain(whitelisted_receivers.iter().copied())
        .collect();

    // Add senders and recipients to whitelist
    try_join_all(whitelisted_accounts.iter().map(|account| async {
        registry
            .modifyPolicyWhitelist(policy_id, *account, true)
            .gas_price(TEMPO_BASE_FEE as u128)
            .send()
            .await
            .expect("Could not send tx")
            .get_receipt()
            .await
    }))
    .await?;

    // Mint tokens to all accounts
    try_join_all(accounts.iter().map(|account| async {
        token
            .mint(account.address(), U256::from(1000))
            .gas_price(TEMPO_BASE_FEE as u128)
            .send()
            .await
            .expect("Could not send tx")
            .get_receipt()
            .await
    }))
    .await?;

    // Create providers and tokens for whitelisted senders
    let whitelisted_senders: Vec<_> = whitelisted_senders
        .iter()
        .map(|account| {
            let provider = ProviderBuilder::new()
                .wallet(account.clone())
                .connect_http(http_url.clone());
            ITIP20::new(*token.address(), provider)
        })
        .collect();

    // Ensure non-whitelisted accounts can't send tokens
    for account in non_whitelisted_accounts {
        let provider = ProviderBuilder::new()
            .wallet(account.clone())
            .connect_http(http_url.clone());
        let token = ITIP20::new(*token.address(), provider);

        let transfer_result = token.transfer(Address::random(), U256::ONE).call().await;
        assert!(transfer_result.is_err());
    }

    // Ensure whitelisted accounts can't send to non-whitelisted receivers
    for sender in whitelisted_senders.iter() {
        let transfer_result = sender.transfer(Address::random(), U256::ONE).call().await;
        // TODO: assert the actual error once PrecompileError is propagated through revm
        assert!(transfer_result.is_err());
    }

    // Ensure whitelisted accounts can send tokens to whitelisted recipients
    try_join_all(
        whitelisted_senders
            .iter()
            .zip(whitelisted_receivers.iter())
            .map(|(token, recipient)| async {
                token
                    .transfer(*recipient, U256::ONE)
                    .gas_price(TEMPO_BASE_FEE as u128)
                    .send()
                    .await
                    .expect("Could not send tx")
                    .get_receipt()
                    .await
            }),
    )
    .await?;

    Ok(())
}
