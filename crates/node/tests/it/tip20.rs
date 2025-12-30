use alloy::{
    primitives::{Address, FixedBytes, U256},
    providers::ProviderBuilder,
    signers::local::MnemonicBuilder,
    sol_types::SolEvent,
};
use futures::future::try_join_all;
use tempo_chainspec::spec::TEMPO_BASE_FEE;
use tempo_contracts::precompiles::{ITIP20, ITIP403Registry, TIP20Error};
use tempo_precompiles::TIP403_REGISTRY_ADDRESS;

use crate::utils::{TestNodeBuilder, await_receipts, setup_test_token};

#[tokio::test(flavor = "multi_thread")]
async fn test_tip20_transfer() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url.clone());
    let token = setup_test_token(provider.clone(), caller).await?;

    // Create accounts with random balances
    // NOTE: The tests-genesis.json pre allocates feeToken balances for gas fees
    let account_data: Vec<_> = (1..100)
        .map(|i| {
            let signer = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
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
                .gas(300_000)
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

    // Attempt to transfer more than the balance
    for (_, wallet, balance) in &account_data {
        let account_provider = ProviderBuilder::new()
            .wallet(wallet.clone())
            .connect_http(http_url.clone());
        let account_token = ITIP20::new(*token.address(), account_provider);

        let Err(result) = account_token
            .transfer(Address::random(), balance + U256::ONE)
            .call()
            .await
        else {
            panic!("expected error");
        };
        assert_eq!(
            result.as_decoded_interface_error::<TIP20Error>(),
            Some(TIP20Error::InsufficientBalance(
                ITIP20::InsufficientBalance {
                    available: *balance,
                    required: balance + U256::ONE,
                    token: *token.address()
                }
            ))
        );
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
            .gas(300_000)
            .send()
            .await?;

        tx_data.push((pending_tx, sender_balance, recipient, recipient_balance));
    }

    for (pending_tx, sender_balance, recipient, recipient_balance) in tx_data.into_iter() {
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
        assert_eq!(recipient_balance_after, recipient_balance + sender_balance);
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tip20_mint() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

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
                .gas(300_000)
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

    token
        .setSupplyCap(U256::from(u128::MAX))
        .send()
        .await?
        .get_receipt()
        .await?;

    // Try to mint U256::MAX and assert it causes a SupplyCapExceeded error
    let max_mint_result = token
        .mint(Address::random(), U256::from(u128::MAX))
        .call()
        .await;
    assert!(max_mint_result.is_err(), "Minting U256::MAX should fail");

    let err = max_mint_result.unwrap_err();
    assert_eq!(
        err.as_decoded_interface_error::<TIP20Error>(),
        Some(TIP20Error::SupplyCapExceeded(ITIP20::SupplyCapExceeded {}))
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tip20_transfer_from() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let owner = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = owner.address();
    let provider = ProviderBuilder::new()
        .wallet(owner)
        .connect_http(http_url.clone());

    // Deploy and setup token
    let token = setup_test_token(provider.clone(), caller).await?;
    let account_data: Vec<_> = (1..20)
        .map(|i| {
            let signer = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
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
        .gas(300_000)
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
                .gas(300_000)
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
            .gas(300_000)
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

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let token = setup_test_token(provider.clone(), caller).await?;

    let transfer_amount = U256::from(500u32);
    let recipient = Address::random();
    token
        .mint(caller, transfer_amount)
        .gas_price(TEMPO_BASE_FEE as u128)
        .gas(300_000)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Test transfer with memo
    let memo = FixedBytes::<32>::random();
    let receipt = token
        .transferWithMemo(recipient, transfer_amount, memo)
        .gas_price(TEMPO_BASE_FEE as u128)
        .gas(300_000)
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

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
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
        .gas(300_000)
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
        .gas(300_000)
        .send()
        .await?
        .get_receipt()
        .await?;

    let accounts: Vec<_> = (1..100)
        .map(|i| {
            MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
                .index(i)
                .unwrap()
                .build()
                .unwrap()
        })
        .collect();

    let (allowed_accounts, blacklisted_accounts) = accounts.split_at(accounts.len() / 2);

    let mut pending = vec![];
    for account in blacklisted_accounts {
        let pending_tx = registry
            .modifyPolicyBlacklist(policy_id, account.address(), true)
            .gas_price(TEMPO_BASE_FEE as u128)
            .gas(300_000)
            .send()
            .await?;

        pending.push(pending_tx);
    }

    // Mint tokens to all accounts
    try_join_all(accounts.iter().map(|account| async {
        token
            .mint(account.address(), U256::from(1000))
            .gas_price(TEMPO_BASE_FEE as u128)
            .gas(300_000)
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
                .gas(300_000)
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

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
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
        .gas(300_000)
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
        .gas(300_000)
        .send()
        .await?
        .get_receipt()
        .await?;

    let accounts: Vec<_> = (1..100)
        .map(|i| {
            MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
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
    let mut pending = vec![];
    for account in whitelisted_accounts {
        let pending_tx = registry
            .modifyPolicyWhitelist(policy_id, account, true)
            .gas_price(TEMPO_BASE_FEE as u128)
            .gas(300_000)
            .send()
            .await?;

        pending.push(pending_tx);
    }

    try_join_all(pending.into_iter().map(|tx| tx.get_receipt())).await?;

    // Mint tokens to all accounts
    try_join_all(accounts.iter().map(|account| async {
        token
            .mint(account.address(), U256::from(1000))
            .gas_price(TEMPO_BASE_FEE as u128)
            .gas(300_000)
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

/// Test immediate reward distribution functionality.
#[tokio::test(flavor = "multi_thread")]
async fn test_tip20_rewards() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let admin_wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let admin = admin_wallet.address();
    let admin_provider = ProviderBuilder::new()
        .wallet(admin_wallet)
        .connect_http(http_url.clone());

    let token = setup_test_token(admin_provider.clone(), admin).await?;

    let alice_wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
        .index(1)?
        .build()?;
    let alice = alice_wallet.address();
    let alice_provider = ProviderBuilder::new()
        .wallet(alice_wallet)
        .connect_http(http_url.clone());
    let alice_token = ITIP20::new(*token.address(), alice_provider);

    let bob_wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
        .index(2)?
        .build()?;
    let bob = bob_wallet.address();
    let bob_provider = ProviderBuilder::new()
        .wallet(bob_wallet)
        .connect_http(http_url.clone());
    let bob_token = ITIP20::new(*token.address(), bob_provider);

    let mint_amount = U256::from(1000e18);
    let reward_amount = U256::from(300e18);

    let gas = 300_000;
    let gas_price = TEMPO_BASE_FEE as u128;

    let mut pending = vec![];
    pending.push(
        token
            .mint(alice, mint_amount)
            .gas(gas)
            .gas_price(gas_price)
            .send()
            .await?,
    );
    pending.push(
        token
            .mint(admin, reward_amount)
            .gas(gas)
            .gas_price(gas_price)
            .send()
            .await?,
    );
    pending.push(
        alice_token
            .setRewardRecipient(bob)
            .gas(gas)
            .gas_price(gas_price)
            .send()
            .await?,
    );
    await_receipts(&mut pending).await?;

    // Distribute reward (immediate distribution)
    let distribute_receipt = token
        .distributeReward(reward_amount)
        .gas(gas)
        .gas_price(gas_price)
        .send()
        .await?
        .get_receipt()
        .await?;

    distribute_receipt
        .logs()
        .iter()
        .filter_map(|log| ITIP20::RewardDistributed::decode_log(&log.inner).ok())
        .next()
        .expect("RewardDistributed event should be emitted");

    // Transfer to trigger reward update (use authorized address, not random)
    pending.push(
        alice_token
            .transfer(admin, U256::from(100e18))
            .gas(gas)
            .gas_price(gas_price)
            .send()
            .await?,
    );
    await_receipts(&mut pending).await?;

    assert_eq!(token.balanceOf(alice).call().await?, U256::from(900e18));
    assert_eq!(token.balanceOf(bob).call().await?, U256::ZERO);
    assert_eq!(
        token.balanceOf(*token.address()).call().await?,
        reward_amount
    );

    bob_token
        .claimRewards()
        .gas(gas)
        .gas_price(gas_price)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert_eq!(token.balanceOf(bob).call().await?, reward_amount);

    Ok(())
}
