use alloy::{
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::{MnemonicBuilder, coins_bip39::English},
    sol_types::SolEvent,
    transports::http::reqwest::Url,
};
use reth_chainspec::ChainSpec;
use reth_ethereum::tasks::TaskManager;
use reth_node_builder::{NodeBuilder, NodeConfig, NodeHandle};
use reth_node_core::args::RpcServerArgs;
use std::sync::Arc;
use tempo_node::node::TempoNode;
use tempo_precompiles::{
    TIP20_FACTORY_ADDRESS,
    contracts::{
        ITIP20, ITIP20Factory, tip20::ISSUER_ROLE, token_id_to_address, types::IRolesAuth,
    },
};

#[tokio::test(flavor = "multi_thread")]
async fn test_tip20_transfer() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let tasks = TaskManager::current();
    let executor = tasks.executor();

    let chain_spec = ChainSpec::from_genesis(serde_json::from_str(include_str!(
        "../assets/test-genesis.json"
    ))?);

    let node_config = NodeConfig::test()
        .with_chain(Arc::new(chain_spec))
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

    // Deploy token
    let factory = ITIP20Factory::new(TIP20_FACTORY_ADDRESS, provider.clone());
    let receipt = factory
        .createToken(
            "Test".to_string(),
            "TEST".to_string(),
            "USD".to_string(),
            caller,
        )
        .send()
        .await?
        .get_receipt()
        .await?;
    let event = ITIP20Factory::TokenCreated::decode_log(&receipt.logs()[0].inner).unwrap();

    // Init the token and grant the caller the issuer role
    let token_addr = token_id_to_address(event.tokenId.to());
    let token = ITIP20::new(token_addr, provider.clone());
    let roles = IRolesAuth::new(*token.address(), provider.clone());

    // Grant issuer role
    roles
        .grantRole(*ISSUER_ROLE, caller)
        .send()
        .await?
        .get_receipt()
        .await?;

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
        pending_txs.push(token.mint(*account, *balance).send().await?);
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
        let token = ITIP20::new(token_addr, account_provider);

        let sender_balance = token.balanceOf(*account).call().await?;
        let recipient_balance = token.balanceOf(recipient).call().await?;

        // Simulate the tx and send
        let success = token.transfer(recipient, sender_balance).call().await?;
        assert!(success);
        let pending_tx = token.transfer(recipient, sender_balance).send().await?;

        tx_data.push((pending_tx, sender_balance, recipient, recipient_balance));
    }

    for (pending_tx, sender_balance, recipient, receipient_balance) in tx_data.into_iter() {
        let receipt = pending_tx.get_receipt().await?;
        // Check balances after transfer
        let sender_balance_after = token.balanceOf(receipt.from).call().await?;
        let recipient_balance_after = token.balanceOf(recipient).call().await?;

        assert_eq!(sender_balance_after, U256::ZERO);
        assert_eq!(recipient_balance_after, receipient_balance + sender_balance);
    }

    Ok(())
}
