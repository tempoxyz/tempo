use alloy::{
    network::ReceiptResponse,
    primitives::U256,
    providers::{Provider, ProviderBuilder},
    signers::local::{MnemonicBuilder, coins_bip39::English},
};
use alloy_rpc_types_eth::TransactionRequest;
use std::env;
use tempo_chainspec::spec::TEMPO_BASE_FEE;
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    contracts::{IFeeManager, ITIP20, tip_fee_amm::PoolKey, types::ITIPFeeAMM},
};

use crate::utils::setup_test_token;

#[tokio::test(flavor = "multi_thread")]
async fn test_mint_fee_tokens() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        crate::utils::NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        crate::utils::NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _local_node) = crate::utils::setup_test_node(source).await?;

    let wallet = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let amount = U256::from(rand::random::<u128>());
    let token_0 = setup_test_token(provider.clone(), caller).await?;
    token_0
        .mint(caller, amount)
        .send()
        .await?
        .get_receipt()
        .await?;

    let token_1 = setup_test_token(provider.clone(), caller).await?;
    token_1
        .mint(caller, amount)
        .send()
        .await?
        .get_receipt()
        .await?;

    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

    fee_amm
        .mint(
            PoolKey::new(*token_0.address(), *token_1.address()).into(),
            amount,
            amount,
            caller,
        )
        .send()
        .await?
        .get_receipt()
        .await?;

    // TODO: assert state changes
    Ok(())
}
