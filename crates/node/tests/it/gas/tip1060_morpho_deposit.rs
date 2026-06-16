use alloy::{
    hex,
    primitives::{Address, B256, Bytes, U256, address, b256},
    providers::{Provider, ProviderBuilder},
    sol,
};
use serde_json::{Map, Value};
use tempo_chainspec::hardfork::TempoHardfork;

use super::helpers::{
    GasSnapshot, TempoCalls, TempoTxSender, ensure_call_trace_succeeded, find_call_gas_used,
    fixed_signer, mainnet_prestate_genesis_value, mapping_slot_address, print_gas_snapshot,
    successful_raw_receipt_gas_used, tip20_allowance_slot, tip20_balance_slot, upsert_balance,
    upsert_storage,
};
use crate::utils::TestNodeBuilder;

// Mainnet tx 0x4d17...5db9 at block 0x1844940, replayed from a prestateTracer
// fixture while forcing the local chain spec to T7.
const MAINNET_TX_HASH: B256 =
    b256!("4d1767b5efe3bfdf3576e336fc5ad56bf55800e5ba071e168585538add8c5db9");
const MAINNET_CHAIN_ID: u64 = 0x1079;
const MAINNET_BLOCK_TIMESTAMP: u64 = 1_781_578_286;
const SMART_ACCOUNT_ADDRESS: Address = address!("0bc95cddc7da082eef47856091c519a61c8eee9b");
const PATHUSD_ADDRESS: Address = address!("20c0000000000000000000000000000000000000");
const PRIMARY_VAULT_ADDRESS: Address = address!("83a1491f3e7f8daab8f787a631334b9ca7a87023");
const NESTED_VAULT_ADDRESS: Address = address!("9a044ae05e5e6290dcf56afd69548565e957a626");
const MORPHO_ADDRESS: Address = address!("799cd096e5ebc436daecef85392b2ecf196dfbe6");
const MORPHO_DEPOSIT_AMOUNT: u64 = 1_200_000_000;
const APPROVE_SELECTOR: &str = "0x095ea7b3";
const DEPOSIT_SELECTOR: &str = "0x6e553f65";
const MORPHO_SUPPLY_SELECTOR: &str = "0x1eadd778";
const PRESTATE_JSON: &str = include_str!("fixtures/tip1060_morpho_deposit_prestate.json");
const RAW_TX: &str = "0x76f90193821079808504a817c8008316372ff8bcf85c9420c000000000000000000000000000000000000080b844095ea7b300000000000000000000000083a1491f3e7f8daab8f787a631334b9ca7a870230000000000000000000000000000000000000000000000000000000047868c00f85c9483a1491f3e7f8daab8f787a631334b9ca7a8702380b8446e553f650000000000000000000000000000000000000000000000000000000047868c000000000000000000000000000bc95cddc7da082eef47856091c519a61c8eee9bc0a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80846a30ba47809420c0000000000000000000000000000000000000f84301a0357f48124418ec52f37fc956e9083adb098109e53863ebd64c985cdb0de861a7a05ba6e80cfd61da3e4fa760168feabf9126a5757d352d6b915a9fd5b0dd0979b7c0b841584f5d897e9fbf2adbffe490c5e4bc681a405615fffe7b5e87fdfd90006ca9f657a796dfc131dfa95c518400d0048d83402828a19364aa63c6ee02a667a2f4481c";

sol! {
    interface IERC20 {
        function approve(address spender, uint256 amount) external returns (bool);
    }

    interface IERC4626 {
        function deposit(uint256 assets, address receiver) external returns (uint256 shares);
    }
}

#[derive(Clone, Copy)]
enum UserState {
    Captured,
    Returning,
}

#[derive(Clone, Copy)]
enum ConstructedUserState {
    New,
    Returning,
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tip1060_morpho_deposit_t7_gas_snapshot() -> eyre::Result<()> {
    test_tip1060_morpho_deposit_gas_snapshot(UserState::Captured, "tip1060_morpho_deposit_t7_gas")
        .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tip1060_morpho_deposit_returning_user_t7_gas_snapshot() -> eyre::Result<()> {
    test_tip1060_morpho_deposit_gas_snapshot(
        UserState::Returning,
        "tip1060_morpho_deposit_returning_user_t7_gas",
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tip1060_morpho_deposit_new_user_t7_gas_snapshot() -> eyre::Result<()> {
    test_tip1060_morpho_deposit_constructed_gas_snapshot(
        ConstructedUserState::New,
        "tip1060_morpho_deposit_new_user_t7_gas",
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tip1060_morpho_deposit_constructed_returning_user_t7_gas_snapshot() -> eyre::Result<()>
{
    test_tip1060_morpho_deposit_constructed_gas_snapshot(
        ConstructedUserState::Returning,
        "tip1060_morpho_deposit_constructed_returning_user_t7_gas",
    )
    .await
}

async fn test_tip1060_morpho_deposit_gas_snapshot(
    user_state: UserState,
    snapshot_name: &'static str,
) -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut setup = TestNodeBuilder::new()
        .with_genesis(mainnet_replay_genesis(user_state)?)
        .build_with_node_access()
        .await?;
    setup.node.payload.timestamp = MAINNET_BLOCK_TIMESTAMP;
    let provider = ProviderBuilder::new().connect_http(setup.node.rpc_url());
    assert_eq!(provider.get_chain_id().await?, MAINNET_CHAIN_ID);

    let raw_tx = Bytes::from(hex::decode(RAW_TX.trim_start_matches("0x"))?);
    setup.node.rpc.inject_tx(raw_tx.into()).await?;
    setup.node.advance_block().await?;

    let receipt: Option<Value> = provider
        .raw_request("eth_getTransactionReceipt".into(), (MAINNET_TX_HASH,))
        .await?;
    let receipt =
        receipt.ok_or_else(|| eyre::eyre!("mainnet replay transaction receipt missing"))?;
    let receipt_gas_used = successful_raw_receipt_gas_used(&receipt, MAINNET_TX_HASH)?;

    let trace: Value = provider
        .raw_request(
            "debug_traceTransaction".into(),
            (
                MAINNET_TX_HASH,
                serde_json::json!({ "tracer": "callTracer" }),
            ),
        )
        .await?;
    ensure_call_trace_succeeded(&trace)?;

    let mut gas = GasSnapshot::new();
    gas.record("morpho_deposit", receipt_gas_used);
    gas.record(
        "morpho_deposit_pathusd_approve",
        find_call_gas_used(&trace, PATHUSD_ADDRESS, APPROVE_SELECTOR)?,
    );
    gas.record(
        "morpho_deposit_primary_vault_deposit",
        find_call_gas_used(&trace, PRIMARY_VAULT_ADDRESS, DEPOSIT_SELECTOR)?,
    );
    gas.record(
        "morpho_deposit_nested_vault_deposit",
        find_call_gas_used(&trace, NESTED_VAULT_ADDRESS, DEPOSIT_SELECTOR)?,
    );
    gas.record(
        "morpho_deposit_morpho_supply",
        find_call_gas_used(&trace, MORPHO_ADDRESS, MORPHO_SUPPLY_SELECTOR)?,
    );

    print_gas_snapshot(
        match user_state {
            UserState::Captured => "TIP-1060 Morpho deposit gas snapshot (T7, captured user)",
            UserState::Returning => "TIP-1060 Morpho deposit gas snapshot (T7, returning user)",
        },
        &gas,
    );

    insta::assert_yaml_snapshot!(snapshot_name, gas);

    Ok(())
}

async fn test_tip1060_morpho_deposit_constructed_gas_snapshot(
    user_state: ConstructedUserState,
    snapshot_name: &'static str,
) -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let signer = fixed_signer(match user_state {
        ConstructedUserState::New => 0x44,
        ConstructedUserState::Returning => 0x45,
    });
    let user = signer.address();
    let setup = TestNodeBuilder::new()
        .with_genesis(mainnet_constructed_user_genesis(user_state, user)?)
        .build_http_only()
        .await?;
    let provider = ProviderBuilder::new().connect_http(setup.http_url.clone());
    assert_eq!(provider.get_chain_id().await?, MAINNET_CHAIN_ID);

    let mut sender = TempoTxSender::connect_with_zero_nonce(setup.http_url, signer).await?;
    let amount = U256::from(MORPHO_DEPOSIT_AMOUNT);
    let receipt = TempoCalls::new()
        .push(
            PATHUSD_ADDRESS,
            IERC20::approveCall {
                spender: PRIMARY_VAULT_ADDRESS,
                amount,
            },
        )
        .push(
            PRIMARY_VAULT_ADDRESS,
            IERC4626::depositCall {
                assets: amount,
                receiver: user,
            },
        )
        .send_with_receipt(&mut sender)
        .await?;

    let trace: Value = provider
        .raw_request(
            "debug_traceTransaction".into(),
            (
                receipt.tx_hash,
                serde_json::json!({ "tracer": "callTracer" }),
            ),
        )
        .await?;
    ensure_call_trace_succeeded(&trace)?;

    let mut gas = GasSnapshot::new();
    gas.record("morpho_deposit", receipt.gas_used);
    gas.record(
        "morpho_deposit_pathusd_approve",
        find_call_gas_used(&trace, PATHUSD_ADDRESS, APPROVE_SELECTOR)?,
    );
    gas.record(
        "morpho_deposit_primary_vault_deposit",
        find_call_gas_used(&trace, PRIMARY_VAULT_ADDRESS, DEPOSIT_SELECTOR)?,
    );
    gas.record(
        "morpho_deposit_nested_vault_deposit",
        find_call_gas_used(&trace, NESTED_VAULT_ADDRESS, DEPOSIT_SELECTOR)?,
    );
    gas.record(
        "morpho_deposit_morpho_supply",
        find_call_gas_used(&trace, MORPHO_ADDRESS, MORPHO_SUPPLY_SELECTOR)?,
    );

    print_gas_snapshot(
        match user_state {
            ConstructedUserState::New => {
                "TIP-1060 Morpho deposit gas snapshot (T7, constructed new user)"
            }
            ConstructedUserState::Returning => {
                "TIP-1060 Morpho deposit gas snapshot (T7, constructed returning user)"
            }
        },
        &gas,
    );

    insta::assert_yaml_snapshot!(snapshot_name, gas);

    Ok(())
}

fn mainnet_replay_genesis(user_state: UserState) -> eyre::Result<String> {
    let mut genesis = mainnet_prestate_genesis_value(
        TempoHardfork::T7,
        MAINNET_CHAIN_ID,
        MAINNET_BLOCK_TIMESTAMP,
        PRESTATE_JSON,
    )?;
    let alloc = genesis["alloc"]
        .as_object_mut()
        .ok_or_else(|| eyre::eyre!("test genesis missing alloc"))?;
    apply_user_state(alloc, user_state)?;

    Ok(serde_json::to_string(&genesis)?)
}

fn mainnet_constructed_user_genesis(
    user_state: ConstructedUserState,
    user: Address,
) -> eyre::Result<String> {
    let mut genesis = mainnet_prestate_genesis_value(
        TempoHardfork::T7,
        MAINNET_CHAIN_ID,
        MAINNET_BLOCK_TIMESTAMP,
        PRESTATE_JSON,
    )?;
    let alloc = genesis["alloc"]
        .as_object_mut()
        .ok_or_else(|| eyre::eyre!("test genesis missing alloc"))?;

    upsert_balance(alloc, user, "0x3635c9adc5dea00000")?;
    upsert_storage(
        alloc,
        PATHUSD_ADDRESS,
        tip20_balance_slot(user),
        U256::from(50_000_000_000u64),
    )?;

    if matches!(user_state, ConstructedUserState::Returning) {
        apply_returning_state(alloc, user)?;
    }

    Ok(serde_json::to_string(&genesis)?)
}

fn apply_user_state(alloc: &mut Map<String, Value>, user_state: UserState) -> eyre::Result<()> {
    if matches!(user_state, UserState::Captured) {
        return Ok(());
    }
    apply_returning_state(alloc, SMART_ACCOUNT_ADDRESS)
}

fn apply_returning_state(alloc: &mut Map<String, Value>, user: Address) -> eyre::Result<()> {
    let value = U256::ONE;

    for (token, owner) in [
        (PATHUSD_ADDRESS, PRIMARY_VAULT_ADDRESS),
        (PATHUSD_ADDRESS, NESTED_VAULT_ADDRESS),
        (PATHUSD_ADDRESS, MORPHO_ADDRESS),
    ] {
        upsert_storage(alloc, token, tip20_balance_slot(owner), value)?;
    }

    for (owner, spender) in [
        (user, PRIMARY_VAULT_ADDRESS),
        (PRIMARY_VAULT_ADDRESS, NESTED_VAULT_ADDRESS),
        (NESTED_VAULT_ADDRESS, MORPHO_ADDRESS),
    ] {
        upsert_storage(
            alloc,
            PATHUSD_ADDRESS,
            tip20_allowance_slot(owner, spender),
            value,
        )?;
    }

    upsert_storage(alloc, PRIMARY_VAULT_ADDRESS, vault_share_slot(user), value)?;
    upsert_storage(
        alloc,
        NESTED_VAULT_ADDRESS,
        vault_share_slot(PRIMARY_VAULT_ADDRESS),
        value,
    )?;

    Ok(())
}

fn vault_share_slot(owner: Address) -> B256 {
    mapping_slot_address(owner, B256::from(U256::from(12)))
}
