use alloy::{
    consensus::BlockHeader,
    eips::{BlockNumberOrTag, Encodable2718},
    network::ReceiptResponse,
    primitives::{Address, B256, U256},
    providers::{Provider, ProviderBuilder},
    signers::{SignerSync, local::PrivateKeySigner},
    sol_types::{SolCall, SolValue},
};
use std::time::Duration;
use tempo_alloy::TempoNetwork;
use tempo_contracts::precompiles::{
    IFundingSource, IRolesAuth, IStablecoinDEX, ITIP20, ITIP20Factory, PATH_USD_ADDRESS,
    STABLECOIN_DEX_ADDRESS, TIP20_FACTORY_ADDRESS,
};
use tempo_precompiles::{tip20::ISSUER_ROLE, tip20_factory::TIP20Factory};
use tempo_primitives::{
    TempoTransaction, TempoTxEnvelope,
    transaction::{
        Call, FundingRequirement, FundingSource, PrimitiveSignature, TempoSignature,
        tempo_transaction::FEE_PAYER_SIGNATURE_MARKER,
    },
};

const FUNDER: Address = tempo_contracts::precompiles::TIP20_FUNDER_ADDRESS;
const SOURCE: Address = tempo_contracts::precompiles::DEX_FUNDING_SOURCE_ADDRESS;
const UNIT: u64 = 1_000_000;

fn signed(tx: TempoTransaction, owner: &PrivateKeySigner, sponsor: &PrivateKeySigner) -> Vec<u8> {
    let mut tx = tx;
    tx.fee_payer_signature = Some(FEE_PAYER_SIGNATURE_MARKER);
    let signature = owner.sign_hash_sync(&tx.signature_hash()).unwrap();
    tx.fee_payer_signature = Some(
        sponsor
            .sign_hash_sync(&tx.fee_payer_signature_hash(owner.address()))
            .unwrap(),
    );
    let envelope: TempoTxEnvelope = tx
        .into_signed(TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            signature,
        )))
        .into();
    envelope.encoded_2718()
}

pub(super) async fn run_demo(
    urls: Vec<alloy::transports::http::reqwest::Url>,
    maker: PrivateKeySigner,
) -> eyre::Result<()> {
    let owner = PrivateKeySigner::from_bytes(&B256::with_last_byte(112))?;
    let recipient = Address::repeat_byte(0x88);
    let salts = [B256::ZERO, B256::with_last_byte(1)];
    let assets = salts.map(|salt| {
        TIP20Factory::default()
            .get_token_address(ITIP20Factory::getTokenAddressCall {
                sender: maker.address(),
                salt,
            })
            .unwrap()
    });
    let provider = ProviderBuilder::new()
        .wallet(maker.clone())
        .connect_http(urls[0].clone());
    let rpc = ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(urls[0].clone());
    let factory = ITIP20Factory::new(TIP20_FACTORY_ADDRESS, provider.clone());
    let dex = IStablecoinDEX::new(STABLECOIN_DEX_ADDRESS, provider.clone());
    let output = ITIP20::new(PATH_USD_ADDRESS, provider.clone());
    assert!(output.balanceOf(owner.address()).call().await?.is_zero());
    assert!(
        output
            .approve(STABLECOIN_DEX_ADDRESS, U256::MAX)
            .send()
            .await?
            .get_receipt()
            .await?
            .status()
    );
    for (asset, salt) in assets.into_iter().zip(salts) {
        assert!(
            factory
                .createToken_0(
                    "Funding input".into(),
                    "INPUT".into(),
                    "USD".into(),
                    PATH_USD_ADDRESS,
                    maker.address(),
                    salt
                )
                .gas(5_000_000)
                .send()
                .await?
                .get_receipt()
                .await?
                .status()
        );
        assert!(
            IRolesAuth::new(asset, provider.clone())
                .grantRole(ISSUER_ROLE, maker.address())
                .gas(1_000_000)
                .send()
                .await?
                .get_receipt()
                .await?
                .status()
        );
        assert!(
            ITIP20::new(asset, provider.clone())
                .mint(owner.address(), U256::from(500 * UNIT))
                .send()
                .await?
                .get_receipt()
                .await?
                .status()
        );
        assert!(
            dex.place(asset, u128::from(500 * UNIT), true, 0)
                .gas(5_000_000)
                .send()
                .await?
                .get_receipt()
                .await?
                .status()
        );
    }
    let mut candidates = Vec::new();
    for input in assets {
        let found = IFundingSource::new(SOURCE, provider.clone())
            .discover(
                owner.address(),
                PATH_USD_ADDRESS,
                U256::from(50 * UNIT),
                U256::from(50 * UNIT),
                (input, U256::MAX).abi_encode().into(),
            )
            .call()
            .await?;
        candidates.extend(found);
    }
    assert_eq!(candidates.len(), 2);
    for (candidate, asset) in candidates.iter().zip(assets) {
        assert_eq!(candidate.availableAmount, U256::from(50 * UNIT));
        assert_eq!(
            <(Address, U256)>::abi_decode_validate(&candidate.executionData)?,
            (asset, U256::from(50 * UNIT))
        );
        assert_eq!(
            ITIP20::new(asset, provider.clone())
                .balanceOf(owner.address())
                .call()
                .await?,
            U256::from(500 * UNIT)
        );
    }
    let requirement = FundingRequirement {
        policy_rules: None,
        token: PATH_USD_ADDRESS,
        amount: U256::from(50 * UNIT),
        slippage_bps: Some(100),
        sources: vec![
            FundingSource {
                target: SOURCE,
                data: (assets[0], U256::from(30 * UNIT)).abi_encode().into(),
            },
            FundingSource {
                target: SOURCE,
                data: candidates[1].executionData.clone(),
            },
        ],
    };
    let tx = TempoTransaction {
        chain_id: rpc.get_chain_id().await?,
        gas_limit: 10_000_000,
        max_fee_per_gas: 20_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        fee_token: Some(PATH_USD_ADDRESS),
        require_funds: Some(vec![requirement.clone()]),
        calls: vec![Call {
            to: PATH_USD_ADDRESS.into(),
            value: U256::ZERO,
            input: ITIP20::transferCall {
                to: recipient,
                amount: U256::from(50 * UNIT),
            }
            .abi_encode()
            .into(),
        }],
        ..Default::default()
    };

    assert!(
        output
            .transfer(recipient, U256::from(UNIT))
            .send()
            .await?
            .get_receipt()
            .await?
            .status()
    );
    let mut input_balances = [500u64, 500];
    let mut delivered = 1u64;
    let mut observations = Vec::new();
    for (nonce, scenario) in [
        "first_transaction",
        "direct",
        "covered",
        "one_source",
        "two_sources",
        "payment_revert",
        "funding_revert",
    ]
    .into_iter()
    .enumerate()
    {
        let mut tx = tx.clone();
        tx.nonce = nonce as u64;
        if matches!(scenario, "first_transaction" | "direct" | "covered") {
            assert!(
                output
                    .transfer(owner.address(), U256::from(50 * UNIT))
                    .send()
                    .await?
                    .get_receipt()
                    .await?
                    .status()
            );
        }
        match scenario {
            "first_transaction" | "direct" => tx.require_funds = None,
            "covered" => tx.require_funds.as_mut().unwrap()[0].sources.clear(),
            "one_source" => {
                let entry = &mut tx.require_funds.as_mut().unwrap()[0];
                entry.slippage_bps = None;
                entry.sources.truncate(1);
                entry.sources[0].data = (assets[0], U256::MAX).abi_encode().into();
            }
            "payment_revert" => {
                tx.calls[0].input = ITIP20::transferCall {
                    to: recipient,
                    amount: U256::from(51 * UNIT),
                }
                .abi_encode()
                .into()
            }
            "funding_revert" => tx.require_funds.as_mut().unwrap()[0].sources.truncate(1),
            _ => {}
        }
        let bytes = signed(tx, &owner, &maker);
        let receipt = rpc
            .send_raw_transaction(&bytes)
            .await?
            .get_receipt()
            .await?;
        let success = !scenario.ends_with("revert");
        assert_eq!(receipt.status(), success, "{scenario}");
        assert_eq!(receipt.fee_payer, maker.address());
        let expected_events = match scenario {
            "covered" => 1,
            "one_source" => 2,
            "two_sources" => 3,
            _ => 0,
        };
        assert_eq!(
            receipt
                .inner
                .logs()
                .iter()
                .filter(|log| log.address() == FUNDER)
                .count(),
            expected_events
        );
        let height = receipt.block_number.unwrap();
        let hash = receipt.block_hash.unwrap();
        if success {
            delivered += 50;
            if scenario == "one_source" {
                input_balances[0] -= 50;
            }
            if scenario == "two_sources" {
                input_balances[0] -= 30;
                input_balances[1] -= 20;
            }
        } else {
            assert!(
                !receipt
                    .inner
                    .logs()
                    .iter()
                    .any(|log| log.address() == FUNDER)
            );
        }
        let mut state_root = None;
        for url in &urls {
            let peer =
                ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(url.clone());
            tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    if let Some(block) = peer
                        .get_block_by_number(BlockNumberOrTag::Finalized)
                        .await?
                        && block.header.number() >= height
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Ok::<_, eyre::Report>(())
            })
            .await??;
            let block = peer.get_block_by_number(height.into()).await?.unwrap();
            assert_eq!(
                block.header.hash, hash,
                "{scenario}: finalized block differs"
            );
            let root = block.header.state_root();
            if let Some(expected) = state_root {
                assert_eq!(root, expected);
            } else {
                state_root = Some(root);
            }
            let peer_receipt = peer
                .get_transaction_receipt(receipt.transaction_hash())
                .await?
                .unwrap();
            assert_eq!(
                serde_json::to_value(&peer_receipt)?,
                serde_json::to_value(&receipt)?,
                "{scenario}: receipt differs"
            );
            let token = ITIP20::new(PATH_USD_ADDRESS, peer.clone());
            assert_eq!(
                token
                    .balanceOf(recipient)
                    .block(height.into())
                    .call()
                    .await?,
                U256::from(delivered * UNIT)
            );
            assert!(
                token
                    .balanceOf(owner.address())
                    .block(height.into())
                    .call()
                    .await?
                    .is_zero()
            );
            for (asset, remaining) in assets.into_iter().zip(input_balances) {
                let token = ITIP20::new(asset, peer.clone());
                assert_eq!(
                    IStablecoinDEX::new(STABLECOIN_DEX_ADDRESS, peer.clone())
                        .balanceOf(maker.address(), asset)
                        .block(height.into())
                        .call()
                        .await?,
                    u128::from((500 - remaining) * UNIT)
                );
                assert_eq!(
                    token
                        .balanceOf(owner.address())
                        .block(height.into())
                        .call()
                        .await?,
                    U256::from(remaining * UNIT)
                );
                assert!(
                    token
                        .allowance(owner.address(), SOURCE)
                        .block(height.into())
                        .call()
                        .await?
                        .is_zero()
                );
                assert!(
                    token
                        .allowance(owner.address(), STABLECOIN_DEX_ADDRESS)
                        .block(height.into())
                        .call()
                        .await?
                        .is_zero()
                );
            }
        }
        observations.push(serde_json::json!({"scenario": scenario, "gasUsed": receipt.gas_used(), "transaction": receipt.transaction_hash(), "block": hash, "stateRoot": state_root, "validators": urls.len()}));
    }
    println!(
        "FUNDING_GAS_RESULTS={}",
        serde_json::to_string(&observations)?
    );
    Ok(())
}
