//! Signed owner funding through RPC, native DEX execution, and receipt accounting.
use crate::utils::{TEST_MNEMONIC, TestNodeBuilder};
use alloy::{
    network::ReceiptResponse,
    primitives::{Address, B256, U256},
    providers::{Provider, ProviderBuilder},
    signers::{
        SignerSync,
        local::{MnemonicBuilder, PrivateKeySigner},
    },
    sol_types::{SolCall, SolValue},
};
use alloy_eips::{Decodable2718, Encodable2718};
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

#[tokio::test(flavor = "multi_thread")]
async fn funding_rpc_native_dex_payment_and_rollback() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let maker = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
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
    let mut first_execution = None;
    for _ in 0..2 {
        let setup = TestNodeBuilder::new().build_http_only().await?;
        let provider = ProviderBuilder::new()
            .wallet(maker.clone())
            .connect_http(setup.http_url.clone());
        let rpc = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_http(setup.http_url.clone());
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
                    .mint(owner.address(), U256::from(200 * UNIT))
                    .send()
                    .await?
                    .get_receipt()
                    .await?
                    .status()
            );
            assert!(
                dex.place(asset, u128::from(150 * UNIT), true, 0)
                    .gas(5_000_000)
                    .send()
                    .await?
                    .get_receipt()
                    .await?
                    .status()
            );
        }
        let source = IFundingSource::new(SOURCE, provider.clone());
        let mut candidates = Vec::new();
        for input in assets {
            let found = source
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
        }
        let quote = source
            .quote(
                owner.address(),
                PATH_USD_ADDRESS,
                U256::from(50 * UNIT),
                U256::from(50 * UNIT),
                (assets[0], U256::from(30 * UNIT)).abi_encode().into(),
                Default::default(),
                true,
            )
            .call()
            .await?;
        assert_eq!(quote.amountOut, U256::from(30 * UNIT));
        assert_eq!(quote.maxAmountIn, U256::from(30 * UNIT));
        assert!(
            source
                .fund(
                    owner.address(),
                    PATH_USD_ADDRESS,
                    quote.amountOut,
                    quote.executionData
                )
                .call()
                .await
                .is_err()
        );
        assert_eq!(
            ITIP20::new(assets[0], provider.clone())
                .balanceOf(owner.address())
                .call()
                .await?,
            U256::from(200 * UNIT)
        );
        assert!(output.balanceOf(owner.address()).call().await?.is_zero());
        let requirement = FundingRequirement {
            policy_rules: None,
            token: PATH_USD_ADDRESS,
            amount: U256::from(50 * UNIT),
            slippage_bps: Some(100),
            sources: vec![
                FundingSource {
                    address: SOURCE,
                    data: (assets[0], U256::from(30 * UNIT)).abi_encode().into(),
                },
                FundingSource {
                    address: SOURCE,
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
        let encoded = signed(tx.clone(), &owner, &maker);
        let envelope = TempoTxEnvelope::decode_2718(&mut encoded.as_slice())?;
        let mut simulation =
            tempo_alloy::rpc::TempoTransactionRequest::from(envelope.as_aa().unwrap().tx().clone());
        simulation.inner.from = Some(owner.address());
        assert!(!rpc.call(simulation.clone()).await?.is_empty());
        assert!(rpc.estimate_gas(simulation).await? > 21_000);
        assert!(output.balanceOf(owner.address()).call().await?.is_zero());
        let receipt = rpc
            .send_raw_transaction(&encoded)
            .await?
            .get_receipt()
            .await?;
        assert!(receipt.status());
        assert_eq!(receipt.fee_payer, maker.address());
        assert!(
            receipt
                .inner
                .logs()
                .iter()
                .any(|log| log.address() == FUNDER)
        );
        let execution = (encoded.clone(), receipt.gas_used());
        if let Some(expected) = &first_execution {
            assert_eq!(&execution, expected);
        } else {
            first_execution = Some(execution);
        }

        let trace: serde_json::Value = rpc
            .client()
            .request(
                "debug_traceTransaction",
                (
                    receipt.transaction_hash(),
                    serde_json::json!({"tracer": "callTracer"}),
                ),
            )
            .await?;
        assert!(
            trace
                .to_string()
                .to_lowercase()
                .contains(&format!("{SOURCE:#x}"))
        );
        assert_eq!(
            output.balanceOf(recipient).call().await?,
            U256::from(50 * UNIT)
        );
        assert!(output.balanceOf(owner.address()).call().await?.is_zero());
        for (asset, remaining) in assets.into_iter().zip([170, 180]) {
            let token = ITIP20::new(asset, provider.clone());
            assert_eq!(
                token.balanceOf(owner.address()).call().await?,
                U256::from(remaining * UNIT)
            );
            assert!(
                token
                    .allowance(owner.address(), SOURCE)
                    .call()
                    .await?
                    .is_zero()
            );
            assert!(
                token
                    .allowance(owner.address(), STABLECOIN_DEX_ADDRESS)
                    .call()
                    .await?
                    .is_zero()
            );
        }
        let mut failed = tx.clone();
        failed.nonce = 1;
        failed.calls[0].input = ITIP20::transferCall {
            to: recipient,
            amount: U256::from(51 * UNIT),
        }
        .abi_encode()
        .into();
        let receipt = rpc
            .send_raw_transaction(&signed(failed, &owner, &maker))
            .await?
            .get_receipt()
            .await?;
        assert!(!receipt.status());
        assert!(
            receipt
                .inner
                .logs()
                .iter()
                .all(|log| log.address() != FUNDER)
        );
        assert_eq!(
            output.balanceOf(recipient).call().await?,
            U256::from(50 * UNIT)
        );
        assert!(output.balanceOf(owner.address()).call().await?.is_zero());
        for (asset, remaining) in assets.into_iter().zip([170, 180]) {
            assert_eq!(
                ITIP20::new(asset, provider.clone())
                    .balanceOf(owner.address())
                    .call()
                    .await?,
                U256::from(remaining * UNIT)
            );
        }
        // The failed transaction consumes its nonce; a fresh transaction can use new funding authority.
        let mut next = tx.clone();
        next.nonce = 2;
        let mut first = requirement.clone();
        first.amount = U256::from(25 * UNIT);
        first.sources.truncate(1);
        let mut second = requirement.clone();
        second.sources.remove(0);
        next.require_funds = Some(vec![first, second]);
        assert!(
            rpc.send_raw_transaction(&signed(next, &owner, &maker))
                .await?
                .get_receipt()
                .await?
                .status()
        );
        assert_eq!(
            output.balanceOf(recipient).call().await?,
            U256::from(100 * UNIT)
        );
        for (asset, remaining) in assets.into_iter().zip([145, 155]) {
            let token = ITIP20::new(asset, provider.clone());
            assert_eq!(
                token.balanceOf(owner.address()).call().await?,
                U256::from(remaining * UNIT)
            );
            assert!(
                token
                    .transferFrom(owner.address(), maker.address(), U256::from(1))
                    .call()
                    .await
                    .is_err()
            );
        }
        let mut denied = tx.clone();
        denied.nonce = 3;
        denied.require_funds = Some(vec![FundingRequirement {
            policy_rules: None,
            token: PATH_USD_ADDRESS,
            amount: U256::ZERO,
            sources: vec![],
            slippage_bps: None,
        }]);
        let signature = owner.sign_hash_sync(&denied.signature_hash())?;
        let envelope: TempoTxEnvelope = denied
            .into_signed(TempoSignature::Keychain(
                tempo_primitives::transaction::tt_signature::KeychainSignature::new(
                    owner.address(),
                    PrimitiveSignature::Secp256k1(signature),
                ),
            ))
            .into();
        let error = rpc
            .send_raw_transaction(&envelope.encoded_2718())
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("access key funding is not activated"),
            "{error}"
        );
        let mut invalidated = tx;
        invalidated.nonce = 3;
        invalidated.require_funds = Some(vec![
            FundingRequirement {
                policy_rules: None,
                token: assets[0],
                amount: U256::from(145 * UNIT),
                sources: vec![],
                slippage_bps: None,
            },
            requirement,
        ]);
        let receipt = rpc
            .send_raw_transaction(&signed(invalidated, &owner, &maker))
            .await?
            .get_receipt()
            .await?;
        assert!(!receipt.status());
        assert!(
            receipt
                .inner
                .logs()
                .iter()
                .all(|log| log.address() != FUNDER)
        );
        assert_eq!(
            ITIP20::new(assets[0], provider.clone())
                .balanceOf(owner.address())
                .call()
                .await?,
            U256::from(145 * UNIT)
        );
        assert_eq!(
            output.balanceOf(recipient).call().await?,
            U256::from(100 * UNIT)
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn funding_rpc_rejects_pre_t13_transactions() -> eyre::Result<()> {
    use crate::utils::ForkSchedule;
    use tempo_chainspec::hardfork::TempoHardfork;
    let owner = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    for fork in [TempoHardfork::T11, TempoHardfork::T12] {
        let setup = TestNodeBuilder::new()
            .with_schedule(ForkSchedule::DevnetAt(fork))
            .build_http_only()
            .await?;
        let rpc = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_http(setup.http_url.clone());
        let tx = TempoTransaction {
            chain_id: rpc.get_chain_id().await?,
            gas_limit: 1_000_000,
            max_fee_per_gas: 20_000_000_000,
            fee_token: Some(PATH_USD_ADDRESS),
            require_funds: Some(vec![FundingRequirement {
                policy_rules: None,
                token: PATH_USD_ADDRESS,
                amount: U256::ZERO,
                sources: vec![],
                slippage_bps: None,
            }]),
            calls: vec![Call {
                to: owner.address().into(),
                value: U256::ZERO,
                input: Default::default(),
            }],
            ..Default::default()
        };
        let signature = owner.sign_hash_sync(&tx.signature_hash())?;
        let envelope: TempoTxEnvelope = tx
            .into_signed(TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                signature,
            )))
            .into();
        let error = rpc
            .send_raw_transaction(&envelope.encoded_2718())
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("funding requirements are not activated"),
            "{error}"
        );
        assert_eq!(rpc.get_transaction_count(owner.address()).await?, 0);
    }
    Ok(())
}
