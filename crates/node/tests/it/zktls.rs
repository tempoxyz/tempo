use alloy::{
    primitives::{Address, B256, Bytes, keccak256},
    providers::{Provider, ProviderBuilder},
    signers::{
        SignerSync,
        local::{MnemonicBuilder, PrivateKeySigner},
    },
};
use tempo_contracts::precompiles::{IZkTlsVerifier, ZK_TLS_VERIFIER_ADDRESS};

use crate::utils::TestNodeBuilder;

const TDX_QUOTE_HEADER_LENGTH: usize = 48;
const TDX_TD10_REPORT_LENGTH: usize = 584;
const TDX_MRCONFIG_OFFSET: usize = 184;
const TDX_REPORTDATA_OFFSET: usize = 520;
const QUOTE_VERSION_V4: u16 = 4;
const TDX_TD10_QUOTE_BODY_TYPE: u16 = 2;

#[tokio::test(flavor = "multi_thread")]
async fn test_zktls_precompile_verifies_and_marks_claim_on_devnet() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let owner = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(setup.http_url);
    let verifier = IZkTlsVerifier::new(ZK_TLS_VERIFIER_ADDRESS, provider.clone());

    assert_eq!(verifier.owner().call().await?, owner);
    assert_eq!(
        provider
            .get_code_at(ZK_TLS_VERIFIER_ADDRESS)
            .await?
            .as_ref(),
        [0xef],
        "zkTLS verifier should be registered as a stateful precompile"
    );

    let tee_signer = tee_signer();
    let dstack_app = Address::from_word(B256::with_last_byte(0xd5));
    let provider_hash = B256::from([0x11; 32]);
    let claim_type = B256::from([0x22; 32]);
    let nonce = B256::from([0x44; 32]);
    let compose_hash = B256::from([0x77; 32]);
    let device_id = B256::from([0x88; 32]);
    let raw_quote = raw_quote(tee_signer.address(), nonce, compose_hash);

    let claim = IZkTlsVerifier::TempoZkTlsClaim {
        subject: owner,
        providerHash: provider_hash,
        claimType: claim_type,
        extractedHash: B256::from([0x33; 32]),
        nonce,
        sessionId: B256::from([0x55; 32]),
        issuedAt: 0,
        expiresAt: u64::MAX,
        sourceHash: B256::from([0x66; 32]),
        dstackApp: dstack_app,
        composeHash: compose_hash,
        deviceId: device_id,
        quoteHash: keccak256(&raw_quote),
    };
    let policy = IZkTlsVerifier::VerificationPolicy {
        expectedSubject: claim.subject,
        expectedProviderHash: claim.providerHash,
        expectedClaimType: claim.claimType,
        expectedNonce: claim.nonce,
        expectedSourceHash: claim.sourceHash,
        expectedDstackApp: claim.dstackApp,
        expectedComposeHash: claim.composeHash,
        expectedDeviceId: claim.deviceId,
        expectedTeeSigner: tee_signer.address(),
        maxClaimAgeSeconds: u64::MAX,
        maxFutureSkewSeconds: 5,
    };

    approve_precompile_policy(
        &verifier,
        provider_hash,
        claim_type,
        dstack_app,
        compose_hash,
        device_id,
        tee_signer.address(),
    )
    .await?;

    let claim_hash = verifier.hashTempoClaim(claim.clone()).call().await?;
    let digest = verifier.toEthSignedMessageHash(claim_hash).call().await?;
    let signature = Bytes::copy_from_slice(&tee_signer.sign_hash_sync(&digest)?.as_bytes());

    let verified = verifier
        .verifyTempoClaim(
            claim.clone(),
            policy.clone(),
            Bytes::from(raw_quote.clone()),
            signature.clone(),
        )
        .call()
        .await?;
    assert_eq!(verified.claimHash, claim_hash);
    assert_eq!(verified.teeSigner, tee_signer.address());

    let receipt = verifier
        .verifyAndMarkTempoClaim(claim.clone(), policy, Bytes::from(raw_quote), signature)
        .gas(5_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "verifyAndMarkTempoClaim should succeed");
    assert!(
        verifier
            .isNonceUsed(claim.subject, claim.nonce)
            .call()
            .await?
    );

    Ok(())
}

async fn approve_precompile_policy<P>(
    verifier: &IZkTlsVerifier::IZkTlsVerifierInstance<P>,
    provider_hash: B256,
    claim_type: B256,
    dstack_app: Address,
    compose_hash: B256,
    device_id: B256,
    tee_signer: Address,
) -> eyre::Result<()>
where
    P: Provider + Clone,
{
    send_ok(
        verifier
            .setProviderHashApproved(provider_hash, claim_type, true)
            .gas(1_000_000)
            .send()
            .await?,
    )
    .await?;
    send_ok(
        verifier
            .setDstackAppApproved(dstack_app, true)
            .gas(1_000_000)
            .send()
            .await?,
    )
    .await?;
    send_ok(
        verifier
            .setDstackComposeHashApproved(dstack_app, compose_hash, true)
            .gas(1_000_000)
            .send()
            .await?,
    )
    .await?;
    send_ok(
        verifier
            .setDstackDeviceApproved(dstack_app, device_id, true)
            .gas(1_000_000)
            .send()
            .await?,
    )
    .await?;
    send_ok(
        verifier
            .setDstackSignerApproved(dstack_app, tee_signer, true)
            .gas(1_000_000)
            .send()
            .await?,
    )
    .await?;
    Ok(())
}

async fn send_ok(
    pending: alloy::providers::PendingTransactionBuilder<alloy::network::Ethereum>,
) -> eyre::Result<()> {
    let receipt = pending.get_receipt().await?;
    assert!(receipt.status(), "approval transaction should succeed");
    Ok(())
}

fn tee_signer() -> PrivateKeySigner {
    "0x59c6995e998f97a5a004497e5da108fd4eae01d05b09b7b6b4832c5c2d8c6c6d"
        .parse()
        .expect("valid test key")
}

fn raw_quote(signer: Address, nonce: B256, compose_hash: B256) -> Vec<u8> {
    let mut quote = vec![0u8; TDX_QUOTE_HEADER_LENGTH + TDX_TD10_REPORT_LENGTH];
    quote[0..2].copy_from_slice(&QUOTE_VERSION_V4.to_le_bytes());
    quote[2..4].copy_from_slice(&TDX_TD10_QUOTE_BODY_TYPE.to_le_bytes());

    let mrconfig_offset = TDX_QUOTE_HEADER_LENGTH + TDX_MRCONFIG_OFFSET;
    quote[mrconfig_offset] = 0x01;
    quote[mrconfig_offset + 1..mrconfig_offset + 33].copy_from_slice(compose_hash.as_slice());

    let report_data_offset = TDX_QUOTE_HEADER_LENGTH + TDX_REPORTDATA_OFFSET;
    quote[report_data_offset..report_data_offset + 20].copy_from_slice(signer.as_slice());
    quote[report_data_offset + 32..report_data_offset + 64].copy_from_slice(nonce.as_slice());
    quote
}
