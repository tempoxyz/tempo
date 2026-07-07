//! E2E coverage for native multisig accounts spending through scoped AccountKeychain access keys.

use alloy::{
    primitives::{Address, B256, Bytes, U256},
    providers::Provider,
    signers::{SignerSync, local::PrivateKeySigner},
};
use alloy_eips::Encodable2718;
use reth_primitives_traits::transaction::TxHashRef;
use tempo_alloy::provider::keychain::{authorize_key, tip20_transfer_policy};
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_contracts::precompiles::{
    DEFAULT_FEE_TOKEN, account_keychain::IAccountKeychain::IAccountKeychainInstance,
};
use tempo_precompiles::{ACCOUNT_KEYCHAIN_ADDRESS, tip20::ITIP20::ITIP20Instance};
use tempo_primitives::{
    SignatureType, TempoTransaction, TempoTxEnvelope,
    transaction::{
        InitMultisig, KeychainSignature, MultisigOwner, MultisigSignature, PrimitiveSignature,
        TempoSignature, multisig_digest,
    },
};

use super::{helpers::*, local::Localnet};

const TOKEN: Address = DEFAULT_FEE_TOKEN;
const ONE_TOKEN: u64 = 1_000_000;
const LOW_LIMIT: u64 = 1_000 * ONE_TOKEN;
const HIGH_LIMIT: u64 = 10_000 * ONE_TOKEN;
const SHARED_MULTISIG_FUNDING: u64 = 100_000 * ONE_TOKEN;
const ACCESS_KEY_MULTISIG_FUNDING: u64 = 10_000 * ONE_TOKEN;

#[tokio::test(flavor = "multi_thread")]
async fn shared_multisig_spends_through_tiered_scoped_access_keys() -> eyre::Result<()> {
    let mut env = Localnet::new().await?;

    let shared_signers = multisig_owner_signers(0x10);
    let low_signers = multisig_owner_signers(0x20);
    let high_signers = multisig_owner_signers(0x30);
    let shared_config = multisig_config(B256::repeat_byte(0x51), 2, &shared_signers);
    let low_key_config = multisig_config(B256::repeat_byte(0x52), 2, &low_signers);
    let high_key_config = multisig_config(B256::repeat_byte(0x53), 3, &high_signers);
    let shared_multisig = multisig_account(&shared_config)?;
    let low_key = multisig_account(&low_key_config)?;
    let high_key = multisig_account(&high_key_config)?;
    let allowed_recipient = Address::random();
    let blocked_recipient = Address::random();

    fund_address_with(
        &mut env.setup,
        &env.provider,
        &env.funder_signer,
        env.funder_addr,
        shared_multisig,
        U256::from(SHARED_MULTISIG_FUNDING),
        TOKEN,
        env.chain_id,
    )
    .await?;
    fund_multisig_account(&mut env, low_key).await?;
    fund_multisig_account(&mut env, high_key).await?;

    bootstrap_multisig(&mut env, &shared_config, &shared_signers).await?;
    bootstrap_multisig(&mut env, &low_key_config, &low_signers).await?;
    bootstrap_multisig(&mut env, &high_key_config, &high_signers).await?;
    authorize_tiered_access_keys(
        &mut env,
        shared_multisig,
        &shared_config,
        &shared_signers,
        low_key,
        high_key,
        allowed_recipient,
    )
    .await?;

    let low_remaining_before = remaining_limit(&env.provider, shared_multisig, low_key).await?;
    assert_eq!(low_remaining_before, U256::from(LOW_LIMIT));

    let low_amount = U256::from(LOW_LIMIT / 4);
    let allowed_balance_before = token_balance(&env.provider, allowed_recipient).await?;
    submit_access_key_transfer(
        &mut env,
        shared_multisig,
        &low_key_config,
        &low_signers,
        allowed_recipient,
        low_amount,
    )
    .await?;
    assert_eq!(
        token_balance(&env.provider, allowed_recipient).await?,
        allowed_balance_before + low_amount,
        "low-tier access key should spend from the shared multisig within its policy"
    );

    let low_remaining_after = remaining_limit(&env.provider, shared_multisig, low_key).await?;
    assert!(
        low_remaining_after < low_remaining_before,
        "successful spend should consume the low-tier key's limit"
    );

    let over_limit_tx = transfer_tx(
        &env.provider,
        env.chain_id,
        shared_multisig,
        allowed_recipient,
        U256::from(LOW_LIMIT + ONE_TOKEN),
    )
    .await?;
    let over_limit_sig = sign_aa_tx_with_multisig_access_key(
        &over_limit_tx,
        shared_multisig,
        &low_key_config,
        &low_signers,
    )?;
    assert_rejected(
        &mut env,
        over_limit_tx,
        over_limit_sig,
        "over low-tier limit",
    )
    .await?;

    let wrong_recipient_tx = transfer_tx(
        &env.provider,
        env.chain_id,
        shared_multisig,
        blocked_recipient,
        U256::from(ONE_TOKEN),
    )
    .await?;
    let wrong_recipient_sig = sign_aa_tx_with_multisig_access_key(
        &wrong_recipient_tx,
        shared_multisig,
        &low_key_config,
        &low_signers,
    )?;
    assert_rejected(
        &mut env,
        wrong_recipient_tx,
        wrong_recipient_sig,
        "outside allowed recipient scope",
    )
    .await?;

    let under_threshold_tx = transfer_tx(
        &env.provider,
        env.chain_id,
        shared_multisig,
        allowed_recipient,
        U256::from(ONE_TOKEN),
    )
    .await?;
    let under_threshold_sig = sign_aa_tx_with_multisig_access_key(
        &under_threshold_tx,
        shared_multisig,
        &low_key_config,
        &low_signers[..1],
    )?;
    assert_rejected(
        &mut env,
        under_threshold_tx,
        under_threshold_sig,
        "below low-tier key threshold",
    )
    .await?;

    let high_amount = U256::from(LOW_LIMIT + 500 * ONE_TOKEN);
    let high_balance_before = token_balance(&env.provider, allowed_recipient).await?;
    submit_access_key_transfer(
        &mut env,
        shared_multisig,
        &high_key_config,
        &high_signers,
        allowed_recipient,
        high_amount,
    )
    .await?;
    assert_eq!(
        token_balance(&env.provider, allowed_recipient).await?,
        high_balance_before + high_amount,
        "higher-tier access key should spend above the low-tier limit"
    );

    Ok(())
}

fn multisig_owner_signers(base: u8) -> [PrivateKeySigner; 3] {
    [
        PrivateKeySigner::from_bytes(&B256::repeat_byte(base + 1)).unwrap(),
        PrivateKeySigner::from_bytes(&B256::repeat_byte(base + 2)).unwrap(),
        PrivateKeySigner::from_bytes(&B256::repeat_byte(base + 3)).unwrap(),
    ]
}

fn multisig_config(salt: B256, threshold: u8, signers: &[PrivateKeySigner]) -> InitMultisig {
    let mut owners = signers
        .iter()
        .map(|signer| MultisigOwner {
            owner: signer.address(),
            weight: 1,
        })
        .collect::<Vec<_>>();
    owners.sort_by_key(|owner| owner.owner);

    InitMultisig {
        salt,
        threshold,
        owners,
    }
}

async fn bootstrap_multisig(
    env: &mut Localnet,
    config: &InitMultisig,
    owner_signers: &[PrivateKeySigner],
) -> eyre::Result<()> {
    let account = multisig_account(config)?;
    let tx = create_basic_aa_tx(
        env.chain_id,
        0,
        vec![create_balance_of_call(account)],
        3_000_000,
    );
    let signature = sign_multisig_tx(&tx, config, owner_signers, true)?;
    submit_and_mine_success(env, tx, signature, "bootstrap shared multisig").await?;
    Ok(())
}

async fn fund_multisig_account(env: &mut Localnet, account: Address) -> eyre::Result<()> {
    fund_address_with(
        &mut env.setup,
        &env.provider,
        &env.funder_signer,
        env.funder_addr,
        account,
        U256::from(ACCESS_KEY_MULTISIG_FUNDING),
        TOKEN,
        env.chain_id,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn authorize_tiered_access_keys(
    env: &mut Localnet,
    shared_multisig: Address,
    config: &InitMultisig,
    owner_signers: &[PrivateKeySigner],
    low_key: Address,
    high_key: Address,
    allowed_recipient: Address,
) -> eyre::Result<()> {
    let nonce = env.provider.get_transaction_count(shared_multisig).await?;
    let calls = vec![
        authorize_key(
            low_key,
            SignatureType::Multisig,
            tip20_transfer_policy(TOKEN, U256::from(LOW_LIMIT), vec![allowed_recipient]),
        ),
        authorize_key(
            high_key,
            SignatureType::Multisig,
            tip20_transfer_policy(TOKEN, U256::from(HIGH_LIMIT), vec![allowed_recipient]),
        ),
    ];
    let tx = create_basic_aa_tx(env.chain_id, nonce, calls, 20_000_000);
    let signature = sign_multisig_tx(&tx, config, owner_signers, false)?;
    submit_and_mine_success(env, tx, signature, "authorize tiered access keys").await?;
    Ok(())
}

fn sign_multisig_tx(
    tx: &TempoTransaction,
    config: &InitMultisig,
    owner_signers: &[PrivateKeySigner],
    include_init: bool,
) -> eyre::Result<TempoSignature> {
    let account = multisig_account(config)?;
    Ok(TempoSignature::Multisig(sign_multisig_digest(
        tx.signature_hash(),
        account,
        config,
        owner_signers,
        include_init,
    )?))
}

fn sign_multisig_digest(
    signature_hash: B256,
    account: Address,
    config: &InitMultisig,
    owner_signers: &[PrivateKeySigner],
    include_init: bool,
) -> eyre::Result<MultisigSignature> {
    let digest = multisig_digest(signature_hash, account);
    let mut approvals = owner_signers
        .iter()
        .map(|signer| {
            let signature = signer.sign_hash_sync(&digest)?;
            Ok((
                signer.address(),
                PrimitiveSignature::Secp256k1(signature).to_bytes(),
            ))
        })
        .collect::<eyre::Result<Vec<_>>>()?;
    approvals.sort_by_key(|(owner, _)| *owner);

    let signatures = approvals
        .into_iter()
        .take(config.threshold as usize)
        .map(|(_, signature)| Bytes::from(signature))
        .collect();

    Ok(MultisigSignature::new(
        account,
        signatures,
        include_init.then(|| config.clone()),
    ))
}

fn multisig_account(config: &InitMultisig) -> eyre::Result<Address> {
    config
        .account()
        .map_err(|err| eyre::eyre!("invalid multisig config: {err:?}"))
}

async fn submit_access_key_transfer(
    env: &mut Localnet,
    shared_multisig: Address,
    access_key_config: &InitMultisig,
    access_key_signers: &[PrivateKeySigner],
    recipient: Address,
    amount: U256,
) -> eyre::Result<()> {
    let tx = transfer_tx(
        &env.provider,
        env.chain_id,
        shared_multisig,
        recipient,
        amount,
    )
    .await?;
    let signature = sign_aa_tx_with_multisig_access_key(
        &tx,
        shared_multisig,
        access_key_config,
        access_key_signers,
    )?;
    submit_and_mine_success(env, tx, signature, "access key transfer").await?;
    Ok(())
}

fn sign_aa_tx_with_multisig_access_key(
    tx: &TempoTransaction,
    shared_multisig: Address,
    access_key_config: &InitMultisig,
    access_key_signers: &[PrivateKeySigner],
) -> eyre::Result<TempoSignature> {
    let access_key_account = multisig_account(access_key_config)?;
    let signing_hash = KeychainSignature::signing_hash(tx.signature_hash(), shared_multisig);
    let inner = sign_multisig_digest(
        signing_hash,
        access_key_account,
        access_key_config,
        access_key_signers,
        false,
    )?;
    Ok(TempoSignature::Keychain(KeychainSignature::new(
        shared_multisig,
        inner,
    )))
}

async fn transfer_tx(
    provider: &impl Provider,
    chain_id: u64,
    from: Address,
    to: Address,
    amount: U256,
) -> eyre::Result<TempoTransaction> {
    let nonce = provider.get_transaction_count(from).await?;
    let mut tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_transfer_call(TOKEN, to, amount)],
        3_000_000,
    );
    tx.max_priority_fee_per_gas = TEMPO_T1_BASE_FEE as u128;
    tx.max_fee_per_gas = TEMPO_T1_BASE_FEE as u128;
    Ok(tx)
}

async fn assert_rejected(
    env: &mut Localnet,
    tx: TempoTransaction,
    signature: TempoSignature,
    label: &str,
) -> eyre::Result<()> {
    let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
    let tx_hash = *envelope.tx_hash();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);

    let result = env.setup.node.rpc.inject_tx(encoded.into()).await;
    if result.is_err() {
        return Ok(());
    }

    env.setup.node.advance_block().await?;
    let receipt: Option<serde_json::Value> = env
        .provider
        .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
        .await?;
    let receipt = receipt.ok_or_else(|| eyre::eyre!("{label} receipt not found for {tx_hash}"))?;
    let status = receipt["status"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("{label} receipt missing status for {tx_hash}"))?;
    assert_eq!(
        status, "0x0",
        "{label} transaction {tx_hash} should be rejected or revert"
    );
    Ok(())
}

async fn submit_and_mine_success(
    env: &mut Localnet,
    tx: TempoTransaction,
    signature: TempoSignature,
    label: &str,
) -> eyre::Result<()> {
    let hash = submit_and_mine_aa_tx(&mut env.setup, tx, signature).await?;
    let receipt: Option<serde_json::Value> = env
        .provider
        .raw_request("eth_getTransactionReceipt".into(), [hash])
        .await?;
    let receipt = receipt.ok_or_else(|| eyre::eyre!("{label} receipt not found for {hash}"))?;
    let status = receipt["status"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("{label} receipt missing status for {hash}"))?;
    eyre::ensure!(
        status == "0x1",
        "{label} reverted with status {status}: {receipt}"
    );
    Ok(())
}

async fn token_balance(provider: &impl Provider, account: Address) -> eyre::Result<U256> {
    Ok(ITIP20Instance::new(TOKEN, provider)
        .balanceOf(account)
        .call()
        .await?)
}

async fn remaining_limit(
    provider: &impl Provider,
    account: Address,
    key: Address,
) -> eyre::Result<U256> {
    Ok(
        IAccountKeychainInstance::new(ACCOUNT_KEYCHAIN_ADDRESS, provider)
            .getRemainingLimitWithPeriod(account, key, TOKEN)
            .call()
            .await?
            .remaining,
    )
}
