//! Real-node coverage for the canonical TIP-1061 examples.

use super::{
    helpers::{
        assert_fee_payer_spent, create_basic_aa_tx, sign_aa_tx_with_secp256k1_access_key,
        sign_fee_payer,
    },
    types::{ExpectedOutcome, FeePayerContext, TestEnv},
};
use alloy::{
    primitives::{Address, B256, Bytes},
    signers::{SignerSync, local::PrivateKeySigner},
    sol_types::SolCall,
};
use alloy_eips::Encodable2718;
use alloy_primitives::TxKind;
use reth_primitives_traits::transaction::TxHashRef;
use tempo_contracts::precompiles::{
    DEFAULT_FEE_TOKEN, NATIVE_MULTISIG_ADDRESS,
    account_keychain::IAccountKeychain::IAccountKeychainInstance,
    native_multisig::INativeMultisig::{self, INativeMultisigInstance},
};
use tempo_precompiles::{ACCOUNT_KEYCHAIN_ADDRESS, tip20::ITIP20};
use tempo_primitives::{
    SignatureType, TempoTransaction, TempoTxEnvelope,
    transaction::{
        FEE_PAYER_SIGNATURE_MARKER, InitMultisig, KeyAuthorization, MultisigOwner,
        MultisigSignature, multisig_digest,
        tempo_transaction::Call,
        tt_signature::{PrimitiveSignature, TempoSignature},
    },
};

const EXAMPLE_GAS_LIMIT: u64 = 5_000_000;

pub(super) fn sorted_signers() -> Vec<PrivateKeySigner> {
    let mut signers = (1..=3)
        .map(|byte| PrivateKeySigner::from_bytes(&B256::repeat_byte(byte)).unwrap())
        .collect::<Vec<_>>();
    signers.sort_by_key(|signer| signer.address());
    signers
}

fn signer(byte: u8) -> PrivateKeySigner {
    PrivateKeySigner::from_bytes(&B256::repeat_byte(byte)).unwrap()
}

pub(super) fn multisig_config(
    salt: u8,
    threshold: u8,
    owners: &[(&PrivateKeySigner, u8)],
) -> InitMultisig {
    let owners = owners
        .iter()
        .map(|(signer, weight)| MultisigOwner {
            owner: signer.address(),
            weight: *weight,
        })
        .collect::<Vec<_>>();
    assert!(owners.windows(2).all(|pair| pair[0].owner < pair[1].owner));

    InitMultisig {
        salt: B256::repeat_byte(salt),
        threshold,
        owners,
    }
}

pub(super) fn derived_account(config: &InitMultisig) -> eyre::Result<Address> {
    config.account().map_err(|err| eyre::eyre!(err.as_str()))
}

pub(super) fn no_op_call(byte: u8) -> Call {
    Call {
        to: TxKind::Call(Address::repeat_byte(byte)),
        value: Default::default(),
        input: Bytes::new(),
    }
}

pub(super) fn sign_multisig(
    account: Address,
    inner_digest: B256,
    version: u64,
    signers: &[&PrivateKeySigner],
    init: Option<InitMultisig>,
) -> eyre::Result<TempoSignature> {
    assert!(
        signers
            .windows(2)
            .all(|pair| pair[0].address() < pair[1].address())
    );
    let digest = multisig_digest(inner_digest, account, version);
    let approvals = signers
        .iter()
        .map(|signer| {
            signer
                .sign_hash_sync(&digest)
                .map(PrimitiveSignature::Secp256k1)
                .map(TempoSignature::Primitive)
        })
        .collect::<Result<Vec<_>, _>>()?;

    multisig_from_approvals(account, approvals, init)
}

fn multisig_from_approvals(
    account: Address,
    approvals: Vec<TempoSignature>,
    init: Option<InitMultisig>,
) -> eyre::Result<TempoSignature> {
    Ok(TempoSignature::Multisig(
        MultisigSignature::from_decoded(account, approvals, init).map_err(eyre::Report::msg)?,
    ))
}

async fn submit<E: TestEnv>(
    env: &mut E,
    tx: TempoTransaction,
    signature: TempoSignature,
) -> eyre::Result<serde_json::Value> {
    let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
    let tx_hash = *envelope.tx_hash();
    env.submit_tx(envelope.encoded_2718(), tx_hash).await
}

async fn reject<E: TestEnv>(
    env: &E,
    tx: TempoTransaction,
    signature: TempoSignature,
) -> eyre::Result<()> {
    let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
    env.submit_tx_expecting_rejection(envelope.encoded_2718(), None)
        .await
}

pub(super) async fn stored_config<E: TestEnv>(
    env: &E,
    account: Address,
) -> eyre::Result<INativeMultisig::MultisigConfig> {
    Ok(
        INativeMultisigInstance::new(NATIVE_MULTISIG_ADDRESS, env.provider())
            .getConfig(account)
            .call()
            .await?,
    )
}

async fn assert_active_key<E: TestEnv>(
    env: &E,
    account: Address,
    key_id: Address,
) -> eyre::Result<()> {
    let keychain = IAccountKeychainInstance::new(ACCOUNT_KEYCHAIN_ADDRESS, env.provider());
    let key = keychain.getKey(account, key_id).call().await?;
    assert_eq!(key.keyId, key_id);
    assert!(!key.isRevoked);
    Ok(())
}

enum SponsorshipOrder {
    OwnersFirst,
    FeePayerFirst,
}

struct MultisigAuthorization {
    account: Address,
    version: u64,
    init: Option<InitMultisig>,
}

async fn submit_sponsored<E: TestEnv>(
    env: &mut E,
    mut tx: TempoTransaction,
    authorization: MultisigAuthorization,
    owners: &[&PrivateKeySigner],
    fee_payer: &PrivateKeySigner,
    order: SponsorshipOrder,
) -> eyre::Result<()> {
    let balance_before = ITIP20::new(DEFAULT_FEE_TOKEN, env.provider())
        .balanceOf(fee_payer.address())
        .call()
        .await?;
    let owner_signature = match order {
        SponsorshipOrder::OwnersFirst => {
            tx.fee_token = None;
            tx.fee_payer_signature = Some(FEE_PAYER_SIGNATURE_MARKER);
            let signature = sign_multisig(
                authorization.account,
                tx.signature_hash(),
                authorization.version,
                owners,
                authorization.init,
            )?;
            tx.fee_token = Some(DEFAULT_FEE_TOKEN);
            sign_fee_payer(&mut tx, authorization.account, fee_payer)?;
            signature
        }
        SponsorshipOrder::FeePayerFirst => {
            sign_fee_payer(&mut tx, authorization.account, fee_payer)?;
            sign_multisig(
                authorization.account,
                tx.signature_hash(),
                authorization.version,
                owners,
                authorization.init,
            )?
        }
    };
    let receipt = submit(env, tx, owner_signature).await?;
    assert_fee_payer_spent(
        env.provider(),
        FeePayerContext {
            addr: fee_payer.address(),
            token: DEFAULT_FEE_TOKEN,
            balance_before,
        },
        &receipt,
    )
    .await
}

async fn bootstrap_weighted_quorum<E: TestEnv>(
    env: &mut E,
    salt: u8,
    alice: &PrivateKeySigner,
    bob: &PrivateKeySigner,
    carol: &PrivateKeySigner,
    approvals: &[&PrivateKeySigner],
    expected: ExpectedOutcome,
) -> eyre::Result<()> {
    let config = multisig_config(salt, 3, &[(alice, 2), (bob, 1), (carol, 1)]);
    let account = derived_account(&config)?;
    env.fund_account(account).await?;

    let tx = create_basic_aa_tx(env.chain_id(), 0, vec![no_op_call(salt)], EXAMPLE_GAS_LIMIT);
    let signature = sign_multisig(account, tx.signature_hash(), 0, approvals, Some(config))?;
    match expected {
        ExpectedOutcome::Success => {
            submit(env, tx, signature).await?;
        }
        ExpectedOutcome::Rejection => reject(env, tx, signature).await?,
        ExpectedOutcome::Revert => unreachable!("quorum validation does not execute the call"),
    }
    Ok(())
}

async fn bootstrap_and_initialized<E: TestEnv>(
    env: &mut E,
    alice: &PrivateKeySigner,
    bob: &PrivateKeySigner,
) -> eyre::Result<()> {
    let config = multisig_config(0x11, 2, &[(alice, 1), (bob, 1)]);
    let account = derived_account(&config)?;
    env.fund_account(account).await?;

    let bootstrap =
        create_basic_aa_tx(env.chain_id(), 0, vec![no_op_call(0x11)], EXAMPLE_GAS_LIMIT);
    let signature = sign_multisig(
        account,
        bootstrap.signature_hash(),
        0,
        &[alice, bob],
        Some(config),
    )?;
    submit(env, bootstrap, signature).await?;

    let stored = stored_config(env, account).await?;
    assert_eq!(stored.version, 1);
    assert_eq!(stored.threshold, 2);

    let initialized =
        create_basic_aa_tx(env.chain_id(), 1, vec![no_op_call(0x12)], EXAMPLE_GAS_LIMIT);
    let signature = sign_multisig(
        account,
        initialized.signature_hash(),
        stored.version,
        &[alice, bob],
        None,
    )?;
    submit(env, initialized, signature).await?;
    Ok(())
}

async fn nested_ownership<E: TestEnv>(
    env: &mut E,
    alice: &PrivateKeySigner,
    bob: &PrivateKeySigner,
) -> eyre::Result<()> {
    let child_config = multisig_config(0x21, 2, &[(alice, 1), (bob, 1)]);
    let child = derived_account(&child_config)?;
    env.fund_account(child).await?;

    let child_bootstrap =
        create_basic_aa_tx(env.chain_id(), 0, vec![no_op_call(0x21)], EXAMPLE_GAS_LIMIT);
    let signature = sign_multisig(
        child,
        child_bootstrap.signature_hash(),
        0,
        &[alice, bob],
        Some(child_config),
    )?;
    submit(env, child_bootstrap, signature).await?;
    let child_version = stored_config(env, child).await?.version;

    let parent_config = InitMultisig {
        salt: B256::repeat_byte(0x22),
        threshold: 1,
        owners: vec![MultisigOwner {
            owner: child,
            weight: 1,
        }],
    };
    let parent = derived_account(&parent_config)?;
    env.fund_account(parent).await?;

    let parent_bootstrap =
        create_basic_aa_tx(env.chain_id(), 0, vec![no_op_call(0x22)], EXAMPLE_GAS_LIMIT);
    let parent_digest = multisig_digest(parent_bootstrap.signature_hash(), parent, 0);
    let child_signature = sign_multisig(child, parent_digest, child_version, &[alice, bob], None)?;
    let signature = multisig_from_approvals(parent, vec![child_signature], Some(parent_config))?;
    submit(env, parent_bootstrap, signature).await?;
    let parent_version = stored_config(env, parent).await?.version;

    let initialized =
        create_basic_aa_tx(env.chain_id(), 1, vec![no_op_call(0x23)], EXAMPLE_GAS_LIMIT);
    let parent_digest = multisig_digest(initialized.signature_hash(), parent, parent_version);
    let child_signature = sign_multisig(child, parent_digest, child_version, &[alice, bob], None)?;
    let signature = multisig_from_approvals(parent, vec![child_signature], None)?;
    submit(env, initialized, signature).await?;
    Ok(())
}

async fn fee_sponsorship<E: TestEnv>(
    env: &mut E,
    alice: &PrivateKeySigner,
    bob: &PrivateKeySigner,
) -> eyre::Result<()> {
    let chain_id = env.chain_id();
    let fee_payer = signer(0x31);
    env.fund_account(fee_payer.address()).await?;

    let config = multisig_config(0x31, 2, &[(alice, 1), (bob, 1)]);
    let account = derived_account(&config)?;
    env.fund_account(account).await?;
    submit_sponsored(
        env,
        create_basic_aa_tx(chain_id, 0, vec![no_op_call(0x31)], EXAMPLE_GAS_LIMIT),
        MultisigAuthorization {
            account,
            version: 0,
            init: Some(config),
        },
        &[alice, bob],
        &fee_payer,
        SponsorshipOrder::OwnersFirst,
    )
    .await?;

    let config = multisig_config(0x32, 2, &[(alice, 1), (bob, 1)]);
    let account = derived_account(&config)?;
    env.fund_account(account).await?;
    submit_sponsored(
        env,
        create_basic_aa_tx(chain_id, 0, vec![no_op_call(0x32)], EXAMPLE_GAS_LIMIT),
        MultisigAuthorization {
            account,
            version: 0,
            init: Some(config),
        },
        &[alice, bob],
        &fee_payer,
        SponsorshipOrder::FeePayerFirst,
    )
    .await?;

    let config = multisig_config(0x33, 2, &[(alice, 1), (bob, 1)]);
    let account = derived_account(&config)?;
    env.fund_account(account).await?;
    let bootstrap = create_basic_aa_tx(chain_id, 0, vec![no_op_call(0x33)], EXAMPLE_GAS_LIMIT);
    let signature = sign_multisig(
        account,
        bootstrap.signature_hash(),
        0,
        &[alice, bob],
        Some(config),
    )?;
    submit(env, bootstrap, signature).await?;
    let version = stored_config(env, account).await?.version;

    submit_sponsored(
        env,
        create_basic_aa_tx(chain_id, 1, vec![no_op_call(0x34)], EXAMPLE_GAS_LIMIT),
        MultisigAuthorization {
            account,
            version,
            init: None,
        },
        &[alice, bob],
        &fee_payer,
        SponsorshipOrder::OwnersFirst,
    )
    .await?;
    submit_sponsored(
        env,
        create_basic_aa_tx(chain_id, 2, vec![no_op_call(0x35)], EXAMPLE_GAS_LIMIT),
        MultisigAuthorization {
            account,
            version,
            init: None,
        },
        &[alice, bob],
        &fee_payer,
        SponsorshipOrder::FeePayerFirst,
    )
    .await?;
    Ok(())
}

async fn weighted_quorum<E: TestEnv>(
    env: &mut E,
    alice: &PrivateKeySigner,
    bob: &PrivateKeySigner,
    carol: &PrivateKeySigner,
) -> eyre::Result<()> {
    bootstrap_weighted_quorum(
        env,
        0x41,
        alice,
        bob,
        carol,
        &[alice, bob],
        ExpectedOutcome::Success,
    )
    .await?;
    bootstrap_weighted_quorum(
        env,
        0x42,
        alice,
        bob,
        carol,
        &[alice, carol],
        ExpectedOutcome::Success,
    )
    .await?;
    bootstrap_weighted_quorum(
        env,
        0x43,
        alice,
        bob,
        carol,
        &[bob, carol],
        ExpectedOutcome::Rejection,
    )
    .await?;
    bootstrap_weighted_quorum(
        env,
        0x44,
        alice,
        bob,
        carol,
        &[alice, bob, carol],
        ExpectedOutcome::Rejection,
    )
    .await?;

    let config = multisig_config(0x45, 3, &[(alice, 2), (bob, 1), (carol, 1)]);
    let account = derived_account(&config)?;
    env.fund_account(account).await?;

    let bootstrap =
        create_basic_aa_tx(env.chain_id(), 0, vec![no_op_call(0x45)], EXAMPLE_GAS_LIMIT);
    let signature = sign_multisig(
        account,
        bootstrap.signature_hash(),
        0,
        &[alice, bob],
        Some(config),
    )?;
    submit(env, bootstrap, signature).await?;
    let version = stored_config(env, account).await?.version;

    let alice_bob =
        create_basic_aa_tx(env.chain_id(), 1, vec![no_op_call(0x46)], EXAMPLE_GAS_LIMIT);
    let signature = sign_multisig(
        account,
        alice_bob.signature_hash(),
        version,
        &[alice, bob],
        None,
    )?;
    submit(env, alice_bob, signature).await?;

    let alice_carol =
        create_basic_aa_tx(env.chain_id(), 2, vec![no_op_call(0x47)], EXAMPLE_GAS_LIMIT);
    let signature = sign_multisig(
        account,
        alice_carol.signature_hash(),
        version,
        &[alice, carol],
        None,
    )?;
    submit(env, alice_carol, signature).await?;

    let below_threshold =
        create_basic_aa_tx(env.chain_id(), 3, vec![no_op_call(0x48)], EXAMPLE_GAS_LIMIT);
    let signature = sign_multisig(
        account,
        below_threshold.signature_hash(),
        version,
        &[bob, carol],
        None,
    )?;
    reject(env, below_threshold, signature).await?;

    let excess_signature =
        create_basic_aa_tx(env.chain_id(), 3, vec![no_op_call(0x49)], EXAMPLE_GAS_LIMIT);
    let signature = sign_multisig(
        account,
        excess_signature.signature_hash(),
        version,
        &[alice, bob, carol],
        None,
    )?;
    reject(env, excess_signature, signature).await?;
    Ok(())
}

async fn bootstrap_and_immediate_access_key_use<E: TestEnv>(
    env: &mut E,
    alice: &PrivateKeySigner,
    bob: &PrivateKeySigner,
) -> eyre::Result<()> {
    let config = multisig_config(0x51, 2, &[(alice, 1), (bob, 1)]);
    let account = derived_account(&config)?;
    let access_key = signer(0x51);
    env.fund_account(account).await?;

    let authorization = KeyAuthorization::unrestricted(
        env.chain_id(),
        SignatureType::Secp256k1,
        access_key.address(),
    )
    .with_account(account);
    let authorization_signature = sign_multisig(
        account,
        authorization.signature_hash(),
        0,
        &[alice, bob],
        Some(config),
    )?;

    let mut tx = create_basic_aa_tx(env.chain_id(), 0, vec![no_op_call(0x51)], EXAMPLE_GAS_LIMIT);
    tx.key_authorization = Some(authorization.into_signed(authorization_signature));
    let signature = sign_aa_tx_with_secp256k1_access_key(&tx, &access_key, account)?;
    submit(env, tx, signature).await?;

    assert_eq!(stored_config(env, account).await?.version, 1);
    assert_active_key(env, account, access_key.address()).await?;
    Ok(())
}

async fn bootstrap_and_subsequent_access_key_use<E: TestEnv>(
    env: &mut E,
    alice: &PrivateKeySigner,
    bob: &PrivateKeySigner,
) -> eyre::Result<()> {
    let config = multisig_config(0x61, 2, &[(alice, 1), (bob, 1)]);
    let account = derived_account(&config)?;
    let access_key = signer(0x61);
    env.fund_account(account).await?;

    let authorization = KeyAuthorization::unrestricted(
        env.chain_id(),
        SignatureType::Secp256k1,
        access_key.address(),
    )
    .with_account(account);
    let authorization_signature = sign_multisig(
        account,
        authorization.signature_hash(),
        0,
        &[alice, bob],
        None,
    )?;

    let mut bootstrap =
        create_basic_aa_tx(env.chain_id(), 0, vec![no_op_call(0x61)], EXAMPLE_GAS_LIMIT);
    bootstrap.key_authorization = Some(authorization.into_signed(authorization_signature));
    let signature = sign_multisig(
        account,
        bootstrap.signature_hash(),
        0,
        &[alice, bob],
        Some(config),
    )?;
    submit(env, bootstrap, signature).await?;
    assert_active_key(env, account, access_key.address()).await?;

    let access_key_tx =
        create_basic_aa_tx(env.chain_id(), 1, vec![no_op_call(0x62)], EXAMPLE_GAS_LIMIT);
    let signature = sign_aa_tx_with_secp256k1_access_key(&access_key_tx, &access_key, account)?;
    submit(env, access_key_tx, signature).await?;
    Ok(())
}

async fn configuration_rotation<E: TestEnv>(
    env: &mut E,
    alice: &PrivateKeySigner,
    bob: &PrivateKeySigner,
    carol: &PrivateKeySigner,
) -> eyre::Result<()> {
    let config = multisig_config(0x71, 2, &[(alice, 1), (bob, 1)]);
    let account = derived_account(&config)?;
    env.fund_account(account).await?;

    let bootstrap =
        create_basic_aa_tx(env.chain_id(), 0, vec![no_op_call(0x71)], EXAMPLE_GAS_LIMIT);
    let signature = sign_multisig(
        account,
        bootstrap.signature_hash(),
        0,
        &[alice, bob],
        Some(config),
    )?;
    submit(env, bootstrap, signature).await?;
    let current_version = stored_config(env, account).await?.version;

    let update_call = INativeMultisig::updateConfigCall {
        threshold: 1,
        owners: vec![INativeMultisig::MultisigOwner {
            owner: carol.address(),
            weight: 1,
        }],
    };
    let rotation = create_basic_aa_tx(
        env.chain_id(),
        1,
        vec![Call {
            to: NATIVE_MULTISIG_ADDRESS.into(),
            value: Default::default(),
            input: update_call.abi_encode().into(),
        }],
        EXAMPLE_GAS_LIMIT,
    );
    let signature = sign_multisig(
        account,
        rotation.signature_hash(),
        current_version,
        &[alice, bob],
        None,
    )?;
    submit(env, rotation, signature).await?;

    let next_config = stored_config(env, account).await?;
    assert_eq!(next_config.version, current_version + 1);
    assert_eq!(next_config.threshold, 1);
    assert_eq!(next_config.owners.len(), 1);
    assert_eq!(next_config.owners[0].owner, carol.address());

    let stale_tx = create_basic_aa_tx(env.chain_id(), 2, vec![no_op_call(0x72)], EXAMPLE_GAS_LIMIT);
    let stale_signature = sign_multisig(
        account,
        stale_tx.signature_hash(),
        current_version,
        &[alice, bob],
        None,
    )?;
    reject(env, stale_tx, stale_signature).await?;

    let next_tx = create_basic_aa_tx(env.chain_id(), 2, vec![no_op_call(0x72)], EXAMPLE_GAS_LIMIT);
    let signature = sign_multisig(
        account,
        next_tx.signature_hash(),
        next_config.version,
        &[carol],
        None,
    )?;
    submit(env, next_tx, signature).await?;
    Ok(())
}

pub(super) async fn run_tip_1061_examples<E: TestEnv>(env: &mut E) -> eyre::Result<()> {
    let signers = sorted_signers();
    let (alice, bob, carol) = (&signers[0], &signers[1], &signers[2]);

    bootstrap_and_initialized(env, alice, bob).await?;
    nested_ownership(env, alice, bob).await?;
    fee_sponsorship(env, alice, bob).await?;
    weighted_quorum(env, alice, bob, carol).await?;
    bootstrap_and_immediate_access_key_use(env, alice, bob).await?;
    bootstrap_and_subsequent_access_key_use(env, alice, bob).await?;
    configuration_rotation(env, alice, bob, carol).await?;
    Ok(())
}
