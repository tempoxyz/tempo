//! Real-node coverage for the canonical TIP-1061 examples.

use super::{
    helpers::{
        assert_fee_payer_spent, create_basic_aa_tx, sign_aa_tx_with_secp256k1_access_key,
        sign_fee_payer,
    },
    types::{ExpectedOutcome, FeePayerContext, TestEnv},
};
use alloy::{
    primitives::{Address, B256, Bytes, U256},
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
    SignatureType, TempoAddressExt, TempoTransaction, TempoTxEnvelope,
    transaction::{
        FEE_PAYER_SIGNATURE_MARKER, KeyAuthorization, MultisigConfig, MultisigOwner,
        MultisigSignature, SignedKeyAuthorization, multisig_digest,
        tempo_transaction::Call,
        tt_signature::{PrimitiveSignature, TempoSignature},
    },
};

const EXAMPLE_GAS_LIMIT: u64 = 5_000_000;
const CONFIG_COMMITMENT_MISMATCH: &str = "multisig configuration commitment mismatch";

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
) -> MultisigConfig {
    let owners = owners
        .iter()
        .map(|(signer, weight)| MultisigOwner {
            owner: signer.address(),
            weight: *weight,
        })
        .collect::<Vec<_>>();
    assert!(owners.windows(2).all(|pair| pair[0].owner < pair[1].owner));

    MultisigConfig {
        salt: B256::repeat_byte(salt),
        version: 0,
        threshold,
        owners,
    }
}

pub(super) fn derived_account(config: &MultisigConfig) -> eyre::Result<Address> {
    config
        .derive_account()
        .map_err(|err| eyre::eyre!(err.as_str()))
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
    config: &MultisigConfig,
    signers: &[&PrivateKeySigner],
) -> eyre::Result<TempoSignature> {
    assert!(
        signers
            .windows(2)
            .all(|pair| pair[0].address() < pair[1].address())
    );
    let digest = multisig_digest(inner_digest, account, config.version);
    let approvals = signers
        .iter()
        .map(|signer| {
            signer
                .sign_hash_sync(&digest)
                .map(PrimitiveSignature::Secp256k1)
                .map(TempoSignature::Primitive)
        })
        .collect::<Result<Vec<_>, _>>()?;

    multisig_from_approvals(account, config, approvals)
}

pub(super) fn multisig_from_approvals(
    account: Address,
    config: &MultisigConfig,
    approvals: Vec<TempoSignature>,
) -> eyre::Result<TempoSignature> {
    Ok(TempoSignature::Multisig(
        MultisigSignature::try_new(account, config.clone(), approvals)
            .map_err(|error| eyre::eyre!(error.as_str()))?,
    ))
}

/// Funded multisig account with nonce-aware transaction and signing helpers.
struct MultisigAccountFixture<'a> {
    account: Address,
    config: MultisigConfig,
    owners: Vec<&'a PrivateKeySigner>,
    nonce: u64,
}

impl<'a> MultisigAccountFixture<'a> {
    async fn funded<E: TestEnv>(
        env: &mut E,
        salt: u8,
        threshold: u8,
        owners: &[(&'a PrivateKeySigner, u8)],
    ) -> eyre::Result<Self> {
        let config = multisig_config(salt, threshold, owners);
        let account = derived_account(&config)?;
        env.fund_account(account).await?;
        Ok(Self {
            account,
            config,
            owners: owners.iter().map(|(owner, _)| *owner).collect(),
            nonce: 0,
        })
    }

    fn transaction_with_calls<E: TestEnv>(&self, env: &E, calls: Vec<Call>) -> TempoTransaction {
        create_basic_aa_tx(env.chain_id(), self.nonce, calls, EXAMPLE_GAS_LIMIT)
    }

    fn no_op_transaction<E: TestEnv>(&self, env: &E, byte: u8) -> TempoTransaction {
        self.transaction_with_calls(env, vec![no_op_call(byte)])
    }

    fn sign(&self, tx: &TempoTransaction) -> eyre::Result<TempoSignature> {
        self.sign_with_owners(tx, &self.owners)
    }

    fn sign_with_owners(
        &self,
        tx: &TempoTransaction,
        owners: &[&PrivateKeySigner],
    ) -> eyre::Result<TempoSignature> {
        sign_multisig(self.account, tx.signature_hash(), &self.config, owners)
    }

    fn signed_key_authorization(
        &self,
        chain_id: u64,
        key_id: Address,
        is_admin: bool,
    ) -> eyre::Result<SignedKeyAuthorization> {
        signed_key_authorization(
            chain_id,
            self.account,
            &self.config,
            key_id,
            is_admin,
            KeyAuthorizationSigner::Quorum(&self.owners),
        )
    }

    /// Advances the fixture nonce only after a successful submission.
    async fn submit_signed<E: TestEnv>(
        &mut self,
        env: &mut E,
        tx: TempoTransaction,
        signature: TempoSignature,
    ) -> eyre::Result<()> {
        submit(env, tx, signature).await?;
        self.nonce += 1;
        Ok(())
    }

    async fn submit_no_op<E: TestEnv>(&mut self, env: &mut E, byte: u8) -> eyre::Result<()> {
        let tx = self.no_op_transaction(env, byte);
        let signature = self.sign(&tx)?;
        self.submit_signed(env, tx, signature).await
    }

    async fn assert_no_stored_config<E: TestEnv>(&self, env: &E) -> eyre::Result<()> {
        assert_eq!(
            stored_config_commitment(env, self.account).await?,
            B256::ZERO
        );
        Ok(())
    }
}

fn sign_nested_multisig(
    account: Address,
    inner_digest: B256,
    config: &MultisigConfig,
    nested_account: Address,
    nested_config: &MultisigConfig,
    nested_signers: &[&PrivateKeySigner],
) -> eyre::Result<TempoSignature> {
    let nested_digest = multisig_digest(inner_digest, account, config.version);
    let nested_signature =
        sign_multisig(nested_account, nested_digest, nested_config, nested_signers)?;
    multisig_from_approvals(account, config, vec![nested_signature])
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

pub(super) async fn reject<E: TestEnv>(
    env: &E,
    tx: TempoTransaction,
    signature: TempoSignature,
    expected_reason: &str,
) -> eyre::Result<()> {
    let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
    env.submit_tx_expecting_rejection(envelope.encoded_2718(), Some(expected_reason))
        .await
}

async fn revert<E: TestEnv>(
    env: &mut E,
    tx: TempoTransaction,
    signature: TempoSignature,
) -> eyre::Result<()> {
    let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
    let tx_hash = *envelope.tx_hash();
    let receipt = env
        .submit_tx_unchecked(envelope.encoded_2718(), tx_hash)
        .await?;
    assert_eq!(receipt["status"].as_str(), Some("0x0"));
    Ok(())
}

pub(super) async fn stored_config_commitment<E: TestEnv>(
    env: &E,
    account: Address,
) -> eyre::Result<B256> {
    Ok(
        INativeMultisigInstance::new(NATIVE_MULTISIG_ADDRESS, env.provider())
            .getConfigCommitment(account)
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

async fn assert_inactive_key<E: TestEnv>(
    env: &E,
    account: Address,
    key_id: Address,
) -> eyre::Result<()> {
    let keychain = IAccountKeychainInstance::new(ACCOUNT_KEYCHAIN_ADDRESS, env.provider());
    assert_eq!(
        keychain.getKey(account, key_id).call().await?.keyId,
        Address::ZERO
    );
    Ok(())
}

async fn assert_admin_key<E: TestEnv>(
    env: &E,
    account: Address,
    key_id: Address,
) -> eyre::Result<()> {
    let keychain = IAccountKeychainInstance::new(ACCOUNT_KEYCHAIN_ADDRESS, env.provider());
    assert!(keychain.isAdminKey(account, key_id).call().await?);
    Ok(())
}

#[derive(Clone, Copy)]
enum KeyAuthorizationSigner<'a> {
    Quorum(&'a [&'a PrivateKeySigner]),
    Primitive(&'a PrivateKeySigner),
}

fn signed_key_authorization(
    chain_id: u64,
    account: Address,
    config: &MultisigConfig,
    key_id: Address,
    is_admin: bool,
    signer: KeyAuthorizationSigner<'_>,
) -> eyre::Result<SignedKeyAuthorization> {
    let authorization = KeyAuthorization::unrestricted(chain_id, SignatureType::Secp256k1, key_id);
    let authorization = if is_admin {
        authorization.into_admin(account)
    } else {
        authorization.with_account(account)
    };
    let signature = match signer {
        KeyAuthorizationSigner::Quorum(owners) => {
            sign_multisig(account, authorization.signature_hash(), config, owners)?
        }
        KeyAuthorizationSigner::Primitive(signer) => TempoSignature::Primitive(
            PrimitiveSignature::Secp256k1(signer.sign_hash_sync(&authorization.signature_hash())?),
        ),
    };
    Ok(authorization.into_signed(signature))
}

pub(super) fn update_config_call(current: &MultisigConfig, next: &MultisigConfig) -> Call {
    assert_eq!(next.salt, current.salt);
    assert_eq!(next.version, current.version + 1);
    Call {
        to: NATIVE_MULTISIG_ADDRESS.into(),
        value: Default::default(),
        input: INativeMultisig::updateConfigCall {
            current: current.clone().into(),
            threshold: next.threshold,
            owners: next.owners.iter().cloned().map(Into::into).collect(),
        }
        .abi_encode()
        .into(),
    }
}

enum SponsorshipOrder {
    OwnersFirst,
    FeePayerFirst,
}

struct MultisigAuthorization {
    account: Address,
    config: MultisigConfig,
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
    let account_balance_before = ITIP20::new(DEFAULT_FEE_TOKEN, env.provider())
        .balanceOf(authorization.account)
        .call()
        .await?;
    assert_eq!(account_balance_before, U256::ZERO);
    let owner_signature = match order {
        SponsorshipOrder::OwnersFirst => {
            tx.fee_token = None;
            tx.fee_payer_signature = Some(FEE_PAYER_SIGNATURE_MARKER);
            let signature = sign_multisig(
                authorization.account,
                tx.signature_hash(),
                &authorization.config,
                owners,
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
                &authorization.config,
                owners,
            )?
        }
    };
    let receipt = submit(env, tx, owner_signature).await?;
    assert_eq!(
        ITIP20::new(DEFAULT_FEE_TOKEN, env.provider())
            .balanceOf(authorization.account)
            .call()
            .await?,
        account_balance_before
    );
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

async fn initial_weighted_quorum<E: TestEnv>(
    env: &mut E,
    salt: u8,
    alice: &PrivateKeySigner,
    bob: &PrivateKeySigner,
    carol: &PrivateKeySigner,
    approvals: &[&PrivateKeySigner],
    rejection_reason: Option<&str>,
) -> eyre::Result<()> {
    let mut fixture =
        MultisigAccountFixture::funded(env, salt, 3, &[(alice, 2), (bob, 1), (carol, 1)]).await?;
    let tx = fixture.no_op_transaction(env, salt);
    let signature = fixture.sign_with_owners(&tx, approvals)?;
    if let Some(reason) = rejection_reason {
        reject(env, tx, signature, reason).await?;
        fixture.assert_no_stored_config(env).await?;
    } else {
        fixture.submit_signed(env, tx, signature).await?;
    }
    Ok(())
}

async fn repeated_initial_authorization<E: TestEnv>(
    env: &mut E,
    alice: &PrivateKeySigner,
    bob: &PrivateKeySigner,
) -> eyre::Result<()> {
    let mut fixture = MultisigAccountFixture::funded(env, 0x11, 2, &[(alice, 1), (bob, 1)]).await?;

    fixture.submit_no_op(env, 0x11).await?;
    fixture.assert_no_stored_config(env).await?;

    fixture.submit_no_op(env, 0x12).await?;
    fixture.assert_no_stored_config(env).await?;
    Ok(())
}

async fn reserved_accounts_are_rejected<E: TestEnv>(
    env: &E,
    alice: &PrivateKeySigner,
    bob: &PrivateKeySigner,
) -> eyre::Result<()> {
    let mut config = multisig_config(0x12, 2, &[(alice, 1), (bob, 1)]);
    config.version = 1;

    let mut tip20 = [0u8; 20];
    tip20[..12].copy_from_slice(&Address::TIP20_PREFIX);
    tip20[19] = 1;
    let mut zone_portal = [0u8; 20];
    zone_portal[..12].copy_from_slice(&Address::ZONE_PORTAL_PREFIX);
    zone_portal[19] = 1;
    let mut virtual_account = [0u8; 20];
    virtual_account[4..14].fill(0xfd);

    for account in [
        Address::from(tip20),
        Address::from(zone_portal),
        Address::from(virtual_account),
        Address::with_last_byte(1),
        NATIVE_MULTISIG_ADDRESS,
    ] {
        let tx = create_basic_aa_tx(env.chain_id(), 0, vec![no_op_call(0x12)], EXAMPLE_GAS_LIMIT);
        let signature = sign_multisig(account, tx.signature_hash(), &config, &[alice, bob])?;
        let expected_reason = format!("invalid multisig account {account}");
        reject(env, tx, signature, &expected_reason).await?;
    }
    Ok(())
}

async fn nested_ownership<E: TestEnv>(
    env: &mut E,
    alice: &PrivateKeySigner,
    bob: &PrivateKeySigner,
) -> eyre::Result<()> {
    let mut child_fixture =
        MultisigAccountFixture::funded(env, 0x21, 2, &[(alice, 1), (bob, 1)]).await?;
    let child = child_fixture.account;

    child_fixture.submit_no_op(env, 0x21).await?;

    let child_initial_config = child_fixture.config.clone();
    let mut child_current = child_initial_config.clone();
    child_current.version = 1;
    let child_rotation = child_fixture.transaction_with_calls(
        env,
        vec![update_config_call(&child_initial_config, &child_current)],
    );
    let signature = child_fixture.sign(&child_rotation)?;
    child_fixture
        .submit_signed(env, child_rotation, signature)
        .await?;
    child_fixture.config = child_current;

    let parent_config = MultisigConfig {
        salt: B256::repeat_byte(0x22),
        version: 0,
        threshold: 1,
        owners: vec![MultisigOwner {
            owner: child,
            weight: 1,
        }],
    };
    let parent = derived_account(&parent_config)?;
    env.fund_account(parent).await?;

    let parent_initial =
        create_basic_aa_tx(env.chain_id(), 0, vec![no_op_call(0x22)], EXAMPLE_GAS_LIMIT);
    let signature = sign_nested_multisig(
        parent,
        parent_initial.signature_hash(),
        &parent_config,
        child,
        &child_fixture.config,
        &[alice, bob],
    )?;
    submit(env, parent_initial, signature).await?;

    let repeated = create_basic_aa_tx(env.chain_id(), 1, vec![no_op_call(0x23)], EXAMPLE_GAS_LIMIT);
    let stale_signature = sign_nested_multisig(
        parent,
        repeated.signature_hash(),
        &parent_config,
        child,
        &child_initial_config,
        &[alice, bob],
    )?;
    reject(
        env,
        repeated.clone(),
        stale_signature,
        CONFIG_COMMITMENT_MISMATCH,
    )
    .await?;
    assert_eq!(stored_config_commitment(env, parent).await?, B256::ZERO);
    assert_eq!(
        stored_config_commitment(env, child).await?,
        child_fixture
            .config
            .commitment()
            .map_err(|error| eyre::eyre!(error.as_str()))?
    );
    let signature = sign_nested_multisig(
        parent,
        repeated.signature_hash(),
        &parent_config,
        child,
        &child_fixture.config,
        &[alice, bob],
    )?;
    submit(env, repeated, signature).await?;

    let access_key = signer(0x24);
    let authorization = KeyAuthorization::unrestricted(
        env.chain_id(),
        SignatureType::Secp256k1,
        access_key.address(),
    )
    .with_account(parent);
    let authorization_signature = sign_nested_multisig(
        parent,
        authorization.signature_hash(),
        &parent_config,
        child,
        &child_fixture.config,
        &[alice, bob],
    )?;
    let mut authorize =
        create_basic_aa_tx(env.chain_id(), 2, vec![no_op_call(0x24)], EXAMPLE_GAS_LIMIT);
    authorize.key_authorization = Some(authorization.into_signed(authorization_signature));
    let signature = sign_nested_multisig(
        parent,
        authorize.signature_hash(),
        &parent_config,
        child,
        &child_fixture.config,
        &[alice, bob],
    )?;
    submit(env, authorize, signature).await?;
    assert_active_key(env, parent, access_key.address()).await?;

    let access_key_tx =
        create_basic_aa_tx(env.chain_id(), 3, vec![no_op_call(0x25)], EXAMPLE_GAS_LIMIT);
    let signature = sign_aa_tx_with_secp256k1_access_key(&access_key_tx, &access_key, parent)?;
    submit(env, access_key_tx, signature).await?;
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
    submit_sponsored(
        env,
        create_basic_aa_tx(chain_id, 0, vec![no_op_call(0x31)], EXAMPLE_GAS_LIMIT),
        MultisigAuthorization { account, config },
        &[alice, bob],
        &fee_payer,
        SponsorshipOrder::OwnersFirst,
    )
    .await?;

    let config = multisig_config(0x32, 2, &[(alice, 1), (bob, 1)]);
    let account = derived_account(&config)?;
    submit_sponsored(
        env,
        create_basic_aa_tx(chain_id, 0, vec![no_op_call(0x32)], EXAMPLE_GAS_LIMIT),
        MultisigAuthorization { account, config },
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
    let cases: &[(u8, &[&PrivateKeySigner], Option<&str>)] = &[
        (0x41, &[alice, bob], None),
        (0x42, &[alice, carol], None),
        (
            0x43,
            &[bob, carol],
            Some("multisig signature weight below threshold"),
        ),
        (
            0x44,
            &[alice, bob, carol],
            Some("excess multisig owner signatures"),
        ),
    ];
    for &(salt, approvals, rejection_reason) in cases {
        initial_weighted_quorum(env, salt, alice, bob, carol, approvals, rejection_reason).await?;
    }
    Ok(())
}

async fn initial_and_immediate_access_key_use<E: TestEnv>(
    env: &mut E,
    alice: &PrivateKeySigner,
    bob: &PrivateKeySigner,
) -> eyre::Result<()> {
    let mut fixture = MultisigAccountFixture::funded(env, 0x51, 2, &[(alice, 1), (bob, 1)]).await?;
    let access_key = signer(0x51);

    let mut tx = fixture.no_op_transaction(env, 0x51);
    tx.key_authorization =
        Some(fixture.signed_key_authorization(env.chain_id(), access_key.address(), false)?);
    let signature = sign_aa_tx_with_secp256k1_access_key(&tx, &access_key, fixture.account)?;
    fixture.submit_signed(env, tx, signature).await?;

    fixture.assert_no_stored_config(env).await?;
    assert_active_key(env, fixture.account, access_key.address()).await?;
    Ok(())
}

async fn access_key_authorization_matrix<E: TestEnv>(
    env: &mut E,
    alice: &PrivateKeySigner,
    bob: &PrivateKeySigner,
) -> eyre::Result<()> {
    let mut fixture = MultisigAccountFixture::funded(env, 0x61, 2, &[(alice, 1), (bob, 1)]).await?;
    let access_key = signer(0x61);

    let mut initial = fixture.no_op_transaction(env, 0x61);
    initial.key_authorization =
        Some(fixture.signed_key_authorization(env.chain_id(), access_key.address(), false)?);
    let signature = fixture.sign(&initial)?;
    fixture.submit_signed(env, initial, signature).await?;
    assert_active_key(env, fixture.account, access_key.address()).await?;

    let access_key_tx = fixture.no_op_transaction(env, 0x62);
    let signature =
        sign_aa_tx_with_secp256k1_access_key(&access_key_tx, &access_key, fixture.account)?;
    fixture.submit_signed(env, access_key_tx, signature).await?;

    struct Case<'a> {
        outer: &'a PrivateKeySigner,
        authorizer: KeyAuthorizationSigner<'a>,
        target: &'a PrivateKeySigner,
        is_admin: bool,
        expected: ExpectedOutcome,
    }

    let admin_key = signer(0x62);
    let child_key = signer(0x63);
    let quorum = [alice, bob];
    let cases = [
        Case {
            outer: &access_key,
            authorizer: KeyAuthorizationSigner::Primitive(&access_key),
            target: &child_key,
            is_admin: false,
            expected: ExpectedOutcome::Rejection,
        },
        Case {
            outer: &access_key,
            authorizer: KeyAuthorizationSigner::Quorum(&quorum),
            target: &admin_key,
            is_admin: true,
            expected: ExpectedOutcome::Success,
        },
        Case {
            outer: &admin_key,
            authorizer: KeyAuthorizationSigner::Primitive(&admin_key),
            target: &child_key,
            is_admin: false,
            expected: ExpectedOutcome::Success,
        },
    ];
    for (index, case) in cases.into_iter().enumerate() {
        let key_authorization = signed_key_authorization(
            env.chain_id(),
            fixture.account,
            &fixture.config,
            case.target.address(),
            case.is_admin,
            case.authorizer,
        )?;
        let mut tx = fixture.no_op_transaction(env, 0x63 + index as u8);
        tx.key_authorization = Some(key_authorization);
        let signature = sign_aa_tx_with_secp256k1_access_key(&tx, case.outer, fixture.account)?;

        match case.expected {
            ExpectedOutcome::Success => {
                fixture.submit_signed(env, tx, signature).await?;
                assert_active_key(env, fixture.account, case.target.address()).await?;
                if case.is_admin {
                    assert_admin_key(env, fixture.account, case.target.address()).await?;
                }
            }
            ExpectedOutcome::Rejection => {
                reject(
                    env,
                    tx,
                    signature,
                    "access keys cannot authorize other keys, only the root key can authorize new keys",
                )
                .await?;
                fixture.assert_no_stored_config(env).await?;
                assert_inactive_key(env, fixture.account, case.target.address()).await?;
            }
            ExpectedOutcome::Revert => unreachable!("key authorization is validated pre-call"),
        }
    }

    let mut next_config = fixture.config.clone();
    next_config.version = 1;
    let update = fixture
        .transaction_with_calls(env, vec![update_config_call(&fixture.config, &next_config)]);
    let signature = sign_aa_tx_with_secp256k1_access_key(&update, &admin_key, fixture.account)?;
    revert(env, update, signature).await?;
    fixture.assert_no_stored_config(env).await?;
    Ok(())
}

async fn configuration_rotation_and_access_keys<E: TestEnv>(
    env: &mut E,
    alice: &PrivateKeySigner,
    bob: &PrivateKeySigner,
    carol: &PrivateKeySigner,
) -> eyre::Result<()> {
    let mut fixture = MultisigAccountFixture::funded(env, 0x71, 2, &[(alice, 1), (bob, 1)]).await?;
    let account = fixture.account;
    let initial_config = fixture.config.clone();

    let next_config = MultisigConfig {
        salt: initial_config.salt,
        version: 1,
        threshold: 1,
        owners: vec![MultisigOwner {
            owner: carol.address(),
            weight: 1,
        }],
    };
    let rotation = fixture
        .transaction_with_calls(env, vec![update_config_call(&initial_config, &next_config)]);
    let signature = fixture.sign(&rotation)?;
    fixture.submit_signed(env, rotation, signature).await?;
    fixture.config = next_config;
    fixture.owners = vec![carol];

    assert_eq!(
        stored_config_commitment(env, account).await?,
        fixture
            .config
            .commitment()
            .map_err(|error| eyre::eyre!(error.as_str()))?
    );

    let stale_tx = fixture.no_op_transaction(env, 0x72);
    let stale_signature = sign_multisig(
        account,
        stale_tx.signature_hash(),
        &initial_config,
        &[alice, bob],
    )?;
    reject(env, stale_tx, stale_signature, CONFIG_COMMITMENT_MISMATCH).await?;
    let current_commitment = fixture
        .config
        .commitment()
        .map_err(|error| eyre::eyre!(error.as_str()))?;
    assert_eq!(
        stored_config_commitment(env, account).await?,
        current_commitment
    );

    let access_key = signer(0x72);
    let stale_authorization = signed_key_authorization(
        env.chain_id(),
        account,
        &initial_config,
        access_key.address(),
        false,
        KeyAuthorizationSigner::Quorum(&[alice, bob]),
    )?;
    let mut stale_sidecar = fixture.no_op_transaction(env, 0x73);
    stale_sidecar.key_authorization = Some(stale_authorization);
    let signature = fixture.sign(&stale_sidecar)?;
    reject(env, stale_sidecar, signature, CONFIG_COMMITMENT_MISMATCH).await?;
    assert_eq!(
        stored_config_commitment(env, account).await?,
        current_commitment
    );
    assert_inactive_key(env, account, access_key.address()).await?;

    let current_authorization =
        fixture.signed_key_authorization(env.chain_id(), access_key.address(), false)?;
    let mut current = fixture.no_op_transaction(env, 0x74);
    current.key_authorization = Some(current_authorization);
    let signature = fixture.sign(&current)?;
    fixture.submit_signed(env, current, signature).await?;
    assert_active_key(env, account, access_key.address()).await?;

    let access_key_tx = fixture.no_op_transaction(env, 0x75);
    let signature = sign_aa_tx_with_secp256k1_access_key(&access_key_tx, &access_key, account)?;
    fixture.submit_signed(env, access_key_tx, signature).await?;

    let source_fixture =
        MultisigAccountFixture::funded(env, 0x73, 2, &[(alice, 1), (bob, 1)]).await?;
    let forbidden_authorization =
        source_fixture.signed_key_authorization(env.chain_id(), account, false)?;
    let mut forbidden = source_fixture.no_op_transaction(env, 0x76);
    forbidden.key_authorization = Some(forbidden_authorization);
    let signature = source_fixture.sign(&forbidden)?;
    reject(
        env,
        forbidden,
        signature,
        &format!("native multisig account {account} cannot be used as an access key"),
    )
    .await?;
    source_fixture.assert_no_stored_config(env).await?;
    assert_inactive_key(env, source_fixture.account, account).await?;
    Ok(())
}

pub(super) async fn run_tip_1061_examples<E: TestEnv>(env: &mut E) -> eyre::Result<()> {
    let signers = sorted_signers();
    let (alice, bob, carol) = (&signers[0], &signers[1], &signers[2]);

    repeated_initial_authorization(env, alice, bob).await?;
    reserved_accounts_are_rejected(env, alice, bob).await?;
    nested_ownership(env, alice, bob).await?;
    fee_sponsorship(env, alice, bob).await?;
    weighted_quorum(env, alice, bob, carol).await?;
    initial_and_immediate_access_key_use(env, alice, bob).await?;
    access_key_authorization_matrix(env, alice, bob).await?;
    configuration_rotation_and_access_keys(env, alice, bob, carol).await?;
    Ok(())
}
