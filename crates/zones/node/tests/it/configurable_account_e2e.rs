//! Configurable accounts across a real Tempo L1 and a zone: Tempo owns every configuration change,
//! and the zone applies it once its anchor includes the Tempo block (TIP-1154).

use std::time::Duration;

use alloy::{
    primitives::{Address, B256, Bytes, U256, keccak256},
    sol_types::{SolCall, SolError, SolStruct, sol},
};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use eyre::OptionExt;
use reqwest::StatusCode;
use tempo_alloy::{TempoNetwork, provider::keychain::revoke_key};
use tempo_chainspec::spec::{TEMPO_T0_BASE_FEE, TEMPO_T1_BASE_FEE};
use tempo_contracts::{
    precompiles::{
        AccountKeychainError, IAccountKeychain, ISignatureVerifier, ITIP20,
        SIGNATURE_VERIFIER_ADDRESS,
    },
    zones::{IZoneOutbox, ZONE_OUTBOX_ADDRESS, ZONE_TOKEN_ADDRESS},
};
use tempo_evm::{
    TempoInvalidTransaction,
    transaction_error::{ConfigurableAccountError, RootKeyRole},
};
use tempo_precompiles::{PATH_USD_ADDRESS, error::TempoPrecompileError};
use tempo_primitives::{
    SignatureType,
    transaction::{Call, KeyAuthorization, TempoSignature, TempoTransaction},
};
use test_case::test_case;
use zone_node::rpc::auth::build_token_fields;

use crate::{
    configurable_account::{
        Account, Authority, Chain, Change, ORIGINAL_OWNERS, ROOT_KEY, ZONE_FUNDING, approve_outbox,
    },
    utils::{
        DEFAULT_POLL, RedactedRpcL1TestCtx, WITHDRAWAL_TX_GAS, ZoneAccount,
        build_token_with_signature, now_secs, poll_until, signer_at, spawn_sequencer,
        start_zone_with_redacted_rpc_l1,
    },
};

const L1_TIMEOUT: Duration = Duration::from_secs(30);
/// pathUSD each account holds on Tempo for its own fees.
const TEMPO_FUNDING: u128 = 100_000_000;
/// Test key index of the EOA whose access key the old authority is, and whose fees it sponsors.
const BYSTANDER_KEY: u32 = 140;
/// Test key index of the access key the old authority grants before the change.
const KEPT_KEY: u32 = 150;
/// Test key index of the access key granted by the transactions that wait in the pool.
const PENDING_KEY: u32 = 151;
/// Test key index of the access key granted after the change.
const FRESH_KEY: u32 = 152;
/// Every role a primitive key fills.
const KEY_ROLES: [RootKeyRole; 4] = [
    RootKeyRole::Sender,
    RootKeyRole::FeePayer,
    RootKeyRole::AccessKey,
    RootKeyRole::KeyAuthorizationSigner,
];
/// The roles an owner quorum fills: every one but the fee payer, which signs with a primitive key.
const OWNER_ROLES: [RootKeyRole; 3] = [
    RootKeyRole::Sender,
    RootKeyRole::AccessKey,
    RootKeyRole::KeyAuthorizationSigner,
];
/// The hash the signature verifier checks owner quorums of.
const MESSAGE: B256 = B256::repeat_byte(0x99);
const AUTH_TOKEN_LIFETIME_SECS: u64 = 600;

sol! {
    /// The EIP-2612 permit that TIP-20 `permit` verifies.
    struct Permit {
        address owner;
        address spender;
        uint256 value;
        uint256 nonce;
        uint256 deadline;
    }
}

/// A Tempo L1 dev node and a zone that follows it behind its private RPC.
struct Env {
    rpc: RedactedRpcL1TestCtx,
    tempo: Chain,
    zone_chain: Chain,
}

impl Env {
    async fn start() -> eyre::Result<Self> {
        reth_tracing::init_test_tracing();
        let rpc = start_zone_with_redacted_rpc_l1().await?;
        let tempo = Chain::connect(
            ProviderBuilder::new_with_network::<TempoNetwork>()
                .connect_http(rpc.l1().http_url().clone())
                .erased(),
            TEMPO_T1_BASE_FEE,
        )
        .await?;
        let zone_chain = Chain::connect(rpc.zone.provider(), TEMPO_T0_BASE_FEE).await?;
        Ok(Self {
            rpc,
            tempo,
            zone_chain,
        })
    }

    /// Deposits pathUSD to `account` on the zone from the L1 user account.
    async fn fund_on_zone(&self, account: Address) -> eyre::Result<()> {
        let l1 = self.rpc.l1();
        let mut depositor =
            ZoneAccount::from_l1_and_zone(l1, &self.rpc.zone, self.rpc.portal_address());
        l1.fund_user(depositor.address(), ZONE_FUNDING).await?;
        depositor
            .deposit_to(account, ZONE_FUNDING, L1_TIMEOUT, &self.rpc.zone)
            .await?;
        Ok(())
    }

    /// Whether the private RPC authenticates a token that `authority` signed: `true` for a call it
    /// serves and `false` for one it forbids.
    async fn authenticates(&self, authority: Authority<'_>) -> eyre::Result<bool> {
        let now = now_secs();
        let (fields, digest) = build_token_fields(
            self.rpc.config.zone_id,
            self.rpc.config.chain_id,
            now,
            now + AUTH_TOKEN_LIFETIME_SECS,
        );
        let signature = TempoSignature::from(authority.approve(digest)?);
        let token = build_token_with_signature(signature, &fields);
        let (status, body) = self
            .rpc
            .call_raw(
                "eth_blockNumber",
                serde_json::Value::Array(Vec::new()),
                &token,
            )
            .await?;
        if status == StatusCode::FORBIDDEN {
            return Ok(false);
        }
        eyre::ensure!(
            status == StatusCode::OK && body.contains("\"result\""),
            "unexpected private RPC response {status}: {body}"
        );
        Ok(true)
    }

    /// Whether the zone's signature verifier accepts a quorum of `owners` for their account.
    async fn verifies(&self, owners: &Account) -> eyre::Result<bool> {
        let signature = TempoSignature::ConfigurableAccount(owners.quorum(MESSAGE)?);
        Ok(
            ISignatureVerifier::new(SIGNATURE_VERIFIER_ADDRESS, &self.zone_chain.provider)
                .verifyConfigurableAccount(owners.address, MESSAGE, signature.to_bytes())
                .call()
                .await?,
        )
    }

    /// Calls the zone's pathUSD `permit` with a first permit that `owner` signs for the outbox.
    async fn permit(&self, owner: &PrivateKeySigner) -> eyre::Result<()> {
        let token = ITIP20::new(PATH_USD_ADDRESS, &self.zone_chain.provider);
        let domain_separator = token.DOMAIN_SEPARATOR().call().await?;
        let struct_hash = Permit {
            owner: owner.address(),
            spender: ZONE_OUTBOX_ADDRESS,
            value: U256::MAX,
            nonce: U256::ZERO,
            deadline: U256::MAX,
        }
        .eip712_hash_struct();
        let digest = keccak256(
            [
                [0x19, 0x01].as_slice(),
                domain_separator.as_slice(),
                struct_hash.as_slice(),
            ]
            .concat(),
        );
        let signature = owner.sign_hash_sync(&digest)?;
        token
            .permit(
                owner.address(),
                ZONE_OUTBOX_ADDRESS,
                U256::MAX,
                U256::MAX,
                signature.v_byte(),
                signature.r().into(),
                signature.s().into(),
            )
            .call()
            .await?;
        Ok(())
    }
}

/// A transaction of `account` on `chain` in which `authority` fills `role`, at its sender's next
/// nonce plus `gap`. As an access key the authority signs for `bystander`, whose stored grant names
/// it; as the fee payer it sponsors `bystander`; as the key authorization signer it grants `key` to
/// `account`, and `key` signs.
async fn role_transaction(
    chain: &Chain,
    role: RootKeyRole,
    account: Address,
    authority: Authority<'_>,
    bystander: &PrivateKeySigner,
    key: &PrivateKeySigner,
    gap: u64,
) -> eyre::Result<(TempoTransaction, TempoSignature)> {
    Ok(match role {
        RootKeyRole::Sender => {
            let tx = chain
                .transaction(account, gap, vec![approve_outbox()])
                .await?;
            let signature = authority.sign(&tx)?;
            (tx, signature)
        }
        RootKeyRole::FeePayer => {
            let Authority::Key(sponsor) = authority else {
                eyre::bail!("owner quorums do not sponsor fees");
            };
            let mut tx = chain
                .transaction(bystander.address(), gap, vec![approve_outbox()])
                .await?;
            let sponsorship = tx.fee_payer_signature_hash(bystander.address());
            tx.fee_payer_signature = Some(sponsor.sign_hash_sync(&sponsorship)?);
            let signature = Authority::Key(bystander).sign(&tx)?;
            (tx, signature)
        }
        RootKeyRole::AccessKey => {
            let tx = chain
                .transaction(bystander.address(), gap, vec![approve_outbox()])
                .await?;
            let signature = authority.sign_as_key(&tx, bystander.address())?;
            (tx, signature)
        }
        RootKeyRole::KeyAuthorizationSigner => {
            let mut tx = chain
                .transaction(account, gap, vec![approve_outbox()])
                .await?;
            let grant = KeyAuthorization::unrestricted(
                chain.chain_id,
                SignatureType::Secp256k1,
                key.address(),
            )
            .with_account(account);
            let approval = authority.approve(grant.signature_hash())?;
            tx.key_authorization = Some(grant.into_signed(approval));
            let signature = Authority::Key(key).sign_as_key(&tx, account)?;
            (tx, signature)
        }
    })
}

/// A Tempo change reaches the zone once its anchor includes it.
///
/// Before the change the old authority sends, grants an access key, authenticates to the private
/// RPC and passes the zone's signature precompiles, and a transaction in which it fills each role
/// the change retires it from waits in the pool. After it the zone reports Tempo's commitment,
/// evicts those transactions, refuses the old authority in each of those roles with the exact
/// error, and so do the private RPC and the precompiles. The new owners then act as the bystander's
/// access key (for a migration, through the grant of the retired root key), grant a key, revoke the
/// key granted before the change, which then stops working, and withdraw to Tempo. A registration
/// retires nothing.
#[test_case(Change::Registration ; "registration")]
#[test_case(Change::OwnerRotation ; "owner rotation")]
#[test_case(Change::ThresholdRaise ; "threshold raise")]
#[test_case(Change::Migration ; "migration")]
#[tokio::test(flavor = "multi_thread")]
async fn test_tempo_change_reaches_the_zone(change: Change) -> eyre::Result<()> {
    let env = Env::start().await?;
    let l1 = env.rpc.l1();
    let zone = &env.rpc.zone;
    let portal = env.rpc.portal_address();
    let root = signer_at(ROOT_KEY);
    let original = Account::new(ORIGINAL_OWNERS, 2, 1);
    let bystander = signer_at(BYSTANDER_KEY);
    let [kept, pending_key, fresh] = [KEPT_KEY, PENDING_KEY, FRESH_KEY].map(signer_at);
    let old = change.authority(&root, &original);
    let (changed, call) = change.apply(&root, &original);
    let new = Authority::Owners(&changed);
    let account = changed.address;
    // The roles the change retires the old authority from, each with the zone's refusal.
    let retired: Vec<(RootKeyRole, TempoInvalidTransaction)> = match old {
        Authority::Key(key) => KEY_ROLES
            .into_iter()
            .map(|role| {
                let account = key.address();
                (
                    role,
                    TempoInvalidTransaction::RootKeyRetired { account, role },
                )
            })
            .collect(),
        Authority::Owners(_) if matches!(change, Change::Registration) => Vec::new(),
        Authority::Owners(original) => OWNER_ROLES
            .into_iter()
            .map(|role| {
                let mismatch = ConfigurableAccountError::ConfigurationCommitmentMismatch {
                    expected: changed.commitment(),
                    actual: original.commitment(),
                };
                (role, TempoInvalidTransaction::ConfigurableAccount(mismatch))
            })
            .collect(),
    };

    l1.fund_user(account, TEMPO_FUNDING).await?;
    env.fund_on_zone(account).await?;
    env.fund_on_zone(bystander.address()).await?;
    // The test zone is closed, so the portal must admit the account's withdrawal.
    let allowed = l1
        .set_allowed_account_on_portal(portal, account, true)
        .await?;
    zone.wait_for_tempo_block_number(allowed, L1_TIMEOUT)
        .await?;

    assert_eq!(env.zone_chain.commitment(account).await?, B256::ZERO);
    let tx = env
        .zone_chain
        .transaction(account, 0, vec![approve_outbox()])
        .await?;
    let signature = old.sign(&tx)?;
    env.zone_chain.execute(tx, signature).await?;
    // The bystander grants the old authority as its access key.
    let key_type = match old {
        Authority::Key(_) => SignatureType::Secp256k1,
        Authority::Owners(_) => SignatureType::ConfigurableAccount,
    };
    let grant = KeyAuthorization::unrestricted(env.zone_chain.chain_id, key_type, account);
    let approval = Authority::Key(&bystander).approve(grant.signature_hash())?;
    let mut tx = env
        .zone_chain
        .transaction(bystander.address(), 0, vec![approve_outbox()])
        .await?;
    tx.key_authorization = Some(grant.into_signed(approval));
    let signature = Authority::Key(&bystander).sign(&tx)?;
    env.zone_chain.execute(tx, signature).await?;
    let (tx, signature) = role_transaction(
        &env.zone_chain,
        RootKeyRole::KeyAuthorizationSigner,
        account,
        old,
        &bystander,
        &kept,
        0,
    )
    .await?;
    env.zone_chain.execute(tx, signature).await?;
    assert!(env.authenticates(old).await?);
    match old {
        Authority::Key(key) => env.permit(key).await?,
        Authority::Owners(owners) => assert!(env.verifies(owners).await?),
    }
    // Each waits behind a nonce gap of its own.
    let mut pending = Vec::new();
    for (gap, (role, _)) in (1..).zip(&retired) {
        let (tx, signature) = role_transaction(
            &env.zone_chain,
            *role,
            account,
            old,
            &bystander,
            &pending_key,
            gap,
        )
        .await?;
        let hash = *env.zone_chain.send(tx, signature).await?.tx_hash();
        eyre::ensure!(
            env.zone_chain
                .provider
                .get_transaction_by_hash(hash)
                .await?
                .is_some(),
            "{role:?}: the gapped transaction should wait in the pool"
        );
        pending.push(hash);
    }

    let tx = env.tempo.transaction(account, 0, vec![call]).await?;
    let signature = old.sign(&tx)?;
    let block = env.tempo.execute(tx, signature).await?;
    zone.wait_for_tempo_block_number(block, L1_TIMEOUT).await?;

    assert_eq!(env.tempo.commitment(account).await?, changed.commitment());
    assert_eq!(
        env.zone_chain.commitment(account).await?,
        changed.commitment()
    );
    // A transaction found by hash is either pooled or mined.
    poll_until(
        L1_TIMEOUT,
        DEFAULT_POLL,
        "the retired authority's transactions leave the pool",
        || async {
            for hash in &pending {
                if env
                    .zone_chain
                    .provider
                    .get_transaction_by_hash(*hash)
                    .await?
                    .is_some()
                {
                    return Ok(None);
                }
            }
            Ok(Some(()))
        },
    )
    .await?;
    for (role, refusal) in &retired {
        let (tx, signature) =
            role_transaction(&env.zone_chain, *role, account, old, &bystander, &fresh, 0).await?;
        env.zone_chain.reject(tx, signature, refusal).await?;
    }
    assert_eq!(env.authenticates(old).await?, retired.is_empty());
    match old {
        Authority::Key(key) => {
            let error = env
                .permit(key)
                .await
                .expect_err("a retired root key must not sign a permit");
            let revert = error
                .downcast_ref::<alloy_contract::Error>()
                .and_then(alloy_contract::Error::as_revert_data)
                .ok_or_eyre("the permit did not revert")?;
            assert_eq!(revert, ITIP20::RootKeyRetired { account }.abi_encode());
        }
        Authority::Owners(owners) => {
            assert_eq!(env.verifies(owners).await?, retired.is_empty());
        }
    }

    assert!(env.authenticates(new).await?);
    assert!(env.verifies(&changed).await?);
    for role in [RootKeyRole::AccessKey, RootKeyRole::KeyAuthorizationSigner] {
        let (tx, signature) =
            role_transaction(&env.zone_chain, role, account, new, &bystander, &fresh, 0).await?;
        env.zone_chain.execute(tx, signature).await?;
    }
    // Grants live in zone state, so the key granted before the change works until the new owners
    // revoke it.
    let tx = env
        .zone_chain
        .transaction(account, 0, vec![approve_outbox()])
        .await?;
    let signature = Authority::Key(&kept).sign_as_key(&tx, account)?;
    env.zone_chain.execute(tx, signature).await?;
    let tx = env
        .zone_chain
        .transaction(account, 0, vec![revoke_key(kept.address())])
        .await?;
    let signature = new.sign(&tx)?;
    env.zone_chain.execute(tx, signature).await?;
    let tx = env
        .zone_chain
        .transaction(account, 0, vec![approve_outbox()])
        .await?;
    let signature = Authority::Key(&kept).sign_as_key(&tx, account)?;
    let revoked = TempoPrecompileError::from(AccountKeychainError::KeyAlreadyRevoked(
        IAccountKeychain::KeyAlreadyRevoked {},
    ));
    env.zone_chain
        .reject(
            tx,
            signature,
            TempoInvalidTransaction::KeychainValidationFailed {
                reason: format!("{revoked:?}"),
            },
        )
        .await?;

    let _sequencer = spawn_sequencer(l1, zone, portal, l1.dev_signer()).await;
    let amount = ZONE_FUNDING / 2;
    let balance_before = l1.balance_of(PATH_USD_ADDRESS, account).await?;
    let withdraw = Call {
        to: ZONE_OUTBOX_ADDRESS.into(),
        value: U256::ZERO,
        input: IZoneOutbox::requestWithdrawalCall {
            token: ZONE_TOKEN_ADDRESS,
            to: account,
            amount,
            memo: B256::ZERO,
            gasLimit: 0,
            zoneFallbackRecipient: account,
            data: Bytes::new(),
            revealTo: Bytes::new(),
        }
        .abi_encode()
        .into(),
    };
    let mut tx = env
        .zone_chain
        .transaction(account, 0, vec![withdraw])
        .await?;
    tx.gas_limit = WITHDRAWAL_TX_GAS;
    let signature = new.sign(&tx)?;
    env.zone_chain.execute(tx, signature).await?;
    l1.wait_for_withdrawal_on_l1(
        portal,
        account,
        balance_before,
        amount,
        Duration::from_secs(60),
    )
    .await?;
    Ok(())
}
