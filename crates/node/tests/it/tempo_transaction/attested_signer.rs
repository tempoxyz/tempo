//! Attested signers (signature type `0x06`) through a local node: a registered program key
//! authorizes an access key for an attested address, `revokeKeys` ends that authority, and a
//! registration into an occupied slot ends the key it held.

use super::{
    helpers::{
        create_basic_aa_tx, generate_p256_access_key, sign_aa_tx_secp256k1,
        sign_aa_tx_with_p256_access_key, sign_p256_primitive,
    },
    local::Localnet,
    types::TestEnv,
};
use crate::utils::TestNodeBuilder;
use alloy::{
    primitives::{Address, B256, B512, Bytes, U256, keccak256},
    providers::Provider,
    sol_types::{SolCall, SolValue},
};
use alloy_eips::Encodable2718;
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use reth_e2e_test_utils::wallet::test_signer;
use reth_primitives_traits::transaction::TxHashRef;
use std::time::{SystemTime, UNIX_EPOCH};
use tempo_contracts::precompiles::{ATTESTED_KEY_REGISTRY_ADDRESS, IAttestedKeyRegistry};
use tempo_nitro_attestation::testing::{DEV_PCRS, DevAttestation};
use tempo_primitives::{
    SignatureType, TempoTxEnvelope,
    transaction::{
        AttestedSignature, Call, ConfigurableAccountConfig, ConfigurableAccountOwner,
        ConfigurableAccountSignature, KeyAuthorization, OwnerApproval, SignedKeyAuthorization,
        TempoSignature, configurable_account_digest,
    },
};

const GAS_LIMIT: u64 = 3_000_000;
const SCHEME_NITRO_DEV: u8 = 0xFE;
/// `maxKeyLifetime` of the test policy.
const MAX_KEY_LIFETIME: u64 = 3_600;

/// A program key of the dev signer, the policy it registers under, and its slot.
struct Signer {
    key: SigningKey,
    policy_id: B256,
    slot: u8,
    user_tag: B256,
}

impl Signer {
    /// A fresh program key for `slot` of `policy_id`.
    fn random(policy_id: B256, slot: u8) -> Self {
        Self {
            key: SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng),
            policy_id,
            slot,
            user_tag: B256::repeat_byte(0x7A),
        }
    }

    fn program_key(&self) -> B512 {
        let point = self.key.verifying_key().to_encoded_point(false);
        B512::from_slice(&point.as_bytes()[1..])
    }

    fn coordinates(&self) -> (B256, B256) {
        let program_key = self.program_key();
        (
            B256::from_slice(&program_key[..32]),
            B256::from_slice(&program_key[32..]),
        )
    }

    fn address(&self) -> Address {
        tempo_primitives::transaction::attested_address(self.policy_id, self.user_tag)
    }

    /// Signs the context digest `d` as an attested signature valid until `valid_until`.
    fn sign(&self, d: B256, valid_until: u64) -> eyre::Result<AttestedSignature> {
        let mut signature = AttestedSignature {
            policy_id: self.policy_id,
            user_tag: self.user_tag,
            slot: self.slot,
            program_key: self.program_key(),
            valid_until,
            signature: B512::ZERO,
        };
        let raw: Signature = self.key.sign_prehash(signature.digest(d).as_slice())?;
        let raw = raw.normalize_s().unwrap_or(raw);
        signature.signature = B512::from_slice(&raw.to_bytes());
        Ok(signature)
    }

    /// Authorizes a fresh P256 access key for the attested address.
    fn authorize(
        &self,
        chain_id: u64,
        valid_until: u64,
    ) -> eyre::Result<(SignedKeyAuthorization, SigningKey, B256, B256)> {
        let (access_key, x, y, key_id) = generate_p256_access_key();
        let authorization = KeyAuthorization::unrestricted(chain_id, SignatureType::P256, key_id);
        let signature = self.sign(authorization.signature_hash(), valid_until)?;
        Ok((authorization.into_signed(signature), access_key, x, y))
    }
}

/// Sends `input` to the registry from the funded owner, asserts success, and returns the gas
/// used.
async fn owner_call(env: &mut Localnet, input: Vec<u8>) -> eyre::Result<u64> {
    // Simulate first, so a revert reports its error instead of a failed receipt.
    let request = alloy::rpc::types::TransactionRequest::default()
        .from(env.funder_addr)
        .to(ATTESTED_KEY_REGISTRY_ADDRESS)
        .input(input.clone().into());
    if let Err(error) = env.provider.call(request).await {
        eyre::bail!("registry call reverts: {error}");
    }
    let nonce = env.provider.get_transaction_count(env.funder_addr).await?;
    let tx = create_basic_aa_tx(
        env.chain_id,
        nonce,
        vec![Call {
            to: ATTESTED_KEY_REGISTRY_ADDRESS.into(),
            value: U256::ZERO,
            input: input.into(),
        }],
        GAS_LIMIT,
    );
    let signature = sign_aa_tx_secp256k1(&tx, &env.funder_signer)?;
    let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
    let hash = *envelope.tx_hash();
    let receipt = env.submit_tx(envelope.encoded_2718(), hash).await?;
    let gas_used = receipt["gasUsed"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("receipt without gasUsed"))?;
    Ok(u64::from_str_radix(gas_used.trim_start_matches("0x"), 16)?)
}

/// Registers `signer`'s program key into its slot with a dev document issued now, for the
/// policy's maximum lifetime. Returns the gas used.
async fn register(env: &mut Localnet, signer: &Signer) -> eyre::Result<u64> {
    let (x, y) = signer.coordinates();
    let binding = keccak256(
        [
            b"tempo:attested-key".as_slice(),
            &U256::from(env.chain_id).to_be_bytes::<32>(),
            ATTESTED_KEY_REGISTRY_ADDRESS.as_slice(),
            signer.policy_id.as_slice(),
            &[signer.slot],
            x.as_slice(),
            y.as_slice(),
        ]
        .concat(),
    );
    let now = env.current_block_timestamp().await?;
    let gas_used = owner_call(
        env,
        IAttestedKeyRegistry::registerKeyCall {
            policyId: signer.policy_id,
            slot: signer.slot,
            document: DevAttestation::new(binding.as_slice(), now * 1_000)
                .build()
                .into(),
            programKeyX: x,
            programKeyY: y,
            lifetime: 0,
        }
        .abi_encode(),
    )
    .await?;
    let registry = IAttestedKeyRegistry::new(ATTESTED_KEY_REGISTRY_ADDRESS, env.provider.clone());
    let valid_until = registry
        .keyValidUntil(signer.policy_id, x, y)
        .call()
        .await?;
    assert!(valid_until > now && valid_until <= now + 1 + MAX_KEY_LIFETIME);
    Ok(gas_used)
}

fn noop_call() -> Call {
    Call {
        to: Address::repeat_byte(0x77).into(),
        value: U256::ZERO,
        input: Bytes::new(),
    }
}

/// Starts a dev node, creates a dev-scheme policy owned by the funder, and registers a fresh
/// program key into its slot 0. Returns the node, the signer, and the program key's coordinates.
async fn registered_signer() -> eyre::Result<(Localnet, Signer, B256, B256)> {
    // The dev root's certificates are valid from 2026-10-31, so blocks follow wall-clock time.
    reth_tracing::init_test_tracing();
    let setup = TestNodeBuilder::new()
        .with_block_timestamps_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
        .build_with_node_access()
        .await?;
    let provider = alloy::providers::RootProvider::new_http(setup.node.rpc_url());
    let funder_signer = test_signer(0);
    let mut env = Localnet {
        chain_id: provider.get_chain_id().await?,
        setup,
        provider,
        funder_addr: funder_signer.address(),
        funder_signer,
    };
    let chain_id = env.chain_id;
    eyre::ensure!(chain_id == 1337, "the dev scheme needs chain 1337");

    let owner = env.funder_addr;
    let salt = B256::repeat_byte(0x5A);
    let policy_id = keccak256((owner, salt).abi_encode());
    owner_call(
        &mut env,
        IAttestedKeyRegistry::createPolicyCall {
            salt,
            scheme: SCHEME_NITRO_DEV,
            owner,
            guardian: Address::ZERO,
            delay: 0,
            maxKeyLifetime: MAX_KEY_LIFETIME,
            measurements: vec![keccak256(DEV_PCRS.concat())],
            anchors: vec![],
        }
        .abi_encode(),
    )
    .await?;

    let signer = Signer::random(policy_id, 0);
    register(&mut env, &signer).await?;
    let (x, y) = signer.coordinates();
    Ok((env, signer, x, y))
}

#[tokio::test(flavor = "multi_thread")]
async fn attested_key_authorization_until_revoked() -> eyre::Result<()> {
    let (mut env, signer, x, y) = registered_signer().await?;
    let (chain_id, policy_id) = (env.chain_id, signer.policy_id);
    let registry = IAttestedKeyRegistry::new(ATTESTED_KEY_REGISTRY_ADDRESS, env.provider.clone());

    let attested = signer.address();
    env.fund_account(attested).await?;

    // A first transaction authorizes an access key with an attested signature and is signed by
    // that access key.
    let now = env.current_block_timestamp().await?;
    let (authorization, access_key, key_x, key_y) = signer.authorize(chain_id, now + 300)?;
    let mut tx = create_basic_aa_tx(chain_id, 0, vec![noop_call()], GAS_LIMIT);
    tx.key_authorization = Some(authorization);
    let signature = sign_aa_tx_with_p256_access_key(&tx, &access_key, &key_x, &key_y, attested)?;
    let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
    let hash = *envelope.tx_hash();
    env.submit_tx(envelope.encoded_2718(), hash).await?;

    // A program key signature over another digest passes decoding, the window, and the
    // registry read, and fails the P256 verification that pool admission runs last.
    let tx = create_basic_aa_tx(chain_id, 1, vec![noop_call()], GAS_LIMIT);
    let forged = TempoSignature::Attested(signer.sign(B256::ZERO, now + 300)?);
    let envelope: TempoTxEnvelope = tx.into_signed(forged).into();
    env.submit_tx_expecting_rejection(
        envelope.encoded_2718(),
        Some("P256 signature verification failed"),
    )
    .await?;

    // The attested signature also signs a transaction directly.
    let tx = create_basic_aa_tx(chain_id, 1, vec![noop_call()], GAS_LIMIT);
    let signature = TempoSignature::Attested(signer.sign(tx.signature_hash(), now + 300)?);
    let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
    let hash = *envelope.tx_hash();
    env.submit_tx(envelope.encoded_2718(), hash).await?;

    owner_call(
        &mut env,
        IAttestedKeyRegistry::revokeKeysCall {
            policyId: policy_id,
        }
        .abi_encode(),
    )
    .await?;
    assert_eq!(registry.keyValidUntil(policy_id, x, y).call().await?, 0);

    // After `revokeKeys`, the same program key can neither authorize a key nor sign directly.
    let now = env.current_block_timestamp().await?;
    let (authorization, access_key, key_x, key_y) = signer.authorize(chain_id, now + 300)?;
    let mut tx = create_basic_aa_tx(chain_id, 2, vec![noop_call()], GAS_LIMIT);
    tx.key_authorization = Some(authorization);
    let signature = sign_aa_tx_with_p256_access_key(&tx, &access_key, &key_x, &key_y, attested)?;
    let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
    env.submit_tx_expecting_rejection(
        envelope.encoded_2718(),
        Some("attested signature rejected: program key is not current"),
    )
    .await?;

    let tx = create_basic_aa_tx(chain_id, 2, vec![noop_call()], GAS_LIMIT);
    let signature = TempoSignature::Attested(signer.sign(tx.signature_hash(), now + 300)?);
    let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
    env.submit_tx_expecting_rejection(
        envelope.encoded_2718(),
        Some("attested signature rejected: program key is not current"),
    )
    .await?;

    // Pool admission checks the window, then the registry, before any P256 verification: forged
    // signatures, as a sender or a key authorization signature, fail those checks first.
    let tx = create_basic_aa_tx(chain_id, 2, vec![noop_call()], GAS_LIMIT);
    let forged = TempoSignature::Attested(signer.sign(B256::ZERO, now + 10_000)?);
    let envelope: TempoTxEnvelope = tx.into_signed(forged).into();
    env.submit_tx_expecting_rejection(
        envelope.encoded_2718(),
        Some("attested signature rejected: valid_until too far in the future"),
    )
    .await?;

    let tx = create_basic_aa_tx(chain_id, 2, vec![noop_call()], GAS_LIMIT);
    let forged = TempoSignature::Attested(signer.sign(B256::ZERO, now + 300)?);
    let envelope: TempoTxEnvelope = tx.into_signed(forged).into();
    env.submit_tx_expecting_rejection(
        envelope.encoded_2718(),
        Some("attested signature rejected: program key is not current"),
    )
    .await?;

    let (access_key, key_x, key_y, key_id) = generate_p256_access_key();
    let authorization = KeyAuthorization::unrestricted(chain_id, SignatureType::P256, key_id)
        .into_signed(signer.sign(B256::ZERO, now + 300)?);
    let mut tx = create_basic_aa_tx(chain_id, 2, vec![noop_call()], GAS_LIMIT);
    tx.key_authorization = Some(authorization);
    let signature = sign_aa_tx_with_p256_access_key(&tx, &access_key, &key_x, &key_y, attested)?;
    let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
    env.submit_tx_expecting_rejection(
        envelope.encoded_2718(),
        Some("attested signature rejected: program key is not current"),
    )
    .await?;
    Ok(())
}

/// A configurable account whose owners, of weight one each, are an attested address and a P256
/// key.
struct AttestedOwnedAccount {
    address: Address,
    config: ConfigurableAccountConfig,
    p256: (SigningKey, B256, B256, Address),
}

impl AttestedOwnedAccount {
    fn new(signer: &Signer, threshold: u8, salt: u8) -> Self {
        let p256 = generate_p256_access_key();
        let mut owners = vec![
            ConfigurableAccountOwner {
                owner: signer.address(),
                weight: 1,
            },
            ConfigurableAccountOwner {
                owner: p256.3,
                weight: 1,
            },
        ];
        owners.sort_by_key(|owner| owner.owner);
        let config = ConfigurableAccountConfig {
            salt: B256::repeat_byte(salt),
            version: 0,
            threshold,
            owners,
        };
        Self {
            address: config.derive_account().expect("valid config"),
            config,
            p256,
        }
    }

    /// Signs a no-op transaction with the attested approval and, if `with_p256`, the P256
    /// approval, in ascending owner order.
    fn signed_tx(
        &self,
        signer: &Signer,
        chain_id: u64,
        nonce: u64,
        valid_until: u64,
        with_p256: bool,
    ) -> eyre::Result<Vec<u8>> {
        let tx = create_basic_aa_tx(chain_id, nonce, vec![noop_call()], GAS_LIMIT);
        let digest =
            configurable_account_digest(tx.signature_hash(), self.address, self.config.version);
        let mut approvals = vec![(
            signer.address(),
            OwnerApproval::from(signer.sign(digest, valid_until)?),
        )];
        if with_p256 {
            let (key, x, y, owner) = &self.p256;
            approvals.push((*owner, sign_p256_primitive(digest, key, *x, *y)?.into()));
        }
        approvals.sort_by_key(|(owner, _)| *owner);
        let signature = ConfigurableAccountSignature::try_new(
            self.address,
            self.config.clone(),
            approvals.into_iter().map(|(_, approval)| approval),
        )
        .map_err(|error| eyre::eyre!("{error}"))?;
        let envelope: TempoTxEnvelope = tx
            .into_signed(TempoSignature::ConfigurableAccount(signature))
            .into();
        Ok(envelope.encoded_2718())
    }
}

/// Submits an encoded transaction and asserts it is mined successfully.
async fn submit(env: &mut Localnet, encoded: Vec<u8>) -> eyre::Result<()> {
    let hash = keccak256(&encoded);
    env.submit_tx(encoded, hash).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn attested_owner_approves_configurable_account() -> eyre::Result<()> {
    let (mut env, signer, _, _) = registered_signer().await?;
    let chain_id = env.chain_id;
    let single = AttestedOwnedAccount::new(&signer, 1, 0x01);
    let pair = AttestedOwnedAccount::new(&signer, 2, 0x02);
    env.fund_account(single.address).await?;
    env.fund_account(pair.address).await?;
    let now = env.current_block_timestamp().await?;

    // Threshold 1: the attested approval alone authorizes the account.
    let encoded = single.signed_tx(&signer, chain_id, 0, now + 300, false)?;
    submit(&mut env, encoded).await?;

    // Threshold 2: the attested approval alone is below the threshold, and with the P256
    // approval it reaches it.
    let encoded = pair.signed_tx(&signer, chain_id, 0, now + 300, false)?;
    env.submit_tx_expecting_rejection(
        encoded,
        Some("configurable account signature weight below threshold"),
    )
    .await?;
    let encoded = pair.signed_tx(&signer, chain_id, 0, now + 300, true)?;
    submit(&mut env, encoded).await?;

    owner_call(
        &mut env,
        IAttestedKeyRegistry::revokeKeysCall {
            policyId: signer.policy_id,
        }
        .abi_encode(),
    )
    .await?;

    // After `revokeKeys`, the attested approval no longer authorizes, alone or with the P256 one.
    let now = env.current_block_timestamp().await?;
    for (account, with_p256) in [(&single, false), (&pair, true)] {
        let encoded = account.signed_tx(&signer, chain_id, 1, now + 300, with_p256)?;
        env.submit_tx_expecting_rejection(
            encoded,
            Some("attested signature rejected: program key is not current"),
        )
        .await?;
    }
    Ok(())
}

/// Signs a no-op transaction from the attested address with `signer` and asserts it is mined.
async fn submit_signed(env: &mut Localnet, signer: &Signer, nonce: u64) -> eyre::Result<()> {
    let now = env.current_block_timestamp().await?;
    let tx = create_basic_aa_tx(env.chain_id, nonce, vec![noop_call()], GAS_LIMIT);
    let signature = TempoSignature::Attested(signer.sign(tx.signature_hash(), now + 300)?);
    let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
    let hash = *envelope.tx_hash();
    env.submit_tx(envelope.encoded_2718(), hash).await?;
    Ok(())
}

/// Signs a no-op transaction from the attested address with `signer` and asserts the pool
/// rejects it because the program key is not current in the slot it names.
async fn expect_not_current(env: &mut Localnet, signer: &Signer, nonce: u64) -> eyre::Result<()> {
    let now = env.current_block_timestamp().await?;
    let tx = create_basic_aa_tx(env.chain_id, nonce, vec![noop_call()], GAS_LIMIT);
    let signature = TempoSignature::Attested(signer.sign(tx.signature_hash(), now + 300)?);
    let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
    env.submit_tx_expecting_rejection(
        envelope.encoded_2718(),
        Some("attested signature rejected: program key is not current"),
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn attested_slot_rotation() -> eyre::Result<()> {
    let (mut env, first, ..) = registered_signer().await?;
    env.fund_account(first.address()).await?;

    // A key in the empty slot 1 overlaps the key in slot 0, and both sign for the same address.
    let second = Signer::random(first.policy_id, 1);
    assert_eq!(second.address(), first.address());
    let first_write_gas = register(&mut env, &second).await?;
    submit_signed(&mut env, &first, 0).await?;
    submit_signed(&mut env, &second, 1).await?;

    // Rotating slot 0 overwrites it and ends the first key at once, with time left on it.
    let third = Signer::random(first.policy_id, 0);
    let rotation_gas = register(&mut env, &third).await?;
    expect_not_current(&mut env, &first, 2).await?;
    let registry = IAttestedKeyRegistry::new(ATTESTED_KEY_REGISTRY_ADDRESS, env.provider.clone());
    let (x, y) = first.coordinates();
    assert_eq!(
        registry.keyValidUntil(first.policy_id, x, y).call().await?,
        0
    );
    submit_signed(&mut env, &third, 2).await?;
    submit_signed(&mut env, &second, 3).await?;

    // A registered key naming a slot that does not hold it.
    let wrong_slot = Signer { slot: 1, ..third };
    expect_not_current(&mut env, &wrong_slot, 4).await?;

    // Overwriting a non-zero slot avoids the new-slot storage cost of the first write.
    println!("registerKey gas: first write {first_write_gas}, rotation {rotation_gas}");
    assert!(
        first_write_gas > rotation_gas + 200_000,
        "first write {first_write_gas}, rotation {rotation_gas}"
    );
    Ok(())
}
