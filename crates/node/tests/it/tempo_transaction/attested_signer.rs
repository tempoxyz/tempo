//! Attested signers (signature type `0x06`) through a local node: a registered program key
//! authorizes an access key for an attested address, and `revokeKeys` ends that authority.

use super::{
    helpers::{
        create_basic_aa_tx, generate_p256_access_key, sign_aa_tx_secp256k1,
        sign_aa_tx_with_p256_access_key,
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
        AttestedSignature, Call, KeyAuthorization, SignedKeyAuthorization, TempoSignature,
    },
};

const GAS_LIMIT: u64 = 3_000_000;
const SCHEME_NITRO_DEV: u8 = 0xFE;

/// A program key of the dev signer and the policy it registers under.
struct Signer {
    key: SigningKey,
    policy_id: B256,
    user_tag: B256,
}

impl Signer {
    fn program_key(&self) -> B512 {
        let point = self.key.verifying_key().to_encoded_point(false);
        B512::from_slice(&point.as_bytes()[1..])
    }

    fn address(&self) -> Address {
        tempo_primitives::transaction::attested_address(self.policy_id, self.user_tag)
    }

    /// Signs the context digest `d` as an attested signature valid until `valid_until`.
    fn sign(&self, d: B256, valid_until: u64) -> eyre::Result<AttestedSignature> {
        let mut signature = AttestedSignature {
            policy_id: self.policy_id,
            user_tag: self.user_tag,
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

/// Sends `input` to the registry from the funded owner and asserts success.
async fn owner_call(env: &mut Localnet, input: Vec<u8>) -> eyre::Result<()> {
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
    env.submit_tx(envelope.encoded_2718(), hash).await?;
    Ok(())
}

fn noop_call() -> Call {
    Call {
        to: Address::repeat_byte(0x77).into(),
        value: U256::ZERO,
        input: Bytes::new(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn attested_key_authorization_until_revoked() -> eyre::Result<()> {
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
            measurements: vec![keccak256(DEV_PCRS.concat())],
            anchors: vec![],
        }
        .abi_encode(),
    )
    .await?;

    let signer = Signer {
        key: SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng),
        policy_id,
        user_tag: B256::repeat_byte(0x7A),
    };
    let program_key = signer.program_key();
    let (x, y) = (
        B256::from_slice(&program_key[..32]),
        B256::from_slice(&program_key[32..]),
    );
    let binding = keccak256(
        [
            b"tempo:attested-key".as_slice(),
            &U256::from(chain_id).to_be_bytes::<32>(),
            ATTESTED_KEY_REGISTRY_ADDRESS.as_slice(),
            policy_id.as_slice(),
            x.as_slice(),
            y.as_slice(),
        ]
        .concat(),
    );
    let now = env.current_block_timestamp().await?;
    owner_call(
        &mut env,
        IAttestedKeyRegistry::registerKeyCall {
            policyId: policy_id,
            document: DevAttestation::new(binding.as_slice(), now * 1_000)
                .build()
                .into(),
            programKeyX: x,
            programKeyY: y,
        }
        .abi_encode(),
    )
    .await?;
    let registry = IAttestedKeyRegistry::new(ATTESTED_KEY_REGISTRY_ADDRESS, env.provider.clone());
    assert!(registry.keyValidUntil(policy_id, x, y).call().await? > now);

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

    // A signature valid for longer than the window is rejected before the registry read.
    let tx = create_basic_aa_tx(chain_id, 2, vec![noop_call()], GAS_LIMIT);
    let signature = TempoSignature::Attested(signer.sign(tx.signature_hash(), now + 10_000)?);
    let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
    env.submit_tx_expecting_rejection(
        envelope.encoded_2718(),
        Some("attested signature rejected: valid_until too far in the future"),
    )
    .await?;
    Ok(())
}
