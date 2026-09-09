//! Signed native-account transactions through a local node's public RPC.
mod tests;

use super::{
    helpers::{create_basic_aa_tx, sign_p256_primitive, sign_webauthn_primitive},
    local::Localnet,
    types::TestEnv,
};
use crate::utils::{TEST_MNEMONIC, TestNodeBuilder, make_genesis_at};
use alloy::{
    primitives::{Address, B256, Bytes, U256},
    providers::{Provider, RootProvider},
    signers::{
        SignerSync,
        local::{MnemonicBuilder, PrivateKeySigner},
    },
    sol_types::SolCall,
};
use alloy_eips::Encodable2718;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{INativeMultisig, NATIVE_MULTISIG_ADDRESS};
use tempo_primitives::{
    SignatureType, TempoTransaction, TempoTxEnvelope,
    transaction::{
        Call, KeychainSignature, MultisigConfig, MultisigOwner, MultisigSignature,
        PrimitiveSignature, TempoSignature, multisig_digest, tt_signature::derive_p256_address,
    },
};

const FACTORY: Address = Address::repeat_byte(0x71);
const OBSERVER: Address = Address::repeat_byte(0x72);
const GAS_LIMIT: u64 = 5_000_000;

struct NativeAccount {
    address: Address,
    config: MultisigConfig,
    owners: Vec<OwnerKey>,
    nonce: u64,
}

impl NativeAccount {
    fn new(seed: u8, count: usize) -> Self {
        let mut owners = (0..count)
            .map(|index| {
                let kind = [
                    SignatureType::Secp256k1,
                    SignatureType::P256,
                    SignatureType::WebAuthn,
                ][index % 3];
                OwnerKey::new(seed + index as u8, kind)
            })
            .collect::<Vec<_>>();
        owners.sort_by_key(OwnerKey::address);
        let config = MultisigConfig {
            salt: B256::repeat_byte(seed),
            version: 0,
            threshold: count as u8,
            owners: owners
                .iter()
                .map(|owner| MultisigOwner {
                    owner: owner.address(),
                    weight: 1,
                })
                .collect(),
        };
        let address = config.derive_account(FACTORY).unwrap();
        Self {
            address,
            config,
            owners,
            nonce: 0,
        }
    }

    fn transaction(&self, env: &Localnet, calls: Vec<Call>) -> TempoTransaction {
        create_basic_aa_tx(env.chain_id(), self.nonce, calls, GAS_LIMIT)
    }

    fn simulation_request(&self) -> serde_json::Value {
        serde_json::json!({
            "from": self.address,
            "to": NATIVE_MULTISIG_ADDRESS,
            "data": Bytes::from(INativeMultisig::getConfigCommitmentCall { account: self.address }.abi_encode()),
            "gas": "0x4c4b40",
            "feeToken": tempo_contracts::precompiles::DEFAULT_FEE_TOKEN,
            "multisigSimulation": {
                "config": Bytes::from(alloy_rlp::encode(&self.config)),
                "approvals": self.config.owners.iter().map(|owner| serde_json::json!({"owner": owner.owner})).collect::<Vec<_>>()
            }
        })
    }

    fn quorum(&self, inner: B256, invalid_final: bool) -> eyre::Result<MultisigSignature> {
        let digest = multisig_digest(inner, self.address, self.config.version);
        let signatures = self
            .owners
            .iter()
            .enumerate()
            .map(|(index, owner)| {
                owner.sign(if invalid_final && index + 1 == self.owners.len() {
                    B256::ZERO
                } else {
                    digest
                })
            })
            .collect::<eyre::Result<Vec<_>>>()?;
        Ok(
            MultisigSignature::try_new(self.address, self.config.clone(), signatures)
                .expect("fixture configuration and primitive signatures are bounded"),
        )
    }

    fn sign(&self, tx: &TempoTransaction) -> eyre::Result<TempoSignature> {
        Ok(TempoSignature::Multisig(
            self.quorum(tx.signature_hash(), false)?,
        ))
    }

    fn as_delegate(
        &self,
        tx: &TempoTransaction,
        parent: Address,
        invalid_final: bool,
    ) -> eyre::Result<TempoSignature> {
        Ok(TempoSignature::Keychain(KeychainSignature::new(
            parent,
            self.quorum(
                KeychainSignature::signing_hash(tx.signature_hash(), parent),
                invalid_final,
            )?,
        )))
    }

    fn rotate_to(&self, replacement: &Self) -> (MultisigConfig, Call) {
        let mut next = replacement.config.clone();
        next.salt = self.config.salt;
        next.version = self.config.version + 1;
        let call = INativeMultisig::updateConfigCall {
            current: INativeMultisig::MultisigConfig {
                salt: self.config.salt,
                version: self.config.version,
                threshold: self.config.threshold,
                owners: abi_owners(&self.config),
            },
            threshold: next.threshold,
            owners: abi_owners(&next),
        };
        (
            next,
            Call {
                to: NATIVE_MULTISIG_ADDRESS.into(),
                value: U256::ZERO,
                input: call.abi_encode().into(),
            },
        )
    }

    async fn submit(
        &mut self,
        env: &mut Localnet,
        tx: TempoTransaction,
        signature: TempoSignature,
        succeeds: bool,
    ) -> eyre::Result<serde_json::Value> {
        let receipt = submit(env, tx, signature, succeeds).await?;
        self.nonce += 1;
        Ok(receipt)
    }
}

enum OwnerKey {
    Secp(PrivateKeySigner),
    P256 {
        key: p256::ecdsa::SigningKey,
        x: B256,
        y: B256,
        webauthn: bool,
    },
}

impl OwnerKey {
    fn new(seed: u8, kind: SignatureType) -> Self {
        let webauthn = match kind {
            SignatureType::Secp256k1 => {
                return Self::Secp(PrivateKeySigner::from_bytes(&B256::repeat_byte(seed)).unwrap());
            }
            SignatureType::P256 => false,
            SignatureType::WebAuthn => true,
            SignatureType::Multisig => panic!("fixture owners must use primitive signatures"),
        };
        let key = p256::ecdsa::SigningKey::from_bytes(&[seed; 32].into()).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        Self::P256 {
            x: B256::from_slice(point.x().unwrap()),
            y: B256::from_slice(point.y().unwrap()),
            key,
            webauthn,
        }
    }

    fn address(&self) -> Address {
        match self {
            Self::Secp(key) => key.address(),
            Self::P256 { x, y, .. } => derive_p256_address(x, y),
        }
    }

    fn sign(&self, digest: B256) -> eyre::Result<PrimitiveSignature> {
        match self {
            Self::Secp(key) => Ok(PrimitiveSignature::Secp256k1(key.sign_hash_sync(&digest)?)),
            Self::P256 {
                key,
                x,
                y,
                webauthn: false,
            } => sign_p256_primitive(digest, key, *x, *y),
            Self::P256 {
                key,
                x,
                y,
                webauthn: true,
            } => sign_webauthn_primitive(digest, key, *x, *y, "https://native.example"),
        }
    }
}

fn abi_owners(config: &MultisigConfig) -> Vec<INativeMultisig::MultisigOwner> {
    config
        .owners
        .iter()
        .map(|owner| INativeMultisig::MultisigOwner {
            owner: owner.owner,
            weight: owner.weight,
        })
        .collect()
}

fn noop() -> Call {
    Call {
        to: Address::repeat_byte(0x73).into(),
        value: U256::ZERO,
        input: Bytes::new(),
    }
}

async fn commitment(env: &Localnet, account: Address) -> eyre::Result<B256> {
    Ok(
        INativeMultisig::new(NATIVE_MULTISIG_ADDRESS, env.provider())
            .getConfigCommitment(account)
            .call()
            .await?,
    )
}

async fn submit(
    env: &mut Localnet,
    tx: TempoTransaction,
    signature: TempoSignature,
    succeeds: bool,
) -> eyre::Result<serde_json::Value> {
    let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
    let hash: B256 = env
        .provider()
        .raw_request(
            "eth_sendRawTransaction".into(),
            [Bytes::from(envelope.encoded_2718())],
        )
        .await?;
    env.setup.node.advance_block().await?;
    let receipt: Option<serde_json::Value> = env
        .provider()
        .raw_request("eth_getTransactionReceipt".into(), [hash])
        .await?;
    let receipt = receipt.ok_or_else(|| eyre::eyre!("missing receipt for {hash}"))?;
    assert_eq!(
        receipt["status"].as_str(),
        Some(if succeeds { "0x1" } else { "0x0" }),
        "{receipt}"
    );
    Ok(receipt)
}

async fn reject(
    env: &Localnet,
    tx: TempoTransaction,
    signature: TempoSignature,
) -> eyre::Result<String> {
    let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
    let result = env
        .provider()
        .raw_request::<_, B256>(
            "eth_sendRawTransaction".into(),
            [Bytes::from(envelope.encoded_2718())],
        )
        .await;
    Ok(result
        .expect_err("invalid authorization accepted by RPC")
        .to_string())
}

async fn environment() -> eyre::Result<Localnet> {
    reth_tracing::init_test_tracing();
    let mut genesis: serde_json::Value =
        serde_json::from_str(&make_genesis_at(TempoHardfork::T12))?;
    genesis["config"]["multisigRecoveryFactory"] = serde_json::json!(FACTORY);
    // Store the getter's result in slot zero, proving visibility inside the first signed call.
    let mut code = vec![0x63];
    code.extend_from_slice(&INativeMultisig::getConfigCommitmentCall::SELECTOR);
    code.extend_from_slice(&[
        0x60, 0xe0, 0x1b, 0x5f, 0x52, 0x33, 0x60, 0x04, 0x52, 0x60, 0x20, 0x5f, 0x60, 0x24, 0x5f,
        0x73,
    ]);
    code.extend_from_slice(NATIVE_MULTISIG_ADDRESS.as_slice());
    code.extend_from_slice(&[0x5a, 0xfa, 0x50, 0x5f, 0x51, 0x5f, 0x55, 0x00]);
    genesis["alloc"][format!("{OBSERVER}")] =
        serde_json::json!({"balance": "0x0", "code": Bytes::from(code)});
    let setup = TestNodeBuilder::new()
        .with_genesis(serde_json::to_string(&genesis)?)
        .build_with_node_access()
        .await?;
    let provider = RootProvider::new_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;
    let funder_signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let funder_addr = funder_signer.address();
    Ok(Localnet {
        setup,
        provider,
        chain_id,
        funder_signer,
        funder_addr,
    })
}
