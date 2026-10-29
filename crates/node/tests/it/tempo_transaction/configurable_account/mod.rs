//! Signed configurable account transactions through a local node's public RPC.
use super::{
    helpers::{create_basic_aa_tx, sign_p256_primitive, sign_webauthn_primitive},
    local::Localnet,
    types::TestEnv,
};
use crate::utils::{TestNodeBuilder, make_genesis_at};
use alloy::{
    network::ReceiptResponse,
    primitives::{Address, B256, Bytes, U256, keccak256},
    providers::{Provider, RootProvider},
    rpc::types::{TransactionRequest, error::EthRpcErrorCode},
    signers::{SignerSync, local::PrivateKeySigner},
    sol_types::SolCall,
    transports::TransportError,
};
use alloy_eips::Encodable2718;
use eyre::eyre;
use p256::ecdsa::SigningKey;
use reth_e2e_test_utils::wallet::test_signer;
use reth_tracing::init_test_tracing;
use serde_json::{Value, from_str, json, to_string};
use tempo_alloy::{TempoNetwork, rpc::TempoTransactionReceipt};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{
    CONFIGURABLE_ACCOUNT_ADDRESS, DEFAULT_FEE_TOKEN, IConfigurableAccount,
};
use tempo_evm::{TempoInvalidTransaction, transaction_error::RootKeyRole};
use tempo_primitives::{
    SignatureType, TempoTransaction, TempoTxEnvelope,
    transaction::{
        CONFIGURABLE_ACCOUNT_UPGRADE_DOMAIN, Call, ConfigurableAccountConfig,
        ConfigurableAccountOwner, ConfigurableAccountSignature, KeychainSignature,
        PrimitiveSignature, TempoSignature, configurable_account_digest,
        tt_signature::derive_p256_address,
    },
};

const OBSERVER: Address = Address::repeat_byte(0x72);
const GAS_LIMIT: u64 = 5_000_000;

type P256Signer = fn(B256, &SigningKey, B256, B256) -> eyre::Result<PrimitiveSignature>;

struct ConfigurableAccount {
    address: Address,
    config: ConfigurableAccountConfig,
    owners: Vec<OwnerKey>,
    nonce: u64,
}

impl ConfigurableAccount {
    fn new(seed: u8, count: u8) -> Self {
        let mut owners = (0..count)
            .map(|index| {
                let kind = [
                    SignatureType::Secp256k1,
                    SignatureType::P256,
                    SignatureType::WebAuthn,
                ][usize::from(index % 3)];
                OwnerKey::new(seed + index, kind)
            })
            .collect::<Vec<_>>();
        owners.sort_by_key(OwnerKey::address);
        let config = ConfigurableAccountConfig {
            salt: B256::repeat_byte(seed),
            version: 0,
            threshold: count,
            owners: owners
                .iter()
                .map(|owner| ConfigurableAccountOwner {
                    owner: owner.address(),
                    weight: 1,
                })
                .collect(),
        };
        let address = config.derive_account().unwrap();
        Self {
            address,
            config,
            owners,
            nonce: 0,
        }
    }

    /// The configuration an EOA `address` has after `upgradeAccount`: the upgrade salt, version
    /// one, and an address that is not derived from the configuration.
    fn migrated(address: Address, seed: u8, count: u8) -> Self {
        let mut account = Self::new(seed, count);
        account.address = address;
        account.config.salt =
            keccak256([CONFIGURABLE_ACCOUNT_UPGRADE_DOMAIN, address.as_slice()].concat());
        account.config.version = 1;
        account
    }

    /// The `upgradeAccount` call that commits this configuration for its address.
    fn upgrade_call(&self) -> Call {
        Call {
            to: CONFIGURABLE_ACCOUNT_ADDRESS.into(),
            value: U256::ZERO,
            input: IConfigurableAccount::upgradeAccountCall {
                threshold: self.config.threshold,
                owners: abi_owners(&self.config),
            }
            .abi_encode()
            .into(),
        }
    }

    fn transaction(&self, env: &Localnet, calls: Vec<Call>) -> TempoTransaction {
        create_basic_aa_tx(env.chain_id(), self.nonce, calls, GAS_LIMIT)
    }

    fn quorum(
        &self,
        inner: B256,
        invalid_final: bool,
    ) -> eyre::Result<ConfigurableAccountSignature> {
        let digest = configurable_account_digest(inner, self.address, self.config.version);
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
            ConfigurableAccountSignature::try_new(self.address, self.config.clone(), signatures)
                .expect("fixture configuration and primitive signatures are bounded"),
        )
    }

    fn sign(&self, tx: &TempoTransaction) -> eyre::Result<TempoSignature> {
        Ok(TempoSignature::ConfigurableAccount(
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

    /// Makes the rotation to `replacement`, whose configuration is `next`, the account's own.
    fn adopt(&mut self, next: ConfigurableAccountConfig, replacement: Self) {
        self.config = next;
        self.owners = replacement.owners;
    }

    fn rotate_to(&self, replacement: &Self) -> (ConfigurableAccountConfig, Call) {
        let mut next = replacement.config.clone();
        next.salt = self.config.salt;
        next.version = self.config.version + 1;
        let call = IConfigurableAccount::updateConfigCall {
            current: IConfigurableAccount::ConfigurableAccountConfig {
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
                to: CONFIGURABLE_ACCOUNT_ADDRESS.into(),
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
    ) -> eyre::Result<TempoTransactionReceipt> {
        let receipt = submit(env, tx, signature, succeeds).await?;
        self.nonce += 1;
        Ok(receipt)
    }
}

enum OwnerKey {
    Secp(PrivateKeySigner),
    P256 {
        key: SigningKey,
        x: B256,
        y: B256,
        sign: P256Signer,
    },
}

impl OwnerKey {
    fn new(seed: u8, kind: SignatureType) -> Self {
        let sign: P256Signer = match kind {
            SignatureType::Secp256k1 => {
                return Self::Secp(signer(seed));
            }
            SignatureType::P256 => sign_p256_primitive,
            SignatureType::WebAuthn => |digest, key, x, y| {
                sign_webauthn_primitive(digest, key, x, y, "https://native.example")
            },
            SignatureType::ConfigurableAccount => {
                panic!("fixture owners must use primitive signatures")
            }
        };
        let key = SigningKey::from_bytes(&[seed; 32].into()).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        Self::P256 {
            x: B256::from_slice(point.x().unwrap()),
            y: B256::from_slice(point.y().unwrap()),
            key,
            sign,
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
            Self::P256 { key, x, y, sign } => sign(digest, key, *x, *y),
        }
    }
}

fn abi_owners(
    config: &ConfigurableAccountConfig,
) -> Vec<IConfigurableAccount::ConfigurableAccountOwner> {
    config
        .owners
        .iter()
        .map(|owner| IConfigurableAccount::ConfigurableAccountOwner {
            owner: owner.owner,
            weight: owner.weight,
        })
        .collect()
}

/// A call of the configurable account precompile with `input` from `from`, with every other field
/// left to the node.
fn call_request(from: Address, input: Bytes) -> TransactionRequest {
    TransactionRequest {
        from: Some(from),
        to: Some(CONFIGURABLE_ACCOUNT_ADDRESS.into()),
        gas_price: None,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        max_fee_per_blob_gas: None,
        gas: Some(GAS_LIMIT),
        value: None,
        input: input.into(),
        nonce: None,
        chain_id: None,
        access_list: None,
        transaction_type: None,
        blob_versioned_hashes: None,
        sidecar: None,
        authorization_list: None,
    }
}

/// The key that `seed` determines, for the tests that need keys they can name.
fn signer(seed: u8) -> PrivateKeySigner {
    PrivateKeySigner::from_bytes(&B256::repeat_byte(seed)).unwrap()
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
        IConfigurableAccount::new(CONFIGURABLE_ACCOUNT_ADDRESS, env.provider())
            .getConfigCommitment(account)
            .call()
            .await?,
    )
}

/// Typed Tempo view of the node's RPC, which can carry AA receipts.
fn tempo_provider(env: &Localnet) -> RootProvider<TempoNetwork> {
    RootProvider::new_http(env.setup.node.rpc_url())
}

async fn submit(
    env: &mut Localnet,
    tx: TempoTransaction,
    signature: TempoSignature,
    succeeds: bool,
) -> eyre::Result<TempoTransactionReceipt> {
    let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
    let provider = tempo_provider(env);
    let hash = *provider
        .send_raw_transaction(&envelope.encoded_2718())
        .await?
        .tx_hash();
    env.setup.node.advance_block().await?;
    let receipt = provider
        .get_transaction_receipt(hash)
        .await?
        .ok_or_else(|| eyre!("missing receipt for {hash}"))?;
    assert_eq!(receipt.status(), succeeds, "{receipt:?}");
    Ok(receipt)
}

async fn rejection(
    env: &Localnet,
    tx: TempoTransaction,
    signature: TempoSignature,
) -> TransportError {
    let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
    tempo_provider(env)
        .send_raw_transaction(&envelope.encoded_2718())
        .await
        .expect_err("invalid authorization accepted by RPC")
}

/// Requires `error` to be a JSON-RPC error response of `code` with exactly `message`.
fn assert_rpc_error(error: &TransportError, code: i32, message: &str) -> eyre::Result<()> {
    let payload = error
        .as_error_resp()
        .ok_or_else(|| eyre!("not a JSON-RPC error response: {error:?}"))?;
    assert_eq!(payload.code, i64::from(code), "{error:?}");
    assert_eq!(payload.message, message, "{error:?}");
    Ok(())
}

/// Requires the RPC to reject `tx` with exactly the error the node reports for `invalid`.
async fn reject_with(
    env: &Localnet,
    tx: TempoTransaction,
    signature: TempoSignature,
    invalid: TempoInvalidTransaction,
) -> eyre::Result<()> {
    assert_rpc_error(
        &rejection(env, tx, signature).await,
        EthRpcErrorCode::InvalidInput.code(),
        &invalid.to_string(),
    )
}

async fn environment() -> eyre::Result<Localnet> {
    init_test_tracing();
    let mut genesis: Value = from_str(&make_genesis_at(TempoHardfork::T14))?;
    genesis["config"]["t14Time"] = json!(0);
    // Store the getter's result in slot zero, proving visibility inside the first signed call.
    let mut code = vec![0x63];
    code.extend_from_slice(&IConfigurableAccount::getConfigCommitmentCall::SELECTOR);
    code.extend_from_slice(&[
        0x60, 0xe0, 0x1b, 0x5f, 0x52, 0x33, 0x60, 0x04, 0x52, 0x60, 0x20, 0x5f, 0x60, 0x24, 0x5f,
        0x73,
    ]);
    code.extend_from_slice(CONFIGURABLE_ACCOUNT_ADDRESS.as_slice());
    code.extend_from_slice(&[0x5a, 0xfa, 0x50, 0x5f, 0x51, 0x5f, 0x55, 0x00]);
    genesis["alloc"][format!("{OBSERVER}")] = json!({"balance": "0x0", "code": Bytes::from(code)});
    let setup = TestNodeBuilder::new()
        .with_genesis(to_string(&genesis)?)
        .build_with_node_access()
        .await?;
    let provider = RootProvider::new_http(setup.node.rpc_url());
    let chain_id = provider.get_chain_id().await?;
    let funder_signer = test_signer(0);
    let funder_addr = funder_signer.address();
    Ok(Localnet {
        setup,
        provider,
        chain_id,
        funder_signer,
        funder_addr,
    })
}

mod tests;
