//! Signed configurable account transactions through a local node's public RPC.
use super::{helpers::create_basic_aa_tx, local::Localnet, types::TestEnv};
use crate::utils::{TestNodeBuilder, make_genesis_at};
use alloy::{
    network::ReceiptResponse,
    primitives::{Address, B256, Bytes, U256, keccak256},
    providers::{Provider, RootProvider},
    signers::{SignerSync, local::PrivateKeySigner},
    sol_types::SolCall,
};
use alloy_eips::Encodable2718;
use eyre::eyre;
use p256::ecdsa::SigningKey;
use reth_e2e_test_utils::wallet::test_signer;
use reth_tracing::init_test_tracing;
use serde_json::{Value, from_str, json, to_string};
use tempo_alloy::{TempoNetwork, rpc::TempoTransactionReceipt};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{CONFIGURABLE_ACCOUNT_ADDRESS, IConfigurableAccount};
use tempo_primitives::{
    SignatureType, TempoTransaction, TempoTxEnvelope,
    transaction::{
        CONFIGURABLE_ACCOUNT_UPGRADE_DOMAIN, Call, ConfigurableAccountConfig,
        ConfigurableAccountOwner, TempoSignature, tt_signature::derive_p256_address,
    },
};

const GAS_LIMIT: u64 = 5_000_000;

struct ConfigurableAccount {
    address: Address,
    config: ConfigurableAccountConfig,
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
    P256 { x: B256, y: B256 },
}

impl OwnerKey {
    fn new(seed: u8, kind: SignatureType) -> Self {
        match kind {
            SignatureType::Secp256k1 => Self::Secp(signer(seed)),
            SignatureType::P256 | SignatureType::WebAuthn => {
                let key = SigningKey::from_bytes(&[seed; 32].into()).unwrap();
                let point = key.verifying_key().to_encoded_point(false);
                Self::P256 {
                    x: B256::from_slice(point.x().unwrap()),
                    y: B256::from_slice(point.y().unwrap()),
                }
            }
        }
    }

    fn address(&self) -> Address {
        match self {
            Self::Secp(key) => key.address(),
            Self::P256 { x, y } => derive_p256_address(x, y),
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

async fn environment() -> eyre::Result<Localnet> {
    init_test_tracing();
    let mut genesis: Value = from_str(&make_genesis_at(TempoHardfork::T14))?;
    genesis["config"]["t14Time"] = json!(0);
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
