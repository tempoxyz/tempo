//! Configurable accounts across a real Tempo L1 and a zone: Tempo owns every configuration change,
//! and the zone applies it once its anchor includes the Tempo block (TIP-1154).

use alloy::{
    network::ReceiptResponse as _,
    primitives::{Address, B256, Bytes, U256, keccak256},
};
use alloy_eips::eip2718::Encodable2718;
use alloy_provider::{DynProvider, PendingTransactionBuilder, Provider, ProviderBuilder};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use tempo_alloy::TempoNetwork;
use tempo_chainspec::spec::{TEMPO_T0_BASE_FEE, TEMPO_T1_BASE_FEE};
use tempo_contracts::{
    precompiles::{CONFIGURABLE_ACCOUNT_ADDRESS, IConfigurableAccount, ITIP20},
    zones::{IZoneOutbox, ZONE_OUTBOX_ADDRESS, ZONE_TOKEN_ADDRESS},
};
use tempo_evm::{
    TempoInvalidTransaction,
    transaction_error::{ConfigurableAccountError, RootKeyRole},
};
use tempo_precompiles::PATH_USD_ADDRESS;
use tempo_primitives::{
    SignatureType, TempoTxEnvelope,
    transaction::{
        CONFIGURABLE_ACCOUNT_UPGRADE_DOMAIN, Call, ConfigurableAccountConfig,
        ConfigurableAccountOwner, ConfigurableAccountSignature, KeyAuthorization,
        KeychainSignature, PrimitiveSignature, TempoSignature, TempoTransaction,
        configurable_account_digest,
    },
};

use crate::utils::{
    DEFAULT_POLL, L1TestNode, WITHDRAWAL_TX_GAS, ZoneAccount, ZoneTestNode, poll_until,
    spawn_sequencer,
};

const L1_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const GAS_LIMIT: u64 = 5_000_000;
/// pathUSD each account holds on Tempo for its own fees.
const TEMPO_FUNDING: u128 = 100_000_000;
/// pathUSD each account receives on the zone.
const ZONE_DEPOSIT: u128 = 1_000_000;

/// A configurable account with secp256k1 owners of weight one.
struct Account {
    address: Address,
    config: ConfigurableAccountConfig,
    owners: Vec<PrivateKeySigner>,
}

impl Account {
    /// A version-zero account whose address derives from its configuration.
    fn new(seed: u8, count: u8, threshold: u8) -> Self {
        let mut owners = (0..count)
            .map(|index| signer(seed + index))
            .collect::<Vec<_>>();
        owners.sort_by_key(PrivateKeySigner::address);
        let config = ConfigurableAccountConfig {
            salt: B256::repeat_byte(seed),
            version: 0,
            threshold,
            owners: owners
                .iter()
                .map(|owner| ConfigurableAccountOwner {
                    owner: owner.address(),
                    weight: 1,
                })
                .collect(),
        };
        let address = config
            .derive_account()
            .expect("the configuration derives an account");
        Self {
            address,
            config,
            owners,
        }
    }

    /// The account the EOA `address` becomes with `upgradeAccount`: the upgrade salt, version
    /// one, and an address that does not derive from the configuration.
    fn migrated(address: Address, seed: u8, count: u8) -> Self {
        let mut account = Self::new(seed, count, count);
        account.address = address;
        account.config.salt =
            keccak256([CONFIGURABLE_ACCOUNT_UPGRADE_DOMAIN, address.as_slice()].concat());
        account.config.version = 1;
        account
    }

    fn commitment(&self) -> B256 {
        self.config
            .commitment()
            .expect("the fixture configuration is valid")
    }

    /// The `upgradeAccount` call that commits this configuration for its address.
    fn upgrade_call(&self) -> Call {
        configurable_account_call(IConfigurableAccount::upgradeAccountCall {
            threshold: self.config.threshold,
            owners: abi_owners(&self.config),
        })
    }

    /// The account after an `updateConfig` to `replacement`'s owners and threshold, and that call.
    fn rotate_to(&self, replacement: Self) -> (Self, Call) {
        let mut config = replacement.config;
        config.salt = self.config.salt;
        config.version = self.config.version + 1;
        let call = configurable_account_call(IConfigurableAccount::updateConfigCall {
            current: IConfigurableAccount::ConfigurableAccountConfig {
                salt: self.config.salt,
                version: self.config.version,
                threshold: self.config.threshold,
                owners: abi_owners(&self.config),
            },
            threshold: config.threshold,
            owners: abi_owners(&config),
        });
        let rotated = Self {
            address: self.address,
            config,
            owners: replacement.owners,
        };
        (rotated, call)
    }

    /// Approvals of `inner` from the first `approvals` owners.
    fn quorum(&self, inner: B256, approvals: usize) -> eyre::Result<ConfigurableAccountSignature> {
        let digest = configurable_account_digest(inner, self.address, self.config.version);
        let signatures = self.owners[..approvals]
            .iter()
            .map(|owner| {
                Ok(PrimitiveSignature::Secp256k1(
                    owner.sign_hash_sync(&digest)?,
                ))
            })
            .collect::<eyre::Result<Vec<_>>>()?;
        Ok(
            ConfigurableAccountSignature::try_new(self.address, self.config.clone(), signatures)
                .expect("the witness has a valid shape"),
        )
    }

    /// A minimal quorum of `tx` as the sender's signature.
    fn sign(&self, tx: &TempoTransaction) -> eyre::Result<TempoSignature> {
        Ok(TempoSignature::ConfigurableAccount(self.quorum(
            tx.signature_hash(),
            usize::from(self.config.threshold),
        )?))
    }

    /// A minimal quorum of `tx` as the access key of `parent`.
    fn sign_as_delegate(
        &self,
        tx: &TempoTransaction,
        parent: Address,
    ) -> eyre::Result<TempoSignature> {
        Ok(TempoSignature::Keychain(KeychainSignature::new(
            parent,
            self.quorum(
                KeychainSignature::signing_hash(tx.signature_hash(), parent),
                usize::from(self.config.threshold),
            )?,
        )))
    }
}

/// One chain's typed provider and the fee fields its transactions use.
struct Chain {
    provider: DynProvider<TempoNetwork>,
    chain_id: u64,
    base_fee: u128,
}

impl Chain {
    async fn connect(url: &url::Url, base_fee: u64) -> eyre::Result<Self> {
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_http(url.clone())
            .erased();
        let chain_id = provider.get_chain_id().await?;
        Ok(Self {
            provider,
            chain_id,
            base_fee: u128::from(base_fee),
        })
    }

    /// A pathUSD-paid transaction of `calls` from `sender` at its next nonce plus `gap`.
    async fn transaction(
        &self,
        sender: Address,
        gap: u64,
        calls: Vec<Call>,
    ) -> eyre::Result<TempoTransaction> {
        Ok(TempoTransaction {
            chain_id: self.chain_id,
            fee_token: Some(PATH_USD_ADDRESS),
            max_priority_fee_per_gas: self.base_fee,
            max_fee_per_gas: self.base_fee,
            gas_limit: GAS_LIMIT,
            calls,
            nonce: self.provider.get_transaction_count(sender).await? + gap,
            ..Default::default()
        })
    }

    async fn send(
        &self,
        tx: TempoTransaction,
        signature: TempoSignature,
    ) -> eyre::Result<PendingTransactionBuilder<TempoNetwork>> {
        let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
        Ok(self
            .provider
            .send_raw_transaction(&envelope.encoded_2718())
            .await?)
    }

    /// Sends `tx` and requires it to succeed, returning the block that included it.
    async fn execute(&self, tx: TempoTransaction, signature: TempoSignature) -> eyre::Result<u64> {
        let receipt = self.send(tx, signature).await?.get_receipt().await?;
        eyre::ensure!(receipt.status(), "transaction reverted: {receipt:?}");
        receipt
            .block_number()
            .ok_or_else(|| eyre::eyre!("receipt without a block number"))
    }

    /// Requires the node to refuse `tx` with an error that contains `expected`.
    async fn reject(
        &self,
        tx: TempoTransaction,
        signature: TempoSignature,
        expected: impl std::fmt::Display,
    ) -> eyre::Result<()> {
        let error = self
            .send(tx, signature)
            .await
            .expect_err("the node accepted a transaction it must refuse");
        let expected = expected.to_string();
        eyre::ensure!(
            format!("{error:#}").contains(&expected),
            "expected an error containing {expected:?}, got {error:#}"
        );
        Ok(())
    }

    async fn commitment(&self, account: Address) -> eyre::Result<B256> {
        Ok(
            IConfigurableAccount::new(CONFIGURABLE_ACCOUNT_ADDRESS, &self.provider)
                .getConfigCommitment(account)
                .call()
                .await?,
        )
    }
}

/// A Tempo L1 dev node and a zone that follows it.
struct Env {
    l1: L1TestNode,
    zone: ZoneTestNode,
    portal: Address,
    tempo: Chain,
    zone_chain: Chain,
}

impl Env {
    async fn start() -> eyre::Result<Self> {
        reth_tracing::init_test_tracing();
        let l1 = L1TestNode::start().await?;
        let portal = l1.deploy_zone().await?;
        let zone = ZoneTestNode::start_from_l1(l1.http_url(), l1.ws_url(), portal).await?;
        zone.wait_for_l2_tempo_finalized(0, L1_TIMEOUT).await?;
        let tempo = Chain::connect(l1.http_url(), TEMPO_T1_BASE_FEE).await?;
        let zone_chain = Chain::connect(zone.http_url(), TEMPO_T0_BASE_FEE).await?;
        Ok(Self {
            l1,
            zone,
            portal,
            tempo,
            zone_chain,
        })
    }

    /// Funds `account` on Tempo for its fees there.
    async fn fund_on_tempo(&self, account: Address) -> eyre::Result<()> {
        self.l1.fund_user(account, TEMPO_FUNDING).await
    }

    /// Deposits pathUSD to `account` on the zone from the L1 user account.
    async fn fund_on_zone(&self, account: Address) -> eyre::Result<()> {
        let mut depositor = ZoneAccount::from_l1_and_zone(&self.l1, &self.zone, self.portal);
        self.l1.fund_user(depositor.address(), ZONE_DEPOSIT).await?;
        depositor
            .deposit_to(account, ZONE_DEPOSIT, L1_TIMEOUT, &self.zone)
            .await?;
        Ok(())
    }

    /// Sends `call` on Tempo from `account`, signed by its quorum, and waits until the zone's
    /// anchor includes it.
    async fn change_on_tempo(&self, account: &Account, call: Call) -> eyre::Result<()> {
        let tx = self
            .tempo
            .transaction(account.address, 0, vec![call])
            .await?;
        let signature = account.sign(&tx)?;
        let block = self.tempo.execute(tx, signature).await?;
        self.zone
            .wait_for_tempo_block_number(block, L1_TIMEOUT)
            .await?;
        Ok(())
    }
}

/// An owner rotation on Tempo reaches the zone: the zone reports the new commitment, refuses the
/// old owners, and the new owners can still withdraw the account's funds to Tempo.
#[tokio::test(flavor = "multi_thread")]
async fn test_tempo_owner_rotation_reaches_the_zone() -> eyre::Result<()> {
    let env = Env::start().await?;
    let account = Account::new(0x11, 1, 1);
    env.fund_on_tempo(account.address).await?;
    env.fund_on_zone(account.address).await?;

    // Unregistered on Tempo, the account sends from the zone with its version-zero owners.
    let tx = env
        .zone_chain
        .transaction(account.address, 0, vec![approve_outbox()])
        .await?;
    let signature = account.sign(&tx)?;
    env.zone_chain.execute(tx, signature).await?;

    // Its first Tempo transaction registers it and rotates its owners.
    let (rotated, rotate) = account.rotate_to(Account::new(0x21, 1, 1));
    env.change_on_tempo(&account, rotate).await?;
    assert_eq!(
        env.tempo.commitment(account.address).await?,
        rotated.commitment()
    );
    assert_eq!(
        env.zone_chain.commitment(account.address).await?,
        rotated.commitment()
    );

    let tx = env
        .zone_chain
        .transaction(account.address, 0, vec![approve_outbox()])
        .await?;
    env.zone_chain
        .reject(
            tx.clone(),
            account.sign(&tx)?,
            TempoInvalidTransaction::ConfigurableAccount(
                ConfigurableAccountError::ConfigurationCommitmentMismatch {
                    expected: rotated.commitment(),
                    actual: account.commitment(),
                },
            ),
        )
        .await?;

    // The new owners withdraw to Tempo. The test zone is closed, so the portal admits the account.
    let allowed = env
        .l1
        .set_allowed_account_on_portal(env.portal, account.address, true)
        .await?;
    env.zone
        .wait_for_tempo_block_number(allowed, L1_TIMEOUT)
        .await?;
    let _sequencer = spawn_sequencer(&env.l1, &env.zone, env.portal, env.l1.dev_signer()).await;
    let amount = ZONE_DEPOSIT / 2;
    let balance_before = env.l1.balance_of(PATH_USD_ADDRESS, account.address).await?;
    let withdraw = Call {
        to: ZONE_OUTBOX_ADDRESS.into(),
        value: U256::ZERO,
        input: IZoneOutbox::requestWithdrawalCall {
            token: ZONE_TOKEN_ADDRESS,
            to: account.address,
            amount,
            memo: B256::ZERO,
            gasLimit: 0,
            zoneFallbackRecipient: account.address,
            data: Bytes::new(),
            revealTo: Bytes::new(),
        }
        .abi_encode()
        .into(),
    };
    let mut tx = env
        .zone_chain
        .transaction(account.address, 0, vec![approve_outbox(), withdraw])
        .await?;
    tx.gas_limit = WITHDRAWAL_TX_GAS;
    let signature = rotated.sign(&tx)?;
    env.zone_chain.execute(tx, signature).await?;
    env.l1
        .wait_for_withdrawal_on_l1(
            env.portal,
            account.address,
            balance_before,
            amount,
            std::time::Duration::from_secs(60),
        )
        .await?;
    Ok(())
}

/// Once an EOA migrates on Tempo, the zone reports its commitment, refuses the original key and
/// accepts the configured owners.
#[tokio::test(flavor = "multi_thread")]
async fn test_tempo_migration_retires_the_root_key_on_the_zone() -> eyre::Result<()> {
    let env = Env::start().await?;
    let root = signer(0x31);
    env.fund_on_tempo(root.address()).await?;
    env.fund_on_zone(root.address()).await?;

    let tx = env
        .zone_chain
        .transaction(root.address(), 0, vec![approve_outbox()])
        .await?;
    let signature = root.sign_hash_sync(&tx.signature_hash())?.into();
    env.zone_chain.execute(tx, signature).await?;

    let account = Account::migrated(root.address(), 0x32, 2);
    let tx = env
        .tempo
        .transaction(root.address(), 0, vec![account.upgrade_call()])
        .await?;
    let signature = root.sign_hash_sync(&tx.signature_hash())?.into();
    let block = env.tempo.execute(tx, signature).await?;
    env.zone
        .wait_for_tempo_block_number(block, L1_TIMEOUT)
        .await?;

    assert_eq!(
        env.zone_chain.commitment(root.address()).await?,
        account.commitment()
    );
    let tx = env
        .zone_chain
        .transaction(root.address(), 0, vec![approve_outbox()])
        .await?;
    let signature = root.sign_hash_sync(&tx.signature_hash())?.into();
    env.zone_chain
        .reject(
            tx,
            signature,
            TempoInvalidTransaction::RootKeyRetired {
                account: root.address(),
                role: RootKeyRole::Sender,
            },
        )
        .await?;

    let tx = env
        .zone_chain
        .transaction(root.address(), 0, vec![approve_outbox()])
        .await?;
    let signature = account.sign(&tx)?;
    env.zone_chain.execute(tx, signature).await?;
    Ok(())
}

/// A zone transaction the old owners signed, waiting in the pool behind a nonce gap, is evicted
/// once the zone imports the Tempo rotation.
#[tokio::test(flavor = "multi_thread")]
async fn test_tempo_rotation_evicts_pending_zone_transactions() -> eyre::Result<()> {
    let env = Env::start().await?;
    let account = Account::new(0x41, 1, 1);
    env.fund_on_tempo(account.address).await?;
    env.fund_on_zone(account.address).await?;

    let nonce = env
        .zone_chain
        .provider
        .get_transaction_count(account.address)
        .await?;
    let tx = env
        .zone_chain
        .transaction(account.address, 1, vec![approve_outbox()])
        .await?;
    let signature = account.sign(&tx)?;
    let hash = *env.zone_chain.send(tx, signature).await?.tx_hash();
    eyre::ensure!(
        env.zone_chain
            .provider
            .get_transaction_by_hash(hash)
            .await?
            .is_some(),
        "the gapped transaction should wait in the pool"
    );

    let (_, rotate) = account.rotate_to(Account::new(0x51, 1, 1));
    env.change_on_tempo(&account, rotate).await?;

    poll_until(
        L1_TIMEOUT,
        DEFAULT_POLL,
        "the stale transaction leaves the pool",
        || async {
            Ok(env
                .zone_chain
                .provider
                .get_transaction_by_hash(hash)
                .await?
                .is_none()
                .then_some(()))
        },
    )
    .await?;
    // The gap was never filled, so the transaction was evicted rather than mined.
    assert_eq!(
        env.zone_chain
            .provider
            .get_transaction_count(account.address)
            .await?,
        nonce
    );
    Ok(())
}

/// A threshold raised on Tempo applies on the zone: one approval of the new 2-of-3 is refused and
/// two are accepted.
#[tokio::test(flavor = "multi_thread")]
async fn test_tempo_threshold_change_reaches_the_zone() -> eyre::Result<()> {
    let env = Env::start().await?;
    let account = Account::new(0x61, 1, 1);
    env.fund_on_tempo(account.address).await?;
    env.fund_on_zone(account.address).await?;

    let (rotated, rotate) = account.rotate_to(Account::new(0x71, 3, 2));
    env.change_on_tempo(&account, rotate).await?;

    let tx = env
        .zone_chain
        .transaction(account.address, 0, vec![approve_outbox()])
        .await?;
    let signature = TempoSignature::ConfigurableAccount(rotated.quorum(tx.signature_hash(), 1)?);
    env.zone_chain
        .reject(tx.clone(), signature, "invalid transaction signature")
        .await?;
    let signature = rotated.sign(&tx)?;
    env.zone_chain.execute(tx, signature).await?;
    Ok(())
}

/// A configurable account acting as an EOA's access key on the zone follows its Tempo rotation:
/// its old owners lose the key and its new owners hold it.
#[tokio::test(flavor = "multi_thread")]
async fn test_configurable_delegate_follows_tempo_rotation() -> eyre::Result<()> {
    let env = Env::start().await?;
    let parent = signer(0x81);
    let delegate = Account::new(0x91, 1, 1);
    env.fund_on_zone(parent.address()).await?;
    env.fund_on_tempo(delegate.address).await?;

    let grant = KeyAuthorization::unrestricted(
        env.zone_chain.chain_id,
        SignatureType::ConfigurableAccount,
        delegate.address,
    );
    let grant_signature =
        PrimitiveSignature::Secp256k1(parent.sign_hash_sync(&grant.signature_hash())?);
    let mut tx = env
        .zone_chain
        .transaction(parent.address(), 0, vec![approve_outbox()])
        .await?;
    tx.key_authorization = Some(grant.into_signed(grant_signature));
    let signature = delegate.sign_as_delegate(&tx, parent.address())?;
    env.zone_chain.execute(tx, signature).await?;

    let (rotated, rotate) = delegate.rotate_to(Account::new(0xa1, 1, 1));
    env.change_on_tempo(&delegate, rotate).await?;

    let tx = env
        .zone_chain
        .transaction(parent.address(), 0, vec![approve_outbox()])
        .await?;
    env.zone_chain
        .reject(
            tx.clone(),
            delegate.sign_as_delegate(&tx, parent.address())?,
            TempoInvalidTransaction::ConfigurableAccount(
                ConfigurableAccountError::ConfigurationCommitmentMismatch {
                    expected: rotated.commitment(),
                    actual: delegate.commitment(),
                },
            ),
        )
        .await?;
    let signature = rotated.sign_as_delegate(&tx, parent.address())?;
    env.zone_chain.execute(tx, signature).await?;
    Ok(())
}

/// A configurable account grants access keys on the zone with the quorum Tempo holds: a key it
/// granted keeps working after a Tempo rotation, and a new grant from the old owners is refused.
#[tokio::test(flavor = "multi_thread")]
async fn test_zone_key_grants_follow_tempo_rotation() -> eyre::Result<()> {
    let env = Env::start().await?;
    let account = Account::new(0xb1, 1, 1);
    env.fund_on_tempo(account.address).await?;
    env.fund_on_zone(account.address).await?;

    let granted = signer(0xc1);
    let mut tx = env
        .zone_chain
        .transaction(account.address, 0, vec![approve_outbox()])
        .await?;
    tx.key_authorization = Some(grant(&env.zone_chain, &account, &granted)?);
    let signature = sign_as_key(&tx, account.address, &granted)?;
    env.zone_chain.execute(tx, signature).await?;

    let (rotated, rotate) = account.rotate_to(Account::new(0xd1, 1, 1));
    env.change_on_tempo(&account, rotate).await?;

    // Grants live in zone state, so the rotation leaves this one in place.
    let tx = env
        .zone_chain
        .transaction(account.address, 0, vec![approve_outbox()])
        .await?;
    let signature = sign_as_key(&tx, account.address, &granted)?;
    env.zone_chain.execute(tx, signature).await?;

    let refused = signer(0xe1);
    let mut tx = env
        .zone_chain
        .transaction(account.address, 0, vec![approve_outbox()])
        .await?;
    tx.key_authorization = Some(grant(&env.zone_chain, &account, &refused)?);
    env.zone_chain
        .reject(
            tx.clone(),
            sign_as_key(&tx, account.address, &refused)?,
            TempoInvalidTransaction::ConfigurableAccount(
                ConfigurableAccountError::ConfigurationCommitmentMismatch {
                    expected: rotated.commitment(),
                    actual: account.commitment(),
                },
            ),
        )
        .await?;
    Ok(())
}

/// `account`'s owner quorum granting `key` as an unrestricted secp256k1 access key.
fn grant(
    chain: &Chain,
    account: &Account,
    key: &PrivateKeySigner,
) -> eyre::Result<tempo_primitives::transaction::SignedKeyAuthorization> {
    let grant =
        KeyAuthorization::unrestricted(chain.chain_id, SignatureType::Secp256k1, key.address())
            .with_account(account.address);
    let signature = account.quorum(
        grant.signature_hash(),
        usize::from(account.config.threshold),
    )?;
    Ok(grant.into_signed(signature))
}

/// `key`'s signature of `tx` as an access key of `account`.
fn sign_as_key(
    tx: &TempoTransaction,
    account: Address,
    key: &PrivateKeySigner,
) -> eyre::Result<TempoSignature> {
    let digest = KeychainSignature::signing_hash(tx.signature_hash(), account);
    Ok(TempoSignature::Keychain(KeychainSignature::new(
        account,
        PrimitiveSignature::Secp256k1(key.sign_hash_sync(&digest)?),
    )))
}

/// The key that `seed` determines.
fn signer(seed: u8) -> PrivateKeySigner {
    PrivateKeySigner::from_bytes(&B256::repeat_byte(seed)).expect("a valid secp256k1 key")
}

/// Approves the zone outbox for the account's whole pathUSD balance.
fn approve_outbox() -> Call {
    Call {
        to: PATH_USD_ADDRESS.into(),
        value: U256::ZERO,
        input: ITIP20::approveCall {
            spender: ZONE_OUTBOX_ADDRESS,
            amount: U256::MAX,
        }
        .abi_encode()
        .into(),
    }
}

fn configurable_account_call(call: impl SolCall) -> Call {
    Call {
        to: CONFIGURABLE_ACCOUNT_ADDRESS.into(),
        value: U256::ZERO,
        input: call.abi_encode().into(),
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
