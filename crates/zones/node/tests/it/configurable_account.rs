//! Zones read configurable accounts from Tempo and never update them (TIP-1154).

use alloy::{
    network::ReceiptResponse as _,
    primitives::{Address, B256, U256, keccak256},
};
use alloy_eips::eip2718::Encodable2718;
use alloy_provider::{DynProvider, PendingTransactionBuilder, Provider};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use eyre::OptionExt;
use jsonrpsee::types::error::INVALID_PARAMS_CODE;
use std::fmt::Display;
use tempo_alloy::TempoNetwork;
use tempo_chainspec::spec::TEMPO_T0_BASE_FEE;
use tempo_contracts::{
    precompiles::{CONFIGURABLE_ACCOUNT_ADDRESS, IConfigurableAccount, ITIP20},
    zones::ZONE_OUTBOX_ADDRESS,
};
use tempo_evm::{
    TempoInvalidTransaction,
    transaction_error::{ConfigurableAccountError, RootKeyRole},
};
use tempo_precompiles::{PATH_USD_ADDRESS, configurable_account};
use tempo_primitives::{
    TempoTxEnvelope,
    account::{
        CONFIGURABLE_ACCOUNT_CODE, CONFIGURABLE_ACCOUNT_CODE_HASH, encode_config_commitment,
    },
    transaction::{
        AccountSignature, CONFIGURABLE_ACCOUNT_UPGRADE_DOMAIN, Call, ConfigurableAccountConfig,
        ConfigurableAccountSignature, KeychainSignature, PrimitiveSignature, TempoSignature,
        TempoTransaction, configurable_account_digest,
    },
};
use test_case::test_case;

use crate::utils::{
    DEFAULT_TIMEOUT, L1Fixture, ZoneTestNode, l1_dev_signer, signer_at,
    start_local_zone_with_fixture_and_withdrawal_batch_interval,
};

/// Test key index of the EOA that migrates.
pub(crate) const ROOT_KEY: u32 = 100;
/// First test key index of the two owners of the original configurable account.
pub(crate) const ORIGINAL_OWNERS: u32 = 110;
/// pathUSD each account receives on the zone.
pub(crate) const ZONE_FUNDING: u128 = 1_000_000;
/// Test key index of the owner an owner rotation installs.
const ROTATED_OWNER: u32 = 120;
/// First test key index of the two owners a migration installs.
const MIGRATED_OWNERS: u32 = 130;
const GAS_LIMIT: u64 = 5_000_000;

/// A configurable account with secp256k1 owners of weight one.
#[derive(Clone)]
pub(crate) struct Account {
    pub(crate) address: Address,
    /// The configuration, in the form the precompile's calls take.
    pub(crate) config: IConfigurableAccount::ConfigurableAccountConfig,
    pub(crate) owners: Vec<PrivateKeySigner>,
}

impl Account {
    /// The version-zero account whose `count` owners are the test keys from index `seed` on,
    /// at the address its configuration derives.
    pub(crate) fn new(seed: u32, count: u8, threshold: u8) -> Self {
        let mut owners = (0..count)
            .map(|index| signer_at(seed + u32::from(index)))
            .collect::<Vec<_>>();
        owners.sort_by_key(PrivateKeySigner::address);
        let config = IConfigurableAccount::ConfigurableAccountConfig {
            salt: B256::from(U256::from(seed)),
            version: 0,
            threshold,
            owners: owners
                .iter()
                .map(|owner| IConfigurableAccount::ConfigurableAccountOwner {
                    owner: owner.address(),
                    weight: 1,
                })
                .collect(),
        };
        let account = Self {
            address: Address::ZERO,
            config,
            owners,
        };
        Self {
            address: account
                .configuration()
                .derive_account()
                .expect("the configuration derives an account"),
            ..account
        }
    }

    /// The configuration the owners sign for.
    fn configuration(&self) -> ConfigurableAccountConfig {
        configurable_account::config(
            self.config.salt,
            self.config.version,
            self.config.threshold,
            &self.config.owners,
        )
    }

    pub(crate) fn commitment(&self) -> B256 {
        self.configuration()
            .commitment()
            .expect("the fixture configuration is valid")
    }

    /// The account after an `updateConfig` to `replacement`'s owners and threshold, and that call.
    fn rotate_to(&self, replacement: Self) -> (Self, Call) {
        let mut config = replacement.config;
        config.salt = self.config.salt;
        config.version = self.config.version + 1;
        let call = Call {
            to: CONFIGURABLE_ACCOUNT_ADDRESS.into(),
            value: U256::ZERO,
            input: IConfigurableAccount::updateConfigCall {
                current: self.config.clone(),
                threshold: config.threshold,
                owners: config.owners.clone(),
            }
            .abi_encode()
            .into(),
        };
        let rotated = Self {
            address: self.address,
            config,
            owners: replacement.owners,
        };
        (rotated, call)
    }

    /// A minimal quorum of approvals of `inner`.
    pub(crate) fn quorum(&self, inner: B256) -> eyre::Result<ConfigurableAccountSignature> {
        let digest = configurable_account_digest(inner, self.address, self.config.version);
        let signatures = self.owners[..usize::from(self.config.threshold)]
            .iter()
            .map(|owner| {
                Ok(PrimitiveSignature::Secp256k1(
                    owner.sign_hash_sync(&digest)?,
                ))
            })
            .collect::<eyre::Result<Vec<_>>>()?;
        Ok(
            ConfigurableAccountSignature::try_new(self.address, self.configuration(), signatures)
                .expect("the witness has a valid shape"),
        )
    }
}

/// A Tempo transaction that changes how an account authorizes.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Change {
    /// The account's first Tempo transaction registers its version-zero configuration.
    Registration,
    /// `updateConfig` replaces the owners.
    OwnerRotation,
    /// `updateConfig` keeps the owners and raises the threshold.
    ThresholdRaise,
    /// `upgradeAccount` makes an EOA a configurable account and retires its root key.
    Migration,
}

impl Change {
    /// The authority that signs for the account until the change: `root` for a migration, and
    /// otherwise the owners of `original`.
    pub(crate) fn authority<'a>(
        self,
        root: &'a PrivateKeySigner,
        original: &'a Account,
    ) -> Authority<'a> {
        match self {
            Self::Migration => Authority::Key(root),
            Self::Registration | Self::OwnerRotation | Self::ThresholdRaise => {
                Authority::Owners(original)
            }
        }
    }

    /// The account after the change, and the Tempo call that makes it.
    pub(crate) fn apply(self, root: &PrivateKeySigner, original: &Account) -> (Account, Call) {
        match self {
            Self::Registration => (original.clone(), approve_outbox()),
            Self::OwnerRotation => original.rotate_to(Account::new(ROTATED_OWNER, 1, 1)),
            Self::ThresholdRaise => {
                let mut raised = original.clone();
                raised.config.threshold += 1;
                original.rotate_to(raised)
            }
            Self::Migration => {
                // The upgrade salt and version one, at the EOA's address rather than a derived one.
                let address = root.address();
                let mut migrated = Account::new(MIGRATED_OWNERS, 2, 2);
                migrated.address = address;
                migrated.config.salt =
                    keccak256([CONFIGURABLE_ACCOUNT_UPGRADE_DOMAIN, address.as_slice()].concat());
                migrated.config.version = 1;
                let upgrade = Call {
                    to: CONFIGURABLE_ACCOUNT_ADDRESS.into(),
                    value: U256::ZERO,
                    input: IConfigurableAccount::upgradeAccountCall {
                        threshold: migrated.config.threshold,
                        owners: migrated.config.owners.clone(),
                    }
                    .abi_encode()
                    .into(),
                };
                (migrated, upgrade)
            }
        }
    }
}

/// Who signs for an account: a primitive key or the owner quorum of a configurable account.
#[derive(Clone, Copy)]
pub(crate) enum Authority<'a> {
    /// A secp256k1 key: an EOA's root key, or an access key.
    Key(&'a PrivateKeySigner),
    /// A minimal quorum of the account's owners.
    Owners(&'a Account),
}

impl Authority<'_> {
    /// The authority's approval of `digest`.
    pub(crate) fn approve(self, digest: B256) -> eyre::Result<AccountSignature> {
        Ok(match self {
            Self::Key(key) => PrimitiveSignature::Secp256k1(key.sign_hash_sync(&digest)?).into(),
            Self::Owners(account) => account.quorum(digest)?.into(),
        })
    }

    /// The authority's signature of `tx` as its sender.
    pub(crate) fn sign(self, tx: &TempoTransaction) -> eyre::Result<TempoSignature> {
        Ok(self.approve(tx.signature_hash())?.into())
    }

    /// The authority's signature of `tx` as an access key of `account`.
    pub(crate) fn sign_as_key(
        self,
        tx: &TempoTransaction,
        account: Address,
    ) -> eyre::Result<TempoSignature> {
        let digest = KeychainSignature::signing_hash(tx.signature_hash(), account);
        Ok(TempoSignature::Keychain(KeychainSignature::new(
            account,
            self.approve(digest)?,
        )))
    }
}

/// One chain's typed provider and the fee fields its transactions use.
pub(crate) struct Chain {
    pub(crate) provider: DynProvider<TempoNetwork>,
    pub(crate) chain_id: u64,
    pub(crate) base_fee: u128,
}

impl Chain {
    pub(crate) async fn connect(
        provider: DynProvider<TempoNetwork>,
        base_fee: u64,
    ) -> eyre::Result<Self> {
        let chain_id = provider.get_chain_id().await?;
        Ok(Self {
            provider,
            chain_id,
            base_fee: u128::from(base_fee),
        })
    }

    /// A pathUSD-paid transaction of `calls` from `sender` at its next nonce plus `gap`.
    pub(crate) async fn transaction(
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

    pub(crate) async fn send(
        &self,
        tx: TempoTransaction,
        signature: TempoSignature,
    ) -> eyre::Result<PendingTransactionBuilder<TempoNetwork>> {
        let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
        Ok(self
            .provider
            .send_raw_transaction(&envelope.encoded_2718())
            .await?
            .with_timeout(Some(DEFAULT_TIMEOUT)))
    }

    /// Sends `tx` and requires it to succeed, returning the block that included it.
    pub(crate) async fn execute(
        &self,
        tx: TempoTransaction,
        signature: TempoSignature,
    ) -> eyre::Result<u64> {
        let receipt = self.send(tx, signature).await?.get_receipt().await?;
        eyre::ensure!(receipt.status(), "transaction reverted: {receipt:?}");
        receipt
            .block_number()
            .ok_or_eyre("receipt without a block number")
    }

    /// Requires the node to refuse `tx` with an error that contains `expected`.
    pub(crate) async fn reject(
        &self,
        tx: TempoTransaction,
        signature: TempoSignature,
        expected: impl Display,
    ) -> eyre::Result<()> {
        let Err(error) = self.send(tx, signature).await else {
            eyre::bail!("the node accepted a transaction it must refuse with {expected}");
        };
        let expected = expected.to_string();
        eyre::ensure!(
            format!("{error:#}").contains(&expected),
            "expected an error containing {expected:?}, got {error:#}"
        );
        Ok(())
    }

    pub(crate) async fn commitment(&self, account: Address) -> eyre::Result<B256> {
        Ok(
            IConfigurableAccount::new(CONFIGURABLE_ACCOUNT_ADDRESS, &self.provider)
                .getConfigCommitment(account)
                .call()
                .await?,
        )
    }
}

/// Approves the zone outbox for the account's whole pathUSD balance.
pub(crate) fn approve_outbox() -> Call {
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

/// A zone whose dev account holds pathUSD, with its chain and the dev address.
async fn funded_zone() -> eyre::Result<(ZoneTestNode, L1Fixture, Chain, Address)> {
    reth_tracing::init_test_tracing();
    let genesis = zone_node::genesis::genesis_template()?;
    let (zone, mut fixture) =
        start_local_zone_with_fixture_and_withdrawal_batch_interval(1114, 10, 8, genesis).await?;
    let chain = Chain::connect(zone.provider(), TEMPO_T0_BASE_FEE).await?;
    let dev_address = l1_dev_signer().address();
    fund(&zone, &mut fixture, dev_address).await?;
    Ok((zone, fixture, chain, dev_address))
}

/// Deposits pathUSD to `account`, which also seeds its zero commitment on Tempo.
async fn fund(zone: &ZoneTestNode, fixture: &mut L1Fixture, account: Address) -> eyre::Result<()> {
    let deposit = fixture.make_deposit(PATH_USD_ADDRESS, account, account, ZONE_FUNDING);
    fixture.inject_deposits(zone.deposit_queue(), vec![deposit]);
    zone.wait_for_balance(
        PATH_USD_ADDRESS,
        account,
        U256::from(ZONE_FUNDING),
        DEFAULT_TIMEOUT,
    )
    .await?;
    Ok(())
}

/// Once Tempo migrates an EOA, the zone reports the account marker code and commitment and rejects its original key.
#[tokio::test(flavor = "multi_thread")]
async fn test_migrated_account_rejects_its_original_key() -> eyre::Result<()> {
    let (zone, _fixture, chain, dev_address) = funded_zone().await?;
    let provider = &chain.provider;
    let anchor = zone.tempo_block_number().await?;
    // An unregistered account has no code.
    assert!(provider.get_code_at(dev_address).await?.is_empty());
    assert!(
        provider
            .get_code_at(dev_address)
            .pending()
            .await?
            .is_empty()
    );
    let info = provider.get_account_info(dev_address).latest().await?;
    assert!(info.code.is_empty());
    assert!(info.extension.is_empty());
    // Its pathUSD balance lives in token storage, so the zone holds no account for it.
    let account: Option<alloy::consensus::TrieAccount> = provider
        .raw_request("eth_getAccount".into(), (dev_address, "latest"))
        .await?;
    assert_eq!(account, None);
    let outbox_code = provider.get_code_at(ZONE_OUTBOX_ADDRESS).await?;
    {
        let mut cache = zone.l1_state_cache().lock();
        cache.set_commitment(dev_address, anchor, B256::repeat_byte(0x11));
        // A zone precompile never carries a Tempo commitment, whatever Tempo holds for it.
        cache.set_commitment(ZONE_OUTBOX_ADDRESS, anchor, B256::repeat_byte(0x11));
    }
    // The operator RPC returns the account marker code that zone execution sees, at every tag.
    assert_eq!(
        provider.get_code_at(dev_address).await?,
        CONFIGURABLE_ACCOUNT_CODE
    );
    assert_eq!(
        provider.get_code_at(dev_address).pending().await?,
        CONFIGURABLE_ACCOUNT_CODE
    );
    assert_eq!(
        provider.get_code_at(ZONE_OUTBOX_ADDRESS).await?,
        outbox_code
    );
    // eth_getAccountInfo agrees with eth_getCode and carries the commitment, as on Tempo.
    let commitment = encode_config_commitment(B256::repeat_byte(0x11));
    for info in [
        provider.get_account_info(dev_address).latest().await?,
        provider.get_account_info(dev_address).pending().await?,
    ] {
        assert_eq!(info.code, CONFIGURABLE_ACCOUNT_CODE);
        assert_eq!(info.extension, commitment.clone().into());
    }
    // Named parameters get an invalid params error, as from reth's generated handlers.
    for (method, params) in [
        (
            "eth_getCode",
            serde_json::json!({ "address": dev_address, "blockNumber": "latest" }),
        ),
        (
            "eth_getAccountInfo",
            serde_json::json!({ "address": dev_address, "block": "latest" }),
        ),
        (
            "eth_getAccount",
            serde_json::json!({ "address": dev_address, "block": "latest" }),
        ),
        (
            "eth_getBalance",
            serde_json::json!({ "address": dev_address, "block": "latest" }),
        ),
    ] {
        let err = provider
            .raw_request::<_, serde_json::Value>(method.into(), params)
            .await
            .expect_err("named params must be rejected");
        assert_eq!(
            err.as_error_resp().expect("expected a JSON-RPC error").code,
            i64::from(INVALID_PARAMS_CODE),
            "{method}"
        );
    }
    // So does eth_getAccount, with the marker's code hash, though the zone holds no account.
    for account in [
        provider.get_account(dev_address).latest().await?,
        provider.get_account(dev_address).pending().await?,
    ] {
        assert_eq!(account.code_hash, CONFIGURABLE_ACCOUNT_CODE_HASH);
        assert_eq!(account.extension, commitment.clone().into());
    }
    let outbox_info = provider
        .get_account_info(ZONE_OUTBOX_ADDRESS)
        .latest()
        .await?;
    assert_eq!(outbox_info.code, outbox_code);
    assert!(outbox_info.extension.is_empty());

    let tx = chain
        .transaction(dev_address, 0, vec![approve_outbox()])
        .await?;
    let signature = Authority::Key(&l1_dev_signer()).sign(&tx)?;
    chain
        .reject(
            tx,
            signature,
            TempoInvalidTransaction::RootKeyRetired {
                account: dev_address,
                role: RootKeyRole::Sender,
            },
        )
        .await?;
    Ok(())
}

/// The zone applies a Tempo change from the block whose anchor includes it. Until then the old
/// authority sends, including from an account Tempo never registered, and the changed
/// configuration is refused. The block that imports the change leaves out an executable
/// transaction of the old authority admitted before it, and from then on the zone refuses the old
/// authority and accepts the changed configuration.
#[test_case(Change::OwnerRotation ; "owner rotation")]
#[test_case(Change::Migration ; "migration")]
#[tokio::test(flavor = "multi_thread")]
async fn test_zone_anchor_decides_when_a_tempo_change_applies(change: Change) -> eyre::Result<()> {
    let (zone, mut fixture, chain, _) = funded_zone().await?;
    let root = signer_at(ROOT_KEY);
    let original = Account::new(ORIGINAL_OWNERS, 2, 1);
    let old = change.authority(&root, &original);
    let (changed, _) = change.apply(&root, &original);
    let account = changed.address;
    let refusal = match old {
        Authority::Key(key) => TempoInvalidTransaction::RootKeyRetired {
            account: key.address(),
            role: RootKeyRole::Sender,
        },
        Authority::Owners(original) => TempoInvalidTransaction::ConfigurableAccount(
            ConfigurableAccountError::ConfigurationCommitmentMismatch {
                expected: changed.commitment(),
                actual: original.commitment(),
            },
        ),
    };
    fund(&zone, &mut fixture, account).await?;
    // Tempo changes the account in the block after the next one the zone imports.
    let unchanged = fixture.next_anchor_number();
    zone.l1_state_cache()
        .lock()
        .set_commitment(account, unchanged + 1, changed.commitment());

    assert_eq!(chain.commitment(account).await?, B256::ZERO);
    let tx = chain
        .transaction(account, 0, vec![approve_outbox()])
        .await?;
    let signature = Authority::Owners(&changed).sign(&tx)?;
    chain
        .reject(
            tx,
            signature,
            TempoInvalidTransaction::ConfigurableAccount(
                ConfigurableAccountError::InvalidAccount { account },
            ),
        )
        .await?;
    let tx = chain
        .transaction(account, 0, vec![approve_outbox()])
        .await?;
    let signature = old.sign(&tx)?;
    let pending = chain.send(tx, signature).await?;
    fixture.inject_empty_block(zone.deposit_queue());
    let receipt = pending.get_receipt().await?;
    assert!(receipt.status(), "{receipt:?}");
    assert_eq!(receipt.from(), account);

    let tx = chain
        .transaction(account, 0, vec![approve_outbox()])
        .await?;
    let signature = old.sign(&tx)?;
    let stale = *chain.send(tx, signature).await?.tx_hash();
    fixture.inject_empty_block(zone.deposit_queue());
    zone.wait_for_tempo_block_number(unchanged + 1, DEFAULT_TIMEOUT)
        .await?;
    eyre::ensure!(
        chain
            .provider
            .get_transaction_receipt(stale)
            .await?
            .is_none(),
        "the block that imports the change included a transaction of the old authority"
    );

    assert_eq!(chain.commitment(account).await?, changed.commitment());
    // The stale transaction holds the next nonce.
    let tx = chain
        .transaction(account, 1, vec![approve_outbox()])
        .await?;
    let signature = old.sign(&tx)?;
    chain.reject(tx, signature, refusal).await?;
    // The changed configuration replaces the stale transaction at its nonce.
    let mut tx = chain
        .transaction(account, 0, vec![approve_outbox()])
        .await?;
    tx.max_fee_per_gas *= 2;
    tx.max_priority_fee_per_gas *= 2;
    let signature = Authority::Owners(&changed).sign(&tx)?;
    let pending = chain.send(tx, signature).await?;
    fixture.inject_empty_block(zone.deposit_queue());
    let receipt = pending.get_receipt().await?;
    assert!(receipt.status(), "{receipt:?}");
    Ok(())
}
