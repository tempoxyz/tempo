//! SLH-DSA owner approvals (signature type `0x06`) on a chain that enables them at genesis, and
//! their rejection on one that does not.
use super::*;
use alloy::sol_types::SolError;
use tempo_contracts::precompiles::{ISignatureVerifier, SIGNATURE_VERIFIER_ADDRESS};
use tempo_evm::transaction_error::ConfigurableAccountError;
use tempo_primitives::transaction::{
    ConfigurableAccountQuorumError, SlhDsaSignature, derive_slh_dsa_address,
};

/// An SLH-DSA-SHA2-128s owner key.
struct SlhDsaOwner {
    secret_key: [u8; 64],
    public_key: B256,
}

impl SlhDsaOwner {
    fn new(seed: u8) -> Self {
        let mut secret_key = [0u8; 64];
        let mut public_key = [0u8; 32];
        slhdsa::sha2_128s::keygen(&[seed; 48], &mut secret_key, &mut public_key);
        Self {
            secret_key,
            public_key: B256::from(public_key),
        }
    }

    fn address(&self) -> Address {
        derive_slh_dsa_address(&self.public_key)
    }

    fn sign(&self, digest: B256) -> PrimitiveSignature {
        let signature =
            slhdsa::sha2_128s::sign_deterministic(digest.as_slice(), &[], &self.secret_key)
                .expect("a 32-byte message and empty context are signable");
        PrimitiveSignature::SlhDsa(SlhDsaSignature {
            public_key: self.public_key,
            signature: signature.into(),
        })
    }
}

/// A P256 owner key.
struct P256Owner {
    key: SigningKey,
    x: B256,
    y: B256,
}

impl P256Owner {
    fn new(seed: u8) -> Self {
        let key = SigningKey::from_bytes(&[seed; 32].into()).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        Self {
            x: B256::from_slice(point.x().unwrap()),
            y: B256::from_slice(point.y().unwrap()),
            key,
        }
    }

    fn address(&self) -> Address {
        derive_p256_address(&self.x, &self.y)
    }

    fn sign(&self, digest: B256) -> eyre::Result<PrimitiveSignature> {
        sign_p256_primitive(digest, &self.key, self.x, self.y)
    }
}

fn config(salt: B256, version: u64, owners: &[Address]) -> ConfigurableAccountConfig {
    let mut owners = owners
        .iter()
        .map(|&owner| ConfigurableAccountOwner { owner, weight: 1 })
        .collect::<Vec<_>>();
    owners.sort_by_key(|owner| owner.owner);
    ConfigurableAccountConfig {
        salt,
        version,
        threshold: 1,
        owners,
    }
}

/// The outer signature of `tx` by one owner `approval` under `config`.
fn signed_by(
    account: Address,
    config: &ConfigurableAccountConfig,
    tx: &TempoTransaction,
    approve: impl FnOnce(B256) -> eyre::Result<PrimitiveSignature>,
) -> eyre::Result<TempoSignature> {
    let digest = configurable_account_digest(tx.signature_hash(), account, config.version);
    Ok(TempoSignature::ConfigurableAccount(
        ConfigurableAccountSignature::try_new(account, config.clone(), vec![approve(digest)?])
            .expect("one bounded owner approval"),
    ))
}

/// `verifyConfigurableAccount` of `slh`'s approval of a fixed hash for `account` under `config`.
async fn verify(
    env: &Localnet,
    account: Address,
    config: &ConfigurableAccountConfig,
    slh: &SlhDsaOwner,
) -> Result<bool, alloy::contract::Error> {
    let hash = B256::repeat_byte(0x5a);
    let approval = slh.sign(configurable_account_digest(hash, account, config.version));
    let signature = TempoSignature::ConfigurableAccount(
        ConfigurableAccountSignature::try_new(account, config.clone(), vec![approval])
            .expect("one bounded owner approval"),
    );
    ISignatureVerifier::new(SIGNATURE_VERIFIER_ADDRESS, env.provider())
        .verifyConfigurableAccount(account, hash, signature.to_bytes())
        .call()
        .await
}

/// Estimates a no-op from the registered `account` modeled with one `key_type` approval.
async fn estimate(
    env: &Localnet,
    account: Address,
    config: &ConfigurableAccountConfig,
    owner: Address,
    key_type: PrimitiveSignatureType,
) -> eyre::Result<u64> {
    let request = TempoTransactionRequest {
        inner: TransactionRequest {
            from: Some(account),
            to: Some(noop().to),
            gas: None,
            ..Default::default()
        },
        fee_token: Some(DEFAULT_FEE_TOKEN),
        configurable_account_simulation: Some(ConfigurableAccountSimulationSpec {
            signer: None,
            config: config.clone(),
            approvals: vec![ConfigurableAccountSimulationApproval {
                owner,
                key_type: Some(key_type),
                key_data: None,
            }],
        }),
        ..Default::default()
    };
    Ok(tempo_provider(env).estimate_gas(request).latest().await?)
}

/// A 1-of-2 passkey + SLH-DSA account registers with an SLH-DSA send, drops the passkey with an
/// SLH-DSA-signed `updateConfig`, and then rejects a passkey-signed transaction.
#[tokio::test(flavor = "multi_thread")]
async fn slh_dsa_owner_signs_and_removes_the_passkey() -> eyre::Result<()> {
    let mut env = environment_with_genesis(|genesis| {
        genesis["config"]["slhDsaTime"] = json!(0);
    })
    .await?;
    let chain_id = env.chain_id();
    let passkey = P256Owner::new(0x61);
    let slh = SlhDsaOwner::new(0x62);
    let salt = B256::repeat_byte(0x63);
    let initial = config(salt, 0, &[passkey.address(), slh.address()]);
    let account = initial.derive_account().unwrap();
    env.fund_account(account).await?;

    // The first send, signed by the SLH-DSA owner, registers the account.
    let tx = create_basic_aa_tx(chain_id, 0, vec![noop()], GAS_LIMIT);
    let signature = signed_by(account, &initial, &tx, |digest| Ok(slh.sign(digest)))?;
    let registration = submit(&mut env, tx, signature, true).await?;
    assert_eq!(
        commitment(&env, account).await?,
        initial.commitment().unwrap()
    );
    assert!(verify(&env, account, &initial, &slh).await?);

    // A registered no-op: the estimate covers the SLH-DSA verification and signature bytes, and
    // the signed transaction it models uses no more.
    let slh_estimate = estimate(
        &env,
        account,
        &initial,
        slh.address(),
        PrimitiveSignatureType::SlhDsa,
    )
    .await?;
    let p256_estimate = estimate(
        &env,
        account,
        &initial,
        passkey.address(),
        PrimitiveSignatureType::P256,
    )
    .await?;
    // 87,000 - 8,000 verification plus 7,890 nonzero bytes against 130 P256 bytes.
    assert!(
        slh_estimate >= p256_estimate + 79_000 + 120_000,
        "SLH-DSA {slh_estimate} vs P256 {p256_estimate}"
    );
    let tx = create_basic_aa_tx(chain_id, 1, vec![noop()], slh_estimate);
    let signature = signed_by(account, &initial, &tx, |digest| Ok(slh.sign(digest)))?;
    let send = submit(&mut env, tx, signature, true).await?;
    assert!(
        send.gas_used() <= slh_estimate,
        "{} > {slh_estimate}",
        send.gas_used()
    );
    assert!(registration.gas_used() > send.gas_used());

    // The SLH-DSA owner removes the passkey: the address stays, the version becomes one.
    let quantum_only = config(salt, 1, &[slh.address()]);
    let update = Call::new(
        CONFIGURABLE_ACCOUNT_ADDRESS,
        IConfigurableAccount::updateConfigCall {
            current: IConfigurableAccount::ConfigurableAccountConfig {
                salt,
                version: 0,
                threshold: initial.threshold,
                owners: abi_owners(&initial),
            },
            threshold: quantum_only.threshold,
            owners: abi_owners(&quantum_only),
        }
        .abi_encode(),
    );
    let tx = create_basic_aa_tx(chain_id, 2, vec![update], GAS_LIMIT);
    let signature = signed_by(account, &initial, &tx, |digest| Ok(slh.sign(digest)))?;
    submit(&mut env, tx, signature, true).await?;
    assert_eq!(
        commitment(&env, account).await?,
        quantum_only.commitment().unwrap()
    );
    assert!(verify(&env, account, &quantum_only, &slh).await?);
    assert!(!verify(&env, account, &initial, &slh).await?);

    // The passkey no longer signs: not under the new configuration, which lacks it...
    let tx = create_basic_aa_tx(chain_id, 3, vec![noop()], GAS_LIMIT);
    reject_with(
        &env,
        tx.clone(),
        signed_by(account, &quantum_only, &tx, |digest| passkey.sign(digest))?,
        TempoInvalidTransaction::ConfigurableAccount(ConfigurableAccountError::Quorum(
            ConfigurableAccountQuorumError::SignerNotOwner,
        )),
    )
    .await?;
    // ...nor under the old one, whose commitment was replaced.
    reject_with(
        &env,
        tx.clone(),
        signed_by(account, &initial, &tx, |digest| passkey.sign(digest))?,
        TempoInvalidTransaction::ConfigurableAccount(
            ConfigurableAccountError::ConfigurationCommitmentMismatch {
                expected: quantum_only.commitment().unwrap(),
                actual: initial.commitment().unwrap(),
            },
        ),
    )
    .await?;
    // The SLH-DSA owner still signs.
    let signature = signed_by(account, &quantum_only, &tx, |digest| Ok(slh.sign(digest)))?;
    submit(&mut env, tx, signature, true).await?;
    Ok(())
}

/// Without `slhDsaTime` in genesis, a configurable account signature with an SLH-DSA approval is
/// rejected before execution, while the same account still signs with its passkey.
#[tokio::test(flavor = "multi_thread")]
async fn slh_dsa_owner_rejected_when_inactive() -> eyre::Result<()> {
    let mut env = environment().await?;
    let chain_id = env.chain_id();
    let passkey = P256Owner::new(0x71);
    let slh = SlhDsaOwner::new(0x72);
    let initial = config(
        B256::repeat_byte(0x73),
        0,
        &[passkey.address(), slh.address()],
    );
    let account = initial.derive_account().unwrap();
    env.fund_account(account).await?;
    let error = verify(&env, account, &initial, &slh)
        .await
        .expect_err("an inactive SLH-DSA approval is malformed");
    assert_eq!(
        error.as_revert_data(),
        Some(ISignatureVerifier::InvalidFormat {}.abi_encode().into())
    );

    let tx = create_basic_aa_tx(chain_id, 0, vec![noop()], GAS_LIMIT);
    reject_with(
        &env,
        tx.clone(),
        signed_by(account, &initial, &tx, |digest| Ok(slh.sign(digest)))?,
        TempoInvalidTransaction::ConfigurableAccount(ConfigurableAccountError::SlhDsaInactive),
    )
    .await?;
    let signature = signed_by(account, &initial, &tx, |digest| passkey.sign(digest))?;
    submit(&mut env, tx, signature, true).await?;
    Ok(())
}
