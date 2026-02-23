use alloy::{
    primitives::{Address, B256, Bytes, U256},
    providers::Provider,
    rpc::types::TransactionRequest,
    signers::{SignerSync, local::PrivateKeySigner},
    sol_types::SolCall,
};
use alloy_eips::{Decodable2718, Encodable2718};
use alloy_primitives::TxKind;
use reth_primitives_traits::transaction::TxHashRef;
use tempo_contracts::precompiles::DEFAULT_FEE_TOKEN;
use tempo_node::rpc::TempoTransactionRequest;
use tempo_primitives::{
    SignatureType, TempoTransaction, TempoTxEnvelope,
    transaction::{
        KeyAuthorization, TEMPO_EXPIRING_NONCE_KEY, TokenLimit,
        tempo_transaction::Call,
        tt_signature::{PrimitiveSignature, TempoSignature},
    },
};

use super::{helpers::*, types::*};

// ===========================================================================
// Matrix runners
// ===========================================================================

/// Run the eth_sendRawTransaction matrix over a `TestEnv`.
pub(super) async fn run_raw_send_matrix<E: TestEnv>(env: &mut E) -> eyre::Result<()> {
    let access_key = || KeySetup::AccessKey {
        limits: SpendingLimits::Default,
        expiry: KeyExpiry::None,
    };

    // Use small fixed amounts that fit within the minimum funding (1M = 1 token).
    // fund_account returns rand_funding_amount() ∈ [1M, 1000M], so all amounts
    // must stay well below 1M to avoid insufficient-balance reverts.
    let spending_limit = U256::from(100_000u64);
    let transfer_over = spending_limit + U256::from(1u64);
    let transfer_under = spending_limit / U256::from(2);
    let transfer_small = U256::from(50_000u64);

    let matrix = vec![
        // --- core key type × fee_payer × access_key ---
        RawSendTestCase::new(KeyType::Secp256k1),
        RawSendTestCase::new(KeyType::Secp256k1).fee_payer(),
        RawSendTestCase::new(KeyType::Secp256k1).key_setup(access_key()),
        RawSendTestCase::new(KeyType::Secp256k1)
            .fee_payer()
            .key_setup(access_key()),
        RawSendTestCase::new(KeyType::P256),
        RawSendTestCase::new(KeyType::P256).fee_payer(),
        RawSendTestCase::new(KeyType::P256).key_setup(access_key()),
        RawSendTestCase::new(KeyType::P256)
            .fee_payer()
            .key_setup(access_key()),
        RawSendTestCase::new(KeyType::WebAuthn),
        RawSendTestCase::new(KeyType::WebAuthn).fee_payer(),
        RawSendTestCase::new(KeyType::WebAuthn).key_setup(access_key()),
        RawSendTestCase::new(KeyType::WebAuthn)
            .fee_payer()
            .key_setup(access_key()),
        // --- extended cases ---
        RawSendTestCase::new(KeyType::Secp256k1).fee_payer().sync(),
        RawSendTestCase::new(KeyType::Secp256k1).test_action(TestAction::Empty),
        RawSendTestCase::new(KeyType::Secp256k1).test_action(TestAction::InvalidCreate),
        RawSendTestCase::new(KeyType::Secp256k1).key_setup(KeySetup::ZeroPubKey),
        RawSendTestCase::new(KeyType::Secp256k1).key_setup(KeySetup::DuplicateAuth),
        RawSendTestCase::new(KeyType::P256).key_setup(KeySetup::UnauthorizedAuthorize),
        RawSendTestCase::new(KeyType::Secp256k1)
            .key_setup(access_key())
            .auth_chain_id(AuthChainId::Wrong),
        RawSendTestCase::new(KeyType::Secp256k1)
            .key_setup(access_key())
            .auth_chain_id(AuthChainId::Wildcard),
        // --- spending limit cases (folded from scenario runners) ---
        RawSendTestCase::new(KeyType::P256)
            .key_setup(KeySetup::AccessKey {
                limits: SpendingLimits::Custom(spending_limit),
                expiry: KeyExpiry::None,
            })
            .test_action(TestAction::Transfer(transfer_over))
            .expected(ExpectedOutcome::Revert),
        RawSendTestCase::new(KeyType::P256)
            .key_setup(KeySetup::AccessKey {
                limits: SpendingLimits::Custom(spending_limit),
                expiry: KeyExpiry::None,
            })
            .test_action(TestAction::Transfer(transfer_under)),
        RawSendTestCase::new(KeyType::P256)
            .key_setup(KeySetup::AccessKey {
                limits: SpendingLimits::Custom(spending_limit),
                expiry: KeyExpiry::None,
            })
            .test_action(TestAction::Transfer(spending_limit)),
        RawSendTestCase::new(KeyType::P256)
            .key_setup(KeySetup::AccessKey {
                limits: SpendingLimits::Custom(spending_limit),
                expiry: KeyExpiry::None,
            })
            .test_action(TestAction::AdminCall),
        // --- enforce limit cases ---
        RawSendTestCase::new(KeyType::P256)
            .key_setup(KeySetup::AccessKey {
                limits: SpendingLimits::Unlimited,
                expiry: KeyExpiry::None,
            })
            .test_action(TestAction::Transfer(transfer_small)),
        RawSendTestCase::new(KeyType::P256)
            .key_setup(KeySetup::AccessKey {
                limits: SpendingLimits::Empty,
                expiry: KeyExpiry::None,
            })
            .test_action(TestAction::Transfer(transfer_small))
            .expected(ExpectedOutcome::ExcludedByBuilder),
        // --- expiry ---
        RawSendTestCase::new(KeyType::P256).key_setup(KeySetup::AccessKey {
            limits: SpendingLimits::Default,
            expiry: KeyExpiry::Past,
        }),
        // --- RPC validation cases (folded from scenario runner) ---
        RawSendTestCase::new(KeyType::P256).key_setup(KeySetup::UnauthorizedKey),
        RawSendTestCase::new(KeyType::P256).key_setup(KeySetup::InvalidAuthSignature),
        RawSendTestCase::new(KeyType::Secp256k1).key_setup(KeySetup::InvalidAuthSignature),
    ];

    println!("\n=== eth_sendRawTransaction matrix ===\n");
    println!("Running {} raw send cases...\n", matrix.len());

    for (index, test_case) in matrix.iter().enumerate() {
        println!("[{}/{}] {}", index + 1, matrix.len(), test_case.name);
        run_raw_case(env, test_case).await?;
    }

    println!("\n✓ All {} raw send cases passed", matrix.len());
    Ok(())
}

/// Run the eth_sendTransaction matrix over a `TestEnv`.
pub(super) async fn run_send_matrix<E: TestEnv>(env: &mut E) -> eyre::Result<()> {
    let matrix = vec![
        SendTestCase::new(KeyType::Secp256k1),
        SendTestCase::new(KeyType::Secp256k1).fee_payer(),
        SendTestCase::new(KeyType::P256).fee_payer(),
        SendTestCase::new(KeyType::P256).fee_payer().access_key(),
        SendTestCase::new(KeyType::P256),
        SendTestCase::new(KeyType::P256).batch_calls(),
        SendTestCase::new(KeyType::P256).access_key(),
        SendTestCase::new(KeyType::WebAuthn).batch_calls(),
        SendTestCase::new(KeyType::WebAuthn).fee_payer(),
        SendTestCase::new(KeyType::WebAuthn).access_key(),
    ];

    println!("\n=== eth_sendTransaction matrix ===\n");
    println!("Running {} sendTransaction cases...\n", matrix.len());

    for (index, test_case) in matrix.iter().enumerate() {
        println!("[{}/{}] {}", index + 1, matrix.len(), test_case.name);
        run_send_case(env, test_case).await?;
    }

    println!("\n✓ All {} sendTransaction cases passed", matrix.len());
    Ok(())
}

/// Run the eth_estimateGas matrix over a `TestEnv`.
pub(super) async fn run_estimate_gas_matrix<E: TestEnv>(env: &mut E) -> eyre::Result<()> {
    let signer = PrivateKeySigner::random();
    let signer_addr = signer.address();
    let recipient = Address::random();

    let base_tx_request = || TempoTransactionRequest {
        inner: TransactionRequest {
            from: Some(signer_addr),
            ..Default::default()
        },
        calls: vec![Call {
            to: TxKind::Call(recipient),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        ..Default::default()
    };

    let matrix = [
        GasCase {
            name: "p256",
            kind: GasCaseKind::KeyType {
                key_type: SignatureType::P256,
                key_data: None,
            },
            expected: ExpectedGasDiff::Range(3_000..=8_000),
        },
        GasCase {
            name: "webauthn",
            kind: GasCaseKind::KeyType {
                key_type: SignatureType::WebAuthn,
                key_data: Some(Bytes::from(116u16.to_be_bytes().to_vec())),
            },
            expected: ExpectedGasDiff::GreaterThan("p256"),
        },
        GasCase {
            name: "keychain_secp256k1",
            kind: GasCaseKind::Keychain {
                key_type: None,
                num_limits: 0,
            },
            expected: ExpectedGasDiff::Range(275_000..=300_000),
        },
        GasCase {
            name: "keychain_p256",
            kind: GasCaseKind::Keychain {
                key_type: Some(SignatureType::P256),
                num_limits: 0,
            },
            expected: ExpectedGasDiff::GreaterThan("keychain_secp256k1"),
        },
        GasCase {
            name: "key_auth_secp256k1",
            kind: GasCaseKind::KeyAuth {
                key_type: SignatureType::Secp256k1,
                num_limits: 0,
            },
            expected: ExpectedGasDiff::Range(270_000..=300_000),
        },
        GasCase {
            name: "key_auth_p256",
            kind: GasCaseKind::KeyAuth {
                key_type: SignatureType::P256,
                num_limits: 0,
            },
            expected: ExpectedGasDiff::Range(270_000..=300_000),
        },
        GasCase {
            name: "key_auth_secp256k1_3_limits",
            kind: GasCaseKind::KeyAuth {
                key_type: SignatureType::Secp256k1,
                num_limits: 3,
            },
            expected: ExpectedGasDiff::Range(330_000..=370_000),
        },
    ];
    let provider = env.provider();

    let baseline_gas = estimate_gas(provider, &base_tx_request()).await?;
    println!("Baseline gas (secp256k1): {baseline_gas}");

    let mut results: std::collections::HashMap<&str, u64> = std::collections::HashMap::new();
    results.insert("baseline", baseline_gas);

    for (i, test_case) in matrix.iter().enumerate() {
        println!("\n[{}/{}] {}", i + 1, matrix.len(), test_case.name);

        let mut request = base_tx_request();
        match &test_case.kind {
            GasCaseKind::KeyType { key_type, key_data } => {
                request.key_type = Some(*key_type);
                request.key_data = key_data.clone();
            }
            GasCaseKind::Keychain {
                key_type,
                num_limits,
            } => {
                let auth = create_signed_key_authorization(
                    &signer,
                    key_type.unwrap_or(SignatureType::Secp256k1),
                    *num_limits,
                );
                request.key_id = Some(auth.key_id);
                request.key_authorization = Some(auth);
                if let Some(kt) = key_type {
                    request.key_type = Some(*kt);
                }
            }
            GasCaseKind::KeyAuth {
                key_type,
                num_limits,
            } => {
                let auth = create_signed_key_authorization(&signer, *key_type, *num_limits);
                request.key_authorization = Some(auth);
            }
        }

        let gas = estimate_gas(provider, &request).await?;
        println!("  gas: {gas}");

        match &test_case.expected {
            ExpectedGasDiff::Range(range) => {
                assert!(
                    gas >= baseline_gas,
                    "[{}] gas {gas} < baseline {baseline_gas} — regression: estimate should never be below baseline",
                    test_case.name,
                );
                let diff = gas - baseline_gas;
                assert!(
                    range.contains(&diff),
                    "[{}] expected diff in {:?}, got {diff}",
                    test_case.name,
                    range,
                );
                println!("  ✓ diff {diff} in {range:?}");
            }
            ExpectedGasDiff::GreaterThan(ref_name) => {
                let ref_gas = *results
                    .get(ref_name)
                    .unwrap_or_else(|| panic!("missing reference gas case '{ref_name}'"));
                assert!(
                    gas > ref_gas,
                    "[{}] expected gas {gas} > {ref_name} gas {ref_gas}",
                    test_case.name,
                );
                println!("  ✓ gas {gas} > {ref_name} gas {ref_gas}");
            }
        }

        results.insert(test_case.name, gas);
    }

    println!("\n✓ All gas estimation cases passed");
    Ok(())
}

/// Run the eth_fillTransaction matrix over a `TestEnv`.
///
/// For fee-payer cases, also verifies that the fee-payer signature hash is
/// deterministic by signing + recovering with a random signer.
pub(super) async fn run_fill_transaction_matrix<E: TestEnv>(env: &mut E) -> eyre::Result<()> {
    let signer_addr = Address::random();
    let current_timestamp = env.current_block_timestamp().await?;
    let fee_payer_signer = PrivateKeySigner::random();

    let matrix = [
        FillTestCase::new(NonceMode::Protocol, KeyType::Secp256k1).omit_nonce_key(),
        FillTestCase::new(NonceMode::TwoD(42), KeyType::Secp256k1),
        FillTestCase::new(NonceMode::Expiring, KeyType::Secp256k1).valid_before_offset(20),
        FillTestCase::new(NonceMode::Expiring, KeyType::Secp256k1)
            .valid_before_offset(20)
            .valid_after_offset(-10),
        FillTestCase::new(NonceMode::Expiring, KeyType::Secp256k1)
            .valid_before_offset(20)
            .explicit_nonce(12),
        FillTestCase::new(NonceMode::Protocol, KeyType::Secp256k1).fee_token(DEFAULT_FEE_TOKEN),
        FillTestCase::new(NonceMode::Protocol, KeyType::Secp256k1)
            .fee_payer()
            .fee_token(DEFAULT_FEE_TOKEN),
    ];

    println!("\n=== eth_fillTransaction matrix ===\n");
    println!("Running {} fillTransaction cases...\n", matrix.len());

    for (index, test_case) in matrix.iter().enumerate() {
        println!("[{}/{}] {}", index + 1, matrix.len(), test_case.name);

        let (filled_tx, request_context) =
            fill_transaction_from_case(env.provider(), test_case, signer_addr, current_timestamp)
                .await?;
        assert_fill_request_expectations(&filled_tx, &request_context, test_case)?;

        if test_case.fee_payer {
            let fee_payer_sig_hash = filled_tx.fee_payer_signature_hash(signer_addr);
            let fee_payer_signature = fee_payer_signer.sign_hash_sync(&fee_payer_sig_hash)?;
            assert_eq!(
                fee_payer_signature.recover_address_from_prehash(&fee_payer_sig_hash)?,
                fee_payer_signer.address(),
                "feePayerSignature hash should be deterministic"
            );
        }
    }

    println!("\n✓ All {} fillTransaction cases passed", matrix.len());
    Ok(())
}

/// Run the E2E fill → sign → send matrix over a `TestEnv`.
pub(super) async fn run_fill_sign_send_matrix<E: TestEnv>(env: &mut E) -> eyre::Result<()> {
    let matrix = vec![
        FillTestCase::new(NonceMode::Protocol, KeyType::Secp256k1),
        FillTestCase::new(NonceMode::TwoD(42), KeyType::Secp256k1),
        FillTestCase::new(NonceMode::Expiring, KeyType::Secp256k1),
        FillTestCase::new(NonceMode::Expiring, KeyType::P256),
        FillTestCase::new(NonceMode::Expiring, KeyType::WebAuthn),
        FillTestCase::new(NonceMode::ExpiringAtBoundary, KeyType::Secp256k1),
        FillTestCase::new(NonceMode::ExpiringAtBoundary, KeyType::P256),
        FillTestCase::new(NonceMode::ExpiringAtBoundary, KeyType::WebAuthn),
        FillTestCase::new(NonceMode::ExpiringExceedsBoundary, KeyType::Secp256k1).reject(),
        FillTestCase::new(NonceMode::ExpiringExceedsBoundary, KeyType::P256).reject(),
        FillTestCase::new(NonceMode::ExpiringExceedsBoundary, KeyType::WebAuthn).reject(),
        FillTestCase::new(NonceMode::ExpiringInPast, KeyType::Secp256k1).reject(),
        FillTestCase::new(NonceMode::TwoD(12345), KeyType::Secp256k1).pre_bump_nonce(5),
        FillTestCase::new(NonceMode::Expiring, KeyType::Secp256k1)
            .explicit_nonce(0)
            .pre_bump_nonce(3),
        FillTestCase::new(NonceMode::Expiring, KeyType::Secp256k1).explicit_nonce(0),
    ];

    println!("\n=== E2E fill → sign → send matrix ===\n");
    println!("Running {} test cases...\n", matrix.len());

    for (i, test_case) in matrix.iter().enumerate() {
        println!("[{}/{}] {}", i + 1, matrix.len(), test_case.name);
        run_fill_sign_send(env, test_case).await?;
    }

    println!("\n✓ All {} test cases passed", matrix.len());
    Ok(())
}
// ===========================================================================
// Unified matrix runners, generic over TestEnv
// ===========================================================================

/// Submit a signed envelope and assert the expected outcome.
/// When `sync` is true, uses `submit_tx_sync` for the Success path.
/// When `fee_payer_ctx` is Some on Success, asserts that the fee payer spent tokens.
/// Returns the transaction hash.
async fn submit_expecting<E: TestEnv>(
    env: &mut E,
    envelope: TempoTxEnvelope,
    expected: ExpectedOutcome,
    sync: bool,
    fee_payer_ctx: Option<FeePayerContext>,
) -> eyre::Result<B256> {
    let tx_hash = *envelope.tx_hash();
    match expected {
        ExpectedOutcome::Success => {
            let receipt = if sync {
                env.submit_tx_sync(envelope.encoded_2718(), tx_hash).await?
            } else {
                env.submit_tx(envelope.encoded_2718(), tx_hash).await?
            };
            let status = receipt["status"]
                .as_str()
                .map(|s| s == "0x1")
                .unwrap_or(false);
            assert!(status, "Transaction should succeed");
            if let Some(ctx) = fee_payer_ctx {
                assert_fee_payer_spent(env.provider(), ctx, &receipt).await?;
            }
        }
        ExpectedOutcome::Rejection => {
            env.submit_tx_expecting_rejection(envelope.encoded_2718(), None)
                .await?;
        }
        ExpectedOutcome::Revert => {
            let receipt = env
                .submit_tx_unchecked(envelope.encoded_2718(), tx_hash)
                .await?;
            let status = receipt["status"]
                .as_str()
                .map(|s| s == "0x1")
                .unwrap_or(false);
            assert!(!status, "Transaction should revert (status 0x0)");
        }
        ExpectedOutcome::ExcludedByBuilder => {
            env.submit_tx_excluded_by_builder(envelope.encoded_2718(), tx_hash)
                .await?;
        }
    }
    Ok(tx_hash)
}

pub(crate) async fn run_raw_case<E: TestEnv>(
    env: &mut E,
    test_case: &RawSendTestCase,
) -> eyre::Result<()> {
    use tempo_precompiles::account_keychain::updateSpendingLimitCall;

    println!("\n=== Raw send test: {} ===\n", test_case.name);
    let chain_id = env.chain_id();

    // --- choose signer and fund ---
    let root_signer = PrivateKeySigner::random();
    let root_addr = root_signer.address();
    let funded = if !test_case.fee_payer {
        env.fund_account(root_addr).await?
    } else {
        rand_funding_amount()
    };

    let fee_payer_signer = PrivateKeySigner::random();
    if test_case.fee_payer {
        let _ = env.fund_account(fee_payer_signer.address()).await?;
    }

    // --- build calls based on TestAction ---
    let calls = match &test_case.test_action {
        TestAction::NoOp => vec![Call {
            to: Address::random().into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        TestAction::Empty => vec![],
        TestAction::InvalidCreate => vec![Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: alloy_primitives::bytes!("ef"),
        }],
        TestAction::Transfer(amount) => {
            vec![create_transfer_call(
                DEFAULT_FEE_TOKEN,
                Address::random(),
                *amount,
            )]
        }
        TestAction::AdminCall => vec![Call {
            to: tempo_precompiles::ACCOUNT_KEYCHAIN_ADDRESS.into(),
            value: U256::ZERO,
            input: updateSpendingLimitCall {
                keyId: Address::random(),
                token: DEFAULT_FEE_TOKEN,
                newLimit: U256::from(20u64) * U256::from(10).pow(U256::from(18)),
            }
            .abi_encode()
            .into(),
        }],
    };

    let nonce_before = env.provider().get_transaction_count(root_addr).await?;
    let mut tx = create_basic_aa_tx(chain_id, nonce_before, calls.clone(), 2_000_000);

    // InvalidCreate: fee_token = None (no fee token, uses native ETH-equivalent)
    if matches!(test_case.test_action, TestAction::InvalidCreate) {
        tx.fee_token = None;
    }

    // --- key_setup handling ---
    match &test_case.key_setup {
        KeySetup::RootKey => {
            // Sign with root key directly (handled below)
        }
        KeySetup::ZeroPubKey => {
            use tempo_precompiles::{
                ACCOUNT_KEYCHAIN_ADDRESS,
                account_keychain::{SignatureType as KCSignatureType, authorizeKeyCall},
            };

            let authorize_call = authorizeKeyCall {
                keyId: Address::ZERO,
                signatureType: KCSignatureType::P256,
                expiry: u64::MAX,
                enforceLimits: true,
                limits: vec![],
            };
            tx.calls = vec![Call {
                to: ACCOUNT_KEYCHAIN_ADDRESS.into(),
                value: U256::ZERO,
                input: authorize_call.abi_encode().into(),
            }];
            tx.fee_token = None;
        }
        KeySetup::AccessKey { limits, expiry } => {
            let auth_chain_id_value = match test_case.auth_chain_id {
                AuthChainId::Matching => chain_id,
                AuthChainId::Wrong => chain_id + 1,
                AuthChainId::Wildcard => 0,
            };

            let expiry_value = match expiry {
                KeyExpiry::None => None,
                KeyExpiry::Past => Some(1u64),
            };

            let spending_limits = match limits {
                SpendingLimits::Default => Some(create_default_token_limit(funded)),
                SpendingLimits::Unlimited => None,
                SpendingLimits::Empty => Some(vec![]),
                SpendingLimits::Custom(amount) => Some(vec![TokenLimit {
                    token: DEFAULT_FEE_TOKEN,
                    limit: *amount,
                }]),
            };

            return run_raw_access_key_case(
                env,
                test_case,
                &root_signer,
                root_addr,
                &fee_payer_signer,
                &mut tx,
                nonce_before,
                chain_id,
                auth_chain_id_value,
                expiry_value,
                spending_limits,
                None, // normal access key
            )
            .await;
        }
        KeySetup::DuplicateAuth => {
            let auth_chain_id_value = match test_case.auth_chain_id {
                AuthChainId::Matching => chain_id,
                AuthChainId::Wrong => chain_id + 1,
                AuthChainId::Wildcard => 0,
            };

            return run_raw_access_key_case(
                env,
                test_case,
                &root_signer,
                root_addr,
                &fee_payer_signer,
                &mut tx,
                nonce_before,
                chain_id,
                auth_chain_id_value,
                None,
                Some(create_default_token_limit(funded)),
                Some(AccessKeyPreStep::DuplicateAuth),
            )
            .await;
        }
        KeySetup::UnauthorizedAuthorize => {
            let auth_chain_id_value = match test_case.auth_chain_id {
                AuthChainId::Matching => chain_id,
                AuthChainId::Wrong => chain_id + 1,
                AuthChainId::Wildcard => 0,
            };

            return run_raw_access_key_case(
                env,
                test_case,
                &root_signer,
                root_addr,
                &fee_payer_signer,
                &mut tx,
                nonce_before,
                chain_id,
                auth_chain_id_value,
                None,
                Some(create_default_token_limit(funded)),
                Some(AccessKeyPreStep::UnauthorizedAuthorize),
            )
            .await;
        }
        KeySetup::UnauthorizedKey => {
            assert!(matches!(test_case.expected, ExpectedOutcome::Rejection));
            // Authorize one key, then sign tx with a different (never-authorized) key
            let (_auth_signing, auth_pub_x, auth_pub_y, auth_addr) = generate_p256_access_key();
            let (unauth_signing, unauth_pub_x, unauth_pub_y, _unauth_addr) =
                generate_p256_access_key();

            let mock_sig = match test_case.key_type {
                KeyType::P256 => create_mock_p256_sig(auth_pub_x, auth_pub_y),
                KeyType::WebAuthn => create_mock_webauthn_sig(auth_pub_x, auth_pub_y),
                _ => create_mock_secp256k1_sig(),
            };

            let key_auth = create_key_authorization(
                &root_signer,
                auth_addr,
                mock_sig,
                chain_id,
                None,
                Some(create_default_token_limit(funded)),
            )?;

            // Authorize the real key first
            let mut auth_tx = create_basic_aa_tx(
                chain_id,
                nonce_before,
                vec![create_balance_of_call(root_addr)],
                2_000_000,
            );
            auth_tx.key_authorization = Some(key_auth);
            let sig = sign_aa_tx_secp256k1(&auth_tx, &root_signer)?;
            let envelope: TempoTxEnvelope = auth_tx.into_signed(sig).into();
            let hash = *envelope.tx_hash();
            env.submit_tx(envelope.encoded_2718(), hash).await?;

            // Now sign tx with the unauthorized key
            let new_nonce = env.provider().get_transaction_count(root_addr).await?;
            tx = create_basic_aa_tx(chain_id, new_nonce, tx.calls.clone(), 2_000_000);

            let sig = sign_aa_tx_with_p256_access_key(
                &tx,
                &unauth_signing,
                &unauth_pub_x,
                &unauth_pub_y,
                root_addr,
            )?;
            let envelope: TempoTxEnvelope = tx.into_signed(sig).into();
            env.submit_tx_expecting_rejection(envelope.encoded_2718(), None)
                .await?;
            return Ok(());
        }
        KeySetup::InvalidAuthSignature => {
            assert!(matches!(test_case.expected, ExpectedOutcome::Rejection));

            match test_case.key_type {
                KeyType::Secp256k1 => {
                    // KeyAuthorization signed by a wrong secp256k1 signer
                    let access_signer = PrivateKeySigner::random();
                    let access_addr = access_signer.address();
                    let wrong_root = PrivateKeySigner::random();

                    let key_auth = KeyAuthorization {
                        chain_id,
                        key_type: SignatureType::Secp256k1,
                        key_id: access_addr,
                        expiry: None,
                        limits: None,
                    };
                    let wrong_sig = wrong_root.sign_hash_sync(&key_auth.signature_hash())?;
                    let invalid_key_auth =
                        key_auth.into_signed(PrimitiveSignature::Secp256k1(wrong_sig));

                    tx.key_authorization = Some(invalid_key_auth);
                    let sig = sign_aa_tx_secp256k1(&tx, &root_signer)?;
                    let envelope: TempoTxEnvelope = tx.into_signed(sig).into();
                    env.submit_tx_expecting_rejection(envelope.encoded_2718(), None)
                        .await?;
                    return Ok(());
                }
                _ => {
                    // P256 / WebAuthn path (existing logic)
                    use tempo_primitives::transaction::tt_signature::{
                        P256SignatureWithPreHash, normalize_p256_s,
                    };

                    let (another_key, pub_x_3, pub_y_3, addr_3) = generate_p256_access_key();
                    let (wrong_signer_key, wrong_pub_x, wrong_pub_y, _) =
                        generate_p256_access_key();

                    let auth_message_hash = KeyAuthorization {
                        chain_id,
                        key_type: SignatureType::P256,
                        key_id: addr_3,
                        expiry: None,
                        limits: None,
                    }
                    .signature_hash();

                    use p256::ecdsa::signature::hazmat::PrehashSigner;
                    use sha2::{Digest, Sha256};
                    let wrong_sig_hash =
                        B256::from_slice(Sha256::digest(auth_message_hash).as_ref());
                    let wrong_signature: p256::ecdsa::Signature =
                        wrong_signer_key.sign_prehash(wrong_sig_hash.as_slice())?;
                    let wrong_sig_bytes = wrong_signature.to_bytes();

                    let invalid_key_auth = KeyAuthorization {
                        chain_id,
                        key_type: SignatureType::P256,
                        key_id: addr_3,
                        expiry: None,
                        limits: None,
                    }
                    .into_signed(PrimitiveSignature::P256(P256SignatureWithPreHash {
                        r: B256::from_slice(&wrong_sig_bytes[0..32]),
                        s: normalize_p256_s(&wrong_sig_bytes[32..64]),
                        pub_key_x: wrong_pub_x,
                        pub_key_y: wrong_pub_y,
                        pre_hash: true,
                    }));

                    tx.key_authorization = Some(invalid_key_auth);
                    let sig = sign_aa_tx_with_p256_access_key(
                        &tx,
                        &another_key,
                        &pub_x_3,
                        &pub_y_3,
                        root_addr,
                    )?;
                    let envelope: TempoTxEnvelope = tx.into_signed(sig).into();
                    env.submit_tx_expecting_rejection(envelope.encoded_2718(), None)
                        .await?;
                    return Ok(());
                }
            }
        }
    }

    // --- RootKey / ZeroPubKey path: sign with root key ---
    match test_case.key_type {
        KeyType::Secp256k1 => {
            let fee_payer_ctx = configure_fee_payer_context(
                env.provider(),
                &mut tx,
                test_case.fee_payer,
                root_addr,
                &fee_payer_signer,
            )
            .await?;

            let signature = sign_aa_tx_secp256k1(&tx, &root_signer)?;
            let envelope: TempoTxEnvelope = tx.into_signed(signature).into();

            submit_expecting(
                env,
                envelope,
                test_case.expected,
                test_case.sync,
                fee_payer_ctx,
            )
            .await?;

            if matches!(test_case.expected, ExpectedOutcome::Revert) {
                let nonce_after = env.provider().get_transaction_count(root_addr).await?;
                assert_eq!(
                    nonce_after,
                    nonce_before + 1,
                    "Nonce should bump even on revert"
                );
            }
        }
        KeyType::P256 | KeyType::WebAuthn => {
            let (signing_key, pub_key_x, pub_key_y, signer_addr) = generate_p256_access_key();
            if !test_case.fee_payer {
                let _ = env.fund_account(signer_addr).await?;
            }

            let mut tx = create_basic_aa_tx(
                chain_id,
                env.provider().get_transaction_count(signer_addr).await?,
                calls,
                2_000_000,
            );

            if matches!(test_case.test_action, TestAction::InvalidCreate) {
                tx.fee_token = None;
            }

            let fee_payer_ctx = configure_fee_payer_context(
                env.provider(),
                &mut tx,
                test_case.fee_payer,
                signer_addr,
                &fee_payer_signer,
            )
            .await?;

            let signature = match test_case.key_type {
                KeyType::P256 => sign_aa_tx_p256(&tx, &signing_key, pub_key_x, pub_key_y)?,
                KeyType::WebAuthn => sign_aa_tx_webauthn(
                    &tx,
                    &signing_key,
                    pub_key_x,
                    pub_key_y,
                    "https://example.com",
                )?,
                KeyType::Secp256k1 => unreachable!("handled above"),
            };

            let envelope: TempoTxEnvelope = tx.into_signed(signature).into();

            submit_expecting(
                env,
                envelope,
                test_case.expected,
                test_case.sync,
                fee_payer_ctx,
            )
            .await?;
        }
    }

    Ok(())
}

/// Internal pre-step variants for access key cases.
enum AccessKeyPreStep {
    DuplicateAuth,
    UnauthorizedAuthorize,
}

/// Shared logic for access key raw-send cases (AccessKey, DuplicateAuth, UnauthorizedAuthorize).
#[allow(clippy::too_many_arguments)]
async fn run_raw_access_key_case<E: TestEnv>(
    env: &mut E,
    test_case: &RawSendTestCase,
    root_signer: &PrivateKeySigner,
    root_addr: Address,
    fee_payer_signer: &PrivateKeySigner,
    tx: &mut TempoTransaction,
    nonce_before: u64,
    chain_id: u64,
    auth_chain_id_value: u64,
    expiry: Option<u64>,
    spending_limits: Option<Vec<TokenLimit>>,
    pre_step: Option<AccessKeyPreStep>,
) -> eyre::Result<()> {
    match test_case.key_type {
        KeyType::Secp256k1 => {
            let access_signer = PrivateKeySigner::random();
            let access_addr = access_signer.address();

            let key_auth = create_key_authorization(
                root_signer,
                access_addr,
                create_mock_secp256k1_sig(),
                auth_chain_id_value,
                expiry,
                spending_limits,
            )?;

            match pre_step {
                Some(AccessKeyPreStep::DuplicateAuth) => {
                    let mut setup_tx = create_basic_aa_tx(
                        chain_id,
                        nonce_before,
                        vec![create_balance_of_call(root_addr)],
                        2_000_000,
                    );
                    setup_tx.key_authorization = Some(key_auth.clone());
                    let setup_sig = sign_aa_tx_secp256k1(&setup_tx, root_signer)?;
                    let setup_envelope: TempoTxEnvelope = setup_tx.into_signed(setup_sig).into();
                    let setup_hash = *setup_envelope.tx_hash();
                    env.submit_tx(setup_envelope.encoded_2718(), setup_hash)
                        .await?;

                    let new_nonce = env.provider().get_transaction_count(root_addr).await?;
                    *tx = create_basic_aa_tx(chain_id, new_nonce, tx.calls.clone(), 2_000_000);
                    tx.key_authorization = Some(key_auth);
                }
                Some(AccessKeyPreStep::UnauthorizedAuthorize) => {
                    unreachable!("secp256k1 does not support UnauthorizedAuthorize")
                }
                None => {
                    tx.key_authorization = Some(key_auth);
                }
            }

            let fee_payer_ctx = configure_fee_payer_context(
                env.provider(),
                tx,
                test_case.fee_payer,
                root_addr,
                fee_payer_signer,
            )
            .await?;

            let sig = sign_aa_tx_with_secp256k1_access_key(tx, &access_signer, root_addr)?;
            let envelope: TempoTxEnvelope = tx.clone().into_signed(sig).into();

            submit_expecting(
                env,
                envelope,
                test_case.expected,
                test_case.sync,
                fee_payer_ctx,
            )
            .await?;
            Ok(())
        }
        KeyType::P256 | KeyType::WebAuthn => {
            let (access_signing_key, access_pub_x, access_pub_y, access_key_addr) =
                generate_p256_access_key();
            let mock_sig = match test_case.key_type {
                KeyType::P256 => create_mock_p256_sig(access_pub_x, access_pub_y),
                KeyType::WebAuthn => create_mock_webauthn_sig(access_pub_x, access_pub_y),
                _ => unreachable!(),
            };

            let key_auth = create_key_authorization(
                root_signer,
                access_key_addr,
                mock_sig,
                auth_chain_id_value,
                expiry,
                spending_limits.clone(),
            )?;

            match pre_step {
                Some(AccessKeyPreStep::UnauthorizedAuthorize) => {
                    // Authorize key1 first via a setup tx (root signs)
                    let mut setup_tx = create_basic_aa_tx(
                        chain_id,
                        nonce_before,
                        vec![create_balance_of_call(root_addr)],
                        2_000_000,
                    );
                    setup_tx.key_authorization = Some(key_auth.clone());
                    let setup_sig = sign_aa_tx_secp256k1(&setup_tx, root_signer)?;
                    let setup_envelope: TempoTxEnvelope = setup_tx.into_signed(setup_sig).into();
                    let setup_hash = *setup_envelope.tx_hash();
                    env.submit_tx(setup_envelope.encoded_2718(), setup_hash)
                        .await?;

                    // Now key1 tries to authorize key2 (unauthorized)
                    let (_, pub_x_2, pub_y_2, access_addr_2) = generate_p256_access_key();
                    let mock_sig_2 = match test_case.key_type {
                        KeyType::P256 => create_mock_p256_sig(pub_x_2, pub_y_2),
                        KeyType::WebAuthn => create_mock_webauthn_sig(pub_x_2, pub_y_2),
                        _ => unreachable!(),
                    };
                    let key_auth_2 = create_key_authorization(
                        root_signer,
                        access_addr_2,
                        mock_sig_2,
                        auth_chain_id_value,
                        None,
                        Some(vec![]),
                    )?;

                    let new_nonce = env.provider().get_transaction_count(root_addr).await?;
                    *tx = create_basic_aa_tx(
                        chain_id,
                        new_nonce,
                        vec![Call {
                            to: Address::random().into(),
                            value: U256::ZERO,
                            input: Bytes::new(),
                        }],
                        2_000_000,
                    );
                    tx.key_authorization = Some(key_auth_2);
                }
                Some(AccessKeyPreStep::DuplicateAuth) => {
                    // Authorize key first, then re-use same auth (duplicate)
                    let mut setup_tx = create_basic_aa_tx(
                        chain_id,
                        nonce_before,
                        vec![create_balance_of_call(root_addr)],
                        2_000_000,
                    );
                    setup_tx.key_authorization = Some(key_auth.clone());
                    let setup_sig = sign_aa_tx_secp256k1(&setup_tx, root_signer)?;
                    let setup_envelope: TempoTxEnvelope = setup_tx.into_signed(setup_sig).into();
                    let setup_hash = *setup_envelope.tx_hash();
                    env.submit_tx(setup_envelope.encoded_2718(), setup_hash)
                        .await?;

                    let new_nonce = env.provider().get_transaction_count(root_addr).await?;
                    *tx = create_basic_aa_tx(chain_id, new_nonce, tx.calls.clone(), 2_000_000);
                    tx.key_authorization = Some(key_auth);
                }
                None => {
                    tx.key_authorization = Some(key_auth);
                }
            }

            let fee_payer_ctx = configure_fee_payer_context(
                env.provider(),
                tx,
                test_case.fee_payer,
                root_addr,
                fee_payer_signer,
            )
            .await?;

            let sig = match test_case.key_type {
                KeyType::P256 => sign_aa_tx_with_p256_access_key(
                    tx,
                    &access_signing_key,
                    &access_pub_x,
                    &access_pub_y,
                    root_addr,
                )?,
                KeyType::WebAuthn => sign_aa_tx_with_webauthn_access_key(
                    tx,
                    &access_signing_key,
                    access_pub_x,
                    access_pub_y,
                    "https://example.com",
                    root_addr,
                )?,
                _ => unreachable!(),
            };

            let envelope: TempoTxEnvelope = tx.clone().into_signed(sig).into();

            submit_expecting(
                env,
                envelope,
                test_case.expected,
                test_case.sync,
                fee_payer_ctx,
            )
            .await?;
            Ok(())
        }
    }
}

pub(super) async fn run_send_case<E: TestEnv>(
    env: &mut E,
    test_case: &SendTestCase,
) -> eyre::Result<()> {
    println!("\n=== Send transaction test: {} ===\n", test_case.name);

    if test_case.key_type == KeyType::Secp256k1 && test_case.access_key {
        return Err(eyre::eyre!(
            "secp256k1 access key not supported in send matrix"
        ));
    }
    if test_case.key_type == KeyType::Secp256k1 && test_case.batch_calls {
        return Err(eyre::eyre!(
            "secp256k1 batch calls not supported in send matrix"
        ));
    }

    let chain_id = env.chain_id();

    if test_case.access_key {
        let root_signer = PrivateKeySigner::random();
        let root_addr = root_signer.address();
        let funded = env.fund_account(root_addr).await?;
        let transfer_amount = resolve_send_amounts(test_case, funded);

        let (access_signing_key, access_pub_key_x, access_pub_key_y, access_key_addr) =
            generate_p256_access_key();
        let access_signature = match test_case.key_type {
            KeyType::P256 => create_mock_p256_sig(access_pub_key_x, access_pub_key_y),
            KeyType::WebAuthn => create_mock_webauthn_sig(access_pub_key_x, access_pub_key_y),
            KeyType::Secp256k1 => unreachable!("guarded above"),
        };
        let key_auth = create_key_authorization(
            &root_signer,
            access_key_addr,
            access_signature,
            chain_id,
            None,
            Some(create_default_token_limit(funded)),
        )?;

        let recipient_1 = Address::random();
        let recipient_2 = if test_case.batch_calls {
            Some(Address::random())
        } else {
            None
        };
        let mut tx = create_basic_aa_tx(
            chain_id,
            env.provider().get_transaction_count(root_addr).await?,
            create_send_calls(
                recipient_1,
                recipient_2,
                DEFAULT_FEE_TOKEN,
                test_case.batch_calls,
                transfer_amount,
            ),
            2_000_000,
        );
        tx.key_authorization = Some(key_auth);

        let fee_payer_signer = PrivateKeySigner::random();
        if test_case.fee_payer {
            let _ = env.fund_account(fee_payer_signer.address()).await?;
        }
        let fee_payer_ctx = configure_fee_payer_context(
            env.provider(),
            &mut tx,
            test_case.fee_payer,
            root_addr,
            &fee_payer_signer,
        )
        .await?;

        let signature = match test_case.key_type {
            KeyType::P256 => sign_aa_tx_with_p256_access_key(
                &tx,
                &access_signing_key,
                &access_pub_key_x,
                &access_pub_key_y,
                root_addr,
            )?,
            KeyType::WebAuthn => sign_aa_tx_with_webauthn_access_key(
                &tx,
                &access_signing_key,
                access_pub_key_x,
                access_pub_key_y,
                "https://example.com",
                root_addr,
            )?,
            KeyType::Secp256k1 => unreachable!("guarded above"),
        };

        let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
        let tx_hash = *envelope.tx_hash();
        let receipt = env.submit_tx(envelope.encoded_2718(), tx_hash).await?;
        if let Some(ctx) = fee_payer_ctx {
            assert_fee_payer_spent(env.provider(), ctx, &receipt).await?;
        }

        if test_case.batch_calls {
            assert_batch_recipient_balances(
                env.provider(),
                DEFAULT_FEE_TOKEN,
                recipient_1,
                recipient_2.expect("batch_calls requires recipient_2"),
                transfer_amount,
            )
            .await?;
        }

        return Ok(());
    }

    match test_case.key_type {
        KeyType::Secp256k1 => {
            let signer = PrivateKeySigner::random();
            let signer_addr = signer.address();
            let funded = if !test_case.fee_payer {
                env.fund_account(signer_addr).await?
            } else {
                rand_funding_amount()
            };
            let transfer_amount = resolve_send_amounts(test_case, funded);

            let recipient = Address::random();
            let mut tx = create_basic_aa_tx(
                chain_id,
                env.provider().get_transaction_count(signer_addr).await?,
                create_send_calls(recipient, None, DEFAULT_FEE_TOKEN, false, transfer_amount),
                2_000_000,
            );

            let fee_payer_signer = PrivateKeySigner::random();
            if test_case.fee_payer {
                let _ = env.fund_account(fee_payer_signer.address()).await?;
            }
            let fee_payer_ctx = configure_fee_payer_context(
                env.provider(),
                &mut tx,
                test_case.fee_payer,
                signer_addr,
                &fee_payer_signer,
            )
            .await?;

            let signature = sign_aa_tx_secp256k1(&tx, &signer)?;
            let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
            let tx_hash = *envelope.tx_hash();
            let receipt = env.submit_tx(envelope.encoded_2718(), tx_hash).await?;
            if let Some(ctx) = fee_payer_ctx {
                assert_fee_payer_spent(env.provider(), ctx, &receipt).await?;
            }
            assert_token_balance(
                env.provider(),
                DEFAULT_FEE_TOKEN,
                recipient,
                transfer_amount,
                "Recipient should receive transfer",
            )
            .await?;
        }
        KeyType::P256 | KeyType::WebAuthn => {
            let (signing_key, pub_key_x, pub_key_y, signer_addr) = generate_p256_access_key();
            let funded = if !test_case.fee_payer {
                env.fund_account(signer_addr).await?
            } else {
                rand_funding_amount()
            };
            let transfer_amount = resolve_send_amounts(test_case, funded);

            let recipient_1 = Address::random();
            let recipient_2 = if test_case.batch_calls {
                Some(Address::random())
            } else {
                None
            };

            // For batch calls, each transfer gets half the funded amount
            let batch_transfer = if test_case.batch_calls {
                rand_sub_amount(funded / U256::from(3))
            } else {
                transfer_amount
            };

            let mut tx = create_basic_aa_tx(
                chain_id,
                env.provider().get_transaction_count(signer_addr).await?,
                create_send_calls(
                    recipient_1,
                    recipient_2,
                    DEFAULT_FEE_TOKEN,
                    test_case.batch_calls,
                    batch_transfer,
                ),
                2_000_000,
            );

            let fee_payer_signer = PrivateKeySigner::random();
            if test_case.fee_payer {
                let _ = env.fund_account(fee_payer_signer.address()).await?;
            }
            let fee_payer_ctx = configure_fee_payer_context(
                env.provider(),
                &mut tx,
                test_case.fee_payer,
                signer_addr,
                &fee_payer_signer,
            )
            .await?;

            let signature = match test_case.key_type {
                KeyType::P256 => sign_aa_tx_p256(&tx, &signing_key, pub_key_x, pub_key_y)?,
                KeyType::WebAuthn => sign_aa_tx_webauthn(
                    &tx,
                    &signing_key,
                    pub_key_x,
                    pub_key_y,
                    "https://example.com",
                )?,
                KeyType::Secp256k1 => unreachable!("handled above"),
            };

            let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
            let tx_hash = *envelope.tx_hash();
            let receipt = env.submit_tx(envelope.encoded_2718(), tx_hash).await?;
            if let Some(ctx) = fee_payer_ctx {
                assert_fee_payer_spent(env.provider(), ctx, &receipt).await?;
            }

            if test_case.batch_calls {
                assert_batch_recipient_balances(
                    env.provider(),
                    DEFAULT_FEE_TOKEN,
                    recipient_1,
                    recipient_2.expect("batch_calls requires recipient_2"),
                    batch_transfer,
                )
                .await?;
            } else {
                assert_token_balance(
                    env.provider(),
                    DEFAULT_FEE_TOKEN,
                    recipient_1,
                    transfer_amount,
                    "Recipient should receive transfer",
                )
                .await?;
            }
        }
    }

    Ok(())
}

pub(super) async fn run_fill_sign_send<E: TestEnv>(
    env: &mut E,
    test_case: &FillTestCase,
) -> eyre::Result<()> {
    println!("\n=== E2E Test: {} ===\n", test_case.name);
    println!("  nonce_mode: {:?}", test_case.nonce_mode);
    println!("  key_type: {:?}", test_case.key_type);

    let uses_p256 = matches!(test_case.key_type, KeyType::P256 | KeyType::WebAuthn);
    let chain_id = env.chain_id();

    if uses_p256 && test_case.pre_bump_nonce.is_some() {
        return Err(eyre::eyre!(
            "pre_bump_nonce is only supported for secp256k1 cases"
        ));
    }

    let tx_hash = if uses_p256 {
        let (signing_key, pub_key_x, pub_key_y, signer_addr) = generate_p256_access_key();

        // In the E2E fill flow, P256/WebAuthn signers use a fee payer
        // to cover gas (the fee_payer flag on FillTestCase is not checked
        // here because eth_fillTransaction always requires one).
        let fee_payer_signer = PrivateKeySigner::random();
        let _ = env.fund_account(fee_payer_signer.address()).await?;

        let current_timestamp = env.current_block_timestamp().await?;

        let fill_result =
            fill_transaction_from_case(env.provider(), test_case, signer_addr, current_timestamp)
                .await;

        let (mut tx, _request_context) = match fill_result {
            Ok(pair) => pair,
            Err(e) => {
                if matches!(test_case.expected, ExpectedOutcome::Rejection) {
                    println!("  Fill rejected as expected: {e}");
                    println!("✓ Test passed: {}", test_case.name);
                    return Ok(());
                }
                return Err(e);
            }
        };

        assert_eq!(
            tx.chain_id, chain_id,
            "eth_fillTransaction should return matching chain_id"
        );
        assert!(
            tx.fee_token.is_none(),
            "eth_fillTransaction should not set fee_token (client must set it)"
        );
        tx.fee_token = Some(DEFAULT_FEE_TOKEN);
        sign_fee_payer(&mut tx, signer_addr, &fee_payer_signer)?;

        let signature = match test_case.key_type {
            KeyType::P256 => sign_aa_tx_p256(&tx, &signing_key, pub_key_x, pub_key_y)?,
            KeyType::WebAuthn => sign_aa_tx_webauthn(
                &tx,
                &signing_key,
                pub_key_x,
                pub_key_y,
                "https://example.com",
            )?,
            KeyType::Secp256k1 => unreachable!(),
        };

        let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
        submit_expecting(env, envelope, test_case.expected, false, None).await?
    } else {
        let signer = PrivateKeySigner::random();
        let signer_addr = signer.address();
        if !test_case.fee_payer {
            let _ = env.fund_account(signer_addr).await?;
        }

        if let Some(count) = test_case.pre_bump_nonce {
            env.bump_protocol_nonce(&signer, signer_addr, count).await?;
        }

        let current_timestamp = env.current_block_timestamp().await?;
        let initial_protocol_nonce = env.provider().get_transaction_count(signer_addr).await?;

        let fill_result =
            fill_transaction_from_case(env.provider(), test_case, signer_addr, current_timestamp)
                .await;

        let (mut tx, request_context) = match fill_result {
            Ok(pair) => pair,
            Err(e) => {
                if matches!(test_case.expected, ExpectedOutcome::Rejection) {
                    println!("  Fill rejected as expected: {e}");
                    println!("✓ Test passed: {}", test_case.name);
                    return Ok(());
                }
                return Err(e);
            }
        };

        assert!(
            tx.fee_token.is_none(),
            "eth_fillTransaction should not set fee_token (client must set it)"
        );
        tx.fee_token = Some(DEFAULT_FEE_TOKEN);
        if request_context.expected_valid_before.is_none() {
            assert!(
                tx.valid_before.is_none(),
                "eth_fillTransaction should not set validBefore when not provided"
            );
            tx.valid_before = Some(u64::MAX);
        }

        let fee_payer_signer = PrivateKeySigner::random();
        if test_case.fee_payer {
            let _ = env.fund_account(fee_payer_signer.address()).await?;
            sign_fee_payer(&mut tx, signer_addr, &fee_payer_signer)?;
        }

        let signature = sign_aa_tx_secp256k1(&tx, &signer)?;
        let envelope: TempoTxEnvelope = tx.into_signed(signature).into();

        let tx_hash = submit_expecting(env, envelope, test_case.expected, false, None).await?;

        if matches!(test_case.expected, ExpectedOutcome::Success) {
            let final_protocol_nonce = env.provider().get_transaction_count(signer_addr).await?;
            let should_increment = matches!(test_case.nonce_mode, NonceMode::Protocol);
            if should_increment {
                assert_eq!(final_protocol_nonce, initial_protocol_nonce + 1);
            } else {
                assert_eq!(final_protocol_nonce, initial_protocol_nonce);
            }
        }

        tx_hash
    };

    // After successful submission, verify nonceKey in mined transaction via RPC
    if matches!(test_case.expected, ExpectedOutcome::Success) {
        let expected_nonce_key = match test_case.nonce_mode {
            NonceMode::Protocol => U256::ZERO,
            NonceMode::TwoD(key) => U256::from(key),
            NonceMode::Expiring
            | NonceMode::ExpiringAtBoundary
            | NonceMode::ExpiringExceedsBoundary
            | NonceMode::ExpiringInPast => TEMPO_EXPIRING_NONCE_KEY,
        };

        let raw_tx: Option<serde_json::Value> = env
            .provider()
            .raw_request("eth_getTransactionByHash".into(), [tx_hash])
            .await?;
        let tx_data = raw_tx.expect("Mined transaction should be retrievable via RPC");
        let nonce_key_str = tx_data["nonceKey"]
            .as_str()
            .expect("nonceKey field should be present in transaction response");
        let actual_nonce_key: U256 = nonce_key_str
            .parse()
            .expect("nonceKey should be valid U256");
        assert_eq!(
            actual_nonce_key, expected_nonce_key,
            "nonceKey mismatch: expected {expected_nonce_key}, got {actual_nonce_key}"
        );
        println!("  ✓ nonceKey verified: {expected_nonce_key}");
    }

    println!("✓ Test passed: {}", test_case.name);
    Ok(())
}

// ===========================================================================
// Scenario runners (migrated from localnet-only tests)
// ===========================================================================

/// Multi-party fee payer cosign: encode → decode → cosign → submit.
pub(super) async fn run_fee_payer_cosign_scenario<E: TestEnv>(env: &mut E) -> eyre::Result<()> {
    println!("\n=== Fee payer cosign scenario ===\n");

    let chain_id = env.chain_id();

    let fee_payer_signer = PrivateKeySigner::random();
    let fee_payer_addr = fee_payer_signer.address();
    let _ = env.fund_account(fee_payer_addr).await?;

    let user_signer = PrivateKeySigner::random();
    let user_addr = user_signer.address();

    let fee_payer_balance_before =
        tempo_precompiles::tip20::ITIP20::new(DEFAULT_FEE_TOKEN, env.provider())
            .balanceOf(fee_payer_addr)
            .call()
            .await?;

    let mut tx = create_basic_aa_tx(
        chain_id,
        0,
        vec![Call {
            to: Address::random().into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        2_000_000,
    );
    tx.fee_payer_signature = Some(alloy::primitives::Signature::new(
        U256::ZERO,
        U256::ZERO,
        false,
    ));

    let user_signature = sign_aa_tx_secp256k1(&tx, &user_signer)?;
    let sign_only_envelope: TempoTxEnvelope = tx.into_signed(user_signature).into();
    let sign_only_encoded = sign_only_envelope.encoded_2718();

    let decoded = TempoTxEnvelope::decode_2718(&mut sign_only_encoded.as_slice())?;
    let (mut decoded_tx, decoded_sig) = match decoded {
        TempoTxEnvelope::AA(aa_tx) => (aa_tx.tx().clone(), aa_tx.signature().clone()),
        _ => return Err(eyre::eyre!("Expected AA transaction")),
    };

    let fee_payer_sig_hash = decoded_tx.fee_payer_signature_hash(user_addr);
    let fee_payer_signature = fee_payer_signer.sign_hash_sync(&fee_payer_sig_hash)?;
    decoded_tx.fee_payer_signature = Some(fee_payer_signature);

    let final_envelope: TempoTxEnvelope = decoded_tx.into_signed(decoded_sig).into();
    let tx_hash = *final_envelope.tx_hash();

    let receipt = env
        .submit_tx(final_envelope.encoded_2718(), tx_hash)
        .await?;
    assert_eq!(
        receipt["status"].as_str(),
        Some("0x1"),
        "Cosigned transaction should succeed"
    );

    let fee_payer_ctx = FeePayerContext {
        addr: fee_payer_addr,
        token: DEFAULT_FEE_TOKEN,
        balance_before: fee_payer_balance_before,
    };
    assert_fee_payer_spent(env.provider(), fee_payer_ctx, &receipt).await?;

    println!("✓ Fee payer cosign scenario passed");
    Ok(())
}

/// EIP-7702 authorization list with 3 key types.
pub(super) async fn run_authorization_list_scenario<E: TestEnv>(env: &mut E) -> eyre::Result<()> {
    use tempo_primitives::transaction::TempoSignedAuthorization;

    println!("\n=== Authorization list scenario ===\n");

    let chain_id = env.chain_id();

    let sender_signer = PrivateKeySigner::random();
    let sender_addr = sender_signer.address();
    let _ = env.fund_account(sender_addr).await?;

    let delegate_address = tempo_precompiles::ACCOUNT_KEYCHAIN_ADDRESS;

    // Authority 1: Secp256k1
    let auth1_signer = PrivateKeySigner::random();
    let auth1_addr = auth1_signer.address();
    let (auth1, sig_hash1) = build_authorization(chain_id, delegate_address);
    let sig1 = auth1_signer.sign_hash_sync(&sig_hash1)?;
    let auth1_signed = TempoSignedAuthorization::new_unchecked(
        auth1,
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(sig1)),
    );

    // Authority 2: P256
    let (auth2_key, pub2_x, pub2_y, auth2_addr) = generate_p256_access_key();
    let (auth2, sig_hash2) = build_authorization(chain_id, delegate_address);
    let inner2 = sign_p256_primitive(sig_hash2, &auth2_key, pub2_x, pub2_y)?;
    let auth2_signed =
        TempoSignedAuthorization::new_unchecked(auth2, TempoSignature::Primitive(inner2));

    // Authority 3: WebAuthn
    let (auth3_key, pub3_x, pub3_y, auth3_addr) = generate_p256_access_key();
    let (auth3, sig_hash3) = build_authorization(chain_id, delegate_address);
    let inner3 =
        sign_webauthn_primitive(sig_hash3, &auth3_key, pub3_x, pub3_y, "https://example.com")?;
    let auth3_signed =
        TempoSignedAuthorization::new_unchecked(auth3, TempoSignature::Primitive(inner3));

    // Verify BEFORE state
    assert!(env.provider().get_code_at(auth1_addr).await?.is_empty());

    let recipient = Address::random();
    let tx_request = TempoTransactionRequest {
        inner: TransactionRequest {
            from: Some(sender_addr),
            to: Some(recipient.into()),
            value: Some(U256::ZERO),
            gas: Some(2_000_000),
            max_fee_per_gas: Some(tempo_chainspec::spec::TEMPO_T1_BASE_FEE as u128),
            max_priority_fee_per_gas: Some(tempo_chainspec::spec::TEMPO_T1_BASE_FEE as u128),
            nonce: Some(env.provider().get_transaction_count(sender_addr).await?),
            chain_id: Some(chain_id),
            ..Default::default()
        },
        calls: vec![Call {
            to: recipient.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        fee_token: Some(DEFAULT_FEE_TOKEN),
        tempo_authorization_list: vec![auth1_signed, auth2_signed, auth3_signed],
        ..Default::default()
    };

    let tx = tx_request
        .build_aa()
        .map_err(|e| eyre::eyre!("Failed to build AA tx: {:?}", e))?;

    let signature = sign_aa_tx_secp256k1(&tx, &sender_signer)?;
    let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
    let tx_hash = *envelope.tx_hash();

    let receipt = env.submit_tx(envelope.encoded_2718(), tx_hash).await?;
    assert_eq!(receipt["status"].as_str(), Some("0x1"));

    // Verify AFTER state: delegation code
    let auth1_code_after = env.provider().get_code_at(auth1_addr).await?;
    verify_delegation_code(
        &auth1_code_after,
        delegate_address,
        "Authority 1 (Secp256k1)",
    );

    let auth2_code_after = env.provider().get_code_at(auth2_addr).await?;
    verify_delegation_code(&auth2_code_after, delegate_address, "Authority 2 (P256)");

    let auth3_code_after = env.provider().get_code_at(auth3_addr).await?;
    verify_delegation_code(
        &auth3_code_after,
        delegate_address,
        "Authority 3 (WebAuthn)",
    );

    println!("✓ Authorization list scenario passed");
    Ok(())
}

/// Keychain authorization in auth list is skipped (attack prevention).
pub(super) async fn run_keychain_auth_list_skipped_scenario<E: TestEnv>(
    env: &mut E,
) -> eyre::Result<()> {
    use tempo_primitives::transaction::{
        TempoSignedAuthorization, tt_signature::KeychainSignature,
    };

    println!("\n=== Keychain auth list skipped scenario ===\n");

    let chain_id = env.chain_id();

    let sender_signer = PrivateKeySigner::random();
    let sender_addr = sender_signer.address();
    let _ = env.fund_account(sender_addr).await?;

    let attacker_signer = PrivateKeySigner::random();
    let victim_addr = Address::random();
    let delegate_address = attacker_signer.address();

    let victim_nonce_before = env.provider().get_transaction_count(victim_addr).await?;
    let victim_code_before = env.provider().get_code_at(victim_addr).await?;

    let auth = alloy_eips::eip7702::Authorization {
        chain_id: alloy_primitives::U256::from(chain_id),
        address: delegate_address,
        nonce: victim_nonce_before,
    };
    let sig_hash = compute_authorization_signature_hash(&auth);
    let attacker_signature = attacker_signer.sign_hash_sync(&sig_hash)?;
    let inner_sig = PrimitiveSignature::Secp256k1(attacker_signature);
    let keychain_sig = KeychainSignature::new(victim_addr, inner_sig);
    let spoofed_sig = TempoSignature::Keychain(keychain_sig);
    let spoofed_auth = TempoSignedAuthorization::new_unchecked(auth, spoofed_sig);

    let recovered = spoofed_auth.recover_authority()?;
    assert_eq!(recovered, victim_addr);

    let recipient = Address::random();
    let sender_nonce_before = env.provider().get_transaction_count(sender_addr).await?;
    let tx_request = TempoTransactionRequest {
        inner: TransactionRequest {
            from: Some(sender_addr),
            to: Some(recipient.into()),
            value: Some(U256::ZERO),
            gas: Some(2_000_000),
            max_fee_per_gas: Some(tempo_chainspec::spec::TEMPO_T1_BASE_FEE as u128),
            max_priority_fee_per_gas: Some(tempo_chainspec::spec::TEMPO_T1_BASE_FEE as u128),
            nonce: Some(sender_nonce_before),
            chain_id: Some(chain_id),
            ..Default::default()
        },
        calls: vec![Call {
            to: recipient.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        fee_token: Some(DEFAULT_FEE_TOKEN),
        tempo_authorization_list: vec![spoofed_auth],
        ..Default::default()
    };

    let tx = tx_request
        .build_aa()
        .map_err(|e| eyre::eyre!("Failed to build AA tx: {:?}", e))?;

    let signature = sign_aa_tx_secp256k1(&tx, &sender_signer)?;
    let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
    let tx_hash = *envelope.tx_hash();

    let receipt = env
        .submit_tx_unchecked(envelope.encoded_2718(), tx_hash)
        .await?;
    let status = receipt["status"].as_str().unwrap_or("0x0");
    assert_eq!(
        status, "0x1",
        "Keychain-auth-list tx should succeed (auth skipped, not rejected)"
    );
    let sender_nonce_after = env.provider().get_transaction_count(sender_addr).await?;
    assert_eq!(
        sender_nonce_after,
        sender_nonce_before + 1,
        "Sender nonce should have incremented"
    );

    let victim_nonce_after = env.provider().get_transaction_count(victim_addr).await?;
    let victim_code_after = env.provider().get_code_at(victim_addr).await?;

    assert_eq!(victim_nonce_before, victim_nonce_after);
    assert_eq!(victim_code_before.len(), victim_code_after.len());
    assert!(victim_code_after.is_empty());

    println!("✓ Keychain auth list skipped scenario passed");
    Ok(())
}

/// Key expiry: never-expires → short-expiry → advance time → expired → past-expiry.
pub(super) async fn run_keychain_expiry_scenario<E: TestEnv>(env: &mut E) -> eyre::Result<()> {
    println!("\n=== Keychain expiry scenario ===\n");

    let chain_id = env.chain_id();

    let root_signer = PrivateKeySigner::random();
    let root_addr = root_signer.address();
    let funded = env.fund_account(root_addr).await?;

    let (never_signing, never_pub_x, never_pub_y, never_addr) = generate_p256_access_key();
    let (short_signing, short_pub_x, short_pub_y, short_addr) = generate_p256_access_key();
    let (_past_signing, past_pub_x, past_pub_y, past_addr) = generate_p256_access_key();

    let mut nonce = env.provider().get_transaction_count(root_addr).await?;
    // Use a small fraction to leave room for gas across multiple operations
    let transfer_amount = rand_sub_amount(funded / U256::from(4));

    // TEST 1: Never-expires key
    let never_auth = create_key_authorization(
        &root_signer,
        never_addr,
        create_mock_p256_sig(never_pub_x, never_pub_y),
        chain_id,
        None,
        Some(create_default_token_limit(funded)),
    )?;
    let mut auth_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_balance_of_call(root_addr)],
        2_000_000,
    );
    auth_tx.key_authorization = Some(never_auth);
    let sig = sign_aa_tx_secp256k1(&auth_tx, &root_signer)?;
    let envelope: TempoTxEnvelope = auth_tx.into_signed(sig).into();
    let hash = *envelope.tx_hash();
    env.submit_tx(envelope.encoded_2718(), hash).await?;
    nonce += 1;

    let recipient1 = Address::random();
    let transfer_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_transfer_call(
            DEFAULT_FEE_TOKEN,
            recipient1,
            transfer_amount,
        )],
        2_000_000,
    );
    let never_sig = sign_aa_tx_with_p256_access_key(
        &transfer_tx,
        &never_signing,
        &never_pub_x,
        &never_pub_y,
        root_addr,
    )?;
    let envelope: TempoTxEnvelope = transfer_tx.into_signed(never_sig).into();
    let hash = *envelope.tx_hash();
    env.submit_tx(envelope.encoded_2718(), hash).await?;
    nonce += 1;

    assert_token_balance(
        env.provider(),
        DEFAULT_FEE_TOKEN,
        recipient1,
        transfer_amount,
        "Never-expires transfer",
    )
    .await?;
    println!("  ✓ Never-expires key works");

    // TEST 2: Short-expiry key
    let current_ts = env.current_block_timestamp().await?;
    let short_expiry = current_ts + 3;

    let short_auth = create_key_authorization(
        &root_signer,
        short_addr,
        create_mock_p256_sig(short_pub_x, short_pub_y),
        chain_id,
        Some(short_expiry),
        Some(create_default_token_limit(funded)),
    )?;
    let mut auth_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_balance_of_call(root_addr)],
        2_000_000,
    );
    auth_tx.key_authorization = Some(short_auth);
    let sig = sign_aa_tx_secp256k1(&auth_tx, &root_signer)?;
    let envelope: TempoTxEnvelope = auth_tx.into_signed(sig).into();
    let hash = *envelope.tx_hash();
    env.submit_tx(envelope.encoded_2718(), hash).await?;
    nonce += 1;

    // Use before expiry
    let recipient2 = Address::random();
    let before_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_transfer_call(
            DEFAULT_FEE_TOKEN,
            recipient2,
            transfer_amount,
        )],
        2_000_000,
    );
    let short_sig = sign_aa_tx_with_p256_access_key(
        &before_tx,
        &short_signing,
        &short_pub_x,
        &short_pub_y,
        root_addr,
    )?;
    let envelope: TempoTxEnvelope = before_tx.into_signed(short_sig).into();
    let hash = *envelope.tx_hash();
    env.submit_tx(envelope.encoded_2718(), hash).await?;
    nonce += 1;

    assert_token_balance(
        env.provider(),
        DEFAULT_FEE_TOKEN,
        recipient2,
        transfer_amount,
        "Before-expiry transfer",
    )
    .await?;
    println!("  ✓ Short-expiry key works before expiry");

    // Advance time past expiry
    let mut new_ts = env.current_block_timestamp().await?;
    for _ in 0..10 {
        if new_ts >= short_expiry {
            break;
        }
        new_ts = env.current_block_timestamp().await?;
    }
    assert!(new_ts >= short_expiry, "Should be past expiry");

    // Use expired key (should be rejected)
    let after_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_transfer_call(
            DEFAULT_FEE_TOKEN,
            Address::random(),
            transfer_amount,
        )],
        2_000_000,
    );
    let expired_sig = sign_aa_tx_with_p256_access_key(
        &after_tx,
        &short_signing,
        &short_pub_x,
        &short_pub_y,
        root_addr,
    )?;
    let envelope: TempoTxEnvelope = after_tx.into_signed(expired_sig).into();
    env.submit_tx_expecting_rejection(envelope.encoded_2718(), None)
        .await?;
    println!("  ✓ Expired key rejected");

    // TEST 3: Past-expiry key authorization (should be rejected)
    let past_auth = create_key_authorization(
        &root_signer,
        past_addr,
        create_mock_p256_sig(past_pub_x, past_pub_y),
        chain_id,
        Some(1),
        Some(create_default_token_limit(funded)),
    )?;
    let mut past_tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![create_balance_of_call(root_addr)],
        2_000_000,
    );
    past_tx.key_authorization = Some(past_auth);
    let sig = sign_aa_tx_secp256k1(&past_tx, &root_signer)?;
    let envelope: TempoTxEnvelope = past_tx.into_signed(sig).into();
    env.submit_tx_expecting_rejection(envelope.encoded_2718(), None)
        .await?;
    println!("  ✓ Past-expiry key auth rejected");

    println!("✓ Keychain expiry scenario passed");
    Ok(())
}

/// Negative eth_sendTransaction cases: empty calls, key_type mismatch.
pub(super) async fn run_send_negative_scenario<E: TestEnv>(env: &mut E) -> eyre::Result<()> {
    println!("\n=== Send negative scenario ===\n");

    let (_signing_key, _pub_key_x, _pub_key_y, signer_addr) = generate_p256_access_key();
    let _ = env.fund_account(signer_addr).await?;
    let _chain_id = env.chain_id();

    // Case 1: Empty calls
    {
        println!("  Case 1: Empty calls");
        let request = TempoTransactionRequest {
            inner: TransactionRequest {
                from: Some(signer_addr),
                ..Default::default()
            },
            calls: vec![],
            ..Default::default()
        };

        let result: Result<serde_json::Value, _> = env
            .provider()
            .raw_request("eth_sendTransaction".into(), [request])
            .await;
        assert!(result.is_err(), "Empty calls should be rejected");
    }

    // Case 2: WebAuthn key_type with no key_data
    {
        println!("  Case 2: WebAuthn key_type with no key_data");
        let request = TempoTransactionRequest {
            inner: TransactionRequest {
                from: Some(signer_addr),
                ..Default::default()
            },
            calls: vec![Call {
                to: Address::random().into(),
                value: U256::ZERO,
                input: Bytes::new(),
            }],
            key_type: Some(SignatureType::WebAuthn),
            key_data: None,
            ..Default::default()
        };

        let result: Result<serde_json::Value, _> = env
            .provider()
            .raw_request("eth_sendTransaction".into(), [request])
            .await;
        assert!(
            result.is_err(),
            "WebAuthn without key_data should be rejected"
        );
    }

    println!("✓ Send negative scenario passed");
    Ok(())
}

/// Fee payer signature negative cases: wrong signer, missing sig, placeholder sig.
pub(super) async fn run_fee_payer_negative_scenario<E: TestEnv>(env: &mut E) -> eyre::Result<()> {
    println!("\n=== Fee payer negative scenario ===\n");

    let chain_id = env.chain_id();
    let user_signer = PrivateKeySigner::random();
    let user_addr = user_signer.address();
    // Don't fund user — fee payer is expected to pay

    let real_fee_payer = PrivateKeySigner::random();
    let _ = env.fund_account(real_fee_payer.address()).await?;

    // Case 1: Wrong fee payer signature (signed by a different, unfunded signer)
    {
        println!("  Case 1: Wrong fee payer signature");
        let wrong_signer = PrivateKeySigner::random();
        let mut tx = create_basic_aa_tx(
            chain_id,
            0,
            vec![Call {
                to: Address::random().into(),
                value: U256::ZERO,
                input: Bytes::new(),
            }],
            2_000_000,
        );
        sign_fee_payer(&mut tx, user_addr, &wrong_signer)?;
        let sig = sign_aa_tx_secp256k1(&tx, &user_signer)?;
        let envelope: TempoTxEnvelope = tx.into_signed(sig).into();
        env.submit_tx_expecting_rejection(envelope.encoded_2718(), None)
            .await?;
    }

    // Case 2: Placeholder fee payer signature (zeros) not replaced
    {
        println!("  Case 2: Placeholder fee payer signature");
        let mut tx = create_basic_aa_tx(
            chain_id,
            0,
            vec![Call {
                to: Address::random().into(),
                value: U256::ZERO,
                input: Bytes::new(),
            }],
            2_000_000,
        );
        tx.fee_payer_signature = Some(alloy::primitives::Signature::new(
            U256::ZERO,
            U256::ZERO,
            false,
        ));
        let sig = sign_aa_tx_secp256k1(&tx, &user_signer)?;
        let envelope: TempoTxEnvelope = tx.into_signed(sig).into();
        env.submit_tx_expecting_rejection(envelope.encoded_2718(), None)
            .await?;
    }

    println!("✓ Fee payer negative scenario passed");
    Ok(())
}

/// Nonce rejection: protocol nonce too low and 2D nonce replay.
pub(super) async fn run_nonce_rejection_scenario<E: TestEnv>(env: &mut E) -> eyre::Result<()> {
    println!("\n=== Nonce rejection scenario ===\n");

    let chain_id = env.chain_id();

    // Case 1: Protocol nonce too low
    {
        println!("  Case 1: Protocol nonce too low");
        let signer = PrivateKeySigner::random();
        let signer_addr = signer.address();
        let _ = env.fund_account(signer_addr).await?;

        // Send one tx to bump nonce to 1
        let tx = create_basic_aa_tx(
            chain_id,
            0,
            vec![Call {
                to: Address::random().into(),
                value: U256::ZERO,
                input: Bytes::new(),
            }],
            2_000_000,
        );
        let sig = sign_aa_tx_secp256k1(&tx, &signer)?;
        let envelope: TempoTxEnvelope = tx.into_signed(sig).into();
        let tx_hash = *envelope.tx_hash();
        env.submit_tx(envelope.encoded_2718(), tx_hash).await?;

        // Now try to send with nonce=0 again (should be rejected)
        let replay_tx = create_basic_aa_tx(
            chain_id,
            0,
            vec![Call {
                to: Address::random().into(),
                value: U256::ZERO,
                input: Bytes::new(),
            }],
            2_000_000,
        );
        let replay_sig = sign_aa_tx_secp256k1(&replay_tx, &signer)?;
        let replay_envelope: TempoTxEnvelope = replay_tx.into_signed(replay_sig).into();
        env.submit_tx_expecting_rejection(replay_envelope.encoded_2718(), None)
            .await?;
    }

    // Case 2: 2D nonce replay
    {
        println!("  Case 2: 2D nonce replay");
        let signer = PrivateKeySigner::random();
        let signer_addr = signer.address();
        let _ = env.fund_account(signer_addr).await?;

        // Send tx with nonce_key=42, nonce=0
        let mut tx = create_basic_aa_tx(
            chain_id,
            0,
            vec![Call {
                to: Address::random().into(),
                value: U256::ZERO,
                input: Bytes::new(),
            }],
            2_000_000,
        );
        tx.nonce_key = U256::from(42);
        let sig = sign_aa_tx_secp256k1(&tx, &signer)?;
        let envelope: TempoTxEnvelope = tx.into_signed(sig).into();
        let tx_hash = *envelope.tx_hash();
        env.submit_tx(envelope.encoded_2718(), tx_hash).await?;

        // Replay same nonce_key=42, nonce=0 (should be rejected)
        let mut replay_tx = create_basic_aa_tx(
            chain_id,
            0,
            vec![Call {
                to: Address::random().into(),
                value: U256::ZERO,
                input: Bytes::new(),
            }],
            2_000_000,
        );
        replay_tx.nonce_key = U256::from(42);
        let replay_sig = sign_aa_tx_secp256k1(&replay_tx, &signer)?;
        let replay_envelope: TempoTxEnvelope = replay_tx.into_signed(replay_sig).into();
        env.submit_tx_expecting_rejection(replay_envelope.encoded_2718(), None)
            .await?;
    }

    println!("✓ Nonce rejection scenario passed");
    Ok(())
}

/// Gas/fee boundary rejections: gas too low, max_fee < base_fee, priority > max_fee.
pub(super) async fn run_gas_fee_boundary_scenario<E: TestEnv>(env: &mut E) -> eyre::Result<()> {
    println!("\n=== Gas/fee boundary scenario ===\n");

    let chain_id = env.chain_id();
    let calls = vec![Call {
        to: Address::random().into(),
        value: U256::ZERO,
        input: Bytes::new(),
    }];

    // Case 1: Gas limit too low
    {
        println!("  Case 1: Gas limit too low");
        let signer = PrivateKeySigner::random();
        let _ = env.fund_account(signer.address()).await?;
        let nonce = env
            .provider()
            .get_transaction_count(signer.address())
            .await?;
        let tx = create_basic_aa_tx(chain_id, nonce, calls.clone(), 1);
        let sig = sign_aa_tx_secp256k1(&tx, &signer)?;
        let envelope: TempoTxEnvelope = tx.into_signed(sig).into();
        env.submit_tx_expecting_rejection(envelope.encoded_2718(), None)
            .await?;
    }

    // Case 2: max_fee_per_gas < base_fee
    {
        println!("  Case 2: max_fee_per_gas < base_fee");
        let signer = PrivateKeySigner::random();
        let _ = env.fund_account(signer.address()).await?;
        let nonce = env
            .provider()
            .get_transaction_count(signer.address())
            .await?;
        let mut tx = create_basic_aa_tx(chain_id, nonce, calls.clone(), 2_000_000);
        tx.max_fee_per_gas = 1;
        tx.max_priority_fee_per_gas = 0;
        let sig = sign_aa_tx_secp256k1(&tx, &signer)?;
        let envelope: TempoTxEnvelope = tx.into_signed(sig).into();
        env.submit_tx_expecting_rejection(envelope.encoded_2718(), None)
            .await?;
    }

    // Case 3: max_priority_fee_per_gas > max_fee_per_gas
    {
        println!("  Case 3: max_priority > max_fee");
        let signer = PrivateKeySigner::random();
        let _ = env.fund_account(signer.address()).await?;
        let nonce = env
            .provider()
            .get_transaction_count(signer.address())
            .await?;
        let mut tx = create_basic_aa_tx(chain_id, nonce, calls.clone(), 2_000_000);
        tx.max_priority_fee_per_gas = tx.max_fee_per_gas + 1;
        let sig = sign_aa_tx_secp256k1(&tx, &signer)?;
        let envelope: TempoTxEnvelope = tx.into_signed(sig).into();
        env.submit_tx_expecting_rejection(envelope.encoded_2718(), None)
            .await?;
    }

    println!("✓ Gas/fee boundary scenario passed");
    Ok(())
}

/// CREATE contract address correctness.
pub(super) async fn run_create_contract_address_scenario<E: TestEnv>(
    env: &mut E,
) -> eyre::Result<()> {
    println!("\n=== Create contract address scenario ===\n");

    let chain_id = env.chain_id();

    let signer = PrivateKeySigner::random();
    let signer_addr = signer.address();
    let _ = env.fund_account(signer_addr).await?;

    let nonce = env.provider().get_transaction_count(signer_addr).await?;
    let expected_contract_address = signer_addr.create(nonce);

    // Simple initcode: stores 42 at memory[0], returns 32 bytes
    let init_code =
        Bytes::from_static(&[0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3]);

    let tx = TempoTransaction {
        chain_id,
        max_priority_fee_per_gas: tempo_chainspec::spec::TEMPO_T1_BASE_FEE as u128,
        max_fee_per_gas: tempo_chainspec::spec::TEMPO_T1_BASE_FEE as u128,
        gas_limit: 2_000_000,
        calls: vec![Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: init_code,
        }],
        nonce_key: U256::ZERO,
        nonce,
        fee_token: Some(DEFAULT_FEE_TOKEN),
        valid_before: Some(u64::MAX),
        ..Default::default()
    };

    let sig = sign_aa_tx_secp256k1(&tx, &signer)?;
    let envelope: TempoTxEnvelope = tx.into_signed(sig).into();
    let tx_hash = *envelope.tx_hash();

    let receipt = env.submit_tx(envelope.encoded_2718(), tx_hash).await?;
    assert_eq!(receipt["status"].as_str(), Some("0x1"));

    let actual_contract_address: Address = receipt["contractAddress"]
        .as_str()
        .expect("Receipt should have contractAddress")
        .parse()?;

    assert_eq!(
        actual_contract_address, expected_contract_address,
        "Contract address should be computed from nonce {nonce}"
    );

    let deployed_code = env.provider().get_code_at(actual_contract_address).await?;
    assert!(!deployed_code.is_empty(), "Contract should be deployed");

    let mut expected_code = [0u8; 32];
    expected_code[31] = 0x2a;
    assert_eq!(deployed_code.as_ref(), &expected_code);

    println!("✓ Create contract address scenario passed");
    Ok(())
}
