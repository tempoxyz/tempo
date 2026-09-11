//! Real signed transaction executions for TIP-1086, including the configurable-account stack.
use super::*;
use alloy_evm::FromRecoveredTx;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner};
use revm::DatabaseCommit;
use sha2::{Digest, Sha256};
use tempo_contracts::precompiles::{IAccountKeychain, ITIP20};
use tempo_primitives::transaction::{
    CarriedAuthorization, KeyAuthorization, KeychainSignature, MultisigConfig, MultisigOwner,
    MultisigSignature, SignedKeyAuthorization, TempoTransaction, multisig_digest,
    tt_signature::{derive_p256_address, normalize_p256_s},
};

const FACTORY: Address = Address::repeat_byte(0x71);
const RECIPIENT: Address = Address::repeat_byte(0x77);

#[path = "carried_tree.rs"]
mod account_tree;

#[derive(Clone, Copy, Debug)]
enum Curve {
    Secp,
    P256,
    WebAuthn,
    WebAuthnMax,
}

#[derive(Clone, Copy, Debug)]
struct Actor {
    curve: Curve,
    native: bool,
    seed: u8,
    quorum: u8,
    version: u64,
}

impl Actor {
    fn primitive(&self, digest: B256) -> PrimitiveSignature {
        if matches!(self.curve, Curve::Secp) {
            return PrimitiveSignature::Secp256k1(
                PrivateKeySigner::from_bytes(&B256::repeat_byte(self.seed))
                    .unwrap()
                    .sign_hash_sync(&digest)
                    .unwrap(),
            );
        }
        let key = SigningKey::from_bytes((&[self.seed; 32]).into()).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        let x = B256::from_slice(point.x().unwrap());
        let y = B256::from_slice(point.y().unwrap());
        let (prehash, data) = if matches!(self.curve, Curve::WebAuthn | Curve::WebAuthnMax) {
            let challenge = URL_SAFE_NO_PAD.encode(digest);
            let mut json = format!(r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"https://carried.example"}}"#).into_bytes();
            if matches!(self.curve, Curve::WebAuthnMax) {
                json.resize(
                    tempo_primitives::transaction::MAX_WEBAUTHN_SIGNATURE_LENGTH - 128 - 37,
                    b' ',
                );
            }
            let mut data = vec![0; 37];
            data[32] = 1;
            let mut hash = Sha256::new();
            hash.update(&data);
            hash.update(Sha256::digest(&json));
            data.extend(json);
            (B256::from_slice(&hash.finalize()), data)
        } else {
            (digest, Vec::new())
        };
        let signature: p256::ecdsa::Signature = key.sign_prehash(prehash.as_slice()).unwrap();
        let bytes = signature.to_bytes();
        let r = B256::from_slice(&bytes[..32]);
        let s = normalize_p256_s(&bytes[32..]).unwrap();
        if matches!(self.curve, Curve::WebAuthn | Curve::WebAuthnMax) {
            PrimitiveSignature::WebAuthn(WebAuthnSignature {
                r,
                s,
                pub_key_x: x,
                pub_key_y: y,
                webauthn_data: data.into(),
            })
        } else {
            PrimitiveSignature::P256(P256SignatureWithPreHash {
                r,
                s,
                pub_key_x: x,
                pub_key_y: y,
                pre_hash: false,
            })
        }
    }
    fn owner(&self) -> Address {
        if matches!(self.curve, Curve::Secp) {
            PrivateKeySigner::from_bytes(&B256::repeat_byte(self.seed))
                .unwrap()
                .address()
        } else {
            let key = SigningKey::from_bytes((&[self.seed; 32]).into()).unwrap();
            let point = key.verifying_key().to_encoded_point(false);
            derive_p256_address(
                &B256::from_slice(point.x().unwrap()),
                &B256::from_slice(point.y().unwrap()),
            )
        }
    }
    fn config(&self) -> MultisigConfig {
        let mut owners = (0..self.quorum)
            .map(|offset| MultisigOwner {
                owner: Self {
                    seed: self.seed + offset,
                    ..*self
                }
                .owner(),
                weight: 1,
            })
            .collect::<Vec<_>>();
        owners.sort_by_key(|owner| owner.owner);
        MultisigConfig {
            salt: B256::repeat_byte(self.seed),
            version: self.version,
            threshold: self.quorum.into(),
            owners,
        }
    }
    fn address(&self) -> Address {
        if self.native {
            let mut config = self.config();
            config.version = 0;
            config.derive_account(FACTORY).unwrap()
        } else {
            self.owner()
        }
    }
    fn kind(&self) -> SignatureType {
        if self.native {
            SignatureType::Multisig
        } else {
            match self.curve {
                Curve::Secp => SignatureType::Secp256k1,
                Curve::P256 => SignatureType::P256,
                Curve::WebAuthn | Curve::WebAuthnMax => SignatureType::WebAuthn,
            }
        }
    }
    fn sign(&self, digest: B256) -> TempoSignature {
        if self.native {
            TempoSignature::Multisig(
                MultisigSignature::try_new(self.address(), self.config(), {
                    let mut actors = (0..self.quorum)
                        .map(|offset| Self {
                            seed: self.seed + offset,
                            ..*self
                        })
                        .collect::<Vec<_>>();
                    actors.sort_by_key(Self::owner);
                    actors
                        .iter()
                        .map(|actor| {
                            actor.primitive(multisig_digest(digest, self.address(), self.version))
                        })
                        .collect()
                })
                .unwrap(),
            )
        } else {
            self.primitive(digest).into()
        }
    }
}

struct Fixture {
    parent: Actor,
    delegate: Actor,
    auth: SignedKeyAuthorization,
    sponsor: PrivateKeySigner,
    sponsored: bool,
    test: TestHandlerEvm,
    nonce: u64,
}

impl Fixture {
    fn new(parent: Actor, delegate: Actor, carried: bool, sponsored: bool, policy: usize) -> Self {
        let mut grant = KeyAuthorization::unrestricted(1, delegate.kind(), delegate.address())
            .with_account(parent.address())
            .with_witness(B256::repeat_byte(0x42));
        grant.expiry = core::num::NonZeroU64::new(10_000);
        if policy != 0 {
            grant.limits = Some(vec![tempo_primitives::transaction::TokenLimit {
                token: PATH_USD_ADDRESS,
                limit: U256::from(1_000_000_000u64),
                period: if policy == 2 { 60 } else { 0 },
            }]);
        }
        if policy == 3 {
            grant
                .limits
                .as_mut()
                .unwrap()
                .push(tempo_primitives::transaction::TokenLimit {
                    token: alloy_primitives::address!("20c0000000000000000000000000000000000001"),
                    limit: U256::from(1_000_000_000u64),
                    period: 0,
                });
            grant.allowed_calls = Some(vec![
                tempo_primitives::transaction::CallScope {
                    target: PATH_USD_ADDRESS,
                    selector_rules: vec![],
                },
                tempo_primitives::transaction::CallScope {
                    target: alloy_primitives::address!("20c0000000000000000000000000000000000001"),
                    selector_rules: vec![],
                },
            ]);
        }
        let auth = if carried {
            let extra = CarriedAuthorization {
                valid_after: 100,
                authority_config: if parent.native {
                    parent.config().commitment().unwrap()
                } else {
                    B256::ZERO
                },
            };
            let signature = parent.sign(extra.signature_hash(&grant));
            SignedKeyAuthorization::new_carried(grant, extra, signature).unwrap()
        } else {
            let signature = parent.sign(grant.signature_hash());
            grant.into_signed(signature)
        };
        let sponsor = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x31)).unwrap();
        let mut test = TestHandlerEvm::new(TempoHardfork::T12, TempoTxEnv::default());
        test.evm.ctx.block.timestamp = U256::from(125);
        test.evm.ctx.block.basefee = 600_000_000;
        test.evm.ctx.block.multisig_recovery_factory = Some(FACTORY);
        test.evm.ctx.block.beneficiary = sponsor.address();
        test.evm.ctx.journaled_state.database.insert_account_info(
            parent.address(),
            revm::state::AccountInfo {
                nonce: 1,
                extension: if parent.native {
                    tempo_primitives::account::encode_config_commitment(
                        parent.config().commitment().unwrap(),
                    )
                    .into()
                } else {
                    Default::default()
                },
                ..Default::default()
            },
        );
        if delegate.native {
            test.evm.ctx.journaled_state.database.insert_account_info(
                delegate.address(),
                revm::state::AccountInfo {
                    extension: tempo_primitives::account::encode_config_commitment(
                        delegate.config().commitment().unwrap(),
                    )
                    .into(),
                    ..Default::default()
                },
            );
        }
        StorageCtx::enter_ctx(test.evm.ctx_mut(), StorageActions::disabled(), || {
            TIP20Setup::path_usd(parent.address())
                .with_issuer(parent.address())
                .with_mint(parent.address(), U256::from(1_000_000_000_000u64))
                .with_mint(sponsor.address(), U256::from(1_000_000_000_000u64))
                .with_mint(RECIPIENT, U256::from(1))
                .apply()
        })
        .unwrap();
        let state = test.evm.ctx.journaled_state.finalize();
        test.evm.ctx.journaled_state.database.commit(state);
        Self {
            parent,
            delegate,
            auth,
            sponsor,
            sponsored,
            test,
            nonce: 1,
        }
    }

    fn tx(&self, include: bool, amount: u64, fail_scope: bool) -> TempoTransaction {
        let mut tx = TempoTransaction {
            chain_id: 1,
            nonce: self.nonce,
            gas_limit: 15_000_000,
            max_fee_per_gas: self.test.evm.ctx.block.basefee as u128,
            fee_token: Some(PATH_USD_ADDRESS),
            calls: vec![Call {
                to: TxKind::Call(if fail_scope {
                    Address::repeat_byte(0x88)
                } else {
                    PATH_USD_ADDRESS
                }),
                value: U256::ZERO,
                input: ITIP20::transferCall {
                    to: RECIPIENT,
                    amount: U256::from(amount),
                }
                .abi_encode()
                .into(),
            }],
            key_authorization: include.then(|| self.auth.clone()),
            ..Default::default()
        };
        if self.sponsored {
            tx.fee_payer_signature = Some(
                self.sponsor
                    .sign_hash_sync(&tx.fee_payer_signature_hash(self.parent.address()))
                    .unwrap(),
            );
        }
        tx
    }

    fn prepare(&mut self, tx: TempoTransaction) {
        use alloy_rlp::Decodable;
        // Exercise the actual tagged wire decoder for every curve and configurable role.
        let mut tx = tx;
        if let Some(auth) = tx.key_authorization.as_mut() {
            let encoded = alloy_rlp::encode(&*auth);
            *auth = SignedKeyAuthorization::decode(&mut encoded.as_slice()).unwrap();
        }
        if self.sponsored {
            tx.fee_payer_signature = Some(
                self.sponsor
                    .sign_hash_sync(&tx.fee_payer_signature_hash(self.parent.address()))
                    .unwrap(),
            );
        }
        let digest = KeychainSignature::signing_hash(tx.signature_hash(), self.parent.address());
        let inner = self.delegate.sign(digest);
        let keychain = match inner {
            TempoSignature::Primitive(signature) => {
                KeychainSignature::new(self.parent.address(), signature)
            }
            TempoSignature::Multisig(signature) => {
                KeychainSignature::new(self.parent.address(), signature)
            }
            _ => unreachable!(),
        };
        let signed = tx.into_signed(TempoSignature::Keychain(keychain));
        self.test.evm.ctx.tx = TempoTxEnv::from_recovered_tx(&signed, self.parent.address());
    }

    fn run(&mut self, include: bool, amount: u64, fail_scope: bool) -> (u64, usize) {
        self.prepare(self.tx(include, amount, fail_scope));
        let result = self.test.handler.run(&mut self.test.evm).unwrap();
        assert_eq!(result.is_success(), !fail_scope, "{result:?}");
        let gas = result.tx_gas_used();
        let state = self.test.evm.ctx.journaled_state.finalize();
        let created = state
            .get(&tempo_precompiles::ACCOUNT_KEYCHAIN_ADDRESS)
            .map_or(0, |account| {
                account
                    .storage
                    .values()
                    .filter(|slot| {
                        slot.original_value().is_zero() && !slot.present_value().is_zero()
                    })
                    .count()
            });
        self.test.evm.ctx.journaled_state.database.commit(state);
        self.nonce += 1;
        (gas, created)
    }

    fn spent(&mut self) -> U256 {
        StorageCtx::enter_ctx(self.test.evm.ctx_mut(), StorageActions::disabled(), || {
            AccountKeychain::default()
                .get_carried_spending(IAccountKeychain::getCarriedSpendingCall {
                    account: self.parent.address(),
                    authorizationId: self.auth.signature_hash(),
                    token: PATH_USD_ADDRESS,
                })
                .unwrap()
                .spent
        })
    }

    fn root_state(&mut self, action: impl FnOnce(&mut AccountKeychain)) {
        self.test.evm.ctx.tx.caller = self.parent.address();
        self.test
            .evm
            .ctx
            .journaled_state
            .load_account(self.parent.address())
            .unwrap();
        StorageCtx::enter_ctx(self.test.evm.ctx_mut(), StorageActions::disabled(), || {
            let mut keychain = AccountKeychain::default();
            keychain.set_transaction_key(Address::ZERO).unwrap();
            keychain.set_tx_origin(self.parent.address()).unwrap();
            action(&mut keychain);
        });
        let state = self.test.evm.ctx.journaled_state.finalize();
        self.test.evm.ctx.journaled_state.database.commit(state);
    }
}

fn secp(seed: u8, native: bool) -> Actor {
    Actor {
        curve: Curve::Secp,
        native,
        seed,
        quorum: 1,
        version: 0,
    }
}

#[test]
fn carried_first_repeat_and_rollover() {
    for sponsored in [false, true] {
        let mut f = Fixture::new(secp(1, false), secp(2, false), true, sponsored, 2);
        let (_, first) = f.run(true, 10, false);
        assert_eq!(first, 1, "only the spent word; window zero needs no write");
        let used = f.spent();
        assert!(used >= U256::from(10));
        let (_, repeated) = f.run(true, 20, false);
        assert_eq!(repeated, 0);
        assert!(f.spent() >= used + U256::from(20));
        f.test.evm.ctx.block.timestamp = U256::from(160);
        let (_, rollover) = f.run(true, 1, false);
        assert_eq!(rollover, 1, "first nonzero window word");
        assert!(f.spent() < used + U256::from(20));
        if sponsored {
            assert_eq!(f.spent(), U256::from(1));
        }
    }
}

#[test]
fn carried_scope_failure_charges_only_actual_fees() {
    for sponsored in [false, true] {
        let mut f = Fixture::new(secp(1, false), secp(2, false), true, sponsored, 3);
        let (gas, _) = f.run(true, 500, true);
        assert_eq!(
            f.spent(),
            if sponsored {
                U256::ZERO
            } else {
                calc_gas_balance_spending(gas, 600_000_000)
            }
        );
    }
}

#[test]
fn carried_missing_certificate_cannot_reuse_unregistered_key() {
    let mut f = Fixture::new(secp(1, false), secp(2, false), true, true, 1);
    f.run(true, 1, false);
    f.prepare(f.tx(false, 1, false));
    assert!(f.test.handler.run(&mut f.test.evm).is_err());
}

#[test]
fn carried_all_signature_roles_execute() {
    for curve in [Curve::Secp, Curve::P256, Curve::WebAuthn] {
        for parent_native in [false, true] {
            for delegate_native in [false, true] {
                let mut f = Fixture::new(
                    Actor {
                        curve,
                        native: parent_native,
                        seed: 1,
                        quorum: 1,
                        version: 0,
                    },
                    Actor {
                        curve,
                        native: delegate_native,
                        seed: 2,
                        quorum: 1,
                        version: 0,
                    },
                    true,
                    true,
                    1,
                );
                f.run(true, 3, false);
                f.run(true, 4, false);
                assert_eq!(f.spent(), U256::from(7));
            }
        }
    }
}

#[test]
fn carried_revocation_before_and_after_first_use() {
    for first_use in [false, true] {
        for burn_witness in [false, true] {
            let mut f = Fixture::new(secp(1, false), secp(2, false), true, true, 1);
            if first_use {
                f.run(true, 1, false);
            }
            let account = f.parent.address();
            let key_id = f.delegate.address();
            let witness = f.auth.witness.unwrap();
            f.root_state(|keychain| {
                if burn_witness {
                    keychain
                        .burn_key_authorization_witness(
                            account,
                            IAccountKeychain::burnKeyAuthorizationWitnessCall { witness },
                        )
                        .unwrap();
                } else {
                    keychain.revoke_carried_key(account, key_id).unwrap();
                    keychain.revoke_carried_key(account, key_id).unwrap();
                }
            });
            f.prepare(f.tx(true, 1, false));
            assert!(f.test.handler.run(&mut f.test.evm).is_err());
        }
    }
}

#[test]
fn carried_parent_rotation_invalidates_grant_without_resetting_budget() {
    let mut f = Fixture::new(secp(1, true), secp(2, false), true, true, 1);
    f.run(true, 7, false);
    let account = f.parent.address();
    let mut config = f.parent.config();
    config.version = 1;
    f.root_state(|_| {
        StorageCtx
            .set_config_commitment(
                account,
                config.commitment().unwrap(),
                tempo_precompiles::storage::ConfigCommitmentWriteGas::Precompile,
            )
            .unwrap()
    });
    f.prepare(f.tx(true, 1, false));
    assert!(f.test.handler.run(&mut f.test.evm).is_err());
    assert_eq!(f.spent(), U256::from(7));
}

#[test]
fn carried_exhaustion_and_batch_rollback() {
    let mut f = Fixture::new(secp(1, false), secp(2, false), true, true, 1);
    let mut grant = f.auth.authorization.clone();
    grant.limits.as_mut().unwrap()[0].limit = U256::from(20);
    let extra = f.auth.carried.clone().unwrap();
    f.auth = SignedKeyAuthorization::new_carried(
        grant.clone(),
        extra.clone(),
        f.parent.sign(extra.signature_hash(&grant)),
    )
    .unwrap();
    f.run(true, 10, false);
    let mut tx = f.tx(true, 5, false);
    tx.calls.push(Call {
        to: TxKind::Call(PATH_USD_ADDRESS),
        value: U256::ZERO,
        input: ITIP20::transferCall {
            to: RECIPIENT,
            amount: U256::from(6),
        }
        .abi_encode()
        .into(),
    });
    f.prepare(tx);
    assert!(!f.test.handler.run(&mut f.test.evm).unwrap().is_success());
    let state = f.test.evm.ctx.journaled_state.finalize();
    f.test.evm.ctx.journaled_state.database.commit(state);
    f.nonce += 1;
    assert_eq!(
        f.spent(),
        U256::from(10),
        "first call of failed batch rolls back"
    );
    f.run(true, 10, false);
    assert_eq!(f.spent(), U256::from(20));
    f.prepare(f.tx(true, 1, false));
    assert!(!f.test.handler.run(&mut f.test.evm).unwrap().is_success());
}

#[test]
fn carried_validity_and_fork_rejection() {
    for now in [99, 10_000, u64::MAX] {
        let mut f = Fixture::new(secp(1, false), secp(2, false), true, true, 1);
        f.test.evm.ctx.block.timestamp = U256::from(now);
        f.prepare(f.tx(true, 1, false));
        assert!(f.test.handler.run(&mut f.test.evm).is_err());
    }
    let mut f = Fixture::new(secp(1, false), secp(2, false), true, true, 1);
    f.test.evm.ctx.cfg.spec = TempoHardfork::T11;
    f.prepare(f.tx(true, 1, false));
    assert!(f.test.handler.run(&mut f.test.evm).is_err());
}

#[test]
fn carried_stored_admin_issuer_and_its_revocation() {
    let mut f = Fixture::new(secp(1, false), secp(2, false), true, true, 1);
    let admin = secp(3, false);
    let account = f.parent.address();
    f.root_state(|keychain| {
        keychain
            .authorize_admin_key(
                account,
                admin.address(),
                IAccountKeychain::SignatureType::Secp256k1,
                None,
            )
            .unwrap()
    });
    f.auth.signature = admin.sign(f.auth.signature_hash());
    f.run(true, 5, false);
    f.root_state(|keychain| {
        keychain
            .revoke_key(
                account,
                IAccountKeychain::revokeKeyCall {
                    keyId: admin.address(),
                },
            )
            .unwrap()
    });
    f.prepare(f.tx(true, 1, false));
    assert!(f.test.handler.run(&mut f.test.evm).is_err());
    assert_eq!(f.spent(), U256::from(5));
}

#[test]
fn carried_fee_counter_creation_is_charged() {
    let mut f = Fixture::new(secp(1, false), secp(2, false), true, false, 1);
    let (first, _) = f.run(true, 10, false);
    let (repeat, _) = f.run(true, 10, false);
    assert!(
        first >= repeat + 245_000,
        "first fee-counter creation must pay the T7 creditable component: {first}, {repeat}"
    );
}

#[test]
fn carried_estimation_keeps_policy_and_counters() {
    let mut f = Fixture::new(secp(1, false), secp(2, false), true, true, 1);
    f.prepare(f.tx(true, 7, false));
    f.test.evm.ctx.tx.execution_context = crate::ExecutionContext::Simulation;
    f.test
        .evm
        .ctx
        .tx
        .tempo_tx_env
        .as_mut()
        .unwrap()
        .override_key_id = Some(f.delegate.address());
    let result = f.test.handler.run(&mut f.test.evm).unwrap();
    assert!(result.is_success());
    assert_eq!(f.spent(), U256::from(7));
    // The RPC adapter, not the handler, discards simulation state. No database commit here.
}

fn failure_costs() {
    println!("failure,mode,configurable,sponsored,gas");
    for failure in ["scope", "revert", "out-of-gas"] {
        for native in [false, true] {
            for sponsored in [false, true] {
                for carried in [false, true] {
                    let mut f = Fixture::new(
                        secp(1, native),
                        secp(2, native),
                        carried,
                        sponsored,
                        if failure == "scope" { 3 } else { 1 },
                    );
                    f.run(true, 1, false);
                    let before = if carried { f.spent() } else { U256::ZERO };
                    let mut tx = f.tx(carried, 1, failure == "scope");
                    tx.gas_limit = 500_000;
                    if failure != "scope" {
                        let code = revm::bytecode::Bytecode::new_raw(
                            if failure == "revert" {
                                // PUSH0 PUSH0 REVERT
                                vec![0x5f, 0x5f, 0xfd]
                            } else {
                                // JUMPDEST PUSH1 0 JUMP
                                vec![0x5b, 0x60, 0x00, 0x56]
                            }
                            .into(),
                        );
                        f.test.evm.ctx.journaled_state.database.insert_account_info(
                            RECIPIENT,
                            revm::state::AccountInfo {
                                code_hash: code.hash_slow(),
                                code: Some(code),
                                ..Default::default()
                            },
                        );
                        tx.calls[0].to = TxKind::Call(RECIPIENT);
                    }
                    f.prepare(tx);
                    let result = f.test.handler.run(&mut f.test.evm).unwrap();
                    assert!(!result.is_success(), "{failure}: {result:?}");
                    let gas = result.tx_gas_used();
                    let state = f.test.evm.ctx.journaled_state.finalize();
                    f.test.evm.ctx.journaled_state.database.commit(state);
                    if carried {
                        assert_eq!(
                            f.spent(),
                            before
                                + if sponsored {
                                    U256::ZERO
                                } else {
                                    calc_gas_balance_spending(gas, 600_000_000)
                                },
                            "{failure}: only actual fees survive"
                        );
                    }
                    println!(
                        "{failure},{},{native},{sponsored},{gas}",
                        if carried { "carried" } else { "stored" }
                    );
                }
            }
        }
    }
}

#[test]
fn carried_failed_execution_settles_only_actual_fees() {
    failure_costs();
}

#[test]
#[ignore = "emits failed-execution receipt gas; run --ignored --nocapture"]
fn carried_cost_failures() {
    failure_costs();
}

#[test]
#[ignore = "emits receipt gas matrix; run --ignored --nocapture"]
fn carried_cost_matrix() {
    println!("BASELINE_BASEFEE,12000000000");
    println!(
        "mode,parent,delegate,sponsored,policy,phase,authorization_bytes,gas,keychain_words_created,execution_us"
    );
    for parent_curve in [Curve::Secp, Curve::P256, Curve::WebAuthn] {
        for delegate_curve in [Curve::Secp, Curve::P256, Curve::WebAuthn] {
            for parent_native in [false, true] {
                for delegate_native in [false, true] {
                    for sponsored in [false, true] {
                        for policy in 0..4 {
                            for carried in [false, true] {
                                let parent = Actor {
                                    curve: parent_curve,
                                    native: parent_native,
                                    seed: 1,
                                    quorum: 1,
                                    version: 0,
                                };
                                let delegate = Actor {
                                    curve: delegate_curve,
                                    native: delegate_native,
                                    seed: 2,
                                    quorum: 1,
                                    version: 0,
                                };
                                let mut f =
                                    Fixture::new(parent, delegate, carried, sponsored, policy);
                                // Fresh comparison run at the same TIP-1067 cap as V2.
                                f.test.evm.ctx.block.basefee = 12_000_000_000;
                                for phase in 0..3 {
                                    if phase == 2 {
                                        f.test.evm.ctx.block.timestamp = U256::from(200);
                                    }
                                    let include = carried || phase == 0;
                                    let bytes = if include {
                                        alloy_rlp::encode(&f.auth).len()
                                    } else {
                                        0
                                    };
                                    f.prepare(f.tx(include, 10, false));
                                    let start = std::time::Instant::now();
                                    let result = f.test.handler.run(&mut f.test.evm).unwrap();
                                    let elapsed = start.elapsed().as_micros();
                                    assert!(result.is_success(), "{result:?}");
                                    let gas = result.tx_gas_used();
                                    let state = f.test.evm.ctx.journaled_state.finalize();
                                    let words = state
                                        .get(&tempo_precompiles::ACCOUNT_KEYCHAIN_ADDRESS)
                                        .map_or(0, |account| {
                                            account
                                                .storage
                                                .values()
                                                .filter(|slot| {
                                                    slot.original_value().is_zero()
                                                        && !slot.present_value().is_zero()
                                                })
                                                .count()
                                        });
                                    f.test.evm.ctx.journaled_state.database.commit(state);
                                    f.nonce += 1;
                                    println!(
                                        "{},{parent_curve:?}-{parent_native},{delegate_curve:?}-{delegate_native},{sponsored},{policy},{phase},{bytes},{gas},{words},{elapsed}",
                                        if carried { "carried" } else { "stored" }
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn carried_delegate_rotation_preserves_budget() {
    let mut f = Fixture::new(secp(1, false), secp(2, true), true, true, 1);
    f.run(true, 7, false);
    f.delegate.version = 1;
    let account = f.delegate.address();
    let commitment = f.delegate.config().commitment().unwrap();
    f.root_state(|_| {
        StorageCtx
            .set_config_commitment(
                account,
                commitment,
                tempo_precompiles::storage::ConfigCommitmentWriteGas::Precompile,
            )
            .unwrap()
    });
    f.run(true, 5, false);
    assert_eq!(f.spent(), U256::from(12));
}

#[test]
#[ignore = "emits additional gas cases; run --ignored --nocapture"]
fn carried_cost_edges() {
    println!("edge,mode,sponsored,authorization_bytes,gas,status");
    for edge in [
        "max-webauthn",
        "two-eight-owner-quorums",
        "32-calls",
        "120-recipients",
        "new-account",
        "new-configurable-accounts",
        "warm-counter-access-list",
        "late-first-period",
    ] {
        for sponsored in [false, true] {
            for carried in [false, true] {
                let mut parent = secp(1, false);
                let mut delegate = secp(20, false);
                if edge == "max-webauthn" {
                    parent.curve = Curve::WebAuthnMax;
                    delegate.curve = Curve::WebAuthnMax;
                }
                if edge == "two-eight-owner-quorums" {
                    parent.native = true;
                    delegate.native = true;
                    parent.quorum = 8;
                    delegate.quorum = 8;
                }
                if edge == "new-configurable-accounts" {
                    parent.native = true;
                    delegate.native = true;
                }
                let mut f = Fixture::new(
                    parent,
                    delegate,
                    carried,
                    sponsored,
                    if edge == "late-first-period" { 2 } else { 1 },
                );
                if edge == "120-recipients" {
                    let mut recipients = (1..120)
                        .map(|i| {
                            let mut bytes = [0; 20];
                            bytes[19] = i;
                            Address::from(bytes)
                        })
                        .collect::<Vec<_>>();
                    recipients.push(RECIPIENT);
                    let mut auth = f.auth.authorization.clone();
                    auth.allowed_calls = Some(vec![tempo_primitives::transaction::CallScope {
                        target: PATH_USD_ADDRESS,
                        selector_rules: vec![tempo_primitives::transaction::SelectorRule {
                            selector: ITIP20::transferCall::SELECTOR,
                            recipients,
                        }],
                    }]);
                    f.auth = if let Some(extra) = f.auth.carried.clone() {
                        let signature = parent.sign(extra.signature_hash(&auth));
                        SignedKeyAuthorization::new_carried(auth, extra, signature).unwrap()
                    } else {
                        let signature = parent.sign(auth.signature_hash());
                        auth.into_signed(signature)
                    };
                }
                if edge == "new-account" || edge == "new-configurable-accounts" {
                    f.nonce = 0;
                    f.test.evm.ctx.journaled_state.database.insert_account_info(
                        f.parent.address(),
                        revm::state::AccountInfo::default(),
                    );
                    if delegate.native {
                        f.test.evm.ctx.journaled_state.database.insert_account_info(
                            delegate.address(),
                            revm::state::AccountInfo::default(),
                        );
                    }
                }
                if edge == "late-first-period" {
                    f.test.evm.ctx.block.timestamp = U256::from(1_000);
                }
                let mut tx = f.tx(true, 1, false);
                tx.gas_limit = 16_777_216;
                if edge == "32-calls" {
                    tx.calls = vec![tx.calls[0].clone(); 32];
                }
                if edge == "warm-counter-access-list" {
                    let slot = if carried {
                        tempo_precompiles::account_keychain::carried::counter_slot(
                            false,
                            parent.address(),
                            f.auth.signature_hash(),
                            PATH_USD_ADDRESS,
                        )
                    } else {
                        AccountKeychain::default().spending_limits
                            [AccountKeychain::spending_limit_key(
                                parent.address(),
                                delegate.address(),
                            )][PATH_USD_ADDRESS]
                            .remaining
                            .slot()
                    };
                    tx.access_list = alloy_eips::eip2930::AccessList(vec![
                        alloy_eips::eip2930::AccessListItem {
                            address: tempo_precompiles::ACCOUNT_KEYCHAIN_ADDRESS,
                            storage_keys: vec![slot.into()],
                        },
                    ]);
                }
                // Every mutation of the transaction must precede the sponsor signature.
                if sponsored {
                    tx.fee_payer_signature = Some(
                        f.sponsor
                            .sign_hash_sync(&tx.fee_payer_signature_hash(parent.address()))
                            .unwrap(),
                    );
                }
                f.prepare(tx);
                let result = match f.test.handler.run(&mut f.test.evm) {
                    Ok(result) => result,
                    Err(EVMError::Transaction(TempoInvalidTransaction::EthInvalidTransaction(
                        InvalidTransaction::CallGasCostMoreThanGasLimit { .. },
                    ))) if edge == "120-recipients" && !carried => {
                        println!(
                            "{edge},stored,{sponsored},{},0,exceeds-16777216-gas-limit",
                            alloy_rlp::encode(&f.auth).len()
                        );
                        continue;
                    }
                    Err(error) => panic!("{edge}: {error:?}"),
                };
                assert!(result.is_success(), "{edge}: {result:?}");
                println!(
                    "{edge},{},{sponsored},{},{},success",
                    if carried { "carried" } else { "stored" },
                    alloy_rlp::encode(&f.auth).len(),
                    result.tx_gas_used()
                );
            }
        }
    }
}
