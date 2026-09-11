//! Executed V2 account-tree receipts at the TIP-1067 cap.
use super::*;
use alloy_primitives::keccak256;
use tempo_contracts::precompiles::{INativeMultisig, NATIVE_MULTISIG_ADDRESS};
use tempo_precompiles::account_keychain::tree::WorkingTree;
use tempo_primitives::account::tree::{
    self, AccountOpening, PolicyLeaf, TreeAuthorization, TreeWitness, Usage,
};

const CAP: u64 = 12_000_000_000;

struct TreeFixture {
    f: Fixture,
    opening: AccountOpening,
    leaves: Vec<PolicyLeaf>,
    selected: usize,
}

impl TreeFixture {
    fn owner_call(&mut self, input: Vec<u8>, expected: AccountOpening) -> u64 {
        let mut tx = self.f.tx(false, 0, false);
        tx.max_fee_per_gas = CAP as u128;
        tx.calls[0].to = TxKind::Call(NATIVE_MULTISIG_ADDRESS);
        tx.calls[0].input = input.into();
        if self.f.sponsored {
            tx.fee_payer_signature = Some(
                self.f
                    .sponsor
                    .sign_hash_sync(&tx.fee_payer_signature_hash(self.f.parent.address()))
                    .unwrap(),
            );
        }
        let mut signature = self.f.parent.sign(tx.signature_hash());
        let TempoSignature::Multisig(native) = &mut signature else {
            unreachable!()
        };
        native.account_opening = Some(self.opening.clone());
        let signed = tx.into_signed(signature);
        self.f.test.evm.ctx.tx = TempoTxEnv::from_recovered_tx(&signed, self.f.parent.address());
        let result = self.f.test.handler.run(&mut self.f.test.evm).unwrap();
        assert!(result.is_success(), "{result:?}");
        let state = self.f.test.evm.ctx.journaled_state.finalize();
        assert_eq!(
            tempo_primitives::account::decode_config_commitment(
                &state[&self.f.parent.address()].info.extension,
                true
            )
            .unwrap(),
            expected.commitment()
        );
        self.f.test.evm.ctx.journaled_state.database.commit(state);
        self.f.nonce += 1;
        self.opening = expected;
        result.tx_gas_used()
    }

    fn new(
        parent: Actor,
        delegate: Actor,
        sponsored: bool,
        policy: usize,
        active: usize,
        fresh: bool,
    ) -> Self {
        assert!(parent.native && (1..=256).contains(&active));
        let mut f = Fixture::new(parent, delegate, true, sponsored, policy);
        f.test.evm.ctx.block.basefee = CAP;
        let mut opening = AccountOpening::empty(parent.config().commitment().unwrap());
        let tokens = f.auth.limits.as_ref().map_or(0, Vec::len);
        // Prior grants are fixture state, not part of the measured installation transaction.
        let leaves: Vec<_> = (0..active - 1)
            .map(|i| PolicyLeaf {
                id: i as u64,
                policy: B256::repeat_byte(0x93),
                usage: vec![Usage::default(); tokens],
            })
            .collect();
        opening.next_id = leaves.len() as u64;
        opening.count = leaves.len() as u16;
        opening.policies =
            tree::root(&leaves.iter().map(PolicyLeaf::hash).collect::<Vec<_>>()).unwrap();
        let mut info = f
            .test
            .evm
            .ctx
            .journaled_state
            .database
            .load_account(parent.address())
            .unwrap()
            .info
            .clone();
        info.extension = if fresh {
            Default::default()
        } else if leaves.is_empty() {
            tempo_primitives::account::encode_config_commitment(opening.authority).into()
        } else {
            tempo_primitives::account::encode_config_commitment(opening.commitment()).into()
        };
        assert!(!fresh || active == 1);
        f.test
            .evm
            .ctx
            .journaled_state
            .database
            .insert_account_info(parent.address(), info);
        f.auth.tree = Some(TreeAuthorization {
            epoch: 0,
            grant_id: opening.next_id,
            witness: TreeWitness {
                opening: opening.clone(),
                index: leaves.len() as u16,
                usage: vec![Usage::default(); tokens],
                siblings: tree::proof(
                    &leaves.iter().map(PolicyLeaf::hash).collect::<Vec<_>>(),
                    leaves.len(),
                )
                .unwrap(),
            },
        });
        f.auth.signature = parent.sign(f.auth.signature_hash());
        Self {
            f,
            opening,
            selected: leaves.len(),
            leaves,
        }
    }

    fn refresh(&mut self) {
        let witness = &mut self.f.auth.tree.as_mut().unwrap().witness;
        witness.opening = self.opening.clone();
        witness.index = self.selected as u16;
        if let Some(leaf) = self.leaves.get(self.selected) {
            witness.usage = leaf.usage.clone();
        }
        witness.siblings = tree::proof(
            &self.leaves.iter().map(PolicyLeaf::hash).collect::<Vec<_>>(),
            self.selected,
        )
        .unwrap();
    }

    fn execute(&mut self, amount: u64, fail: bool) -> (u64, WorkingTree) {
        self.refresh();
        let mut tx = self.f.tx(true, amount, fail);
        tx.max_fee_per_gas = CAP as u128;
        self.execute_tx(tx, !fail)
    }

    fn execute_tx(&mut self, tx: TempoTransaction, success: bool) -> (u64, WorkingTree) {
        self.f.prepare(tx);
        let result = self.f.test.handler.run(&mut self.f.test.evm).unwrap();
        assert_eq!(result.is_success(), success, "{result:?}");
        let gas = result.tx_gas_used();
        // The handler clears transient state at transaction end. Rebuild from the receipt's
        // final transition, exactly as a witness provider must (including failed transactions).
        let working = result.logs().iter().rev().find_map(|log| {
            if log.data.topics().first() != Some(&keccak256(b"TempoAccountTreeTransitionV2")) {
                return None;
            }
            let transition = <tempo_precompiles::account_keychain::tree::TreeTransition as alloy_rlp::Decodable>::decode(&mut log.data.data.as_ref()).unwrap();
            Some(WorkingTree { opening: transition.opening, index: transition.index, leaf: transition.leaf,
                siblings: self.f.auth.tree.as_ref().unwrap().witness.siblings.clone(),
                tokens: self.f.auth.limits.clone().unwrap_or_default() })
        }).unwrap_or_else(|| {
            let auth = self.f.auth.tree.as_ref().unwrap();
            let tokens = self.f.auth.limits.clone().unwrap_or_default();
            let (opening, leaf) = auth.open(self.f.auth.signature_hash(), tokens.len()).unwrap();
            WorkingTree { opening, leaf, index: auth.witness.index, siblings: auth.witness.siblings.clone(), tokens }
        });
        self.opening = working.opening.clone();
        if self.selected == self.leaves.len() {
            self.leaves.push(working.leaf.clone());
        } else {
            self.leaves[self.selected] = working.leaf.clone();
        }
        assert_eq!(
            self.opening.policies,
            tree::root(&self.leaves.iter().map(PolicyLeaf::hash).collect::<Vec<_>>()).unwrap()
        );
        let state = self.f.test.evm.ctx.journaled_state.finalize();
        if let Some(keychain) = state.get(&tempo_precompiles::ACCOUNT_KEYCHAIN_ADDRESS) {
            assert!(
                keychain
                    .storage
                    .values()
                    .all(|s| s.original_value() == s.present_value()),
                "no persistent keychain writes"
            );
        }
        let extension = &state[&self.f.parent.address()].info.extension;
        assert_eq!(
            tempo_primitives::account::decode_config_commitment(extension, true).unwrap(),
            self.opening.commitment()
        );
        self.f.test.evm.ctx.journaled_state.database.commit(state);
        self.f.nonce += 1;
        (gas, working)
    }
}

#[test]
fn account_tree_remove_compacts_without_resetting_usage() {
    let mut f = TreeFixture::new(secp(1, true), secp(2, false), true, 1, 4, false);
    f.execute(10, false);
    let input = INativeMultisig::removePolicyCall {
        leaves: f.leaves.iter().map(PolicyLeaf::hash).collect(),
        index: 1,
    }
    .abi_encode();
    f.leaves.swap_remove(1);
    f.selected = 1;
    let mut expected = f.opening.clone();
    expected.count -= 1;
    expected.policies =
        tree::root(&f.leaves.iter().map(PolicyLeaf::hash).collect::<Vec<_>>()).unwrap();
    f.owner_call(input, expected);
    let (_, usage) = f.execute(20, false);
    assert_eq!(usage.leaf.usage[0].spent, U256::from(30));
    let input = INativeMultisig::removePolicyCall {
        leaves: f.leaves.iter().map(PolicyLeaf::hash).collect(),
        index: 1,
    }
    .abi_encode();
    f.leaves.swap_remove(1);
    let mut expected = f.opening.clone();
    expected.count -= 1;
    expected.policies =
        tree::root(&f.leaves.iter().map(PolicyLeaf::hash).collect::<Vec<_>>()).unwrap();
    f.owner_call(input, expected);
    f.refresh();
    let mut tx = f.f.tx(true, 1, false);
    tx.max_fee_per_gas = CAP as u128;
    f.f.prepare(tx);
    assert!(f.f.test.handler.run(&mut f.f.test.evm).is_err());
}

#[test]
fn account_tree_cancel_unused_approval_and_rotate_authority() {
    let mut f = TreeFixture::new(secp(1, true), secp(2, false), true, 1, 1, false);
    let mut expected = f.opening.clone();
    expected.next_id = 5;
    f.owner_call(
        INativeMultisig::cancelPolicyApprovalsCall { nextId: 5 }.abi_encode(),
        expected,
    );
    f.refresh();
    assert!(
        f.f.auth
            .tree
            .as_ref()
            .unwrap()
            .open(f.f.auth.signature_hash(), 1)
            .is_err()
    );

    let mut f = TreeFixture::new(secp(1, true), secp(2, false), true, 1, 1, false);
    f.execute(10, false);
    let config = f.f.parent.config();
    let owners: Vec<_> = config
        .owners
        .iter()
        .map(|o| INativeMultisig::MultisigOwner {
            owner: o.owner,
            weight: o.weight,
        })
        .collect();
    let mut next = config.clone();
    next.version += 1;
    let mut expected = f.opening.clone();
    expected.authority = next.commitment().unwrap();
    expected.epoch += 1;
    expected.count = 0;
    expected.policies = tree::empty();
    f.owner_call(
        INativeMultisig::updateConfigCall {
            current: INativeMultisig::MultisigConfig {
                salt: config.salt,
                version: config.version,
                threshold: config.threshold,
                owners: owners.clone(),
            },
            threshold: config.threshold,
            owners,
        }
        .abi_encode(),
        expected,
    );
    assert_eq!(f.opening.next_id, 1);
    f.f.parent.version += 1;
    let mut expected = f.opening.clone();
    expected.next_id += 1;
    f.owner_call(
        INativeMultisig::cancelPolicyApprovalsCall { nextId: 2 }.abi_encode(),
        expected,
    );
    f.leaves.clear();
    f.refresh();
    let mut tx = f.f.tx(true, 1, false);
    tx.max_fee_per_gas = CAP as u128;
    f.f.prepare(tx);
    assert!(f.f.test.handler.run(&mut f.f.test.evm).is_err());
}

#[test]
fn account_tree_first_repeat_rollover_and_failed_fees() {
    for sponsored in [false, true] {
        for policy in 0..4 {
            let mut f =
                TreeFixture::new(secp(1, true), secp(2, false), sponsored, policy, 4, false);
            let (_, first) = f.execute(10, false);
            let (_, repeat) = f.execute(20, false);
            if policy != 0 {
                assert!(repeat.leaf.usage[0].spent >= first.leaf.usage[0].spent + U256::from(20));
                f.f.test.evm.ctx.block.timestamp = U256::from(200);
                let (_, later) = f.execute(1, false);
                if policy == 2 {
                    assert_eq!(later.leaf.usage[0].window, 1);
                    assert!(later.leaf.usage[0].spent < repeat.leaf.usage[0].spent);
                }
            }
        }
        let mut f = TreeFixture::new(secp(1, true), secp(2, true), sponsored, 3, 1, true);
        let (gas, failed) = f.execute(100, true);
        assert_eq!(
            failed.leaf.usage[0].spent,
            if sponsored {
                U256::ZERO
            } else {
                calc_gas_balance_spending(gas, CAP as u128)
            }
        );
    }
}

#[test]
fn account_tree_refresh_preserves_approvals_and_rejects_stale_state() {
    let mut f = TreeFixture::new(secp(1, true), secp(2, false), false, 3, 2, false);
    let old = f.f.auth.clone();
    let mut tx = f.f.tx(true, 10, false);
    let intent = tx.signature_hash();
    let payer = tx.fee_payer_signature_hash(f.f.parent.address());
    let bytes = alloy_rlp::encode(&tx);
    f.execute(10, false);
    f.refresh();
    tx.key_authorization = Some(f.f.auth.clone());
    assert_eq!(intent, tx.signature_hash());
    assert_eq!(payer, tx.fee_payer_signature_hash(f.f.parent.address()));
    assert_ne!(bytes, alloy_rlp::encode(&tx));
    f.f.auth = old;
    let mut stale = f.f.tx(true, 10, false);
    stale.max_fee_per_gas = CAP as u128;
    f.f.prepare(stale);
    assert!(f.f.test.handler.run(&mut f.f.test.evm).is_err());
}

#[test]
fn account_tree_failed_batches_settle_only_fees() {
    println!("TREE_FAILURE,failure,sponsored,active,gas,micro_pathusd");
    for failure in ["scope", "revert", "out-of-gas"] {
        for sponsored in [false, true] {
            for active in [1, 4, 256] {
                let mut f = TreeFixture::new(
                    secp(1, true),
                    secp(2, false),
                    sponsored,
                    if failure == "scope" { 3 } else { 1 },
                    active,
                    false,
                );
                let (_, first) = f.execute(10, false);
                f.refresh();
                let mut tx = f.f.tx(true, 20, false);
                tx.max_fee_per_gas = CAP as u128;
                tx.gas_limit = 500_000;
                // A successful first debit must roll back with the later failed call.
                let mut failing = tx.calls[0].clone();
                failing.to = TxKind::Call(RECIPIENT);
                if failure != "scope" {
                    let code = revm::bytecode::Bytecode::new_raw(
                        if failure == "revert" {
                            vec![0x5f, 0x5f, 0xfd]
                        } else {
                            vec![0x5b, 0x60, 0x00, 0x56]
                        }
                        .into(),
                    );
                    f.f.test
                        .evm
                        .ctx
                        .journaled_state
                        .database
                        .insert_account_info(
                            RECIPIENT,
                            revm::state::AccountInfo {
                                code_hash: code.hash_slow(),
                                code: Some(code),
                                ..Default::default()
                            },
                        );
                }
                tx.calls.push(failing);
                let (gas, after) = f.execute_tx(tx, false);
                let fee = calc_gas_balance_spending(gas, CAP as u128);
                assert_eq!(
                    after.leaf.usage[0].spent,
                    first.leaf.usage[0].spent + if sponsored { U256::ZERO } else { fee }
                );
                println!("TREE_FAILURE,{failure},{sponsored},{active},{gas},{fee}");
            }
        }
    }
}

#[test]
fn account_tree_delegate_rotation_preserves_budget() {
    let mut f = TreeFixture::new(secp(1, true), secp(2, true), true, 1, 4, false);
    f.execute(7, false);
    f.f.delegate.version = 1;
    let account = f.f.delegate.address();
    let commitment = f.f.delegate.config().commitment().unwrap();
    f.f.root_state(|_| {
        StorageCtx
            .set_config_commitment(
                account,
                commitment,
                tempo_precompiles::storage::ConfigCommitmentWriteGas::Precompile,
            )
            .unwrap()
    });
    let (_, working) = f.execute(5, false);
    assert_eq!(working.leaf.usage[0].spent, U256::from(12));
}

#[test]
#[ignore = "executed receipt matrix"]
fn account_tree_cost_matrix() {
    println!(
        "TREE_COST,parent,delegate,sponsored,policy,active,fresh,phase,bytes,gas,micro_pathusd"
    );
    for curve in [Curve::Secp, Curve::P256, Curve::WebAuthn] {
        for delegate_curve in [Curve::Secp, Curve::P256, Curve::WebAuthn] {
            for native_delegate in [false, true] {
                for sponsored in [false, true] {
                    for policy in 0..4 {
                        for active in [1, 2, 4, 8, 16, 64, 256] {
                            for fresh in [false, true] {
                                if fresh && active != 1 {
                                    continue;
                                }
                                let parent = Actor {
                                    curve,
                                    ..secp(1, true)
                                };
                                let delegate = Actor {
                                    curve: delegate_curve,
                                    ..secp(2, native_delegate)
                                };
                                let mut f = TreeFixture::new(
                                    parent, delegate, sponsored, policy, active, fresh,
                                );
                                for phase in 0..3 {
                                    if phase == 2 {
                                        f.f.test.evm.ctx.block.timestamp = U256::from(200);
                                    }
                                    f.refresh();
                                    let bytes = alloy_rlp::encode(&f.f.auth).len();
                                    let (gas, _) = f.execute(10, false);
                                    println!(
                                        "TREE_COST,{curve:?},{delegate_curve:?}-{native_delegate},{sponsored},{policy},{active},{fresh},{phase},{bytes},{gas},{}",
                                        calc_gas_balance_spending(gas, CAP as u128)
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
#[ignore = "executed boundary receipts"]
fn account_tree_cost_edges() {
    println!("TREE_EDGE,edge,sponsored,phase,bytes,gas,status");
    for edge in [
        "max-webauthn",
        "eight-owner-quorums",
        "eight-max-webauthn",
        "32-tokens",
        "32-calls",
        "120-recipients",
        "new-accounts",
        "late-first-period",
    ] {
        for sponsored in [false, true] {
            let mut parent = secp(1, true);
            let mut delegate = secp(60, true);
            if edge == "max-webauthn" {
                parent.curve = Curve::WebAuthnMax;
                delegate.curve = Curve::WebAuthnMax;
            }
            if edge.ends_with("owner-quorums") {
                parent.quorum = 8;
                delegate.quorum = parent.quorum;
            }
            if edge == "eight-max-webauthn" {
                parent.quorum = 8;
                parent.curve = Curve::WebAuthnMax;
                delegate.quorum = 8;
                delegate.curve = Curve::WebAuthnMax;
                // This valid quorum shape exceeds the carried wrapper bound even before
                // execution; construct it without the size-checking fixture constructor.
                let mut auth =
                    KeyAuthorization::unrestricted(1, delegate.kind(), delegate.address())
                        .with_account(parent.address())
                        .with_witness(B256::repeat_byte(0x42))
                        .into_signed(parent.sign(B256::ZERO));
                auth.authorization.expiry = core::num::NonZeroU64::new(10_000);
                let authority = parent.config().commitment().unwrap();
                auth.carried = Some(CarriedAuthorization {
                    valid_after: 100,
                    authority_config: authority,
                });
                auth.tree = Some(TreeAuthorization {
                    epoch: 0,
                    grant_id: 0,
                    witness: TreeWitness {
                        opening: AccountOpening::empty(authority),
                        ..Default::default()
                    },
                });
                auth.signature = parent.sign(auth.signature_hash());
                let bytes = alloy_rlp::encode(&auth);
                assert!(bytes.len() > tempo_primitives::transaction::carried_authorization::MAX_CARRIED_AUTHORIZATION_BYTES);
                assert!(
                    <SignedKeyAuthorization as alloy_rlp::Decodable>::decode(&mut bytes.as_slice())
                        .is_err()
                );
                for phase in 0..2 {
                    println!(
                        "TREE_EDGE,{edge},{sponsored},{phase},{},0,rejected-size",
                        bytes.len()
                    );
                }
                continue;
            }
            let mut f = TreeFixture::new(
                parent,
                delegate,
                sponsored,
                if edge == "late-first-period" { 2 } else { 1 },
                1,
                edge == "new-accounts",
            );
            if edge == "new-accounts" {
                f.f.nonce = 0;
                for account in [parent.address(), delegate.address()] {
                    f.f.test
                        .evm
                        .ctx
                        .journaled_state
                        .database
                        .insert_account_info(account, Default::default());
                }
            }
            if edge == "32-tokens" {
                let tokens: Vec<_> = (0..32)
                    .map(|i| {
                        let mut token = PATH_USD_ADDRESS;
                        token.0[19] = i;
                        tempo_primitives::transaction::TokenLimit {
                            token,
                            limit: U256::from(1_000_000_000u64),
                            period: 0,
                        }
                    })
                    .collect();
                f.f.auth.authorization.limits = Some(tokens);
                f.f.auth.tree.as_mut().unwrap().witness.usage = vec![Usage::default(); 32];
            }
            if edge == "120-recipients" {
                let mut recipients: Vec<_> = (1..120)
                    .map(|i| {
                        let mut bytes = [0; 20];
                        bytes[19] = i;
                        Address::from(bytes)
                    })
                    .collect();
                recipients.push(RECIPIENT);
                f.f.auth.authorization.allowed_calls =
                    Some(vec![tempo_primitives::transaction::CallScope {
                        target: PATH_USD_ADDRESS,
                        selector_rules: vec![tempo_primitives::transaction::SelectorRule {
                            selector: ITIP20::transferCall::SELECTOR,
                            recipients,
                        }],
                    }]);
            }
            f.f.auth.signature = parent.sign(f.f.auth.signature_hash());
            if edge == "late-first-period" {
                f.f.test.evm.ctx.block.timestamp = U256::from(1_000);
            }
            for phase in 0..2 {
                f.refresh();
                let bytes = alloy_rlp::encode(&f.f.auth).len();
                if bytes > tempo_primitives::transaction::carried_authorization::MAX_CARRIED_AUTHORIZATION_BYTES {
                    assert!(<SignedKeyAuthorization as alloy_rlp::Decodable>::decode(&mut alloy_rlp::encode(&f.f.auth).as_slice()).is_err());
                    println!("TREE_EDGE,{edge},{sponsored},{phase},{bytes},0,rejected-size");
                    continue;
                }
                let mut tx = f.f.tx(true, 1, false);
                tx.max_fee_per_gas = CAP as u128;
                if edge == "32-calls" {
                    tx.calls = vec![tx.calls[0].clone(); 32];
                }
                let (gas, _) = f.execute_tx(tx, true);
                println!("TREE_EDGE,{edge},{sponsored},{phase},{bytes},{gas},success");
            }
        }
    }
}
