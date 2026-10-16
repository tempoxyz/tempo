//! Accepting and adversarial witnesses for the private weighted multisig,
//! four slots of any kind ([`Profile::Mixed`]).
//!
//! Rejections are checked against the constraint system itself: the witness
//! generator runs the honest hints, and `Error::Unsatisfied` means some rank-1
//! constraint fails on the resulting assignment.

mod common;

use bitz_cli::end_to_end::CircuitStatement;
use circuit::constraints::ConstraintGenerator;
use common::*;
use tip_1136_bitz::{
    Error,
    policy::{Approval, Evidence, FLAG_UP, Profile, Statement, Witness},
    relation::{PrivateAuthorization, witness_bits},
};

const PROFILE: Profile = Profile::Mixed;

fn witness(approvals: &[Approval]) -> Witness {
    Witness::new(PROFILE, &policy(), approvals, &digest()).unwrap()
}

fn honest(indices: &[usize]) -> Witness {
    let approvals: Vec<_> = indices.iter().map(|&i| approve(i, &digest())).collect();
    witness(&approvals)
}

fn satisfied_for(statement: &Statement, witness: &Witness) -> Result<(), Error> {
    authorizer(PROFILE)
        .lock()
        .unwrap()
        .check(statement, witness)
}

fn satisfied(witness: &Witness) -> Result<(), Error> {
    satisfied_for(&statement(), witness)
}

#[track_caller]
fn assert_rejected(witness: &Witness) {
    assert!(matches!(satisfied(witness), Err(Error::Unsatisfied)));
}

#[test]
fn input_layout_matches_witness_encoding() {
    assert_eq!(
        witness_bits(&statement(), &honest(&[ALICE])).len(),
        tip_1136_bitz::relation::INPUT_BITS
    );
}

/// `set_statement` reuses one constraint system, which is sound only if the
/// constraints do not depend on the statement.
#[test]
fn constraints_do_not_depend_on_the_statement() {
    let matrices = |statement: Statement| {
        let statement = PrivateAuthorization {
            profile: PROFILE,
            statement,
        };
        let mut cs = ConstraintGenerator::<num_bigint::BigInt>::new(statement.input_bits());
        let inputs: Vec<_> = (0..statement.input_bits()).map(|i| cs.input(i)).collect();
        statement.synthesize(&mut cs, &inputs).unwrap();
        cs.into_matrices()
    };
    assert!(matrices(statement()) == matrices(Statement::default()));
}

#[test]
fn mixed_k1_passkey_k1_meets_threshold() {
    satisfied(&honest(&[ALICE, CAROL, EVE])).unwrap();
}

#[test]
fn heavy_passkey_meets_threshold() {
    satisfied(&honest(&[BOB, DAVE])).unwrap();
}

#[test]
fn full_house_meets_threshold() {
    satisfied(&honest(&[ALICE, BOB, CAROL, DAVE])).unwrap();
}

#[test]
fn two_light_signers_insufficient() {
    assert_rejected(&honest(&[ALICE, BOB]));
}

#[test]
fn same_member_twice() {
    let mut witness = honest(&[ALICE, BOB, EVE]);
    witness.slots[1] = witness.slots[0].clone();
    assert_rejected(&witness);
}

#[test]
fn out_of_order() {
    let mut witness = honest(&[ALICE, CAROL, EVE]);
    witness.slots.swap(0, 2);
    assert_rejected(&witness);
}

#[test]
fn padding_gap() {
    let mut witness = honest(&[ALICE, CAROL, EVE]);
    witness.slots.rotate_right(1);
    assert!(!witness.slots[0].enabled);
    assert_rejected(&witness);
}

#[test]
fn inflated_weight() {
    let mut witness = honest(&[ALICE, BOB]);
    witness.slots[0].weight = 2;
    assert_rejected(&witness);
}

#[test]
fn outsider_with_stolen_path() {
    let mut witness = honest(&[ALICE, CAROL, EVE]);
    let mallory = k1_member("mallory", 1);
    let slot = &mut witness.slots[0];
    slot.pk_x = mallory.pk_x;
    slot.pk_y = mallory.pk_y;
    slot.secp256k1.qx = num_bigint::BigUint::from_bytes_be(&mallory.pk_x);
    slot.secp256k1.qy = num_bigint::BigUint::from_bytes_be(&mallory.pk_y);
    let signature = k1_sign("mallory", &digest());
    slot.secp256k1.r = num_bigint::BigUint::from_bytes_be(&signature[..32]);
    slot.secp256k1.s = num_bigint::BigUint::from_bytes_be(&signature[32..]);
    assert_rejected(&witness);
}

#[test]
fn signature_over_other_action() {
    let mut approvals: Vec<_> = [ALICE, CAROL, EVE].map(|i| approve(i, &digest())).into();
    approvals[0] = approve(ALICE, &other_digest());
    assert_rejected(&witness(&approvals));
}

#[test]
fn passkey_over_other_action() {
    let mut approvals: Vec<_> = [ALICE, CAROL, EVE].map(|i| approve(i, &digest())).into();
    approvals[1] = approve(CAROL, &other_digest());
    assert_rejected(&witness(&approvals));
}

#[test]
fn wrong_salt() {
    let mut witness = honest(&[ALICE, CAROL, EVE]);
    witness.salt[0] ^= 1;
    assert_rejected(&witness);
}

#[test]
fn prover_lowers_threshold() {
    let mut witness = honest(&[ALICE]);
    witness.threshold = 1;
    assert_rejected(&witness);
}

#[test]
fn zero_threshold() {
    // Even a policy committed with threshold 0 cannot authorize anything.
    let mut low = policy();
    low.threshold = 0;
    let mut witness = honest(&[]);
    witness.threshold = 0;
    witness.roster_root = low.roster_root();
    let statement = Statement {
        policy_commitment: low.commitment(),
        authorization_digest: digest(),
    };
    assert!(matches!(
        satisfied_for(&statement, &witness),
        Err(Error::Unsatisfied)
    ));
}

#[test]
fn approval_for_other_statement() {
    // A satisfying witness for another digest does not satisfy this one.
    let approvals: Vec<_> = [ALICE, CAROL, EVE]
        .map(|i| approve(i, &other_digest()))
        .into();
    let witness = Witness::new(PROFILE, &policy(), &approvals, &other_digest()).unwrap();
    let other = Statement {
        policy_commitment: statement().policy_commitment,
        authorization_digest: other_digest(),
    };
    satisfied_for(&other, &witness).unwrap();
    assert_rejected(&witness);
}

#[test]
fn passkey_without_user_verification() {
    let mut approvals: Vec<_> = [ALICE, CAROL, EVE].map(|i| approve(i, &digest())).into();
    let mut params = WebAuthn::honest(digest());
    params.flags = FLAG_UP;
    approvals[1].evidence = passkey_evidence("carol", &params);
    assert_rejected(&witness(&approvals));
}

#[test]
fn passkey_for_other_rp() {
    let mut approvals: Vec<_> = [ALICE, CAROL, EVE].map(|i| approve(i, &digest())).into();
    let mut params = WebAuthn::honest(digest());
    params.rp_id = "evil.example".into();
    approvals[1].evidence = passkey_evidence("carol", &params);
    assert_rejected(&witness(&approvals));
}

#[test]
fn tampered_client_data() {
    let mut approvals: Vec<_> = [ALICE, CAROL, EVE].map(|i| approve(i, &digest())).into();
    let Evidence::Passkey {
        client_data_json, ..
    } = &mut approvals[1].evidence
    else {
        unreachable!()
    };
    let last = client_data_json.len() - 2;
    client_data_json[last] = b'X';
    assert_rejected(&witness(&approvals));
}

#[test]
fn kind_confusion() {
    // Claim a secp256k1 member is a passkey: the leaf commits to the kind.
    let mut approvals: Vec<_> = [ALICE, CAROL, EVE].map(|i| approve(i, &digest())).into();
    approvals[0] = Approval {
        leaf_index: ALICE,
        evidence: passkey_evidence("alice", &WebAuthn::honest(digest())),
    };
    let mut witness = witness(&[approvals[1].clone(), approvals[2].clone()]);
    let alice = policy().members[ALICE].clone();
    let mut slot = witness.slots[0].clone();
    let Evidence::Passkey {
        signature,
        auth_data,
        client_data_json,
    } = &approvals[0].evidence
    else {
        unreachable!()
    };
    let r1 = r1_key("alice");
    let point = r1.verifying_key().to_encoded_point(false);
    slot.leaf_index = ALICE as u8;
    slot.path = policy().path(ALICE);
    slot.weight = alice.weight;
    slot.pk_x = point.as_bytes()[1..33].try_into().unwrap();
    slot.pk_y = point.as_bytes()[33..65].try_into().unwrap();
    slot.rp_id_hash = sha256_rp();
    slot.auth_data = *auth_data;
    let padded = tip_1136_bitz::policy::sha256_pad(client_data_json);
    slot.cdj_blocks = [0; 256];
    slot.cdj_blocks[..padded.len()].copy_from_slice(&padded);
    slot.cdj_block_count = padded.len() / 64;
    slot.p256.qx = num_bigint::BigUint::from_bytes_be(&slot.pk_x);
    slot.p256.qy = num_bigint::BigUint::from_bytes_be(&slot.pk_y);
    slot.p256.r = num_bigint::BigUint::from_bytes_be(&signature[..32]);
    slot.p256.s = num_bigint::BigUint::from_bytes_be(&signature[32..]);
    witness.slots.rotate_right(1);
    witness.slots[0] = slot;
    assert_rejected(&witness);
}

fn sha256_rp() -> [u8; 32] {
    tip_1136_bitz::policy::sha256(RP_ID.as_bytes())
}

#[test]
fn prove_and_verify() {
    let mut authorizer = authorizer(PROFILE).lock().unwrap();
    let proof = authorizer
        .prove(statement(), &honest(&[ALICE, CAROL, EVE]))
        .unwrap();
    authorizer.verify(statement(), &proof).unwrap();

    // The same proof does not verify for another action or policy.
    let other_action = Statement {
        authorization_digest: other_digest(),
        ..statement()
    };
    assert!(authorizer.verify(other_action, &proof).is_err());
    let mut other_policy = statement();
    other_policy.policy_commitment[31] ^= 1;
    assert!(authorizer.verify(other_policy, &proof).is_err());

    // A prover cannot claim a statement other than the one in its inputs.
    let approvals: Vec<_> = [ALICE, CAROL, EVE]
        .map(|i| approve(i, &other_digest()))
        .into();
    let witness = Witness::new(PROFILE, &policy(), &approvals, &other_digest()).unwrap();
    authorizer.bind(statement());
    let system = authorizer.system();
    let assignment = system
        .witness(&witness_bits(&other_action, &witness))
        .unwrap();
    let commitment = system.commit(&assignment).unwrap();
    if let Ok(proof) = system.prove(assignment, commitment) {
        assert!(authorizer.verify(statement(), &proof).is_err());
    }
}

#[test]
fn unpadded_client_data_blocks() {
    // A passkey signature over a compression chain of blocks that are not
    // SHA-256 padding of any message must not count, even with a valid
    // signature over exactly that chain.
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use tip_1136_bitz::policy::CDJ_CHECKED_LEN;

    let mut witness = honest(&[ALICE, CAROL, EVE]);
    let slot = &mut witness.slots[1];
    assert!(slot.is_passkey);
    slot.cdj_blocks[CDJ_CHECKED_LEN..128].fill(b'x');
    slot.cdj_block_count = 2;
    let signature: p256::ecdsa::Signature = r1_key("carol")
        .sign_prehash(&slot.webauthn_message())
        .unwrap();
    let bytes = signature.to_bytes();
    slot.p256.r = num_bigint::BigUint::from_bytes_be(&bytes[..32]);
    slot.p256.s = num_bigint::BigUint::from_bytes_be(&bytes[32..]);
    assert_rejected(&witness);
}

#[test]
fn wrong_padding_length_field() {
    use k256::ecdsa::signature::hazmat::PrehashSigner;

    let mut witness = honest(&[ALICE, CAROL, EVE]);
    let slot = &mut witness.slots[1];
    let end = 64 * slot.cdj_block_count;
    slot.cdj_blocks[end - 1] ^= 0x08;
    let signature: p256::ecdsa::Signature = r1_key("carol")
        .sign_prehash(&slot.webauthn_message())
        .unwrap();
    let bytes = signature.to_bytes();
    slot.p256.r = num_bigint::BigUint::from_bytes_be(&bytes[..32]);
    slot.p256.s = num_bigint::BigUint::from_bytes_be(&bytes[32..]);
    assert_rejected(&witness);
}
