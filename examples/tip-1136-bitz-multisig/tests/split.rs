//! Two secp256k1 slots and two passkey slots ([`Profile::Split`]).

mod common;

use common::*;
use tip_1136_bitz::{
    Error,
    policy::{Profile, Statement, Witness},
};

const PROFILE: Profile = Profile::Split;

fn honest(indices: &[usize]) -> Witness {
    let approvals: Vec<_> = indices.iter().map(|&i| approve(i, &digest())).collect();
    Witness::new(PROFILE, &policy(), &approvals, &digest()).unwrap()
}

fn satisfied(witness: &Witness) -> Result<(), Error> {
    authorizer(PROFILE)
        .lock()
        .unwrap()
        .check(&statement(), witness)
}

#[track_caller]
fn assert_rejected(witness: &Witness) {
    assert!(matches!(satisfied(witness), Err(Error::Unsatisfied)));
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
fn both_passkeys_meet_threshold() {
    satisfied(&honest(&[CAROL, DAVE])).unwrap();
}

#[test]
fn three_secp256k1_approvals_do_not_fit() {
    let approvals: Vec<_> = [ALICE, BOB, EVE].map(|i| approve(i, &digest())).into();
    assert!(Witness::new(PROFILE, &policy(), &approvals, &digest()).is_err());
}

#[test]
fn two_light_signers_insufficient() {
    assert_rejected(&honest(&[ALICE, BOB]));
}

#[test]
fn same_member_twice_in_group() {
    let mut witness = honest(&[ALICE, CAROL]);
    witness.slots[1] = witness.slots[0].clone();
    assert_rejected(&witness);
}

#[test]
fn out_of_order_in_group() {
    let mut witness = honest(&[ALICE, CAROL, DAVE]);
    witness.slots.swap(2, 3);
    assert_rejected(&witness);
}

#[test]
fn padding_gap_in_group() {
    let mut witness = honest(&[ALICE, BOB, DAVE]);
    witness.slots.swap(2, 3);
    assert!(!witness.slots[2].enabled);
    assert_rejected(&witness);
}

#[test]
fn secp256k1_member_in_passkey_group() {
    // Moving alice's approval into a passkey slot changes the leaf's kind bit,
    // so the member cannot count once per group.
    let mut witness = honest(&[ALICE, BOB, CAROL]);
    let mut moved = witness.slots[0].clone();
    moved.is_passkey = true;
    witness.slots[3] = moved;
    assert_rejected(&witness);
}

#[test]
fn prove_and_verify() {
    let mut authorizer = authorizer(PROFILE).lock().unwrap();
    let proof = authorizer
        .prove(statement(), &honest(&[ALICE, CAROL, EVE]))
        .unwrap();
    authorizer.verify(statement(), &proof).unwrap();
    let other = Statement {
        authorization_digest: other_digest(),
        ..statement()
    };
    assert!(authorizer.verify(other, &proof).is_err());
}
