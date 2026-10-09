// Policy: 5 hidden members, weighted, threshold 3.
//   0 alice  secp256k1  w1      2 carol  passkey  w1      4 eve  secp256k1  w1
//   1 bob    secp256k1  w1      3 dave   passkey  w2 (CFO)
use crate::{Approval, authorize, DEPTH, MAX_APPROVALS, MAX_CDJ};
use crate::hashing::{build_tree, member_leaf, policy_commitment, EMPTY_LEAF};
use crate::vectors::{ALICE_AD, ALICE_CDJ, ALICE_CDJ_LEN, ALICE_KIND, ALICE_RP, ALICE_SIG, ALICE_X, ALICE_Y, BOB_AD, BOB_CDJ, BOB_CDJ_LEN, BOB_KIND, BOB_RP, BOB_SIG, BOB_X, BOB_Y, CAROL_AD, CAROL_CDJ, CAROL_CDJ_LEN, CAROL_KIND, CAROL_NO_UV_AD, CAROL_NO_UV_SIG, CAROL_RP, CAROL_SIG, CAROL_X, CAROL_Y, DAVE_AD, DAVE_CDJ, DAVE_CDJ_LEN, DAVE_KIND, DAVE_RP, DAVE_SIG, DAVE_X, DAVE_Y, DIGEST_HI, DIGEST_LO, EVE_AD, EVE_CDJ, EVE_CDJ_LEN, EVE_KIND, EVE_RP, EVE_SIG, EVE_X, EVE_Y, MALLORY_SIG, MALLORY_X, MALLORY_Y};

global THRESHOLD: u32 = 3;
global SALT: Field = 0x5a17ed5a17ed5a17ed; // private commitment randomness
global WEIGHTS: [u32; 5] = [1, 1, 1, 2, 1];

struct Cred { kind: u8, x: [u8; 32], y: [u8; 32], rp: [u8; 32], sig: [u8; 64], ad: [u8; 37], cdj: [u8; MAX_CDJ], cdj_len: u32 }

fn creds() -> [Cred; 5] {
    [
        Cred { kind: ALICE_KIND, x: ALICE_X, y: ALICE_Y, rp: ALICE_RP, sig: ALICE_SIG, ad: ALICE_AD, cdj: ALICE_CDJ, cdj_len: ALICE_CDJ_LEN },
        Cred { kind: BOB_KIND, x: BOB_X, y: BOB_Y, rp: BOB_RP, sig: BOB_SIG, ad: BOB_AD, cdj: BOB_CDJ, cdj_len: BOB_CDJ_LEN },
        Cred { kind: CAROL_KIND, x: CAROL_X, y: CAROL_Y, rp: CAROL_RP, sig: CAROL_SIG, ad: CAROL_AD, cdj: CAROL_CDJ, cdj_len: CAROL_CDJ_LEN },
        Cred { kind: DAVE_KIND, x: DAVE_X, y: DAVE_Y, rp: DAVE_RP, sig: DAVE_SIG, ad: DAVE_AD, cdj: DAVE_CDJ, cdj_len: DAVE_CDJ_LEN },
        Cred { kind: EVE_KIND, x: EVE_X, y: EVE_Y, rp: EVE_RP, sig: EVE_SIG, ad: EVE_AD, cdj: EVE_CDJ, cdj_len: EVE_CDJ_LEN },
    ]
}

fn roster() -> (Field, [[Field; DEPTH]; 16]) {
    let c = creds();
    let mut leaves = [EMPTY_LEAF; 16];
    for i in 0..5 {
        leaves[i] = member_leaf(c[i].kind, WEIGHTS[i], c[i].x, c[i].y, c[i].rp);
    }
    build_tree(leaves)
}

fn empty() -> Approval {
    Approval { enabled: false, kind: 0, weight: 0, leaf_index: 0, path: [0; DEPTH], pk_x: [0; 32], pk_y: [0; 32], rp_id_hash: [0; 32], signature: [0; 64], auth_data: [0; 37], client_data_json: [0; MAX_CDJ], client_data_json_len: 0 }
}

fn approval(i: u32) -> Approval {
    let c = creds()[i];
    let (_, paths) = roster();
    Approval { enabled: true, kind: c.kind, weight: WEIGHTS[i], leaf_index: i, path: paths[i], pk_x: c.x, pk_y: c.y, rp_id_hash: c.rp, signature: c.sig, auth_data: c.ad, client_data_json: c.cdj, client_data_json_len: c.cdj_len }
}

fn with(list: [Approval; MAX_APPROVALS]) {
    let (root, _) = roster();
    authorize(policy_commitment(root, THRESHOLD, SALT), DIGEST_HI, DIGEST_LO, root, THRESHOLD, SALT, list);
}

// ---------------------------------------------------------------- accept
#[test]
fn three_of_five_mixed_hardware_and_passkeys() { with([approval(0), approval(2), approval(4), empty()]); }

#[test]
fn weighted_cfo_passkey_plus_one() { with([approval(1), approval(3), empty(), empty()]); }

#[test]
fn all_four_slots() { with([approval(0), approval(1), approval(2), approval(3)]); }

#[test]
fn print_public_statement() {
    let (root, _) = roster();
    println(policy_commitment(root, THRESHOLD, SALT));
}

// ---------------------------------------------------------------- reject
#[test(should_fail_with = "threshold not met")]
fn two_light_signers_insufficient() { with([approval(0), approval(1), empty(), empty()]); }

#[test(should_fail_with = "approvals must be strictly increasing")]
fn same_member_twice() { with([approval(0), approval(0), approval(1), empty()]); }

#[test(should_fail_with = "approvals must be strictly increasing")]
fn out_of_order() { with([approval(1), approval(0), approval(2), empty()]); }

#[test(should_fail_with = "enabled approvals must be packed first")]
fn padding_gap() { with([approval(0), empty(), approval(2), approval(4)]); }

#[test(should_fail_with = "not a roster member")]
fn inflated_weight() {
    let mut a = approval(0);
    a.weight = 3;
    with([a, empty(), empty(), empty()]);
}

#[test(should_fail_with = "not a roster member")]
fn outsider_with_stolen_path() {
    let mut a = approval(0);
    a.pk_x = MALLORY_X; a.pk_y = MALLORY_Y; a.signature = MALLORY_SIG;
    with([a, approval(1), approval(2), empty()]);
}

#[test(should_fail_with = "bad secp256k1 approval")]
fn signature_over_other_action() {
    let (root, _) = roster();
    authorize(policy_commitment(root, THRESHOLD, SALT), DIGEST_HI, DIGEST_LO + 1, root, THRESHOLD, SALT,
        [approval(0), approval(1), approval(4), empty()]);
}

#[test(should_fail_with = "challenge != authorization digest")]
fn passkey_over_other_action() {
    let (root, _) = roster();
    authorize(policy_commitment(root, THRESHOLD, SALT), DIGEST_HI, DIGEST_LO + 1, root, THRESHOLD, SALT,
        [approval(2), approval(3), empty(), empty()]);
}

#[test(should_fail_with = "policy opening mismatch")]
fn wrong_salt() {
    let (root, _) = roster();
    authorize(policy_commitment(root, THRESHOLD, SALT), DIGEST_HI, DIGEST_LO, root, THRESHOLD, SALT + 1,
        [approval(0), approval(2), approval(4), empty()]);
}

#[test(should_fail_with = "policy opening mismatch")]
fn prover_lowers_threshold() {
    let (root, _) = roster();
    authorize(policy_commitment(root, THRESHOLD, SALT), DIGEST_HI, DIGEST_LO, root, 1, SALT,
        [approval(0), empty(), empty(), empty()]);
}

#[test(should_fail_with = "user verification required")]
fn passkey_without_user_verification() {
    let mut a = approval(2);
    a.auth_data = CAROL_NO_UV_AD; a.signature = CAROL_NO_UV_SIG;
    with([a, approval(3), empty(), empty()]);
}

#[test(should_fail_with = "rpIdHash mismatch")]
fn passkey_for_other_rp() {
    let mut a = approval(2);
    a.auth_data[0] ^= 1;
    with([a, approval(3), empty(), empty()]);
}

#[test(should_fail_with = "bad passkey approval")]
fn tampered_client_data() {
    let mut a = approval(3);
    a.client_data_json[100] ^= 1;
    with([approval(1), a, empty(), empty()]);
}

// Used by scripts/gen_prover_toml.py to emit Prover.toml for the 3-of-5 example.
#[test]
fn print_witness_material() {
    let (root, paths) = roster();
    println(root);
    for i in 0..5 { println(paths[i]); }
}
