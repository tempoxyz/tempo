use alloy_primitives::Address;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::zones::ZoneIdentityError;
use tempo_precompiles::storage::{StorageCtx, hashmap::HashMapStorageProvider};
use tempo_primitives::TempoAddressExt as _;

use super::*;
use crate::error::ZonePrecompileError;

fn with_identity<R>(f: impl FnOnce(&mut ZoneIdentity, Address) -> R) -> R {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
    StorageCtx::enter(&mut storage, || {
        let registrar = Address::repeat_byte(0xbb);
        f(&mut ZoneIdentity::new(), registrar)
    })
}

fn token(id: u64) -> Address {
    Address::new_tip20(id)
}

fn identity_error(error: ZoneIdentityError) -> ZonePrecompileError {
    error.into()
}

/// Whether the move is allowed with enforcement on.
fn allows(token: Address, from: Address, to: Address, kind: TransferKind) -> bool {
    ZoneIdentity::new()
        .allows(true, token, from, to, kind)
        .unwrap()
}

const ALICE: Address = Address::repeat_byte(0x11);
const BOB: Address = Address::repeat_byte(0x22);

/// One org administered by the returned admin, with Alice and Bob as members and `usd` allowed
/// inside it.
fn org_with_members(
    identity: &mut ZoneIdentity,
    registrar: Address,
    usd: Address,
) -> (Address, u64) {
    let admin = Address::repeat_byte(1);
    let org = identity.create_org(registrar, registrar, admin).unwrap();
    identity
        .set_outbound(admin, registrar, org, org, &[usd], true)
        .unwrap();
    identity
        .set_inbound(admin, registrar, org, org, &[usd], true)
        .unwrap();
    identity.add_member(admin, registrar, org, ALICE).unwrap();
    identity.add_member(admin, registrar, org, BOB).unwrap();
    (admin, org)
}

#[test]
fn admins_only_set_their_own_half() {
    with_identity(|identity, registrar| {
        let (admin_a, admin_b) = (Address::repeat_byte(1), Address::repeat_byte(2));
        let a = identity.create_org(registrar, registrar, admin_a).unwrap();
        let b = identity.create_org(registrar, registrar, admin_b).unwrap();
        assert_eq!(
            identity.set_inbound(admin_a, registrar, b, a, &[token(1)], true),
            Err(identity_error(ZoneIdentityError::unauthorized()))
        );
        assert_eq!(
            identity.set_outbound(admin_b, registrar, a, b, &[token(1)], true),
            Err(identity_error(ZoneIdentityError::unauthorized()))
        );
        assert_eq!(
            identity.set_outbound(admin_a, registrar, a, 9, &[token(1)], true),
            Err(identity_error(ZoneIdentityError::unknown_org(9)))
        );
    });
}

#[test]
fn edges_are_per_token() {
    with_identity(|identity, registrar| {
        let (usd, share, other) = (token(1), token(2), token(3));
        org_with_members(identity, registrar, usd);
        assert!(allows(usd, ALICE, BOB, TransferKind::InZone));
        assert!(!allows(share, ALICE, BOB, TransferKind::InZone));
        assert!(!allows(other, ALICE, BOB, TransferKind::InZone));
    });
}

#[test]
fn removed_members_keep_only_the_self_withdrawal_exit() {
    with_identity(|identity, registrar| {
        let usd = token(1);
        let (admin, _) = org_with_members(identity, registrar, usd);
        // Members cannot remove themselves.
        assert_eq!(
            identity.remove_member(BOB, registrar, BOB),
            Err(identity_error(ZoneIdentityError::unauthorized()))
        );
        identity.remove_member(admin, registrar, BOB).unwrap();
        assert!(!allows(usd, ALICE, BOB, TransferKind::InZone));
        assert!(allows(usd, BOB, BOB, TransferKind::Withdrawal));
    });
}

#[test]
fn an_address_belongs_to_one_org() {
    with_identity(|identity, registrar| {
        let (admin_a, admin_b) = (Address::repeat_byte(1), Address::repeat_byte(2));
        let a = identity.create_org(registrar, registrar, admin_a).unwrap();
        let b = identity.create_org(registrar, registrar, admin_b).unwrap();
        identity.add_member(admin_a, registrar, a, ALICE).unwrap();
        assert_eq!(
            identity.add_member(admin_b, registrar, b, ALICE),
            Err(identity_error(ZoneIdentityError::already_member(ALICE)))
        );
    });
}

#[test]
fn tempo_sides_are_separate_from_zone_sides() {
    with_identity(|identity, registrar| {
        let usd = token(1);
        let (admin, org) = org_with_members(identity, registrar, usd);
        let exit_admin = Address::repeat_byte(2);
        let exits = identity
            .create_org(registrar, registrar, exit_admin)
            .unwrap();
        let offramp = Address::repeat_byte(0x33);
        identity
            .add_member(exit_admin, registrar, exits, offramp)
            .unwrap();
        // Withdrawals from the org to the exit org's Tempo addresses, not transfers to it.
        identity
            .set_outbound(admin, registrar, org, exits | L1_SIDE, &[usd], true)
            .unwrap();
        identity
            .set_inbound(exit_admin, registrar, exits | L1_SIDE, org, &[usd], true)
            .unwrap();
        assert!(allows(usd, ALICE, offramp, TransferKind::Withdrawal));
        assert!(!allows(usd, ALICE, offramp, TransferKind::InZone));
        assert!(!allows(usd, offramp, ALICE, TransferKind::Deposit));

        // Org 0's Tempo side stands for any address on Tempo: the org accepts deposits from anyone.
        let stranger = Address::repeat_byte(0x44);
        assert!(!allows(usd, stranger, ALICE, TransferKind::Deposit));
        identity
            .set_outbound(registrar, registrar, L1_SIDE, org, &[usd], true)
            .unwrap();
        identity
            .set_inbound(admin, registrar, org, L1_SIDE, &[usd], true)
            .unwrap();
        assert!(allows(usd, stranger, ALICE, TransferKind::Deposit));
        assert!(allows(usd, offramp, ALICE, TransferKind::Deposit));
    });
}
