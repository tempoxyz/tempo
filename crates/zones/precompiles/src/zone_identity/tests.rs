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

/// The verdict with enforcement on.
fn check(token: Address, from: Address, to: Address, kind: TransferKind) -> TransferVerdict {
    ZoneIdentity::new()
        .verdict(true, token, from, to, kind)
        .unwrap()
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
        let admin = Address::repeat_byte(1);
        let org = identity.create_org(registrar, registrar, admin).unwrap();
        let (usd, share, other) = (token(1), token(2), token(3));
        identity
            .set_outbound(admin, registrar, org, org, &[usd], true)
            .unwrap();
        identity
            .set_inbound(admin, registrar, org, org, &[usd], true)
            .unwrap();
        let (alice, bob) = (Address::repeat_byte(0x11), Address::repeat_byte(0x22));
        identity.add_member(admin, registrar, org, alice).unwrap();
        identity.add_member(admin, registrar, org, bob).unwrap();

        assert_eq!(
            check(usd, alice, bob, TransferKind::InZone),
            TransferVerdict::Allowed
        );
        assert_eq!(
            check(share, alice, bob, TransferKind::InZone),
            TransferVerdict::NoEdge
        );
        assert_eq!(
            check(other, alice, bob, TransferKind::InZone),
            TransferVerdict::NoEdge
        );
    });
}

#[test]
fn removed_members_keep_only_the_self_withdrawal_exit() {
    with_identity(|identity, registrar| {
        let admin = Address::repeat_byte(1);
        let org = identity.create_org(registrar, registrar, admin).unwrap();
        let usd = token(1);
        identity
            .set_outbound(admin, registrar, org, org, &[usd], true)
            .unwrap();
        identity
            .set_inbound(admin, registrar, org, org, &[usd], true)
            .unwrap();
        let (alice, bob) = (Address::repeat_byte(0x11), Address::repeat_byte(0x22));
        identity.add_member(admin, registrar, org, alice).unwrap();
        identity.add_member(admin, registrar, org, bob).unwrap();

        // Members cannot remove themselves.
        assert_eq!(
            identity.remove_member(bob, registrar, bob),
            Err(identity_error(ZoneIdentityError::unauthorized()))
        );
        identity.remove_member(admin, registrar, bob).unwrap();
        assert_eq!(
            check(usd, alice, bob, TransferKind::InZone),
            TransferVerdict::NoEdge
        );
        assert_eq!(
            check(usd, bob, bob, TransferKind::Withdrawal),
            TransferVerdict::SelfWithdrawal
        );
    });
}

#[test]
fn an_address_belongs_to_one_org() {
    with_identity(|identity, registrar| {
        let (admin_a, admin_b) = (Address::repeat_byte(1), Address::repeat_byte(2));
        let a = identity.create_org(registrar, registrar, admin_a).unwrap();
        let b = identity.create_org(registrar, registrar, admin_b).unwrap();
        let alice = Address::repeat_byte(0x11);
        identity.add_member(admin_a, registrar, a, alice).unwrap();
        assert_eq!(
            identity.add_member(admin_b, registrar, b, alice),
            Err(identity_error(ZoneIdentityError::already_member(alice)))
        );
    });
}
