use alloy_primitives::{Address, U256};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::zones::ZoneIdentityError;
use tempo_precompiles::storage::{StorageCtx, hashmap::HashMapStorageProvider};

use super::*;
use crate::error::ZonePrecompileError;

fn with_identity<R>(f: impl FnOnce(&mut ZoneIdentity, Address, Address) -> R) -> R {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
    StorageCtx::enter(&mut storage, || {
        let portal_admin = Address::repeat_byte(0xaa);
        let registrar = Address::repeat_byte(0xbb);
        let mut identity = ZoneIdentity::new();
        identity
            .set_registrar(portal_admin, portal_admin, registrar)
            .unwrap();
        identity
            .set_enforced(portal_admin, portal_admin, true)
            .unwrap();
        f(&mut identity, portal_admin, registrar)
    })
}

fn token(id: u64) -> Address {
    Address::new_tip20(id)
}

fn identity_error(error: ZoneIdentityError) -> ZonePrecompileError {
    error.into()
}

/// Reads storage the way the sequencer does, through raw slots.
fn check(token: Address, from: Address, to: Address, kind: TransferKind) -> TransferVerdict {
    let identity = ZoneIdentity::new();
    check_transfer(
        |slot| identity.storage.sload(ZONE_IDENTITY_ADDRESS, slot),
        token,
        from,
        to,
        kind,
    )
    .unwrap()
}

#[test]
fn member_word_round_trips() {
    for member in [
        Member::default(),
        Member {
            org: u64::MAX,
            l1_only: true,
            frozen: false,
        },
        Member {
            org: 7,
            l1_only: false,
            frozen: true,
        },
    ] {
        assert_eq!(Member::decode(member.encode()), member);
    }
}

#[test]
fn only_portal_admin_sets_registrar_and_enforcement() {
    with_identity(|identity, portal_admin, registrar| {
        assert_eq!(
            identity.set_registrar(registrar, portal_admin, registrar),
            Err(identity_error(ZoneIdentityError::unauthorized()))
        );
        assert_eq!(
            identity.set_enforced(registrar, portal_admin, false),
            Err(identity_error(ZoneIdentityError::unauthorized()))
        );
    });
}

#[test]
fn edges_need_both_halves() {
    with_identity(|identity, _, registrar| {
        let (admin_a, admin_b) = (Address::repeat_byte(1), Address::repeat_byte(2));
        let a = identity.create_org(registrar, admin_a).unwrap();
        let b = identity.create_org(registrar, admin_b).unwrap();
        let usd = token(1);
        let bit = identity.register_token(registrar, usd).unwrap();
        let mask = U256::from(1) << bit;
        let (alice, bob) = (Address::repeat_byte(0x11), Address::repeat_byte(0x22));
        identity.add_member(admin_a, a, alice, false).unwrap();
        identity.add_member(admin_b, b, bob, false).unwrap();

        identity.set_outbound(admin_a, a, b, mask).unwrap();
        assert_eq!(
            check(usd, alice, bob, TransferKind::InZone),
            TransferVerdict::NoEdge
        );

        identity.set_inbound(admin_b, b, a, mask).unwrap();
        assert_eq!(
            check(usd, alice, bob, TransferKind::InZone),
            TransferVerdict::Allowed
        );
        assert_eq!(
            check(usd, bob, alice, TransferKind::InZone),
            TransferVerdict::NoEdge
        );

        // Either side can close the edge alone.
        identity.set_inbound(admin_b, b, a, U256::ZERO).unwrap();
        assert_eq!(
            check(usd, alice, bob, TransferKind::InZone),
            TransferVerdict::NoEdge
        );
    });
}

#[test]
fn admins_only_set_their_own_half() {
    with_identity(|identity, _, registrar| {
        let (admin_a, admin_b) = (Address::repeat_byte(1), Address::repeat_byte(2));
        let a = identity.create_org(registrar, admin_a).unwrap();
        let b = identity.create_org(registrar, admin_b).unwrap();
        assert_eq!(
            identity.set_inbound(admin_a, b, a, U256::MAX),
            Err(identity_error(ZoneIdentityError::unauthorized()))
        );
        assert_eq!(
            identity.set_outbound(admin_b, a, b, U256::MAX),
            Err(identity_error(ZoneIdentityError::unauthorized()))
        );
        assert_eq!(
            identity.set_outbound(admin_a, a, 9, U256::MAX),
            Err(identity_error(ZoneIdentityError::unknown_org(9)))
        );
    });
}

#[test]
fn edges_are_per_token() {
    with_identity(|identity, _, registrar| {
        let admin = Address::repeat_byte(1);
        let org = identity.create_org(registrar, admin).unwrap();
        let (usd, share, other) = (token(1), token(2), token(3));
        let usd_bit = identity.register_token(registrar, usd).unwrap();
        identity.register_token(registrar, share).unwrap();
        let mask = U256::from(1) << usd_bit;
        identity.set_outbound(admin, org, org, mask).unwrap();
        identity.set_inbound(admin, org, org, mask).unwrap();
        let (alice, bob) = (Address::repeat_byte(0x11), Address::repeat_byte(0x22));
        identity.add_member(admin, org, alice, false).unwrap();
        identity.add_member(admin, org, bob, false).unwrap();

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
            TransferVerdict::UnregisteredToken
        );
    });
}

#[test]
fn unaffiliated_addresses_are_denied_except_self_withdrawal() {
    with_identity(|identity, _, registrar| {
        let usd = token(1);
        identity.register_token(registrar, usd).unwrap();
        let (stray, other) = (Address::repeat_byte(0x33), Address::repeat_byte(0x44));
        assert_eq!(
            check(usd, stray, other, TransferKind::InZone),
            TransferVerdict::NoEdge
        );
        assert_eq!(
            check(usd, stray, other, TransferKind::Withdrawal),
            TransferVerdict::NoEdge
        );
        assert_eq!(
            check(usd, stray, stray, TransferKind::Withdrawal),
            TransferVerdict::SelfWithdrawal
        );
    });
}

#[test]
fn l1_only_endpoints_only_take_deposits_and_withdrawals() {
    with_identity(|identity, _, registrar| {
        let admin = Address::repeat_byte(1);
        let org = identity.create_org(registrar, admin).unwrap();
        let funding = identity.create_org(registrar, registrar).unwrap();
        let usd = token(1);
        let mask = U256::from(1) << identity.register_token(registrar, usd).unwrap();
        let (endpoint, alice) = (Address::repeat_byte(0x55), Address::repeat_byte(0x11));
        identity
            .add_member(registrar, funding, endpoint, true)
            .unwrap();
        identity.add_member(admin, org, alice, false).unwrap();
        identity
            .set_outbound(registrar, funding, org, mask)
            .unwrap();
        identity.set_inbound(admin, org, funding, mask).unwrap();

        assert_eq!(
            check(usd, endpoint, alice, TransferKind::Deposit),
            TransferVerdict::Allowed
        );
        assert_eq!(
            check(usd, endpoint, alice, TransferKind::InZone),
            TransferVerdict::L1OnlyInZone
        );
        // A sender outside the endpoint org bounces.
        let stranger = Address::repeat_byte(0x66);
        assert_eq!(
            check(usd, stranger, alice, TransferKind::Deposit),
            TransferVerdict::NoEdge
        );
    });
}

#[test]
fn frozen_and_removed_members_lose_their_edges() {
    with_identity(|identity, _, registrar| {
        let admin = Address::repeat_byte(1);
        let org = identity.create_org(registrar, admin).unwrap();
        let usd = token(1);
        let mask = U256::from(1) << identity.register_token(registrar, usd).unwrap();
        identity.set_outbound(admin, org, org, mask).unwrap();
        identity.set_inbound(admin, org, org, mask).unwrap();
        let (alice, bob) = (Address::repeat_byte(0x11), Address::repeat_byte(0x22));
        identity.add_member(admin, org, alice, false).unwrap();
        identity.add_member(admin, org, bob, false).unwrap();

        identity.set_frozen(admin, bob, true).unwrap();
        assert_eq!(
            check(usd, alice, bob, TransferKind::InZone),
            TransferVerdict::Frozen
        );
        identity.set_frozen(admin, bob, false).unwrap();

        // Members cannot remove themselves.
        assert_eq!(
            identity.remove_member(bob, bob),
            Err(identity_error(ZoneIdentityError::unauthorized()))
        );
        identity.remove_member(admin, bob).unwrap();
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
    with_identity(|identity, _, registrar| {
        let (admin_a, admin_b) = (Address::repeat_byte(1), Address::repeat_byte(2));
        let a = identity.create_org(registrar, admin_a).unwrap();
        let b = identity.create_org(registrar, admin_b).unwrap();
        let alice = Address::repeat_byte(0x11);
        identity.add_member(admin_a, a, alice, false).unwrap();
        assert_eq!(
            identity.add_member(admin_b, b, alice, false),
            Err(identity_error(ZoneIdentityError::already_member(alice)))
        );
    });
}

#[test]
fn membership_is_visible_to_account_admin_and_registrar_only() {
    with_identity(|identity, _, registrar| {
        let admin = Address::repeat_byte(1);
        let org = identity.create_org(registrar, admin).unwrap();
        let alice = Address::repeat_byte(0x11);
        identity.add_member(admin, org, alice, false).unwrap();
        for caller in [alice, admin, registrar] {
            assert_eq!(identity.org_of(caller, alice).unwrap().org, org);
        }
        assert_eq!(
            identity.org_of(Address::repeat_byte(0x77), alice),
            Err(identity_error(ZoneIdentityError::unauthorized()))
        );
    });
}

#[test]
fn token_bits_are_assigned_once() {
    with_identity(|identity, _, registrar| {
        assert_eq!(identity.register_token(registrar, token(5)).unwrap(), 0);
        assert_eq!(identity.register_token(registrar, token(9)).unwrap(), 1);
        assert_eq!(
            identity.register_token(registrar, token(5)),
            Err(identity_error(ZoneIdentityError::token_already_registered(
                token(5)
            )))
        );
        assert_eq!(
            identity.register_token(registrar, Address::repeat_byte(0x12)),
            Err(identity_error(ZoneIdentityError::invalid_address()))
        );
    });
}

#[test]
fn nothing_is_enforced_before_the_fork() {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
    StorageCtx::enter(&mut storage, || {
        seed_for_test(&[], &[]).unwrap();
        let (a, b) = (Address::repeat_byte(0x11), Address::repeat_byte(0x22));
        let identity = ZoneIdentity::new();
        assert_eq!(
            identity
                .verdict(token(1), a, b, TransferKind::InZone)
                .unwrap(),
            TransferVerdict::NotEnforced
        );
        assert!(
            identity
                .ensure_transfer(token(1), a, b, TransferKind::Withdrawal)
                .is_ok()
        );
    });
}

#[test]
fn ensure_transfer_reverts_with_org_policy_forbids() {
    with_identity(|identity, _, registrar| {
        identity.register_token(registrar, token(1)).unwrap();
        let (a, b) = (Address::repeat_byte(0x11), Address::repeat_byte(0x22));
        assert_eq!(
            identity.ensure_transfer(token(1), a, b, TransferKind::InZone),
            Err(identity_error(ZoneIdentityError::org_policy_forbids(
                token(1),
                a,
                b
            )))
        );
    });
}

#[test]
fn check_is_skipped_when_not_enforced() {
    with_identity(|identity, portal_admin, _| {
        identity
            .set_enforced(portal_admin, portal_admin, false)
            .unwrap();
        let (a, b) = (Address::repeat_byte(0x11), Address::repeat_byte(0x22));
        assert_eq!(
            check(token(1), a, b, TransferKind::InZone),
            TransferVerdict::NotEnforced
        );
    });
}
