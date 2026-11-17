use alloy_primitives::{Address, U256};
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

/// Enables `token` at the next position of the portal's list and returns its bit.
fn enable(identity: &mut ZoneIdentity, token: Address) -> u16 {
    let position = identity.synced_token_count.read().unwrap();
    identity
        .sync_token_bits(position + 1, |_| Ok(token))
        .unwrap();
    position as u16
}

/// Reads storage the way execution does, with enforcement on.
fn check(token: Address, from: Address, to: Address, kind: TransferKind) -> TransferVerdict {
    let identity = ZoneIdentity::new();
    check_transfer(
        true,
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
            frozen: false,
        },
        Member {
            org: 7,
            frozen: true,
        },
    ] {
        assert_eq!(Member::decode(member.encode()), member);
    }
}

#[test]
fn edges_need_both_halves() {
    with_identity(|identity, registrar| {
        let (admin_a, admin_b) = (Address::repeat_byte(1), Address::repeat_byte(2));
        let a = identity.create_org(registrar, registrar, admin_a).unwrap();
        let b = identity.create_org(registrar, registrar, admin_b).unwrap();
        let usd = token(1);
        let bit = enable(identity, usd);
        let mask = U256::from(1) << bit;
        let (alice, bob) = (Address::repeat_byte(0x11), Address::repeat_byte(0x22));
        identity.add_member(admin_a, registrar, a, alice).unwrap();
        identity.add_member(admin_b, registrar, b, bob).unwrap();

        identity
            .set_outbound(admin_a, registrar, a, b, mask)
            .unwrap();
        assert_eq!(
            check(usd, alice, bob, TransferKind::InZone),
            TransferVerdict::NoEdge
        );

        identity
            .set_inbound(admin_b, registrar, b, a, mask)
            .unwrap();
        assert_eq!(
            check(usd, alice, bob, TransferKind::InZone),
            TransferVerdict::Allowed
        );
        assert_eq!(
            check(usd, bob, alice, TransferKind::InZone),
            TransferVerdict::NoEdge
        );

        // Either side can close the edge alone.
        identity
            .set_inbound(admin_b, registrar, b, a, U256::ZERO)
            .unwrap();
        assert_eq!(
            check(usd, alice, bob, TransferKind::InZone),
            TransferVerdict::NoEdge
        );
    });
}

#[test]
fn admins_only_set_their_own_half() {
    with_identity(|identity, registrar| {
        let (admin_a, admin_b) = (Address::repeat_byte(1), Address::repeat_byte(2));
        let a = identity.create_org(registrar, registrar, admin_a).unwrap();
        let b = identity.create_org(registrar, registrar, admin_b).unwrap();
        assert_eq!(
            identity.set_inbound(admin_a, registrar, b, a, U256::MAX),
            Err(identity_error(ZoneIdentityError::unauthorized()))
        );
        assert_eq!(
            identity.set_outbound(admin_b, registrar, a, b, U256::MAX),
            Err(identity_error(ZoneIdentityError::unauthorized()))
        );
        assert_eq!(
            identity.set_outbound(admin_a, registrar, a, 9, U256::MAX),
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
        let usd_bit = enable(identity, usd);
        enable(identity, share);
        let mask = U256::from(1) << usd_bit;
        identity
            .set_outbound(admin, registrar, org, org, mask)
            .unwrap();
        identity
            .set_inbound(admin, registrar, org, org, mask)
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
            TransferVerdict::UnregisteredToken
        );
    });
}

#[test]
fn unaffiliated_addresses_are_denied_except_self_withdrawal() {
    with_identity(|identity, _| {
        let usd = token(1);
        enable(identity, usd);
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
fn endpoint_orgs_gate_deposit_senders() {
    with_identity(|identity, registrar| {
        let admin = Address::repeat_byte(1);
        let org = identity.create_org(registrar, registrar, admin).unwrap();
        let funding = identity
            .create_org(registrar, registrar, registrar)
            .unwrap();
        let usd = token(1);
        let mask = U256::from(1) << enable(identity, usd);
        let (endpoint, alice) = (Address::repeat_byte(0x55), Address::repeat_byte(0x11));
        identity
            .add_member(registrar, registrar, funding, endpoint)
            .unwrap();
        identity.add_member(admin, registrar, org, alice).unwrap();
        identity
            .set_outbound(registrar, registrar, funding, org, mask)
            .unwrap();
        identity
            .set_inbound(admin, registrar, org, funding, mask)
            .unwrap();

        assert_eq!(
            check(usd, endpoint, alice, TransferKind::Deposit),
            TransferVerdict::Allowed
        );
        // The same edge allows the endpoint address on the zone; edges, not the address, decide.
        assert_eq!(
            check(usd, endpoint, alice, TransferKind::InZone),
            TransferVerdict::Allowed
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
    with_identity(|identity, registrar| {
        let admin = Address::repeat_byte(1);
        let org = identity.create_org(registrar, registrar, admin).unwrap();
        let usd = token(1);
        let mask = U256::from(1) << enable(identity, usd);
        identity
            .set_outbound(admin, registrar, org, org, mask)
            .unwrap();
        identity
            .set_inbound(admin, registrar, org, org, mask)
            .unwrap();
        let (alice, bob) = (Address::repeat_byte(0x11), Address::repeat_byte(0x22));
        identity.add_member(admin, registrar, org, alice).unwrap();
        identity.add_member(admin, registrar, org, bob).unwrap();

        identity.set_frozen(admin, registrar, bob, true).unwrap();
        assert_eq!(
            check(usd, alice, bob, TransferKind::InZone),
            TransferVerdict::Frozen
        );
        identity.set_frozen(admin, registrar, bob, false).unwrap();

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

#[test]
fn membership_is_visible_to_account_admin_and_registrar_only() {
    with_identity(|identity, registrar| {
        let admin = Address::repeat_byte(1);
        let org = identity.create_org(registrar, registrar, admin).unwrap();
        let alice = Address::repeat_byte(0x11);
        identity.add_member(admin, registrar, org, alice).unwrap();
        for caller in [alice, admin, registrar] {
            assert_eq!(identity.org_of(caller, registrar, alice).unwrap().org, org);
        }
        assert_eq!(
            identity.org_of(Address::repeat_byte(0x77), registrar, alice),
            Err(identity_error(ZoneIdentityError::unauthorized()))
        );
    });
}

#[test]
fn ensure_transfer_reverts_with_org_policy_forbids() {
    with_identity(|identity, _| {
        enable(identity, token(1));
        let (a, b) = (Address::repeat_byte(0x11), Address::repeat_byte(0x22));
        assert_eq!(
            identity.ensure_transfer(true, token(1), a, b, TransferKind::InZone),
            Err(identity_error(ZoneIdentityError::org_policy_forbids(
                token(1),
                a,
                b
            )))
        );
    });
}

#[test]
fn nothing_is_read_when_not_enforced() {
    with_identity(|identity, _| {
        let (a, b) = (Address::repeat_byte(0x11), Address::repeat_byte(0x22));
        assert_eq!(
            identity
                .verdict(false, token(1), a, b, TransferKind::InZone)
                .unwrap(),
            TransferVerdict::NotEnforced
        );
        let verdict = check_transfer(
            false,
            |_| -> Result<U256, ()> { panic!("read storage while not enforced") },
            token(1),
            a,
            b,
            TransferKind::Withdrawal,
        );
        assert_eq!(verdict, Ok(TransferVerdict::NotEnforced));
    });
}

#[test]
fn token_bits_follow_enabled_positions() {
    with_identity(|identity, _| {
        let list = [token(5), token(9), token(2)];
        identity
            .sync_token_bits(2, |position| Ok(list[position as usize]))
            .unwrap();
        assert_eq!(identity.token_bits[token(5)].read().unwrap(), 1);
        assert_eq!(identity.token_bits[token(9)].read().unwrap(), 2);
        assert_eq!(identity.token_bits[token(2)].read().unwrap(), 0);

        // Only positions not yet synced are read.
        identity
            .sync_token_bits(3, |position| {
                assert_eq!(position, 2);
                Ok(list[position as usize])
            })
            .unwrap();
        assert_eq!(identity.token_bits[token(2)].read().unwrap(), 3);
        identity
            .sync_token_bits(3, |_| panic!("nothing left to sync"))
            .unwrap();
    });
}

#[test]
fn tokens_past_the_mask_get_no_bit() {
    with_identity(|identity, _| {
        let count = u64::from(MAX_IDENTITY_TOKENS) + 2;
        identity
            .sync_token_bits(count, |position| Ok(token(position + 1)))
            .unwrap();
        assert_eq!(
            identity.token_bits[token(u64::from(MAX_IDENTITY_TOKENS))]
                .read()
                .unwrap(),
            MAX_IDENTITY_TOKENS
        );
        assert_eq!(identity.token_bits[token(count)].read().unwrap(), 0);
        assert_eq!(
            identity.synced_token_count.read().unwrap(),
            u64::from(MAX_IDENTITY_TOKENS)
        );
    });
}
