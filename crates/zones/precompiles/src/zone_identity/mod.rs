//! Zone-native org registry for shared zones.
//!
//! [`ZoneIdentity`] is the source of truth for which org each address belongs to and which TIP-20s
//! each org may send to each other org. An org is a set of addresses with one admin; an address in
//! no org is in org 0, whose admin is the registrar. Org A may send token T to org B only when A's
//! admin allows T outbound to B and B's admin allows T inbound from A.
//!
//! The portal admin configures it on Tempo: `ZonePortal.setIdentityConfig` sets the registrar and
//! whether the zone enforces edges, and the zone reads both from finalized Tempo state, so a
//! multisig admin never has to act on the zone.
//!
//! Execution enforces it: zone TIP-20 transfers revert, `ZoneOutbox::requestWithdrawal` reverts and
//! `ZoneInbox` bounces a deposit when [`ZoneIdentity::allows`] denies the move. The
//! enforcement flag shares a Tempo slot with the transfer opt-in TIP-20 already reads; on the zone
//! the check reads at most three slots (both members and one per-token edge) whatever the
//! number of orgs, tokens or edges, and a transfer inside an org costs the same as one between
//! orgs.

mod dispatch;

use alloy_primitives::Address;
use tempo_contracts::zones::{IZoneIdentity, ZoneIdentityError};
use tempo_precompiles::{
    address_registry::AddressRegistry,
    error::TempoPrecompileError,
    storage::{Handler, Mapping},
};
use tempo_precompiles_macros::{Storable, contract};
use tempo_primitives::TempoAddressExt as _;
use zone_primitives::constants::ZONE_IDENTITY_ADDRESS;

use crate::{
    error::ZoneResult,
    storage::{L1State, L1StorageReader},
};

use tempo_contracts::zones::IZoneIdentity::OrgKey;

/// Org registry and per-token edges between orgs.
///
/// Field order is the storage layout; append new fields only.
#[contract(addr = ZONE_IDENTITY_ADDRESS)]
pub struct ZoneIdentity {
    /// Highest org ID created. Org IDs start at 1.
    pub org_count: u64,
    /// Each org's configuration, keyed by org ID.
    pub orgs: Mapping<u64, Org>,
    /// Each address's membership.
    pub members: Mapping<Address, Member>,
}

impl ZoneIdentity {
    /// Whether the zone enforces org edges: the portal's `identityEnforced` flag on finalized
    /// Tempo. Before the fork that adds `ZoneIdentity` it reads nothing and returns false.
    pub fn enforced<P: L1StorageReader>(l1: &L1State<P>) -> ZoneResult<bool> {
        if !tempo_precompiles::storage::StorageCtx.spec().is_t15() {
            return Ok(false);
        }
        Ok(l1.read_portal(|portal| &portal.identity_enforced)?)
    }

    /// Whether `token` may move from `from` to `to`. `enforced` is the portal's flag; when it is off
    /// nothing is read. Otherwise neither address may be frozen, and the edge between their sides
    /// must allow the token: Zone to Zone for a transfer, the sender's Tempo side to the Zone for a
    /// deposit, and the Zone to the recipient's Tempo side for a withdrawal. A deposit or
    /// withdrawal that misses falls back to org 0's Tempo side, meaning any address on Tempo.
    pub fn allows(
        &self,
        enforced: bool,
        token: Address,
        from: Address,
        to: Address,
        kind: TransferKind,
    ) -> ZoneResult<bool> {
        if !enforced {
            return Ok(true);
        }
        // TIP-20 credits a TIP-1022 virtual recipient's master, so the master's org decides. The
        // registry is mirrored from Tempo, so this also resolves Tempo-side withdrawal recipients.
        // An unregistered virtual recipient is denied rather than an error, so a deposit to one
        // bounces instead of failing the whole block.
        let to = if to.is_virtual() {
            match AddressRegistry::new().resolve_virtual_address(to)? {
                master if master.is_zero() => return Ok(false),
                master => master,
            }
        } else {
            to
        };
        // From here the reads depend only on `kind`, which the caller chose, and are priced as
        // cold: the gas shows neither the orgs involved nor whether the move is allowed.
        self.storage.with_cold_pricing(|| {
            let sender = self.members[from].read()?;
            let recipient = self.members[to].read()?;
            let edge = |from: u64, to: u64| -> ZoneResult<bool> {
                Ok(self.orgs[from].edges[to][token].read()?.allows(kind))
            };
            let direct = edge(sender.org, recipient.org)?;
            // A deposit or withdrawal that misses falls back to org 0's Tempo side: any address
            // there.
            let fallback = match kind {
                TransferKind::InZone => false,
                TransferKind::Deposit => edge(0, recipient.org)?,
                TransferKind::Withdrawal => edge(sender.org, 0)?,
            };
            Ok(!sender.frozen && !recipient.frozen && (direct || fallback))
        })
    }

    /// Reverts with `OrgPolicyForbids` unless `token` may move from `from` to `to`.
    pub fn ensure_transfer(
        &self,
        enforced: bool,
        token: Address,
        from: Address,
        to: Address,
        kind: TransferKind,
    ) -> ZoneResult<()> {
        if !self.allows(enforced, token, from, to, kind)? {
            return Err(ZoneIdentityError::org_policy_forbids(token, from, to).into());
        }
        Ok(())
    }

    /// Creates an org administered by `admin` and returns its ID.
    pub fn create_org(
        &mut self,
        caller: Address,
        registrar: Address,
        admin: Address,
    ) -> ZoneResult<u64> {
        ensure_caller(caller, registrar)?;
        if admin.is_zero() {
            return Err(ZoneIdentityError::invalid_address().into());
        }
        let org = self
            .org_count
            .read()?
            .checked_add(1)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        self.org_count.write(org)?;
        self.orgs[org].admin.write(admin)?;
        self.emit_event(IZoneIdentity::OrgCreated { orgId: org, admin })?;
        Ok(org)
    }

    /// Replaces an org's admin. Org 0 is always administered by the registrar.
    pub fn set_org_admin(
        &mut self,
        caller: Address,
        registrar: Address,
        org: u64,
        admin: Address,
    ) -> ZoneResult<()> {
        ensure_caller(caller, registrar)?;
        self.ensure_org(org)?;
        if org == 0 || admin.is_zero() {
            return Err(ZoneIdentityError::invalid_address().into());
        }
        self.orgs[org].admin.write(admin)?;
        Ok(self.emit_event(IZoneIdentity::OrgAdminUpdated { orgId: org, admin })?)
    }

    /// Adds `accounts`, each in no org, to `org`. Reverts, adding none, if any is already in an org.
    pub fn add_members(
        &mut self,
        caller: Address,
        registrar: Address,
        org: u64,
        accounts: &[Address],
    ) -> ZoneResult<()> {
        self.ensure_org_admin(caller, registrar, org)?;
        if org == 0 {
            return Err(ZoneIdentityError::invalid_address().into());
        }
        // Check every account first, so a rejected batch writes nothing.
        for &account in accounts {
            // A virtual address never holds funds; moves to it are checked as its master.
            if account.is_zero() || account.is_virtual() {
                return Err(ZoneIdentityError::invalid_address().into());
            }
            if self.members[account].read()? != Member::default() {
                return Err(ZoneIdentityError::already_member(account).into());
            }
        }
        for &account in accounts {
            self.write_member(account, Member { org, frozen: false })?;
        }
        Ok(())
    }

    /// Moves `account` back to org 0. Only its org's admin may remove it, so a member cannot leave
    /// to escape its org's outbound rules.
    pub fn remove_member(&mut self, caller: Address, account: Address) -> ZoneResult<()> {
        self.ensure_member_admin(caller, account)?;
        self.write_member(account, Member::default())
    }

    /// Freezes or unfreezes a member of the caller's org.
    pub fn set_frozen(
        &mut self,
        caller: Address,
        account: Address,
        frozen: bool,
    ) -> ZoneResult<()> {
        let member = self.ensure_member_admin(caller, account)?;
        self.write_member(account, Member { frozen, ..member })
    }

    /// Sets, for each of `tokens`, the halves of the edge from `from` to `to` that the caller
    /// administers: the sending half as `from`'s org admin, the receiving half as `to`'s. An admin of
    /// both orgs, as for an org's edge to itself, sets both.
    pub fn set_edge(
        &mut self,
        caller: Address,
        registrar: Address,
        from: OrgKey,
        to: OrgKey,
        tokens: &[Address],
        allowed: bool,
    ) -> ZoneResult<()> {
        self.ensure_org(from.orgId)?;
        self.ensure_org(to.orgId)?;
        let kind = edge_kind(&from, &to)?;
        let sending = !caller.is_zero() && caller == self.org_admin(registrar, from.orgId)?;
        let receiving = !caller.is_zero() && caller == self.org_admin(registrar, to.orgId)?;
        if !sending && !receiving {
            return Err(ZoneIdentityError::unauthorized().into());
        }
        for &token in tokens {
            let slot = &mut self.orgs[from.orgId].edges[to.orgId][token];
            let mut edges = slot.read()?;
            let (from_ok, to_ok) = edges.halves(kind);
            if sending {
                *from_ok = allowed;
            }
            if receiving {
                *to_ok = allowed;
            }
            let (from_ok, to_ok) = (*from_ok, *to_ok);
            slot.write(edges)?;
            self.emit_event(IZoneIdentity::EdgeUpdated {
                fromOrg: from.orgId,
                fromL1: from.l1,
                toOrg: to.orgId,
                toL1: to.l1,
                token,
                fromOk: from_ok,
                toOk: to_ok,
            })?;
        }
        Ok(())
    }

    /// Admin of `org`; the registrar for org 0.
    pub fn org_admin(&self, registrar: Address, org: u64) -> ZoneResult<Address> {
        if org == 0 {
            return Ok(registrar);
        }
        Ok(self.orgs[org].admin.read()?)
    }

    /// Membership of `account` for a caller that may see it: the account itself, its org's admin or
    /// the registrar.
    pub fn org_of(
        &self,
        caller: Address,
        registrar: Address,
        account: Address,
    ) -> ZoneResult<Member> {
        // Reads the member and its org's admin slot whatever the answer, priced as cold.
        let (member, admin) = self.storage.with_cold_pricing(|| -> ZoneResult<_> {
            let member = self.members[account].read()?;
            Ok((member, self.orgs[member.org].admin.read()?))
        })?;
        let admin = if member.org == 0 { registrar } else { admin };
        if caller != account && caller != admin {
            ensure_caller(caller, registrar)?;
        }
        Ok(member)
    }

    /// Whether `token` may move along the edge from `from` to `to`, for the admin of either org or
    /// the registrar.
    pub fn edge(
        &self,
        caller: Address,
        registrar: Address,
        from: OrgKey,
        to: OrgKey,
        token: Address,
    ) -> ZoneResult<bool> {
        if caller != self.org_admin(registrar, from.orgId)?
            && caller != self.org_admin(registrar, to.orgId)?
        {
            ensure_caller(caller, registrar)?;
        }
        let kind = edge_kind(&from, &to)?;
        Ok(self.orgs[from.orgId].edges[to.orgId][token]
            .read()?
            .allows(kind))
    }

    fn write_member(&mut self, account: Address, member: Member) -> ZoneResult<()> {
        self.members[account].write(member)?;
        Ok(self.emit_event(IZoneIdentity::MemberUpdated {
            account,
            orgId: member.org,
            frozen: member.frozen,
        })?)
    }

    /// Returns `account`'s membership if the caller administers its org. Every other case,
    /// including an account in no org, reverts with the same `Unauthorized` after the same two
    /// reads, so the call does not reveal whether an account is a member.
    fn ensure_member_admin(&self, caller: Address, account: Address) -> ZoneResult<Member> {
        // Reads the member and its org's admin slot whatever the caller, priced as cold.
        let (member, admin) = self.storage.with_cold_pricing(|| -> ZoneResult<_> {
            let member = self.members[account].read()?;
            Ok((member, self.orgs[member.org].admin.read()?))
        })?;
        if member.org == 0 || admin.is_zero() || caller != admin {
            return Err(ZoneIdentityError::unauthorized().into());
        }
        Ok(member)
    }

    fn ensure_org(&self, org: u64) -> ZoneResult<()> {
        if org > self.org_count.read()? {
            return Err(ZoneIdentityError::unknown_org(org).into());
        }
        Ok(())
    }

    fn ensure_org_admin(&self, caller: Address, registrar: Address, org: u64) -> ZoneResult<()> {
        self.ensure_org(org)?;
        ensure_caller(caller, self.org_admin(registrar, org)?)
    }
}

/// One org's configuration.
#[derive(Debug, Clone, Storable, Default)]
pub struct Org {
    /// Key that manages the org's members and its halves of edges.
    pub admin: Address,
    /// Both halves of the transfer, deposit and withdrawal edges from this org to another, keyed by
    /// receiving org and token.
    pub edges: Mapping<u64, Mapping<Address, Edges>>,
}

/// Both halves of the three edges between two orgs for one token, packed into one slot. A move
/// needs both halves of its edge.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Storable)]
pub struct Edges {
    /// Zone to Zone, set by the sending org's admin.
    pub transfer_from: bool,
    /// Zone to Zone, set by the receiving org's admin.
    pub transfer_to: bool,
    /// The sending org's Tempo addresses to the Zone, set by the sending org's admin.
    pub deposit_from: bool,
    /// The sending org's Tempo addresses to the Zone, set by the receiving org's admin.
    pub deposit_to: bool,
    /// The Zone to the receiving org's Tempo addresses, set by the sending org's admin.
    pub withdrawal_from: bool,
    /// The Zone to the receiving org's Tempo addresses, set by the receiving org's admin.
    pub withdrawal_to: bool,
}

impl Edges {
    /// Whether both halves of the edge for `kind` allow the move.
    fn allows(mut self, kind: TransferKind) -> bool {
        let (from_ok, to_ok) = self.halves(kind);
        *from_ok && *to_ok
    }

    /// The sending and receiving halves of the edge for `kind`.
    fn halves(&mut self, kind: TransferKind) -> (&mut bool, &mut bool) {
        match kind {
            TransferKind::InZone => (&mut self.transfer_from, &mut self.transfer_to),
            TransferKind::Deposit => (&mut self.deposit_from, &mut self.deposit_to),
            TransferKind::Withdrawal => (&mut self.withdrawal_from, &mut self.withdrawal_to),
        }
    }
}

/// The move an edge between `from` and `to` governs. Tempo to Tempo has none.
fn edge_kind(from: &OrgKey, to: &OrgKey) -> ZoneResult<TransferKind> {
    match (from.l1, to.l1) {
        (false, false) => Ok(TransferKind::InZone),
        (true, false) => Ok(TransferKind::Deposit),
        (false, true) => Ok(TransferKind::Withdrawal),
        (true, true) => Err(ZoneIdentityError::invalid_edge().into()),
    }
}

/// An address's membership, packed into one slot: zero for an address in no org.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Storable)]
pub struct Member {
    /// Org the address belongs to; 0 when it is in no org.
    pub org: u64,
    /// The org admin froze the address: nothing may be sent to or from it.
    pub frozen: bool,
}

/// How funds move between `from` and `to`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferKind {
    /// A TIP-20 transfer inside the zone.
    InZone,
    /// An L1 deposit from `from` on Tempo to `to` on the zone.
    Deposit,
    /// A withdrawal from `from` on the zone to `to` on Tempo.
    Withdrawal,
}

/// Rejects a call unless `caller` is the nonzero `expected` address.
fn ensure_caller(caller: Address, expected: Address) -> ZoneResult<()> {
    if expected.is_zero() || caller != expected {
        return Err(ZoneIdentityError::unauthorized().into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloy_primitives::Address;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::zones::ZoneIdentityError;
    use tempo_precompiles::{
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{VIRTUAL_MASTER, register_virtual_master},
    };

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
            .set_edge(
                admin,
                registrar,
                OrgKey::zone(org),
                OrgKey::zone(org),
                &[usd],
                true,
            )
            .unwrap();
        identity
            .add_members(admin, registrar, org, &[ALICE, BOB])
            .unwrap();
        (admin, org)
    }

    #[test]
    fn edges_need_both_admins() {
        with_identity(|identity, registrar| {
            let (admin_a, admin_b) = (Address::repeat_byte(1), Address::repeat_byte(2));
            let a = identity.create_org(registrar, registrar, admin_a).unwrap();
            let b = identity.create_org(registrar, registrar, admin_b).unwrap();
            let (from, to, usd) = (OrgKey::zone(a), OrgKey::zone(b), token(1));
            let edge = |identity: &ZoneIdentity| {
                identity
                    .edge(registrar, registrar, from.clone(), to.clone(), usd)
                    .unwrap()
            };
            identity
                .set_edge(admin_a, registrar, from.clone(), to.clone(), &[usd], true)
                .unwrap();
            assert!(!edge(identity));
            identity
                .set_edge(admin_b, registrar, from.clone(), to.clone(), &[usd], true)
                .unwrap();
            assert!(edge(identity));
            // Either admin closes it alone; nobody else can touch it.
            identity
                .set_edge(admin_b, registrar, from.clone(), to.clone(), &[usd], false)
                .unwrap();
            assert!(!edge(identity));
            assert_eq!(
                identity.set_edge(
                    Address::repeat_byte(9),
                    registrar,
                    from.clone(),
                    to.clone(),
                    &[usd],
                    true
                ),
                Err(identity_error(ZoneIdentityError::unauthorized()))
            );
            assert_eq!(
                identity.set_edge(admin_a, registrar, from, OrgKey::zone(9), &[usd], true),
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
    fn removed_members_lose_every_edge() {
        with_identity(|identity, registrar| {
            let usd = token(1);
            let (admin, _) = org_with_members(identity, registrar, usd);
            // Members cannot remove themselves.
            assert_eq!(
                identity.remove_member(BOB, BOB),
                Err(identity_error(ZoneIdentityError::unauthorized()))
            );
            // Outsiders get the same answer for a member and for an address in no org.
            let outsider = Address::repeat_byte(9);
            for account in [BOB, Address::repeat_byte(0x55)] {
                assert_eq!(
                    identity.remove_member(outsider, account),
                    Err(identity_error(ZoneIdentityError::unauthorized()))
                );
                assert_eq!(
                    identity.set_frozen(outsider, account, true),
                    Err(identity_error(ZoneIdentityError::unauthorized()))
                );
            }
            identity.remove_member(admin, BOB).unwrap();
            assert!(!allows(usd, ALICE, BOB, TransferKind::InZone));
            // No exit of its own: org 0 has no edges unless the registrar sets them.
            assert!(!allows(usd, BOB, BOB, TransferKind::Withdrawal));
        });
    }

    #[test]
    fn an_address_belongs_to_one_org() {
        with_identity(|identity, registrar| {
            let (admin_a, admin_b) = (Address::repeat_byte(1), Address::repeat_byte(2));
            let a = identity.create_org(registrar, registrar, admin_a).unwrap();
            let b = identity.create_org(registrar, registrar, admin_b).unwrap();
            identity
                .add_members(admin_a, registrar, a, &[ALICE])
                .unwrap();
            // The whole batch is refused, so BOB is not added either.
            assert_eq!(
                identity.add_members(admin_b, registrar, b, &[BOB, ALICE]),
                Err(identity_error(ZoneIdentityError::already_member(ALICE)))
            );
            assert_eq!(identity.members[BOB].read().unwrap().org, 0);
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
                .add_members(exit_admin, registrar, exits, &[offramp])
                .unwrap();
            // Withdrawals from the org to the exit org's Tempo addresses, not transfers to it.
            for caller in [admin, exit_admin] {
                identity
                    .set_edge(
                        caller,
                        registrar,
                        OrgKey::zone(org),
                        OrgKey::l1(exits),
                        &[usd],
                        true,
                    )
                    .unwrap();
            }
            assert!(allows(usd, ALICE, offramp, TransferKind::Withdrawal));
            assert!(!allows(usd, ALICE, offramp, TransferKind::InZone));
            assert!(!allows(usd, offramp, ALICE, TransferKind::Deposit));

            // Org 0's Tempo side stands for any address on Tempo: the org accepts deposits from anyone.
            let stranger = Address::repeat_byte(0x44);
            assert!(!allows(usd, stranger, ALICE, TransferKind::Deposit));
            for caller in [registrar, admin] {
                identity
                    .set_edge(
                        caller,
                        registrar,
                        OrgKey::l1(0),
                        OrgKey::zone(org),
                        &[usd],
                        true,
                    )
                    .unwrap();
            }
            assert!(allows(usd, stranger, ALICE, TransferKind::Deposit));
            assert!(allows(usd, offramp, ALICE, TransferKind::Deposit));
        });
    }

    #[test]
    fn virtual_recipients_are_checked_as_their_master() {
        with_identity(|identity, registrar| {
            let usd = token(1);
            let (admin, org) = org_with_members(identity, registrar, usd);
            let (_, virtual_addr) = register_virtual_master(&mut AddressRegistry::new()).unwrap();
            // A virtual address of a member's master is in the member's org.
            assert!(!allows(usd, ALICE, virtual_addr, TransferKind::InZone));
            identity
                .add_members(admin, registrar, org, &[VIRTUAL_MASTER])
                .unwrap();
            assert!(allows(usd, ALICE, virtual_addr, TransferKind::InZone));
            assert!(
                allows(usd, ALICE, virtual_addr, TransferKind::Withdrawal)
                    == allows(usd, ALICE, VIRTUAL_MASTER, TransferKind::Withdrawal)
            );
            // Virtual addresses themselves cannot be members.
            assert_eq!(
                identity.add_members(admin, registrar, org, &[virtual_addr]),
                Err(identity_error(ZoneIdentityError::invalid_address()))
            );
            // An unregistered virtual recipient is denied, not an error, for every kind of move.
            let unregistered = Address::new_virtual(
                tempo_primitives::MasterId::repeat_byte(0xee),
                alloy_primitives::FixedBytes::repeat_byte(1),
            );
            for kind in [
                TransferKind::InZone,
                TransferKind::Deposit,
                TransferKind::Withdrawal,
            ] {
                assert!(!allows(usd, ALICE, unregistered, kind));
            }
        });
    }

    #[test]
    fn invalid_edges_and_org_zero_admin_are_refused() {
        with_identity(|identity, registrar| {
            let org = identity
                .create_org(registrar, registrar, registrar)
                .unwrap();
            assert_eq!(
                identity.set_edge(
                    registrar,
                    registrar,
                    OrgKey::l1(org),
                    OrgKey::l1(0),
                    &[token(1)],
                    true
                ),
                Err(identity_error(ZoneIdentityError::invalid_edge()))
            );
            assert_eq!(
                identity.set_org_admin(registrar, registrar, 0, Address::repeat_byte(1)),
                Err(identity_error(ZoneIdentityError::invalid_address()))
            );
        });
    }

    /// Every org check charges the same gas whatever the orgs, freezes and edges involved, and
    /// whether its slots were already warm, so gas cannot reveal an account's org.
    #[test]
    fn org_checks_cost_the_same_whatever_the_state() {
        use crate::test_utils::{test_context_with_hardfork, test_storage_provider};

        let mut ctx = test_context_with_hardfork(TempoHardfork::T15);
        let registrar = Address::repeat_byte(0xbb);
        let usd = token(1);
        let (carol, dave, offramp, stranger) = (
            Address::repeat_byte(0x33),
            Address::repeat_byte(0x44),
            Address::repeat_byte(0x66),
            Address::repeat_byte(0x77),
        );
        {
            let mut storage = test_storage_provider(&mut ctx, u64::MAX, false);
            StorageCtx::enter(&mut storage, || {
                let mut identity = ZoneIdentity::new();
                let (admin, org) = org_with_members(&mut identity, registrar, usd);
                let other = identity
                    .create_org(registrar, registrar, registrar)
                    .unwrap();
                identity
                    .add_members(registrar, registrar, other, &[carol, offramp])
                    .unwrap();
                identity
                    .add_members(admin, registrar, org, &[dave])
                    .unwrap();
                identity.set_frozen(admin, dave, true).unwrap();
                for caller in [admin, registrar] {
                    identity
                        .set_edge(
                            caller,
                            registrar,
                            OrgKey::zone(org),
                            OrgKey::l1(other),
                            &[usd],
                            true,
                        )
                        .unwrap();
                }
            });
        }

        let scenarios = [
            // Allowed in an org, denied across orgs, from org 0, and with a frozen party.
            (
                TransferKind::InZone,
                vec![
                    (ALICE, BOB),
                    (ALICE, carol),
                    (stranger, ALICE),
                    (ALICE, dave),
                ],
            ),
            // Allowed directly, denied, to org 0, and from a frozen party.
            (
                TransferKind::Withdrawal,
                vec![
                    (ALICE, offramp),
                    (ALICE, carol),
                    (ALICE, stranger),
                    (dave, offramp),
                ],
            ),
            (
                TransferKind::Deposit,
                vec![(offramp, ALICE), (stranger, ALICE), (carol, stranger)],
            ),
        ];
        for (kind, moves) in scenarios {
            let mut storage = test_storage_provider(&mut ctx, u64::MAX, false);
            let costs = StorageCtx::enter(&mut storage, || {
                let identity = ZoneIdentity::new();
                let mut costs = Vec::new();
                // Each move twice: the second time every slot it reads is warm.
                for &(from, to) in moves.iter().chain(moves.iter()) {
                    let before = identity.storage.gas_used();
                    identity.allows(true, usd, from, to, kind).unwrap();
                    costs.push(identity.storage.gas_used() - before);
                }
                costs
            });
            assert!(costs[0] > 0, "{kind:?} charged no gas");
            assert!(
                costs.iter().all(|cost| *cost == costs[0]),
                "{kind:?}: {costs:?}"
            );
        }

        // orgOf by an outsider costs the same for members of either org, frozen or not, and for an
        // address in no org, before and after its slots are warm.
        let mut storage = test_storage_provider(&mut ctx, u64::MAX, false);
        let costs = StorageCtx::enter(&mut storage, || {
            let identity = ZoneIdentity::new();
            let outsider = Address::repeat_byte(0x99);
            let accounts = [ALICE, BOB, carol, dave, stranger];
            let mut costs = Vec::new();
            for &account in accounts.iter().chain(accounts.iter()) {
                let before = identity.storage.gas_used();
                let _ = identity.org_of(outsider, registrar, account);
                costs.push(identity.storage.gas_used() - before);
            }
            costs
        });
        assert!(
            costs.iter().all(|cost| *cost == costs[0]),
            "orgOf: {costs:?}"
        );
    }
}
