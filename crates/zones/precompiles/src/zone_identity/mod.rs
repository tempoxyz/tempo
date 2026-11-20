//! Zone-native org registry for shared zones.
//!
//! [`ZoneIdentity`] is the source of truth for which org each Zone address belongs to, which TIP-20s
//! each org may send to each other org, and which Tempo addresses each org's members may deposit
//! from and withdraw to. An org is a set of Zone addresses with one admin; an address in no org is
//! in org 0, whose admin is the registrar.
//!
//! - **Transfers on the Zone** follow edges: org A may send token T to org B only when A's admin
//!   allows T outbound to B and B's admin allows T inbound from A. An org's edge to itself, which
//!   its admin sets alone, allows transfers between its members.
//! - **Deposits and withdrawals** follow the member's org alone. Tempo addresses are never members,
//!   so nobody has to consent for an org to name one: an org lists, per token, the Tempo addresses
//!   it accepts deposits from and lets members withdraw to ([`L1Target`]), and may open either
//!   direction to any address or to the member's own address ([`L1Policy`]). Several orgs may list
//!   the same address, such as an off-ramp or an Earn router on Tempo. An address in no org may
//!   always withdraw to any Tempo address, so removing a member never strands its funds.
//!
//! The portal admin configures it on Tempo: `ZonePortal.setIdentityConfig` sets the registrar and
//! whether the zone enforces edges, and the zone reads both from finalized Tempo state, so a
//! multisig admin never has to act on the zone.
//!
//! Execution enforces it: zone TIP-20 transfers revert, `ZoneOutbox::requestWithdrawal` reverts and
//! `ZoneInbox` bounces a deposit when [`ZoneIdentity::allows`] denies the move. The enforcement
//! flag shares a Tempo slot with the transfer opt-in TIP-20 already reads; on the zone every check
//! reads three slots whatever the number of orgs, tokens, edges or targets, and whatever the
//! answer.

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

/// Org registry, per-token edges between orgs and each org's per-token Tempo targets.
///
/// Field order is the storage layout; append new fields only.
#[contract(addr = ZONE_IDENTITY_ADDRESS)]
pub struct ZoneIdentity {
    /// Highest org ID created. Org IDs start at 1.
    pub org_count: u64,
    /// Each org's configuration, keyed by org ID.
    pub orgs: Mapping<u64, Org>,
    /// Each Zone address's membership.
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
    /// nothing is read. Otherwise the Zone party, or both for a transfer, must not be frozen, and:
    ///
    /// - a transfer needs both halves of the edge from the sender's org to the recipient's;
    /// - a deposit needs the recipient's org to accept `from`, a Tempo address;
    /// - a withdrawal needs the sender's org to allow `to`, a Tempo address; a sender in org 0
    ///   may always withdraw.
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
        // TIP-20 credits a TIP-1022 virtual recipient's master, so the master decides. The Zone's
        // registry holds no masters, so every virtual recipient is denied for now; it is denied
        // rather than an error, so a deposit to one bounces instead of failing the block.
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
        self.storage.with_cold_pricing(|| match kind {
            TransferKind::InZone => {
                let sender = self.members[from].read()?;
                let recipient = self.members[to].read()?;
                let edge = self.orgs[sender.org].edges[recipient.org][token].read()?;
                Ok(!sender.frozen && !recipient.frozen && edge.allows())
            }
            TransferKind::Deposit => {
                let recipient = self.members[to].read()?;
                let (policy, target) = self.l1_rules(recipient.org, token, from)?;
                let allowed = policy.open_deposit
                    || (policy.self_deposit && from == to)
                    || target.deposit_from;
                Ok(!recipient.frozen && allowed)
            }
            TransferKind::Withdrawal => {
                let sender = self.members[from].read()?;
                let (policy, target) = self.l1_rules(sender.org, token, to)?;
                // Read before deciding, so a sender in org 0 costs the same as any other.
                let allowed = sender.org == 0
                    || policy.open_withdrawal
                    || (policy.self_withdrawal && to == from)
                    || target.withdraw_to;
                Ok(!sender.frozen && allowed)
            }
        })
    }

    /// The org `account` is in, 0 when it is in none, for protocol code. Priced as cold.
    pub fn member_org(&self, account: Address) -> ZoneResult<u64> {
        Ok(self
            .storage
            .with_cold_pricing(|| self.members[account].read())?
            .org)
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

    /// Sets, for each of `tokens`, the halves of the Zone edge from `from` to `to` that the caller
    /// administers: the sending half as `from`'s admin, the receiving half as `to`'s. An admin of
    /// both orgs, as for an org's edge to itself, sets both.
    pub fn set_edge(
        &mut self,
        caller: Address,
        registrar: Address,
        from: u64,
        to: u64,
        tokens: &[Address],
        allowed: bool,
    ) -> ZoneResult<()> {
        self.ensure_org(from)?;
        self.ensure_org(to)?;
        let sending = !caller.is_zero() && caller == self.org_admin(registrar, from)?;
        let receiving = !caller.is_zero() && caller == self.org_admin(registrar, to)?;
        if !sending && !receiving {
            return Err(ZoneIdentityError::unauthorized().into());
        }
        for &token in tokens {
            let slot = &mut self.orgs[from].edges[to][token];
            let mut edge = slot.read()?;
            if sending {
                edge.from_ok = allowed;
            }
            if receiving {
                edge.to_ok = allowed;
            }
            slot.write(edge)?;
            self.emit_event(IZoneIdentity::EdgeUpdated {
                fromOrg: from,
                toOrg: to,
                token,
                fromOk: edge.from_ok,
                toOk: edge.to_ok,
            })?;
        }
        Ok(())
    }

    /// Sets, for each of `tokens`, whether `org`'s members accept deposits from the Tempo address
    /// `target` and may withdraw to it. Only `org`'s admin may, and it binds only `org`'s members,
    /// so `target` never has to consent.
    pub fn set_l1_target(
        &mut self,
        caller: Address,
        registrar: Address,
        org: u64,
        target: Address,
        tokens: &[Address],
        rules: L1Target,
    ) -> ZoneResult<()> {
        self.ensure_org_admin(caller, registrar, org)?;
        // Withdrawals to a virtual address are checked as its master, so the master is listed.
        if target.is_zero() || target.is_virtual() {
            return Err(ZoneIdentityError::invalid_address().into());
        }
        for &token in tokens {
            self.orgs[org].l1[token].targets[target].write(rules)?;
            self.emit_event(IZoneIdentity::L1TargetUpdated {
                orgId: org,
                target,
                token,
                depositFrom: rules.deposit_from,
                withdrawTo: rules.withdraw_to,
            })?;
        }
        Ok(())
    }

    /// Sets, for each of `tokens`, which Tempo addresses `org`'s members may use without a target.
    /// Org 0's policy, set by the registrar, governs deposits to addresses in no org; they may
    /// always withdraw.
    pub fn set_l1_policy(
        &mut self,
        caller: Address,
        registrar: Address,
        org: u64,
        tokens: &[Address],
        policy: L1Policy,
    ) -> ZoneResult<()> {
        self.ensure_org_admin(caller, registrar, org)?;
        for &token in tokens {
            self.orgs[org].l1[token].policy.write(policy)?;
            self.emit_event(IZoneIdentity::L1PolicyUpdated {
                orgId: org,
                token,
                policy: policy.into(),
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

    /// Whether `token` may move along the Zone edge from `from` to `to`, for the admin of either
    /// org or the registrar.
    pub fn edge(
        &self,
        caller: Address,
        registrar: Address,
        from: u64,
        to: u64,
        token: Address,
    ) -> ZoneResult<bool> {
        if caller != self.org_admin(registrar, from)? && caller != self.org_admin(registrar, to)? {
            ensure_caller(caller, registrar)?;
        }
        Ok(self.orgs[from].edges[to][token].read()?.allows())
    }

    /// What `org` lets its members do with the Tempo address `target` for `token`, for `org`'s
    /// admin or the registrar.
    pub fn l1_target(
        &self,
        caller: Address,
        registrar: Address,
        org: u64,
        target: Address,
        token: Address,
    ) -> ZoneResult<L1Target> {
        self.ensure_org_reader(caller, registrar, org)?;
        Ok(self.orgs[org].l1[token].targets[target].read()?)
    }

    /// `org`'s policy for `token`, for `org`'s admin or the registrar.
    pub fn l1_policy(
        &self,
        caller: Address,
        registrar: Address,
        org: u64,
        token: Address,
    ) -> ZoneResult<L1Policy> {
        self.ensure_org_reader(caller, registrar, org)?;
        Ok(self.orgs[org].l1[token].policy.read()?)
    }

    /// `org`'s policy for `token` and its target entry for `l1`, always reading both slots.
    fn l1_rules(&self, org: u64, token: Address, l1: Address) -> ZoneResult<(L1Policy, L1Target)> {
        let rules = &self.orgs[org].l1[token];
        Ok((rules.policy.read()?, rules.targets[l1].read()?))
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

    /// Rejects a caller that is neither `org`'s admin nor the registrar.
    fn ensure_org_reader(&self, caller: Address, registrar: Address, org: u64) -> ZoneResult<()> {
        if caller != self.org_admin(registrar, org)? {
            ensure_caller(caller, registrar)?;
        }
        Ok(())
    }
}

/// One org's configuration.
#[derive(Debug, Clone, Storable, Default)]
pub struct Org {
    /// Key that manages the org's members, its halves of edges, its targets and its policy.
    pub admin: Address,
    /// Both halves of the Zone edge from this org to another, keyed by receiving org and token.
    pub edges: Mapping<u64, Mapping<Address, Edge>>,
    /// Which Tempo addresses this org's members may deposit from and withdraw to, keyed by token.
    pub l1: Mapping<Address, L1Rules>,
}

/// One org's Tempo rules for one token.
#[derive(Debug, Clone, Storable, Default)]
pub struct L1Rules {
    /// Which Tempo addresses members may use without a target.
    pub policy: L1Policy,
    /// What members may do with each listed Tempo address, keyed by address.
    pub targets: Mapping<Address, L1Target>,
}

/// Both halves of the Zone edge between two orgs for one token, packed into one slot. A transfer
/// needs both.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Storable)]
pub struct Edge {
    /// Set by the sending org's admin.
    pub from_ok: bool,
    /// Set by the receiving org's admin.
    pub to_ok: bool,
}

impl Edge {
    /// Whether both halves allow the transfer.
    fn allows(self) -> bool {
        self.from_ok && self.to_ok
    }
}

/// What an org's members may do with one Tempo address for one token, packed into one slot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Storable)]
pub struct L1Target {
    /// Members accept deposits from the address.
    pub deposit_from: bool,
    /// Members may withdraw to the address.
    pub withdraw_to: bool,
}

/// Which Tempo addresses an org's members may use for one token without a target, packed into one
/// slot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Storable)]
pub struct L1Policy {
    /// Members accept deposits from any Tempo address.
    pub open_deposit: bool,
    /// Members may withdraw to any Tempo address.
    pub open_withdrawal: bool,
    /// A member accepts deposits from its own address on Tempo.
    pub self_deposit: bool,
    /// A member may withdraw to its own address on Tempo.
    pub self_withdrawal: bool,
}

impl From<IZoneIdentity::L1Policy> for L1Policy {
    fn from(policy: IZoneIdentity::L1Policy) -> Self {
        Self {
            open_deposit: policy.openDeposit,
            open_withdrawal: policy.openWithdrawal,
            self_deposit: policy.selfDeposit,
            self_withdrawal: policy.selfWithdrawal,
        }
    }
}

impl From<L1Policy> for IZoneIdentity::L1Policy {
    fn from(policy: L1Policy) -> Self {
        Self {
            openDeposit: policy.open_deposit,
            openWithdrawal: policy.open_withdrawal,
            selfDeposit: policy.self_deposit,
            selfWithdrawal: policy.self_withdrawal,
        }
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
    use alloy_sol_types::SolCall;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::zones::ZoneIdentityError;
    use tempo_precompiles::{
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{VIRTUAL_MASTER, register_virtual_master},
    };
    use test_case::test_case;

    use super::*;

    use crate::error::ZonePrecompileError;

    const ALICE: Address = Address::repeat_byte(0x11);
    const BOB: Address = Address::repeat_byte(0x22);
    const OFFRAMP: Address = Address::repeat_byte(0x33);
    const DEPOSITOR: Address = Address::repeat_byte(0x34);
    const STRANGER: Address = Address::repeat_byte(0x44);

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
            .set_edge(admin, registrar, org, org, &[usd], true)
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
            let usd = token(1);
            let edge =
                |identity: &ZoneIdentity| identity.edge(registrar, registrar, a, b, usd).unwrap();
            identity
                .set_edge(admin_a, registrar, a, b, &[usd], true)
                .unwrap();
            assert!(!edge(identity));
            identity
                .set_edge(admin_b, registrar, a, b, &[usd], true)
                .unwrap();
            assert!(edge(identity));
            // Either admin closes it alone; nobody else can touch it.
            identity
                .set_edge(admin_b, registrar, a, b, &[usd], false)
                .unwrap();
            assert!(!edge(identity));
            assert_eq!(
                identity.set_edge(Address::repeat_byte(9), registrar, a, b, &[usd], true),
                Err(identity_error(ZoneIdentityError::unauthorized()))
            );
            assert_eq!(
                identity.set_edge(admin_a, registrar, a, 9, &[usd], true),
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
            let (admin, org) = org_with_members(identity, registrar, usd);
            identity
                .set_l1_target(
                    admin,
                    registrar,
                    org,
                    OFFRAMP,
                    &[usd],
                    L1Target {
                        deposit_from: false,
                        withdraw_to: true,
                    },
                )
                .unwrap();
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
            assert!(allows(usd, BOB, OFFRAMP, TransferKind::Withdrawal));
            identity.remove_member(admin, BOB).unwrap();
            assert!(!allows(usd, ALICE, BOB, TransferKind::InZone));
            // The org's edges and targets no longer apply, but org 0 may withdraw anywhere.
            assert!(!allows(usd, BOB, ALICE, TransferKind::InZone));
            assert!(allows(usd, BOB, OFFRAMP, TransferKind::Withdrawal));
            assert!(allows(usd, BOB, STRANGER, TransferKind::Withdrawal));
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
    fn l1_targets_bind_only_their_org() {
        with_identity(|identity, registrar| {
            let (usd, share) = (token(1), token(2));
            let (admin, org) = org_with_members(identity, registrar, usd);
            let set_target =
                |identity: &mut ZoneIdentity, admin, org, target, deposit_from, withdraw_to| {
                    identity
                        .set_l1_target(
                            admin,
                            registrar,
                            org,
                            target,
                            &[usd],
                            L1Target {
                                deposit_from,
                                withdraw_to,
                            },
                        )
                        .unwrap()
                };
            set_target(identity, admin, org, DEPOSITOR, true, false);
            set_target(identity, admin, org, OFFRAMP, false, true);

            // Each direction is separate, and a target is not a Zone recipient.
            assert!(allows(usd, DEPOSITOR, ALICE, TransferKind::Deposit));
            assert!(!allows(usd, ALICE, DEPOSITOR, TransferKind::Withdrawal));
            assert!(allows(usd, ALICE, OFFRAMP, TransferKind::Withdrawal));
            assert!(!allows(usd, OFFRAMP, ALICE, TransferKind::Deposit));
            assert!(!allows(usd, ALICE, OFFRAMP, TransferKind::InZone));
            assert!(!allows(usd, STRANGER, ALICE, TransferKind::Deposit));
            // Targets are per token.
            assert!(!allows(share, ALICE, OFFRAMP, TransferKind::Withdrawal));

            // Another org lists the same off-ramp on its own, without any consent from it or from
            // the first org; until it does, its members cannot reach it.
            let carol = Address::repeat_byte(0x55);
            let admin_b = Address::repeat_byte(2);
            let b = identity.create_org(registrar, registrar, admin_b).unwrap();
            identity
                .add_members(admin_b, registrar, b, &[carol])
                .unwrap();
            assert!(!allows(usd, carol, OFFRAMP, TransferKind::Withdrawal));
            set_target(identity, admin_b, b, OFFRAMP, false, true);
            assert!(allows(usd, carol, OFFRAMP, TransferKind::Withdrawal));
            assert!(allows(usd, ALICE, OFFRAMP, TransferKind::Withdrawal));

            // A frozen member reaches no target.
            identity.set_frozen(admin, ALICE, true).unwrap();
            assert!(!allows(usd, ALICE, OFFRAMP, TransferKind::Withdrawal));
            assert!(!allows(usd, DEPOSITOR, ALICE, TransferKind::Deposit));
        });
    }

    /// Alice deposits from and withdraws to a stranger's Tempo address and her own.
    #[test_case(L1Policy::default() => [false, false, false, false])]
    #[test_case(L1Policy { open_deposit: true, ..Default::default() } => [true, true, false, false])]
    #[test_case(L1Policy { open_withdrawal: true, ..Default::default() } => [false, false, true, true])]
    #[test_case(L1Policy { self_deposit: true, ..Default::default() } => [false, true, false, false])]
    #[test_case(L1Policy { self_withdrawal: true, ..Default::default() } => [false, false, false, true])]
    fn l1_policy_opens_any_or_own_address(policy: L1Policy) -> [bool; 4] {
        with_identity(|identity, registrar| {
            let usd = token(1);
            let (admin, org) = org_with_members(identity, registrar, usd);
            identity
                .set_l1_policy(admin, registrar, org, &[usd], policy)
                .unwrap();
            assert_eq!(identity.l1_policy(admin, registrar, org, usd), Ok(policy));
            [
                allows(usd, STRANGER, ALICE, TransferKind::Deposit),
                allows(usd, ALICE, ALICE, TransferKind::Deposit),
                allows(usd, ALICE, STRANGER, TransferKind::Withdrawal),
                allows(usd, ALICE, ALICE, TransferKind::Withdrawal),
            ]
        })
    }

    #[test]
    fn org_zero_rules_govern_addresses_in_no_org() {
        with_identity(|identity, registrar| {
            let usd = token(1);
            let (admin, org) = org_with_members(identity, registrar, usd);
            let open = L1Policy {
                open_deposit: true,
                ..Default::default()
            };
            // Only the registrar sets org 0's rules.
            assert_eq!(
                identity.set_l1_policy(admin, registrar, 0, &[usd], open),
                Err(identity_error(ZoneIdentityError::unauthorized()))
            );
            assert!(!allows(usd, STRANGER, STRANGER, TransferKind::Deposit));
            identity
                .set_l1_policy(registrar, registrar, 0, &[usd], open)
                .unwrap();
            assert!(allows(usd, STRANGER, STRANGER, TransferKind::Deposit));
            // Org 0 may always withdraw anywhere, whatever its policy.
            assert!(allows(usd, STRANGER, OFFRAMP, TransferKind::Withdrawal));
            // Org 0's rules never apply to members.
            assert!(!allows(usd, STRANGER, ALICE, TransferKind::Deposit));
            assert_eq!(
                identity.l1_policy(registrar, registrar, org, usd),
                Ok(L1Policy::default())
            );
        });
    }

    #[test]
    fn only_the_org_admin_sets_and_reads_l1_rules() {
        with_identity(|identity, registrar| {
            let usd = token(1);
            let (admin, org) = org_with_members(identity, registrar, usd);
            let outsider = Address::repeat_byte(9);
            let rules = L1Target {
                deposit_from: true,
                withdraw_to: true,
            };
            assert_eq!(
                identity.set_l1_target(outsider, registrar, org, OFFRAMP, &[usd], rules),
                Err(identity_error(ZoneIdentityError::unauthorized()))
            );
            assert_eq!(
                identity.set_l1_target(admin, registrar, 9, OFFRAMP, &[usd], rules),
                Err(identity_error(ZoneIdentityError::unknown_org(9)))
            );
            assert_eq!(
                identity.set_l1_policy(outsider, registrar, org, &[usd], L1Policy::default()),
                Err(identity_error(ZoneIdentityError::unauthorized()))
            );
            let (_, virtual_addr) = register_virtual_master(&mut AddressRegistry::new()).unwrap();
            for target in [Address::ZERO, virtual_addr] {
                assert_eq!(
                    identity.set_l1_target(admin, registrar, org, target, &[usd], rules),
                    Err(identity_error(ZoneIdentityError::invalid_address()))
                );
            }
            identity
                .set_l1_target(admin, registrar, org, OFFRAMP, &[usd], rules)
                .unwrap();
            for reader in [admin, registrar] {
                assert_eq!(
                    identity.l1_target(reader, registrar, org, OFFRAMP, usd),
                    Ok(rules)
                );
            }
            assert_eq!(
                identity.l1_target(outsider, registrar, org, OFFRAMP, usd),
                Err(identity_error(ZoneIdentityError::unauthorized()))
            );
            assert_eq!(
                identity.l1_policy(outsider, registrar, org, usd),
                Err(identity_error(ZoneIdentityError::unauthorized()))
            );
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
            // A withdrawal to a virtual Tempo address follows its master's target.
            assert!(!allows(usd, ALICE, virtual_addr, TransferKind::Withdrawal));
            identity
                .set_l1_target(
                    admin,
                    registrar,
                    org,
                    VIRTUAL_MASTER,
                    &[usd],
                    L1Target {
                        deposit_from: false,
                        withdraw_to: true,
                    },
                )
                .unwrap();
            assert!(allows(usd, ALICE, virtual_addr, TransferKind::Withdrawal));
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
    fn org_zero_admin_is_refused() {
        with_identity(|identity, registrar| {
            assert_eq!(
                identity.set_org_admin(registrar, registrar, 0, Address::repeat_byte(1)),
                Err(identity_error(ZoneIdentityError::invalid_address()))
            );
        });
    }

    /// Every org check charges the same gas whatever the orgs, freezes, edges, targets and
    /// policies involved, and whether its slots were already warm, so gas cannot reveal an
    /// account's org.
    #[test]
    fn org_checks_cost_the_same_whatever_the_state() {
        use crate::test_utils::{MockL1Reader, test_context_with_hardfork, test_storage_provider};

        let mut ctx = test_context_with_hardfork(TempoHardfork::T15);
        let registrar = Address::repeat_byte(0xbb);
        let usd = token(1);
        let (carol, dave) = (Address::repeat_byte(0x55), Address::repeat_byte(0x66));
        let (org, other) = {
            let mut storage = test_storage_provider(&mut ctx, u64::MAX, false);
            StorageCtx::enter(&mut storage, || {
                let mut identity = ZoneIdentity::new();
                let (admin, org) = org_with_members(&mut identity, registrar, usd);
                let other = identity
                    .create_org(registrar, registrar, registrar)
                    .unwrap();
                identity
                    .add_members(registrar, registrar, other, &[carol])
                    .unwrap();
                identity
                    .add_members(admin, registrar, org, &[dave])
                    .unwrap();
                identity.set_frozen(admin, dave, true).unwrap();
                identity
                    .set_l1_target(
                        admin,
                        registrar,
                        org,
                        OFFRAMP,
                        &[usd],
                        L1Target {
                            deposit_from: true,
                            withdraw_to: true,
                        },
                    )
                    .unwrap();
                identity
                    .set_l1_policy(
                        registrar,
                        registrar,
                        other,
                        &[usd],
                        L1Policy {
                            self_withdrawal: true,
                            ..Default::default()
                        },
                    )
                    .unwrap();
                (org, other)
            })
        };

        let scenarios = [
            // Allowed in an org, denied across orgs, from org 0, and with a frozen party.
            (
                TransferKind::InZone,
                vec![
                    (ALICE, BOB),
                    (ALICE, carol),
                    (STRANGER, ALICE),
                    (ALICE, dave),
                ],
            ),
            // Allowed by target, by policy and from org 0, denied, and from a frozen party.
            (
                TransferKind::Withdrawal,
                vec![
                    (ALICE, OFFRAMP),
                    (carol, carol),
                    (ALICE, carol),
                    (STRANGER, OFFRAMP),
                    (dave, OFFRAMP),
                ],
            ),
            (
                TransferKind::Deposit,
                vec![
                    (OFFRAMP, ALICE),
                    (STRANGER, ALICE),
                    (carol, STRANGER),
                    (OFFRAMP, dave),
                ],
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
            let accounts = [ALICE, BOB, carol, dave, STRANGER];
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

        // After an outsider's orgOf(Alice) warms her org's admin slot, orgAdmin costs the same for
        // her org as for another, so it cannot tell which slot was warmed. A new transaction
        // starts with every slot cold.
        ctx.evm().state_mut().commit_transaction();
        let l1 = L1State::new(MockL1Reader::default(), Address::ZERO);
        let mut storage = test_storage_provider(&mut ctx, u64::MAX, false);
        let costs = StorageCtx::enter(&mut storage, || {
            let mut identity = ZoneIdentity::new();
            let outsider = Address::repeat_byte(0x99);
            assert_eq!(
                identity.org_of(outsider, registrar, ALICE),
                Err(identity_error(ZoneIdentityError::unauthorized()))
            );
            let mut cost = |org_id| {
                let before = identity.storage.gas_used();
                let call = IZoneIdentity::orgAdminCall { orgId: org_id }.abi_encode();
                identity.call(&l1, &call, outsider).unwrap();
                identity.storage.gas_used() - before
            };
            // Warms the registrar's Tempo slot, which every orgAdmin call reads.
            cost(0);
            [cost(other), cost(org)]
        });
        assert_eq!(costs[0], costs[1], "orgAdmin: {costs:?}");
    }
}
