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
    error::TempoPrecompileError,
    storage::{Handler, Mapping},
};
use tempo_precompiles_macros::{Storable, contract};
pub use zone_primitives::constants::ZONE_IDENTITY_ADDRESS;

use crate::{
    error::ZoneResult,
    storage::{L1State, L1StorageReader},
};

pub use tempo_contracts::zones::IZoneIdentity::OrgKey;

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
    /// Both halves of the transfer, deposit and withdrawal edges between two orgs for a token,
    /// keyed by sending org, receiving org and token.
    pub edges: Mapping<u64, Mapping<u64, Mapping<Address, Edges>>>,
}

/// One org's configuration.
#[derive(Debug, Clone, Storable, Default)]
pub struct Org {
    /// Key that manages the org's members and its halves of edges.
    pub admin: Address,
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
    /// withdrawal that misses falls back to org 0's Tempo side, meaning any address on Tempo. An
    /// address in no org may always withdraw to its own address on Tempo.
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
        let sender = self.members[from].read()?;
        let recipient = self.members[to].read()?;
        if sender.frozen || recipient.frozen {
            return Ok(false);
        }
        let allowed = |from: u64, to: u64| -> ZoneResult<bool> {
            Ok(self.edges[from][to][token].read()?.allows(kind))
        };
        // A deposit or withdrawal that misses falls back to org 0's Tempo side: any address there.
        Ok(match kind {
            TransferKind::InZone => allowed(sender.org, recipient.org)?,
            TransferKind::Deposit => {
                allowed(sender.org, recipient.org)?
                    || (sender.org != 0 && allowed(0, recipient.org)?)
            }
            TransferKind::Withdrawal => {
                (sender.org == 0 && from == to)
                    || allowed(sender.org, recipient.org)?
                    || (recipient.org != 0 && allowed(sender.org, 0)?)
            }
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

    /// Adds `account`, which must be in no org, to `org`.
    pub fn add_member(
        &mut self,
        caller: Address,
        registrar: Address,
        org: u64,
        account: Address,
    ) -> ZoneResult<()> {
        self.ensure_org_admin(caller, registrar, org)?;
        if org == 0 || account.is_zero() {
            return Err(ZoneIdentityError::invalid_address().into());
        }
        if self.members[account].read()? != Member::default() {
            return Err(ZoneIdentityError::already_member(account).into());
        }
        self.write_member(account, Member { org, frozen: false })
    }

    /// Moves `account` back to org 0. Only its org's admin may remove it, so a member cannot leave
    /// to escape its org's outbound rules.
    pub fn remove_member(
        &mut self,
        caller: Address,
        registrar: Address,
        account: Address,
    ) -> ZoneResult<()> {
        let member = self.members[account].read()?;
        if member.org == 0 {
            return Err(ZoneIdentityError::not_member(account).into());
        }
        self.ensure_org_admin(caller, registrar, member.org)?;
        self.write_member(account, Member::default())
    }

    /// Freezes or unfreezes a member of the caller's org.
    pub fn set_frozen(
        &mut self,
        caller: Address,
        registrar: Address,
        account: Address,
        frozen: bool,
    ) -> ZoneResult<()> {
        let member = self.members[account].read()?;
        if member.org == 0 {
            return Err(ZoneIdentityError::not_member(account).into());
        }
        self.ensure_org_admin(caller, registrar, member.org)?;
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
            let slot = &mut self.edges[from.orgId][to.orgId][token];
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
        let member = self.members[account].read()?;
        if caller != account && caller != self.org_admin(registrar, member.org)? {
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
        Ok(self.edges[from.orgId][to.orgId][token].read()?.allows(kind))
    }

    fn write_member(&mut self, account: Address, member: Member) -> ZoneResult<()> {
        self.members[account].write(member)?;
        Ok(self.emit_event(IZoneIdentity::MemberUpdated {
            account,
            orgId: member.org,
            frozen: member.frozen,
        })?)
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

/// Rejects a call unless `caller` is the nonzero `expected` address.
fn ensure_caller(caller: Address, expected: Address) -> ZoneResult<()> {
    if expected.is_zero() || caller != expected {
        return Err(ZoneIdentityError::unauthorized().into());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
