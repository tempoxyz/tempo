//! Zone-native org registry for shared zones.
//!
//! [`ZoneIdentity`] is the source of truth for which org each address belongs to and which TIP-20s
//! each org may send to each other org. An org is a set of addresses with one admin; an address in
//! no org is in org 0, whose admin is the registrar. Org A may send token T to org B only when A's
//! admin allows T outbound to B and B's admin allows T inbound from A. Tempo takes part as the
//! admin of the orgs that hold L1 endpoints (deposit senders, off-ramps) and routers, so an exit
//! needs its half like any other edge.
//!
//! The portal admin configures it on Tempo: `ZonePortal.setIdentityConfig` sets the registrar and
//! whether the zone enforces edges, and the zone reads both from finalized Tempo state, so a
//! multisig admin never has to act on the zone.
//!
//! Execution enforces it: zone TIP-20 transfers revert, `ZoneOutbox::requestWithdrawal` reverts and
//! `ZoneInbox` bounces a deposit when [`ZoneIdentity::ensure_transfer`] denies the move. The
//! enforcement flag shares a Tempo slot with the transfer opt-in TIP-20 already reads; on the zone
//! the check reads at most three slots (both members and one per-token edge) whatever the
//! number of orgs, tokens or edges, and a transfer inside an org costs the same as one between
//! orgs.

mod dispatch;

use alloy_primitives::{Address, U256};
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

/// Org registry and per-token edges between orgs.
///
/// Field order is the storage layout; append new fields only.
#[contract(addr = ZONE_IDENTITY_ADDRESS)]
pub struct ZoneIdentity {
    /// Highest org ID created. Org IDs start at 1.
    pub org_count: u64,
    /// Each org's admin and edges, keyed by org ID.
    pub orgs: Mapping<u64, Org>,
    /// Packed [`Member`] word of each address; zero for addresses in no org.
    pub members: Mapping<Address, U256>,
}

/// One org's configuration. Its mappings are keyed by the other org of each edge, then the token.
#[derive(Debug, Clone, Storable, Default)]
pub struct Org {
    /// Key that manages the org's members and its halves of edges.
    pub admin: Address,
    /// Tokens this org allows to each other org, set by this org's admin.
    pub outbound: Mapping<u64, Mapping<Address, bool>>,
    /// Tokens this org accepts from each other org, set by this org's admin.
    pub inbound: Mapping<u64, Mapping<Address, bool>>,
    /// `outbound[B][T] && orgs[B].inbound[this org][T]`, rewritten whenever either half changes.
    /// The transfer check reads only this.
    pub edges: Mapping<u64, Mapping<Address, bool>>,
}

/// An address's packed membership: `org(64) | frozen << 64`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Member {
    /// Org the address belongs to; 0 when it is in no org.
    pub org: u64,
    /// The org admin froze the address: nothing may be sent to or from it.
    pub frozen: bool,
}

impl Member {
    const FROZEN_BIT: usize = 64;

    /// Decodes a stored member word.
    pub fn decode(word: U256) -> Self {
        Self {
            org: word.as_limbs()[0],
            frozen: word.bit(Self::FROZEN_BIT),
        }
    }

    /// Encodes the member word to store.
    pub fn encode(self) -> U256 {
        let mut word = U256::from(self.org);
        word.set_bit(Self::FROZEN_BIT, self.frozen);
        word
    }
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

/// Outcome of [`ZoneIdentity::verdict`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferVerdict {
    /// The zone does not enforce orgs.
    NotEnforced,
    /// The edge between the two orgs includes the token.
    Allowed,
    /// An address in no org withdrawing to its own L1 address: the exit for removed members.
    SelfWithdrawal,
    /// One side is frozen.
    Frozen,
    /// The edge between the two orgs does not include the token.
    NoEdge,
}

impl TransferVerdict {
    /// Whether the transfer may proceed.
    pub fn is_allowed(self) -> bool {
        matches!(
            self,
            Self::NotEnforced | Self::Allowed | Self::SelfWithdrawal
        )
    }
}

impl ZoneIdentity {
    /// Whether the zone enforces org edges: the portal's `identityEnforced` flag on finalized
    /// Tempo. Before the fork that adds `ZoneIdentity` it reads nothing and returns false.
    pub fn enforced<P: L1StorageReader>(l1: &L1State<P>) -> ZoneResult<bool> {
        if !crate::zone_identity_active(tempo_precompiles::storage::StorageCtx.spec()) {
            return Ok(false);
        }
        Ok(l1.read_portal(|portal| &portal.identity_enforced)?)
    }

    /// The registrar the portal admin set on finalized Tempo.
    pub fn registrar<P: L1StorageReader>(l1: &L1State<P>) -> ZoneResult<Address> {
        Ok(l1.read_portal(|portal| &portal.identity_registrar)?)
    }

    /// Decides whether `token` may move from `from` to `to`. `enforced` is the portal's flag from
    /// [`Self::enforced`]; when it is off nothing is read. Otherwise it reads at most three slots.
    pub fn verdict(
        &self,
        enforced: bool,
        token: Address,
        from: Address,
        to: Address,
        kind: TransferKind,
    ) -> ZoneResult<TransferVerdict> {
        if !enforced {
            return Ok(TransferVerdict::NotEnforced);
        }
        let sender = self.member(from)?;
        let recipient = self.member(to)?;
        if sender.frozen || recipient.frozen {
            return Ok(TransferVerdict::Frozen);
        }
        if kind == TransferKind::Withdrawal && sender.org == 0 && from == to {
            return Ok(TransferVerdict::SelfWithdrawal);
        }
        Ok(
            if self.orgs[sender.org].edges[recipient.org][token].read()? {
                TransferVerdict::Allowed
            } else {
                TransferVerdict::NoEdge
            },
        )
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
        if !self.verdict(enforced, token, from, to, kind)?.is_allowed() {
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
        if !self.members[account].read()?.is_zero() {
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
        let member = self.member(account)?;
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
        let member = self.member(account)?;
        if member.org == 0 {
            return Err(ZoneIdentityError::not_member(account).into());
        }
        self.ensure_org_admin(caller, registrar, member.org)?;
        self.write_member(account, Member { frozen, ..member })
    }

    /// Allows or stops `tokens` from `from` to `to`. The caller must administer `from`.
    pub fn set_outbound(
        &mut self,
        caller: Address,
        registrar: Address,
        from: u64,
        to: u64,
        tokens: &[Address],
        allowed: bool,
    ) -> ZoneResult<()> {
        self.ensure_org_admin(caller, registrar, from)?;
        self.ensure_org(to)?;
        for &token in tokens {
            self.orgs[from].outbound[to][token].write(allowed)?;
            let inbound = self.orgs[to].inbound[from][token].read()?;
            self.orgs[from].edges[to][token].write(allowed && inbound)?;
            self.emit_event(IZoneIdentity::OutboundUpdated {
                fromOrg: from,
                toOrg: to,
                token,
                allowed,
            })?;
        }
        Ok(())
    }

    /// Accepts or refuses `tokens` from `from` to `to`. The caller must administer `to`.
    pub fn set_inbound(
        &mut self,
        caller: Address,
        registrar: Address,
        to: u64,
        from: u64,
        tokens: &[Address],
        allowed: bool,
    ) -> ZoneResult<()> {
        self.ensure_org_admin(caller, registrar, to)?;
        self.ensure_org(from)?;
        for &token in tokens {
            self.orgs[to].inbound[from][token].write(allowed)?;
            let outbound = self.orgs[from].outbound[to][token].read()?;
            self.orgs[from].edges[to][token].write(outbound && allowed)?;
            self.emit_event(IZoneIdentity::InboundUpdated {
                toOrg: to,
                fromOrg: from,
                token,
                allowed,
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

    /// Decoded membership of `account`.
    pub fn member(&self, account: Address) -> ZoneResult<Member> {
        Ok(Member::decode(self.members[account].read()?))
    }

    /// Membership of `account` for a caller that may see it: the account itself, its org's admin or
    /// the registrar.
    pub fn org_of(
        &self,
        caller: Address,
        registrar: Address,
        account: Address,
    ) -> ZoneResult<Member> {
        let member = self.member(account)?;
        if caller != account && caller != self.org_admin(registrar, member.org)? {
            ensure_caller(caller, registrar)?;
        }
        Ok(member)
    }

    /// Whether `token` may move from `from` to `to`, for the admin of either org or the registrar.
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
        Ok(self.orgs[from].edges[to][token].read()?)
    }

    fn write_member(&mut self, account: Address, member: Member) -> ZoneResult<()> {
        self.members[account].write(member.encode())?;
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

/// Seeds `ZoneIdentity` storage directly, for tests of the paths that enforce it.
#[cfg(test)]
pub(crate) fn seed_for_test(
    members: &[(Address, u64)],
    edges: &[(u64, u64, Address)],
) -> tempo_precompiles::Result<()> {
    let mut identity = ZoneIdentity::new();
    let mut org_count = identity.org_count.read()?;
    for &(account, org) in members {
        org_count = org_count.max(org);
        let member = Member { org, frozen: false };
        identity.members[account].write(member.encode())?;
    }
    identity.org_count.write(org_count)?;
    for &(from, to, token) in edges {
        identity.orgs[from].edges[to][token].write(true)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
