//! Zone-native org registry for shared zones.
//!
//! [`ZoneIdentity`] is the source of truth for which org each address belongs to and which TIP-20s
//! each org may send to each other org. An org is a set of addresses with one admin; an address in
//! no org is in org 0, whose admin is the registrar. Org A may send token T to org B only when A's
//! admin allows T outbound to B and B's admin allows T inbound from A. Tempo takes part as the
//! admin of the orgs that hold L1 endpoints (deposit senders, off-ramps) and routers, so an exit
//! needs its half like any other edge.
//!
//! Until a later fork hooks [`check_transfer`] into TIP-20, the outbox and the inbox, the
//! sequencer enforces it by leaving disallowed transactions out of blocks and bouncing disallowed
//! deposits. The storage is laid out for that later in-EVM check: [`check_transfer`] reads at most
//! five slots (`enforced`, both members, the token's bit and one edge) whatever the number of orgs,
//! tokens or edges, and a transfer inside an org costs the same as one between orgs.

mod dispatch;

use alloy_primitives::{Address, U256};
use tempo_contracts::zones::ZoneIdentityError;
use tempo_precompiles::{
    error::TempoPrecompileError,
    storage::{Handler, Mapping},
};
use tempo_precompiles_macros::contract;
use tempo_primitives::TempoAddressExt as _;
pub use zone_primitives::constants::ZONE_IDENTITY_ADDRESS;

use crate::error::ZoneResult;

/// Number of TIP-20s one edge mask can name.
pub const MAX_IDENTITY_TOKENS: u16 = 256;

/// Org registry and per-token edges between orgs.
///
/// Field order is the storage layout the later TIP-20 hook reads; append new fields only.
#[contract(addr = ZONE_IDENTITY_ADDRESS)]
pub struct ZoneIdentity {
    /// Tempo's key that creates orgs, assigns org admins, registers tokens and administers org 0.
    pub registrar: Address,
    /// Whether the zone enforces org edges. Dedicated zones leave it off.
    pub enforced: bool,
    /// Highest org ID created. Org IDs start at 1.
    pub org_count: u64,
    /// Admin of each org.
    pub org_admins: Mapping<u64, Address>,
    /// Packed [`Member`] word of each address; zero for addresses in no org.
    pub members: Mapping<Address, U256>,
    /// Tokens org A allows to org B, set by A's admin: `out_masks[A][B]`.
    pub out_masks: Mapping<u64, Mapping<u64, U256>>,
    /// Tokens org B accepts from org A, set by B's admin: `in_masks[B][A]`.
    pub in_masks: Mapping<u64, Mapping<u64, U256>>,
    /// `out_masks[A][B] & in_masks[B][A]`, written whenever either half changes.
    pub edges: Mapping<u64, Mapping<u64, U256>>,
    /// Bit index + 1 of each registered token; zero for unregistered tokens.
    pub token_bits: Mapping<Address, u16>,
    /// Number of registered tokens.
    pub token_count: u16,
}

/// An address's packed membership: `org(64) | l1_only << 64 | frozen << 65`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Member {
    /// Org the address belongs to; 0 when it is in no org.
    pub org: u64,
    /// The address only appears on L1 (a deposit sender or withdrawal destination), so no in-zone
    /// transfer may name it.
    pub l1_only: bool,
    /// The org admin froze the address: nothing may be sent to or from it.
    pub frozen: bool,
}

impl Member {
    const L1_ONLY_BIT: usize = 64;
    const FROZEN_BIT: usize = 65;

    /// Decodes a stored member word.
    pub fn decode(word: U256) -> Self {
        Self {
            org: word.as_limbs()[0],
            l1_only: word.bit(Self::L1_ONLY_BIT),
            frozen: word.bit(Self::FROZEN_BIT),
        }
    }

    /// Encodes the member word to store.
    pub fn encode(self) -> U256 {
        let mut word = U256::from(self.org);
        word.set_bit(Self::L1_ONLY_BIT, self.l1_only);
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

/// Outcome of [`check_transfer`].
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
    /// An in-zone transfer names an L1-only address.
    L1OnlyInZone,
    /// The token was never registered, so no edge can include it.
    UnregisteredToken,
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

/// Decides whether `token` may move from `from` to `to`, reading `ZoneIdentity` storage through
/// `sload`.
///
/// The sequencer calls this against the latest or in-block state; a later fork calls it from
/// TIP-20, the outbox and the inbox over the same storage. It reads at most five slots.
pub fn check_transfer<E>(
    mut sload: impl FnMut(U256) -> core::result::Result<U256, E>,
    token: Address,
    from: Address,
    to: Address,
    kind: TransferKind,
) -> core::result::Result<TransferVerdict, E> {
    let identity = ZoneIdentity::new();
    // `enforced` shares slot 0 with `registrar`.
    let enforced_shift = identity.enforced.offset().unwrap_or_default() * 8;
    if !(sload(identity.enforced.slot())? >> enforced_shift).bit(0) {
        return Ok(TransferVerdict::NotEnforced);
    }
    let sender = Member::decode(sload(identity.members[from].slot())?);
    let recipient = Member::decode(sload(identity.members[to].slot())?);
    if sender.frozen || recipient.frozen {
        return Ok(TransferVerdict::Frozen);
    }
    if kind == TransferKind::InZone && (sender.l1_only || recipient.l1_only) {
        return Ok(TransferVerdict::L1OnlyInZone);
    }
    if kind == TransferKind::Withdrawal && sender.org == 0 && from == to {
        return Ok(TransferVerdict::SelfWithdrawal);
    }
    let bit = sload(identity.token_bits[token].slot())?;
    if bit.is_zero() {
        return Ok(TransferVerdict::UnregisteredToken);
    }
    let edge = sload(identity.edges[sender.org][recipient.org].slot())?;
    Ok(if edge.bit(bit.to::<usize>() - 1) {
        TransferVerdict::Allowed
    } else {
        TransferVerdict::NoEdge
    })
}

impl ZoneIdentity {
    /// Sets the registrar. Only the portal admin, read from finalized Tempo, may call it.
    pub fn set_registrar(
        &mut self,
        caller: Address,
        portal_admin: Address,
        registrar: Address,
    ) -> ZoneResult<()> {
        ensure_caller(caller, portal_admin)?;
        Ok(self.registrar.write(registrar)?)
    }

    /// Turns enforcement on or off. Only the portal admin may call it.
    pub fn set_enforced(
        &mut self,
        caller: Address,
        portal_admin: Address,
        enforced: bool,
    ) -> ZoneResult<()> {
        ensure_caller(caller, portal_admin)?;
        Ok(self.enforced.write(enforced)?)
    }

    /// Creates an org administered by `admin` and returns its ID.
    pub fn create_org(&mut self, caller: Address, admin: Address) -> ZoneResult<u64> {
        self.ensure_registrar(caller)?;
        if admin.is_zero() {
            return Err(ZoneIdentityError::invalid_address().into());
        }
        let org = self
            .org_count
            .read()?
            .checked_add(1)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        self.org_count.write(org)?;
        self.org_admins[org].write(admin)?;
        Ok(org)
    }

    /// Replaces an org's admin. Org 0 is always administered by the registrar.
    pub fn set_org_admin(&mut self, caller: Address, org: u64, admin: Address) -> ZoneResult<()> {
        self.ensure_registrar(caller)?;
        self.ensure_org(org)?;
        if org == 0 || admin.is_zero() {
            return Err(ZoneIdentityError::invalid_address().into());
        }
        Ok(self.org_admins[org].write(admin)?)
    }

    /// Assigns `token` the next free bit of the edge masks. Bits are never reused.
    pub fn register_token(&mut self, caller: Address, token: Address) -> ZoneResult<u16> {
        self.ensure_registrar(caller)?;
        if !token.is_tip20() {
            return Err(ZoneIdentityError::invalid_address().into());
        }
        if self.token_bits[token].read()? != 0 {
            return Err(ZoneIdentityError::token_already_registered(token).into());
        }
        let bit = self.token_count.read()?;
        if bit >= MAX_IDENTITY_TOKENS {
            return Err(ZoneIdentityError::too_many_tokens().into());
        }
        self.token_bits[token].write(bit + 1)?;
        self.token_count.write(bit + 1)?;
        Ok(bit)
    }

    /// Adds `account`, which must be in no org, to `org`.
    pub fn add_member(
        &mut self,
        caller: Address,
        org: u64,
        account: Address,
        l1_only: bool,
    ) -> ZoneResult<()> {
        self.ensure_org_admin(caller, org)?;
        if org == 0 || account.is_zero() {
            return Err(ZoneIdentityError::invalid_address().into());
        }
        if !self.members[account].read()?.is_zero() {
            return Err(ZoneIdentityError::already_member(account).into());
        }
        let member = Member {
            org,
            l1_only,
            frozen: false,
        };
        Ok(self.members[account].write(member.encode())?)
    }

    /// Moves `account` back to org 0. Only its org's admin may remove it, so a member cannot leave
    /// to escape its org's outbound rules.
    pub fn remove_member(&mut self, caller: Address, account: Address) -> ZoneResult<()> {
        let member = self.member(account)?;
        if member.org == 0 {
            return Err(ZoneIdentityError::not_member(account).into());
        }
        self.ensure_org_admin(caller, member.org)?;
        Ok(self.members[account].write(U256::ZERO)?)
    }

    /// Freezes or unfreezes a member of the caller's org.
    pub fn set_frozen(
        &mut self,
        caller: Address,
        account: Address,
        frozen: bool,
    ) -> ZoneResult<()> {
        let member = self.member(account)?;
        if member.org == 0 {
            return Err(ZoneIdentityError::not_member(account).into());
        }
        self.ensure_org_admin(caller, member.org)?;
        Ok(self.members[account].write(Member { frozen, ..member }.encode())?)
    }

    /// Sets which tokens `from` allows to `to`. The caller must administer `from`.
    pub fn set_outbound(
        &mut self,
        caller: Address,
        from: u64,
        to: u64,
        mask: U256,
    ) -> ZoneResult<()> {
        self.ensure_org_admin(caller, from)?;
        self.ensure_org(to)?;
        self.out_masks[from][to].write(mask)?;
        let inbound = self.in_masks[to][from].read()?;
        Ok(self.edges[from][to].write(mask & inbound)?)
    }

    /// Sets which tokens `to` accepts from `from`. The caller must administer `to`.
    pub fn set_inbound(
        &mut self,
        caller: Address,
        to: u64,
        from: u64,
        mask: U256,
    ) -> ZoneResult<()> {
        self.ensure_org_admin(caller, to)?;
        self.ensure_org(from)?;
        self.in_masks[to][from].write(mask)?;
        let outbound = self.out_masks[from][to].read()?;
        Ok(self.edges[from][to].write(outbound & mask)?)
    }

    /// Admin of `org`; the registrar for org 0.
    pub fn org_admin(&self, org: u64) -> ZoneResult<Address> {
        if org == 0 {
            return Ok(self.registrar.read()?);
        }
        Ok(self.org_admins[org].read()?)
    }

    /// Decoded membership of `account`.
    pub fn member(&self, account: Address) -> ZoneResult<Member> {
        Ok(Member::decode(self.members[account].read()?))
    }

    /// Membership of `account` for a caller that may see it: the account itself, its org's admin or
    /// the registrar.
    pub fn org_of(&self, caller: Address, account: Address) -> ZoneResult<Member> {
        let member = self.member(account)?;
        if caller != account && caller != self.org_admin(member.org)? {
            self.ensure_registrar(caller)?;
        }
        Ok(member)
    }

    /// Edge mask from `from` to `to`, for the admin of either org or the registrar.
    pub fn edge(&self, caller: Address, from: u64, to: u64) -> ZoneResult<U256> {
        if caller != self.org_admin(from)? && caller != self.org_admin(to)? {
            self.ensure_registrar(caller)?;
        }
        Ok(self.edges[from][to].read()?)
    }

    fn ensure_registrar(&self, caller: Address) -> ZoneResult<()> {
        ensure_caller(caller, self.registrar.read()?)
    }

    fn ensure_org(&self, org: u64) -> ZoneResult<()> {
        if org > self.org_count.read()? {
            return Err(ZoneIdentityError::unknown_org(org).into());
        }
        Ok(())
    }

    fn ensure_org_admin(&self, caller: Address, org: u64) -> ZoneResult<()> {
        self.ensure_org(org)?;
        ensure_caller(caller, self.org_admin(org)?)
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
