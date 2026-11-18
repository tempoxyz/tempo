//! Zone-native org registry for shared zones.
//!
//! [`ZoneIdentity`] is the source of truth for which org each Zone address belongs to, which TIP-20s
//! each org may send to each other org, and which Tempo addresses each org's members may deposit
//! from and withdraw to. An org is a set of Zone addresses with one admin; an address in no org is
//! in org 0, whose admin is the registrar. An address joins only when both sides sign the same
//! EIP-712 `Join`, since a member can be frozen and read by its admin and cannot leave on its own:
//! the admin submits `addMembers` with each account's signature, or the account submits `joinOrg`
//! with the admin's.
//!
//! - **Transfers on the Zone** follow edges: org A may send token T to org B only when A's admin
//!   allows T outbound to B and B's admin allows T inbound from A. An org's edge to itself, which
//!   its admin sets alone, allows transfers between its members.
//! - **Deposits and withdrawals** follow the member's org alone. Tempo addresses are never members,
//!   so nobody has to consent for an org to name one: an org lists, per token, the Tempo addresses
//!   it accepts deposits from and lets members withdraw to ([`L1Target`]), and may open either
//!   direction to any address or to the member's own address ([`L1Policy`]). Several orgs may list
//!   the same address, such as an off-ramp or an Earn router on Tempo.
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

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::{SolStruct, eip712_domain};
use tempo_contracts::zones::{IZoneIdentity, ZoneIdentityError};
use tempo_precompiles::{
    address_registry::AddressRegistry,
    error::TempoPrecompileError,
    signature_verifier::SignatureVerifier,
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
    /// Each address's next join nonce. A join spends it, so a join signature works once and an
    /// address removed from an org needs a new one to rejoin.
    pub join_nonces: Mapping<Address, u64>,
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
    /// - a withdrawal needs the sender's org to allow `to`, a Tempo address.
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
        // TIP-20 credits a TIP-1022 virtual recipient's master, so the master decides. The registry
        // is mirrored from Tempo, so this also resolves Tempo-side withdrawal recipients. An
        // unregistered virtual recipient is denied rather than an error, so a deposit to one
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
                let allowed = policy.open_withdrawal
                    || (policy.self_withdrawal && to == from)
                    || target.withdraw_to;
                Ok(!sender.frozen && allowed)
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

    /// Adds each approving account, in no org, to `org`. Only `org`'s admin may call it, and each
    /// approval must carry the account's own signature over its [`IZoneIdentity::Join`], so no
    /// admin can place an address in an org. Reverts, adding none, if any approval fails.
    pub fn add_members(
        &mut self,
        caller: Address,
        registrar: Address,
        org: u64,
        approvals: &[IZoneIdentity::MemberApproval],
    ) -> ZoneResult<()> {
        self.ensure_org_admin(caller, registrar, org)?;
        if org == 0 {
            return Err(ZoneIdentityError::invalid_address().into());
        }
        // Verify every approval first, so a rejected batch writes nothing.
        let mut nonces = Vec::with_capacity(approvals.len());
        for approval in approvals {
            let nonce = self.ensure_joinable(approval.account, approval.deadline)?;
            let hash = self.join_hash(org, approval.account, nonce, approval.deadline);
            ensure_signed_by(approval.account, hash, &approval.signature)?;
            nonces.push(nonce);
        }
        for (approval, nonce) in approvals.iter().zip(nonces) {
            // An account listed twice was verified twice against the same nonce; the second join
            // finds it a member.
            if self.members[approval.account].read()? != Member::default() {
                return Err(ZoneIdentityError::already_member(approval.account).into());
            }
            self.join(approval.account, org, nonce)?;
        }
        Ok(())
    }

    /// Makes the caller a member of `org` with `org`'s admin's signature over the caller's
    /// [`IZoneIdentity::Join`]. The caller's own transaction is its consent.
    pub fn join_org(
        &mut self,
        caller: Address,
        registrar: Address,
        org: u64,
        deadline: u64,
        admin_signature: &[u8],
    ) -> ZoneResult<()> {
        self.ensure_org(org)?;
        if org == 0 {
            return Err(ZoneIdentityError::invalid_address().into());
        }
        let nonce = self.ensure_joinable(caller, deadline)?;
        let hash = self.join_hash(org, caller, nonce, deadline);
        ensure_signed_by(self.org_admin(registrar, org)?, hash, admin_signature)?;
        self.join(caller, org, nonce)
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
    /// Org 0's policy, set by the registrar, governs addresses in no org.
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

    /// `account`'s next join nonce, for the same callers as [`Self::org_of`]. Each side of a join
    /// signs it into the [`IZoneIdentity::Join`].
    pub fn join_nonce(
        &self,
        caller: Address,
        registrar: Address,
        account: Address,
    ) -> ZoneResult<u64> {
        self.org_of(caller, registrar, account)?;
        Ok(self.join_nonces[account].read()?)
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

    /// The signing hash of `account`'s [`IZoneIdentity::Join`] to `org`.
    fn join_hash(&self, org: u64, account: Address, nonce: u64, deadline: u64) -> B256 {
        let domain = eip712_domain! {
            name: "ZoneIdentity",
            version: "1",
            chain_id: self.storage.chain_id(),
            verifying_contract: ZONE_IDENTITY_ADDRESS,
        };
        IZoneIdentity::Join {
            orgId: org,
            account,
            nonce,
            deadline,
        }
        .eip712_signing_hash(&domain)
    }

    /// Returns `account`'s join nonce if it may join now: a real address in no org, with a deadline
    /// that has not passed.
    fn ensure_joinable(&self, account: Address, deadline: u64) -> ZoneResult<u64> {
        // A virtual address never holds funds; moves to it are checked as its master.
        if account.is_zero() || account.is_virtual() {
            return Err(ZoneIdentityError::invalid_address().into());
        }
        if self.storage.timestamp() > U256::from(deadline) {
            return Err(ZoneIdentityError::join_expired(deadline).into());
        }
        if self.members[account].read()? != Member::default() {
            return Err(ZoneIdentityError::already_member(account).into());
        }
        Ok(self.join_nonces[account].read()?)
    }

    /// Adds `account` to `org` and spends its join nonce.
    fn join(&mut self, account: Address, org: u64, nonce: u64) -> ZoneResult<()> {
        let next = nonce
            .checked_add(1)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        self.join_nonces[account].write(next)?;
        self.write_member(account, Member { org, frozen: false })
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
    /// Key that approves joins, removes and freezes the org's members and sets its halves of
    /// edges, its targets and its policy.
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

/// Rejects `signature` unless it is `signer`'s over `hash`. Only primitive signatures count:
/// secp256k1, P256 and WebAuthn. Keychain signatures are refused, since a join hands the org admin
/// powers over the account that an access key should not be able to grant.
// TODO: accept configurable account (TIP-1113) signatures.
fn ensure_signed_by(signer: Address, hash: B256, signature: &[u8]) -> ZoneResult<()> {
    match SignatureVerifier::new().recover(hash, signature) {
        Ok(recovered) if !signer.is_zero() && recovered == signer => Ok(()),
        Err(error) if error.is_system_error() => Err(error.into()),
        _ => Err(ZoneIdentityError::invalid_join_signature(signer).into()),
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
pub(crate) mod tests {
    use alloy_primitives::{Address, B256, Bytes};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use alloy_sol_types::SolCall;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::zones::{IZoneIdentity::MemberApproval, ZoneIdentityError};
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

    /// Adds `accounts` to `org` without signatures, for tests of everything but joining.
    pub(crate) fn enroll(
        identity: &mut ZoneIdentity,
        _admin: Address,
        _registrar: Address,
        org: u64,
        accounts: &[Address],
    ) {
        for &account in accounts {
            let nonce = identity.join_nonces[account].read().unwrap();
            identity.join(account, org, nonce).unwrap();
        }
    }

    fn key(byte: u8) -> PrivateKeySigner {
        PrivateKeySigner::from_bytes(&B256::repeat_byte(byte)).unwrap()
    }

    /// `key`'s signature over `account`'s join to `org`.
    fn sign_join(
        identity: &ZoneIdentity,
        key: &PrivateKeySigner,
        org: u64,
        account: Address,
        nonce: u64,
        deadline: u64,
    ) -> Bytes {
        let hash = identity.join_hash(org, account, nonce, deadline);
        Bytes::from(key.sign_hash_sync(&hash).unwrap().as_bytes())
    }

    /// `key`'s own approval to join `org`.
    fn approve(
        identity: &ZoneIdentity,
        key: &PrivateKeySigner,
        org: u64,
        nonce: u64,
        deadline: u64,
    ) -> MemberApproval {
        MemberApproval {
            account: key.address(),
            deadline,
            signature: sign_join(identity, key, org, key.address(), nonce, deadline),
        }
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
        enroll(identity, admin, registrar, org, &[ALICE, BOB]);
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
            // The org's targets no longer apply, and org 0 has none unless the registrar sets them.
            assert!(!allows(usd, BOB, OFFRAMP, TransferKind::Withdrawal));
        });
    }

    #[test]
    fn add_members_needs_each_accounts_signature() {
        with_identity(|identity, registrar| {
            let admin = Address::repeat_byte(1);
            let org = identity.create_org(registrar, registrar, admin).unwrap();
            let other = identity
                .create_org(registrar, registrar, Address::repeat_byte(2))
                .unwrap();
            let (alice, bob) = (key(0xa1), key(0xb1));
            let forged = MemberApproval {
                account: alice.address(),
                deadline: u64::MAX,
                signature: sign_join(identity, &bob, org, alice.address(), 0, u64::MAX),
            };
            let empty = MemberApproval {
                account: alice.address(),
                deadline: u64::MAX,
                signature: Bytes::new(),
            };
            let refused = [
                // A bad approval anywhere refuses the whole batch.
                (
                    vec![approve(identity, &bob, org, 0, u64::MAX), forged],
                    ZoneIdentityError::invalid_join_signature(alice.address()),
                ),
                (
                    vec![approve(identity, &alice, other, 0, u64::MAX)],
                    ZoneIdentityError::invalid_join_signature(alice.address()),
                ),
                (
                    vec![approve(identity, &alice, org, 1, u64::MAX)],
                    ZoneIdentityError::invalid_join_signature(alice.address()),
                ),
                (
                    vec![empty],
                    ZoneIdentityError::invalid_join_signature(alice.address()),
                ),
                (
                    vec![approve(identity, &alice, org, 0, 0)],
                    ZoneIdentityError::join_expired(0),
                ),
            ];
            for (approvals, error) in refused {
                assert_eq!(
                    identity.add_members(admin, registrar, org, &approvals),
                    Err(identity_error(error))
                );
            }
            assert_eq!(
                identity.members[bob.address()].read().unwrap(),
                Member::default()
            );

            let approvals = [
                approve(identity, &alice, org, 0, u64::MAX),
                approve(identity, &bob, org, 0, u64::MAX),
            ];
            assert_eq!(
                identity.add_members(Address::repeat_byte(2), registrar, org, &approvals),
                Err(identity_error(ZoneIdentityError::unauthorized()))
            );
            identity
                .add_members(admin, registrar, org, &approvals)
                .unwrap();
            for account in [alice.address(), bob.address()] {
                assert_eq!(
                    identity.members[account].read().unwrap(),
                    Member { org, frozen: false }
                );
                assert_eq!(identity.join_nonces[account].read().unwrap(), 1);
            }

            // A member can't join again, and a used signature can't bring a removed member back.
            assert_eq!(
                identity.add_members(
                    admin,
                    registrar,
                    org,
                    &[approve(identity, &bob, org, 1, u64::MAX)]
                ),
                Err(identity_error(ZoneIdentityError::already_member(
                    bob.address()
                )))
            );
            identity.remove_member(admin, alice.address()).unwrap();
            assert_eq!(
                identity.add_members(admin, registrar, org, &approvals[..1]),
                Err(identity_error(ZoneIdentityError::invalid_join_signature(
                    alice.address()
                )))
            );
            // An account listed twice joins once.
            let twice = approve(identity, &alice, org, 1, u64::MAX);
            assert_eq!(
                identity.add_members(admin, registrar, org, &[twice.clone(), twice]),
                Err(identity_error(ZoneIdentityError::already_member(
                    alice.address()
                )))
            );
        });
    }

    #[test]
    fn join_org_needs_the_admins_signature() {
        with_identity(|identity, registrar| {
            let admin = key(0xad);
            let org = identity
                .create_org(registrar, registrar, admin.address())
                .unwrap();
            let refused = [
                (
                    org,
                    u64::MAX,
                    sign_join(identity, &key(0xee), org, ALICE, 0, u64::MAX),
                    ZoneIdentityError::invalid_join_signature(admin.address()),
                ),
                (
                    org,
                    u64::MAX,
                    sign_join(identity, &admin, org, BOB, 0, u64::MAX),
                    ZoneIdentityError::invalid_join_signature(admin.address()),
                ),
                (
                    org,
                    0,
                    sign_join(identity, &admin, org, ALICE, 0, 0),
                    ZoneIdentityError::join_expired(0),
                ),
                (
                    0,
                    u64::MAX,
                    Bytes::new(),
                    ZoneIdentityError::invalid_address(),
                ),
                (9, u64::MAX, Bytes::new(), ZoneIdentityError::unknown_org(9)),
            ];
            for (org, deadline, signature, error) in refused {
                assert_eq!(
                    identity.join_org(ALICE, registrar, org, deadline, &signature),
                    Err(identity_error(error))
                );
            }

            let signature = sign_join(identity, &admin, org, ALICE, 0, u64::MAX);
            identity
                .join_org(ALICE, registrar, org, u64::MAX, &signature)
                .unwrap();
            assert_eq!(
                identity.members[ALICE].read().unwrap(),
                Member { org, frozen: false }
            );
            // The nonce is visible to the account and the registrar only.
            for reader in [ALICE, registrar] {
                assert_eq!(identity.join_nonce(reader, registrar, ALICE), Ok(1));
            }
            assert_eq!(
                identity.join_nonce(STRANGER, registrar, ALICE),
                Err(identity_error(ZoneIdentityError::unauthorized()))
            );

            // After removal the old signature is spent; a new one rejoins.
            identity.remove_member(admin.address(), ALICE).unwrap();
            assert_eq!(
                identity.join_org(ALICE, registrar, org, u64::MAX, &signature),
                Err(identity_error(ZoneIdentityError::invalid_join_signature(
                    admin.address()
                )))
            );
            let signature = sign_join(identity, &admin, org, ALICE, 1, u64::MAX);
            identity
                .join_org(ALICE, registrar, org, u64::MAX, &signature)
                .unwrap();
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
            enroll(identity, admin_b, registrar, b, &[carol]);
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
            enroll(identity, admin, registrar, org, &[VIRTUAL_MASTER]);
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
                identity.join_org(virtual_addr, registrar, org, u64::MAX, &[]),
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
                enroll(&mut identity, registrar, registrar, other, &[carol]);
                enroll(&mut identity, admin, registrar, org, &[dave]);
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
            // Allowed by target and by policy, denied, from org 0, and from a frozen party.
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
