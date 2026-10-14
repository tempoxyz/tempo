//! [TIP-1145] flat token-specific transfer policies and receive configurations.
//!
//! Token-specific policies are permanently keyed by the TIP-20 address and carry independent
//! sender, recipient, and mint-recipient [`PolicyMode`]s. Account memberships for every role are
//! packed into a single `tokenUserFlags[token][account]` word, whose bit 3 also stores the
//! account's receive-token membership for that token. Receive configurations pack both filter
//! modes with the recovery authority into one word.
//!
//! [TIP-1145]: <https://docs.tempo.xyz/protocol/tips/tip-1145>

use super::{AuthRole, ReceiveConfig, ReceivePolicyConfig, TIP403Registry, TokenPolicy};
use crate::{
    RECEIVE_POLICY_GUARD_ADDRESS,
    error::Result,
    receive_policy_guard::RecoveryMode,
    storage::{Handler, Layout, LayoutCtx, Slot, Storable, StorableType, StorageOps},
    tip20::{TIP20Token, roles::DEFAULT_ADMIN_ROLE},
    tip20_factory::TIP20Factory,
};
use alloy::primitives::{Address, U256};
use tempo_contracts::precompiles::{
    ITIP403Registry::{self, AuthRole as Role, BlockedReason, MembershipKind, PolicyMode},
    TIP403RegistryError,
};
use tempo_primitives::TempoAddressExt;

/// Reserved transfer policy ID selecting the token's own TIP-1145 policy.
///
/// Never allocated to generic policies: the policy counter overflows before reaching it.
pub const TOKEN_POLICY_ID: u64 = u64::MAX;

/// First byte of a TIP-1145 receive configuration word (legacy words use `0`/`1`).
pub const RECEIVE_CONFIG_KIND: u8 = 2;

/// `tokenUserFlags` bit for sender membership.
pub const SENDER_FLAG: u8 = 0b0001;
/// `tokenUserFlags` bit for recipient membership.
pub const RECIPIENT_FLAG: u8 = 0b0010;
/// `tokenUserFlags` bit for mint-recipient membership.
pub const MINT_RECIPIENT_FLAG: u8 = 0b0100;
/// `tokenUserFlags` bit for the account's own receive-token membership.
pub const RECEIVE_TOKEN_FLAG: u8 = 0b1000;

/// Stores [`PolicyMode`] as one byte, rejecting undefined encodings in both directions.
impl StorableType for PolicyMode {
    const LAYOUT: Layout = Layout::Bytes(1);
    type Handler = Slot<Self>;

    fn handle(slot: U256, ctx: LayoutCtx, address: Address) -> Self::Handler {
        Slot::new_with_ctx(slot, ctx, address)
    }
}

impl Storable for PolicyMode {
    fn load<S: StorageOps>(storage: &S, slot: U256, ctx: LayoutCtx) -> Result<Self> {
        Self::try_from(u8::load(storage, slot, ctx)?)
            .map_err(|_| TIP403RegistryError::invalid_policy_mode().into())
    }

    fn store<S: StorageOps>(&self, storage: &mut S, slot: U256, ctx: LayoutCtx) -> Result<()> {
        if *self == Self::__Invalid {
            return Err(TIP403RegistryError::invalid_policy_mode().into());
        }
        (*self as u8).store(storage, slot, ctx)
    }
}

/// Returns whether `mode` allows an account, evaluating its list `member`ship only for list
/// modes.
fn allows(mode: PolicyMode, member: impl FnOnce() -> Result<bool>) -> Result<bool> {
    Ok(match mode {
        PolicyMode::ALLOW => true,
        PolicyMode::WHITELIST => member()?,
        PolicyMode::BLACKLIST => !member()?,
        PolicyMode::DENY | PolicyMode::__Invalid => false,
    })
}

/// Maps an ABI role to its issuer membership mask.
fn role_mask(role: Role) -> Result<u8> {
    Ok(match role {
        Role::SENDER => SENDER_FLAG,
        Role::RECIPIENT => RECIPIENT_FLAG,
        Role::MINT_RECIPIENT => MINT_RECIPIENT_FLAG,
        Role::TRANSFER => SENDER_FLAG | RECIPIENT_FLAG,
        Role::ALL => SENDER_FLAG | RECIPIENT_FLAG | MINT_RECIPIENT_FLAG,
        Role::__Invalid => return Err(TIP403RegistryError::invalid_auth_role().into()),
    })
}

impl AuthRole {
    /// Returns the issuer membership mask checked by this role.
    pub(crate) fn mask(self) -> u8 {
        match self {
            Self::Transfer => SENDER_FLAG | RECIPIENT_FLAG,
            Self::Sender => SENDER_FLAG,
            Self::Recipient => RECIPIENT_FLAG,
            Self::MintRecipient => MINT_RECIPIENT_FLAG,
        }
    }
}

impl TokenPolicy {
    /// Active policy with all three roles in `ALLOW` mode (the creation default).
    pub const ALLOW_ALL: Self = Self {
        is_set: true,
        sender: PolicyMode::ALLOW,
        recipient: PolicyMode::ALLOW,
        mint_recipient: PolicyMode::ALLOW,
    };

    /// Packs the modes into the TIP-20 control byte: two bits per role, sender lowest.
    pub(crate) fn modes_byte(&self) -> u8 {
        self.sender as u8 | (self.recipient as u8) << 2 | (self.mint_recipient as u8) << 4
    }

    /// Unpacks an active policy from the TIP-20 control byte. Returns `None` when the unused
    /// high bits are set.
    pub(crate) fn from_modes_byte(byte: u8) -> Option<Self> {
        let mode = |i: u8| PolicyMode::try_from((byte >> (2 * i)) & 0b11).expect("two-bit mode");
        (byte >> 6 == 0).then(|| Self {
            is_set: true,
            sender: mode(0),
            recipient: mode(1),
            mint_recipient: mode(2),
        })
    }
}

/// Validates a token argument's TIP-20 prefix.
fn ensure_tip20_prefix(token: Address) -> Result<()> {
    if !token.is_tip20() {
        return Err(TIP403RegistryError::invalid_token().into());
    }
    Ok(())
}

/// Rejects virtual addresses as list members or receive-setter callers.
fn ensure_not_virtual(account: Address) -> Result<()> {
    if account.is_virtual() {
        return Err(TIP403RegistryError::virtual_address_not_allowed().into());
    }
    Ok(())
}

/// Rejects virtual and `ReceivePolicyGuard` receive-setter callers.
fn ensure_receive_owner(msg_sender: Address) -> Result<()> {
    ensure_not_virtual(msg_sender)?;
    if msg_sender == RECEIVE_POLICY_GUARD_ADDRESS {
        return Err(TIP403RegistryError::address_reserved().into());
    }
    Ok(())
}

impl ReceiveConfig {
    /// Returns the public recovery authority: zero for originator recovery, the receiver for
    /// receiver recovery, or the third party.
    pub(super) fn recovery_authority(&self, receiver: Address) -> Address {
        match self.recovery_mode {
            RecoveryMode::Originator => Address::ZERO,
            RecoveryMode::Receiver => receiver,
            RecoveryMode::ThirdParty => self.third_party_recovery_authority,
        }
    }
}

impl TIP403Registry {
    // ----- token-specific issuer policies -----------------------------------------------------

    /// Returns the stored policy of `token`, including prepared (inactive) modes.
    ///
    /// # Errors
    /// - `InvalidToken` — `token` lacks the TIP-20 prefix
    pub fn token_policy(&self, token: Address) -> Result<TokenPolicy> {
        ensure_tip20_prefix(token)?;
        self.token_policies[token].read()
    }

    /// Activates the prepared policy of an existing token, returning it. Clears the obsolete
    /// generic binding, so registry mirrors resolve the token-specific policy.
    pub(crate) fn activate_token_policy(&mut self, token: Address) -> Result<TokenPolicy> {
        self.token_transfer_policies[token].delete()?;
        let policy = TokenPolicy {
            is_set: true,
            ..self.token_policy(token)?
        };
        self.write_token_policy(token, policy)?;
        Ok(policy)
    }

    /// Writes `policy` for `token` and emits `TransferPolicyUpdated`.
    pub(crate) fn write_token_policy(&mut self, token: Address, policy: TokenPolicy) -> Result<()> {
        self.token_policies[token].write(policy)?;
        self.emit_event(ITIP403Registry::TransferPolicyUpdated {
            token,
            senderMode: policy.sender,
            recipientMode: policy.recipient,
            mintRecipientMode: policy.mint_recipient,
        })
    }

    /// Returns the membership flags of `account` for `token`. Supports future (undeployed) tokens.
    ///
    /// # Errors
    /// - `InvalidToken` — `token` lacks the TIP-20 prefix
    /// - `InvalidPolicyMode` — the stored word has undefined bits
    pub fn token_user_flags(&self, token: Address, account: Address) -> Result<u8> {
        ensure_tip20_prefix(token)?;
        let flags = self.token_user_flags[token][account].read()?;
        if flags & !(SENDER_FLAG | RECIPIENT_FLAG | MINT_RECIPIENT_FLAG | RECEIVE_TOKEN_FLAG) != 0 {
            return Err(TIP403RegistryError::invalid_policy_mode().into());
        }
        Ok(flags)
    }

    /// Returns whether `policy` allows `account` in every issuer role in `mask`, checking sender,
    /// recipient, then mint recipient and stopping at the first rejection. Flags are read at most
    /// once, and only for list modes.
    pub(crate) fn token_policy_allows(
        &self,
        token: Address,
        policy: &TokenPolicy,
        account: Address,
        mask: u8,
    ) -> Result<bool> {
        if self.is_always_authorized(account) {
            return Ok(true);
        }

        let mut flags = None;
        for (flag, mode) in [
            (SENDER_FLAG, policy.sender),
            (RECIPIENT_FLAG, policy.recipient),
            (MINT_RECIPIENT_FLAG, policy.mint_recipient),
        ] {
            if mask & flag == 0 {
                continue;
            }
            let member = || {
                let flags = match flags {
                    Some(flags) => flags,
                    None => *flags.insert(self.token_user_flags(token, account)?),
                };
                Ok(flags & flag != 0)
            };
            if !allows(mode, member)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Returns whether `account` passes every rule selected by `role` under the registered
    /// token-specific policy.
    ///
    /// # Errors
    /// - `InvalidToken` — `token` lacks the TIP-20 prefix or has no registered policy
    /// - `InvalidAuthRole` — `role` is not a valid encoding
    pub fn is_token_authorized(
        &self,
        token: Address,
        account: Address,
        role: Role,
    ) -> Result<bool> {
        let policy = self.token_policy(token)?;
        let mask = role_mask(role)?;
        if !policy.is_set {
            return Err(TIP403RegistryError::invalid_token().into());
        }
        self.token_policy_allows(token, &policy, account, mask)
    }

    /// Validates the token and the caller's `DEFAULT_ADMIN_ROLE` for issuer setters.
    fn ensure_token_admin(&self, msg_sender: Address, token: Address) -> Result<TIP20Token> {
        if !TIP20Factory::new().is_tip20(token)? {
            return Err(TIP403RegistryError::invalid_token().into());
        }
        let tip20 = TIP20Token::from_address(token)?;
        if !tip20.has_role_internal(msg_sender, DEFAULT_ADMIN_ROLE)? {
            return Err(TIP403RegistryError::unauthorized().into());
        }
        Ok(tip20)
    }

    /// Sets the issuer modes, preserving lists and activation state, and synchronizes the
    /// packed TIP-20 cache of converted tokens. Emits `TransferPolicyUpdated`, even for no-ops.
    ///
    /// # Errors
    /// - `InvalidToken` — `token` lacks the TIP-20 prefix or is not deployed
    /// - `Unauthorized` — caller lacks the token's `DEFAULT_ADMIN_ROLE`
    /// - `InvalidPolicyMode` — a mode is not a valid encoding
    pub fn set_token_policy_modes(
        &mut self,
        msg_sender: Address,
        call: ITIP403Registry::setTokenPolicyModesCall,
    ) -> Result<()> {
        let mut tip20 = self.ensure_token_admin(msg_sender, call.token)?;
        let policy = TokenPolicy {
            is_set: self.token_policy(call.token)?.is_set,
            sender: call.senderMode,
            recipient: call.recipientMode,
            mint_recipient: call.mintRecipientMode,
        };
        self.write_token_policy(call.token, policy)?;
        tip20.set_policy_modes(&policy)
    }

    /// Adds or removes issuer list members for every role selected by `role`.
    ///
    /// # Errors
    /// - `InvalidToken` — `token` lacks the TIP-20 prefix or is not deployed
    /// - `Unauthorized` — caller lacks the token's `DEFAULT_ADMIN_ROLE`
    /// - `InvalidAuthRole` — `role` is not a valid encoding
    /// - `VirtualAddressNotAllowed` — a member is a virtual address
    pub fn modify_token_members(
        &mut self,
        msg_sender: Address,
        token: Address,
        accounts: &[Address],
        role: Role,
        is_member: bool,
    ) -> Result<()> {
        self.ensure_token_admin(msg_sender, token)?;
        let mask = role_mask(role)?;
        for &account in accounts {
            ensure_not_virtual(account)?;
            self.set_token_user_flags(token, account, mask, is_member)?;
            self.emit_event(ITIP403Registry::PolicyMembershipUpdated {
                kind: MembershipKind::ISSUER,
                owner: token,
                account,
                role,
                isMember: is_member,
            })?;
        }
        Ok(())
    }

    /// Sets or clears `mask` in `tokenUserFlags[token][account]`, preserving unrelated bits.
    fn set_token_user_flags(
        &mut self,
        token: Address,
        account: Address,
        mask: u8,
        set: bool,
    ) -> Result<()> {
        let flags = self.token_user_flags(token, account)?;
        let flags = if set { flags | mask } else { flags & !mask };
        self.token_user_flags[token][account].write(flags)
    }

    // ----- receive configurations -------------------------------------------------------------

    /// Returns the active receive configuration of `receiver`, or `None` if not opted in.
    pub(crate) fn receive_config(&self, receiver: Address) -> Result<Option<ReceiveConfig>> {
        Ok(match self.receive_policies[receiver].config.read()? {
            ReceivePolicyConfig::Config(config) => Some(config),
            ReceivePolicyConfig::Legacy(_) => None,
        })
    }

    /// Encodes a public recovery authority, rejecting virtual and precompile addresses.
    pub(super) fn encode_recovery_authority(
        &self,
        authority: Address,
        receiver: Address,
    ) -> Result<(RecoveryMode, Address)> {
        if authority.is_precompile(self.storage.spec()) || authority.is_virtual() {
            return Err(TIP403RegistryError::invalid_recovery_authority().into());
        }
        Ok(RecoveryMode::encode(authority, receiver))
    }

    /// Activates and updates the caller's receive configuration. Opting in is permanent.
    ///
    /// # Errors
    /// - `VirtualAddressNotAllowed` — caller is a virtual address
    /// - `AddressReserved` — caller is the `ReceivePolicyGuard`
    /// - `InvalidPolicyMode` — a mode is not a valid encoding
    /// - `InvalidRecoveryAuthority` — authority is virtual or a protocol precompile
    pub fn set_receive_config(
        &mut self,
        msg_sender: Address,
        call: ITIP403Registry::setReceiveConfigCall,
    ) -> Result<()> {
        ensure_receive_owner(msg_sender)?;
        let (recovery_mode, third_party_recovery_authority) =
            self.encode_recovery_authority(call.recoveryAuthority, msg_sender)?;
        self.receive_policies[msg_sender]
            .config
            .write(ReceivePolicyConfig::Config(ReceiveConfig {
                kind: RECEIVE_CONFIG_KIND,
                token_mode: call.tokenMode,
                sender_mode: call.senderMode,
                recovery_mode,
                third_party_recovery_authority,
            }))?;

        self.emit_event(ITIP403Registry::ReceivePolicyUpdated_1 {
            receiver: msg_sender,
            tokenMode: call.tokenMode,
            senderMode: call.senderMode,
            recoveryAuthority: call.recoveryAuthority,
        })
    }

    /// Adds or removes accounts from the caller's receive-token (`RECEIVE_TOKEN`) or
    /// receive-sender (`RECEIVE_SENDER`) list. Token lists support future tokens.
    ///
    /// # Errors
    /// - `VirtualAddressNotAllowed` — caller or a listed sender is a virtual address
    /// - `AddressReserved` — caller is the `ReceivePolicyGuard`
    /// - `InvalidToken` — a listed token lacks the TIP-20 prefix
    pub fn modify_receive_members(
        &mut self,
        msg_sender: Address,
        kind: MembershipKind,
        accounts: &[Address],
        is_member: bool,
    ) -> Result<()> {
        debug_assert_ne!(kind, MembershipKind::ISSUER);
        ensure_receive_owner(msg_sender)?;
        for &account in accounts {
            if kind == MembershipKind::RECEIVE_TOKEN {
                ensure_tip20_prefix(account)?;
                self.set_token_user_flags(account, msg_sender, RECEIVE_TOKEN_FLAG, is_member)?;
            } else {
                ensure_not_virtual(account)?;
                self.receive_sender_members[msg_sender][account].write(is_member)?;
            }
            self.emit_event(ITIP403Registry::PolicyMembershipUpdated {
                kind,
                owner: msg_sender,
                account,
                role: Role::SENDER,
                isMember: is_member,
            })?;
        }
        Ok(())
    }

    /// Evaluates an active receive configuration. Token rejection has priority; constant modes
    /// skip membership reads.
    pub(super) fn check_receive_config(
        &self,
        config: &ReceiveConfig,
        token: Address,
        sender: Address,
        receiver: Address,
    ) -> Result<Option<(BlockedReason, Address)>> {
        let token_member = || Ok(self.token_user_flags(token, receiver)? & RECEIVE_TOKEN_FLAG != 0);
        let sender_member = || self.receive_sender_members[receiver][sender].read();
        let reason = if !allows(config.token_mode, token_member)? {
            BlockedReason::TOKEN_FILTER
        } else if !allows(config.sender_mode, sender_member)? {
            BlockedReason::RECEIVE_POLICY
        } else {
            return Ok(None);
        };
        Ok(Some((reason, config.recovery_authority(receiver))))
    }
}
