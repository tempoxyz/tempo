//! [TIP-1145] packed TIP-20 control and supply storage.
//!
//! Converted ("packed") tokens store pause, layout, cached issuer modes, quote IDs, and short
//! currencies in the slot-12 control word, and total supply with the cap in slot 8. Legacy tokens
//! keep the original layout, whose slot-12 word is exactly `0`/`1`. Every accessor decodes the
//! actual layout and never converts implicitly.
//!
//! [TIP-1145]: <https://docs.tempo.xyz/protocol/tips/tip-1145>

use super::{TIP20Error, TIP20Token, U128_MAX, USD_CURRENCY, slots};
use crate::{
    PATH_USD_ADDRESS,
    error::{Result, TempoPrecompileError},
    storage::{Handler, Slot},
    tip20_factory::TIP20Factory,
    tip403_registry::{TIP403Registry, TokenPolicy},
};
use alloy::primitives::{Address, FixedBytes, U256};
use tempo_precompiles_macros::Storable;
use tempo_primitives::TempoAddressExt;

/// Control flag: transfers are paused (also the legacy `paused == true` word).
const PAUSED_FLAG: u8 = 0b01;
/// Control flag: the token uses the packed layout.
const PACKED_FLAG: u8 = 0b10;

/// Slot-12 control word. The legacy `bool paused` word decodes as `flags` 0 or 1 with every other
/// field zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Storable)]
pub struct TokenControl {
    flags: u8,
    /// Cache of the token's canonical TIP-403 issuer modes (two bits per role).
    modes: u8,
    /// Active quote token suffix (zero is pathUSD).
    quote_id: u64,
    /// Staged quote token suffix (zero is pathUSD).
    next_quote_id: u64,
    /// Inline currency, right-padded with zeros. All zero when the currency is external.
    currency: FixedBytes<14>,
}

impl TokenControl {
    /// Builds a packed control word. The currency is stored inline if it is nonempty,
    /// NUL-free, and fits 14 bytes; otherwise the inline field stays zero and the currency is
    /// external.
    fn new(policy: &TokenPolicy, quote_id: u64, next_quote_id: u64, currency: &str) -> Self {
        let bytes = currency.as_bytes();
        let inline = (1..=14).contains(&bytes.len()) && !bytes.contains(&0);
        Self {
            flags: PACKED_FLAG,
            modes: policy.modes_byte(),
            quote_id,
            next_quote_id,
            currency: if inline {
                FixedBytes::right_padding_from(bytes)
            } else {
                FixedBytes::ZERO
            },
        }
    }

    /// Rejects malformed words: unknown flags, nonzero legacy fields, invalid modes, non-canonical
    /// inline currencies, and quotes on pathUSD.
    fn validate(self, token: Address) -> Result<Self> {
        let valid = match self.flags & !PAUSED_FLAG {
            0 => Self { flags: 0, ..self } == Self::default(),
            PACKED_FLAG => {
                TokenPolicy::from_modes_byte(self.modes).is_some()
                    && (self.currency.is_zero() || self.inline_currency().is_some())
                    && (token != PATH_USD_ADDRESS || (self.quote_id | self.next_quote_id) == 0)
            }
            _ => false,
        };
        valid.then_some(self).ok_or_else(|| {
            TempoPrecompileError::Fatal(format!("invalid TIP-1145 control word for token {token}"))
        })
    }

    pub(crate) fn is_packed(&self) -> bool {
        self.flags & PACKED_FLAG != 0
    }

    pub(crate) fn is_paused(&self) -> bool {
        self.flags & PAUSED_FLAG != 0
    }

    fn with_paused(self, paused: bool) -> Self {
        let flags = if paused {
            self.flags | PAUSED_FLAG
        } else {
            self.flags & !PAUSED_FLAG
        };
        Self { flags, ..self }
    }

    /// Returns the cached issuer policy of a packed token.
    pub(crate) fn policy(&self) -> Option<TokenPolicy> {
        TokenPolicy::from_modes_byte(self.modes).filter(|_| self.is_packed())
    }

    /// Decodes a nonzero inline currency, returning `None` for non-canonical encodings.
    pub fn inline_currency(&self) -> Option<&str> {
        let currency = core::str::from_utf8(&self.currency[..])
            .ok()?
            .trim_end_matches('\0');
        (!currency.is_empty() && !currency.contains('\0')).then_some(currency)
    }
}

/// Packed slot-8 word: total supply (low 128 bits) and supply cap (high 128 bits).
#[derive(Debug, Clone, Copy, Default, Storable)]
struct PackedSupply {
    total_supply: u128,
    supply_cap: u128,
}

/// Decoded supply state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Supply {
    pub(crate) total: U256,
    /// Packed supply cap; `None` for the legacy layout, which stores it in slot 13.
    pub(crate) cap: Option<U256>,
}

impl TIP20Token {
    fn control_slot(&self) -> Slot<TokenControl> {
        Slot::new(slots::PAUSED, self.address)
    }

    fn supply_slot(&self) -> Slot<PackedSupply> {
        Slot::new(slots::TOTAL_SUPPLY, self.address)
    }

    /// Loads the control word. Pre-T14 this is exactly the legacy `paused` read.
    pub(crate) fn get_token_control(&self) -> Result<TokenControl> {
        if !self.storage.spec().is_t14() {
            return Ok(TokenControl::default().with_paused(self.paused.read()?));
        }
        self.control_slot().read()?.validate(self.address)
    }

    /// Probes the layout, returning the control word of packed tokens. Pre-T14 every token is
    /// legacy, so no storage is read.
    pub fn token_control(&self) -> Result<Option<TokenControl>> {
        if !self.storage.spec().is_t14() {
            return Ok(None);
        }
        Ok(Some(self.get_token_control()?).filter(TokenControl::is_packed))
    }

    /// Writes the pause state, preserving the packed fields.
    pub(crate) fn set_paused(&mut self, paused: bool) -> Result<()> {
        match self.token_control()? {
            Some(control) => self.control_slot().write(control.with_paused(paused)),
            None => self.paused.write(paused),
        }
    }

    /// Synchronizes the cached issuer modes of packed tokens. Legacy tokens and unchanged modes
    /// receive no write.
    pub(crate) fn set_policy_modes(&mut self, policy: &TokenPolicy) -> Result<()> {
        let modes = policy.modes_byte();
        match self.token_control()? {
            Some(control) if control.modes != modes => {
                self.control_slot().write(TokenControl { modes, ..control })
            }
            _ => Ok(()),
        }
    }

    // ----- supply -----------------------------------------------------------------------------

    /// Loads the total supply in the token's layout.
    pub(crate) fn get_supply(&self) -> Result<Supply> {
        Ok(if self.token_control()?.is_some() {
            let supply = self.supply_slot().read()?;
            Supply {
                total: U256::from(supply.total_supply),
                cap: Some(U256::from(supply.supply_cap)),
            }
        } else {
            Supply {
                total: self.total_supply.read()?,
                cap: None,
            }
        })
    }

    /// Returns the supply cap, reading the legacy slot when not already loaded.
    pub(crate) fn supply_cap_of(&self, supply: &Supply) -> Result<U256> {
        supply.cap.map_or_else(|| self.supply_cap.read(), Ok)
    }

    /// Writes supply in its layout: packed tokens store total and cap (both ≤ `u128::MAX`)
    /// together, legacy tokens only the total, as their cap has its own slot.
    pub(crate) fn set_supply(&mut self, supply: Supply) -> Result<()> {
        match supply.cap {
            Some(cap) => self.supply_slot().write(PackedSupply {
                total_supply: supply.total.to(),
                supply_cap: cap.to(),
            }),
            None => self.total_supply.write(supply.total),
        }
    }

    /// Overwrites the total supply in either layout (test helper).
    #[cfg(test)]
    pub(crate) fn set_total_supply(&mut self, total: U256) -> Result<()> {
        let supply = self.get_supply()?;
        self.set_supply(Supply { total, ..supply })
    }

    // ----- quote tokens -----------------------------------------------------------------------

    /// Returns the active (`staged == false`) or staged quote token.
    pub(crate) fn get_quote(&self, staged: bool) -> Result<Address> {
        Ok(match self.token_control()? {
            // pathUSD itself has no quote token.
            Some(_) if self.address == PATH_USD_ADDRESS => Address::ZERO,
            Some(control) if staged => Address::new_tip20(control.next_quote_id),
            Some(control) => Address::new_tip20(control.quote_id),
            None if staged => self.next_quote_token.read()?,
            None => self.quote_token.read()?,
        })
    }

    /// Writes the active (`staged == false`) or staged quote token, a deployed TIP-20.
    pub(crate) fn set_quote(&mut self, staged: bool, quote: Address) -> Result<()> {
        match self.token_control()? {
            Some(mut control) => {
                *if staged {
                    &mut control.next_quote_id
                } else {
                    &mut control.quote_id
                } = quote.tip20_id().expect("quote tokens are TIP-20s");
                self.control_slot().write(control)
            }
            None if staged => self.next_quote_token.write(quote),
            None => self.quote_token.write(quote),
        }
    }

    // ----- currency ---------------------------------------------------------------------------

    /// Returns whether the currency is [`USD_CURRENCY`]. Packed tokens skip the external read,
    /// since `"USD"` always fits inline.
    pub fn is_usd(&self) -> Result<bool> {
        match self.token_control()? {
            Some(control) => Ok(control.inline_currency() == Some(USD_CURRENCY)),
            None => Ok(self.currency.read()? == USD_CURRENCY),
        }
    }

    // ----- initialization and conversion ------------------------------------------------------

    /// Returns the packed quote ID for `quote`, or `None` if it cannot be represented (a
    /// non-pathUSD token with a null quote) or is not a deployed TIP-20.
    fn packable_quote_id(&self, quote: Address) -> Result<Option<u64>> {
        if self.address == PATH_USD_ADDRESS {
            return Ok(quote.is_zero().then_some(0));
        }
        if quote.is_zero() || !TIP20Factory::new().is_tip20(quote)? {
            return Ok(None);
        }
        Ok(quote.tip20_id())
    }

    /// Initializes packed metadata, supply, and an `ALLOW` token-specific policy for a new
    /// token. Returns `false`, writing nothing, when `quote_token` cannot be packed.
    pub(crate) fn try_initialize_packed(
        &mut self,
        currency: &str,
        quote_token: Address,
    ) -> Result<bool> {
        let Some(quote_id) = self.packable_quote_id(quote_token)? else {
            return Ok(false);
        };

        let policy = TokenPolicy::ALLOW_ALL;
        let control = TokenControl::new(&policy, quote_id, quote_id, currency);
        if control.currency.is_zero() {
            self.currency.write(currency.to_string())?;
        }
        self.set_supply(Supply {
            total: U256::ZERO,
            cap: Some(U128_MAX),
        })?;
        self.control_slot().write(control)?;
        TIP403Registry::new().write_token_policy(self.address, policy)?;
        Ok(true)
    }

    /// Converts a legacy token to the packed layout when it activates its token-specific policy.
    ///
    /// Reads every source field first, then clears obsolete words and writes supply before the
    /// control word, skipping unchanged writes. Logical values are preserved exactly.
    ///
    /// # Errors
    /// - `InvalidQuoteToken` — a quote is null (non-pathUSD) or undeployed
    /// - `SupplyCapExceeded` — supply or cap exceeds 128 bits
    pub(crate) fn convert_to_packed(&mut self, paused: bool, policy: &TokenPolicy) -> Result<()> {
        let currency = self.currency.read()?;
        let quote_id = self
            .packable_quote_id(self.quote_token.read()?)?
            .ok_or_else(TIP20Error::invalid_quote_token)?;
        let next_quote_id = self
            .packable_quote_id(self.next_quote_token.read()?)?
            .ok_or_else(TIP20Error::invalid_quote_token)?;
        let total = self.total_supply.read()?;
        let cap = self.supply_cap.read()?;
        if total > U128_MAX || cap > U128_MAX {
            return Err(TIP20Error::supply_cap_exceeded().into());
        }

        let control =
            TokenControl::new(policy, quote_id, next_quote_id, &currency).with_paused(paused);
        if !control.currency.is_zero() {
            self.clear_word(slots::CURRENCY)?;
        }
        for slot in [
            slots::QUOTE_TOKEN,
            slots::NEXT_QUOTE_TOKEN,
            slots::SUPPLY_CAP,
        ] {
            self.clear_word(slot)?;
        }
        // A zero cap leaves the legacy supply word unchanged.
        if !cap.is_zero() {
            self.set_supply(Supply {
                total,
                cap: Some(cap),
            })?;
        }
        self.control_slot().write(control)
    }

    /// Zeroes an obsolete legacy word, skipping the write when already zero.
    fn clear_word(&mut self, slot: U256) -> Result<()> {
        let mut word = Slot::<U256>::new(slot, self.address);
        if !word.read()?.is_zero() {
            word.write(U256::ZERO)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! TIP-1145 policy, cache, and storage-conversion tests.

    use super::*;
    use crate::{
        Precompile, RECEIVE_POLICY_GUARD_ADDRESS, TIP403_REGISTRY_ADDRESS,
        storage::{StorageCtx, StorageKey, hashmap::HashMapStorageProvider},
        test_util::TIP20Setup,
        tip20::{ISSUER_ROLE, ITIP20},
        tip403_registry::{
            AuthRole, ITIP403Registry, MINT_RECIPIENT_FLAG, RECEIVE_CONFIG_KIND,
            RECEIVE_TOKEN_FLAG, RECIPIENT_FLAG, REJECT_ALL_POLICY_ID, SENDER_FLAG,
            TIP403RegistryError, TOKEN_POLICY_ID, tip403_registry_slots,
        },
    };
    use alloy::{
        primitives::B256,
        sol_types::{SolCall, SolEvent},
    };
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::ITIP403Registry::{
        AuthRole as Role, MembershipKind,
        PolicyMode::{self, ALLOW, BLACKLIST, DENY, WHITELIST},
    };
    use tempo_primitives::{MasterId, UserTag};

    fn roundtrip(control: TokenControl) -> U256 {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
        let address = Address::new_tip20(0x20);
        StorageCtx::enter(&mut storage, || {
            let mut slot = Slot::<TokenControl>::new(slots::PAUSED, address);
            slot.write(control).unwrap();
            assert_eq!(slot.read().unwrap(), control);
            let token = TIP20Token::from_address(address).unwrap();
            let decoded = control.validate(address);
            assert_eq!(token.get_token_control(), decoded);
            StorageCtx.sload(address, slots::PAUSED).unwrap()
        })
    }

    #[test]
    fn control_word_layout_and_legacy_compat() {
        let token = Address::repeat_byte(0x20);
        let fatal = |token| {
            Err(TempoPrecompileError::Fatal(format!(
                "invalid TIP-1145 control word for token {token}"
            )))
        };
        for paused in [false, true] {
            let legacy = TokenControl::default().with_paused(paused);
            assert_eq!(roundtrip(legacy), U256::from(u8::from(paused)));
            assert!(!legacy.validate(token).unwrap().is_packed());
        }

        let control = TokenControl::new(&TokenPolicy::ALLOW_ALL, 1, 2, "USD").with_paused(true);
        let word = roundtrip(control);
        assert_eq!(
            word & U256::from(0xff),
            U256::from(PAUSED_FLAG | PACKED_FLAG)
        );
        assert_eq!((word >> 16) & U256::from(u64::MAX), U256::ONE);
        assert_eq!((word >> 80) & U256::from(u64::MAX), U256::from(2));
        assert_eq!(word >> 248, U256::from(b'U'));
        assert!(control.validate(token).unwrap().is_paused());

        // Legacy words other than 0/1, unknown flags, and high mode bits are malformed.
        for malformed in [
            TokenControl {
                flags: PAUSED_FLAG,
                quote_id: 1,
                ..Default::default()
            },
            TokenControl {
                flags: 4,
                ..Default::default()
            },
            TokenControl {
                modes: 0xC0,
                ..control
            },
            TokenControl {
                currency: FixedBytes::right_padding_from(b"A\0B"),
                ..control
            },
        ] {
            assert_eq!(malformed.validate(token), fatal(token));
            roundtrip(malformed);
        }
        assert_eq!(control.validate(PATH_USD_ADDRESS), fatal(PATH_USD_ADDRESS));
    }

    #[test]
    fn inline_currency_rules() {
        let inline = |currency| TokenControl::new(&TokenPolicy::ALLOW_ALL, 0, 0, currency);
        assert_eq!(inline("USD").inline_currency(), Some(USD_CURRENCY));
        for external in ["", "A\0B", "FIFTEEN_BYTES__"] {
            assert!(inline(external).currency.is_zero());
        }
        for currency in ["FOURTEENBYTES!", "€"] {
            assert_eq!(inline(currency).inline_currency(), Some(currency));
        }
        let invalid_utf8 = TokenControl {
            currency: FixedBytes::right_padding_from(&[0xff]),
            ..inline("")
        };
        assert!(invalid_utf8.inline_currency().is_none());
    }

    fn set_modes(
        admin: Address,
        token: Address,
        sender: PolicyMode,
        recipient: PolicyMode,
        mint_recipient: PolicyMode,
    ) -> Result<()> {
        TIP403Registry::new().set_token_policy_modes(
            admin,
            ITIP403Registry::setTokenPolicyModesCall {
                token,
                senderMode: sender,
                recipientMode: recipient,
                mintRecipientMode: mint_recipient,
            },
        )
    }

    fn add_members(admin: Address, token: Address, accounts: &[Address], role: Role) -> Result<()> {
        TIP403Registry::new().modify_token_members(admin, token, accounts, role, true)
    }

    fn transfer(token: &mut TIP20Token, from: Address, to: Address, amount: u64) -> Result<bool> {
        token.transfer(
            from,
            ITIP20::transferCall {
                to,
                amount: U256::from(amount),
            },
        )
    }

    fn mint(token: &mut TIP20Token, issuer: Address, to: Address, amount: u64) -> Result<()> {
        token.mint(
            issuer,
            ITIP20::mintCall {
                to,
                amount: U256::from(amount),
            },
        )
    }

    /// Reads `receiveConfig` through ABI dispatch.
    fn receive_config(receiver: Address) -> ITIP403Registry::receiveConfigReturn {
        let call = ITIP403Registry::receiveConfigCall { receiver }.abi_encode();
        let output = TIP403Registry::new().call(&call, Address::ZERO).unwrap();
        ITIP403Registry::receiveConfigCall::abi_decode_returns(&output.bytes).unwrap()
    }

    #[test]
    fn issuer_modes_and_memberships() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
        let admin = Address::random();
        let (alice, bob, carol) = (Address::random(), Address::random(), Address::random());

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(alice, U256::from(1_000))
                .apply()?;
            let address = token.address;
            let mut registry = TIP403Registry::new();

            assert_eq!(
                set_modes(alice, address, DENY, ALLOW, ALLOW),
                Err(TIP403RegistryError::unauthorized().into())
            );
            assert_eq!(
                add_members(alice, address, &[], Role::SENDER),
                Err(TIP403RegistryError::unauthorized().into())
            );

            set_modes(admin, address, BLACKLIST, WHITELIST, ALLOW)?;
            assert_eq!(
                transfer(&mut token, alice, bob, 10),
                Err(TIP20Error::policy_forbids().into()),
                "bob is not whitelisted"
            );
            add_members(admin, address, &[bob], Role::RECIPIENT)?;
            assert!(transfer(&mut token, alice, bob, 10)?);
            add_members(admin, address, &[alice], Role::SENDER)?;
            assert_eq!(
                transfer(&mut token, alice, bob, 10),
                Err(TIP20Error::policy_forbids().into())
            );
            registry.modify_token_members(admin, address, &[alice], Role::SENDER, false)?;
            assert!(transfer(&mut token, alice, bob, 10)?);

            // `ALL` edits all three lists without touching the receive-token bit.
            registry.modify_receive_members(
                carol,
                MembershipKind::RECEIVE_TOKEN,
                &[address],
                true,
            )?;
            add_members(admin, address, &[carol], Role::ALL)?;
            assert_eq!(
                registry.token_user_flags(address, carol)?,
                SENDER_FLAG | RECIPIENT_FLAG | MINT_RECIPIENT_FLAG | RECEIVE_TOKEN_FLAG
            );
            registry.modify_token_members(admin, address, &[carol], Role::TRANSFER, false)?;
            assert_eq!(
                registry.token_user_flags(address, carol)?,
                MINT_RECIPIENT_FLAG | RECEIVE_TOKEN_FLAG
            );

            // Mint-recipient rules are independent.
            set_modes(admin, address, ALLOW, ALLOW, WHITELIST)?;
            assert_eq!(
                mint(&mut token, admin, bob, 1),
                Err(TIP20Error::policy_forbids().into())
            );
            mint(&mut token, admin, carol, 1)?;
            set_modes(admin, address, ALLOW, ALLOW, DENY)?;
            assert_eq!(
                mint(&mut token, admin, carol, 1),
                Err(TIP20Error::policy_forbids().into())
            );
            assert!(registry.is_token_authorized(address, carol, Role::TRANSFER)?);
            assert!(!registry.is_token_authorized(address, carol, Role::ALL)?);

            let virtual_addr = Address::new_virtual(MasterId::ZERO, UserTag::ZERO);
            assert_eq!(
                add_members(admin, address, &[virtual_addr], Role::SENDER),
                Err(TIP403RegistryError::virtual_address_not_allowed().into())
            );
            assert_eq!(
                add_members(admin, Address::random(), &[bob], Role::SENDER),
                Err(TIP403RegistryError::invalid_token().into())
            );
            let undeployed = Address::new_tip20(u64::from_be_bytes([9; 8]));
            assert_eq!(
                set_modes(admin, undeployed, ALLOW, ALLOW, ALLOW),
                Err(TIP403RegistryError::invalid_token().into())
            );
            assert_eq!(
                registry.is_token_authorized(undeployed, bob, Role::SENDER),
                Err(TIP403RegistryError::invalid_token().into()),
                "unregistered tokens are rejected"
            );

            let before = token.get_token_control()?;
            registry.clear_emitted_events();
            set_modes(admin, address, DENY, BLACKLIST, WHITELIST)?;
            assert_eq!(
                token.get_token_control()?,
                TokenControl {
                    modes: registry.token_policy(address)?.modes_byte(),
                    ..before
                }
            );

            // No-op updates still emit, and batches emit per entry including duplicates.
            set_modes(admin, address, DENY, BLACKLIST, WHITELIST)?;
            add_members(admin, address, &[alice, bob, alice], Role::TRANSFER)?;
            add_members(admin, address, &[], Role::SENDER)?;

            let modes_event = ITIP403Registry::TransferPolicyUpdated {
                token: address,
                senderMode: DENY,
                recipientMode: BLACKLIST,
                mintRecipientMode: WHITELIST,
            }
            .encode_log_data();
            let member = |account| {
                ITIP403Registry::PolicyMembershipUpdated {
                    kind: MembershipKind::ISSUER,
                    owner: address,
                    account,
                    role: Role::TRANSFER,
                    isMember: true,
                }
                .encode_log_data()
            };
            assert_eq!(
                registry.emitted_events().as_slice(),
                &[
                    modes_event.clone(),
                    modes_event,
                    member(alice),
                    member(bob),
                    member(alice)
                ]
            );

            set_modes(admin, address, DENY, DENY, DENY)?;
            assert!(token.is_authorized_as(RECEIVE_POLICY_GUARD_ADDRESS, AuthRole::Transfer)?);
            assert!(!token.is_authorized_as(admin, AuthRole::Sender)?);
            Ok(())
        })
    }

    #[test]
    fn receive_configs_filter_tokens_then_senders() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
        let admin = Address::random();
        let (sender, receiver, recovery) =
            (Address::random(), Address::random(), Address::random());

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(sender, U256::from(1_000))
                .apply()?;
            let address = token.address;
            let mut registry = TIP403Registry::new();

            assert_eq!(
                receive_config(receiver),
                ITIP403Registry::receiveConfigReturn {
                    hasReceivePolicy: false,
                    tokenMode: ALLOW,
                    senderMode: ALLOW,
                    recoveryAuthority: Address::ZERO,
                }
            );
            registry.set_receive_config(
                receiver,
                ITIP403Registry::setReceiveConfigCall {
                    tokenMode: WHITELIST,
                    senderMode: BLACKLIST,
                    recoveryAuthority: recovery,
                },
            )?;
            assert_eq!(
                receive_config(receiver),
                ITIP403Registry::receiveConfigReturn {
                    hasReceivePolicy: true,
                    tokenMode: WHITELIST,
                    senderMode: BLACKLIST,
                    recoveryAuthority: recovery,
                }
            );
            // The config replaces the legacy word: kind, modes, recovery mode, then the authority.
            let word = StorageCtx.sload(
                TIP403_REGISTRY_ADDRESS,
                receiver.mapping_slot(tip403_registry_slots::RECEIVE_POLICIES),
            )?;
            assert_eq!(word.byte(0), RECEIVE_CONFIG_KIND);
            assert_eq!(word.byte(1), WHITELIST as u8);
            assert_eq!(word.byte(2), BLACKLIST as u8);
            assert_eq!(Address::from_word(B256::from(word >> 32)), recovery);

            assert_eq!(
                registry.receive_policy(receiver),
                Err(TIP403RegistryError::receive_policy_ids_unsupported().into())
            );
            assert_eq!(
                registry.set_receive_policy(
                    receiver,
                    ITIP403Registry::setReceivePolicyCall {
                        senderPolicyId: 1,
                        tokenFilterId: 1,
                        recoveryAuthority: Address::ZERO,
                    },
                ),
                Err(TIP403RegistryError::receive_policy_ids_unsupported().into())
            );
            assert!(transfer(&mut token, sender, receiver, 10)?);
            assert_eq!(token.get_balance(receiver)?, U256::ZERO);

            registry.modify_receive_members(
                receiver,
                MembershipKind::RECEIVE_TOKEN,
                &[address],
                true,
            )?;
            assert!(transfer(&mut token, sender, receiver, 10)?);
            assert_eq!(token.get_balance(receiver)?, U256::from(10));

            registry.modify_receive_members(
                receiver,
                MembershipKind::RECEIVE_SENDER,
                &[sender],
                true,
            )?;
            mint(&mut token, admin, receiver, 5)?;
            assert_eq!(
                token.get_balance(receiver)?,
                U256::from(15),
                "mints check msg.sender, which is not blacklisted"
            );
            assert!(transfer(&mut token, sender, receiver, 10)?);
            assert_eq!(token.get_balance(receiver)?, U256::from(15));

            assert_eq!(
                registry.modify_receive_members(
                    RECEIVE_POLICY_GUARD_ADDRESS,
                    MembershipKind::RECEIVE_TOKEN,
                    &[],
                    true
                ),
                Err(TIP403RegistryError::address_reserved().into())
            );
            assert_eq!(
                registry.modify_receive_members(
                    receiver,
                    MembershipKind::RECEIVE_TOKEN,
                    &[Address::random()],
                    true
                ),
                Err(TIP403RegistryError::invalid_token().into())
            );
            assert_eq!(
                registry.set_receive_config(
                    receiver,
                    ITIP403Registry::setReceiveConfigCall {
                        tokenMode: ALLOW,
                        senderMode: ALLOW,
                        recoveryAuthority: TIP403_REGISTRY_ADDRESS,
                    },
                ),
                Err(TIP403RegistryError::invalid_recovery_authority().into())
            );
            Ok(())
        })
    }

    /// Creates a legacy token before T14 with a generic blacklist, then switches to T14.
    fn legacy_token(admin: Address, blocked: Address) -> Result<(TIP20Token, u64)> {
        StorageCtx.set_spec(TempoHardfork::T13);
        let mut token = TIP20Setup::create("Legacy", "LGC", admin)
            .with_issuer(admin)
            .apply()?;
        let policy_id = TIP403Registry::new().create_policy_with_accounts(
            admin,
            ITIP403Registry::createPolicyWithAccountsCall {
                admin,
                policyType: ITIP403Registry::PolicyType::BLACKLIST,
                accounts: vec![blocked],
            },
        )?;
        token.change_transfer_policy_id(
            admin,
            ITIP20::changeTransferPolicyIdCall {
                newPolicyId: policy_id,
            },
        )?;
        StorageCtx.set_spec(TempoHardfork::T14);
        Ok((token, policy_id))
    }

    #[test]
    fn activation_converts_legacy_tokens() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
        let admin = Address::random();
        let (alice, blocked) = (Address::random(), Address::random());

        StorageCtx::enter(&mut storage, || {
            let (mut token, policy_id) = legacy_token(admin, blocked)?;
            let address = token.address;
            let mut registry = TIP403Registry::new();
            mint(&mut token, admin, alice, 1_000)?;
            assert_eq!(
                transfer(&mut token, alice, blocked, 1),
                Err(TIP20Error::policy_forbids().into())
            );

            // Preparing modes and memberships does not activate them.
            set_modes(admin, address, ALLOW, BLACKLIST, ALLOW)?;
            assert_eq!(StorageCtx.sload(address, slots::PAUSED)?, U256::ZERO);
            assert_eq!(token.transfer_policy_id()?, policy_id);
            assert_eq!(
                token.transfer_policy(),
                Err(TIP20Error::invalid_transfer_policy_id().into())
            );

            let before = (
                token.metadata()?,
                token.quote_token()?,
                token.next_quote_token()?,
                token.total_supply()?,
                token.supply_cap()?,
                token.paused()?,
            );
            registry.clear_emitted_events();
            token.change_transfer_policy_id(
                admin,
                ITIP20::changeTransferPolicyIdCall {
                    newPolicyId: TOKEN_POLICY_ID,
                },
            )?;
            assert_eq!(
                registry.emitted_events().as_slice(),
                &[ITIP403Registry::TransferPolicyUpdated {
                    token: address,
                    senderMode: ALLOW,
                    recipientMode: BLACKLIST,
                    mintRecipientMode: ALLOW,
                }
                .encode_log_data()]
            );
            assert!(token.token_control()?.is_some());
            assert_eq!(
                before,
                (
                    token.metadata()?,
                    token.quote_token()?,
                    token.next_quote_token()?,
                    token.total_supply()?,
                    token.supply_cap()?,
                    token.paused()?,
                )
            );
            for slot in [
                slots::CURRENCY,
                slots::QUOTE_TOKEN,
                slots::NEXT_QUOTE_TOKEN,
                slots::SUPPLY_CAP,
            ] {
                assert_eq!(StorageCtx.sload(address, slot)?, U256::ZERO);
            }

            // Lists start empty, so `blocked` passes until it is listed.
            assert_eq!(token.transfer_policy_id()?, TOKEN_POLICY_ID);
            assert!(transfer(&mut token, alice, blocked, 1)?);
            add_members(admin, address, &[blocked], Role::RECIPIENT)?;
            assert_eq!(
                transfer(&mut token, alice, blocked, 1),
                Err(TIP20Error::policy_forbids().into())
            );

            // Repeating activation is a no-op. Generic IDs are unsupported afterwards.
            registry.clear_emitted_events();
            token.change_transfer_policy_id(
                admin,
                ITIP20::changeTransferPolicyIdCall {
                    newPolicyId: TOKEN_POLICY_ID,
                },
            )?;
            assert!(registry.emitted_events().is_empty());
            assert_eq!(
                token.change_transfer_policy_id(
                    admin,
                    ITIP20::changeTransferPolicyIdCall {
                        newPolicyId: REJECT_ALL_POLICY_ID,
                    },
                ),
                Err(TIP403RegistryError::token_policy_ids_unsupported().into())
            );
            assert_eq!(
                StorageCtx.sload(
                    TIP403_REGISTRY_ADDRESS,
                    address.mapping_slot(tip403_registry_slots::TOKEN_TRANSFER_POLICIES)
                )?,
                U256::ZERO
            );
            assert_eq!(
                registry.migrate_transfer_policy_ids(
                    ITIP403Registry::migrateTransferPolicyIdsCall {
                        tokens: vec![address]
                    }
                )?,
                U256::ZERO
            );
            Ok(())
        })
    }

    #[test]
    fn activation_rejects_null_quote() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let (mut token, _) = legacy_token(admin, Address::random())?;
            let address = token.address;
            StorageCtx.sstore(address, slots::QUOTE_TOKEN, U256::ZERO)?;
            assert_eq!(
                token.change_transfer_policy_id(
                    admin,
                    ITIP20::changeTransferPolicyIdCall {
                        newPolicyId: TOKEN_POLICY_ID,
                    }
                ),
                Err(TIP20Error::invalid_quote_token().into())
            );
            Ok(())
        })
    }

    #[test]
    fn registry_mirrors_resolve_token_specific_policies() -> eyre::Result<()> {
        let admin = Address::random();
        let (alice, bob) = (Address::random(), Address::random());

        for fork in [TempoHardfork::T13, TempoHardfork::T14] {
            let mut storage = HashMapStorageProvider::new_with_spec(1, fork);
            StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
                // A legacy-layout mirror (as zones create) without a registry binding.
                TIP20Setup::path_usd(admin).apply()?;
                let address = Address::new_tip20(0x1145);
                let mut token = TIP20Token::from_address(address)?;
                token.initialize_with_mirror(
                    admin,
                    "Mirror",
                    "MIR",
                    "USD",
                    PATH_USD_ADDRESS,
                    admin,
                    true,
                )?;
                assert_eq!(token.legacy_transfer_policy_id()?, REJECT_ALL_POLICY_ID);
                token.grant_role_internal(admin, ISSUER_ROLE)?;
                let mut registry = TIP403Registry::new();
                registry.token_transfer_policies[address].delete()?;
                if !fork.is_t14() {
                    StorageCtx.reset_counters();
                    assert_eq!(token.transfer_policy_id()?, REJECT_ALL_POLICY_ID);
                    assert_eq!(StorageCtx.counter_sload(), 2);
                }
                StorageCtx.set_spec(TempoHardfork::T14);
                assert!(token.token_control()?.is_none());
                assert_eq!(
                    mint(&mut token, admin, alice, 10),
                    Err(TIP20Error::policy_forbids().into())
                );

                // The mirrored registry policy applies, including its lists.
                registry.write_token_policy(
                    address,
                    TokenPolicy {
                        recipient: WHITELIST,
                        ..TokenPolicy::ALLOW_ALL
                    },
                )?;
                mint(&mut token, admin, alice, 10)?;
                assert_eq!(
                    transfer(&mut token, alice, bob, 1),
                    Err(TIP20Error::policy_forbids().into())
                );
                registry.token_user_flags[address][bob].write(RECIPIENT_FLAG)?;
                assert!(transfer(&mut token, alice, bob, 1)?);
                assert_eq!(token.transfer_policy_id()?, TOKEN_POLICY_ID);
                Ok(())
            })?;
        }
        Ok(())
    }
}
