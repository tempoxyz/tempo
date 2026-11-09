//! Native `ZoneAllowlist` precompile.
//!
//! Stores the zone's account allowlist on chain so every node replicates it. The precompile only
//! stores the list and authorizes writes: the sequencer enforces it when it builds blocks, by
//! bouncing deposits whose Tempo sender or zone recipient is unlisted and by leaving out TIP-20
//! transfers that involve an unlisted account. Followers and the prover never consult it. Node
//! code reads the list by raw slot through [`slots`].
//!
//! Enforcement starts disabled, in which state every account is allowed. The admin starts unset;
//! any ZonePortal sequencer on finalized Tempo can set it, so the operator can bootstrap or recover
//! it without chain or node configuration.
//!
//! Zones are private chains, so the member list, its size and per-account membership are only
//! readable by privileged callers, and list changes emit the resulting count, never addresses.
//!
//! # Gas
//!
//! Mutations use fixed charges instead of storage pricing, which charges 250,000 gas per new slot
//! (TIP-1000) and would admit only about 110 new members per 30M gas block:
//!
//! - `setAllowed`: `SET_ALLOWED_BASE_GAS` plus `SET_ALLOWED_ACCOUNT_GAS` per account in the
//!   batch, so a full 5,000-account batch costs 12,510,000 gas. Calldata that does not decode, or a
//!   batch over [`MAX_ZONE_ALLOWLIST_BATCH`], is charged the base and reverts.
//! - `setAdmin`: `SET_ADMIN_GAS`, which covers the finalized Tempo role read.
//! - `setEnabled`: `SET_ENABLED_GAS`.
//!
//! Views keep normal metering, which bounds the work of `accounts` by the caller's gas.

mod dispatch;

#[cfg(test)]
mod tests;

use alloc::vec::Vec;

use alloy_primitives::{Address, U256};
use alloy_sol_types::SolCall;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::zones::{
    IZoneAllowlist, MAX_ZONE_ALLOWLIST_BATCH, MAX_ZONE_ALLOWLIST_LEN, ZoneAllowlistError,
    ZoneAllowlistEvent, ZonePortal::Role,
};
use tempo_precompiles::{
    dispatch::{abi_decoder_config_for_spec, selector_from_calldata},
    error::TempoPrecompileError,
    storage::{ContractStorage, Handler, Mapping, StorageKey as _},
};
use tempo_precompiles_macros::contract;
pub use zone_primitives::constants::ZONE_ALLOWLIST_ADDRESS;

use crate::{
    ZoneResult,
    execution::CallRules,
    storage::{L1State, L1StorageReader},
};

/// Fixed charge for a `setAllowed` call before its per-account charge.
pub(crate) const SET_ALLOWED_BASE_GAS: u64 = 10_000;
/// Fixed charge for each account in a `setAllowed` batch.
pub(crate) const SET_ALLOWED_ACCOUNT_GAS: u64 = 2_500;
/// Fixed charge for a `setAdmin` call.
pub(crate) const SET_ADMIN_GAS: u64 = 10_000;
/// Fixed charge for a `setEnabled` call.
pub(crate) const SET_ENABLED_GAS: u64 = 5_000;

/// On-chain zone account allowlist.
#[contract(addr = ZONE_ALLOWLIST_ADDRESS)]
pub struct ZoneAllowlist {
    /// Account allowed to change the list and toggle enforcement; zero when unset. Kept first and
    /// alone in slot 0, since node code reads it by raw slot.
    admin: Address,
    /// Listed accounts in insertion order, compacted by swap-and-pop on removal.
    members: Vec<Address>,
    /// One-based index of each listed account in `members`; zero when unlisted. Node code reads
    /// it by raw slot.
    member_index: Mapping<Address, u64>,
    /// Whether deposits and transfers are restricted to listed accounts. Node code reads it by
    /// raw slot.
    enabled: bool,
}

impl ZoneAllowlist {
    fn is_enabled(&self) -> tempo_precompiles::Result<bool> {
        self.enabled.read()
    }

    /// Returns whether `account` is allowed: true when enforcement is disabled or it is listed.
    fn allows(&self, account: Address) -> tempo_precompiles::Result<bool> {
        Ok(!self.enabled.read()? || self.is_member(account)?)
    }

    fn is_member(&self, account: Address) -> tempo_precompiles::Result<bool> {
        Ok(self.member_index[account].read()? != 0)
    }

    /// Returns whether `caller` is the configured admin. An unset admin matches nobody.
    fn is_admin(&self, caller: Address) -> tempo_precompiles::Result<bool> {
        let admin = self.admin.read()?;
        Ok(!admin.is_zero() && caller == admin)
    }

    /// Admits operator simulations (`address(0)`), the admin and ZonePortal sequencers.
    fn ensure_privileged_reader<P: L1StorageReader>(
        &self,
        l1: &L1State<P>,
        caller: Address,
    ) -> ZoneResult<()> {
        // The public redacted RPC binds simulations to the authenticated caller, so only the
        // trusted operator RPC can call as `address(0)`.
        if caller.is_zero()
            || self.is_admin(caller)?
            || l1.has_portal_role(caller, Role::Sequencer)?
        {
            return Ok(());
        }
        Err(ZoneAllowlistError::unauthorized().into())
    }

    fn ensure_admin(&self, caller: Address) -> ZoneResult<()> {
        if self.is_admin(caller)? {
            return Ok(());
        }
        Err(ZoneAllowlistError::unauthorized().into())
    }

    /// Deploys the account marker on first write so the account is never cleared as empty. The
    /// address becomes a precompile at T15, after existing zones' genesis.
    fn ensure_initialized(&mut self) -> tempo_precompiles::Result<()> {
        if !self.is_initialized()? {
            self.__initialize()?;
        }
        Ok(())
    }

    fn count<P: L1StorageReader>(&self, l1: &L1State<P>, caller: Address) -> ZoneResult<U256> {
        self.ensure_privileged_reader(l1, caller)?;
        Ok(U256::from(self.members.len()?))
    }

    fn view_is_allowed<P: L1StorageReader>(
        &self,
        l1: &L1State<P>,
        caller: Address,
        account: Address,
    ) -> ZoneResult<bool> {
        if caller != account {
            self.ensure_privileged_reader(l1, caller)?;
        }
        Ok(self.allows(account)?)
    }

    fn view_accounts<P: L1StorageReader>(
        &self,
        l1: &L1State<P>,
        caller: Address,
        offset: U256,
        limit: U256,
    ) -> ZoneResult<Vec<Address>> {
        self.ensure_privileged_reader(l1, caller)?;
        let len = self.members.len()?;
        // An offset that does not fit in `usize` is past every possible member.
        let Some(start) = usize::try_from(offset).ok().filter(|start| *start < len) else {
            return Ok(Vec::new());
        };
        let remaining = len - start;
        let count = usize::try_from(limit).map_or(remaining, |limit| limit.min(remaining));
        Ok((start..start + count)
            .map(|index| self.members[index].read())
            .collect::<tempo_precompiles::Result<_>>()?)
    }

    fn set_admin<P: L1StorageReader>(
        &mut self,
        l1: &L1State<P>,
        caller: Address,
        new_admin: Address,
    ) -> ZoneResult<()> {
        // Inlines `is_admin` so the event below reuses the one admin read.
        let previous_admin = self.admin.read()?;
        let is_admin = !previous_admin.is_zero() && caller == previous_admin;
        if !is_admin && !l1.has_portal_role(caller, Role::Sequencer)? {
            return Err(ZoneAllowlistError::unauthorized().into());
        }
        self.ensure_initialized()?;
        self.admin.write(new_admin)?;
        self.emit_event(ZoneAllowlistEvent::admin_changed(previous_admin, new_admin))?;
        Ok(())
    }

    fn set_enabled(&mut self, caller: Address, enabled: bool) -> ZoneResult<()> {
        self.ensure_admin(caller)?;
        self.ensure_initialized()?;
        self.enabled.write(enabled)?;
        self.emit_event(ZoneAllowlistEvent::enabled_changed(enabled))?;
        Ok(())
    }

    fn set_allowed(
        &mut self,
        caller: Address,
        accounts: Vec<Address>,
        allowed: bool,
    ) -> ZoneResult<()> {
        self.ensure_admin(caller)?;
        if accounts.len() > MAX_ZONE_ALLOWLIST_BATCH {
            return Err(ZoneAllowlistError::batch_too_large(
                U256::from(accounts.len()),
                U256::from(MAX_ZONE_ALLOWLIST_BATCH),
            )
            .into());
        }
        self.ensure_initialized()?;

        let mut len = self.members.len()?;
        for account in accounts {
            let index = self.member_index[account].read()?;
            if allowed {
                if index != 0 {
                    continue;
                }
                if len >= MAX_ZONE_ALLOWLIST_LEN {
                    return Err(ZoneAllowlistError::allowlist_full(U256::from(
                        MAX_ZONE_ALLOWLIST_LEN,
                    ))
                    .into());
                }
                self.members.push(account)?;
                len += 1;
                self.member_index[account].write(
                    u64::try_from(len).map_err(|_| TempoPrecompileError::under_overflow())?,
                )?;
            } else {
                if index == 0 {
                    continue;
                }
                let removed = usize::try_from(index - 1)
                    .map_err(|_| TempoPrecompileError::under_overflow())?;
                let last = len - 1;
                if removed != last {
                    let moved = self.members[last].read()?;
                    self.members[removed].write(moved)?;
                    self.member_index[moved].write(index)?;
                }
                self.members.pop()?;
                self.member_index[account].delete()?;
                len = last;
            }
        }

        self.emit_event(ZoneAllowlistEvent::allowlist_changed(U256::from(len)))?;
        Ok(())
    }
}

/// Storage slot holding the one-based index of `account` in the member list; zero when unlisted.
/// For node code that reads the list by raw slot, alongside [`slots::ENABLED`].
pub fn member_index_slot(account: Address) -> U256 {
    account.mapping_slot(slots::MEMBER_INDEX)
}

/// Storage of an allowlist with enforcement `enabled` that lists `members`, as `(slot, value)`
/// pairs for seeding test state. Covers the slots node code reads, not the member array.
#[cfg(any(test, feature = "test-utils"))]
pub fn storage_entries(enabled: bool, members: &[Address]) -> Vec<(U256, U256)> {
    core::iter::once((slots::ENABLED, U256::from(enabled)))
        .chain(
            members
                .iter()
                .enumerate()
                .map(|(index, member)| (member_index_slot(*member), U256::from(index + 1))),
        )
        .collect()
}

/// Fixed gas for allowlist mutations; see the module docs.
pub(crate) struct AllowlistRules {
    /// Active hardfork, which selects the same ABI decoder settings dispatch uses.
    pub(crate) spec: TempoHardfork,
}

impl CallRules for AllowlistRules {
    fn fixed_gas_for_call(&self, data: &[u8]) -> Option<u64> {
        match selector_from_calldata(data)? {
            IZoneAllowlist::setAllowedCall::SELECTOR => {
                // Decoded like dispatch, so a batch is charged exactly when it is processed.
                // Malformed or oversized batches revert in dispatch and pay only the base.
                let accounts = IZoneAllowlist::setAllowedCall::abi_decode_with_config(
                    data,
                    abi_decoder_config_for_spec(self.spec),
                )
                .ok()
                .map(|call| call.accounts.len())
                .filter(|len| *len <= MAX_ZONE_ALLOWLIST_BATCH)
                .unwrap_or_default();
                Some(SET_ALLOWED_BASE_GAS + accounts as u64 * SET_ALLOWED_ACCOUNT_GAS)
            }
            IZoneAllowlist::setAdminCall::SELECTOR => Some(SET_ADMIN_GAS),
            IZoneAllowlist::setEnabledCall::SELECTOR => Some(SET_ENABLED_GAS),
            _ => None,
        }
    }
}
