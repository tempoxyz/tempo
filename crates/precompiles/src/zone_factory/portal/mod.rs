//! Native ZonePortal: the Solidity-compatible storage layout of every portal account and, from
//! T15, the precompile that runs it.
//!
//! Before T15, calls to a portal execute the ERC-1167 proxy and the canonical Solidity
//! implementation at `ZONE_PORTAL_IMPL_ADDRESS`, and this type is only a storage handle for the
//! factory. From T15, every `ZONE_PORTAL_PREFIX` address dispatches here instead, on the same
//! storage, as TIP-1091 allows once precompiles can make the portal's external calls.
//!
//! The port follows `ZonePortal.sol` function by function. Every call the Solidity makes to
//! another contract, including Tempo precompiles, is a nested EVM call through
//! [`StorageCtx::call`](crate::storage::StorageCtx::call), so reverts, `try`/`catch`
//! isolation and re-entry behave as they do in the EVM.

mod admin;
mod deposits;
mod dispatch;
mod secp256k1;
mod settlement;
mod views;
mod withdrawals;

use crate::{
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping, NestedCall, Slot},
};
use alloy::{
    primitives::{Address, B256, Bytes, FixedBytes, IntoLogData, U256, hex},
    sol_types::SolCall,
};
use tempo_contracts::precompiles::{
    IZoneFactory, ZONE_MESSENGER_ADDRESS, ZONE_VERIFIER_ADDRESS, ZoneFactoryError,
    ZonePortalCapability, ZonePortalError, ZonePortalEvent, ZonePortalRole,
};
use tempo_precompiles_macros::{Storable, contract};

/// Exact ERC-1167 deployed proxy runtime installed at every ZonePortal address.
pub const ZONE_PORTAL_PROXY_RUNTIME: [u8; 45] = hex!(
    "363d3d373d3d3d363d735ad10000000000000000000000000000000000005af43d82803e903d91602b57fd5bf3"
);

/// Packed `TokenConfig` stored in the portal token registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Storable)]
pub struct PortalTokenConfig {
    pub enabled: bool,
    pub deposits_active: bool,
}

/// Historical encryption-key entry stored by ZonePortal.
#[derive(Debug, Clone, Copy, Storable)]
pub struct PortalEncryptionKeyEntry {
    x: B256,
    y_parity: u8,
    activation_block: u64,
}

/// Withdrawal queue stored by ZonePortal.
#[derive(Debug, Clone, Storable)]
pub struct PortalWithdrawalQueue {
    head: U256,
    tail: U256,
    #[expect(dead_code)]
    slots: Mapping<U256, B256>,
}

/// Canonical Solidity storage layout of the ZonePortal runtime installed at T10.
///
/// The generated handlers let the native factory initialize a portal without duplicating raw
/// slot numbers. From T15 the same type is the native portal precompile.
#[contract]
pub struct ZonePortalStorage {
    admin: Address,
    zone_gas_rate: u128,
    withdrawal_batch_index: u64,
    block_hash: B256,
    current_deposit_queue_hash: B256,
    deposit_count: u64,
    last_processed_deposit_number: u64,
    last_synced_tempo_block_number: u64,
    bounceback_gas: u64,
    encryption_keys: Vec<PortalEncryptionKeyEntry>,
    token_configs: Mapping<Address, PortalTokenConfig>,
    enabled_tokens: Vec<Address>,
    refunds: Mapping<Address, Mapping<Address, u128>>,
    withdrawal_queue: PortalWithdrawalQueue,
    rpc_url: String,
    pending_admin: Address,
    withdrawal_reentrancy_status: U256,
    zone_id: u32,
    messenger: Address,
    verifier: Address,
    initialized: bool,
    sequencer_set_version: u64,
    sequencer_threshold: u8,
    zone_height: U256,
    sequencers: Vec<Address>,
    /// Reserved slot 19, available for future use.
    _reserved_slot_19: U256,
    role: Mapping<Address, u8>,
    is_access_enforced: bool,
    is_gateway_enforced: bool,
    /// Reserved remainder of the enforcement modes slot.
    _reserved: FixedBytes<30>,
    /// Maximum Tempo gas rate, stored in slot 22.
    max_tempo_gas_rate: u128,
    /// Active block-producing leader, stored in slot 23.
    leader: Address,
    /// Monotonic leadership transition epoch, packed after `leader` in slot 23.
    leader_epoch: u64,
    /// Tempo block at which the current leader became active, stored in slot 24.
    leader_activation_tempo_block: u64,
    /// Per-block deposit and token-enablement counters occupying slots 24 and 25.
    deposit_count_block: u64,
    deposits_in_current_block: u64,
    token_enable_count_block: u64,
    tokens_enabled_in_current_block: u64,
    /// End of the bounded portal pause, packed in slot 25 after the token enablement counter.
    pause_expiry: u64,
    /// Append-only commitment to the enabled token sequence and metadata, stored in slot 26.
    token_enablement_hash: B256,
    /// Capability-keyed abdication timestamps, stored as a Solidity mapping in slot 27.
    abdication_effective_at: Mapping<u8, u64>,
    /// Enabled-token prefix confirmed by accepted Zone proofs, stored in slot 28.
    last_processed_enabled_token_count: u64,
    /// Whether the token cursor has been initialized, packed into slot 28.
    token_enablement_cursor_initialized: bool,
}

impl ZonePortalStorage {
    pub fn new(address: Address) -> Self {
        Self::__new(address)
    }

    /// Returns the storage handler for the current pause expiry timestamp.
    pub fn pause_expiry_slot(&self) -> &Slot<u64> {
        &self.pause_expiry
    }

    /// Returns the storage handler for a capability's abdication timestamp.
    pub fn abdication_effective_at_slot(&self, capability: ZonePortalCapability) -> &Slot<u64> {
        &self.abdication_effective_at[u8::from(capability)]
    }

    pub(crate) fn initialize_from_factory(
        &mut self,
        zone_id: u32,
        params: &IZoneFactory::CreateZoneParams,
        token_enablement_hash: B256,
    ) -> Result<()> {
        if self.initialized.read()? {
            return Err(ZoneFactoryError::already_initialized().into());
        }

        self.storage
            .set_code(self.address, Bytes::from_static(&ZONE_PORTAL_PROXY_RUNTIME))?;

        self.admin.write(params.admin)?;
        self.token_configs[params.initialToken].write(PortalTokenConfig {
            enabled: true,
            deposits_active: true,
        })?;
        self.enabled_tokens.write(vec![params.initialToken])?;
        self.rpc_url.write(params.rpcUrl.clone())?;
        self.zone_id.write(zone_id)?;
        self.messenger.write(ZONE_MESSENGER_ADDRESS)?;
        self.verifier.write(ZONE_VERIFIER_ADDRESS)?;
        self.initialized.write(true)?;
        self.sequencer_threshold.write(params.threshold)?;
        self.sequencers.write(params.sequencers.clone())?;
        for sequencer in &params.sequencers {
            self.role[*sequencer].write(u8::from(ZonePortalRole::Sequencer))?;
        }
        self.is_access_enforced.write(params.accessMode)?;
        self.is_gateway_enforced.write(params.gatewayMode)?;
        let leader = *params
            .sequencers
            .first()
            .ok_or_else(ZoneFactoryError::invalid_sequencer_set)?;
        self.leader.write(leader)?;
        self.leader_epoch.write(1)?;
        let creation_block = self.storage.block_number();
        self.leader_activation_tempo_block.write(creation_block)?;
        self.token_enable_count_block.write(creation_block)?;
        self.tokens_enabled_in_current_block.write(1)?;
        self.token_enablement_hash.write(token_enablement_hash)?;
        if self.storage.spec().is_t13() {
            self.token_enablement_cursor_initialized.write(true)?;
        }
        for gateway in &params.zoneGateways {
            self.role[*gateway].write(u8::from(ZonePortalRole::CallbackGateway))?;
        }
        for account in &params.allowedAccounts {
            self.role[*account].write(u8::from(ZonePortalRole::Account))?;
        }
        Ok(())
    }
}

alloy::sol! {
    /// Public constants of `ZonePortal.sol` that the `IZonePortal` interface, and so the shared
    /// `ZonePortal` binding, does not declare.
    interface ZonePortalConstants {
        function MAX_SEQUENCERS() external view returns (uint256);
        function PAUSE_DURATION() external view returns (uint64);
        function ABDICATION_DELAY() external view returns (uint64);
    }
}

/// `FIXED_DEPOSIT_GAS`: deposit fee = this * `zoneGasRate`.
pub const FIXED_DEPOSIT_GAS: u64 = 100_000;
/// `MAX_UNPROCESSED_DEPOSITS`.
pub const MAX_UNPROCESSED_DEPOSITS: u64 = 230;
/// `MAX_UNPROCESSED_TOKEN_ENABLEMENTS`.
pub const MAX_UNPROCESSED_TOKEN_ENABLEMENTS: u64 = 8;
/// `WITHDRAWAL_PROCESSING_DEPOSIT_RESERVE`: deposit-queue capacity kept for one withdrawal batch.
pub const WITHDRAWAL_PROCESSING_DEPOSIT_RESERVE: u64 = 20;
/// `MAX_GAS_FEE_RATE`.
pub const MAX_GAS_FEE_RATE: u128 = 1_000_000_000_000_000_000;
/// `TEMPO_BASE_FEE_SCALE`: 18-decimal gas prices to 6-decimal TIP-20 units.
pub const TEMPO_BASE_FEE_SCALE: u128 = 1_000_000_000_000;
/// `PAUSE_DURATION`: 30 days.
pub const PAUSE_DURATION: u64 = 30 * 24 * 60 * 60;
/// `ABDICATION_DELAY`.
pub const ABDICATION_DELAY: u64 = PAUSE_DURATION;

/// Values of the `_withdrawalReentrancyStatus` slot.
pub const WITHDRAWAL_NOT_ENTERED: U256 = U256::ZERO;
pub const WITHDRAWAL_PROCESSING: U256 = U256::from_limbs([1, 0, 0, 0]);
pub const CALLBACK_DEPOSIT_AVAILABLE: U256 = U256::from_limbs([2, 0, 0, 0]);
pub const CALLBACK_DEPOSIT_CONSUMED: U256 = U256::from_limbs([3, 0, 0, 0]);

/// Shared helpers that mirror the Solidity modifiers and internal functions every group uses.
impl ZonePortalStorage {
    /// Whether the factory has initialized this portal.
    pub fn is_initialized(&self) -> Result<bool> {
        self.initialized.read()
    }

    /// Emits a ZonePortal event from this portal.
    pub(crate) fn emit(&mut self, event: ZonePortalEvent) -> Result<()> {
        self.storage.emit_event(self.address, event.into_log_data())
    }

    /// A bare Solidity `require` failure: revert with empty data.
    pub(crate) fn require(condition: bool) -> Result<()> {
        if condition {
            Ok(())
        } else {
            Err(TempoPrecompileError::RawRevert(Bytes::new()))
        }
    }

    /// The role stored for `account`.
    pub(crate) fn role_of(&self, account: Address) -> Result<ZonePortalRole> {
        let raw = self.role[account].read()?;
        ZonePortalRole::try_from(raw)
            .map_err(|_| TempoPrecompileError::Fatal(format!("invalid ZonePortal role {raw}")))
    }

    /// Solidity `hasRole`.
    pub(crate) fn has_role_of(&self, account: Address, expected: ZonePortalRole) -> Result<bool> {
        Ok(self.role_of(account)? == expected)
    }

    /// Solidity `isSequencer`.
    pub(crate) fn is_sequencer_account(&self, account: Address) -> Result<bool> {
        self.has_role_of(account, ZonePortalRole::Sequencer)
    }

    /// Solidity `onlyAdmin`.
    pub(crate) fn only_admin(&self, sender: Address) -> Result<()> {
        if sender != self.admin.read()? {
            return Err(ZonePortalError::not_admin().into());
        }
        Ok(())
    }

    /// Solidity `onlySequencer`.
    pub(crate) fn only_sequencer(&self, sender: Address) -> Result<()> {
        if !self.is_sequencer_account(sender)? {
            return Err(ZonePortalError::not_sequencer().into());
        }
        Ok(())
    }

    /// Solidity `paused()`: the pause lapses once `block.timestamp` reaches `pauseExpiry`.
    pub(crate) fn is_paused(&self) -> Result<bool> {
        Ok(self.storage.timestamp() < U256::from(self.pause_expiry.read()?))
    }

    /// Solidity `whenNotPaused`.
    pub(crate) fn when_not_paused(&self) -> Result<()> {
        if self.is_paused()? {
            return Err(ZonePortalError::portal_is_paused().into());
        }
        Ok(())
    }

    /// Solidity `_isAllowed`.
    pub(crate) fn is_allowed(&self, account: Address) -> Result<bool> {
        Ok(!self.is_access_enforced.read()?
            || self.has_role_of(account, ZonePortalRole::Account)?)
    }

    /// Solidity `_requireAllowed`.
    pub(crate) fn require_allowed(&self, account: Address) -> Result<()> {
        if !self.is_allowed(account)? {
            return Err(ZonePortalError::account_not_allowed(account).into());
        }
        Ok(())
    }

    /// Raw nested call from this portal. Forwards all but one 64th of the remaining gas, as a
    /// Solidity external call does.
    pub(crate) fn raw_call(
        &mut self,
        target: Address,
        input: Bytes,
        is_static: bool,
    ) -> Result<crate::storage::NestedCallResult> {
        self.storage.call(NestedCall {
            target,
            input,
            gas_limit: u64::MAX,
            is_static,
        })
    }

    /// A Solidity high-level external call: reverts bubble up with the callee's revert data, and
    /// return data that does not decode reverts with empty data.
    pub(crate) fn external_call<C: SolCall>(
        &mut self,
        target: Address,
        call: &C,
    ) -> Result<C::Return> {
        let result = self.raw_call(target, call.abi_encode().into(), false)?;
        if !result.success {
            return Err(TempoPrecompileError::RawRevert(result.output));
        }
        C::abi_decode_returns_validate(&result.output)
            .map_err(|_| TempoPrecompileError::RawRevert(Bytes::new()))
    }

    /// A Solidity external call to a `view` function, made with `STATICCALL`.
    pub(crate) fn external_static_call<C: SolCall>(
        &mut self,
        target: Address,
        call: &C,
    ) -> Result<C::Return> {
        let result = self.raw_call(target, call.abi_encode().into(), true)?;
        if !result.success {
            return Err(TempoPrecompileError::RawRevert(result.output));
        }
        C::abi_decode_returns_validate(&result.output)
            .map_err(|_| TempoPrecompileError::RawRevert(Bytes::new()))
    }

    /// A Solidity `try` external call: `None` when the callee reverts or its return data does
    /// not decode, which the `catch` branch handles. Database and fatal errors still surface.
    pub(crate) fn try_external_call<C: SolCall>(
        &mut self,
        target: Address,
        call: &C,
        is_static: bool,
    ) -> Result<Option<C::Return>> {
        let result = self.raw_call(target, call.abi_encode().into(), is_static)?;
        if !result.success {
            return Ok(None);
        }
        C::abi_decode_returns_validate(&result.output)
            .map(Some)
            .map_err(|_| TempoPrecompileError::RawRevert(Bytes::new()))
    }
}
