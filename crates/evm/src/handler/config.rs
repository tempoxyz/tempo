//! EVM2 transaction handler plumbing.

use super::configurable_account;
use crate::{
    FeePaymentError, ProtocolFeeContext, ProtocolFeeManager, ResolvedFeeToken,
    SYSTEM_CALL_GAS_LIMIT, TempoEvmTx, TempoFeeManager, TempoInvalidTransaction, TempoTxEnv,
};
use alloy_consensus::{Transaction, TxEip1559, TxEip2930, TxLegacy};
use alloy_primitives::{Address, TxKind, U256};
use evm2::{
    Evm, EvmConfig, EvmConfigSelector, EvmFeatures, EvmTypesHost, ExecutionConfig, OpcodeConfig,
    SpecId, TxResult,
    ethereum::{LazyTxEip7702, PreparedTx, eip1559, eip2930, eip7702, finalize_gas, legacy},
    evm::{DynDatabase, SystemTx, precompile::PrecompileProvider},
    handler::{GasSettlement, TxHandlerHooks},
    registry::{HandlerError, HandlerResult, TxRegistry, TxRequest, handler},
    version::GasId,
};
use std::{
    any::TypeId,
    cell::RefCell,
    rc::Rc,
    sync::{Arc, LazyLock},
};
use tempo_chainspec::{constants::gas::STORAGE_CREDIT_VALUE, hardfork::TempoHardfork};
use tempo_contracts::precompiles::TIPFeeAMMError;
use tempo_precompiles::{
    STORAGE_CREDITS_ADDRESS,
    error::TempoPrecompileError,
    storage::{FromWord, StorageActions, StorageCtx},
    storage_credits::{NonCreditableSlots, TransientState},
    tip20::TIP20Error,
};
use tempo_primitives::{TempoAddressExt, TempoEvmKind, transaction::calc_gas_balance_spending};
pub use tempo_primitives::{TempoBlockEnv, TempoBlockExt};

/// EVM2 type family used by Tempo execution.
#[derive(Clone, Copy, Debug)]
pub struct TempoEvmTypes;

impl EvmTypesHost for TempoEvmTypes {
    type ConfigSelector = TempoConfigSelector;
    type SpecId = TempoHardfork;
    type Tx = TempoTxEnv;
    type EvmExt = TempoEvmExt;
    type MessageExt = ();
    type MessageResultExt = ();
    type TxEnvExt = ();
    type TxResultExt = TempoTxResultExt;
    type BlockEnvExt = TempoBlockExt;
    type Host<'a> = Evm<'a, Self>;
}

/// Tempo opcode configuration over an inherited Ethereum specification.
#[derive(Clone, Copy, Debug)]
pub struct TempoConfig<const BASE_SPEC_ID: u32>(());

impl<const BASE_SPEC_ID: u32> EvmConfig<TempoEvmTypes> for TempoConfig<BASE_SPEC_ID> {
    const BASE_SPEC_ID: SpecId =
        SpecId::try_from_u32(BASE_SPEC_ID).expect("invalid Tempo base spec id");
    const OPCODE_CONFIG: &'static OpcodeConfig<TempoEvmTypes> =
        &tempo_opcode_config::<BASE_SPEC_ID>();
}

/// Returns Tempo's opcode configuration over an inherited Ethereum specification.
pub const fn tempo_opcode_config<const BASE_SPEC_ID: u32>() -> OpcodeConfig<TempoEvmTypes> {
    let mut config = OpcodeConfig::base::<TempoConfig<BASE_SPEC_ID>>();
    config.set_instruction::<crate::instructions::millis_timestamp>(0x4f, 0);
    config.set_instruction::<crate::instructions::sstore>(evm2::interpreter::op::SSTORE, 0);
    config.set_instruction::<crate::instructions::configurable_account>(0xef, 0);
    config
}

/// Selects Tempo's opcode table for the active Ethereum specification.
#[derive(Clone, Copy, Debug)]
pub struct TempoConfigSelector;

impl EvmConfigSelector<TempoEvmTypes> for TempoConfigSelector {
    type Config<const BASE_SPEC_ID: u32, const CUSTOM_SPEC_ID: u32> = TempoConfig<BASE_SPEC_ID>;

    fn execution_config(spec_id: TempoHardfork) -> ExecutionConfig<TempoEvmTypes> {
        let spec_id = SpecId::from(spec_id);
        evm2::spec_to_generic!(spec_id, |SPEC_ID| ExecutionConfig::for_config::<
            TempoConfig<SPEC_ID>,
        >())
    }
}

/// Tempo-specific transaction result fields produced by EVM2 settlement.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TempoTxResultExt {
    /// Fee credited to the block beneficiary after fee-AMM settlement.
    pub validator_fee: U256,
}

static DEFAULT_FEE_MANAGER: LazyLock<Arc<dyn ProtocolFeeManager>> =
    LazyLock::new(|| Arc::new(TempoFeeManager));

#[inline]
fn is_default_fee_manager(fm: &Arc<dyn ProtocolFeeManager>) -> bool {
    Arc::ptr_eq(fm, &*DEFAULT_FEE_MANAGER)
}

/// Tempo-specific state owned by an EVM2 instance.
#[derive(Clone, Debug)]
pub struct TempoEvmExt {
    /// Kind of the EVM, whose rules every storage context over the EVM follows.
    pub kind: TempoEvmKind,
    /// Protocol fee implementation used by transaction hooks.
    pub fee_manager: Arc<dyn ProtocolFeeManager>,
    /// Recorder for protocol storage accesses.
    pub actions: StorageActions,
    /// Transaction-local slots whose clears must not create storage credits.
    pub non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
    /// Whether transaction-pool execution may skip the lower validity bound.
    pub skip_valid_after_check: bool,
    /// Whether transaction-pool execution may skip the fee AMM liquidity check.
    pub skip_liquidity_check: bool,
    /// Fee token resolved for the most recently handled transaction.
    pub resolved_fee_token: Option<ResolvedFeeToken>,
    /// Access-key expiry resolved for the most recently handled transaction.
    pub key_expiry: Option<u64>,
    /// Fee payer for which `resolved_fee_balance_slot` was computed.
    #[doc(hidden)]
    pub resolved_fee_payer: Address,
    /// Precomputed `balances[fee_payer]` slot for the current transaction.
    #[doc(hidden)]
    pub resolved_fee_balance_slot: U256,
    /// Whether `collect_fee_pre_tx` wrote `two_hop_intermediate` for the current transaction.
    #[doc(hidden)]
    pub has_two_hop_intermediate: bool,
    /// Per-block cached fee-manager mapping slots keyed by beneficiary.
    #[doc(hidden)]
    pub fee_slot_cache: FeeSlotCache,
    /// Per-EVM direct-mapped cache for frequent account mapping slots.
    #[doc(hidden)]
    pub sender_slot_cache: SenderSlotCache,
    #[doc(hidden)]
    pub allowance_slot_cache: AllowanceSlotCache,
    /// Per-transaction transient storage seeds for precompile context slots.
    #[doc(hidden)]
    pub tx_transient_seeds: TxTransientSeeds,
    /// Whether `TempoBlockExecutor::set_state_hook` should batch and deduplicate `StateUpdate`s
    /// on a background worker thread (used by block validation; tests and corpus stay unbatched).
    #[doc(hidden)]
    pub batch_state_hook: bool,
}

/// Per-transaction transient storage seeds stored inline on [`TempoEvmExt`] so normal
/// transactions avoid inserting four entries into EVM transient storage.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TxTransientSeeds {
    active: u8,
    has_transaction_key: bool,
    has_opened_channel: bool,
    pub(crate) has_storage_credit_refunds: bool,
    keychain_tx_origin: U256,
    channel_open_context_hash: U256,
    ca_tx_origin: U256,
    ca_packed_auth: U256,
}

impl TxTransientSeeds {
    const MASK_KEYCHAIN_ORIGIN: u8 = 1 << 0;
    const MASK_CHANNEL_CONTEXT: u8 = 1 << 1;
    const MASK_CA_ORIGIN: u8 = 1 << 2;
    const MASK_CA_PACKED: u8 = 1 << 3;

    #[inline]
    pub(crate) fn clear(&mut self) {
        self.active = 0;
        self.has_transaction_key = false;
        self.has_opened_channel = false;
        self.has_storage_credit_refunds = false;
    }

    #[inline]
    pub(crate) fn seed_base(&mut self, origin: U256, context_hash: U256) {
        self.keychain_tx_origin = origin;
        self.channel_open_context_hash = context_hash;
        self.active = Self::MASK_KEYCHAIN_ORIGIN | Self::MASK_CHANNEL_CONTEXT;
        self.has_transaction_key = false;
        self.has_opened_channel = false;
        self.has_storage_credit_refunds = false;
    }

    #[inline]
    pub(crate) fn seed_configurable_account(&mut self, origin: U256, packed_auth: U256) {
        self.ca_tx_origin = origin;
        self.ca_packed_auth = packed_auth;
        self.active |= Self::MASK_CA_ORIGIN | Self::MASK_CA_PACKED;
    }

    #[inline]
    pub(crate) fn get(&self, address: Address, key: U256) -> Option<U256> {
        if self.active == 0 {
            return None;
        }
        if address == tempo_precompiles::ACCOUNT_KEYCHAIN_ADDRESS {
            if (self.active & Self::MASK_KEYCHAIN_ORIGIN) != 0
                && key == tempo_precompiles::account_keychain::slots::TX_ORIGIN
            {
                return Some(self.keychain_tx_origin);
            }
        } else if address == tempo_precompiles::TIP20_CHANNEL_RESERVE_ADDRESS {
            if (self.active & Self::MASK_CHANNEL_CONTEXT) != 0
                && key == tempo_precompiles::tip20_channel_reserve::slots::CHANNEL_OPEN_CONTEXT_HASH
            {
                return Some(self.channel_open_context_hash);
            }
        } else if address == tempo_precompiles::CONFIGURABLE_ACCOUNT_ADDRESS {
            if (self.active & Self::MASK_CA_ORIGIN) != 0
                && key == tempo_precompiles::configurable_account::slots::TX_ORIGIN
            {
                return Some(self.ca_tx_origin);
            }
            if (self.active & Self::MASK_CA_PACKED) != 0
                && key
                    == tempo_precompiles::configurable_account::slots::DIRECTLY_AUTHORIZED_ACCOUNT
            {
                return Some(self.ca_packed_auth);
            }
        }
        None
    }

    #[inline]
    pub(crate) fn on_tstore(&mut self, address: Address, key: U256, value: U256) {
        if address == tempo_precompiles::ACCOUNT_KEYCHAIN_ADDRESS {
            if key == tempo_precompiles::account_keychain::slots::TRANSACTION_KEY {
                self.has_transaction_key = !value.is_zero();
            } else if key == tempo_precompiles::account_keychain::slots::TX_ORIGIN {
                self.active &= !Self::MASK_KEYCHAIN_ORIGIN;
            }
        } else if address == tempo_precompiles::TIP20_CHANNEL_RESERVE_ADDRESS {
            if key == tempo_precompiles::tip20_channel_reserve::slots::CHANNEL_OPEN_CONTEXT_HASH {
                self.active &= !Self::MASK_CHANNEL_CONTEXT;
            } else {
                self.has_opened_channel = true;
            }
        } else if address == tempo_precompiles::CONFIGURABLE_ACCOUNT_ADDRESS {
            if key == tempo_precompiles::configurable_account::slots::TX_ORIGIN {
                self.active &= !Self::MASK_CA_ORIGIN;
            } else if key
                == tempo_precompiles::configurable_account::slots::DIRECTLY_AUTHORIZED_ACCOUNT
            {
                self.active &= !Self::MASK_CA_PACKED;
            }
        } else if address == STORAGE_CREDITS_ADDRESS && value.as_limbs()[3] != 0 {
            self.has_storage_credit_refunds = true;
        }
    }
}

const SENDER_SLOT_CACHE_LEN: usize = 4096;
const SENDER_SLOT_CACHE_MASK: usize = SENDER_SLOT_CACHE_LEN - 1;

#[derive(Debug, Clone, Copy, Default)]
struct SenderSlotEntry {
    addr: Address,
    flags: u8,
    balance_slot: U256,
    receive_policy_slot: U256,
    nonce_outer_slot: U256,
}

const SLOT_VALID: u8 = 1 << 0;
const SLOT_BALANCE: u8 = 1 << 1;
const SLOT_RECEIVE_POLICY: u8 = 1 << 2;
const SLOT_NONCE_OUTER: u8 = 1 << 3;

const AUX_SLOT_CACHE_LEN: usize = 1024;
const AUX_SLOT_CACHE_MASK: usize = AUX_SLOT_CACHE_LEN - 1;

#[derive(Debug, Clone, Copy, Default)]
struct AuxSlotEntry {
    addr: Address,
    valid: bool,
    slot: U256,
}

const ALLOWANCE_SLOT_CACHE_LEN: usize = 256;
const ALLOWANCE_SLOT_CACHE_MASK: usize = ALLOWANCE_SLOT_CACHE_LEN - 1;

#[derive(Debug, Clone, Copy, Default)]
struct AllowanceSlotEntry {
    owner: Address,
    spender: Address,
    valid: bool,
    slot: U256,
}

#[doc(hidden)]
#[derive(Debug, Default, Clone)]
pub struct AllowanceSlotCache {
    entries: Option<Box<[AllowanceSlotEntry]>>,
}

impl AllowanceSlotCache {
    #[cold]
    #[inline(never)]
    fn alloc_entries() -> Box<[AllowanceSlotEntry]> {
        vec![AllowanceSlotEntry::default(); ALLOWANCE_SLOT_CACHE_LEN].into_boxed_slice()
    }

    #[inline(never)]
    pub(crate) fn allowance_slot(&mut self, owner: Address, spender: Address) -> U256 {
        let ob = owner.0.0;
        let sb = spender.0.0;
        let h = u64::from_le_bytes([ob[0], ob[1], ob[2], ob[3], ob[16], ob[17], ob[18], ob[19]])
            ^ u64::from_le_bytes([sb[0], sb[1], sb[2], sb[3], sb[16], sb[17], sb[18], sb[19]])
                .rotate_left(17);
        let idx = ((h.wrapping_mul(0x9e3779b97f4a7c15)) >> 56) as usize & ALLOWANCE_SLOT_CACHE_MASK;
        let table = self.entries.get_or_insert_with(Self::alloc_entries);
        let e = &mut table[idx];
        if !e.valid || e.owner != owner || e.spender != spender {
            use tempo_precompiles::storage::StorageKey as _;
            e.owner = owner;
            e.spender = spender;
            e.valid = true;
            e.slot = spender
                .mapping_slot(owner.mapping_slot(tempo_precompiles::tip20::slots::ALLOWANCES));
        }
        e.slot
    }
}

/// Per-EVM direct-mapped cache for frequent account mapping slots.
#[doc(hidden)]
#[derive(Debug, Default, Clone)]
pub struct SenderSlotCache {
    inline_entry: SenderSlotEntry,
    entries: Option<Box<[SenderSlotEntry]>>,
    channel_credit_entries: Option<Box<[AuxSlotEntry]>>,
}

impl SenderSlotCache {
    #[cold]
    #[inline(never)]
    fn promote_to_table(&mut self, addr: Address) -> &mut SenderSlotEntry {
        let mut table = vec![SenderSlotEntry::default(); SENDER_SLOT_CACHE_LEN].into_boxed_slice();
        if (self.inline_entry.flags & SLOT_VALID) != 0 {
            table[Self::idx(self.inline_entry.addr)] = self.inline_entry;
        }
        let table = self.entries.insert(table);
        let e = &mut table[Self::idx(addr)];
        if (e.flags & SLOT_VALID) == 0 || e.addr != addr {
            e.addr = addr;
            e.flags = SLOT_VALID;
        }
        e
    }

    #[cold]
    #[inline(never)]
    fn alloc_aux_entries() -> Box<[AuxSlotEntry]> {
        vec![AuxSlotEntry::default(); AUX_SLOT_CACHE_LEN].into_boxed_slice()
    }

    #[inline]
    fn hash_addr(addr: Address) -> u64 {
        let b = addr.0.0;
        let h = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
            ^ u64::from_le_bytes([b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19]]);
        h.wrapping_mul(0x9e3779b97f4a7c15)
    }

    #[inline]
    fn idx(addr: Address) -> usize {
        (Self::hash_addr(addr) >> 52) as usize & SENDER_SLOT_CACHE_MASK
    }

    #[inline]
    fn entry_for(&mut self, addr: Address) -> &mut SenderSlotEntry {
        if self.entries.is_some() {
            let table = self.entries.as_deref_mut().unwrap();
            let e = &mut table[Self::idx(addr)];
            if (e.flags & SLOT_VALID) == 0 || e.addr != addr {
                e.addr = addr;
                e.flags = SLOT_VALID;
            }
            return e;
        }
        if (self.inline_entry.flags & SLOT_VALID) == 0 {
            self.inline_entry.addr = addr;
            self.inline_entry.flags = SLOT_VALID;
            return &mut self.inline_entry;
        }
        if self.inline_entry.addr == addr {
            return &mut self.inline_entry;
        }
        self.promote_to_table(addr)
    }

    #[inline]
    pub(crate) fn balance_slot(&mut self, addr: Address) -> U256 {
        let e = self.entry_for(addr);
        if (e.flags & SLOT_BALANCE) == 0 {
            use tempo_precompiles::storage::StorageKey as _;
            e.flags |= SLOT_BALANCE;
            e.balance_slot = addr.mapping_slot(tempo_precompiles::tip20::slots::BALANCES);
        }
        e.balance_slot
    }

    #[inline]
    pub(crate) fn balance_and_receive_policy_slots(&mut self, addr: Address) -> (U256, U256) {
        let e = self.entry_for(addr);
        if (e.flags & SLOT_BALANCE) == 0 {
            use tempo_precompiles::storage::StorageKey as _;
            e.flags |= SLOT_BALANCE;
            e.balance_slot = addr.mapping_slot(tempo_precompiles::tip20::slots::BALANCES);
        }
        if (e.flags & SLOT_RECEIVE_POLICY) == 0 {
            use tempo_precompiles::storage::StorageKey as _;
            e.flags |= SLOT_RECEIVE_POLICY;
            e.receive_policy_slot =
                addr.mapping_slot(tempo_precompiles::tip403_registry::slots::RECEIVE_POLICIES);
        }
        (e.balance_slot, e.receive_policy_slot)
    }

    #[inline]
    pub(crate) fn nonce_outer_slot(&mut self, addr: Address) -> U256 {
        let e = self.entry_for(addr);
        if (e.flags & SLOT_NONCE_OUTER) == 0 {
            use tempo_precompiles::storage::StorageKey as _;
            e.flags |= SLOT_NONCE_OUTER;
            e.nonce_outer_slot = addr.mapping_slot(tempo_precompiles::nonce::slots::NONCES);
        }
        e.nonce_outer_slot
    }

    #[inline(never)]
    pub(crate) fn channel_credit_slot(&mut self, payer: Address) -> U256 {
        let idx = (Self::hash_addr(payer) >> 54) as usize & AUX_SLOT_CACHE_MASK;
        let table = self
            .channel_credit_entries
            .get_or_insert_with(Self::alloc_aux_entries);
        let e = &mut table[idx];
        if !e.valid || e.addr != payer {
            use tempo_precompiles::storage::StorageKey as _;
            e.addr = payer;
            e.valid = true;
            e.slot = payer.mapping_slot(
                tempo_precompiles::tip20_channel_reserve::slots::CHANNEL_STORAGE_CREDITS,
            );
        }
        e.slot
    }
}

/// Caches beneficiary-keyed `TipFeeManager` mapping slots across transactions in a block.
#[doc(hidden)]
#[derive(Debug, Default, Clone)]
pub struct FeeSlotCache {
    beneficiary: Option<Address>,
    validator_token_slot: U256,
    collected_fees_outer_slot: U256,
    collected_fees_slots: [(Address, U256); 4],
    collected_fees_len: usize,
    token_policy_slots: [(Address, U256); 8],
    token_policy_len: usize,
}

impl FeeSlotCache {
    #[inline]
    fn ensure_beneficiary(&mut self, beneficiary: Address) {
        if self.beneficiary != Some(beneficiary) {
            use tempo_precompiles::{storage::StorageKey as _, tip_fee_manager::slots};
            self.beneficiary = Some(beneficiary);
            self.validator_token_slot = beneficiary.mapping_slot(slots::VALIDATOR_TOKENS);
            self.collected_fees_outer_slot = beneficiary.mapping_slot(slots::COLLECTED_FEES);
            self.collected_fees_len = 0;
        }
    }

    #[inline]
    pub(crate) fn validator_token_slot(&mut self, beneficiary: Address) -> U256 {
        self.ensure_beneficiary(beneficiary);
        self.validator_token_slot
    }

    #[inline]
    pub(crate) fn collected_fees_slot(&mut self, beneficiary: Address, token: Address) -> U256 {
        self.ensure_beneficiary(beneficiary);
        for &(cached_token, cached_slot) in &self.collected_fees_slots[..self.collected_fees_len] {
            if cached_token == token {
                return cached_slot;
            }
        }
        use tempo_precompiles::storage::StorageKey as _;
        let slot = token.mapping_slot(self.collected_fees_outer_slot);
        if self.collected_fees_len < self.collected_fees_slots.len() {
            self.collected_fees_slots[self.collected_fees_len] = (token, slot);
            self.collected_fees_len += 1;
        }
        slot
    }

    #[inline]
    pub(crate) fn token_transfer_policy_slot(&mut self, token: Address) -> U256 {
        for &(cached_token, cached_slot) in &self.token_policy_slots[..self.token_policy_len] {
            if cached_token == token {
                return cached_slot;
            }
        }
        use tempo_precompiles::{storage::StorageKey as _, tip403_registry::slots};
        let slot = token.mapping_slot(slots::TOKEN_TRANSFER_POLICIES);
        if self.token_policy_len < self.token_policy_slots.len() {
            self.token_policy_slots[self.token_policy_len] = (token, slot);
            self.token_policy_len += 1;
        }
        slot
    }
}

impl Default for TempoEvmExt {
    fn default() -> Self {
        Self::new(TempoEvmKind::L1, TempoFeeManager::new())
    }
}

impl TempoEvmExt {
    /// Creates the extension state of an EVM of `kind`, whose transaction hooks collect fees
    /// through `fee_manager`.
    pub fn new<F: ProtocolFeeManager + 'static>(kind: TempoEvmKind, fee_manager: F) -> Self {
        let fee_manager = if TypeId::of::<F>() == TypeId::of::<TempoFeeManager>() {
            Arc::clone(&DEFAULT_FEE_MANAGER)
        } else {
            Arc::new(fee_manager)
        };
        Self {
            kind,
            fee_manager,
            actions: StorageActions::disabled(),
            non_creditable_slots: Rc::new(RefCell::new(NonCreditableSlots::empty())),
            skip_valid_after_check: false,
            skip_liquidity_check: false,
            resolved_fee_token: None,
            key_expiry: None,
            resolved_fee_payer: Address::ZERO,
            resolved_fee_balance_slot: U256::ZERO,
            has_two_hop_intermediate: false,
            fee_slot_cache: FeeSlotCache::default(),
            sender_slot_cache: SenderSlotCache::default(),
            allowance_slot_cache: AllowanceSlotCache::default(),
            tx_transient_seeds: TxTransientSeeds::default(),
            batch_state_hook: false,
        }
    }

    #[inline]
    pub(crate) fn on_storage_credits_tstore(&mut self, address: Address, key: U256, value: U256) {
        self.tx_transient_seeds.on_tstore(address, key, value);
    }
}

impl tempo_precompiles::storage::evm::EvmStorageExt for TempoEvmExt {
    fn storage_actions(&self) -> StorageActions {
        self.actions.clone()
    }

    fn non_creditable_slots(&self) -> Rc<RefCell<NonCreditableSlots>> {
        self.non_creditable_slots.clone()
    }

    fn kind(&self) -> TempoEvmKind {
        self.kind
    }

    #[inline]
    fn resolved_fee_balance_slot(&self, addr: Address) -> Option<U256> {
        (addr == self.resolved_fee_payer && !self.resolved_fee_balance_slot.is_zero())
            .then_some(self.resolved_fee_balance_slot)
    }

    #[inline]
    fn cached_balance_slot(&mut self, addr: Address) -> U256 {
        self.sender_slot_cache.balance_slot(addr)
    }

    #[inline]
    fn cached_token_transfer_policy_slot(&mut self, token: Address) -> U256 {
        self.fee_slot_cache.token_transfer_policy_slot(token)
    }

    #[inline]
    fn cached_balance_and_receive_policy_slots(&mut self, addr: Address) -> (U256, U256) {
        self.sender_slot_cache
            .balance_and_receive_policy_slots(addr)
    }

    #[inline]
    fn cached_allowance_slot(&mut self, owner: Address, spender: Address) -> U256 {
        self.allowance_slot_cache.allowance_slot(owner, spender)
    }

    #[inline]
    fn cached_channel_credit_slot(&mut self, payer: Address) -> U256 {
        self.sender_slot_cache.channel_credit_slot(payer)
    }

    #[inline]
    fn maybe_has_transaction_key(&self) -> bool {
        self.tx_transient_seeds.has_transaction_key
    }

    #[inline]
    fn maybe_has_opened_channel(&self) -> bool {
        self.tx_transient_seeds.has_opened_channel
    }

    #[inline]
    fn transient_seed(&self, address: Address, key: U256) -> Option<U256> {
        self.tx_transient_seeds.get(address, key)
    }

    #[inline]
    fn on_tstore(&mut self, address: Address, key: U256, value: U256) {
        self.tx_transient_seeds.on_tstore(address, key, value);
    }
}

/// Builds an EVM2 execution config for Tempo's ERC-20 fee model.
pub fn tempo_execution_config(
    tempo_spec: TempoHardfork,
    chain_id: u64,
) -> ExecutionConfig<TempoEvmTypes> {
    let spec_id = SpecId::from(tempo_spec);
    let mut version = tempo_chainspec::gas_params::version(spec_id, tempo_spec, false);
    version.chain_id = chain_id;
    version.features.remove(EvmFeatures::BALANCE_CHECK);
    version.features.remove(EvmFeatures::BALANCE_TOP_UP);
    ExecutionConfig::for_spec_and_version(tempo_spec, version)
}

/// Builds a Tempo-configured EVM2 instance.
pub fn build_tempo_evm<'a>(
    tempo_spec: TempoHardfork,
    chain_id: u64,
    block: TempoBlockEnv,
    database: impl DynDatabase + 'a,
    precompiles: impl PrecompileProvider<TempoEvmTypes> + 'a,
    ext: TempoEvmExt,
) -> Evm<'a, TempoEvmTypes> {
    let spec_id = SpecId::from(tempo_spec);
    let execution_config = tempo_execution_config(tempo_spec, chain_id);
    Evm::new_with_execution_config_and_ext(
        execution_config,
        tempo_spec,
        block,
        tempo_tx_registry(spec_id),
        database,
        precompiles,
        ext,
    )
}

#[derive(Clone, Copy, Debug)]
pub(super) struct TempoFeeContext {
    pub(super) fee_payer: alloy_primitives::Address,
    pub(super) fee_token: alloy_primitives::Address,
    pub(super) fee_payer_balance_slot: U256,
    pub(super) collected: U256,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct TempoHandlerHooks;

impl TxHandlerHooks<TempoEvmTypes> for TempoHandlerHooks {
    fn adjust_intrinsic_gas(
        host: &mut Evm<'_, TempoEvmTypes>,
        envelope: &TempoTxEnv,
        intrinsic: &mut u64,
        initial_state_gas: &mut u64,
        _floor_gas: &mut u64,
    ) -> HandlerResult<()> {
        if !host.config_spec_id().is_t1() {
            return Ok(());
        }

        let (nonce, zero_nonce_authorizations) = match envelope.evm_tx() {
            TempoEvmTx::Legacy { transaction, .. } => (transaction.nonce, 0),
            TempoEvmTx::Eip2930(transaction) => (transaction.nonce, 0),
            TempoEvmTx::Eip1559(transaction) => (transaction.nonce, 0),
            TempoEvmTx::Eip7702(transaction) => (
                transaction.nonce,
                transaction
                    .authorizations()
                    .filter(|authorization| authorization.nonce() == 0)
                    .count() as u64,
            ),
            TempoEvmTx::AA(_) => return Ok(()),
        };
        // T14 root-key checks: a configurable account's primitive key no longer signs. A
        // sender-only check charges no gas.
        let spec = host.config_spec_id();
        // Non-AA transactions have no configurable roles, so validation charges no state gas.
        let (validation_gas, _) = configurable_account::validate_state(host, envelope, spec)?;
        let new_accounts = zero_nonce_authorizations.saturating_add(u64::from(nonce == 0));
        *intrinsic = intrinsic.saturating_add(validation_gas);
        *intrinsic = intrinsic.saturating_add(
            new_accounts.saturating_mul(host.version().gas_params.get(GasId::NewAccountCost)),
        );
        *initial_state_gas = initial_state_gas.saturating_add(
            new_accounts.saturating_mul(host.version().gas_params.new_account_state_gas()),
        );
        Ok(())
    }

    fn before_execution(
        host: &mut Evm<'_, TempoEvmTypes>,
        envelope: &TempoTxEnv,
        _caller: Address,
        _upfront_fee: U256,
    ) -> HandlerResult<()> {
        let context = Self::resolve_fee_context(host, envelope)?;
        if host.feature(EvmFeatures::FEE_CHARGE) {
            Self::collect_fee(host, context, None)?;
        }
        Ok(())
    }

    fn settle_transaction(
        host: &mut Evm<'_, TempoEvmTypes>,
        _envelope: &TempoTxEnv,
        mut gas: GasSettlement<TempoEvmTypes>,
    ) -> HandlerResult<TxResult<TempoEvmTypes>> {
        settle_storage_credit_refunds(host, &mut gas.result)?;
        let gas_price = u128::try_from(gas.gas_price)
            .map_err(|_| HandlerError::Fatal("effective gas price does not fit u128".into()))?;
        let gas_limit = gas.gas_limit;
        // A net-negative refund counter refunds the full cap: one fifth of gas used before T7,
        // all of it from T7, where gas used falls to the calldata floor.
        if gas.result.gas.refunded() < 0 {
            gas.result.gas.set_refunded(i64::MAX);
        }
        let mut result = finalize_gas(host, gas)?;
        if !host.feature(EvmFeatures::FEE_CHARGE) {
            host.ext_mut().tx_transient_seeds.clear();
            return Ok(result);
        }
        let actual_spending = calc_gas_balance_spending(result.tx_gas_used(), gas_price);
        let collected = calc_gas_balance_spending(gas_limit, gas_price);
        let refund = collected
            .checked_sub(actual_spending)
            .ok_or_else(|| HandlerError::Fatal("actual fee exceeds upfront fee".into()))?;

        if collected.is_zero() && !actual_spending.is_zero() {
            host.ext_mut().tx_transient_seeds.clear();
            return Ok(result);
        }

        let fee_token = host
            .ext()
            .resolved_fee_token
            .ok_or_else(|| {
                HandlerError::Fatal("fee token was not resolved before settlement".into())
            })?
            .address();
        let fee_payer = host.ext().resolved_fee_payer;
        let beneficiary = host.block().beneficiary;
        let validator_fee = if actual_spending.is_zero() && refund.is_zero() {
            U256::ZERO
        } else if is_default_fee_manager(&host.ext().fee_manager) {
            TempoFeeManager.collect_fee_post_tx(
                ProtocolFeeContext { host },
                fee_payer,
                actual_spending,
                refund,
                fee_token,
                beneficiary,
            )?
        } else {
            let fee_manager = host.ext().fee_manager.clone();
            fee_manager.collect_fee_post_tx(
                ProtocolFeeContext { host },
                fee_payer,
                actual_spending,
                refund,
                fee_token,
                beneficiary,
            )?
        };
        host.ext_mut().tx_transient_seeds.clear();
        result.ext.validator_fee = validator_fee;
        Ok(result)
    }
}

impl TempoHandlerHooks {
    pub(super) fn resolve_fee_context(
        host: &mut Evm<'_, TempoEvmTypes>,
        envelope: &TempoTxEnv,
    ) -> HandlerResult<TempoFeeContext> {
        host.ext_mut().resolved_fee_token = None;
        host.ext_mut().key_expiry = None;
        host.ext().non_creditable_slots.borrow_mut().clear();
        let fee_payer = envelope
            .fee_payer()
            .map_err(|_| TempoInvalidTransaction::InvalidFeePayerSignature)?;
        let base_fee = u64::try_from(host.block().basefee)
            .map_err(|_| HandlerError::Fatal("block base fee does not fit u64".into()))?;
        let gas_price = envelope.evm_tx().effective_gas_price(Some(base_fee));
        let collected = if host.feature(EvmFeatures::FEE_CHARGE) {
            calc_gas_balance_spending(envelope.evm_tx().gas_limit(), gas_price)
        } else {
            U256::ZERO
        };
        let max_fee =
            calc_gas_balance_spending(envelope.evm_tx().gas_limit(), envelope.max_fee_per_gas());
        let spec = host.config_spec_id();

        {
            let origin_word = envelope.evm_tx().signer().to_word();
            let context_hash_word = envelope.channel_open_context_hash().to_word();
            host.ext_mut()
                .tx_transient_seeds
                .seed_base(origin_word, context_hash_word);
            if spec.is_t14() {
                envelope.seed_upgrade_authority_on_evm(host)?;
            }
        }

        let use_default_fm = is_default_fee_manager(&host.ext().fee_manager);
        let fee_manager = (!use_default_fm).then(|| host.ext().fee_manager.clone());
        let resolved_fee_token = if let Some(fm) = fee_manager.as_ref() {
            fm.get_fee_token(host, envelope, fee_payer, max_fee, spec)
        } else {
            TempoFeeManager.get_fee_token(host, envelope, fee_payer, max_fee, spec)
        }
        .map_err(|error| match error {
            TempoPrecompileError::TIP20(TIP20Error::InsufficientBalance(error)) => {
                TempoInvalidTransaction::from(FeePaymentError::InsufficientFeeTokenBalance {
                    fee: error.required,
                    balance: error.available,
                })
                .into()
            }
            error => HandlerError::from(error),
        })?;
        host.ext_mut().resolved_fee_token = Some(resolved_fee_token);
        let fee_token = resolved_fee_token.address();
        if !fee_token.is_tip20() {
            return Err(TempoInvalidTransaction::FeeTokenNotTip20 { address: fee_token }.into());
        }
        let fee_payer_balance_slot = host.ext_mut().sender_slot_cache.balance_slot(fee_payer);
        host.ext_mut().resolved_fee_payer = fee_payer;
        host.ext_mut().resolved_fee_balance_slot = fee_payer_balance_slot;
        host.ext_mut().has_two_hop_intermediate = false;
        let balance = if let Some(fm) = fee_manager.as_ref() {
            fm.validate_and_load_fee_balance(
                host,
                fee_token,
                fee_payer_balance_slot,
                max_fee,
                spec,
            )?
        } else {
            TempoFeeManager.validate_and_load_fee_balance(
                host,
                fee_token,
                fee_payer_balance_slot,
                max_fee,
                spec,
            )?
        };
        if host.feature(EvmFeatures::FEE_CHARGE) && balance < max_fee {
            return Err(TempoInvalidTransaction::from(
                FeePaymentError::InsufficientFeeTokenBalance {
                    fee: max_fee,
                    balance,
                },
            )
            .into());
        }

        Ok(TempoFeeContext {
            fee_payer,
            fee_token,
            fee_payer_balance_slot,
            collected,
        })
    }

    pub(super) fn collect_fee(
        host: &mut Evm<'_, TempoEvmTypes>,
        context: TempoFeeContext,
        key_id: Option<Address>,
    ) -> HandlerResult<()> {
        let checkpoint = host.state().checkpoint();
        let features = host.version().features;
        let beneficiary = host.block().beneficiary;
        let skip_liquidity_check = host.ext().skip_liquidity_check;
        let use_default_fm = is_default_fee_manager(&host.ext().fee_manager);
        let pre_res = if context.collected.is_zero() {
            Ok(Address::ZERO)
        } else if use_default_fm {
            TempoFeeManager.collect_fee_pre_tx(
                ProtocolFeeContext { host },
                context.fee_payer,
                context.fee_token,
                context.collected,
                beneficiary,
                skip_liquidity_check,
            )
        } else {
            let fee_manager = host.ext().fee_manager.clone();
            fee_manager.collect_fee_pre_tx(
                ProtocolFeeContext { host },
                context.fee_payer,
                context.fee_token,
                context.collected,
                beneficiary,
                skip_liquidity_check,
            )
        };
        if let Err(error) = pre_res {
            host.state_mut().rollback(checkpoint, features);
            return Err(match error {
                TempoPrecompileError::TIPFeeAMMError(TIPFeeAMMError::InsufficientLiquidity(_)) => {
                    let validator_token = if use_default_fm {
                        TempoFeeManager.get_validator_token(host, beneficiary).ok()
                    } else {
                        let fee_manager = host.ext().fee_manager.clone();
                        fee_manager.get_validator_token(host, beneficiary).ok()
                    };
                    TempoInvalidTransaction::from(FeePaymentError::InsufficientAmmLiquidity {
                        user_token: validator_token.map(|_| context.fee_token),
                        validator_token,
                        fee: context.collected,
                    })
                    .into()
                }
                TempoPrecompileError::TIP20(TIP20Error::InsufficientBalance(error)) => {
                    TempoInvalidTransaction::from(FeePaymentError::InsufficientFeeTokenBalance {
                        fee: context.collected,
                        balance: error.available,
                    })
                    .into()
                }
                TempoPrecompileError::TIP20(TIP20Error::ContractPaused(_)) => {
                    TempoInvalidTransaction::FeeTokenPaused {
                        address: context.fee_token,
                    }
                    .into()
                }
                TempoPrecompileError::Database(error) => HandlerError::Database(error),
                TempoPrecompileError::Fatal(error) => HandlerError::Fatal(error.into()),
                error => {
                    TempoInvalidTransaction::from(FeePaymentError::Other(error.to_string())).into()
                }
            });
        }

        if host.config_spec_id().is_t7() && !context.collected.is_zero() {
            host.ext()
                .non_creditable_slots
                .borrow_mut()
                .initialize_with_slot(
                    context.fee_payer,
                    context.fee_token,
                    key_id,
                    context.fee_payer_balance_slot,
                );
        }

        Ok(())
    }
}

fn settle_storage_credit_refunds(
    host: &mut Evm<'_, TempoEvmTypes>,
    result: &mut evm2::interpreter::MessageResult<TempoEvmTypes>,
) -> HandlerResult<()> {
    if !host.config_spec_id().is_t7()
        || !result.is_success()
        || !host.ext().tx_transient_seeds.has_storage_credit_refunds
    {
        return Ok(());
    }

    let slots = host
        .state_mut()
        .take_transient_storage(&STORAGE_CREDITS_ADDRESS);
    if slots.is_empty() {
        return Ok(());
    }

    let settled = StorageCtx::enter_evm_without_tip1060_accounting(host, || {
        let mut storage = StorageCtx;
        let mut settled = 0i64;
        for (key, word) in slots {
            let state = TransientState::try_from(word)?;
            if state.pending_refunds == 0 {
                continue;
            }

            let old_word = storage.sload(STORAGE_CREDITS_ADDRESS, key)?;
            let mut balance = u64::from_word(old_word)?;
            let credits = state.pending_refunds.min(balance);
            if credits == 0 {
                continue;
            }

            balance -= credits;
            settled = settled.saturating_add(credits as i64);
            let new_word = U256::from(balance);
            debug_assert_ne!(new_word, old_word);
            storage.sstore(STORAGE_CREDITS_ADDRESS, key, new_word)?;
        }
        Ok::<_, TempoPrecompileError>(settled)
    })?;
    result
        .gas
        .record_refund(settled.saturating_mul(STORAGE_CREDIT_VALUE as i64));
    Ok(())
}

enum PreparedLegacy {
    System,
    Transaction(PreparedTx),
}

fn prepare_legacy(
    request: &mut TxRequest<'_, '_, TempoEvmTypes, TxLegacy>,
) -> HandlerResult<PreparedLegacy> {
    validate_no_native_value(request.envelope)?;
    if request.envelope.evm_tx().is_system_tx() {
        if !matches!(request.tx.to, TxKind::Call(_)) {
            return Err(TempoInvalidTransaction::SystemTransactionMustBeCall.into());
        }
        return Ok(PreparedLegacy::System);
    }
    legacy::prepare_with_hooks::<TempoEvmTypes, TempoHandlerHooks>(request)
        .map(PreparedLegacy::Transaction)
}

fn execute_legacy(
    request: TxRequest<'_, '_, TempoEvmTypes, TxLegacy>,
    prepared: PreparedLegacy,
) -> HandlerResult<TxResult<TempoEvmTypes>> {
    match prepared {
        PreparedLegacy::Transaction(prepared) => {
            legacy::execute_prepared::<TempoEvmTypes, TempoHandlerHooks>(request, prepared)
        }
        PreparedLegacy::System => {
            let tx = request.tx.inner();
            let TxKind::Call(to) = tx.to else {
                unreachable!("system transaction kind was validated during preparation");
            };
            let mut result = request.host.execute_system_call(
                SystemTx::new(to, tx.input.clone())
                    .with_caller(request.tx.signer())
                    .with_gas_limit(SYSTEM_CALL_GAS_LIMIT),
            )?;
            if !result.status {
                return Err(TempoInvalidTransaction::SystemTransactionFailed(format!(
                    "{:?}",
                    result.stop
                ))
                .into());
            }
            result.total_gas_spent = 0;
            result.state_gas_spent = 0;
            result.refunded = 0;
            Ok(result)
        }
    }
}

fn prepare_eip2930(
    request: &mut TxRequest<'_, '_, TempoEvmTypes, TxEip2930>,
) -> HandlerResult<PreparedTx> {
    validate_no_native_value(request.envelope)?;
    eip2930::prepare_with_hooks::<TempoEvmTypes, TempoHandlerHooks>(request)
}

fn prepare_eip1559(
    request: &mut TxRequest<'_, '_, TempoEvmTypes, TxEip1559>,
) -> HandlerResult<PreparedTx> {
    validate_no_native_value(request.envelope)?;
    eip1559::prepare_with_hooks::<TempoEvmTypes, TempoHandlerHooks>(request)
}

fn prepare_eip7702(
    request: &mut TxRequest<'_, '_, TempoEvmTypes, LazyTxEip7702>,
) -> HandlerResult<PreparedTx> {
    validate_no_native_value(request.envelope)?;
    eip7702::prepare_with_hooks::<TempoEvmTypes, TempoHandlerHooks>(request)
}

fn validate_no_native_value(envelope: &TempoTxEnv) -> Result<(), TempoInvalidTransaction> {
    if envelope.value().is_zero() {
        Ok(())
    } else {
        Err(TempoInvalidTransaction::ValueTransferNotAllowed)
    }
}

/// Returns the Tempo transaction registry for `spec_id`.
pub fn tempo_tx_registry(spec_id: SpecId) -> TxRegistry<TempoEvmTypes, TxResult<TempoEvmTypes>> {
    let mut registry = TxRegistry::new().with_handler(
        0,
        TempoTxEnv::as_legacy,
        handler(prepare_legacy, execute_legacy),
    );

    if spec_id.enables(SpecId::BERLIN) {
        registry.register(
            1,
            TempoTxEnv::as_eip2930,
            handler(
                prepare_eip2930,
                eip2930::execute_prepared::<TempoEvmTypes, TempoHandlerHooks>,
            ),
        );
    }
    if spec_id.enables(SpecId::LONDON) {
        registry.register(
            2,
            TempoTxEnv::as_eip1559,
            handler(
                prepare_eip1559,
                eip1559::execute_prepared::<TempoEvmTypes, TempoHandlerHooks>,
            ),
        );
    }
    if spec_id.enables(SpecId::PRAGUE) {
        registry.register(
            4,
            TempoTxEnv::as_eip7702,
            handler(
                prepare_eip7702,
                eip7702::execute_prepared::<TempoEvmTypes, TempoHandlerHooks>,
            ),
        );
    }
    registry.register(
        0x76,
        TempoTxEnv::as_aa,
        handler(super::prepare_aa, super::execute_aa),
    );

    registry
}
