use super::replay::Slots;
use alloy_primitives::{Address, B256, LogData, U256, keccak256};
use revm::{
    context::journaled_state::JournalCheckpoint,
    state::{AccountInfo, Bytecode},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{
    error::TempoPrecompileError,
    storage::{PrecompileStorageProvider, hashmap::HashMapStorageProvider},
};
use tempo_primitives::TempoBlockEnv;

pub(super) struct ReplayStorage {
    pub slots: Slots,
    pub env: HashMapStorageProvider,
}
impl ReplayStorage {
    pub(super) fn new(chain_id: u64, slots: Slots) -> Self {
        Self {
            slots,
            env: HashMapStorageProvider::new(chain_id),
        }
    }
}
impl PrecompileStorageProvider for ReplayStorage {
    fn sload(&mut self, _address: Address, key: U256) -> Result<U256, TempoPrecompileError> {
        Ok(self
            .slots
            .get(&keccak256(key.to_be_bytes::<32>()))
            .copied()
            .unwrap_or_default())
    }
    fn sstore(
        &mut self,
        _address: Address,
        key: U256,
        value: U256,
    ) -> Result<(), TempoPrecompileError> {
        let key = keccak256(key.to_be_bytes::<32>());
        if value.is_zero() {
            self.slots.remove(&key);
        } else {
            self.slots.insert(key, value);
        }
        Ok(())
    }
    fn chain_id(&self) -> u64 {
        self.env.chain_id()
    }
    fn block_env(&self) -> &TempoBlockEnv {
        self.env.block_env()
    }
    fn set_code(&mut self, address: Address, code: Bytecode) -> Result<(), TempoPrecompileError> {
        self.env.set_code(address, code)
    }
    fn with_account_info(
        &mut self,
        address: Address,
        f: &mut dyn FnMut(&AccountInfo),
    ) -> Result<(), TempoPrecompileError> {
        self.env.with_account_info(address, f)
    }
    fn account_code(&mut self, address: Address) -> Result<(B256, Bytecode), TempoPrecompileError> {
        self.env.account_code(address)
    }
    fn tstore(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
    ) -> Result<(), TempoPrecompileError> {
        self.env.tstore(address, key, value)
    }
    fn emit_event(&mut self, address: Address, event: LogData) -> Result<(), TempoPrecompileError> {
        self.env.emit_event(address, event)
    }
    fn tload(&mut self, address: Address, key: U256) -> Result<U256, TempoPrecompileError> {
        self.env.tload(address, key)
    }
    fn deduct_gas(&mut self, _gas: u64) -> Result<(), TempoPrecompileError> {
        self.env.deduct_gas(_gas)
    }
    fn refund_gas(&mut self, _gas: i64) {
        self.env.refund_gas(_gas)
    }
    fn gas_limit(&self) -> u64 {
        self.env.gas_limit()
    }
    fn gas_used(&self) -> u64 {
        self.env.gas_used()
    }
    fn state_gas_used(&self) -> u64 {
        self.env.state_gas_used()
    }
    fn state_gas_spilled(&self) -> u64 {
        self.env.state_gas_spilled()
    }
    fn gas_refunded(&self) -> i64 {
        self.env.gas_refunded()
    }
    fn reservoir(&self) -> u64 {
        self.env.reservoir()
    }
    fn spec(&self) -> TempoHardfork {
        self.env.spec()
    }
    fn amsterdam_eip8037_enabled(&self) -> bool {
        self.env.amsterdam_eip8037_enabled()
    }
    fn is_static(&self) -> bool {
        self.env.is_static()
    }
    fn checkpoint(&mut self) -> JournalCheckpoint {
        unreachable!("nonce replay does not use checkpoints")
    }
    fn checkpoint_commit(&mut self, _checkpoint: JournalCheckpoint) {
        unreachable!("nonce replay does not use checkpoints")
    }
    fn checkpoint_revert(&mut self, _checkpoint: JournalCheckpoint) {
        unreachable!("nonce replay does not use checkpoints")
    }
    fn set_tip1060_storage_credits(&mut self, enabled: bool) {
        self.env.set_tip1060_storage_credits(enabled)
    }
}
