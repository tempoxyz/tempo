//! Signed transaction integration fixtures for the T14 account-leaf protocol.
use alloy_primitives::B256;
use evm2::evm::InMemoryDB;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::CONFIGURABLE_ACCOUNT_ADDRESS;

mod tests;
