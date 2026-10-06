//! TIP-1060 specific implementations.

use crate::{
    TempoInvalidTransaction,
    evm::{TempoContext, TempoEvm},
};
use alloy_evm::Database;
use alloy_primitives::{Address, U256};
use revm::{
    context::{Host as _, JournalTr, result::EVMError},
    context_interface::cfg::GasParams,
    interpreter::{
        Gas, InstructionContext, InstructionResult, StateLoad,
        gas::GasTracker,
        instructions::host::{sstore_default_gas_accounting, sstore_with_gas_accounting},
        interpreter::EthInterpreter,
    },
};
use tempo_chainspec::constants::gas::STORAGE_CREDIT_VALUE;
use tempo_precompiles::{
    STORAGE_CREDITS_ADDRESS,
    storage::{FromWord, SstoreTransitionFlags, StorageAction, access},
    storage_credits::{StorageCreditsBackend, TransientState, sstore_storage_credits},
};

/// Applies storage-credit settlement at the end of a transaction.
///
/// During execution, each account's transaction-local mode and pending `Refund` creations are
/// stored in one transient word at the same key as its persistent balance. At end-of-transaction,
/// entries with non-zero pending creations are settled against the same account's persistent
/// storage credit balance, consuming up to `min(pending, balance)` credits and refunding one fixed
/// storage credit value per credit. Mode-only transient entries are ignored.
pub fn apply_refund<DB: Database, I>(
    evm: &mut TempoEvm<DB, I>,
    gas: &mut Gas,
) -> Result<(), EVMError<DB::Error, TempoInvalidTransaction>> {
    if !evm.cfg.spec.is_t7() {
        return Ok(());
    }

    let journal = &mut evm.inner.ctx.journaled_state;

    // Take the tx-local storage-credit slots so we can settle them while mutating the journal.
    let Some(slots) = journal.transient_storage.remove(&STORAGE_CREDITS_ADDRESS) else {
        return Ok(());
    };

    let mut refunds = 0i64;
    for (key, word) in slots {
        let transient_state =
            TransientState::try_from(word).map_err(|err| EVMError::Custom(err.to_string()))?;
        let pending = transient_state.pending_refunds;
        if pending == 0 {
            continue;
        }

        // SLOAD the current persistent balance and settle pending refund-eligible creations against it.
        let old_word = journal.sload(STORAGE_CREDITS_ADDRESS, key)?.data;
        evm.actions
            .record(StorageAction::Sload(STORAGE_CREDITS_ADDRESS, key, old_word));
        let mut balance =
            u64::from_word(old_word).map_err(|err| EVMError::Custom(err.to_string()))?;
        let settled = pending.min(balance);

        if settled == 0 {
            continue;
        }

        // SSTORE the post-settlement balance back into persistent storage.
        balance -= settled;
        refunds += settled as i64;

        let new_word = U256::from(balance);
        debug_assert_ne!(new_word, old_word);

        journal.sstore(STORAGE_CREDITS_ADDRESS, key, new_word)?;
        evm.actions.record(StorageAction::Sstore(
            STORAGE_CREDITS_ADDRESS,
            key,
            old_word,
            new_word,
        ));
    }

    // Refund storage credit value per settled credit.
    gas.record_refund(refunds.saturating_mul(STORAGE_CREDIT_VALUE as i64));

    Ok(())
}

/// Opcode-level [`StorageCreditsBackend`] adapter over an [`InstructionContext`].
///
/// Bridges the revm host/interpreter to the backend-agnostic [`sstore_storage_credits`] so the
/// SSTORE opcode runs the same TIP-1060 storage credits policy as precompile storage writes.
struct StorageCreditsContext<'a, DB: Database> {
    context: &'a mut TempoContext<DB>,
    gas_tracker: &'a mut GasTracker,
}

impl<DB: Database> StorageCreditsBackend for StorageCreditsContext<'_, DB> {
    type Error = InstructionResult;

    #[inline]
    fn gas_params(&self) -> &GasParams {
        self.context.gas_params()
    }

    #[inline]
    fn gas_tracker(&mut self) -> &mut GasTracker {
        self.gas_tracker
    }

    #[inline]
    fn sload(
        &mut self,
        address: Address,
        key: U256,
        skip_cold_load: bool,
    ) -> Result<StateLoad<U256>, Self::Error> {
        access::storage(address, key);
        self.context
            .load_account_info_skip_cold_load(address, false, false)?;
        Ok(self
            .context
            .sload_skip_cold_load(address, key, skip_cold_load)?)
    }

    #[inline]
    fn sstore(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
        skip_cold_load: bool,
    ) -> Result<SstoreTransitionFlags, Self::Error> {
        access::storage(address, key);
        Ok(self
            .context
            .sstore_skip_cold_load(address, key, value, skip_cold_load)?
            .into())
    }

    #[inline]
    fn tload(&mut self, address: Address, key: U256) -> U256 {
        self.context.tload(address, key)
    }

    #[inline]
    fn tstore(&mut self, address: Address, key: U256, value: U256) -> Result<(), Self::Error> {
        self.context.tstore(address, key, value);
        Ok(())
    }
}

/// Tempo SSTORE instruction with TIP-1060 storage-credit accounting.
pub(crate) fn sstore<DB: Database>(
    context: InstructionContext<'_, TempoContext<DB>, EthInterpreter>,
) -> Result<(), InstructionResult> {
    sstore_with_gas_accounting(context, |context, owner, state_load| {
        {
            let InstructionContext { interpreter, host } = context;
            sstore_storage_credits(
                &mut StorageCreditsContext {
                    context: host,
                    gas_tracker: interpreter.gas.tracker_mut(),
                },
                owner,
                None,
                state_load,
            )?;
        }

        // Storage-credit hook only handles TIP-1060 bookkeeping + state gas. Keep default
        // gas/refunds for cold, update, and residual costs. T7 gas table ensures no double-charge.
        sstore_default_gas_accounting(context, owner, state_load)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use revm::{
        Context, MainContext,
        context::CfgEnv,
        state::{Account, AccountInfo, Bytecode, EvmStorageSlot},
    };
    use std::convert::Infallible;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_precompiles::storage_credits::StorageCredits;

    /// A cached journal access must not fall through to a database recorder.
    #[derive(Debug)]
    struct NoDatabaseReads;

    impl revm::Database for NoDatabaseReads {
        type Error = Infallible;

        fn basic(&mut self, _address: Address) -> Result<Option<AccountInfo>, Self::Error> {
            panic!("credit account must already be in the journal")
        }

        fn code_by_hash(&mut self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
            panic!("credit access must not load code")
        }

        fn storage(&mut self, _address: Address, _key: U256) -> Result<U256, Self::Error> {
            panic!("credit slot must already be in the journal")
        }

        fn block_hash(&mut self, _number: u64) -> Result<B256, Self::Error> {
            panic!("credit access must not load a block hash")
        }
    }

    fn preloaded_credit_context(cold: bool) -> (TempoContext<NoDatabaseReads>, U256) {
        let mut context: TempoContext<NoDatabaseReads> = Context::mainnet()
            .with_db(NoDatabaseReads)
            .with_block(Default::default())
            .with_cfg(CfgEnv::new_with_spec_and_gas_params(
                TempoHardfork::T14,
                crate::gas_params::tempo_gas_params(TempoHardfork::T14),
            ))
            .with_tx(Default::default());
        let key = StorageCredits::slot(Address::with_last_byte(41));
        let transaction_id = context.journaled_state.transaction_id;
        let mut slot = EvmStorageSlot::new(U256::from(7), transaction_id);
        if cold {
            slot.mark_cold();
        }
        let mut account = Account::default();
        account.transaction_id = transaction_id;
        account.storage.insert(key, slot);
        context
            .journaled_state
            .state
            .insert(STORAGE_CREDITS_ADDRESS, account);
        (context, key)
    }

    #[test]
    fn opcode_credit_accesses_record_preloaded_slots_without_database_reads() {
        for cold in [false, true] {
            let (mut context, key) = preloaded_credit_context(cold);
            let mut gas = GasTracker::new(1_000_000, 1_000_000, 0);
            let mut backend = StorageCreditsContext {
                context: &mut context,
                gas_tracker: &mut gas,
            };
            let (loaded, reads) =
                access::record(|| backend.sload(STORAGE_CREDITS_ADDRESS, key, false));
            let loaded = loaded.unwrap();
            assert_eq!(loaded.data, U256::from(7));
            assert_eq!(loaded.is_cold, cold);
            assert_eq!(reads.slots.len(), 1);
            assert!(reads.slots.contains(&(STORAGE_CREDITS_ADDRESS, key)));

            // Use a separate scope: the preceding load must not mask a missing
            // SSTORE dependency, even though it has made this slot warm.
            let (stored, writes) = access::record(|| {
                backend.sstore(STORAGE_CREDITS_ADDRESS, key, U256::from(6), false)
            });
            assert!(stored.is_ok());
            assert_eq!(writes.slots.len(), 1);
            assert!(writes.slots.contains(&(STORAGE_CREDITS_ADDRESS, key)));
            assert_eq!(
                context.journaled_state.state[&STORAGE_CREDITS_ADDRESS].storage[&key].present_value,
                U256::from(6)
            );
        }
    }

    #[test]
    fn opcode_credit_accesses_record_cold_load_failures() {
        let (mut context, key) = preloaded_credit_context(true);
        let (mut reference, _) = preloaded_credit_context(true);
        let mut reference_gas = GasTracker::new(1_000_000, 1_000_000, 0);
        let mut unrecorded = StorageCreditsContext {
            context: &mut reference,
            gas_tracker: &mut reference_gas,
        };
        assert_eq!(
            unrecorded
                .sload(STORAGE_CREDITS_ADDRESS, key, true)
                .unwrap_err(),
            InstructionResult::OutOfGas
        );
        assert_eq!(
            unrecorded
                .sstore(STORAGE_CREDITS_ADDRESS, key, U256::from(6), true)
                .unwrap_err(),
            InstructionResult::OutOfGas
        );
        let mut gas = GasTracker::new(1_000_000, 1_000_000, 0);
        let mut backend = StorageCreditsContext {
            context: &mut context,
            gas_tracker: &mut gas,
        };
        let (loaded, reads) = access::record(|| backend.sload(STORAGE_CREDITS_ADDRESS, key, true));
        assert_eq!(loaded.unwrap_err(), InstructionResult::OutOfGas);
        assert!(reads.slots.contains(&(STORAGE_CREDITS_ADDRESS, key)));

        let (stored, writes) =
            access::record(|| backend.sstore(STORAGE_CREDITS_ADDRESS, key, U256::from(6), true));
        assert_eq!(stored.unwrap_err(), InstructionResult::OutOfGas);
        assert!(writes.slots.contains(&(STORAGE_CREDITS_ADDRESS, key)));
        // A failed SSTORE can still touch the account. Recording must preserve
        // that existing behavior, including its journal entry and cold slot.
        assert_eq!(
            context.journaled_state.inner,
            reference.journaled_state.inner
        );
        assert_eq!(gas, reference_gas);
    }

    #[test]
    fn opcode_credit_store_dependency_survives_checkpoint_revert() {
        let (mut context, key) = preloaded_credit_context(false);
        let before = context.journaled_state.inner.clone();
        let mut gas = GasTracker::new(1_000_000, 1_000_000, 0);
        let (stored, accesses) = access::record(|| {
            let checkpoint = context.journaled_state.checkpoint();
            let result = StorageCreditsContext {
                context: &mut context,
                gas_tracker: &mut gas,
            }
            .sstore(STORAGE_CREDITS_ADDRESS, key, U256::from(6), false);
            context.journaled_state.checkpoint_revert(checkpoint);
            result
        });
        assert!(stored.is_ok());
        assert!(accesses.slots.contains(&(STORAGE_CREDITS_ADDRESS, key)));
        assert_eq!(context.journaled_state.inner.state, before.state);
        assert_eq!(context.journaled_state.inner.journal, before.journal);
    }
}
