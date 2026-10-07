//! Direct payment-lane execution over journaled state.
use super::{
    PreparedAa,
    config::{self, TempoHandlerHooks},
    execution::TempoExecutionHost,
};
use crate::{
    TempoBlockEnv, TempoEvmExt, TempoEvmTx, TempoEvmTypes, TempoInvalidTransaction,
    TempoStateAccess, TempoTxEnv,
};
use alloy_consensus::Transaction;
use alloy_primitives::{
    Address, Bytes, KECCAK256_EMPTY, U256,
    map::{AddressMap, HashMap},
};
use evm2::{
    DatabaseError, EvmFeatures, TxResult, TxResultWithState, Version,
    ethereum::{self},
    evm::{AccountInfo, JournalEntry, PendingState, State},
    handler::GasSettlement,
    interpreter::{GasTracker, InstrStop, MessageResult},
    precompiles::{PrecompileError, PrecompileHalt},
    registry::{HandlerError, HandlerResult},
    version::GasId,
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{
    Precompile, TIP20_CHANNEL_RESERVE_ADDRESS, tip20::TIP20Token,
    tip20_channel_reserve::TIP20ChannelReserve,
};
use tempo_primitives::{TempoAddressExt, transaction::Call};

struct PreparedPayment {
    caller: Address,
    gas_price: U256,
    intrinsic: u64,
    initial_state_gas: u64,
    floor_gas: u64,
}

struct PaymentHost<'host, 'db> {
    state: &'host mut State<'db>,
    version: &'host Version,
    block: &'host TempoBlockEnv,
    spec: TempoHardfork,
    ext: &'host mut TempoEvmExt,
}

impl TempoStateAccess<((),)> for PaymentHost<'_, '_> {
    fn basic(&mut self, address: Address) -> Result<AccountInfo, DatabaseError> {
        let mut account = self.state.account(&address)?;
        account.warm();
        Ok(account.get().cloned().unwrap_or_default())
    }
    fn sload(&mut self, address: Address, key: U256) -> Result<U256, DatabaseError> {
        let mut slot = self.state.storage_slot(&address, key)?;
        slot.warm();
        Ok(slot.current())
    }
}

impl<'db> TempoExecutionHost<'db> for PaymentHost<'_, 'db> {
    fn state(&self) -> &State<'db> {
        self.state
    }
    fn state_mut(&mut self) -> &mut State<'db> {
        self.state
    }
    fn version(&self) -> &Version {
        self.version
    }
    fn block(&self) -> &TempoBlockEnv {
        self.block
    }
    fn config_spec_id(&self) -> TempoHardfork {
        self.spec
    }
    fn ext(&self) -> &TempoEvmExt {
        self.ext
    }
    fn ext_mut(&mut self) -> &mut TempoEvmExt {
        self.ext
    }
}

/// Validates and executes a T5+ payment transaction without constructing an EVM,
/// interpreter, message frame, transaction registry, or precompile registry.
///
/// Uses Tempo's native fee manager and shared AA validation/keychain/nonce logic.
/// The caller supplies the same version, block, and extension settings as normal
/// Tempo execution. `tx` must already have its signer and fee-payer recovered.
/// Returns detached state; apply `pending_state` with `State::commit_source` to
/// accept it. Transaction scratch is cleared on success and error, and the accepted
/// overlay is never changed. Call only between transactions, with empty scratch.
/// Transactions outside TIP-1045, delegated targets, and custom fee managers are
/// rejected with `DirectPaymentUnsupported`; callers may use the general executor.
/// BAL-enabled state also requires the general executor to retain all read metadata.
pub fn execute_payment_transaction(
    state: &mut State<'_>,
    version: &Version,
    spec: TempoHardfork,
    block: &TempoBlockEnv,
    ext: &mut TempoEvmExt,
    tx: &TempoTxEnv,
) -> HandlerResult<TxResultWithState<TempoEvmTypes>> {
    if !spec.is_t5()
        || !tx.transaction().is_payment_v2()
        || !ext.fee_manager.supports_direct_payment_execution()
        || state.bal_builder().is_some()
        || state.bal().is_some()
    {
        return Err(TempoInvalidTransaction::DirectPaymentUnsupported.into());
    }
    let action_cursor = ext.actions.take().map(|actions| {
        let cursor = actions.len();
        ext.actions.replace(actions);
        cursor
    });
    state.clear_transaction_state();
    let outcome = (|| {
        let mut host = PaymentHost {
            state,
            version,
            spec,
            block,
            ext,
        };
        let mut result = if let Some(aa) = tx.as_aa() {
            let prepared = super::prepare_aa_on_host(&mut host, tx, aa)?;
            execute_aa(&mut host, tx, prepared)?
        } else {
            let prepared = prepare_standard(&mut host, tx)?;
            execute_standard(&mut host, tx, prepared)?
        };
        result.logs = host.state.logs().to_vec();
        let pending_state = detach_payment_state(host.state, version)?;
        Ok(TxResultWithState {
            result,
            pending_state,
            _non_exhaustive: (),
        })
    })();
    state.clear_transaction_state();
    if outcome.is_err()
        && let Some(cursor) = action_cursor
        && let Some(mut actions) = ext.actions.take()
    {
        actions.truncate(cursor);
        ext.actions.replace(actions);
    }
    outcome
}

fn prepare_standard(
    host: &mut PaymentHost<'_, '_>,
    envelope: &TempoTxEnv,
) -> HandlerResult<PreparedPayment> {
    let tx = envelope.transaction();
    if !tx.value().is_zero() {
        return Err(TempoInvalidTransaction::ValueTransferNotAllowed.into());
    }
    // TIP-1045 requires an empty list; EIP-7702 requires a nonempty list, so these
    // classified envelopes remain invalid just as they are in the general handler.
    if matches!(envelope.evm_tx(), TempoEvmTx::Eip7702(_)) {
        return Err(HandlerError::EmptyAuthorizationList);
    }
    let caller = envelope.evm_tx().signer();
    let to = tx.kind();
    let legacy = matches!(envelope.evm_tx(), TempoEvmTx::Legacy { .. });
    let max_fee = U256::from(tx.max_fee_per_gas());
    let gas_price = if legacy || matches!(envelope.evm_tx(), TempoEvmTx::Eip2930(_)) {
        max_fee
    } else {
        let priority = U256::from(tx.max_priority_fee_per_gas().unwrap_or_default());
        ethereum::validate_priority_fee(host.version, max_fee, priority)?;
        ethereum::effective_gas_price(max_fee, priority, host.block.basefee)
    };
    ethereum::validate_gas_price(host.version, gas_price, host.block.basefee)?;
    ethereum::validate_chain_id(host.version, tx.chain_id(), legacy)?;
    ethereum::validate_tx_gas_limit_cap(host.version, tx.gas_limit())?;
    ethereum::validate_block_gas_limit(host.version, tx.gas_limit(), host.block.gas_limit)?;
    ethereum::validate_nonce_not_overflow(tx.nonce())?;
    let mut intrinsic =
        ethereum::intrinsic_gas(host.version, caller, to, tx.input(), 0, 0, U256::ZERO);
    let mut initial_state_gas = 0;
    if host.spec.is_t1() && tx.nonce() == 0 {
        intrinsic = intrinsic.saturating_add(u64::from(
            host.version.gas_params.get(GasId::NewAccountCost),
        ));
        initial_state_gas = host.version.gas_params.new_account_state_gas();
    }
    let floor_gas = ethereum::floor_gas(host.version, caller, to, tx.input(), 0, 0, U256::ZERO);
    ethereum::validate_intrinsic_gas(tx.gas_limit(), intrinsic, initial_state_gas)?;
    ethereum::validate_floor_gas(tx.gas_limit(), floor_gas)?;
    ethereum::validate_execution_gas_limit_cap(host.version, tx.gas_limit(), intrinsic, floor_gas)?;
    let mut sender = host.state.account(&caller)?;
    if host.version.feature(EvmFeatures::EIP3607) && sender.code_hash() != KECCAK256_EMPTY {
        let code = sender.load_code()?;
        if !code.is_empty() && !code.is_eip7702() {
            return Err(HandlerError::RejectCallerWithCode);
        }
    }
    if host.version.feature(EvmFeatures::NONCE_CHECK) && sender.nonce() != tx.nonce() {
        return Err(HandlerError::InvalidNonce {
            expected: sender.nonce(),
            got: tx.nonce(),
        });
    }
    let max_upfront = U256::from(tx.gas_limit()) * if legacy { gas_price } else { max_fee };
    if host.version.feature(EvmFeatures::BALANCE_CHECK) && sender.balance() < max_upfront {
        return Err(HandlerError::InsufficientFunds);
    }
    if !host.version.feature(EvmFeatures::BALANCE_CHECK)
        && host.version.feature(EvmFeatures::BALANCE_TOP_UP)
        && sender.balance() < max_upfront
    {
        sender.add_balance(max_upfront - sender.balance());
    }
    drop(sender);
    host.warm_base_accounts(caller, to);
    host.state.account(&caller)?.bump_nonce();
    let fee = TempoHandlerHooks::resolve_fee_context(host, envelope)?;
    if host.feature(EvmFeatures::FEE_CHARGE) {
        TempoHandlerHooks::collect_fee(host, fee, None)?;
    }
    Ok(PreparedPayment {
        caller,
        gas_price,
        intrinsic,
        initial_state_gas,
        floor_gas,
    })
}

fn execute_standard(
    host: &mut PaymentHost<'_, '_>,
    envelope: &TempoTxEnv,
    prepared: PreparedPayment,
) -> HandlerResult<TxResult<TempoEvmTypes>> {
    let tx = envelope.transaction();
    let (gas, reservoir) = ethereum::initial_gas_and_reservoir(
        host.version,
        tx.gas_limit(),
        prepared.intrinsic,
        prepared.initial_state_gas,
    );
    let call = Call {
        to: tx.kind(),
        value: U256::ZERO,
        input: tx.input().clone(),
    };
    let result = execute_batch(host, prepared.caller, None, gas, reservoir, &[call])?;
    config::settle_transaction(
        host,
        envelope,
        GasSettlement {
            caller: prepared.caller,
            gas_price: prepared.gas_price,
            gas_limit: tx.gas_limit(),
            floor_gas: prepared.floor_gas,
            initial_state_gas: prepared.initial_state_gas,
            state_refund: 0,
            result,
        },
    )
}

fn execute_aa(
    host: &mut PaymentHost<'_, '_>,
    envelope: &TempoTxEnv,
    prepared: PreparedAa,
) -> HandlerResult<TxResult<TempoEvmTypes>> {
    if let Some(result) = prepared.result {
        return Ok(result);
    }
    let tx = envelope.as_aa().expect("AA envelope").inner().tx();
    let (gas, reservoir) = ethereum::initial_gas_and_reservoir(
        host.version,
        tx.gas_limit,
        prepared.intrinsic,
        prepared.initial_state_gas,
    );
    let mut result = execute_batch(
        host,
        prepared.caller,
        prepared.access_key,
        gas,
        reservoir + prepared.state_refund,
        &tx.calls,
    )?;
    result
        .gas
        .record_refund(i64::try_from(prepared.regular_refund).unwrap_or(i64::MAX));
    config::settle_transaction(
        host,
        envelope,
        GasSettlement {
            caller: prepared.caller,
            gas_price: prepared.gas_price,
            gas_limit: tx.gas_limit,
            floor_gas: prepared.floor_gas,
            initial_state_gas: prepared.initial_state_gas,
            state_refund: prepared.state_refund,
            result,
        },
    )
}

fn execute_batch(
    host: &mut PaymentHost<'_, '_>,
    caller: Address,
    key: Option<Address>,
    gas_limit: u64,
    reservoir: u64,
    calls: &[Call],
) -> HandlerResult<MessageResult<TempoEvmTypes>> {
    let checkpoint = host.state.checkpoint();
    let mut remaining = gas_limit;
    if let Some(result) =
        super::prevalidate_call_scopes(host, caller, key, calls, &mut remaining, reservoir)?
    {
        host.state.rollback(checkpoint, host.version.features);
        return Ok(result);
    }
    let mut reservoir = reservoir;
    let mut refund = 0i64;
    let mut state_gas = 0i64;
    let mut spilled = 0u64;
    let mut output = Bytes::new();
    for call in calls {
        let address = *call.to.to().expect("payment calls have destinations");
        host.state.prewarm(&address);
        let mut target = host.state.account(&address)?;
        let code = target.load_code()?;
        if host.version.feature(EvmFeatures::EIP7702) && code.is_eip7702() {
            return Err(TempoInvalidTransaction::DirectPaymentUnsupported.into());
        }
        target.touch();
        drop(target);
        let (result, mut gas) = host.enter_metered_storage(remaining, reservoir, || {
            if address.is_tip20() {
                TIP20Token::from_address_unchecked(address).call(&call.input, caller)
            } else {
                debug_assert_eq!(address, TIP20_CHANNEL_RESERVE_ADDRESS);
                TIP20ChannelReserve::new().call(&call.input, caller)
            }
        });
        let stop = match result {
            Ok(bytes) => {
                output = bytes.into_bytes();
                InstrStop::Return
            }
            Err(PrecompileError::Revert(bytes)) => {
                output = bytes;
                InstrStop::Revert
            }
            Err(PrecompileError::Halt(reason)) => {
                output = Bytes::new();
                if reason == PrecompileHalt::OutOfGas {
                    InstrStop::PrecompileOOG
                } else {
                    InstrStop::PrecompileError
                }
            }
            Err(PrecompileError::Database(error)) => return Err(HandlerError::Database(error)),
            Err(PrecompileError::Fatal(error)) => return Err(HandlerError::Fatal(error)),
        };
        if !stop.is_success() {
            host.state.rollback(checkpoint, host.version.features);
            gas.settle_gas(stop);
            let restored_reservoir = gas.reservoir().saturating_add_signed(state_gas);
            gas = GasTracker::from_parts(gas_limit, gas.remaining(), restored_reservoir);
            return Ok(MessageResult::<TempoEvmTypes> {
                stop,
                gas,
                output,
                ..Default::default()
            });
        }
        refund = refund.saturating_add(gas.refunded());
        state_gas = state_gas.saturating_add(gas.state_gas_spent());
        spilled = spilled.saturating_add(gas.state_gas_spilled());
        remaining = gas.remaining();
        reservoir = gas.reservoir();
    }
    let mut gas = GasTracker::from_parts(gas_limit, remaining, reservoir);
    gas.record_refund(refund);
    gas.add_state_gas_spent(state_gas);
    gas.add_state_gas_spilled(spilled);
    Ok(MessageResult::<TempoEvmTypes> {
        stop: InstrStop::Return,
        gas,
        output,
        ..Default::default()
    })
}

/// Native payment calls never create code or selfdestruct. Collect their journaled
/// writes, including EIP-161 cleanup, using the first pre-write boundary value.
fn detach_payment_state(state: &mut State<'_>, version: &Version) -> HandlerResult<PendingState> {
    let mut accounts = AddressMap::default();
    let mut storage = HashMap::<(Address, U256), U256>::default();
    for entry in state.journal() {
        match entry {
            JournalEntry::AccountChange {
                address, previous, ..
            } => {
                accounts.entry(*address).or_insert_with(|| previous.clone());
            }
            JournalEntry::StorageChange {
                address,
                key,
                previous,
            } => {
                storage.entry((*address, *key)).or_insert(*previous);
            }
            _ => {}
        }
    }
    let mut deletions = Vec::new();
    for address in accounts.keys() {
        let account = state.account(address)?;
        if version.feature(EvmFeatures::EIP161)
            && account.is_touched()
            && account.is_existing_dead()
        {
            deletions.push(*address);
        }
    }
    for address in &deletions {
        state.storage(address).wipe();
    }
    let mut pending = if deletions.is_empty() {
        PendingState::default()
    } else {
        // Public EVM2 state APIs preserve wipe markers through isolation.
        state.prepare_isolated_state()
    };
    for (address, original) in accounts {
        let account = state.account(&address)?;
        let current = if version.feature(EvmFeatures::EIP161)
            && account.is_touched()
            && account.get().is_none_or(AccountInfo::is_empty)
        {
            None
        } else {
            account.get().cloned()
        };
        if original != current {
            pending.insert_account(address, original, current);
        }
    }
    for ((address, key), original) in storage {
        let current = state
            .get_storage(&address, &key)
            .expect("journaled slot is loaded");
        if original != current {
            pending.insert_storage(address, key, original, current);
        }
    }
    Ok(pending)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_evm::BlockExecutorFactory;
    use std::collections::BTreeMap;
    fn configured_evm(
        spec: TempoHardfork,
        timestamp: u64,
        amsterdam: bool,
        db: InMemoryDB,
    ) -> crate::TempoEvm<'static> {
        let mut version =
            tempo_chainspec::gas_params::version(evm2::SpecId::OSAKA, spec, amsterdam);
        version.chain_id = 1;
        version
            .features
            .remove(EvmFeatures::BALANCE_CHECK | EvmFeatures::BALANCE_TOP_UP);
        crate::TempoEvmConfig::moderato().evm_with_env(
            db,
            crate::TempoEvmEnv {
                spec,
                version,
                block: TempoBlockEnv {
                    timestamp: U256::from(timestamp),
                    gas_limit: U256::from(30_000_000),
                    ..Default::default()
                },
            },
        )
    }
    fn evm_detach(
        evm: &mut crate::TempoEvm<'_>,
        env: TempoTxEnv,
    ) -> HandlerResult<TxResultWithState<TempoEvmTypes>> {
        let signer = env.evm_tx().signer();
        evm.transact(&Recovered::new_unchecked(env, signer))
            .map(|result| result.detach())
    }
    use alloy_consensus::{Signed, TxEip1559, TxEip2930, TxLegacy, transaction::Recovered};
    use alloy_primitives::{B256, Signature, TxKind};
    use alloy_sol_types::SolCall;
    use core::{convert::Infallible, num::NonZeroU64};
    use evm2::{
        bytecode::Bytecode,
        evm::{AccountChangeRef, InMemoryDB, StateChangeSink, StateChangeSource, StorageChange},
    };
    use tempo_precompiles::{
        PATH_USD_ADDRESS, storage::StorageCtx, test_util::TIP20Setup, tip20::ITIP20,
    };
    use tempo_primitives::{
        TempoTransaction, TempoTxEnvelope,
        transaction::{PrimitiveSignature, TEMPO_EXPIRING_NONCE_KEY, TempoSignature},
    };

    #[derive(Debug, Default, PartialEq, Eq)]
    struct Changes {
        accounts: BTreeMap<Address, (Option<AccountInfo>, Option<AccountInfo>, bool, bool)>,
        storage: BTreeMap<(Address, U256), (U256, U256)>,
        wipes: std::collections::BTreeSet<Address>,
        code: BTreeMap<B256, Bytes>,
    }
    impl StateChangeSink for Changes {
        type Error = Infallible;
        fn account(&mut self, c: AccountChangeRef<'_>) -> Result<(), Infallible> {
            self.accounts.insert(
                c.address,
                (
                    c.original.cloned(),
                    c.current.cloned(),
                    c.created,
                    c.selfdestructed,
                ),
            );
            Ok(())
        }
        fn storage(&mut self, c: StorageChange) -> Result<(), Infallible> {
            self.storage
                .insert((c.address, c.key), (c.original, c.current));
            Ok(())
        }
        fn storage_wipe(&mut self, address: Address) -> Result<(), Infallible> {
            self.wipes.insert(address);
            Ok(())
        }
        fn bytecode(&mut self, hash: B256, code: &Bytecode) -> Result<(), Infallible> {
            self.code.insert(hash, code.original_bytes());
            Ok(())
        }
    }
    fn changes(state: &PendingState) -> Changes {
        let mut c = Changes::default();
        state.visit(&mut c).unwrap();
        c
    }

    fn root_signer() -> alloy_signer_local::PrivateKeySigner {
        alloy_signer_local::PrivateKeySigner::from_bytes(&B256::repeat_byte(1)).unwrap()
    }
    fn sender() -> Address {
        root_signer().address()
    }
    fn recipient() -> Address {
        Address::repeat_byte(0x22)
    }
    fn transfer(amount: U256) -> Call {
        Call {
            to: TxKind::Call(PATH_USD_ADDRESS),
            value: U256::ZERO,
            input: ITIP20::transferCall {
                to: recipient(),
                amount,
            }
            .abi_encode()
            .into(),
        }
    }
    fn aa_env(calls: Vec<Call>, nonce_key: U256, gas_limit: u64) -> TempoTxEnv {
        let tx = TempoTransaction {
            chain_id: 1,
            calls,
            nonce_key,
            nonce: 0,
            gas_limit,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 0,
            valid_before: (nonce_key == TEMPO_EXPIRING_NONCE_KEY)
                .then(|| NonZeroU64::new(110).unwrap()),
            ..Default::default()
        };
        let tx = tx.into_signed(TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            Signature::new(U256::ONE, U256::ONE, false),
        )));
        Recovered::new_unchecked(TempoTxEnvelope::AA(tx), sender()).into()
    }
    fn standard_env(kind: u8, gas_limit: u64, amount: U256) -> TempoTxEnv {
        let call = transfer(amount);
        let sig = Signature::new(U256::ONE, U256::ONE, false);
        let tx = match kind {
            0 => TempoTxEnvelope::Legacy(Signed::new_unhashed(
                TxLegacy {
                    chain_id: Some(1),
                    nonce: 0,
                    gas_limit,
                    gas_price: 1_000_000_000,
                    to: call.to,
                    input: call.input,
                    ..Default::default()
                },
                sig,
            )),
            1 => TempoTxEnvelope::Eip2930(Signed::new_unhashed(
                TxEip2930 {
                    chain_id: 1,
                    nonce: 0,
                    gas_limit,
                    gas_price: 1_000_000_000,
                    to: call.to,
                    input: call.input,
                    ..Default::default()
                },
                sig,
            )),
            _ => TempoTxEnvelope::Eip1559(Signed::new_unhashed(
                TxEip1559 {
                    chain_id: 1,
                    nonce: 0,
                    gas_limit,
                    max_fee_per_gas: 1_000_000_000,
                    max_priority_fee_per_gas: 0,
                    to: call.to,
                    input: call.input,
                    ..Default::default()
                },
                sig,
            )),
        };
        Recovered::new_unchecked(tx, sender()).into()
    }
    fn fixture(spec: TempoHardfork, amsterdam: bool) -> (InMemoryDB, Version, TempoBlockEnv) {
        let mut evm = configured_evm(spec, 100, amsterdam, InMemoryDB::default());
        StorageCtx::enter_evm(&mut evm, || {
            TIP20Setup::path_usd(sender())
                .with_issuer(sender())
                .with_mint(sender(), U256::from(1_000_000_000_000_000_000u128))
                .apply()
        })
        .unwrap();
        evm.state_mut().commit_transaction();
        evm.state_mut().clear_transaction_state();
        let mut db = InMemoryDB::default();
        db.cache = evm.overlay_db().cache.clone();
        (db, *evm.version(), *evm.block())
    }
    fn parity(spec: TempoHardfork, amsterdam: bool, env: TempoTxEnv) {
        let (db, version, block) = fixture(spec, amsterdam);
        let mut evm = configured_evm(spec, 100, amsterdam, db.clone());
        let expected = evm_detach(&mut evm, env.clone());
        let mut state = State::new(db);
        let mut ext = TempoEvmExt::default();
        let actual =
            execute_payment_transaction(&mut state, &version, spec, &block, &mut ext, &env);
        match (expected, actual) {
            (Ok(expected), Ok(actual)) => {
                assert_eq!(
                    actual.result, expected.result,
                    "result {spec:?}, amsterdam={amsterdam}"
                );
                assert_eq!(
                    changes(&actual.pending_state),
                    changes(&expected.pending_state),
                    "state {spec:?}, amsterdam={amsterdam}"
                );
            }
            (Err(expected), Err(actual)) => {
                assert_eq!(actual.to_string(), expected.to_string(), "error {spec:?}")
            }
            (expected, actual) => {
                panic!("{spec:?}, amsterdam={amsterdam}: expected {expected:?}, actual {actual:?}")
            }
        }
        assert!(state.journal().is_empty());
        assert!(state.logs().is_empty());
        assert_eq!(
            state
                .account_info_untracked(&sender())
                .unwrap()
                .map(|account| account.nonce)
                .unwrap_or_default(),
            0,
            "detached execution must not commit the sender nonce"
        );
    }

    #[test]
    fn unsupported_payment_execution_leaves_state_ready_for_fallback() {
        let spec = TempoHardfork::T14;
        let (db, version, block) = fixture(spec, false);
        let mut state = State::new(db.clone());
        state
            .account(&PATH_USD_ADDRESS)
            .unwrap()
            .set_code_slow(Bytecode::new_eip7702(recipient()));
        state.commit_transaction();
        state.clear_transaction_state();
        let mut ext = TempoEvmExt::default();
        let env = standard_env(2, 500_000, U256::ONE);
        let error = execute_payment_transaction(&mut state, &version, spec, &block, &mut ext, &env)
            .unwrap_err();
        assert!(matches!(
            error.external_ref::<TempoInvalidTransaction>(),
            Some(TempoInvalidTransaction::DirectPaymentUnsupported)
        ));
        assert!(state.journal().is_empty());
        assert!(state.logs().is_empty());
        assert_eq!(
            state
                .account_info_untracked(&sender())
                .unwrap()
                .map(|account| account.nonce)
                .unwrap_or_default(),
            0
        );
        // An unsupported hardfork is rejected before transaction preparation.
        let mut state = State::new(db);
        let error = execute_payment_transaction(
            &mut state,
            &version,
            TempoHardfork::T4,
            &block,
            &mut ext,
            &env,
        )
        .unwrap_err();
        assert!(matches!(
            error.external_ref::<TempoInvalidTransaction>(),
            Some(TempoInvalidTransaction::DirectPaymentUnsupported)
        ));
        assert!(state.journal().is_empty());
    }

    #[test]
    fn invalid_payment_envelopes_match_general_validation() {
        for case in 0..5 {
            let call = transfer(U256::ONE);
            let tx = TxLegacy {
                chain_id: Some(if case == 0 { 2 } else { 1 }),
                nonce: if case == 1 {
                    1
                } else if case == 2 {
                    u64::MAX
                } else {
                    0
                },
                gas_price: 1_000_000_000,
                gas_limit: if case == 3 {
                    100
                } else if case == 4 {
                    40_000_000
                } else {
                    500_000
                },
                to: call.to,
                input: call.input,
                ..Default::default()
            };
            let env = Recovered::new_unchecked(
                TempoTxEnvelope::Legacy(Signed::new_unhashed(tx, Signature::test_signature())),
                sender(),
            )
            .into();
            parity(TempoHardfork::T14, false, env);
        }
    }

    #[test]
    fn payment_parity_across_forks_and_gas_modes() {
        for spec in [
            TempoHardfork::T5,
            TempoHardfork::T6,
            TempoHardfork::T7,
            TempoHardfork::T8,
            TempoHardfork::T9,
            TempoHardfork::T10,
            TempoHardfork::T11,
            TempoHardfork::T12,
            TempoHardfork::T13,
            TempoHardfork::T14,
        ] {
            for amsterdam in [false, true]
                .into_iter()
                .filter(|enabled| !enabled || !spec.is_t7())
            {
                for kind in 0..3 {
                    for amount in [U256::ONE, U256::MAX] {
                        parity(spec, amsterdam, standard_env(kind, 500_000, amount));
                    }
                    parity(spec, amsterdam, standard_env(kind, 45_000, U256::ONE));
                }
                for key in [U256::ZERO, U256::from(7), TEMPO_EXPIRING_NONCE_KEY] {
                    parity(
                        spec,
                        amsterdam,
                        aa_env(vec![transfer(U256::ONE)], key, 500_000),
                    );
                    parity(
                        spec,
                        amsterdam,
                        aa_env(vec![transfer(U256::ONE), transfer(U256::ONE)], key, 500_000),
                    );
                    parity(
                        spec,
                        amsterdam,
                        aa_env(vec![transfer(U256::ONE), transfer(U256::MAX)], key, 500_000),
                    );
                    parity(
                        spec,
                        amsterdam,
                        aa_env(vec![transfer(U256::ONE)], key, 45_000),
                    );
                }
            }
        }
    }

    #[test]
    fn payment_selectors_match_native_precompile_dispatch() {
        let to = recipient();
        let from = sender();
        let amount = U256::ONE;
        let memo = B256::repeat_byte(3);
        let inputs: Vec<Bytes> = vec![
            ITIP20::transferCall { to, amount }.abi_encode().into(),
            ITIP20::transferWithMemoCall { to, amount, memo }
                .abi_encode()
                .into(),
            ITIP20::transferFromCall { from, to, amount }
                .abi_encode()
                .into(),
            ITIP20::transferFromWithMemoCall {
                from,
                to,
                amount,
                memo,
            }
            .abi_encode()
            .into(),
            ITIP20::approveCall {
                spender: to,
                amount,
            }
            .abi_encode()
            .into(),
            ITIP20::mintCall { to, amount }.abi_encode().into(),
            ITIP20::mintWithMemoCall { to, amount, memo }
                .abi_encode()
                .into(),
            ITIP20::burnCall { amount }.abi_encode().into(),
            ITIP20::burnWithMemoCall { amount, memo }
                .abi_encode()
                .into(),
        ];
        for spec in [
            TempoHardfork::T5,
            TempoHardfork::T7,
            TempoHardfork::T11,
            TempoHardfork::T14,
        ] {
            for amsterdam in [false, true]
                .into_iter()
                .filter(|enabled| !enabled || !spec.is_t7())
            {
                for input in &inputs {
                    parity(
                        spec,
                        amsterdam,
                        aa_env(
                            vec![Call {
                                to: TxKind::Call(PATH_USD_ADDRESS),
                                value: U256::ZERO,
                                input: input.clone(),
                            }],
                            U256::ZERO,
                            1_000_000,
                        ),
                    );
                }
            }
        }
    }

    #[test]
    fn inline_key_authorization_and_scope_failures_preserve_protocol_state() {
        use alloy_signer::SignerSync;
        use tempo_primitives::transaction::{KeyAuthorization, KeychainSignature, SignatureType};
        let access =
            alloy_signer_local::PrivateKeySigner::from_bytes(&B256::repeat_byte(2)).unwrap();
        for spec in [
            TempoHardfork::T5,
            TempoHardfork::T6,
            TempoHardfork::T7,
            TempoHardfork::T14,
        ] {
            for deny_calls in [false, true] {
                for fail_second_call in [false, true] {
                    let mut auth = KeyAuthorization::unrestricted(
                        1,
                        SignatureType::Secp256k1,
                        access.address(),
                    );
                    if deny_calls {
                        auth = auth.with_no_calls();
                    }
                    let signature = root_signer()
                        .sign_hash_sync(&auth.signature_hash())
                        .unwrap();
                    let auth = auth.into_signed(PrimitiveSignature::Secp256k1(signature));
                    let tx = TempoTransaction {
                        chain_id: 1,
                        calls: vec![
                            transfer(U256::ONE),
                            transfer(if fail_second_call {
                                U256::MAX
                            } else {
                                U256::ONE
                            }),
                        ],
                        gas_limit: 5_000_000,
                        max_fee_per_gas: 1_000_000_000,
                        key_authorization: Some(auth),
                        ..Default::default()
                    };
                    let hash = alloy_primitives::keccak256(
                        [
                            &[4u8][..],
                            tx.signature_hash().as_slice(),
                            sender().as_slice(),
                        ]
                        .concat(),
                    );
                    let signature = access.sign_hash_sync(&hash).unwrap();
                    let signed = tx.into_signed(TempoSignature::Keychain(KeychainSignature::new(
                        sender(),
                        PrimitiveSignature::Secp256k1(signature),
                    )));
                    let env =
                        Recovered::new_unchecked(TempoTxEnvelope::AA(signed), sender()).into();
                    parity(spec, !spec.is_t7(), env);
                }
            }
        }
    }

    #[test]
    fn channel_payment_selectors_match_the_general_executor() {
        use alloy_primitives::aliases::U96;
        use tempo_contracts::precompiles::ITIP20ChannelReserve as Channel;
        let descriptor = Channel::ChannelDescriptor {
            payer: sender(),
            payee: recipient(),
            operator: recipient(),
            token: PATH_USD_ADDRESS,
            salt: B256::ZERO,
            authorizedSigner: sender(),
            expiringNonceHash: B256::ZERO,
        };
        let signature =
            TempoSignature::from(Signature::new(U256::ONE, U256::ONE, false)).to_bytes();
        let inputs: Vec<Bytes> = vec![
            Channel::openCall {
                payee: recipient(),
                operator: recipient(),
                token: PATH_USD_ADDRESS,
                deposit: U96::from(1),
                salt: B256::ZERO,
                authorizedSigner: sender(),
            }
            .abi_encode()
            .into(),
            Channel::topUpCall {
                descriptor: descriptor.clone(),
                additionalDeposit: U96::from(1),
            }
            .abi_encode()
            .into(),
            Channel::settleCall {
                descriptor: descriptor.clone(),
                cumulativeAmount: U96::from(1),
                signature: signature.clone(),
            }
            .abi_encode()
            .into(),
            Channel::closeCall {
                descriptor: descriptor.clone(),
                cumulativeAmount: U96::from(1),
                captureAmount: U96::from(1),
                signature,
            }
            .abi_encode()
            .into(),
            Channel::requestCloseCall {
                descriptor: descriptor.clone(),
            }
            .abi_encode()
            .into(),
            Channel::withdrawCall { descriptor }.abi_encode().into(),
        ];
        for spec in [TempoHardfork::T5, TempoHardfork::T7, TempoHardfork::T14] {
            for input in &inputs {
                let env = aa_env(
                    vec![Call {
                        to: TxKind::Call(TIP20_CHANNEL_RESERVE_ADDRESS),
                        value: U256::ZERO,
                        input: input.clone(),
                    }],
                    U256::ZERO,
                    1_000_000,
                );
                parity(spec, !spec.is_t7(), env);
            }
        }
    }

    #[test]
    fn committed_payment_state_is_visible_to_the_next_transaction() {
        let spec = TempoHardfork::T14;
        let (db, version, block) = fixture(spec, false);
        let mut evm = configured_evm(spec, 100, false, db.clone());
        let mut state = State::new(db);
        let mut ext = TempoEvmExt::default();
        for nonce in 0..5 {
            let mut tx = TempoTransaction {
                chain_id: 1,
                nonce,
                calls: vec![transfer(U256::ONE)],
                gas_limit: 500_000,
                max_fee_per_gas: 1_000_000_000,
                ..Default::default()
            };
            tx.fee_token = Some(PATH_USD_ADDRESS);
            let signed = tx.into_signed(TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                Signature::new(U256::ONE, U256::ONE, false),
            )));
            let env: TempoTxEnv =
                Recovered::new_unchecked(TempoTxEnvelope::AA(signed), sender()).into();
            let expected = evm_detach(&mut evm, env.clone()).unwrap();
            let actual =
                execute_payment_transaction(&mut state, &version, spec, &block, &mut ext, &env)
                    .unwrap();
            assert_eq!(actual.result, expected.result);
            assert_eq!(
                changes(&actual.pending_state),
                changes(&expected.pending_state)
            );
            state.commit_source(&actual.pending_state);
            evm.state_mut().commit_source(&expected.pending_state);
        }
    }
}
