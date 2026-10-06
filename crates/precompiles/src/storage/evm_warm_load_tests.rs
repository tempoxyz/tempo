//! Differential checks against the boxed SLOAD implementation, using revm's
//! standard Journal and a database that records calls and injects failures.

use super::*;
use crate::storage::{access, fee_updates, native_increment};
use revm::{
    Database,
    context::{Journal, TxEnv},
    context_interface::{JournalTr, journaled_state::account::JournaledAccountTr},
    database_interface::DBErrorMarker,
    state::AccountId,
};
use tempo_revm::gas_params::tempo_gas_params_with_amsterdam;

const ADDRESS: Address = Address::repeat_byte(0x51);
const KEY: U256 = U256::from_limbs([17, 0, 0, 0]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("injected {0} failure")]
struct LoadError(&'static str);

impl DBErrorMarker for LoadError {}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ProbeDb {
    fail: Option<&'static str>,
    account_id: Option<AccountId>,
    calls: Vec<(&'static str, Address, U256)>,
}

impl Database for ProbeDb {
    type Error = LoadError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.calls.push(("basic", address, U256::ZERO));
        if self.fail == Some("basic") {
            return Err(LoadError("basic"));
        }
        Ok(Some(AccountInfo {
            nonce: 1,
            account_id: self.account_id,
            ..Default::default()
        }))
    }

    fn storage(&mut self, address: Address, key: U256) -> Result<U256, Self::Error> {
        self.calls.push(("storage", address, key));
        if self.fail == Some("storage") {
            return Err(LoadError("storage"));
        }
        Ok(U256::from(11))
    }

    fn storage_by_account_id(
        &mut self,
        address: Address,
        account_id: AccountId,
        key: U256,
    ) -> Result<U256, Self::Error> {
        assert_eq!(Some(account_id), self.account_id);
        self.calls.push(("storage_by_account_id", address, key));
        if self.fail == Some("storage") {
            return Err(LoadError("storage"));
        }
        Ok(U256::from(11))
    }

    fn code_by_hash(&mut self, _hash: B256) -> Result<Bytecode, Self::Error> {
        panic!("SLOAD must not load bytecode")
    }

    fn block_hash(&mut self, _number: u64) -> Result<B256, Self::Error> {
        panic!("SLOAD must not load block hashes")
    }
}

#[derive(Clone)]
struct Harness {
    journal: Journal<ProbeDb>,
    block: TempoBlockEnv,
    cfg: CfgEnv<TempoHardfork>,
    tx: TxEnv,
}

impl Harness {
    fn new(spec: TempoHardfork) -> Self {
        let mut cfg = CfgEnv::default();
        cfg.spec = spec;
        cfg.gas_params = tempo_gas_params_with_amsterdam(spec, false);
        Self {
            journal: Journal::new(ProbeDb::default()),
            block: TempoBlockEnv::default(),
            cfg,
            tx: TxEnv::default(),
        }
    }

    fn provider(&mut self, gas: u64) -> EvmPrecompileStorageProvider<'_> {
        let internals = EvmInternals::new(&mut self.journal, &self.block, &self.cfg, &self.tx);
        EvmPrecompileStorageProvider::new_with_gas_limit(internals, &self.cfg, gas, 0)
            .with_standard_journal_warm_reads(true)
            .with_actions(StorageActions::enabled())
    }

    fn warm(&mut self) {
        JournalTr::load_account_mut(&mut self.journal, ADDRESS)
            .unwrap()
            .sload(KEY, false)
            .unwrap();
    }

    fn write(&mut self, value: U256) {
        JournalTr::load_account_mut(&mut self.journal, ADDRESS)
            .unwrap()
            .sstore(KEY, value, false)
            .unwrap();
    }
}

// Frozen reference: the original raw operation, including both observer calls.
fn boxed_load(
    provider: &mut EvmPrecompileStorageProvider<'_>,
    skip_cold_load: bool,
) -> Result<StateLoad<U256>, TempoPrecompileError> {
    access::storage(ADDRESS, KEY);
    let mut account = provider.internals.load_account_mut(ADDRESS)?;
    let value = account.sload(KEY, skip_cold_load)?;
    let result = StateLoad::new(value.present_value, value.is_cold);
    if provider.native_recording {
        native_increment::loaded(ADDRESS, KEY, &result);
    }
    Ok(result)
}

fn load(
    provider: &mut EvmPrecompileStorageProvider<'_>,
    boxed: bool,
    skip: bool,
) -> Result<StateLoad<U256>, TempoPrecompileError> {
    if boxed {
        boxed_load(provider, skip)
    } else {
        provider.sload_journal(ADDRESS, KEY, skip)
    }
}

fn compare_raw(
    candidate: &mut Harness,
    reference: &mut Harness,
    skip: bool,
) -> Result<(U256, bool), TempoPrecompileError> {
    let (actual, actual_accesses) = access::record(|| {
        load(&mut candidate.provider(u64::MAX), false, skip)
            .map(|value| (value.data, value.is_cold))
    });
    let (expected, expected_accesses) = access::record(|| {
        load(&mut reference.provider(u64::MAX), true, skip).map(|value| (value.data, value.is_cold))
    });
    assert_eq!(actual, expected);
    assert_eq!(candidate.journal, reference.journal);
    assert_eq!(actual_accesses.slots, expected_accesses.slots);
    assert_eq!(actual_accesses.unsupported, expected_accesses.unsupported);
    assert!(actual_accesses.slots.contains(&(ADDRESS, KEY)));
    actual
}

#[test]
fn warm_load_requires_explicit_standard_journal_opt_in() {
    let mut harness = Harness::new(TempoHardfork::T14);
    let env = crate::PrecompileEnv::new(
        &harness.cfg,
        StorageActions::disabled(),
        Rc::new(RefCell::new(NonCreditableSlots::empty())),
    );
    assert!(!env.standard_journal_warm_reads);
    assert!(
        env.clone()
            .with_standard_journal(&harness.journal)
            .standard_journal_warm_reads
    );
    assert!(!env.standard_journal_warm_reads);
    let internals = EvmInternals::new(
        &mut harness.journal,
        &harness.block,
        &harness.cfg,
        &harness.tx,
    );
    let provider = EvmPrecompileStorageProvider::new_max_gas(internals, &harness.cfg);
    assert!(!provider.standard_journal_warm_reads);
}

#[test]
fn warm_load_matches_boxed_for_slot_lifetimes_and_access_lists() {
    for access_list in [false, true] {
        for account_id in [None, AccountId::new(7)] {
            for shape in 0..5 {
                let mut candidate = Harness::new(TempoHardfork::T14);
                candidate.journal.database.account_id = account_id;
                match shape {
                    0 => {} // Absent slot.
                    1 => candidate.warm(),
                    2 => candidate.write(U256::from(41)), // Dirty, warm slot.
                    3 => {
                        candidate.write(U256::from(41));
                        candidate.journal.commit_tx(); // Retained previous-tx slot.
                    }
                    _ => {
                        // A reverted first load leaves a present but cold slot.
                        JournalTr::load_account_mut(&mut candidate.journal, ADDRESS).unwrap();
                        let checkpoint = candidate.journal.checkpoint();
                        candidate.write(U256::from(41));
                        candidate.journal.checkpoint_revert(checkpoint);
                        assert!(candidate.journal.state[&ADDRESS].storage[&KEY].is_cold);
                    }
                }
                if access_list {
                    candidate.journal.warm_addresses.set_access_list(
                        [(ADDRESS, [KEY].into_iter().collect())]
                            .into_iter()
                            .collect(),
                    );
                }
                let mut reference = candidate.clone();
                let was_warm = matches!(shape, 1 | 2);
                let value = if matches!(shape, 2 | 3) { 41 } else { 11 };
                let mut skipped = candidate.clone();
                let mut skipped_reference = candidate.clone();
                let skip_result = compare_raw(&mut skipped, &mut skipped_reference, true);
                if was_warm || access_list {
                    assert_eq!(skip_result.unwrap(), (U256::from(value), false));
                } else {
                    assert_eq!(skip_result, Err(TempoPrecompileError::OutOfGas));
                }
                assert_eq!(
                    compare_raw(&mut candidate, &mut reference, false).unwrap(),
                    (U256::from(value), !was_warm && !access_list),
                );
                assert_eq!(
                    compare_raw(&mut candidate, &mut reference, true).unwrap(),
                    (U256::from(value), false),
                );
                let slot = &candidate.journal.state[&ADDRESS].storage[&KEY];
                assert_eq!(
                    slot.original_value,
                    U256::from(if shape == 3 { 41 } else { 11 })
                );
            }
        }
    }
}

#[test]
fn warm_load_preserves_skipped_cold_loads_and_database_failures() {
    for fail in [None, Some("basic"), Some("storage")] {
        for skip in [false, true] {
            for warm in [false, true] {
                let mut candidate = Harness::new(TempoHardfork::T14);
                if warm {
                    candidate.warm();
                }
                candidate.journal.database.fail = fail;
                let mut reference = candidate.clone();
                let result = compare_raw(&mut candidate, &mut reference, skip);
                if warm {
                    assert_eq!(result.unwrap(), (U256::from(11), false));
                } else if fail == Some("basic") || (!skip && fail == Some("storage")) {
                    assert!(matches!(result, Err(TempoPrecompileError::Fatal(_))));
                } else if skip {
                    assert_eq!(result, Err(TempoPrecompileError::OutOfGas));
                } else {
                    assert_eq!(result.unwrap(), (U256::from(11), true));
                }
            }
        }
    }
}

// Frozen reference metering retains the pre-T4 post-load charge and T4+
// pre-charge, and records the action before any cold-load gas failure.
fn boxed_metered_load(
    provider: &mut EvmPrecompileStorageProvider<'_>,
) -> Result<U256, TempoPrecompileError> {
    let cold_cost = provider.gas_params.cold_storage_additional_cost();
    let skip = if provider.spec.is_t4() {
        provider.deduct_gas(provider.gas_params.warm_storage_read_cost())?;
        provider.gas_tracker.remaining() < cold_cost
    } else {
        false
    };
    let result = boxed_load(provider, skip)?;
    provider
        .actions
        .record(StorageAction::Sload(ADDRESS, KEY, result.data));
    if !provider.spec.is_t4() {
        provider.deduct_gas(provider.gas_params.warm_storage_read_cost())?;
    }
    if result.is_cold {
        provider.deduct_gas(cold_cost)?;
    }
    Ok(result.data)
}

#[test]
fn warm_load_preserves_metering_actions_and_failed_access_boundaries() {
    for spec in [TempoHardfork::T3, TempoHardfork::T4, TempoHardfork::T14] {
        for warm in [false, true] {
            let mut seed = Harness::new(spec);
            if warm {
                seed.write(U256::from(41));
            }
            let warm_cost = seed.cfg.gas_params.warm_storage_read_cost();
            let cold_cost = seed.cfg.gas_params.cold_storage_additional_cost();
            for gas in [
                0,
                warm_cost - 1,
                warm_cost,
                warm_cost + cold_cost - 1,
                warm_cost + cold_cost,
                u64::MAX,
            ] {
                let mut candidate = seed.clone();
                let mut reference = seed.clone();
                let run = |harness: &mut Harness, boxed| {
                    access::record(|| {
                        let mut provider = harness.provider(gas);
                        let result = if boxed {
                            boxed_metered_load(&mut provider)
                        } else {
                            provider.sload(ADDRESS, KEY)
                        };
                        (result, provider.gas_tracker, provider.take_actions())
                    })
                };
                let (actual, accesses) = run(&mut candidate, false);
                let (expected, reference_accesses) = run(&mut reference, true);
                assert_eq!(actual, expected, "{spec:?}, warm={warm}, gas={gas}");
                assert_eq!(candidate.journal, reference.journal);
                assert_eq!(accesses.slots, reference_accesses.slots);
                assert_eq!(accesses.slots.is_empty(), spec.is_t4() && gas < warm_cost);
            }
        }
    }
}

#[test]
fn warm_load_keeps_native_and_fee_observers() {
    let target = native_increment::NativeIncrementTarget {
        address: ADDRESS,
        slot: KEY,
        delta: U256::ONE,
    };
    for warm in [false, true] {
        for extra_read in [false, true] {
            let run = |boxed| {
                let mut harness = Harness::new(TempoHardfork::T14);
                if warm {
                    harness.warm();
                }
                let (_, witness) = native_increment::record(target, || {
                    let mut provider = harness.provider(u64::MAX);
                    native_increment::sinc(ADDRESS, KEY, U256::ONE, || {
                        let value = load(&mut provider, boxed, false)?.data;
                        provider.sstore_journal(ADDRESS, KEY, value + U256::ONE, false)?;
                        Ok::<_, TempoPrecompileError>(())
                    })
                    .unwrap();
                    if extra_read {
                        load(&mut provider, boxed, false).unwrap();
                    }
                });
                (witness, harness.journal)
            };
            let actual = run(false);
            assert_eq!(actual, run(true));
            assert_eq!(actual.0.is_some(), !warm && !extra_read);
        }
    }
    for boxed in [false, true] {
        let mut harness = Harness::new(TempoHardfork::T14);
        let (_, updates) = fee_updates::record(|| {
            let mut provider = harness.provider(u64::MAX);
            fee_updates::update(
                Some((ADDRESS, KEY)),
                fee_updates::FeeDelta::Add(U256::ONE),
                || {
                    let value = load(&mut provider, boxed, false)?.data;
                    provider.sstore_journal(ADDRESS, KEY, value + U256::ONE, false)?;
                    Ok::<_, TempoPrecompileError>(())
                },
            )
            .unwrap();
            // A warm read after fee collection must disqualify rebasing.
            load(&mut provider, boxed, false).unwrap();
        });
        assert!(updates.is_empty());
    }
}
