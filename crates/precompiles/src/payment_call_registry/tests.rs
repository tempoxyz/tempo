use super::*;
use crate::{
    Precompile,
    storage::{StorageCtx, hashmap::HashMapStorageProvider},
    test_util::{assert_full_coverage, check_selector_coverage},
};
use alloy::{
    primitives::{Bytes, IntoLogData, Signature, U256, keccak256},
    sol_types::SolCall,
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{IPaymentCallRegistry::IPaymentCallRegistryCalls, ITIP20};
use tempo_primitives::{TempoTransaction, transaction::Call};

const NOW: u64 = 1_000_000;
const START_BLOCK: u64 = 100;
const EPOCH: u64 = 10;
const AUTHORIZE: [u8; 4] = [0xca, 0x89, 0xe4, 0x14];
const CAPTURE: [u8; 4] = [0x09, 0x71, 0xed, 0xe5];

/// `PUSH32 <a> POP PUSH20 <b> POP STOP`: two immutables, at (1, 32) and (35, 20).
fn program_code(a: u8, b: u8) -> Vec<u8> {
    let mut code = vec![0x7f];
    code.extend([a; 32]);
    code.push(0x50);
    code.push(0x73);
    code.extend([b; 20]);
    code.extend([0x50, 0x00]);
    code
}

fn ranges() -> Vec<IPaymentCallRegistry::CodeRange> {
    vec![
        IPaymentCallRegistry::CodeRange {
            offset: 1,
            length: 32,
        },
        IPaymentCallRegistry::CodeRange {
            offset: 35,
            length: 20,
        },
    ]
}

fn selector(
    selector: [u8; 4],
    arguments: u32,
    gas_cap: u64,
) -> IPaymentCallRegistry::PaymentSelector {
    IPaymentCallRegistry::PaymentSelector {
        selector: selector.into(),
        calldataLength: 4 + 32 * arguments,
        gasCap: gas_cap,
    }
}

fn selectors() -> Vec<IPaymentCallRegistry::PaymentSelector> {
    vec![
        selector(AUTHORIZE, 6, 1_500_000),
        selector(CAPTURE, 3, 500_000),
    ]
}

fn calldata(selector: [u8; 4], arguments: usize) -> Bytes {
    let mut input = selector.to_vec();
    input.resize(4 + 32 * arguments, 0x01);
    input.into()
}

struct Fixture {
    governance: Address,
    registry: PaymentCallRegistry,
}

/// Runs `f` at T17 with an initialized registry and ValidatorConfigV2 owned by governance.
fn at_t17(f: impl FnOnce(&mut Fixture) -> eyre::Result<()>) -> eyre::Result<()> {
    let mut storage =
        HashMapStorageProvider::new_with_spec(1, TempoHardfork::T17).with_epoch_length(EPOCH);
    storage.set_timestamp(U256::from(NOW));
    storage.set_block_number(START_BLOCK);
    StorageCtx::enter(&mut storage, || {
        let governance = Address::repeat_byte(0x60);
        ValidatorConfigV2::new().initialize(governance)?;
        let mut registry = PaymentCallRegistry::new();
        registry.initialize()?;
        f(&mut Fixture {
            governance,
            registry,
        })
    })
}

fn set_block(number: u64) {
    StorageCtx.set_block_number(number);
}

fn warp(seconds: u64) {
    let now = StorageCtx.timestamp().saturating_to::<u64>();
    StorageCtx.set_timestamp(U256::from(now + seconds));
}

fn deploy(address: Address, code: Vec<u8>) -> eyre::Result<()> {
    StorageCtx.set_code(address, code.into())?;
    Ok(())
}

fn err(error: PaymentCallRegistryError) -> TempoPrecompileError {
    error.into()
}

use crate::error::TempoPrecompileError;

impl Fixture {
    fn propose(&mut self, code: Vec<u8>) -> Result<u64> {
        self.registry.propose_template(
            self.governance,
            IPaymentCallRegistry::proposeTemplateCall {
                code: code.into(),
                ranges: ranges(),
                selectors: selectors(),
            },
        )
    }

    /// Proposes the program template and activates it after the timelock; it classifies from
    /// the next block.
    fn active_template(&mut self) -> Result<u64> {
        let id = self.propose(program_code(0, 0))?;
        warp(TEMPLATE_TIMELOCK);
        self.registry.activate_template(self.governance, id)?;
        Ok(id)
    }

    fn lane_at(&self, tx: &TempoTxEnvelope, block: u64) -> bool {
        self.registry
            .classify(tx, block)
            .expect("classification reads storage")
            .is_registered_payment
    }
}

fn aa(calls: Vec<(Address, Bytes)>, gas_limit: u64) -> TempoTxEnvelope {
    TempoTxEnvelope::AA(
        TempoTransaction {
            calls: calls
                .into_iter()
                .map(|(to, input)| Call::new(to, input))
                .collect(),
            gas_limit,
            ..Default::default()
        }
        .into_signed(Signature::test_signature().into()),
    )
}

#[test]
fn scan_code_rejects_selfdestruct_outside_push_data() {
    // PUSH1 0xff STOP: 0xff is data.
    assert!(scan_code(&[0x60, 0xff, 0x00]).is_ok());
    // PUSH32 with 0xff in its immediate, truncated at the end of code.
    assert!(scan_code(&[0x7f, 0xff, 0xff]).is_ok());
    // CALLER SELFDESTRUCT
    assert_eq!(
        scan_code(&[0x33, 0xff]).unwrap_err(),
        err(PaymentCallRegistryError::forbidden_opcode(1, 0xff))
    );
    for code in [
        &[][..],
        &[0xef, 0x01, 0x00][..],
        &vec![0; MAX_TEMPLATE_CODE_SIZE + 1][..],
    ] {
        assert_eq!(
            scan_code(code).unwrap_err(),
            err(PaymentCallRegistryError::invalid_code())
        );
    }
    let push_data = scan_code(&program_code(1, 2)).unwrap();
    assert!(!push_data[0] && push_data[1..33].iter().all(|&data| data) && !push_data[33]);
}

#[test]
fn ranges_must_be_push_data_ascending_and_disjoint() {
    let code = program_code(1, 2);
    let push_data = scan_code(&code).unwrap();
    let range = |offset, length| IPaymentCallRegistry::CodeRange { offset, length };
    assert!(validate_ranges(&push_data, &ranges()).is_ok());
    assert!(validate_ranges(&push_data, &[]).is_ok());
    for bad in [
        vec![range(0, 2)],                 // covers the PUSH32 opcode
        vec![range(1, 33)],                // covers POP
        vec![range(1, 0)],                 // empty
        vec![range(35, 20), range(1, 32)], // descending
        vec![range(1, 32), range(20, 4)],  // overlapping
        vec![range(50, 100)],              // past the end
    ] {
        let first_bad = bad
            .iter()
            .enumerate()
            .find(|(index, _)| validate_ranges(&push_data, &bad[..=*index]).is_err())
            .map(|(_, range)| range.clone())
            .unwrap();
        assert_eq!(
            validate_ranges(&push_data, &bad).unwrap_err(),
            err(PaymentCallRegistryError::invalid_code_range(
                first_bad.offset,
                first_bad.length
            ))
        );
    }
}

#[test]
fn propose_requires_governance_and_valid_selectors() -> eyre::Result<()> {
    at_t17(|fx| {
        let call = |selectors| IPaymentCallRegistry::proposeTemplateCall {
            code: program_code(0, 0).into(),
            ranges: ranges(),
            selectors,
        };
        assert_eq!(
            fx.registry
                .propose_template(Address::repeat_byte(1), call(selectors()))
                .unwrap_err(),
            err(PaymentCallRegistryError::unauthorized())
        );
        for (bad, expected) in [
            (vec![selector(AUTHORIZE, 1, 0)], AUTHORIZE),
            (vec![selector(AUTHORIZE, 1, 30_000_001)], AUTHORIZE),
            (vec![selector(AUTHORIZE, 33, 1)], AUTHORIZE),
            (
                vec![selector(AUTHORIZE, 1, 1), selector(AUTHORIZE, 2, 1)],
                AUTHORIZE,
            ),
            (
                vec![IPaymentCallRegistry::PaymentSelector {
                    selector: CAPTURE.into(),
                    calldataLength: 5,
                    gasCap: 1,
                }],
                CAPTURE,
            ),
        ] {
            assert_eq!(
                fx.registry
                    .propose_template(fx.governance, call(bad))
                    .unwrap_err(),
                err(PaymentCallRegistryError::invalid_payment_selector(
                    expected.into()
                ))
            );
        }
        // Selector without arguments is allowed.
        let id = fx
            .registry
            .propose_template(fx.governance, call(vec![selector(CAPTURE, 0, 1)]))?;
        assert_eq!(id, 1);
        assert_eq!(fx.registry.version()?, 1);
        // No selectors make callable code.
        let id = fx.registry.propose_template(fx.governance, call(vec![]))?;
        assert_eq!(id, 2);
        assert!(fx.registry.get_template(id)?.selectors.is_empty());
        Ok(())
    })
}

#[test]
fn propose_records_the_masked_template() -> eyre::Result<()> {
    at_t17(|fx| {
        let code = program_code(0xaa, 0xbb);
        let id = fx.propose(code.clone())?;
        let template = fx.registry.get_template(id)?;
        assert_eq!(template.maskedCodeHash, keccak256(program_code(0, 0)));
        assert_eq!(
            template.maskedCodeHash,
            fx.registry.masked_code_hash(&code, &ranges())?
        );
        assert_eq!(template.codeLength as usize, code.len());
        assert_eq!(template.proposedAt, NOW);
        assert_eq!(template.activationBlock, 0);
        assert_eq!(template.ranges, ranges());
        assert_eq!(template.selectors, selectors());
        assert_eq!(fx.registry.template_count()?, 1);
        assert_eq!(
            fx.registry.get_template(2).unwrap_err(),
            err(PaymentCallRegistryError::unknown_template(2))
        );
        let events = StorageCtx.get_events(PAYMENT_CALL_REGISTRY_ADDRESS);
        assert_eq!(
            events.last().unwrap(),
            &PaymentCallRegistryEvent::template_proposed(
                id,
                template.maskedCodeHash,
                NOW + TEMPLATE_TIMELOCK
            )
            .into_log_data()
        );
        Ok(())
    })
}

#[test]
fn activation_waits_for_the_timelock() -> eyre::Result<()> {
    at_t17(|fx| {
        let id = fx.propose(program_code(0, 0))?;
        warp(TEMPLATE_TIMELOCK - 1);
        assert_eq!(
            fx.registry
                .activate_template(fx.governance, id)
                .unwrap_err(),
            err(PaymentCallRegistryError::timelock_not_elapsed(
                NOW + TEMPLATE_TIMELOCK
            ))
        );
        warp(1);
        assert_eq!(
            fx.registry
                .activate_template(Address::repeat_byte(1), id)
                .unwrap_err(),
            err(PaymentCallRegistryError::unauthorized())
        );
        fx.registry.activate_template(fx.governance, id)?;
        assert_eq!(
            fx.registry.get_template(id)?.activationBlock,
            START_BLOCK + 1
        );
        assert_eq!(
            fx.registry
                .activate_template(fx.governance, id)
                .unwrap_err(),
            err(PaymentCallRegistryError::template_already_activated(id))
        );
        assert_eq!(fx.registry.version()?, 2);
        Ok(())
    })
}

#[test]
fn register_instance_matches_masked_code() -> eyre::Result<()> {
    at_t17(|fx| {
        let id = fx.active_template()?;
        let instance = Address::repeat_byte(0x11);
        let other = Address::repeat_byte(0x12);
        let foreign = Address::repeat_byte(0x13);
        deploy(instance, program_code(0x01, 0x02))?;
        deploy(other, program_code(0x03, 0x04))?;
        // One byte outside the masked ranges differs.
        let mut changed = program_code(0x01, 0x02);
        *changed.last_mut().unwrap() = 0x01;
        deploy(foreign, changed)?;

        assert_eq!(fx.registry.register_instance(instance)?, id);
        assert_eq!(fx.registry.register_instance(other)?, id);
        assert_eq!(
            fx.registry.register_instance(foreign).unwrap_err(),
            err(PaymentCallRegistryError::no_matching_template(foreign))
        );
        assert_eq!(
            fx.registry
                .register_instance(Address::repeat_byte(0x14))
                .unwrap_err(),
            err(PaymentCallRegistryError::no_matching_template(
                Address::repeat_byte(0x14)
            ))
        );
        assert_eq!(
            fx.registry.register_instance(instance).unwrap_err(),
            err(PaymentCallRegistryError::instance_already_registered(
                instance
            ))
        );
        let record = fx.registry.get_instance(instance)?;
        assert_eq!(record.templateId, id);
        // One epoch after registration.
        assert_eq!(record.activationBlock, START_BLOCK + EPOCH);
        assert_eq!(fx.registry.instance_activation_delay()?, EPOCH);
        Ok(())
    })
}

#[test]
fn removed_templates_do_not_match_new_instances() -> eyre::Result<()> {
    at_t17(|fx| {
        let id = fx.active_template()?;
        fx.registry.remove_template(fx.governance, id)?;
        assert_eq!(
            fx.registry.remove_template(fx.governance, id).unwrap_err(),
            err(PaymentCallRegistryError::template_removed_already(id))
        );
        assert_eq!(
            fx.registry
                .activate_template(fx.governance, id)
                .unwrap_err(),
            err(PaymentCallRegistryError::template_removed_already(id))
        );
        let instance = Address::repeat_byte(0x11);
        deploy(instance, program_code(0x01, 0x02))?;
        assert_eq!(
            fx.registry.register_instance(instance).unwrap_err(),
            err(PaymentCallRegistryError::no_matching_template(instance))
        );
        Ok(())
    })
}

#[test]
fn classification_follows_activation_and_removal_blocks() -> eyre::Result<()> {
    at_t17(|fx| {
        fx.active_template()?;
        let instance = Address::repeat_byte(0x11);
        deploy(instance, program_code(0x01, 0x02))?;
        fx.registry.register_instance(instance)?;
        let swipe = aa(vec![(instance, calldata(AUTHORIZE, 6))], 1_500_000);
        let active_from = START_BLOCK + EPOCH;

        let lookup =
            fx.registry
                .lookup_payment_call(instance, &calldata(AUTHORIZE, 6), active_from - 1)?;
        assert_eq!(lookup.gas_cap, None);
        assert_eq!(lookup.changes_at, active_from);
        assert!(!fx.lane_at(&swipe, active_from - 1));
        assert!(fx.lane_at(&swipe, active_from));
        assert_eq!(
            fx.registry.classify(&swipe, active_from)?.changes_at,
            u64::MAX
        );

        // Removal at block R takes effect at R + 1.
        let removal_block = active_from + 5;
        set_block(removal_block);
        fx.registry.remove_instance(fx.governance, instance)?;
        assert!(fx.lane_at(&swipe, removal_block));
        assert_eq!(
            fx.registry.classify(&swipe, removal_block)?.changes_at,
            removal_block + 1
        );
        assert!(!fx.lane_at(&swipe, removal_block + 1));
        assert_eq!(
            fx.registry.register_instance(instance).unwrap_err(),
            err(PaymentCallRegistryError::instance_removed_already(instance))
        );
        assert_eq!(
            fx.registry
                .remove_instance(fx.governance, instance)
                .unwrap_err(),
            err(PaymentCallRegistryError::instance_removed_already(instance))
        );
        assert_eq!(
            fx.registry
                .remove_instance(fx.governance, Address::repeat_byte(0x99))
                .unwrap_err(),
            err(PaymentCallRegistryError::unknown_instance(
                Address::repeat_byte(0x99)
            ))
        );
        Ok(())
    })
}

#[test]
fn template_removal_stops_its_instances() -> eyre::Result<()> {
    at_t17(|fx| {
        let id = fx.active_template()?;
        let instance = Address::repeat_byte(0x11);
        deploy(instance, program_code(0x01, 0x02))?;
        fx.registry.register_instance(instance)?;
        let capture = aa(vec![(instance, calldata(CAPTURE, 3))], 500_000);
        let block = START_BLOCK + EPOCH;
        set_block(block);
        assert!(fx.lane_at(&capture, block));
        fx.registry.remove_template(fx.governance, id)?;
        assert!(fx.lane_at(&capture, block));
        assert!(!fx.lane_at(&capture, block + 1));
        Ok(())
    })
}

#[test]
fn classification_requires_exact_calls_within_gas_caps() -> eyre::Result<()> {
    at_t17(|fx| {
        fx.active_template()?;
        let instance = Address::repeat_byte(0x11);
        let second = Address::repeat_byte(0x12);
        deploy(instance, program_code(0x01, 0x02))?;
        deploy(second, program_code(0x05, 0x06))?;
        fx.registry.register_instance(instance)?;
        fx.registry.register_instance(second)?;
        let block = START_BLOCK + EPOCH;
        let authorize = (instance, calldata(AUTHORIZE, 6));
        let capture = (second, calldata(CAPTURE, 3));

        assert!(fx.lane_at(&aa(vec![authorize.clone()], 1_500_000), block));
        assert!(!fx.lane_at(&aa(vec![authorize.clone()], 1_500_001), block));
        // Caps add up across calls.
        let both = vec![authorize.clone(), capture];
        assert!(fx.lane_at(&aa(both.clone(), 2_000_000), block));
        assert!(!fx.lane_at(&aa(both, 2_000_001), block));
        // Exact calldata length.
        let mut long = calldata(AUTHORIZE, 6).to_vec();
        long.push(0);
        assert!(!fx.lane_at(&aa(vec![(instance, long.into())], 1_000_000), block));
        assert!(!fx.lane_at(
            &aa(vec![(instance, calldata(AUTHORIZE, 5))], 1_000_000),
            block
        ));
        // Unlisted selector, unregistered target.
        assert!(!fx.lane_at(
            &aa(vec![(instance, calldata([1, 2, 3, 4], 6))], 100_000),
            block
        ));
        assert!(!fx.lane_at(
            &aa(
                vec![(Address::repeat_byte(0x77), calldata(AUTHORIZE, 6))],
                100_000
            ),
            block
        ));
        // A TIP-1045 payment call in the same transaction makes it general.
        let transfer = ITIP20::transferCall {
            to: Address::repeat_byte(1),
            amount: U256::ONE,
        }
        .abi_encode();
        let mixed = vec![
            authorize.clone(),
            (
                tempo_contracts::precompiles::PATH_USD_ADDRESS,
                transfer.into(),
            ),
        ];
        assert!(!fx.lane_at(&aa(mixed, 1_500_000), block));
        assert!(!fx.lane_at(&aa(vec![], 0), block));
        // TIP-1045's transaction-level rules apply.
        let with_access_list = TempoTxEnvelope::AA(
            TempoTransaction {
                calls: vec![Call::new(authorize.0, authorize.1)],
                gas_limit: 1_000_000,
                access_list: vec![Default::default()].into(),
                ..Default::default()
            }
            .into_signed(Signature::test_signature().into()),
        );
        assert!(!fx.lane_at(&with_access_list, block));
        // The view reports the cap at the current block.
        set_block(block);
        assert_eq!(
            fx.registry
                .payment_call_gas_cap(instance, &calldata(AUTHORIZE, 6))?,
            1_500_000
        );
        assert_eq!(
            fx.registry
                .payment_call_gas_cap(instance, &calldata(CAPTURE, 2))?,
            0
        );
        Ok(())
    })
}

#[test]
fn genesis_overrides_shorten_delays() -> eyre::Result<()> {
    at_t17(|fx| {
        assert_eq!(fx.registry.template_timelock()?, TEMPLATE_TIMELOCK);
        // Slot 1 packs the template timelock in its low 8 bytes and the instance delay in the
        // next 8, as a genesis allocation writes it.
        let value = U256::from(5u64) | (U256::from(2u64) << 64);
        StorageCtx.sstore(PAYMENT_CALL_REGISTRY_ADDRESS, U256::from(1), value)?;
        assert_eq!(fx.registry.template_timelock()?, 5);
        assert_eq!(fx.registry.instance_activation_delay()?, 2);

        let id = fx.propose(program_code(0, 0))?;
        warp(5);
        fx.registry.activate_template(fx.governance, id)?;
        let instance = Address::repeat_byte(0x11);
        deploy(instance, program_code(0x01, 0x02))?;
        fx.registry.register_instance(instance)?;
        assert_eq!(
            fx.registry.get_instance(instance)?.activationBlock,
            START_BLOCK + 2
        );
        Ok(())
    })
}

#[test]
fn governance_falls_back_to_validator_config_owner() -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T17);
    StorageCtx::enter(&mut storage, || {
        let registry = PaymentCallRegistry::new();
        assert_eq!(registry.governance()?, Address::ZERO);
        let owner = Address::repeat_byte(0x42);
        ValidatorConfig::new().initialize(owner)?;
        assert_eq!(registry.governance()?, owner);
        Ok(())
    })
}

#[test]
fn dispatch_covers_every_selector() -> eyre::Result<()> {
    at_t17(|fx| {
        let unsupported = check_selector_coverage(
            &mut fx.registry,
            IPaymentCallRegistryCalls::SELECTORS,
            "IPaymentCallRegistry",
            IPaymentCallRegistryCalls::name_by_selector,
        );
        assert_full_coverage([unsupported]);

        // A permissionless registration through the ABI.
        let id = fx.active_template()?;
        let instance = Address::repeat_byte(0x11);
        deploy(instance, program_code(0x01, 0x02))?;
        let output = fx.registry.call(
            &IPaymentCallRegistry::registerInstanceCall { instance }.abi_encode(),
            Address::repeat_byte(0x55),
        )?;
        assert_eq!(
            IPaymentCallRegistry::registerInstanceCall::abi_decode_returns(output.bytes())?,
            id
        );
        Ok(())
    })
}

#[test]
fn instances_register_again_after_their_template_is_removed() -> eyre::Result<()> {
    at_t17(|fx| {
        let old = fx.active_template()?;
        // A replacement with the same code, proposed while the old template is active.
        let new = fx.propose(program_code(0, 0))?;

        // Anyone may register an instance; here a third party binds it to the old template.
        let instance = Address::repeat_byte(0x11);
        deploy(instance, program_code(0x01, 0x02))?;
        assert_eq!(fx.registry.register_instance(instance)?, old);
        assert_eq!(
            fx.registry.register_instance(instance).unwrap_err(),
            err(PaymentCallRegistryError::instance_already_registered(
                instance
            ))
        );

        warp(TEMPLATE_TIMELOCK);
        let replaced_at = START_BLOCK + 2 * EPOCH;
        set_block(replaced_at);
        fx.registry.activate_template(fx.governance, new)?;
        fx.registry.remove_template(fx.governance, old)?;
        let swipe = aa(vec![(instance, calldata(AUTHORIZE, 6))], 1_500_000);
        assert!(fx.lane_at(&swipe, replaced_at));
        assert!(!fx.lane_at(&swipe, replaced_at + 1));

        // Once its template is removed (here from the next block), the instance registers
        // again under the replacement, effective one epoch later.
        let version = fx.registry.version()?;
        assert_eq!(fx.registry.register_instance(instance)?, new);
        assert_eq!(fx.registry.version()?, version + 1);
        let record = fx.registry.get_instance(instance)?;
        assert_eq!(record.templateId, new);
        assert_eq!(record.activationBlock, replaced_at + EPOCH);
        assert_eq!(record.removedAtBlock, 0);
        assert!(!fx.lane_at(&swipe, replaced_at + EPOCH - 1));
        assert!(fx.lane_at(&swipe, replaced_at + EPOCH));
        assert_eq!(
            fx.registry.register_instance(instance).unwrap_err(),
            err(PaymentCallRegistryError::instance_already_registered(
                instance
            ))
        );

        // Removal by governance stays final.
        fx.registry.remove_instance(fx.governance, instance)?;
        fx.registry.remove_template(fx.governance, new)?;
        assert_eq!(
            fx.registry.register_instance(instance).unwrap_err(),
            err(PaymentCallRegistryError::instance_removed_already(instance))
        );
        Ok(())
    })
}

#[test]
fn proposed_templates_do_not_capture_instances() -> eyre::Result<()> {
    at_t17(|fx| {
        // Template 1 is only proposed; template 2, with the same code, is active.
        let proposed = fx.propose(program_code(0, 0))?;
        let active = fx.active_template()?;
        assert!(proposed < active);

        let instance = Address::repeat_byte(0x11);
        deploy(instance, program_code(0x01, 0x02))?;
        assert_eq!(fx.registry.register_instance(instance)?, active);
        let swipe = aa(vec![(instance, calldata(AUTHORIZE, 6))], 1_500_000);
        assert!(fx.lane_at(&swipe, START_BLOCK + EPOCH));

        // With no activated template, nothing matches.
        let other = Address::repeat_byte(0x12);
        deploy(other, program_code(0x03, 0x04))?;
        fx.registry.remove_template(fx.governance, active)?;
        assert_eq!(
            fx.registry.register_instance(other).unwrap_err(),
            err(PaymentCallRegistryError::no_matching_template(other))
        );
        Ok(())
    })
}

#[test]
fn accounts_created_in_the_transaction_cannot_register() -> eyre::Result<()> {
    at_t17(|fx| {
        let id = fx.active_template()?;
        let instance = Address::repeat_byte(0x11);
        deploy(instance, program_code(0x01, 0x02))?;
        // Created in this transaction, its code could still be destroyed and redeployed.
        StorageCtx.set_created_in_tx(instance, true);
        assert_eq!(
            fx.registry.register_instance(instance).unwrap_err(),
            err(PaymentCallRegistryError::instance_created_in_transaction(
                instance
            ))
        );
        assert_eq!(fx.registry.get_instance(instance)?.templateId, 0);

        // In a later transaction it registers.
        StorageCtx.set_created_in_tx(instance, false);
        assert_eq!(fx.registry.register_instance(instance)?, id);
        Ok(())
    })
}

#[test]
fn callable_code_counts_as_registered_code_without_payment_calls() -> eyre::Result<()> {
    at_t17(|fx| {
        let program = fx.active_template()?;
        // PUSH32 <a> POP STOP: other code than the program's.
        let library_code = |a: u8| {
            let mut code = vec![0x7f];
            code.extend([a; 32]);
            code.extend([0x50, 0x00]);
            code
        };
        let library = fx.registry.propose_template(
            fx.governance,
            IPaymentCallRegistry::proposeTemplateCall {
                code: library_code(0).into(),
                ranges: vec![IPaymentCallRegistry::CodeRange {
                    offset: 1,
                    length: 32,
                }],
                selectors: vec![],
            },
        )?;
        warp(TEMPLATE_TIMELOCK);
        fx.registry.activate_template(fx.governance, library)?;

        let instance = Address::repeat_byte(0x11);
        let callee = Address::repeat_byte(0x12);
        deploy(instance, program_code(0x01, 0x02))?;
        deploy(callee, library_code(0x03))?;
        assert_eq!(fx.registry.register_instance(instance)?, program);
        assert_eq!(fx.registry.register_instance(callee)?, library);

        let active = START_BLOCK + EPOCH;
        for address in [instance, callee] {
            assert!(!fx.registry.is_registered_code(address, active - 1)?);
            assert!(fx.registry.is_registered_code(address, active)?);
        }
        assert!(
            !fx.registry
                .is_registered_code(Address::repeat_byte(0x13), active)?
        );
        // Calls to callable code never start a registered payment.
        let call = aa(vec![(callee, calldata(AUTHORIZE, 6))], 1_500_000);
        assert!(!fx.lane_at(&call, active));

        // Removal of the template or the instance ends it from the next block.
        set_block(active);
        fx.registry.remove_template(fx.governance, library)?;
        fx.registry.remove_instance(fx.governance, instance)?;
        assert!(fx.registry.is_registered_code(callee, active)?);
        assert!(fx.registry.is_registered_code(instance, active)?);
        assert!(!fx.registry.is_registered_code(callee, active + 1)?);
        assert!(!fx.registry.is_registered_code(instance, active + 1)?);
        Ok(())
    })
}
