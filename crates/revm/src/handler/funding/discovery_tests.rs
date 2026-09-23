use super::{
    tests::{ACCOUNT, Trace, evm},
    *,
};
use alloy_primitives::hex;
use alloy_sol_types::{SolCall, SolError, SolValue};
use revm::{
    context::{ContextSetters, TxEnv},
    database::{CacheDB, EmptyDB},
    handler::SystemCallTx,
    primitives::TxKind,
    state::{AccountInfo, Bytecode},
};
use tempo_contracts::{
    funding_discovery::{FUNDING_DISCOVERY_ADDRESS, FUNDING_DISCOVERY_RUNTIME, IFundingDiscovery},
    precompiles::{IFundingPolicy, IFundingSource, PATH_USD_ADDRESS},
};
use tempo_precompiles::test_util::TIP20Setup;

const POLICY: Address = tempo_contracts::precompiles::FUNDING_POLICY_ADDRESS;
const LIMIT: u64 = 10_000_000;

fn call(
    evm: &mut TempoEvm<CacheDB<EmptyDB>, Trace>,
    target: TxKind,
    data: Bytes,
) -> revm::context::result::ExecutionResult {
    let mut tx = TxEnv::new_system_tx_with_caller(ACCOUNT, POLICY, data);
    tx.kind = target;
    tx.gas_limit = LIMIT;
    evm.inner.ctx.set_tx(tx.into());
    TempoEvmHandler::new().inspect_run_system_call(evm).unwrap()
}

#[test]
fn protocol_discovery_uses_static_source_calls() {
    let mut evm = setup();
    let request = request();
    let result = call(
        &mut evm,
        TxKind::Call(FUNDING_DISCOVERY_ADDRESS),
        request.abi_encode().into(),
    );
    assert!(result.is_success(), "{result:?}");
    let found =
        IFundingDiscovery::discoverCall::abi_decode_returns(result.output().unwrap()).unwrap();
    assert_eq!(found.token, PATH_USD_ADDRESS);
    assert_eq!(found.amount, U256::from(50));
    assert_eq!(found.slippageBps, 100);
    assert!(found.sources.is_empty());
    let candidates = vec![
        IFundingSource::Candidate {
            requestData: Bytes::from_static(&[1]),
            availableAmount: U256::from(30),
        },
        IFundingSource::Candidate {
            requestData: Bytes::from_static(&[2]),
            availableAmount: U256::from(30),
        },
    ];
    let source = source(&mut evm, candidates);
    let request = set_sources(&mut evm, vec![rule(source)]);
    let result = call(
        &mut evm,
        TxKind::Call(FUNDING_DISCOVERY_ADDRESS),
        request.abi_encode().into(),
    );
    assert!(result.is_success(), "{result:?}");
    let found =
        IFundingDiscovery::discoverCall::abi_decode_returns(result.output().unwrap()).unwrap();
    assert_eq!(found.sources.len(), 2);
    for (i, candidate) in found.sources.iter().enumerate() {
        assert_eq!(candidate.target, source);
        assert_eq!(candidate.data.as_ref(), &[(i + 1) as u8]);
        assert_eq!(candidate.availableAmount, U256::from(30));
    }
    assert!(
        evm.inner
            .inspector
            .calls
            .iter()
            .any(
                |(caller, target, scheme, is_static)| *caller == FUNDING_DISCOVERY_ADDRESS
                    && *target == source
                    && *scheme == CallScheme::StaticCall
                    && *is_static
            )
    );

    let denied = IFundingDiscovery::discoverCall {
        token: Address::ZERO,
        amount: U256::ZERO,
        ..request
    };
    let result = call(
        &mut evm,
        TxKind::Call(FUNDING_DISCOVERY_ADDRESS),
        denied.abi_encode().into(),
    );
    assert!(!result.is_success());
    assert_eq!(
        result.output().unwrap().as_ref(),
        IFundingPolicy::TokenNotAllowed {
            token: Address::ZERO
        }
        .abi_encode()
    );
}

fn setup() -> TempoEvm<CacheDB<EmptyDB>, Trace> {
    let mut evm = evm(tempo_chainspec::hardfork::TempoHardfork::T13);
    let code = Bytecode::new_raw(FUNDING_DISCOVERY_RUNTIME);
    evm.inner.ctx.db_mut().insert_account_info(
        FUNDING_DISCOVERY_ADDRESS,
        AccountInfo {
            code_hash: code.hash_slow(),
            code: Some(code),
            ..Default::default()
        },
    );
    StorageCtx::enter_ctx(evm.ctx_mut(), StorageActions::disabled(), || {
        TIP20Setup::path_usd(ACCOUNT)
            .with_issuer(ACCOUNT)
            .with_mint(ACCOUNT, U256::from(20))
            .apply()
            .unwrap();
    });
    let create = IFundingPolicy::createPolicyCall {
        admins: vec![ACCOUNT],
        rules: rules(vec![]),
    };
    assert!(call(&mut evm, TxKind::Call(POLICY), create.abi_encode().into()).is_success());
    evm
}

fn rules(sources: Vec<IFundingPolicy::Source>) -> IFundingPolicy::Rules {
    IFundingPolicy::Rules {
        maxSlippageBps: 100,
        routes: vec![IFundingPolicy::Route {
            token: PATH_USD_ADDRESS,
            sources,
        }],
    }
}

fn request() -> IFundingDiscovery::discoverCall {
    IFundingDiscovery::discoverCall {
        policyId: 1,
        policyRules: rules(vec![]).abi_encode().into(),
        account: ACCOUNT,
        token: PATH_USD_ADDRESS,
        amount: U256::from(50),
    }
}

fn set_sources(
    evm: &mut TempoEvm<CacheDB<EmptyDB>, Trace>,
    sources: Vec<IFundingPolicy::Source>,
) -> IFundingDiscovery::discoverCall {
    let rules = rules(sources);
    let request = IFundingDiscovery::discoverCall {
        policyRules: rules.abi_encode().into(),
        ..request()
    };
    let update = IFundingPolicy::setRulesCall { policyId: 1, rules };
    assert!(call(evm, TxKind::Call(POLICY), update.abi_encode().into()).is_success());
    request
}

fn source(
    evm: &mut TempoEvm<CacheDB<EmptyDB>, Trace>,
    candidates: Vec<IFundingSource::Candidate>,
) -> Address {
    let mut init = hex::decode(include_str!("fixtures/DiscoverySource.hex").trim()).unwrap();
    init.extend(
        (
            ACCOUNT,
            PATH_USD_ADDRESS,
            U256::from(30),
            U256::from(30),
            candidates,
        )
            .abi_encode_params(),
    );
    let result = call(evm, TxKind::Create, init.into());
    assert!(result.is_success(), "{result:?}");
    result.created_address().unwrap()
}

fn rule(target: Address) -> IFundingPolicy::Source {
    IFundingPolicy::Source {
        target,
        data: Bytes::from_static(&[0x11, 0x22]),
    }
}

#[test]
fn discovery_preserves_source_order_and_independent_estimates() {
    let mut evm = setup();
    let a = source(
        &mut evm,
        vec![IFundingSource::Candidate {
            requestData: Bytes::from_static(&[1]),
            availableAmount: U256::from(30),
        }],
    );
    let b = source(
        &mut evm,
        vec![IFundingSource::Candidate {
            requestData: Bytes::from_static(&[2]),
            availableAmount: U256::from(30),
        }],
    );
    let request = set_sources(&mut evm, vec![rule(b), rule(a)]);
    let result = call(
        &mut evm,
        TxKind::Call(FUNDING_DISCOVERY_ADDRESS),
        request.abi_encode().into(),
    );
    assert!(result.is_success(), "{result:?}");
    let found =
        IFundingDiscovery::discoverCall::abi_decode_returns(result.output().unwrap()).unwrap();
    assert_eq!(
        found.sources.iter().map(|c| c.target).collect::<Vec<_>>(),
        vec![b, a]
    );
    assert_eq!(
        found
            .sources
            .iter()
            .map(|c| c.availableAmount)
            .sum::<U256>(),
        U256::from(60)
    );
}

#[test]
fn discovery_checks_policy_before_balance_and_skips_sources_when_satisfied() {
    let mut evm = setup();
    let mut request = set_sources(&mut evm, vec![rule(Address::repeat_byte(0x99))]);
    request.amount = U256::from(20);
    let result = call(
        &mut evm,
        TxKind::Call(FUNDING_DISCOVERY_ADDRESS),
        request.abi_encode().into(),
    );
    assert!(result.is_success(), "{result:?}");
    assert!(
        IFundingDiscovery::discoverCall::abi_decode_returns(result.output().unwrap())
            .unwrap()
            .sources
            .is_empty()
    );
    request.policyId = 99;
    let result = call(
        &mut evm,
        TxKind::Call(FUNDING_DISCOVERY_ADDRESS),
        request.abi_encode().into(),
    );
    assert_eq!(
        result.output().unwrap().as_ref(),
        IFundingPolicy::PolicyNotFound {}.abi_encode()
    );
}

#[test]
fn discovery_rejects_invalid_candidates_and_propagates_source_reverts() {
    let mut evm = setup();
    for (data, amount) in [
        (Bytes::new(), 10),
        (Bytes::from_static(&[1]), 0),
        (Bytes::from_static(&[1]), 31),
    ] {
        let target = source(
            &mut evm,
            vec![IFundingSource::Candidate {
                requestData: data,
                availableAmount: U256::from(amount),
            }],
        );
        let request = set_sources(&mut evm, vec![rule(target)]);
        let result = call(
            &mut evm,
            TxKind::Call(FUNDING_DISCOVERY_ADDRESS),
            request.abi_encode().into(),
        );
        assert_eq!(
            result.output().unwrap().as_ref(),
            IFundingDiscovery::InvalidCandidate { source: target }.abi_encode()
        );
    }
    let target = source(&mut evm, vec![]);
    let request = set_sources(
        &mut evm,
        vec![IFundingPolicy::Source {
            target,
            data: Bytes::from_static(&[0xff]),
        }],
    );
    let result = call(
        &mut evm,
        TxKind::Call(FUNDING_DISCOVERY_ADDRESS),
        request.abi_encode().into(),
    );
    assert!(!result.is_success());
    assert_eq!(
        result.output().unwrap().as_ref(),
        &alloy_primitives::keccak256("SourceFailure()")[..4]
    );
}

#[test]
fn discovery_supports_contract_staticcalls_and_plain_execution() {
    let mut evm = setup();
    let target = source(
        &mut evm,
        vec![IFundingSource::Candidate {
            requestData: Bytes::from_static(&[3]),
            availableAmount: U256::from(30),
        }],
    );
    let request = set_sources(&mut evm, vec![rule(target)]);
    let init = hex::decode(include_str!("fixtures/DiscoveryCaller.hex").trim()).unwrap();
    let deployed = call(&mut evm, TxKind::Create, init.into());
    assert!(deployed.is_success());
    let caller = deployed.created_address().unwrap();
    let traced = call(&mut evm, TxKind::Call(caller), request.abi_encode().into());
    assert!(traced.is_success(), "{traced:?}");
    let mut tx = TxEnv::new_system_tx_with_caller(ACCOUNT, caller, request.abi_encode().into());
    tx.gas_limit = LIMIT;
    evm.inner.ctx.set_tx(tx.into());
    let plain = TempoEvmHandler::new().run_system_call(&mut evm).unwrap();
    assert_eq!(plain.output(), traced.output());
    assert_eq!(plain.tx_gas_used(), traced.tx_gas_used());
    assert!(plain.is_success());
    assert!(evm.inner.frame_stack.index().is_none());
}

#[test]
fn discovery_source_cannot_write_and_failed_frames_can_be_reused() {
    use revm::state::{AccountInfo, Bytecode};
    let mut evm = setup();
    let target = Address::repeat_byte(0x77);
    // SSTORE would mutate slot zero unless the source is executed statically.
    let code = Bytecode::new_raw(hex!("600160005500").into());
    evm.inner.ctx.db_mut().insert_account_info(
        target,
        AccountInfo {
            code_hash: code.hash_slow(),
            code: Some(code),
            ..Default::default()
        },
    );
    let request = set_sources(&mut evm, vec![rule(target)]);
    let result = call(
        &mut evm,
        TxKind::Call(FUNDING_DISCOVERY_ADDRESS),
        request.abi_encode().into(),
    );
    assert!(!result.is_success());
    assert!(evm.inner.frame_stack.index().is_none());
    let request = set_sources(&mut evm, vec![]);
    assert!(
        call(
            &mut evm,
            TxKind::Call(FUNDING_DISCOVERY_ADDRESS),
            request.abi_encode().into()
        )
        .is_success()
    );
}

#[test]
fn discovery_out_of_gas_and_malformed_input_do_not_abort_execution() {
    let mut evm = setup();
    let request = request();
    for limit in [0, 100, 500, 1_000] {
        let mut tx = TxEnv::new_system_tx_with_caller(
            ACCOUNT,
            FUNDING_DISCOVERY_ADDRESS,
            request.abi_encode().into(),
        );
        tx.gas_limit = limit;
        evm.inner.ctx.set_tx(tx.into());
        let result = TempoEvmHandler::new()
            .inspect_run_system_call(&mut evm)
            .unwrap();
        assert!(!result.is_success(), "gas {limit}: {result:?}");
    }
    let result = call(
        &mut evm,
        TxKind::Call(FUNDING_DISCOVERY_ADDRESS),
        IFundingDiscovery::discoverCall::SELECTOR.to_vec().into(),
    );
    assert!(!result.is_success());
    assert!(
        call(
            &mut evm,
            TxKind::Call(FUNDING_DISCOVERY_ADDRESS),
            request.abi_encode().into()
        )
        .is_success()
    );
}

#[test]
fn discovery_is_unavailable_before_activation() {
    let mut evm = evm(tempo_chainspec::hardfork::TempoHardfork::T12);
    let request = request();
    let result = call(
        &mut evm,
        TxKind::Call(FUNDING_DISCOVERY_ADDRESS),
        request.abi_encode().into(),
    );
    assert!(result.output().is_none_or(|bytes| bytes.is_empty()));
    assert!(
        !evm.inner
            .inspector
            .calls
            .iter()
            .any(|(caller, _, _, _)| *caller == FUNDING_DISCOVERY_ADDRESS)
    );
}

#[test]
fn recursive_discovery_is_bounded_by_evm_gas_and_unwinds() {
    let mut evm = setup();
    let init = hex::decode(include_str!("fixtures/RecursiveDiscoverySource.hex").trim()).unwrap();
    let deployed = call(&mut evm, TxKind::Create, init.into());
    assert!(deployed.is_success());
    let request = set_sources(&mut evm, vec![rule(deployed.created_address().unwrap())]);
    let mut configure = alloy_primitives::keccak256("setRules(bytes)")[..4].to_vec();
    configure.extend((request.policyRules.clone(),).abi_encode_params());
    assert!(
        call(
            &mut evm,
            TxKind::Call(deployed.created_address().unwrap()),
            configure.into()
        )
        .is_success()
    );
    let result = call(
        &mut evm,
        TxKind::Call(FUNDING_DISCOVERY_ADDRESS),
        request.abi_encode().into(),
    );
    assert!(!result.is_success());
    assert!(evm.inner.frame_stack.index().is_none());
    let request = set_sources(&mut evm, vec![]);
    assert!(
        call(
            &mut evm,
            TxKind::Call(FUNDING_DISCOVERY_ADDRESS),
            request.abi_encode().into()
        )
        .is_success()
    );
}

#[test]
fn discovery_rejects_empty_source_return_data() {
    let mut evm = setup();
    let target = Address::repeat_byte(0x66);
    let request = set_sources(&mut evm, vec![rule(target)]);
    let result = call(
        &mut evm,
        TxKind::Call(FUNDING_DISCOVERY_ADDRESS),
        request.abi_encode().into(),
    );
    assert!(!result.is_success());
}

#[test]
fn discovery_rejects_overflowing_cost_budget() {
    let mut evm = setup();
    let request = request();
    let request = IFundingDiscovery::discoverCall {
        amount: U256::MAX,
        ..request
    };
    let result = call(
        &mut evm,
        TxKind::Call(FUNDING_DISCOVERY_ADDRESS),
        request.abi_encode().into(),
    );
    assert!(!result.is_success());
}

#[test]
fn discovery_meters_aliased_candidate_data_before_decoding() {
    use revm::state::{AccountInfo, Bytecode};
    let mut evm = setup();
    let target = Address::repeat_byte(0x55);
    // 512 array entries share one 4 KiB payload, expanding to over 2 MiB when decoded.
    let mut output = U256::from(32).to_be_bytes::<32>().to_vec();
    output.extend(U256::from(512).to_be_bytes::<32>());
    for _ in 0..512 {
        output.extend(U256::from(512 * 32).to_be_bytes::<32>());
    }
    output.extend(U256::from(64).to_be_bytes::<32>());
    output.extend(U256::from(1).to_be_bytes::<32>());
    output.extend(U256::from(4096).to_be_bytes::<32>());
    output.resize(output.len() + 4096, 1);
    let [hi, lo] = u16::try_from(output.len()).unwrap().to_be_bytes();
    let mut code = vec![
        0x61, hi, lo, 0x60, 14, 0x60, 0, 0x39, 0x61, hi, lo, 0x60, 0, 0xf3,
    ];
    code.extend(output);
    let code = Bytecode::new_raw(code.into());
    evm.inner.ctx.db_mut().insert_account_info(
        target,
        AccountInfo {
            code_hash: code.hash_slow(),
            code: Some(code),
            ..Default::default()
        },
    );
    let request = set_sources(&mut evm, vec![rule(target)]);
    let mut tx = TxEnv::new_system_tx_with_caller(
        ACCOUNT,
        FUNDING_DISCOVERY_ADDRESS,
        request.abi_encode().into(),
    );
    tx.gas_limit = 100_000;
    evm.inner.ctx.set_tx(tx.into());
    let result = TempoEvmHandler::new()
        .inspect_run_system_call(&mut evm)
        .unwrap();
    assert!(
        matches!(
            result,
            revm::context::result::ExecutionResult::Halt {
                reason: revm::context::result::HaltReason::OutOfGas(_),
                ..
            }
        ),
        "{result:?}"
    );
}
