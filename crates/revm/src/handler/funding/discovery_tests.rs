use super::{
    tests::{ACCOUNT, Trace, evm},
    *,
};
use alloy_primitives::{address, hex};
use alloy_sol_types::{SolCall, SolError, SolValue};
use revm::{
    context::{ContextSetters, TxEnv},
    database::{CacheDB, EmptyDB},
    handler::SystemCallTx,
    primitives::TxKind,
};
use tempo_contracts::{
    funding_discovery::IFundingDiscovery,
    precompiles::{IFundingPolicy, IFundingSource, PATH_USD_ADDRESS},
};
use tempo_precompiles::{PrecompileEnv, funding_policy::FundingPolicy, test_util::TIP20Setup};

const POLICY: Address = address!("0000000000000000000000000000000000006000");
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
fn solidity_discovery_reads_native_policy_through_staticcall() {
    let mut evm = evm(tempo_chainspec::hardfork::TempoHardfork::T13);
    let env = PrecompileEnv::new(
        &evm.inner.ctx.cfg,
        evm.actions.clone(),
        evm.non_creditable_slots.clone(),
    );
    evm.inner
        .precompiles
        .extend_precompiles([(POLICY, FundingPolicy::create_precompile(POLICY, &env))]);
    evm.inner
        .ctx
        .set_tx(TxEnv::new_system_tx_with_caller(ACCOUNT, POLICY, Bytes::new()).into());
    StorageCtx::enter_ctx(evm.ctx_mut(), StorageActions::disabled(), || {
        TIP20Setup::path_usd(ACCOUNT)
            .with_issuer(ACCOUNT)
            .with_mint(ACCOUNT, U256::from(20))
            .apply()
            .unwrap();
    });
    let create = IFundingPolicy::createPolicyCall {
        policy: IFundingPolicy::Policy {
            admins: vec![ACCOUNT],
            slippageBps: 100,
            routes: vec![IFundingPolicy::Route {
                token: PATH_USD_ADDRESS,
                sources: vec![],
            }],
        },
    };
    let result = call(&mut evm, TxKind::Call(POLICY), create.abi_encode().into());
    assert!(result.is_success(), "{result:?}");
    assert_eq!(
        IFundingPolicy::createPolicyCall::abi_decode_returns(result.output().unwrap()).unwrap(),
        1
    );

    let mut init = hex::decode(include_str!("fixtures/FundingDiscovery.hex").trim()).unwrap();
    init.extend(POLICY.abi_encode());
    let result = call(&mut evm, TxKind::Create, init.into());
    assert!(result.is_success(), "{result:?}");
    let helper = result.created_address().unwrap();
    let request = IFundingDiscovery::discoverCall {
        policyId: 1,
        account: ACCOUNT,
        token: PATH_USD_ADDRESS,
        amount: U256::from(50),
    };
    let result = call(&mut evm, TxKind::Call(helper), request.abi_encode().into());
    assert!(result.is_success(), "{result:?}");
    let found =
        IFundingDiscovery::discoverCall::abi_decode_returns(result.output().unwrap()).unwrap();
    assert_eq!(found.token, PATH_USD_ADDRESS);
    assert_eq!(found.amount, U256::from(50));
    assert_eq!(found.slippageBps, 100);
    assert!(found.sources.is_empty());
    assert!(
        evm.inner
            .inspector
            .calls
            .iter()
            .any(|(caller, target, scheme, is_static)| *caller == helper
                && *target == POLICY
                && *scheme == CallScheme::StaticCall
                && *is_static)
    );

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
    let result = call(&mut evm, TxKind::Create, init.into());
    assert!(result.is_success(), "{result:?}");
    let source = result.created_address().unwrap();
    let update = IFundingPolicy::modifyPolicyCall {
        policyId: 1,
        slippageBps: 100,
        routes: vec![IFundingPolicy::Route {
            token: PATH_USD_ADDRESS,
            sources: vec![IFundingPolicy::Source {
                target: source,
                data: Bytes::from_static(&[0x11, 0x22]),
            }],
        }],
    };
    let result = call(&mut evm, TxKind::Call(POLICY), update.abi_encode().into());
    assert!(result.is_success(), "{result:?}");
    let result = call(&mut evm, TxKind::Call(helper), request.abi_encode().into());
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
            .any(|(caller, target, scheme, is_static)| *caller == helper
                && *target == source
                && *scheme == CallScheme::StaticCall
                && *is_static)
    );

    let denied = IFundingDiscovery::discoverCall {
        token: Address::ZERO,
        amount: U256::ZERO,
        ..request
    };
    let result = call(&mut evm, TxKind::Call(helper), denied.abi_encode().into());
    assert!(!result.is_success());
    assert_eq!(
        result.output().unwrap().as_ref(),
        IFundingPolicy::TokenNotAllowed {
            token: Address::ZERO
        }
        .abi_encode()
    );
}
