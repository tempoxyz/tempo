use super::*;
use crate::{
    PATH_USD_ADDRESS, storage::hashmap::HashMapStorageProvider, test_util::TIP20Setup,
    tip20_funder::permission::FundingPermission,
};
use alloy_primitives::{Bytes, address};
use tempo_chainspec::hardfork::TempoHardfork;

const ACCOUNT: Address = address!("0000000000000000000000000000000000002000");
const SOURCE: Address = address!("0000000000000000000000000000000000001000");
const FUNDER: Address = address!("ffffffffffffffffffffffffffffffffffff1120");

fn setup() -> (HashMapStorageProvider, NativeDexFundingSource, Address) {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
    let input = StorageCtx::enter(&mut storage, || {
        TIP20Setup::path_usd(ACCOUNT).apply().unwrap();
        let input = TIP20Setup::create("Input", "IN", ACCOUNT)
            .apply()
            .unwrap()
            .address();
        StablecoinDEX::new().create_pair(input).unwrap();
        input
    });
    (
        storage,
        NativeDexFundingSource::new(SOURCE, FUNDER, vec![input, PATH_USD_ADDRESS]),
        input,
    )
}

fn quote(input: Address, cap: U256, budget: U256) -> IFundingSource::quoteCall {
    IFundingSource::quoteCall {
        account: ACCOUNT,
        amountOut: U256::from(50),
        assetOut: PATH_USD_ADDRESS,
        maxCost: budget,
        data: (input, cap).abi_encode().into(),
        policyData: Bytes::new(),
        ownerAuthorized: true,
    }
}

#[test]
fn caps_omission_zero_and_native_width_without_truncation() {
    let (mut storage, source, input) = setup();
    StorageCtx::enter(&mut storage, || {
        for (cap, budget, expected) in [
            (U256::MAX, U256::from(50), U256::from(50)),
            (U256::ZERO, U256::from(50), U256::ZERO),
            (U256::from(30), U256::from(50), U256::from(30)),
            (U256::MAX, U256::MAX, U256::from(u128::MAX)),
            (
                U256::from(u128::MAX) + U256::ONE,
                U256::MAX,
                U256::from(u128::MAX),
            ),
        ] {
            let plan = source.quote(quote(input, cap, budget)).unwrap();
            assert_eq!(
                (plan.assetIn, plan.rate, plan.maxAmountIn),
                (input, RATE_SCALE, expected)
            );
            assert_eq!(source.decode(&plan.data).unwrap(), (input, expected));
        }
    });
}

#[test]
fn quoting_rejects_unsupported_policy_and_malformed_data() {
    let (mut storage, source, input) = setup();
    StorageCtx::enter(&mut storage, || {
        for mode in 1..4 {
            let mut call = quote(input, U256::MAX, U256::from(50));
            match mode {
                1 => call.ownerAuthorized = false,
                2 => call.policyData = Bytes::from_static(b"policy"),
                3 => call.data = Bytes::from_static(b"invalid"),
                _ => {}
            }
            assert!(source.quote(call).is_err());
        }
    });
    storage.set_spec(TempoHardfork::T11);
    StorageCtx::enter(&mut storage, || {
        assert!(
            source
                .quote(quote(input, U256::MAX, U256::from(50)))
                .is_err()
        );
    });
}

#[test]
fn fund_requires_matching_native_scope_even_when_no_input_available() {
    let (mut storage, source, input) = setup();
    StorageCtx::enter(&mut storage, || {
        let plan = source
            .quote(quote(input, U256::MAX, U256::from(50)))
            .unwrap();
        let call = IFundingSource::fundCall {
            account: ACCOUNT,
            assetOut: PATH_USD_ADDRESS,
            amountOut: U256::from(50),
            data: plan.data.clone(),
        };
        assert!(source.fund(FUNDER, call.clone()).is_err());
        for (account, address) in [(SOURCE, SOURCE), (ACCOUNT, ACCOUNT)] {
            let permission =
                FundingPermission::new(FUNDER, account, address, &plan, U256::from(50)).unwrap();
            permission.initialize().unwrap();
            permission
                .enter(|| assert!(source.fund(FUNDER, call.clone()).is_err()))
                .unwrap();
        }
        let permission =
            FundingPermission::new(FUNDER, ACCOUNT, SOURCE, &plan, U256::from(50)).unwrap();
        permission.initialize().unwrap();
        permission
            .enter(|| source.fund(FUNDER, call.clone()).unwrap())
            .unwrap();
        assert_eq!(permission.usage().unwrap().amount_in, U256::ZERO);
        assert!(source.fund(FUNDER, call).is_err());
    });
}

#[test]
fn all_route_assets_require_explicit_parity_approval() {
    let (mut storage, source, input) = setup();
    StorageCtx::enter(&mut storage, || {
        let output = TIP20Setup::create("Output", "OUT", ACCOUNT)
            .apply()
            .unwrap()
            .address();
        StablecoinDEX::new().create_pair(output).unwrap();
        let mut call = quote(input, U256::MAX, U256::from(50));
        call.assetOut = output;
        assert!(source.quote(call.clone()).is_err());
        // Both endpoints are allowed, but the common quote token is not.
        let endpoints_only = NativeDexFundingSource::new(SOURCE, FUNDER, vec![input, output]);
        assert!(endpoints_only.quote(call.clone()).is_err());
        let all =
            NativeDexFundingSource::new(SOURCE, FUNDER, vec![input, output, PATH_USD_ADDRESS]);
        assert!(all.quote(call).is_ok());
    });
}
