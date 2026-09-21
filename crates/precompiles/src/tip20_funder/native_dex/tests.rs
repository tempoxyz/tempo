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
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
    let input = StorageCtx::enter(&mut storage, || {
        TIP20Setup::path_usd(ACCOUNT).apply().unwrap();
        let input = TIP20Setup::create("Input", "IN", ACCOUNT)
            .apply()
            .unwrap()
            .address();
        StablecoinDEX::new().create_pair(input).unwrap();
        input
    });
    (storage, NativeDexFundingSource::new(SOURCE, FUNDER), input)
}

fn prepare(input: Address, cap: U256, budget: U256) -> IFundingSource::prepareCall {
    IFundingSource::prepareCall {
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
            let plan = source.prepare(FUNDER, prepare(input, cap, budget)).unwrap();
            assert_eq!(
                (plan.assetIn, plan.rate, plan.maxAmountIn),
                (input, RATE_SCALE, expected)
            );
            assert_eq!(source.decode(&plan.data).unwrap(), (input, expected));
        }
    });
}

#[test]
fn preparation_rejects_forged_context_and_malformed_data() {
    let (mut storage, source, input) = setup();
    StorageCtx::enter(&mut storage, || {
        for mode in 0..4 {
            let mut call = prepare(input, U256::MAX, U256::from(50));
            match mode {
                1 => call.ownerAuthorized = false,
                2 => call.policyData = Bytes::from_static(b"policy"),
                3 => call.data = Bytes::from_static(b"invalid"),
                _ => {}
            }
            assert!(
                source
                    .prepare(if mode == 0 { ACCOUNT } else { FUNDER }, call)
                    .is_err()
            );
        }
    });
    storage.set_spec(TempoHardfork::T12);
    StorageCtx::enter(&mut storage, || {
        assert!(
            source
                .prepare(FUNDER, prepare(input, U256::MAX, U256::from(50)))
                .is_err()
        );
    });
}

#[test]
fn fund_requires_matching_native_scope_even_when_no_input_available() {
    let (mut storage, source, input) = setup();
    StorageCtx::enter(&mut storage, || {
        let plan = source
            .prepare(FUNDER, prepare(input, U256::MAX, U256::from(50)))
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
fn currency_metadata_allows_new_usd_assets_and_rejects_non_parity_assets() {
    let (mut storage, source, input) = setup();
    StorageCtx::enter(&mut storage, || {
        let output = TIP20Setup::create("Output", "OUT", ACCOUNT)
            .apply()
            .unwrap()
            .address();
        StablecoinDEX::new().create_pair(output).unwrap();
        let mut call = prepare(input, U256::MAX, U256::from(50));
        call.assetOut = output;
        assert!(source.prepare(FUNDER, call.clone()).is_ok());
        let eur = TIP20Setup::create("Euro", "EUR", ACCOUNT)
            .currency("EUR")
            .apply()
            .unwrap()
            .address();
        call.data = (eur, U256::MAX).abi_encode().into();
        assert!(source.prepare(FUNDER, call).is_err());
    });
}

#[test]
fn paused_intermediate_route_token_is_rejected() {
    let (mut storage, source, input) = setup();
    StorageCtx::enter(&mut storage, || {
        let output = TIP20Setup::create("Output", "OUT", ACCOUNT)
            .apply()
            .unwrap()
            .address();
        StablecoinDEX::new().create_pair(output).unwrap();
        let mut call = prepare(input, U256::MAX, U256::from(50));
        call.assetOut = output;
        assert!(source.prepare(FUNDER, call.clone()).is_ok());
        TIP20Setup::config(PATH_USD_ADDRESS)
            .with_admin(ACCOUNT)
            .with_role(ACCOUNT, TIP20Token::pause_role())
            .apply()
            .unwrap();
        TIP20Token::from_address(PATH_USD_ADDRESS)
            .unwrap()
            .pause(ACCOUNT, ITIP20::pauseCall {})
            .unwrap();
        assert!(source.prepare(FUNDER, call).is_err());
    });
}
