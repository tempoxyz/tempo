use super::*;
use crate::{
    storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider},
    test_util::TIP20Setup,
    tip20::ITIP20,
    tip20_funder::{IFundingSource, RATE_SCALE, permission::FundingPermission},
};
use alloy_primitives::address;
use tempo_chainspec::hardfork::TempoHardfork;

#[test]
fn funding_counts_wallet_and_internal_inputs_once_and_rolls_back() -> Result<()> {
    let owner = address!("0000000000000000000000000000000000002000");
    let source = address!("0000000000000000000000000000000000001000");
    let funder = address!("ffffffffffffffffffffffffffffffffffff1120");
    for internal in [0u128, 10, 30] {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("Input", "IN", owner)
                .with_issuer(owner)
                .with_mint(owner, U256::from(100))
                .apply()?;
            let mut dex = StablecoinDEX::new();
            dex.set_balance(owner, token.address(), internal)?;
            let permission = FundingPermission::new(
                funder,
                owner,
                source,
                &IFundingSource::Quote {
                    assetIn: token.address(),
                    rate: RATE_SCALE,
                    maxAmountIn: U256::from(30),
                    amountOut: U256::ZERO,
                    data: Default::default(),
                },
                U256::from(30),
            )?;
            permission.initialize()?;
            permission.enter(|| {
                {
                    let _checkpoint = StorageCtx.checkpoint();
                    dex.decrement_balance_or_transfer_from(owner, token.address(), 30, true)?;
                    assert_eq!(permission.usage()?.amount_in, U256::from(30));
                    assert_eq!(
                        token.balance_of(ITIP20::balanceOfCall { account: owner })?,
                        U256::from(70 + internal)
                    );
                    assert_eq!(dex.balance_of(owner, token.address())?, 0);
                }
                assert_eq!(permission.usage()?.amount_in, U256::ZERO);
                assert_eq!(dex.balance_of(owner, token.address())?, internal);
                assert_eq!(
                    token.balance_of(ITIP20::balanceOfCall { account: owner })?,
                    U256::from(100)
                );
                {
                    let _checkpoint = StorageCtx.checkpoint();
                    assert!(
                        dex.decrement_balance_or_transfer_from(owner, token.address(), 31, true)
                            .is_err()
                    );
                }
                assert_eq!(permission.usage()?.amount_in, U256::ZERO);
                Ok::<_, crate::error::TempoPrecompileError>(())
            })??;
            Ok::<(), crate::error::TempoPrecompileError>(())
        })?;
    }
    Ok::<(), crate::error::TempoPrecompileError>(())
}
