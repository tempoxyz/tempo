use super::*;
use crate::{
    storage::{ContractStorage, hashmap::HashMapStorageProvider},
    test_util::TIP20Setup,
    tip20::ITIP20,
    tip20_funder::RATE_SCALE,
};
use alloy_primitives::address;
use tempo_chainspec::hardfork::TempoHardfork;

const FUNDER: Address = address!("ffffffffffffffffffffffffffffffffffff1120");
const OWNER: Address = address!("0000000000000000000000000000000000002000");
const SOURCE: Address = address!("0000000000000000000000000000000000001000");

fn permission(asset: Address, rate: U256, cap: u64, cost: u64) -> FundingPermission {
    FundingPermission::new(
        FUNDER,
        OWNER,
        SOURCE,
        &IFundingSource::Plan {
            assetIn: asset,
            rate,
            maxAmountIn: U256::from(cap),
            data: Default::default(),
        },
        U256::from(cost),
    )
    .unwrap()
}

#[test]
fn bounded_transfers_need_no_allowance_and_leave_none() -> Result<()> {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
    StorageCtx::enter(&mut storage, || {
        let mut token = TIP20Setup::create("Input", "IN", OWNER)
            .with_issuer(OWNER)
            .with_mint(OWNER, U256::from(100))
            .apply()?;
        let permission = permission(token.address(), RATE_SCALE, 30, 50);
        permission.initialize()?;
        permission.enter(|| {
            token.transfer_from(
                SOURCE,
                ITIP20::transferFromCall {
                    from: OWNER,
                    to: SOURCE,
                    amount: U256::from(20),
                },
            )?;
            token.transfer_from(
                SOURCE,
                ITIP20::transferFromCall {
                    from: OWNER,
                    to: SOURCE,
                    amount: U256::from(10),
                },
            )?;
            assert!(
                token
                    .transfer_from(
                        SOURCE,
                        ITIP20::transferFromCall {
                            from: OWNER,
                            to: SOURCE,
                            amount: U256::ONE
                        }
                    )
                    .is_err()
            );
            Ok::<_, crate::error::TempoPrecompileError>(())
        })??;
        assert_eq!(
            permission.usage()?,
            FundingUsage {
                amount_in: U256::from(30),
                input_cost: U256::from(30)
            }
        );
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: OWNER })?,
            U256::from(70)
        );
        assert_eq!(
            token.allowance(ITIP20::allowanceCall {
                owner: OWNER,
                spender: SOURCE
            })?,
            U256::ZERO
        );
        assert!(
            token
                .transfer_from(
                    SOURCE,
                    ITIP20::transferFromCall {
                        from: OWNER,
                        to: SOURCE,
                        amount: U256::ONE
                    }
                )
                .is_err()
        );
        Ok::<(), crate::error::TempoPrecompileError>(())
    })
}

#[test]
fn rounds_cumulative_cost_and_restores_nested_debits() -> Result<()> {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
    StorageCtx::enter(&mut storage, || {
        let permission = permission(SOURCE, RATE_SCALE / U256::from(3), 100, 1);
        permission.initialize()?;
        permission.enter(|| {
            assert!(meter_input(OWNER, SOURCE, U256::ONE)?);
            {
                let _checkpoint = StorageCtx.checkpoint();
                assert!(meter_input(OWNER, SOURCE, U256::ONE)?);
                assert_eq!(permission.usage()?.amount_in, U256::from(2));
            }
            assert_eq!(permission.usage()?.amount_in, U256::ONE);
            assert!(meter_input(OWNER, SOURCE, U256::from(2))?);
            assert!(meter_input(OWNER, SOURCE, U256::ONE).is_err());
            assert_eq!(permission.usage()?.input_cost, U256::ONE);
            Ok::<_, crate::error::TempoPrecompileError>(())
        })??;
        assert!(!meter_input(OWNER, SOURCE, U256::ONE)?);
        permission.initialize()?;
        assert_eq!(permission.usage()?, FundingUsage::default());
        Ok::<(), crate::error::TempoPrecompileError>(())
    })
}

#[test]
fn rejects_wrong_asset_zero_input_nested_authority_and_access_keys() -> Result<()> {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
    StorageCtx::enter(&mut storage, || {
        let permission = permission(SOURCE, RATE_SCALE, 5, 5);
        permission.initialize()?;
        permission.enter(|| {
            assert!(meter_input(OWNER, FUNDER, U256::ONE).is_err());
            assert!(!meter_input(SOURCE, SOURCE, U256::ONE)?);
            assert!(permission.initialize().is_err());
            assert!(permission.enter(|| ()).is_err());
            Ok::<_, crate::error::TempoPrecompileError>(())
        })??;
        let no_input = self::permission(Address::ZERO, U256::ZERO, 0, 5);
        no_input.initialize()?;
        no_input.enter(|| assert!(meter_input(OWNER, SOURCE, U256::ONE).is_err()))?;
        AccountKeychain::new().set_transaction_key(SOURCE)?;
        assert!(permission.initialize().is_err());
        Ok::<(), crate::error::TempoPrecompileError>(())
    })
}

#[test]
fn existing_allowances_do_not_bypass_caps_and_refunds_do_not_restore_them() -> Result<()> {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
    StorageCtx::enter(&mut storage, || {
        let mut token = TIP20Setup::create("Input", "IN", OWNER)
            .with_issuer(OWNER)
            .with_mint(OWNER, U256::from(100))
            .with_approval(OWNER, SOURCE, U256::MAX)
            .apply()?;
        let permission = permission(token.address(), RATE_SCALE, 10, 10);
        permission.initialize()?;
        permission.enter(|| {
            token.transfer_from(
                SOURCE,
                ITIP20::transferFromCall {
                    from: OWNER,
                    to: SOURCE,
                    amount: U256::from(10),
                },
            )?;
            token.transfer(
                SOURCE,
                ITIP20::transferCall {
                    to: OWNER,
                    amount: U256::from(10),
                },
            )?;
            assert!(
                token
                    .transfer_from(
                        SOURCE,
                        ITIP20::transferFromCall {
                            from: OWNER,
                            to: SOURCE,
                            amount: U256::ONE
                        }
                    )
                    .is_err()
            );
            Ok::<_, crate::error::TempoPrecompileError>(())
        })??;
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: OWNER })?,
            U256::from(100)
        );
        assert_eq!(permission.usage()?.amount_in, U256::from(10));
        assert_eq!(
            token.allowance(ITIP20::allowanceCall {
                owner: OWNER,
                spender: SOURCE
            })?,
            U256::MAX
        );
        Ok::<(), crate::error::TempoPrecompileError>(())
    })
}

#[test]
fn funding_preserves_token_pause_and_transfer_policy_checks() -> Result<()> {
    use crate::{tip20::PAUSE_ROLE, tip403_registry::REJECT_ALL_POLICY_ID};
    for paused in [false, true] {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Input", "IN", OWNER)
                .with_issuer(OWNER)
                .with_role(OWNER, PAUSE_ROLE)
                .with_mint(OWNER, U256::from(100))
                .apply()?;
            if paused {
                token.pause(OWNER, ITIP20::pauseCall {})?;
            } else {
                token.change_transfer_policy_id(
                    OWNER,
                    ITIP20::changeTransferPolicyIdCall {
                        newPolicyId: REJECT_ALL_POLICY_ID,
                    },
                )?;
            }
            let permission = permission(token.address(), RATE_SCALE, 30, 30);
            permission.initialize()?;
            permission.enter(|| {
                assert!(
                    token
                        .transfer_from(
                            SOURCE,
                            ITIP20::transferFromCall {
                                from: OWNER,
                                to: SOURCE,
                                amount: U256::ONE
                            }
                        )
                        .is_err()
                );
            })?;
            assert_eq!(permission.usage()?, FundingUsage::default());
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: OWNER })?,
                U256::from(100)
            );
            Ok::<(), crate::error::TempoPrecompileError>(())
        })?;
    }
    Ok::<(), crate::error::TempoPrecompileError>(())
}

#[test]
fn scope_is_cleared_on_panic() -> Result<()> {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
    StorageCtx::enter(&mut storage, || {
        let permission = permission(SOURCE, RATE_SCALE, 5, 5);
        permission.initialize()?;
        let panic = std::panic::catch_unwind(|| permission.enter(|| panic!("callback failure")));
        assert!(panic.is_err());
        assert!(!meter_input(OWNER, SOURCE, U256::ONE)?);
        Ok::<(), crate::error::TempoPrecompileError>(())
    })
}
