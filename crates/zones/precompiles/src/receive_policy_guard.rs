//! Zone privacy rules for the upstream Tempo `ReceivePolicyGuard` precompile.
//!
//! A receipt witness is enumerable when most of its fields are known. Restricting
//! `balanceOf(bytes)` before the upstream balance lookup prevents unrelated callers from using
//! the return value as a receipt-existence and amount oracle.

use crate::{
    execution::{CallCheck, CallRules},
    storage::StorageCtx,
    ztip20::TIP20_FIXED_TRANSFER_GAS,
};
use alloy_primitives::Address;
use alloy_sol_types::{SolCall, SolError};
use tempo_contracts::precompiles::IReceivePolicyGuard;
use tempo_precompiles::{
    address_registry::AddressRegistry,
    dispatch::{abi_decoder_config_for_spec, selector_from_calldata},
};
use tempo_zone_contracts::Unauthorized;

/// Stakeholder-only admission for receipt balance lookups.
pub(crate) struct ReceivePolicyGuardRules;

impl CallRules for ReceivePolicyGuardRules {
    // Fixed gas hides destination balance-slot initialization from claim gas estimates, matching
    // the envelope used by direct Zone TIP-20 transfers.
    fn fixed_gas(&self, selector: Option<[u8; 4]>) -> Option<u64> {
        selector
            .is_some_and(|selector| selector == IReceivePolicyGuard::claimCall::SELECTOR)
            .then_some(TIP20_FIXED_TRANSFER_GAS)
    }

    fn admit(&self, data: &[u8], caller: Address) -> CallCheck {
        if selector_from_calldata(data) != Some(IReceivePolicyGuard::balanceOfCall::SELECTOR) {
            return CallCheck::Continue;
        }

        let Ok(call) = IReceivePolicyGuard::balanceOfCall::abi_decode_raw_with_config(
            &data[4..],
            abi_decoder_config_for_spec(StorageCtx::default().spec()),
        ) else {
            // Preserve the upstream ABI error for malformed calldata.
            return CallCheck::Continue;
        };
        let Ok(receipt) = IReceivePolicyGuard::ClaimReceiptV1::try_from(call.receipt) else {
            // Preserve the upstream InvalidReceipt error for malformed receipt bytes.
            return CallCheck::Continue;
        };

        if caller == receipt.originator
            || (!receipt.recoveryAuthority.is_zero() && caller == receipt.recoveryAuthority)
        {
            return CallCheck::Continue;
        }

        match AddressRegistry::new().resolve_recipient(receipt.recipient) {
            Ok(receiver) if caller == receiver => CallCheck::Continue,
            Ok(_) => CallCheck::Revert(Unauthorized {}.abi_encode().into()),
            Err(error) => CallCheck::Error(error),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    use alloy_evm::precompiles::DynPrecompile;
    use alloy_primitives::{B256, Bytes, U256};
    use alloy_sol_types::SolValue;
    use revm::precompile::{PrecompileOutput, PrecompileResult};
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{IReceivePolicyGuard::InboundKind, ITIP20, ITIP403Registry};
    use tempo_precompiles::{
        PATH_USD_ADDRESS, RECEIVE_POLICY_GUARD_ADDRESS,
        address_registry::AddressRegistry,
        receive_policy_guard::BLOCKED_RECEIPT_VERSION,
        storage::StorageCtx,
        test_util::{TIP20Setup, VIRTUAL_MASTER, register_virtual_master},
        tip403_registry::{ALLOW_ALL_POLICY_ID, REJECT_ALL_POLICY_ID, TIP403Registry},
    };

    use crate::test_utils::{
        TestContext, call_precompile, test_context, test_env, test_storage_provider,
    };

    const ADMIN: Address = Address::with_last_byte(0xa1);
    const ORIGINATOR: Address = Address::with_last_byte(0xa2);
    const RECEIVER: Address = Address::with_last_byte(0xa3);
    const RECOVERY: Address = Address::with_last_byte(0xa4);
    const OUTSIDER: Address = Address::with_last_byte(0xa5);
    const BLOCKED_AT: u64 = 123;
    const AMOUNT: U256 = U256::from_limbs([777, 0, 0, 0]);

    fn receipt(
        recipient: Address,
        recovery_authority: Address,
    ) -> IReceivePolicyGuard::ClaimReceiptV1 {
        IReceivePolicyGuard::ClaimReceiptV1::new(
            PATH_USD_ADDRESS,
            recovery_authority,
            ORIGINATOR,
            recipient,
            BLOCKED_AT,
            1,
            ITIP403Registry::BlockedReason::RECEIVE_POLICY as u8,
            InboundKind::TRANSFER,
            B256::ZERO,
        )
    }

    fn balance_call(receipt: &IReceivePolicyGuard::ClaimReceiptV1) -> Bytes {
        IReceivePolicyGuard::balanceOfCall {
            receipt: receipt.abi_encode().into(),
        }
        .abi_encode()
        .into()
    }

    fn assert_allowed(
        rules: &ReceivePolicyGuardRules,
        receipt: &IReceivePolicyGuard::ClaimReceiptV1,
        caller: Address,
    ) {
        assert!(matches!(
            rules.admit(&balance_call(receipt), caller),
            CallCheck::Continue
        ));
    }

    fn assert_unauthorized(
        rules: &ReceivePolicyGuardRules,
        receipt: &IReceivePolicyGuard::ClaimReceiptV1,
        caller: Address,
    ) {
        assert!(matches!(
            rules.admit(&balance_call(receipt), caller),
            CallCheck::Revert(data) if data == Unauthorized {}.abi_encode()
        ));
    }

    #[test]
    fn balance_admission_allows_only_direct_receipt_stakeholders() {
        let rules = ReceivePolicyGuardRules;
        let receipt = receipt(RECEIVER, RECOVERY);
        let mut ctx = test_context();
        let mut storage = test_storage_provider(&mut ctx, u64::MAX, true);

        StorageCtx::enter(&mut storage, || {
            for caller in [ORIGINATOR, RECEIVER, RECOVERY] {
                assert_allowed(&rules, &receipt, caller);
            }
            assert_unauthorized(&rules, &receipt, OUTSIDER);
        });
    }

    #[test]
    fn balance_admission_resolves_virtual_recipient_to_master() -> eyre::Result<()> {
        let rules = ReceivePolicyGuardRules;
        let mut ctx = test_context();
        ctx.cfg.spec = tempo_chainspec::hardfork::TempoHardfork::T8;
        let mut storage = test_storage_provider(&mut ctx, u64::MAX, false);

        StorageCtx::enter(&mut storage, || {
            let (_, virtual_recipient) = register_virtual_master(&mut AddressRegistry::new())?;
            let receipt = receipt(virtual_recipient, Address::ZERO);

            assert_allowed(&rules, &receipt, VIRTUAL_MASTER);
            assert_unauthorized(&rules, &receipt, OUTSIDER);
            Ok(())
        })
    }

    #[test]
    fn balance_admission_preserves_recipient_resolution_errors() -> eyre::Result<()> {
        let rules = ReceivePolicyGuardRules;
        let mut ctx = test_context();
        ctx.cfg.spec = tempo_chainspec::hardfork::TempoHardfork::T8;

        let virtual_recipient = {
            let mut storage = test_storage_provider(&mut ctx, u64::MAX, false);
            StorageCtx::enter(&mut storage, || {
                let (_, virtual_recipient) = register_virtual_master(&mut AddressRegistry::new())?;
                Ok::<_, eyre::Report>(virtual_recipient)
            })?
        };
        let receipt = receipt(virtual_recipient, Address::ZERO);
        let mut storage = test_storage_provider(&mut ctx, 0, true);

        StorageCtx::enter(&mut storage, || {
            assert!(matches!(
                rules.admit(&balance_call(&receipt), OUTSIDER),
                CallCheck::Error(tempo_precompiles::error::TempoPrecompileError::OutOfGas)
            ));
        });
        Ok(())
    }

    #[test]
    fn non_balance_calls_and_malformed_receipts_retain_upstream_dispatch() {
        let rules = ReceivePolicyGuardRules;
        let claim = IReceivePolicyGuard::claimCall {
            to: RECEIVER,
            receipt: Bytes::new(),
        }
        .abi_encode();
        let malformed = IReceivePolicyGuard::balanceOfCall {
            receipt: Bytes::from_static(&[0x01]),
        }
        .abi_encode();

        let mut ctx = test_context();
        let mut storage = test_storage_provider(&mut ctx, u64::MAX, true);
        StorageCtx::enter(&mut storage, || {
            assert!(matches!(rules.admit(&claim, OUTSIDER), CallCheck::Continue));
            assert!(matches!(
                rules.admit(&malformed, OUTSIDER),
                CallCheck::Continue
            ));
        });
    }

    #[test]
    fn t11_defers_noncanonical_balance_calldata_to_upstream() {
        let rules = ReceivePolicyGuardRules;
        let mut data = balance_call(&receipt(RECEIVER, RECOVERY)).to_vec();
        data.extend([0; 32]);
        let admit_at = |spec| {
            let mut ctx = test_context();
            ctx.cfg.spec = spec;
            let mut storage = test_storage_provider(&mut ctx, u64::MAX, true);
            StorageCtx::enter(&mut storage, || rules.admit(&data, OUTSIDER))
        };

        assert!(matches!(
            admit_at(TempoHardfork::T8),
            CallCheck::Revert(data) if data == Unauthorized {}.abi_encode()
        ));
        assert!(matches!(admit_at(TempoHardfork::T11), CallCheck::Continue));
    }

    #[test]
    fn fixed_gas_applies_only_to_claim() {
        let rules = ReceivePolicyGuardRules;

        assert_eq!(
            rules.fixed_gas(Some(IReceivePolicyGuard::claimCall::SELECTOR)),
            Some(TIP20_FIXED_TRANSFER_GAS)
        );
        assert_eq!(
            rules.fixed_gas(Some(IReceivePolicyGuard::balanceOfCall::SELECTOR)),
            None
        );
        assert_eq!(rules.fixed_gas(None), None);
    }

    struct GuardHarness {
        ctx: TestContext,
        precompile: DynPrecompile,
        receipt: IReceivePolicyGuard::ClaimReceiptV1,
    }

    impl GuardHarness {
        fn new() -> eyre::Result<Self> {
            let mut ctx = test_context();
            ctx.cfg.spec = tempo_chainspec::hardfork::TempoHardfork::T8;
            ctx.block.timestamp = U256::from(BLOCKED_AT);

            {
                let mut storage = test_storage_provider(&mut ctx, u64::MAX, false);
                StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
                    let mut token = TIP20Setup::path_usd(ADMIN)
                        .with_issuer(ADMIN)
                        .with_mint(ORIGINATOR, AMOUNT)
                        .apply()?;
                    TIP403Registry::new().set_receive_policy(
                        RECEIVER,
                        ITIP403Registry::setReceivePolicyCall {
                            senderPolicyId: REJECT_ALL_POLICY_ID,
                            tokenFilterId: ALLOW_ALL_POLICY_ID,
                            recoveryAuthority: RECEIVER,
                        },
                    )?;
                    token.transfer(
                        ORIGINATOR,
                        ITIP20::transferCall {
                            to: RECEIVER,
                            amount: AMOUNT,
                        },
                    )?;
                    Ok(())
                })?;
            }

            let receipt = receipt(RECEIVER, RECEIVER);
            assert_eq!(receipt.version, BLOCKED_RECEIPT_VERSION);
            let env = test_env(&ctx);
            let precompile = zone_precompile!(
                env,
                tempo_precompiles::receive_policy_guard::ReceivePolicyGuard,
                ReceivePolicyGuardRules
            );
            Ok(Self {
                ctx,
                precompile,
                receipt,
            })
        }

        fn call(&mut self, caller: Address, data: Bytes, is_static: bool) -> PrecompileResult {
            self.call_with_gas(caller, data, u64::MAX, is_static)
        }

        fn call_with_gas(
            &mut self,
            caller: Address,
            data: Bytes,
            gas: u64,
            is_static: bool,
        ) -> PrecompileResult {
            call_precompile(
                &mut self.ctx,
                &self.precompile,
                caller,
                &data,
                gas,
                is_static,
                RECEIVE_POLICY_GUARD_ADDRESS,
                RECEIVE_POLICY_GUARD_ADDRESS,
            )
        }

        fn balance_of(&mut self, caller: Address) -> PrecompileResult {
            self.balance_of_receipt(caller, self.receipt.clone())
        }

        fn balance_of_receipt(
            &mut self,
            caller: Address,
            receipt: IReceivePolicyGuard::ClaimReceiptV1,
        ) -> PrecompileResult {
            self.call(caller, balance_call(&receipt), true)
        }
    }

    fn decode_balance(output: &PrecompileOutput) -> eyre::Result<U256> {
        Ok(IReceivePolicyGuard::balanceOfCall::abi_decode_returns(
            &output.bytes,
        )?)
    }

    #[test]
    fn wrapper_hides_live_balance_from_outsider_and_preserves_claim() -> eyre::Result<()> {
        let mut harness = GuardHarness::new()?;

        let originator = harness.balance_of(ORIGINATOR)?;
        assert!(originator.is_success());
        assert_eq!(decode_balance(&originator)?, AMOUNT);

        let receiver = harness.balance_of(RECEIVER)?;
        assert!(receiver.is_success());
        assert_eq!(decode_balance(&receiver)?, AMOUNT);

        let outsider = harness.balance_of(OUTSIDER)?;
        assert!(outsider.is_revert());
        assert_eq!(outsider.bytes, Unauthorized {}.abi_encode());

        let mut absent = harness.receipt.clone();
        absent.blockedNonce += 1;
        let outsider_absent = harness.balance_of_receipt(OUTSIDER, absent.clone())?;
        assert!(outsider_absent.is_revert());
        assert_eq!(outsider_absent.bytes, outsider.bytes);
        let originator_absent = harness.balance_of_receipt(ORIGINATOR, absent)?;
        assert!(originator_absent.is_success());
        assert_eq!(decode_balance(&originator_absent)?, U256::ZERO);

        let claim = IReceivePolicyGuard::claimCall {
            to: RECEIVER,
            receipt: harness.receipt.abi_encode().into(),
        }
        .abi_encode()
        .into();
        let claimed = harness.call_with_gas(RECEIVER, claim, TIP20_FIXED_TRANSFER_GAS, false)?;
        assert!(claimed.is_success());
        assert_eq!(claimed.gas_used, TIP20_FIXED_TRANSFER_GAS);

        let balance = harness.balance_of(RECEIVER)?;
        assert_eq!(decode_balance(&balance)?, U256::ZERO);
        Ok(())
    }

    #[test]
    fn wrapper_pins_claim_revert_gas() -> eyre::Result<()> {
        let mut harness = GuardHarness::new()?;
        let mut absent = harness.receipt.clone();
        absent.blockedNonce += 1;
        let claim = IReceivePolicyGuard::claimCall {
            to: RECEIVER,
            receipt: absent.abi_encode().into(),
        }
        .abi_encode()
        .into();

        let result = harness.call_with_gas(RECEIVER, claim, TIP20_FIXED_TRANSFER_GAS, false)?;
        assert!(result.is_revert());
        assert_eq!(result.gas_used, TIP20_FIXED_TRANSFER_GAS);
        Ok(())
    }
}
