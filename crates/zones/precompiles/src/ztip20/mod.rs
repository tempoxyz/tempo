//! Zone pre-execution rules for the upstream Tempo TIP20 precompile.
//!
//! `TIP20Token` remains the source of truth for token and TIP403 policy behavior.
//! Before forwarding a call to Tempo, `TIP20Rules` applies only zone-specific checks:
//! privacy-gated reads, fixed gas for selected selectors, and blocked system/admin entry points.
//!
//! Accepted calldata and callers are forwarded unchanged to Tempo. Ordinary token state remains
//! Zone-local while the EVM context's database adapter exposes selected policy values from the
//! finalized Tempo L1 state.

use alloy_primitives::Address;
use alloy_sol_types::{SolCall, SolError, SolInterface};
use tempo_precompiles::{
    dispatch::abi_decoder_config_for_spec,
    tip20::{IRolesAuth, ITIP20},
};
pub use tempo_contracts::zones::InsufficientBalance;
use tempo_contracts::zones::Unauthorized;

use crate::{
    execution::{CallCheck, CallRules},
    privacy::check_caller,
    storage::StorageCtx,
};

/// Fixed gas charged for TIP20 transfer and approval selectors on the zone.
///
/// A constant charge hides storage-dependent execution costs that could reveal whether a recipient
/// has previously received tokens. This intentionally replaces upstream variable gas pricing.
pub const TIP20_FIXED_TRANSFER_GAS: u64 = 100_000;

pub(crate) const TIP20_FIXED_GAS_SELECTORS: &[[u8; 4]] = &[
    ITIP20::transferCall::SELECTOR,
    ITIP20::transferFromCall::SELECTOR,
    ITIP20::transferWithMemoCall::SELECTOR,
    ITIP20::transferFromWithMemoCall::SELECTOR,
    ITIP20::approveCall::SELECTOR,
    ITIP20::permitCall::SELECTOR,
];

/// Zone-specific rules applied before forwarding to upstream `TIP20Token`.
#[derive(Clone)]
pub(crate) struct TIP20Rules;

impl CallRules for TIP20Rules {
    fn fixed_gas(&self, selector: Option<[u8; 4]>) -> Option<u64> {
        selector
            .is_some_and(|selector| TIP20_FIXED_GAS_SELECTORS.contains(&selector))
            .then_some(TIP20_FIXED_TRANSFER_GAS)
    }

    /// Apply zone privacy and selector restrictions before upstream execution.
    fn admit(&self, data: &[u8], caller: Address) -> CallCheck {
        let config = abi_decoder_config_for_spec(StorageCtx::default().spec());
        if let Ok(call) = ITIP20::ITIP20Calls::abi_decode_with_config(data, config) {
            return match call {
                ITIP20::ITIP20Calls::balanceOf(call) => {
                    check_caller(caller, &[call.account])
                }
                ITIP20::ITIP20Calls::allowance(call) => {
                    check_caller(caller, &[call.owner, call.spender])
                }
                ITIP20::ITIP20Calls::nonces(call) => {
                    check_caller(caller, &[call.owner])
                }
                // Transfers are disabled during the initial permissioned Zone phase.
                // Private asset movement is limited to the protocol-managed inbox and outbox paths.
                ITIP20::ITIP20Calls::transferFrom(_)
                | ITIP20::ITIP20Calls::transfer(_)
                | ITIP20::ITIP20Calls::transferWithMemo(_)
                | ITIP20::ITIP20Calls::transferFromWithMemo(_) => {
                    CallCheck::Revert(Unauthorized {}.abi_encode().into())
                }
                // Inbox/outbox call TIP20 internally; public mint/burn entry points stay disabled.
                ITIP20::ITIP20Calls::mint(_)
                | ITIP20::ITIP20Calls::mintWithMemo(_)
                | ITIP20::ITIP20Calls::burn(_)
                | ITIP20::ITIP20Calls::burnWithMemo(_)
                // Rewards are deprecated and disabled.
                | ITIP20::ITIP20Calls::globalRewardPerToken(_)
                | ITIP20::ITIP20Calls::userRewardInfo(_)
                | ITIP20::ITIP20Calls::getPendingRewards(_)
                | ITIP20::ITIP20Calls::distributeReward(_)
                | ITIP20::ITIP20Calls::setRewardRecipient(_)
                | ITIP20::ITIP20Calls::claimRewards(_)
                | ITIP20::ITIP20Calls::optedInSupply(_)
                // Admin methods are disabled as TIP20 admin is the ZoneInbox.
                | ITIP20::ITIP20Calls::setSupplyCap(_)
                | ITIP20::ITIP20Calls::setLogoURI(_)
                | ITIP20::ITIP20Calls::pause(_)
                | ITIP20::ITIP20Calls::unpause(_)
                | ITIP20::ITIP20Calls::setNextQuoteToken(_)
                | ITIP20::ITIP20Calls::completeQuoteTokenUpdate(_)
                | ITIP20::ITIP20Calls::changeTransferPolicyId(_)
                | ITIP20::ITIP20Calls::burnBlocked(_) => {
                    CallCheck::Revert(Unauthorized {}.abi_encode().into())
                }
                ITIP20::ITIP20Calls::burnAt(_) => {
                    if StorageCtx::default().spec().is_t12() {
                        CallCheck::Revert(Unauthorized {}.abi_encode().into())
                    } else {
                        // Preserve upstream UnknownFunctionSelector before TIP-1006 activation.
                        CallCheck::Continue
                    }
                }
                ITIP20::ITIP20Calls::name(_)
                | ITIP20::ITIP20Calls::symbol(_)
                | ITIP20::ITIP20Calls::decimals(_)
                | ITIP20::ITIP20Calls::currency(_)
                | ITIP20::ITIP20Calls::totalSupply(_)
                | ITIP20::ITIP20Calls::supplyCap(_)
                | ITIP20::ITIP20Calls::transferPolicyId(_)
                | ITIP20::ITIP20Calls::paused(_)
                | ITIP20::ITIP20Calls::logoURI(_)
                | ITIP20::ITIP20Calls::quoteToken(_)
                | ITIP20::ITIP20Calls::nextQuoteToken(_)
                | ITIP20::ITIP20Calls::PAUSE_ROLE(_)
                | ITIP20::ITIP20Calls::UNPAUSE_ROLE(_)
                | ITIP20::ITIP20Calls::ISSUER_ROLE(_)
                | ITIP20::ITIP20Calls::BURN_BLOCKED_ROLE(_)
                | ITIP20::ITIP20Calls::BURN_AT_ROLE(_)
                | ITIP20::ITIP20Calls::approve(_)
                | ITIP20::ITIP20Calls::permit(_)
                | ITIP20::ITIP20Calls::DOMAIN_SEPARATOR(_) => CallCheck::Continue,
            };
        }

        let Ok(call) = IRolesAuth::IRolesAuthCalls::abi_decode_with_config(data, config) else {
            // Preserve the upstream error and gas behavior for malformed or unknown calldata.
            return CallCheck::Continue;
        };

        // Intentionally exhaustive: an upstream ABI addition must be classified here.
        match call {
            // All mutating role calls are disabled on zones.
            IRolesAuth::IRolesAuthCalls::grantRole(_)
            | IRolesAuth::IRolesAuthCalls::revokeRole(_)
            | IRolesAuth::IRolesAuthCalls::renounceRole(_)
            | IRolesAuth::IRolesAuthCalls::setRoleAdmin(_) => {
                CallCheck::Revert(Unauthorized {}.abi_encode().into())
            }
            IRolesAuth::IRolesAuthCalls::hasRole(_)
            | IRolesAuth::IRolesAuthCalls::getRoleAdmin(_) => CallCheck::Continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, B256, Bytes, U256, address};
    use alloy_evm::precompiles::DynPrecompile;
    use alloy_sol_types::{SolCall, SolError, SolInterface};
    use revm::precompile::PrecompileResult;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{TIP20Error, UnknownFunctionSelector};
    use tempo_precompiles::{
        PATH_USD_ADDRESS, Precompile,
        storage::{Handler, StorageCtx},
        test_util::TIP20Setup,
        tip20::{
            IRolesAuth, ISSUER_ROLE, ITIP20,
            ITIP20::InsufficientBalance as TIP20InsufficientBalance, TIP20Token,
        },
        zone_factory::ZonePortalStorage as ZonePortal,
    };
    use tempo_contracts::zones::Unauthorized;
    use zone_primitives::constants::{ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS};

    use crate::{
        TempoState,
        test_utils::{
            MockL1Reader, TestContext, call_precompile, test_context, test_env,
            test_storage_provider,
        },
    };

    const TEMPO_BLOCK_NUMBER: u64 = 7;
    const PORTAL_ADDRESS: Address = address!("0x0000000000000000000000000000000000000b01");

    fn rules() -> TIP20Rules {
        TIP20Rules
    }

    fn admit_at(
        rules: &TIP20Rules,
        data: &[u8],
        caller: Address,
        spec: TempoHardfork,
    ) -> CallCheck {
        let mut ctx = test_context();
        ctx.cfg.spec = spec;
        let mut storage = test_storage_provider(&mut ctx, u64::MAX, true);
        StorageCtx::enter(&mut storage, || rules.admit(data, caller))
    }

    fn assert_allowed(rules: &TIP20Rules, call: impl SolCall, caller: Address) {
        assert!(matches!(
            admit_at(rules, &call.abi_encode(), caller, TempoHardfork::T8),
            CallCheck::Continue
        ));
    }

    fn assert_unauthorized(rules: &TIP20Rules, call: impl SolCall, caller: Address) {
        assert!(matches!(
            admit_at(rules, &call.abi_encode(), caller, TempoHardfork::T8),
            CallCheck::Revert(data) if data == Unauthorized {}.abi_encode()
        ));
    }

    struct PrecompileHarness {
        ctx: TestContext,
        token: Address,
        alice: Address,
        bob: Address,
        spender: Address,
        sequencer: Address,
        l1_reader: MockL1Reader,
        precompile: DynPrecompile,
    }

    impl PrecompileHarness {
        fn new() -> eyre::Result<Self> {
            Self::new_at(TempoHardfork::T8)
        }

        fn new_at(spec: TempoHardfork) -> eyre::Result<Self> {
            let token = PATH_USD_ADDRESS;
            let admin = Address::with_last_byte(0xa1);
            let alice = Address::with_last_byte(0xa2);
            let bob = Address::with_last_byte(0xa3);
            let spender = Address::with_last_byte(0xa4);
            let issuer = Address::with_last_byte(0xa5);
            let sequencer = Address::with_last_byte(0xa6);
            let l1_reader = MockL1Reader::default();
            l1_reader.seed_active_sequencer(PORTAL_ADDRESS, TEMPO_BLOCK_NUMBER, sequencer);
            let mut ctx = test_context();
            ctx.cfg.spec = spec;

            {
                let mut storage = test_storage_provider(&mut ctx, u64::MAX, false);
                StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
                    TempoState::new()
                        .tempo_block_number
                        .write(TEMPO_BLOCK_NUMBER)?;
                    TIP20Setup::path_usd(admin)
                        .with_issuer(admin)
                        .with_issuer(issuer)
                        .with_issuer(ZONE_INBOX_ADDRESS)
                        .with_issuer(ZONE_OUTBOX_ADDRESS)
                        .with_mint(alice, U256::from(1_000_000u64))
                        .with_mint(ZONE_OUTBOX_ADDRESS, U256::from(10_000u64))
                        .with_approval(alice, spender, U256::from(300_000u64))
                        .apply()?;
                    Ok(())
                })?;
            }

            let env = test_env(&ctx);
            let precompile = crate::create_tip20_precompile(token, &env);

            Ok(Self {
                ctx,
                token,
                alice,
                bob,
                spender,
                sequencer,
                l1_reader,
                precompile,
            })
        }

        fn call(
            &mut self,
            caller: Address,
            calldata: Bytes,
            gas: u64,
            is_static: bool,
        ) -> PrecompileResult {
            call_precompile(
                &mut self.ctx,
                &self.precompile,
                caller,
                &calldata,
                gas,
                is_static,
                self.token,
                self.token,
            )
        }

        fn balance_of(&mut self, account: Address) -> eyre::Result<U256> {
            let mut storage = test_storage_provider(&mut self.ctx, u64::MAX, false);
            StorageCtx::enter(&mut storage, || {
                let token = TIP20Token::from_address(self.token).expect("token must exist");
                Ok(token.balance_of(ITIP20::balanceOfCall { account })?)
            })
        }

        fn allowance(&mut self, owner: Address, spender: Address) -> eyre::Result<U256> {
            let mut storage = test_storage_provider(&mut self.ctx, u64::MAX, false);
            StorageCtx::enter(&mut storage, || {
                let token = TIP20Token::from_address(self.token).expect("token must exist");
                Ok(token.allowance(ITIP20::allowanceCall { owner, spender })?)
            })
        }
    }

    #[test]
    fn read_privacy_rules_allow_only_owner_and_spender() {
        let owner = Address::repeat_byte(0x11);
        let spender = Address::repeat_byte(0x22);
        let sequencer = Address::repeat_byte(0x33);
        let outsider = Address::repeat_byte(0x44);
        let rules = TIP20Rules;
        let balance = ITIP20::balanceOfCall { account: owner };
        assert_allowed(&rules, balance.clone(), owner);
        assert_unauthorized(&rules, balance.clone(), sequencer);
        assert_unauthorized(&rules, balance, outsider);

        let allowance = ITIP20::allowanceCall { owner, spender };
        for caller in [owner, spender] {
            assert_allowed(&rules, allowance.clone(), caller);
        }
        assert_unauthorized(&rules, allowance.clone(), sequencer);
        assert_unauthorized(&rules, allowance, outsider);

        let nonce = ITIP20::noncesCall { owner };
        assert_allowed(&rules, nonce.clone(), owner);
        assert_unauthorized(&rules, nonce.clone(), sequencer);
        assert_unauthorized(&rules, nonce, outsider);
    }

    #[test]
    fn role_metadata_reads_are_allowed() {
        let caller = Address::repeat_byte(0x11);
        let account = Address::repeat_byte(0x22);
        let rules = rules();

        assert_allowed(&rules, ITIP20::BURN_AT_ROLECall {}, caller);

        assert_allowed(
            &rules,
            IRolesAuth::hasRoleCall {
                account,
                role: ISSUER_ROLE,
            },
            caller,
        );
        assert_allowed(
            &rules,
            IRolesAuth::getRoleAdminCall { role: ISSUER_ROLE },
            caller,
        );
    }

    #[test]
    fn all_transfer_calls_are_disallowed() {
        let rules = rules();
        let caller = Address::repeat_byte(0x11);
        let recipient = Address::repeat_byte(0x22);
        let amount = U256::ONE;
        let memo = B256::repeat_byte(0x33);
        let calls = [
            ITIP20::transferCall {
                to: recipient,
                amount,
            }
            .abi_encode(),
            ITIP20::transferFromCall {
                from: caller,
                to: recipient,
                amount,
            }
            .abi_encode(),
            ITIP20::transferWithMemoCall {
                to: recipient,
                amount,
                memo,
            }
            .abi_encode(),
            ITIP20::transferFromWithMemoCall {
                from: caller,
                to: recipient,
                amount,
                memo,
            }
            .abi_encode(),
        ];

        for call in calls {
            assert!(matches!(
                admit_at(&rules, &call, caller, TempoHardfork::T8),
                CallCheck::Revert(data) if data == Unauthorized {}.abi_encode()
            ));
        }
    }

    #[test]
    fn reward_reads_are_disallowed() {
        let caller = Address::repeat_byte(0x11);
        let account = Address::repeat_byte(0x22);
        let rules = rules();

        assert_unauthorized(&rules, ITIP20::globalRewardPerTokenCall {}, caller);
        assert_unauthorized(&rules, ITIP20::userRewardInfoCall { account }, caller);
        assert_unauthorized(&rules, ITIP20::getPendingRewardsCall { account }, caller);
    }

    #[test]
    fn token_admin_calls_are_disallowed() {
        let caller = Address::repeat_byte(0x11);
        let account = Address::repeat_byte(0x22);
        let rules = rules();

        assert_unauthorized(
            &rules,
            ITIP20::changeTransferPolicyIdCall { newPolicyId: 1 },
            caller,
        );
        assert_unauthorized(
            &rules,
            ITIP20::setSupplyCapCall {
                newSupplyCap: U256::MAX,
            },
            caller,
        );
        assert_unauthorized(
            &rules,
            ITIP20::setLogoURICall {
                newLogoURI: "https://example.com/token.svg".to_owned(),
            },
            caller,
        );
        assert_unauthorized(&rules, ITIP20::pauseCall {}, caller);
        assert_unauthorized(&rules, ITIP20::unpauseCall {}, caller);
        assert_unauthorized(
            &rules,
            ITIP20::setNextQuoteTokenCall {
                newQuoteToken: account,
            },
            caller,
        );
        assert_unauthorized(&rules, ITIP20::completeQuoteTokenUpdateCall {}, caller);
        assert_unauthorized(
            &rules,
            ITIP20::burnBlockedCall {
                from: account,
                amount: U256::ONE,
            },
            caller,
        );
    }

    #[test]
    fn role_mutations_are_disallowed() {
        let caller = Address::repeat_byte(0x11);
        let account = Address::repeat_byte(0x22);
        let role = ISSUER_ROLE;
        let rules = rules();

        assert_unauthorized(&rules, IRolesAuth::grantRoleCall { role, account }, caller);
        assert_unauthorized(&rules, IRolesAuth::revokeRoleCall { role, account }, caller);
        assert_unauthorized(&rules, IRolesAuth::renounceRoleCall { role }, caller);
        assert_unauthorized(
            &rules,
            IRolesAuth::setRoleAdminCall {
                role,
                adminRole: role,
            },
            caller,
        );
    }

    #[test]
    fn sequencer_privacy_access_is_denied_regardless_of_portal_state() -> eyre::Result<()> {
        let mut harness = PrecompileHarness::new()?;
        let next_sequencer = Address::repeat_byte(0x77);
        let calldata: Bytes = ITIP20::balanceOfCall {
            account: harness.alice,
        }
        .abi_encode()
        .into();

        assert!(
            harness
                .call(harness.sequencer, calldata.clone(), 100_000, true)?
                .is_revert()
        );
        assert!(
            harness
                .call(next_sequencer, calldata.clone(), 100_000, true)?
                .is_revert()
        );

        harness.l1_reader.with_storage(TEMPO_BLOCK_NUMBER, || {
            let mut portal = ZonePortal::new(PORTAL_ADDRESS);
            portal.role[harness.sequencer]
                .write(u8::from(tempo_contracts::zones::ZonePortal::Role::None))?;
            portal.role[next_sequencer]
                .write(u8::from(tempo_contracts::zones::ZonePortal::Role::Sequencer))
        })?;

        assert!(
            harness
                .call(next_sequencer, calldata.clone(), 100_000, true)?
                .is_revert()
        );
        assert!(
            harness
                .call(harness.sequencer, calldata, 100_000, true)?
                .is_revert()
        );

        Ok(())
    }

    #[test]
    fn non_canonical_address_padding_cannot_bypass_read_privacy() -> eyre::Result<()> {
        let mut harness = PrecompileHarness::new()?;
        let mut calldata = ITIP20::balanceOfCall {
            account: harness.alice,
        }
        .abi_encode();

        calldata[4] = 1;
        assert!(ITIP20::balanceOfCall::abi_decode_raw_validate(&calldata[4..]).is_err());
        assert_eq!(
            ITIP20::balanceOfCall::abi_decode_raw(&calldata[4..])?.account,
            harness.alice
        );

        let allowed = harness.call(harness.alice, calldata.clone().into(), 100_000, true)?;
        assert!(allowed.is_success());

        let blocked = harness.call(harness.bob, calldata.into(), 100_000, true)?;
        assert!(blocked.is_revert());
        assert_eq!(blocked.bytes, Bytes::from(Unauthorized {}.abi_encode()));

        Ok(())
    }

    #[test]
    fn t11_strict_decoding_precedes_read_privacy() -> eyre::Result<()> {
        let mut harness = PrecompileHarness::new_at(TempoHardfork::T11)?;
        let mut calldata = ITIP20::balanceOfCall {
            account: harness.alice,
        }
        .abi_encode();
        calldata[4] = 1;

        for caller in [harness.alice, harness.bob] {
            let output = harness.call(caller, calldata.clone().into(), 100_000, true)?;
            assert!(output.is_revert());
            assert!(output.bytes.is_empty());
        }

        Ok(())
    }

    #[test]
    fn wrapper_still_enforces_privacy_and_fixed_gas() -> eyre::Result<()> {
        let mut harness = PrecompileHarness::new()?;

        let private_balance = harness.call(
            harness.bob,
            ITIP20::balanceOfCall {
                account: harness.alice,
            }
            .abi_encode()
            .into(),
            TIP20_FIXED_TRANSFER_GAS,
            true,
        )?;
        assert!(private_balance.is_revert());
        assert_eq!(
            private_balance.bytes,
            Bytes::from(Unauthorized {}.abi_encode())
        );

        let approve = harness.call(
            harness.alice,
            ITIP20::approveCall {
                spender: harness.spender,
                amount: U256::from(12_345u64),
            }
            .abi_encode()
            .into(),
            TIP20_FIXED_TRANSFER_GAS,
            false,
        )?;
        assert!(approve.is_success());
        assert_eq!(approve.gas_used, TIP20_FIXED_TRANSFER_GAS);
        assert_eq!(
            harness.allowance(harness.alice, harness.spender)?,
            U256::from(12_345u64)
        );

        Ok(())
    }

    #[test]
    fn uninitialized_token_rejects_before_policy_read() -> eyre::Result<()> {
        let token = address!("20C0000000000000000000000000000000000999");
        let caller = Address::with_last_byte(0xa2);
        let spender = Address::with_last_byte(0xa3);
        let mut ctx = test_context();
        let env = test_env(&ctx);
        let precompile = crate::create_tip20_precompile(token, &env);
        let calldata: Bytes = ITIP20::approveCall {
            spender,
            amount: U256::ONE,
        }
        .abi_encode()
        .into();

        let result = call_precompile(
            &mut ctx,
            &precompile,
            caller,
            &calldata,
            TIP20_FIXED_TRANSFER_GAS,
            false,
            token,
            token,
        )?;

        assert!(result.is_revert());
        assert_eq!(
            result.bytes,
            Bytes::from(TIP20Error::uninitialized().selector())
        );

        Ok(())
    }

    #[test]
    fn malformed_calldata_uses_upstream_dispatch() -> eyre::Result<()> {
        let mut harness = PrecompileHarness::new()?;

        let balance_of = harness.call(
            harness.alice,
            ITIP20::balanceOfCall::SELECTOR.into(),
            100_000,
            true,
        )?;
        assert!(balance_of.is_revert());
        assert_eq!(balance_of.bytes, Bytes::new());

        let transfer = harness.call(
            harness.alice,
            ITIP20::transferCall::SELECTOR.into(),
            TIP20_FIXED_TRANSFER_GAS,
            false,
        )?;
        assert!(transfer.is_revert());
        assert_eq!(transfer.bytes, Bytes::new());
        assert_eq!(transfer.gas_used, TIP20_FIXED_TRANSFER_GAS);

        Ok(())
    }

    #[test]
    fn external_mint_and_burn_calls_are_disallowed() -> eyre::Result<()> {
        let mut harness = PrecompileHarness::new()?;
        let calls = [
            (
                ZONE_INBOX_ADDRESS,
                ITIP20::mintCall {
                    to: harness.bob,
                    amount: U256::ONE,
                }
                .abi_encode(),
            ),
            (
                ZONE_INBOX_ADDRESS,
                ITIP20::mintWithMemoCall {
                    to: harness.bob,
                    amount: U256::ONE,
                    memo: Default::default(),
                }
                .abi_encode(),
            ),
            (
                ZONE_OUTBOX_ADDRESS,
                ITIP20::burnCall { amount: U256::ONE }.abi_encode(),
            ),
            (
                ZONE_OUTBOX_ADDRESS,
                ITIP20::burnWithMemoCall {
                    amount: U256::ONE,
                    memo: Default::default(),
                }
                .abi_encode(),
            ),
        ];

        for (caller, calldata) in calls {
            let result = harness.call(caller, calldata.into(), 100_000, false)?;
            assert!(result.is_revert());
            assert_eq!(result.bytes, Bytes::from(Unauthorized {}.abi_encode()));
        }

        assert_eq!(harness.balance_of(harness.bob)?, U256::ZERO);
        assert_eq!(
            harness.balance_of(ZONE_OUTBOX_ADDRESS)?,
            U256::from(10_000u64)
        );

        Ok(())
    }

    #[test]
    #[ignore = "TODO: re-enable once zones allow user transfers"]
    fn transfer_from_insufficient_balance_does_not_reveal_the_source_balance() -> eyre::Result<()> {
        let mut harness = PrecompileHarness::new()?;
        // Craft a successful allowance return whose first four bytes collide with the upstream
        // error selector, exercising the redaction filter's revert-status guard.
        let mut allowance_bytes = [0u8; 32];
        allowance_bytes[..4].copy_from_slice(&TIP20InsufficientBalance::SELECTOR);
        allowance_bytes[31] = 1;
        let allowance = U256::from_be_bytes(allowance_bytes);

        harness.call(
            harness.alice,
            ITIP20::approveCall {
                spender: harness.spender,
                amount: allowance,
            }
            .abi_encode()
            .into(),
            TIP20_FIXED_TRANSFER_GAS,
            false,
        )?;

        let allowance_result = harness.call(
            harness.alice,
            ITIP20::allowanceCall {
                owner: harness.alice,
                spender: harness.spender,
            }
            .abi_encode()
            .into(),
            100_000,
            true,
        )?;
        assert!(allowance_result.is_success());
        assert_eq!(allowance_result.bytes, Bytes::from(allowance_bytes));

        let result = harness.call(
            harness.spender,
            ITIP20::transferFromCall {
                from: harness.alice,
                to: harness.bob,
                amount: U256::from(1_000_001u64),
            }
            .abi_encode()
            .into(),
            TIP20_FIXED_TRANSFER_GAS,
            false,
        )?;

        assert!(result.is_revert());
        assert_eq!(
            result.bytes,
            Bytes::from(InsufficientBalance {}.abi_encode())
        );
        assert_eq!(harness.balance_of(harness.alice)?, U256::from(1_000_000u64));

        Ok(())
    }

    #[test]
    fn fixed_gas_selectors_charge_exactly_one_hundred_thousand_gas() -> eyre::Result<()> {
        let mut harness = PrecompileHarness::new()?;
        let calls: Vec<(Address, ITIP20::ITIP20Calls)> = vec![
            (
                harness.alice,
                ITIP20::ITIP20Calls::approve(ITIP20::approveCall {
                    spender: harness.spender,
                    amount: U256::from(111_111u64),
                }),
            ),
            (
                harness.alice,
                ITIP20::ITIP20Calls::approve(ITIP20::approveCall {
                    spender: harness.spender,
                    amount: U256::from(222_222u64),
                }),
            ),
            (
                harness.alice,
                ITIP20::ITIP20Calls::transfer(ITIP20::transferCall {
                    to: harness.bob,
                    amount: U256::from(10_000u64),
                }),
            ),
            (
                harness.alice,
                ITIP20::ITIP20Calls::transfer(ITIP20::transferCall {
                    to: harness.bob,
                    amount: U256::from(10_000u64),
                }),
            ),
            (
                harness.alice,
                ITIP20::ITIP20Calls::transferWithMemo(ITIP20::transferWithMemoCall {
                    to: harness.bob,
                    amount: U256::from(10_000u64),
                    memo: Default::default(),
                }),
            ),
            (
                harness.spender,
                ITIP20::ITIP20Calls::transferFrom(ITIP20::transferFromCall {
                    from: harness.alice,
                    to: harness.bob,
                    amount: U256::from(10_000u64),
                }),
            ),
            (
                harness.spender,
                ITIP20::ITIP20Calls::transferFromWithMemo(ITIP20::transferFromWithMemoCall {
                    from: harness.alice,
                    to: harness.bob,
                    amount: U256::from(10_000u64),
                    memo: Default::default(),
                }),
            ),
        ];

        for (caller, call) in calls {
            let calldata = call.abi_encode().into();
            let output = harness.call(caller, calldata, TIP20_FIXED_TRANSFER_GAS, false)?;
            assert_eq!(output.gas_used, TIP20_FIXED_TRANSFER_GAS);
            assert_eq!(output.state_gas_used, 0);
        }
        Ok(())
    }

    #[test]
    fn fixed_gas_selector_mapping_is_complete() {
        let rules = rules();
        for selector in TIP20_FIXED_GAS_SELECTORS {
            assert_eq!(
                rules.fixed_gas(Some(*selector)),
                Some(TIP20_FIXED_TRANSFER_GAS)
            );
        }
        assert_eq!(rules.fixed_gas(Some([0xff; 4])), None);
        assert_eq!(rules.fixed_gas(None), None);
    }

    #[test]
    fn fixed_gas_keeps_allowance_state_changes_intact() -> eyre::Result<()> {
        let mut harness = PrecompileHarness::new()?;

        let approve = harness.call(
            harness.alice,
            ITIP20::approveCall {
                spender: harness.spender,
                amount: U256::from(123_456u64),
            }
            .abi_encode()
            .into(),
            TIP20_FIXED_TRANSFER_GAS,
            false,
        )?;
        assert!(approve.is_success());
        assert_eq!(
            harness.allowance(harness.alice, harness.spender)?,
            U256::from(123_456u64)
        );

        Ok(())
    }

    #[test]
    fn burn_at_reverts_without_changing_balances_or_supply() -> eyre::Result<()> {
        let mut harness = PrecompileHarness::new_at(TempoHardfork::T12)?;
        for caller in [
            harness.alice,
            harness.sequencer,
            ZONE_INBOX_ADDRESS,
            ZONE_OUTBOX_ADDRESS,
        ] {
            for amount in [U256::ZERO, U256::ONE, U256::MAX] {
                let calldata = ITIP20::burnAtCall {
                    from: harness.alice,
                    amount,
                }
                .abi_encode();
                let result = harness.call(caller, calldata.into(), 100_000, false)?;
                assert!(result.is_revert());
                assert_eq!(result.bytes, Bytes::from(Unauthorized {}.abi_encode()));
            }
        }

        assert_eq!(harness.balance_of(harness.alice)?, U256::from(1_000_000u64));
        assert_eq!(
            harness.balance_of(ZONE_OUTBOX_ADDRESS)?,
            U256::from(10_000u64)
        );
        let mut storage = test_storage_provider(&mut harness.ctx, u64::MAX, false);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            assert_eq!(
                TIP20Token::from_address(harness.token)?.total_supply()?,
                U256::from(1_010_000u64)
            );
            Ok(())
        })
    }

    #[test]
    fn malformed_burn_at_calldata_uses_upstream_dispatch() -> eyre::Result<()> {
        let mut harness = PrecompileHarness::new_at(TempoHardfork::T12)?;
        let calldata = ITIP20::burnAtCall {
            from: harness.alice,
            amount: U256::ONE,
        }
        .abi_encode();
        for len in [0, 3, 4, calldata.len() - 1] {
            let data = &calldata[..len];
            assert!(matches!(
                admit_at(&rules(), data, harness.alice, harness.ctx.cfg.spec),
                CallCheck::Continue
            ));
            let expected = {
                let mut storage = test_storage_provider(&mut harness.ctx, 100_000, false);
                StorageCtx::enter(&mut storage, || {
                    TIP20Token::from_address(harness.token)
                        .expect("token must exist")
                        .call(data, harness.alice)
                })?
            };
            let result =
                harness.call(harness.alice, Bytes::copy_from_slice(data), 100_000, false)?;
            assert!(result.is_revert());
            assert_eq!(result.bytes, expected.bytes);
        }
        Ok(())
    }

    #[test]
    fn burn_at_respects_t12_boundary() -> eyre::Result<()> {
        for (spec, active) in [
            (TempoHardfork::T8, false),
            (TempoHardfork::T11, false),
            (TempoHardfork::T12, true),
            (TempoHardfork::T13, true),
        ] {
            let mut harness = PrecompileHarness::new_at(spec)?;
            let calldata = ITIP20::burnAtCall {
                from: harness.alice,
                amount: U256::ONE,
            }
            .abi_encode();
            let admission = admit_at(&rules(), &calldata, harness.alice, spec);
            let expected = if active {
                assert!(matches!(admission, CallCheck::Revert(_)), "{spec:?}");
                Unauthorized {}.abi_encode()
            } else {
                assert!(matches!(admission, CallCheck::Continue), "{spec:?}");
                UnknownFunctionSelector {
                    selector: ITIP20::burnAtCall::SELECTOR.into(),
                }
                .abi_encode()
            };
            let result = harness.call(harness.alice, calldata.into(), 100_000, false)?;
            assert!(result.is_revert(), "{spec:?}");
            assert_eq!(result.bytes, Bytes::from(expected), "{spec:?}");
            assert_eq!(harness.balance_of(harness.alice)?, U256::from(1_000_000u64));
        }
        Ok(())
    }
}
