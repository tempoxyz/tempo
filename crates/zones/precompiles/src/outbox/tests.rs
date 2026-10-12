use super::*;

use alloy_evm::precompiles::DynPrecompile;
use alloy_primitives::{Bytes, address};
use alloy_sol_types::{SolCall, SolInterface};
use revm::precompile::{PrecompileHalt, PrecompileResult, PrecompileStatus};
use tempo_precompiles::{
    storage::{StorageCtx, StorageKey},
    test_util::TIP20Setup,
    zone_factory::portal::{self, ZonePortalStorage},
};
use tempo_contracts::zones::IZoneOutbox as ZoneOutboxAbi;
use zone_primitives::constants::TEMPO_STATE_ADDRESS;

use crate::{
    create_outbox_precompile,
    tempo_state::TEMPO_BLOCK_NUMBER_SLOT,
    test_utils::{
        MockL1Reader, TestContext, call_precompile, test_context, test_env, test_storage_provider,
    },
    tx_context,
};

const GAS: u64 = 10_000_000;
const ANCHOR: u64 = 42;
const TEST_MAX_TEMPO_GAS_RATE: u128 = 1_000_000_000_000_000_000;
const TX_HASH: B256 = B256::repeat_byte(0x42);
const PORTAL: Address = Address::repeat_byte(0x77);
const ALICE: Address = Address::with_last_byte(0xa1);
const BOB: Address = Address::with_last_byte(0xb2);
const SEQUENCER: Address = Address::with_last_byte(0xc3);
const FEE_PAYER: Address = Address::with_last_byte(0xd4);
const GATEWAY: Address = Address::with_last_byte(0xe5);

struct Harness {
    ctx: TestContext,
    precompile: DynPrecompile,
    l1: MockL1Reader,
    token: Address,
}

impl Harness {
    fn new() -> eyre::Result<Self> {
        let mut ctx = test_context();
        let token = tempo_precompiles::PATH_USD_ADDRESS;
        let l1 = MockL1Reader::default();
        l1.insert(
            PORTAL,
            SEQUENCER.mapping_slot(portal::slots::ROLE),
            ANCHOR,
            U256::from(u8::from(Role::Sequencer)),
        );
        l1.insert(
            PORTAL,
            token.mapping_slot(portal::slots::TOKEN_CONFIGS),
            ANCHOR,
            U256::ONE,
        );
        l1.insert(
            PORTAL,
            portal::slots::MAX_TEMPO_GAS_RATE,
            ANCHOR,
            U256::from(TEST_MAX_TEMPO_GAS_RATE),
        );
        {
            let mut storage = test_storage_provider(&mut ctx, u64::MAX, false);
            StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
                StorageCtx::default().sstore(
                    TEMPO_STATE_ADDRESS,
                    TEMPO_BLOCK_NUMBER_SLOT,
                    U256::from(ANCHOR),
                )?;

                ZoneOutbox::new().initialize()?;
                TIP20Setup::path_usd(ALICE)
                    .with_issuer(ALICE)
                    .with_issuer(ZONE_OUTBOX_ADDRESS)
                    .with_mint(ALICE, U256::from(1_000_000u64))
                    .with_mint(FEE_PAYER, U256::from(1_000_000u64))
                    .with_approval(ALICE, ZONE_OUTBOX_ADDRESS, U256::MAX)
                    .with_approval(FEE_PAYER, ZONE_OUTBOX_ADDRESS, U256::MAX)
                    .apply()?;
                Ok(())
            })?;
        }

        let env = test_env(&ctx);
        let precompile = create_outbox_precompile(L1State::new(l1.clone(), PORTAL), &env);

        Ok(Self {
            ctx,
            precompile,
            l1,
            token,
        })
    }

    #[rustfmt::skip]
    fn call_inner(&mut self, caller: Address, fee_payer: Address, data: impl AsRef<[u8]>, with_context: bool, is_static: bool) -> PrecompileResult {
        let _guard = with_context.then(|| tx_context::set_current_transaction(TX_HASH, fee_payer));
        call_precompile(
            &mut self.ctx, &self.precompile, caller, data.as_ref(), GAS, is_static, ZONE_OUTBOX_ADDRESS, ZONE_OUTBOX_ADDRESS
        )
    }

    fn call_without_hash(&mut self, caller: Address, data: impl AsRef<[u8]>) -> PrecompileResult {
        self.call_inner(caller, caller, data, false, false)
    }

    fn call(&mut self, caller: Address, data: impl AsRef<[u8]>) -> PrecompileResult {
        self.call_inner(caller, caller, data, true, false)
    }

    fn call_with_fee_payer(
        &mut self,
        caller: Address,
        fee_payer: Address,
        data: impl AsRef<[u8]>,
    ) -> PrecompileResult {
        self.call_inner(caller, fee_payer, data, true, false)
    }

    fn call_static(&mut self, caller: Address, data: impl AsRef<[u8]>) -> PrecompileResult {
        self.call_inner(caller, caller, data, false, true)
    }

    fn pending(&mut self) -> eyre::Result<Vec<ZoneOutboxAbi::PendingWithdrawal>> {
        let output = self.call(
            SEQUENCER,
            ZoneOutboxAbi::getPendingWithdrawalsCall {}.abi_encode(),
        )?;
        Ok(ZoneOutboxAbi::getPendingWithdrawalsCall::abi_decode_returns(&output.bytes)?)
    }

    fn last_fallback_nonce(&mut self) -> eyre::Result<u64> {
        let output = self.call(
            Address::ZERO,
            ZoneOutboxAbi::lastFallbackNonceCall {}.abi_encode(),
        )?;
        Ok(ZoneOutboxAbi::lastFallbackNonceCall::abi_decode_returns(
            &output.bytes,
        )?)
    }

    fn request(&mut self, amount: u128, to: Address, memo: B256) -> PrecompileResult {
        self.request_with_gas(amount, to, memo, 0)
    }

    fn request_with_gas(
        &mut self,
        amount: u128,
        to: Address,
        memo: B256,
        gas_limit: u64,
    ) -> PrecompileResult {
        self.request_custom(ZoneOutboxAbi::requestWithdrawalCall {
            token: self.token,
            to,
            amount,
            memo,
            gasLimit: gas_limit,
            zoneFallbackRecipient: ALICE,
            data: Bytes::new(),
            revealTo: Bytes::new(),
        })
    }

    fn request_custom(&mut self, call: ZoneOutboxAbi::requestWithdrawalCall) -> PrecompileResult {
        self.call(ALICE, call.abi_encode())
    }

    fn set_gas_rate(&mut self, rate: u128) -> PrecompileResult {
        self.call(
            SEQUENCER,
            ZoneOutboxAbi::setTempoGasRateCall {
                _tempoGasRate: rate,
            }
            .abi_encode(),
        )
    }

    fn set_max_withdrawals(&mut self, max: u32) -> PrecompileResult {
        self.call(
            SEQUENCER,
            ZoneOutboxAbi::setMaxWithdrawalsPerBlockCall {
                _maxWithdrawalsPerBlock: max,
            }
            .abi_encode(),
        )
    }

    fn set_max_tempo_gas_rate(&self, max: u128) {
        self.l1.insert(
            PORTAL,
            portal::slots::MAX_TEMPO_GAS_RATE,
            ANCHOR,
            U256::from(max),
        );
    }

    fn set_modes(&self, access_enforced: bool, gateway_enforced: bool) {
        let modes =
            U256::from(u8::from(access_enforced)) | (U256::from(u8::from(gateway_enforced)) << 8);
        self.l1
            .insert(PORTAL, portal::slots::IS_ACCESS_ENFORCED, ANCHOR, modes);
    }

    fn set_role(&self, account: Address, role: Role) {
        self.l1.insert(
            PORTAL,
            account.mapping_slot(portal::slots::ROLE),
            ANCHOR,
            U256::from(u8::from(role)),
        );
    }

    fn set_token_enabled(&self, enabled: bool) {
        self.l1.insert(
            PORTAL,
            self.token.mapping_slot(portal::slots::TOKEN_CONFIGS),
            ANCHOR,
            U256::from(u8::from(enabled)),
        );
    }

    fn set_pause_expiry(&self, expiry: u64) {
        self.l1.insert(
            PORTAL,
            portal::slots::PAUSE_EXPIRY,
            ANCHOR,
            U256::from(expiry) << 64,
        );
    }

    fn balance_of(&mut self, account: Address) -> eyre::Result<U256> {
        let mut storage = test_storage_provider(&mut self.ctx, u64::MAX, false);
        StorageCtx::enter(&mut storage, || {
            let token = TIP20Token::from_address(self.token).expect("initialized token");
            Ok(token.balance_of(ITIP20::balanceOfCall { account })?)
        })
    }

    fn finalize(&mut self, count: usize) -> PrecompileResult {
        self.call(
            Address::ZERO,
            ZoneOutboxAbi::finalizeWithdrawalBatchCall {
                count: U256::from(count),
                blockNumber: 0,
                encryptedSenders: vec![Bytes::new(); count],
            }
            .abi_encode(),
        )
    }
}

fn assert_revert(result: PrecompileResult, error: impl SolInterface) {
    let output = result.expect("precompile error");
    assert!(output.is_revert());
    assert_eq!(output.bytes, error.abi_encode());
}

#[test]
fn role_binding_order_matches_solidity_role_enum() {
    assert_eq!(
        [
            u8::from(Role::None),
            u8::from(Role::Sequencer),
            u8::from(Role::Account),
            u8::from(Role::CallbackGateway),
        ],
        [0, 1, 2, 3]
    );
}

#[test]
fn request_withdrawal_stores_fields_and_fifo_order() -> eyre::Result<()> {
    let mut harness = Harness::new()?;
    harness.request(500, ALICE, B256::repeat_byte(1))?;
    harness.request(300, BOB, B256::repeat_byte(2))?;

    let pending = harness.pending()?;
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[0].sender, ALICE);
    assert_eq!(pending[0].txHash, TX_HASH);
    assert_eq!(pending[0].to, ALICE);
    assert_eq!(pending[0].amount, 500);
    assert_eq!(pending[1].to, BOB);
    assert_eq!(pending[1].amount, 300);
    Ok(())
}

#[test]
fn pending_withdrawal_getters_require_sequencer_or_system() -> eyre::Result<()> {
    let mut harness = Harness::new()?;

    for calldata in [
        ZoneOutboxAbi::pendingWithdrawalsCountCall {}.abi_encode(),
        ZoneOutboxAbi::getPendingWithdrawalsCall {}.abi_encode(),
    ] {
        assert_revert(
            harness.call(ALICE, calldata.clone()),
            ZoneOutboxError::only_sequencer(),
        );

        assert!(harness.call(SEQUENCER, calldata.clone())?.is_success());
        assert!(harness.call(Address::ZERO, calldata)?.is_success());
    }

    Ok(())
}

#[test]
fn outbox_reads_injected_l1_state_at_tempo_checkpoint() -> eyre::Result<()> {
    let mut harness = Harness::new()?;
    harness.set_gas_rate(1)?;
    harness.request(1, BOB, B256::ZERO)?;

    let portal = ZonePortalStorage::new(PORTAL);
    assert_eq!(harness.l1.storage_requests().len(), 6);
    assert!(harness.l1.storage_requests().contains(&(
        PORTAL,
        portal::slots::PAUSE_EXPIRY.into(),
        ANCHOR
    )));
    assert_eq!(harness.l1.request_count(ANCHOR, &portal.role[SEQUENCER]), 1);
    assert_eq!(
        harness.l1.request_count(ANCHOR, &portal.max_tempo_gas_rate),
        1
    );
    assert_eq!(
        harness
            .l1
            .request_count(ANCHOR, &portal.token_configs[harness.token].enabled),
        1
    );
    assert_eq!(
        harness.l1.request_count(ANCHOR, &portal.is_access_enforced),
        2
    );
    Ok(())
}

#[test]
fn request_withdrawal_rejects_missing_transaction_hash() -> eyre::Result<()> {
    let mut harness = Harness::new()?;
    let token = harness.token;
    let result = harness.call_without_hash(
        ALICE,
        ZoneOutboxAbi::requestWithdrawalCall {
            token,
            to: BOB,
            amount: 1,
            memo: B256::ZERO,
            gasLimit: 0,
            zoneFallbackRecipient: ALICE,
            data: Bytes::new(),
            revealTo: Bytes::new(),
        }
        .abi_encode(),
    );
    assert_revert(result, ZoneOutboxError::invalid_current_tx_hash());
    assert!(
        harness.l1.storage_requests().is_empty(),
        "missing transaction context must be rejected before portal reads"
    );
    Ok(())
}

#[test]
fn request_withdrawal_rejects_unknown_token_before_portal_read() -> eyre::Result<()> {
    let mut harness = Harness::new()?;
    let result = harness.request_custom(ZoneOutboxAbi::requestWithdrawalCall {
        token: address!("0x20c000000000000000000000000000000000ffff"),
        to: BOB,
        amount: 1,
        memo: B256::ZERO,
        gasLimit: 0,
        zoneFallbackRecipient: ALICE,
        data: Bytes::new(),
        revealTo: Bytes::new(),
    });
    assert_revert(result, TIP20Error::uninitialized());
    assert!(
        harness.l1.storage_requests().is_empty(),
        "unknown tokens must be rejected before portal reads"
    );
    Ok(())
}

#[test]
fn request_withdrawal_rejects_portal_disabled_token_before_state_mutation() -> eyre::Result<()> {
    let mut harness = Harness::new()?;
    harness.set_token_enabled(false);
    let balance_before = harness.balance_of(ALICE)?;

    assert_revert(
        harness.request(1, BOB, B256::ZERO),
        ZonePortalError::token_not_enabled(),
    );
    assert_eq!(harness.balance_of(ALICE)?, balance_before);
    assert!(harness.pending()?.is_empty());
    assert_eq!(harness.last_fallback_nonce()?, 0);
    Ok(())
}

#[test]
fn request_withdrawal_rejects_active_portal_pause_before_state_mutation() -> eyre::Result<()> {
    let mut harness = Harness::new()?;
    harness.ctx.block.timestamp = U256::from(100);
    harness.set_pause_expiry(200);
    let balance_before = harness.balance_of(ALICE)?;

    assert_revert(
        harness.request(1, BOB, B256::ZERO),
        ZonePortalError::portal_is_paused(),
    );
    assert_eq!(harness.balance_of(ALICE)?, balance_before);
    assert!(harness.pending()?.is_empty());
    assert_eq!(harness.last_fallback_nonce()?, 0);
    Ok(())
}

#[test]
fn request_withdrawal_enforces_all_access_and_gateway_mode_combinations() -> eyre::Result<()> {
    // Open access, open gateway: plain and callback withdrawals accept arbitrary recipients.
    let mut open_open = Harness::new()?;
    open_open.set_modes(false, false);
    open_open.request(1, BOB, B256::ZERO)?;
    open_open.request_with_gas(1, GATEWAY, B256::ZERO, 1)?;

    // Closed access, open gateway: plain recipients need the Account role, while callback
    // recipients remain unrestricted.
    let mut closed_open = Harness::new()?;
    closed_open.set_modes(true, false);
    let balance_before = closed_open.balance_of(ALICE)?;
    assert_revert(
        closed_open.request(1, BOB, B256::ZERO),
        ZonePortalError::account_not_allowed(BOB),
    );
    assert_eq!(closed_open.balance_of(ALICE)?, balance_before);
    assert!(closed_open.pending()?.is_empty());
    closed_open.set_role(BOB, Role::Account);
    closed_open.request(1, BOB, B256::ZERO)?;
    closed_open.request_with_gas(1, FEE_PAYER, B256::ZERO, 1)?;

    // Open access, enforced gateway: arbitrary plain recipients remain valid, but registered
    // gateways require callback gas and callback targets must have the CallbackGateway role.
    let mut open_enforced = Harness::new()?;
    open_enforced.set_modes(false, true);
    open_enforced.set_role(GATEWAY, Role::CallbackGateway);
    open_enforced.request(1, BOB, B256::ZERO)?;
    let pending_before = open_enforced.pending()?.len();
    let balance_before = open_enforced.balance_of(ALICE)?;
    assert_revert(
        open_enforced.request(1, GATEWAY, B256::ZERO),
        ZonePortalError::invalid_callback_target(),
    );
    assert_revert(
        open_enforced.request_with_gas(1, BOB, B256::ZERO, 1),
        ZonePortalError::invalid_callback_target(),
    );
    assert_eq!(open_enforced.pending()?.len(), pending_before);
    assert_eq!(open_enforced.balance_of(ALICE)?, balance_before);
    open_enforced.request_with_gas(1, GATEWAY, B256::ZERO, 1)?;

    // Closed access, enforced gateway: plain and callback paths enforce their distinct roles.
    let mut closed_enforced = Harness::new()?;
    closed_enforced.set_modes(true, true);
    closed_enforced.set_role(BOB, Role::Account);
    closed_enforced.set_role(GATEWAY, Role::CallbackGateway);
    closed_enforced.request(1, BOB, B256::ZERO)?;
    closed_enforced.request_with_gas(1, GATEWAY, B256::ZERO, 1)?;
    let pending_before = closed_enforced.pending()?.len();
    let balance_before = closed_enforced.balance_of(ALICE)?;
    assert_revert(
        closed_enforced.request(1, FEE_PAYER, B256::ZERO),
        ZonePortalError::account_not_allowed(FEE_PAYER),
    );
    assert_revert(
        closed_enforced.request_with_gas(1, BOB, B256::ZERO, 1),
        ZonePortalError::invalid_callback_target(),
    );
    assert_eq!(closed_enforced.pending()?.len(), pending_before);
    assert_eq!(closed_enforced.balance_of(ALICE)?, balance_before);
    Ok(())
}

#[test]
fn enqueue_bounce_back_is_inbox_only() -> eyre::Result<()> {
    let mut harness = Harness::new()?;
    let call = ZoneOutboxAbi::enqueueDepositBounceBackCall {
        token: harness.token,
        amount: 100,
        tempoRefundRecipient: BOB,
    }
    .abi_encode();

    assert_revert(
        harness.call(ALICE, &call),
        ZoneOutboxError::only_zone_inbox(),
    );
    harness.call(ZONE_INBOX_ADDRESS, call)?;
    let pending = harness.pending()?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].sender, Address::ZERO);
    assert_eq!(pending[0].fallbackNonce, 0);
    assert_eq!(harness.last_fallback_nonce()?, 0);

    harness.request(1, BOB, B256::ZERO)?;
    assert_eq!(harness.pending()?[1].fallbackNonce, 1);
    assert_eq!(harness.last_fallback_nonce()?, 1);
    Ok(())
}

#[test]
fn finalize_empty_queue_returns_zero() -> eyre::Result<()> {
    let mut harness = Harness::new()?;
    let output = harness.finalize(0)?;
    assert_eq!(
        ZoneOutboxAbi::finalizeWithdrawalBatchCall::abi_decode_returns(&output.bytes)?,
        B256::ZERO
    );
    Ok(())
}

#[test]
fn finalize_withdrawals_match_queue_hash_and_have_unique_sender_tags() -> eyre::Result<()> {
    let mut harness = Harness::new()?;
    harness.request(100, ALICE, B256::repeat_byte(1))?;
    harness.request(200, BOB, B256::repeat_byte(2))?;
    let pending = harness.pending()?;
    let expected: Vec<Withdrawal> = pending
        .iter()
        .map(|pending| Withdrawal {
            token: pending.token,
            senderTag: Withdrawal::sender_tag(
                pending.sender,
                pending.txHash,
                pending.fallbackNonce,
            ),
            to: pending.to,
            amount: pending.amount,
            memo: pending.memo,
            gasLimit: pending.gasLimit,
            fallbackNonce: pending.fallbackNonce,
            callbackData: pending.callbackData.clone(),
            encryptedSender: Bytes::new(),
        })
        .collect();

    let output = harness.finalize(2)?;
    assert_eq!(
        ZoneOutboxAbi::finalizeWithdrawalBatchCall::abi_decode_returns(&output.bytes)?,
        Withdrawal::queue_hash(&expected)
    );
    assert_ne!(expected[0].senderTag, expected[1].senderTag);
    assert!(harness.pending()?.is_empty());
    Ok(())
}

#[test]
fn finalize_rejects_wrong_count_and_non_system_caller() -> eyre::Result<()> {
    let mut harness = Harness::new()?;
    harness.request(100, ALICE, B256::ZERO)?;
    assert_revert(
        harness.finalize(0),
        ZoneOutboxError::invalid_withdrawal_count(U256::ZERO, U256::ONE),
    );

    let result = harness.call(
        SEQUENCER,
        ZoneOutboxAbi::finalizeWithdrawalBatchCall {
            count: U256::ONE,
            blockNumber: 0,
            encryptedSenders: vec![Bytes::new()],
        }
        .abi_encode(),
    );
    assert_revert(result, ZoneOutboxError::only_sequencer());
    Ok(())
}

#[test]
fn fee_rate_and_gas_limit_validation_match_reference() -> eyre::Result<()> {
    let mut harness = Harness::new()?;
    harness.set_gas_rate(3)?;

    let output = harness.call(
        ALICE,
        ZoneOutboxAbi::calculateWithdrawalFeeCall { gasLimit: 7 }.abi_encode(),
    )?;
    assert_eq!(
        ZoneOutboxAbi::calculateWithdrawalFeeCall::abi_decode_returns(&output.bytes)?,
        u128::from(WITHDRAWAL_BASE_GAS + 7) * 3
    );

    assert_revert(
        harness.call(
            ALICE,
            ZoneOutboxAbi::calculateWithdrawalFeeCall {
                gasLimit: MAX_WITHDRAWAL_GAS_LIMIT + 1,
            }
            .abi_encode(),
        ),
        ZoneOutboxError::gas_limit_too_high(),
    );
    assert_revert(
        harness.set_gas_rate(TEST_MAX_TEMPO_GAS_RATE + 1),
        ZoneOutboxError::gas_fee_rate_too_high(),
    );
    harness.set_max_tempo_gas_rate(5);
    assert_revert(
        harness.set_gas_rate(6),
        ZoneOutboxError::gas_fee_rate_too_high(),
    );
    harness.set_gas_rate(5)?;
    harness.set_max_tempo_gas_rate(0);
    assert_revert(
        harness.set_gas_rate(1),
        ZoneOutboxError::gas_fee_rate_too_high(),
    );
    harness.set_gas_rate(0)?;
    Ok(())
}

#[test]
fn setting_tempo_gas_rate_requires_a_sequencer() -> eyre::Result<()> {
    let mut harness = Harness::new()?;
    let result = harness.call(
        ALICE,
        ZoneOutboxAbi::setTempoGasRateCall { _tempoGasRate: 1 }.abi_encode(),
    );
    assert_revert(result, ZoneOutboxError::only_sequencer());
    Ok(())
}

#[test]
fn callback_and_reveal_boundaries_are_enforced() -> eyre::Result<()> {
    let mut harness = Harness::new()?;
    let token = harness.token;
    let base = |data: Bytes, reveal_to: Bytes| ZoneOutboxAbi::requestWithdrawalCall {
        token,
        to: BOB,
        amount: 1,
        memo: B256::ZERO,
        gasLimit: 0,
        zoneFallbackRecipient: ALICE,
        data,
        revealTo: reveal_to,
    };

    harness.request_custom(base(
        Bytes::from(vec![0; MAX_CALLBACK_DATA_SIZE]),
        Bytes::new(),
    ))?;
    assert_revert(
        harness.request_custom(base(
            Bytes::from(vec![0; MAX_CALLBACK_DATA_SIZE + 1]),
            Bytes::new(),
        )),
        ZoneOutboxError::callback_data_too_large(),
    );
    assert_revert(
        harness.request_custom(base(Bytes::new(), Bytes::from(vec![2; 32]))),
        ZoneOutboxError::invalid_reveal_to(),
    );
    assert_revert(
        harness.request_custom(base(Bytes::new(), Bytes::from(vec![4; 33]))),
        ZoneOutboxError::invalid_reveal_to(),
    );

    let valid = alloy_primitives::bytes!(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    );
    harness.request_custom(base(Bytes::new(), valid))?;
    Ok(())
}

#[test]
fn request_rejects_zero_fallback_recipient() -> eyre::Result<()> {
    let mut harness = Harness::new()?;
    let token = harness.token;
    assert_revert(
        harness.request_custom(ZoneOutboxAbi::requestWithdrawalCall {
            token,
            to: BOB,
            amount: 1,
            memo: B256::ZERO,
            gasLimit: 0,
            zoneFallbackRecipient: Address::ZERO,
            data: Bytes::new(),
            revealTo: Bytes::new(),
        }),
        ZoneOutboxError::invalid_fallback_recipient(),
    );
    Ok(())
}

#[test]
fn request_rejects_zero_amount_without_mutating_state() -> eyre::Result<()> {
    let mut harness = Harness::new()?;
    assert_revert(
        harness.request(0, BOB, B256::ZERO),
        ZoneOutboxError::zero_amount_withdrawal(),
    );
    assert!(harness.pending()?.is_empty());
    assert_eq!(harness.last_fallback_nonce()?, 0);
    Ok(())
}

#[test]
fn request_burns_amount_plus_fee_and_rejects_insufficient_funds() -> eyre::Result<()> {
    let mut harness = Harness::new()?;
    harness.set_gas_rate(2)?;
    let before = harness.balance_of(ALICE)?;
    let fee = u128::from(WITHDRAWAL_BASE_GAS) * 2;
    harness.request(100, BOB, B256::ZERO)?;
    assert_eq!(harness.balance_of(ALICE)?, before - U256::from(100 + fee));

    let result = harness.request(u128::MAX, BOB, B256::ZERO);
    assert!(result.expect("precompile result").is_revert());
    Ok(())
}

#[test]
fn request_charges_withdrawal_fee_to_effective_fee_payer() -> eyre::Result<()> {
    let mut harness = Harness::new()?;
    harness.set_gas_rate(2)?;
    let sender_before = harness.balance_of(ALICE)?;
    let fee_payer_before = harness.balance_of(FEE_PAYER)?;
    let fee = u128::from(WITHDRAWAL_BASE_GAS) * 2;
    let token = harness.token;

    harness.call_with_fee_payer(
        ALICE,
        FEE_PAYER,
        ZoneOutboxAbi::requestWithdrawalCall {
            token,
            to: BOB,
            amount: 100,
            memo: B256::ZERO,
            gasLimit: 0,
            zoneFallbackRecipient: ALICE,
            data: Bytes::new(),
            revealTo: Bytes::new(),
        }
        .abi_encode(),
    )?;

    assert_eq!(harness.balance_of(ALICE)?, sender_before - U256::from(100));
    assert_eq!(
        harness.balance_of(FEE_PAYER)?,
        fee_payer_before - U256::from(fee)
    );
    Ok(())
}

#[test]
fn encrypted_sender_count_and_length_are_validated() -> eyre::Result<()> {
    let mut harness = Harness::new()?;
    harness.request(1, BOB, B256::ZERO)?;
    assert_revert(
        harness.call(
            Address::ZERO,
            ZoneOutboxAbi::finalizeWithdrawalBatchCall {
                count: U256::ONE,
                blockNumber: 0,
                encryptedSenders: Vec::new(),
            }
            .abi_encode(),
        ),
        ZoneOutboxError::invalid_encrypted_sender_count(U256::ZERO, U256::ONE),
    );
    assert_revert(
        harness.call(
            Address::ZERO,
            ZoneOutboxAbi::finalizeWithdrawalBatchCall {
                count: U256::ONE,
                blockNumber: 0,
                encryptedSenders: vec![Bytes::from(vec![1])],
            }
            .abi_encode(),
        ),
        ZoneOutboxError::invalid_encrypted_sender_length(U256::ONE, U256::ZERO),
    );
    Ok(())
}

#[test]
fn indices_last_batch_and_timestamp_advance_across_batches() -> eyre::Result<()> {
    let mut harness = Harness::new()?;
    harness.ctx.block.timestamp = U256::from(123);
    harness.request(1, BOB, B256::ZERO)?;
    harness.finalize(1)?;
    harness.request(2, BOB, B256::ZERO)?;
    let second_hash = ZoneOutboxAbi::finalizeWithdrawalBatchCall::abi_decode_returns(
        &harness.finalize(1)?.bytes,
    )?;

    let next = harness.call(
        Address::ZERO,
        ZoneOutboxAbi::nextWithdrawalIndexCall {}.abi_encode(),
    )?;
    assert_eq!(
        ZoneOutboxAbi::nextWithdrawalIndexCall::abi_decode_returns(&next.bytes)?,
        2
    );
    let batch = harness.call(Address::ZERO, ZoneOutboxAbi::lastBatchCall {}.abi_encode())?;
    let batch = ZoneOutboxAbi::lastBatchCall::abi_decode_returns(&batch.bytes)?;
    assert_eq!(batch.withdrawalBatchIndex, 2);
    assert_eq!(batch.withdrawalQueueHash, second_hash);
    let timestamp = harness.call(
        Address::ZERO,
        ZoneOutboxAbi::lastFinalizedTimestampCall {}.abi_encode(),
    )?;
    assert_eq!(
        ZoneOutboxAbi::lastFinalizedTimestampCall::abi_decode_returns(&timestamp.bytes)?,
        123
    );
    Ok(())
}

#[test]
fn per_block_cap_is_unlimited_resettable_and_updateable() -> eyre::Result<()> {
    let mut harness = Harness::new()?;
    harness.set_max_withdrawals(0)?;
    for _ in 0..3 {
        harness.request(1, BOB, B256::ZERO)?;
    }

    harness.set_max_withdrawals(1)?;
    harness.request(1, BOB, B256::ZERO)?;
    assert_revert(
        harness.request(1, BOB, B256::ZERO),
        ZoneOutboxError::too_many_withdrawals_this_block(),
    );
    harness.ctx.block.number = U256::ONE;
    harness.request(1, BOB, B256::ZERO)?;
    assert_revert(
        harness.request(1, BOB, B256::ZERO),
        ZoneOutboxError::too_many_withdrawals_this_block(),
    );
    harness.set_max_withdrawals(2)?;
    harness.request(1, BOB, B256::ZERO)?;
    Ok(())
}

#[test]
fn many_withdrawals_finalize_and_clear_pending_state() -> eyre::Result<()> {
    let mut harness = Harness::new()?;
    for i in 0..20u64 {
        harness.request(1, BOB, B256::from(U256::from(i)))?;
    }
    harness.finalize(20)?;
    assert!(harness.pending()?.is_empty());
    Ok(())
}

#[test]
fn static_mutation_halts_without_changing_state() -> eyre::Result<()> {
    let mut harness = Harness::new()?;
    let token = harness.token;
    let output = harness.call_static(
        ALICE,
        ZoneOutboxAbi::requestWithdrawalCall {
            token,
            to: BOB,
            amount: 1,
            memo: B256::ZERO,
            gasLimit: 0,
            zoneFallbackRecipient: ALICE,
            data: Bytes::new(),
            revealTo: Bytes::new(),
        }
        .abi_encode(),
    )?;
    assert_eq!(
        output.status,
        PrecompileStatus::Halt(PrecompileHalt::other_static(
            "state change during static call"
        ))
    );
    assert!(output.bytes.is_empty());
    assert!(
        harness.l1.storage_requests().is_empty(),
        "static mutation must reach dispatch without portal reads"
    );
    assert!(harness.pending()?.is_empty());
    Ok(())
}

#[test]
fn fallback_recipient_nonce_is_private_and_consumed_once_by_inbox() -> eyre::Result<()> {
    let mut harness = Harness::new()?;
    harness.request(1, BOB, B256::ZERO)?;
    let nonce = harness.pending()?[0].fallbackNonce;
    assert_eq!(nonce, 1);

    let calldata = ZoneOutboxAbi::consumeFallbackRecipientCall {
        fallbackNonce: nonce,
    }
    .abi_encode();
    assert_revert(
        harness.call(ALICE, &calldata),
        ZoneOutboxError::only_zone_inbox(),
    );
    assert_revert(
        harness.call(
            ZONE_INBOX_ADDRESS,
            ZoneOutboxAbi::consumeFallbackRecipientCall {
                fallbackNonce: nonce + 1,
            }
            .abi_encode(),
        ),
        ZoneOutboxError::invalid_fallback_recipient(),
    );
    let output = harness.call_static(ZONE_INBOX_ADDRESS, &calldata)?;
    assert_eq!(
        output.status,
        PrecompileStatus::Halt(PrecompileHalt::other_static(
            "state change during static call"
        ))
    );
    assert!(output.bytes.is_empty());

    // The failed static call must not consume the mapping entry.
    let output = harness.call(ZONE_INBOX_ADDRESS, &calldata)?;
    assert_eq!(
        ZoneOutboxAbi::consumeFallbackRecipientCall::abi_decode_returns(&output.bytes)?,
        ALICE
    );
    assert_revert(
        harness.call(ZONE_INBOX_ADDRESS, calldata),
        ZoneOutboxError::invalid_fallback_recipient(),
    );
    Ok(())
}
