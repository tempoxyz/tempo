use super::*;

use alloy_primitives::{Bytes, address};
use alloy_sol_types::{SolCall, SolInterface};
use evm2::precompiles::PrecompileHalt;
use tempo_contracts::zones::IZoneOutbox as ZoneOutboxAbi;
use tempo_precompiles::{
    PATH_USD_ADDRESS,
    test_util::TIP20Setup,
    zone_factory::portal::{self, ZonePortalStorage},
};
use test_case::test_case;

use crate::{
    test_utils::{PrecompileResult, PrecompileStatus, WITHDRAWAL_TX_HASH, ZoneEnv, ZoneSpec},
    tx_context,
};

const ANCHOR: u64 = 42;
const TEST_MAX_TEMPO_GAS_RATE: u128 = 1_000_000_000_000_000_000;
const PORTAL: Address = Address::repeat_byte(0x77);
const ALICE: Address = Address::with_last_byte(0xa1);
const BOB: Address = Address::with_last_byte(0xb2);
const SEQUENCER: Address = Address::with_last_byte(0xc3);
const FEE_PAYER: Address = Address::with_last_byte(0xd4);
const GATEWAY: Address = Address::with_last_byte(0xe5);

fn spec() -> ZoneSpec {
    ZoneSpec {
        portal: PORTAL,
        sequencer: SEQUENCER,
        tempo_block: ANCHOR,
        max_tempo_gas_rate: TEST_MAX_TEMPO_GAS_RATE,
        tokens: vec![
            TIP20Setup::path_usd(ALICE)
                .with_issuer(ALICE)
                .with_issuer(ZONE_OUTBOX_ADDRESS)
                .with_mint(ALICE, U256::from(1_000_000u64))
                .with_mint(FEE_PAYER, U256::from(1_000_000u64))
                .with_approval(ALICE, ZONE_OUTBOX_ADDRESS, U256::MAX)
                .with_approval(FEE_PAYER, ZONE_OUTBOX_ADDRESS, U256::MAX),
        ],
        ..Default::default()
    }
}

/// A pathUSD withdrawal with a zero memo and ALICE as the zone fallback recipient.
fn withdrawal(amount: u128, to: Address, gas_limit: u64) -> ZoneOutboxAbi::requestWithdrawalCall {
    ZoneOutboxAbi::requestWithdrawalCall {
        token: PATH_USD_ADDRESS,
        to,
        amount,
        memo: B256::ZERO,
        gasLimit: gas_limit,
        zoneFallbackRecipient: ALICE,
        data: Bytes::new(),
        revealTo: Bytes::new(),
    }
}

fn last_fallback_nonce(env: &mut ZoneEnv) -> eyre::Result<u64> {
    let output = env.call(
        Address::ZERO,
        ZONE_OUTBOX_ADDRESS,
        ZoneOutboxAbi::lastFallbackNonceCall {}.abi_encode(),
    )?;
    Ok(ZoneOutboxAbi::lastFallbackNonceCall::abi_decode_returns(
        &output.bytes,
    )?)
}

fn set_gas_rate(env: &mut ZoneEnv, rate: u128) -> PrecompileResult {
    env.call(
        SEQUENCER,
        ZONE_OUTBOX_ADDRESS,
        ZoneOutboxAbi::setTempoGasRateCall {
            _tempoGasRate: rate,
        }
        .abi_encode(),
    )
}

fn set_max_withdrawals(env: &mut ZoneEnv, max: u32) -> PrecompileResult {
    env.call(
        SEQUENCER,
        ZONE_OUTBOX_ADDRESS,
        ZoneOutboxAbi::setMaxWithdrawalsPerBlockCall {
            _maxWithdrawalsPerBlock: max,
        }
        .abi_encode(),
    )
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
            u8::from(Role::PauseGuardian),
        ],
        [0, 1, 2, 3, 4]
    );
}

#[test_case(ZoneOutboxAbi::pendingWithdrawalsCountCall {}.abi_encode())]
#[test_case(ZoneOutboxAbi::getPendingWithdrawalsCall {}.abi_encode())]
fn pending_withdrawal_getters_require_sequencer_or_system(calldata: Vec<u8>) -> eyre::Result<()> {
    let mut env = spec().apply()?;
    assert_revert(
        env.call(ALICE, ZONE_OUTBOX_ADDRESS, &calldata),
        ZoneOutboxError::only_sequencer(),
    );

    assert!(
        env.call(SEQUENCER, ZONE_OUTBOX_ADDRESS, &calldata)?
            .is_success()
    );
    assert!(
        env.call(Address::ZERO, ZONE_OUTBOX_ADDRESS, calldata)?
            .is_success()
    );

    Ok(())
}

#[test]
fn outbox_reads_injected_l1_state_at_tempo_checkpoint() -> eyre::Result<()> {
    let mut env = spec().apply()?;
    set_gas_rate(&mut env, 1)?;
    env.request_withdrawal(ALICE, withdrawal(1, BOB, 0))?;

    let portal = ZonePortalStorage::new(PORTAL);
    assert_eq!(env.l1.storage_requests().len(), 6);
    assert!(env.l1.storage_requests().contains(&(
        PORTAL,
        portal::slots::PAUSE_EXPIRY.into(),
        ANCHOR
    )));
    assert_eq!(env.l1.request_count(ANCHOR, &portal.role[SEQUENCER]), 1);
    assert_eq!(env.l1.request_count(ANCHOR, &portal.max_tempo_gas_rate), 1);
    assert_eq!(
        env.l1
            .request_count(ANCHOR, &portal.token_configs[PATH_USD_ADDRESS].enabled),
        1
    );
    assert_eq!(env.l1.request_count(ANCHOR, &portal.is_access_enforced), 2);
    Ok(())
}

#[test]
fn request_withdrawal_rejects_missing_transaction_hash() -> eyre::Result<()> {
    let mut env = spec().apply()?;
    let result = env.call(
        ALICE,
        ZONE_OUTBOX_ADDRESS,
        withdrawal(1, BOB, 0).abi_encode(),
    );
    assert_revert(result, ZoneOutboxError::invalid_current_tx_hash());
    assert!(
        env.l1.storage_requests().is_empty(),
        "missing transaction context must be rejected before portal reads"
    );
    Ok(())
}

#[test]
fn request_withdrawal_rejects_unknown_token_before_portal_read() -> eyre::Result<()> {
    let mut env = spec().apply()?;
    let result = env.request_withdrawal(
        ALICE,
        ZoneOutboxAbi::requestWithdrawalCall {
            token: address!("0x20c000000000000000000000000000000000ffff"),
            ..withdrawal(1, BOB, 0)
        },
    );
    assert_revert(result, TIP20Error::uninitialized());
    assert!(
        env.l1.storage_requests().is_empty(),
        "unknown tokens must be rejected before portal reads"
    );
    Ok(())
}

#[test_case(false, ZonePortalError::token_not_enabled())]
#[test_case(true, ZonePortalError::portal_is_paused())]
fn request_withdrawal_rejects_disabled_token_and_active_pause_before_state_mutation(
    paused: bool,
    error: ZonePortalError,
) -> eyre::Result<()> {
    let mut env = spec().apply()?;
    env.ctx.block.timestamp = U256::from(100);
    env.write_portal(ANCHOR, |portal| {
        if paused {
            portal.pause_expiry.write(200)
        } else {
            portal.token_configs[PATH_USD_ADDRESS].enabled.write(false)
        }
    });
    let balance_before = env.balance(PATH_USD_ADDRESS, ALICE);

    assert_revert(env.request_withdrawal(ALICE, withdrawal(1, BOB, 0)), error);
    assert_eq!(env.balance(PATH_USD_ADDRESS, ALICE), balance_before);
    assert!(env.pending_withdrawals().is_empty());
    assert_eq!(last_fallback_nonce(&mut env)?, 0);
    Ok(())
}

#[test]
fn request_withdrawal_enforces_all_access_and_gateway_mode_combinations() -> eyre::Result<()> {
    let set_role = |env: &ZoneEnv, account: Address, role: Role| {
        env.write_portal(ANCHOR, |portal| portal.role[account].write(u8::from(role)));
    };

    // Open access, open gateway: plain and callback withdrawals accept arbitrary recipients.
    let mut open_open = spec().apply()?;
    open_open.request_withdrawal(ALICE, withdrawal(1, BOB, 0))?;
    open_open.request_withdrawal(ALICE, withdrawal(1, GATEWAY, 1))?;

    // Closed access, open gateway: plain recipients need the Account role, while callback
    // recipients remain unrestricted.
    let mut closed_open = ZoneSpec {
        access_enforced: true,
        ..spec()
    }
    .apply()?;
    let balance_before = closed_open.balance(PATH_USD_ADDRESS, ALICE);
    assert_revert(
        closed_open.request_withdrawal(ALICE, withdrawal(1, BOB, 0)),
        ZonePortalError::account_not_allowed(BOB),
    );
    assert_eq!(closed_open.balance(PATH_USD_ADDRESS, ALICE), balance_before);
    assert!(closed_open.pending_withdrawals().is_empty());
    set_role(&closed_open, BOB, Role::Account);
    closed_open.request_withdrawal(ALICE, withdrawal(1, BOB, 0))?;
    closed_open.request_withdrawal(ALICE, withdrawal(1, FEE_PAYER, 1))?;

    // Open access, enforced gateway: arbitrary plain recipients remain valid, but registered
    // gateways require callback gas and callback targets must have the CallbackGateway role.
    let mut open_enforced = ZoneSpec {
        gateway_enforced: true,
        ..spec()
    }
    .apply()?;
    set_role(&open_enforced, GATEWAY, Role::CallbackGateway);
    open_enforced.request_withdrawal(ALICE, withdrawal(1, BOB, 0))?;
    let pending_before = open_enforced.pending_withdrawals().len();
    let balance_before = open_enforced.balance(PATH_USD_ADDRESS, ALICE);
    assert_revert(
        open_enforced.request_withdrawal(ALICE, withdrawal(1, GATEWAY, 0)),
        ZonePortalError::invalid_callback_target(),
    );
    assert_revert(
        open_enforced.request_withdrawal(ALICE, withdrawal(1, BOB, 1)),
        ZonePortalError::invalid_callback_target(),
    );
    assert_eq!(open_enforced.pending_withdrawals().len(), pending_before);
    assert_eq!(
        open_enforced.balance(PATH_USD_ADDRESS, ALICE),
        balance_before
    );
    open_enforced.request_withdrawal(ALICE, withdrawal(1, GATEWAY, 1))?;

    // Closed access, enforced gateway: plain and callback paths enforce their distinct roles.
    let mut closed_enforced = ZoneSpec {
        access_enforced: true,
        gateway_enforced: true,
        ..spec()
    }
    .apply()?;
    set_role(&closed_enforced, BOB, Role::Account);
    set_role(&closed_enforced, GATEWAY, Role::CallbackGateway);
    closed_enforced.request_withdrawal(ALICE, withdrawal(1, BOB, 0))?;
    closed_enforced.request_withdrawal(ALICE, withdrawal(1, GATEWAY, 1))?;
    let pending_before = closed_enforced.pending_withdrawals().len();
    let balance_before = closed_enforced.balance(PATH_USD_ADDRESS, ALICE);
    assert_revert(
        closed_enforced.request_withdrawal(ALICE, withdrawal(1, FEE_PAYER, 0)),
        ZonePortalError::account_not_allowed(FEE_PAYER),
    );
    assert_revert(
        closed_enforced.request_withdrawal(ALICE, withdrawal(1, BOB, 1)),
        ZonePortalError::invalid_callback_target(),
    );
    assert_eq!(closed_enforced.pending_withdrawals().len(), pending_before);
    assert_eq!(
        closed_enforced.balance(PATH_USD_ADDRESS, ALICE),
        balance_before
    );
    Ok(())
}

#[test]
fn enqueue_bounce_back_is_inbox_only() -> eyre::Result<()> {
    let mut env = spec().apply()?;
    let call = ZoneOutboxAbi::enqueueDepositBounceBackCall {
        token: PATH_USD_ADDRESS,
        amount: 100,
        tempoRefundRecipient: BOB,
    }
    .abi_encode();

    assert_revert(
        env.call(ALICE, ZONE_OUTBOX_ADDRESS, &call),
        ZoneOutboxError::only_zone_inbox(),
    );
    env.call(ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS, call)?;
    let pending = env.pending_withdrawals();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].sender, Address::ZERO);
    assert_eq!(pending[0].fallbackNonce, 0);
    assert_eq!(last_fallback_nonce(&mut env)?, 0);

    env.request_withdrawal(ALICE, withdrawal(1, BOB, 0))?;
    assert_eq!(env.pending_withdrawals()[1].fallbackNonce, 1);
    assert_eq!(last_fallback_nonce(&mut env)?, 1);
    Ok(())
}

#[test]
fn withdrawals_queue_in_fifo_order_and_finalize_to_their_queue_hash() -> eyre::Result<()> {
    let mut env = spec().apply()?;
    for (memo, amount, to) in [(1, 500, ALICE), (2, 300, BOB)] {
        env.request_withdrawal(
            ALICE,
            ZoneOutboxAbi::requestWithdrawalCall {
                memo: B256::repeat_byte(memo),
                ..withdrawal(amount, to, 0)
            },
        )?;
    }

    let pending = env.pending_withdrawals();
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[0].sender, ALICE);
    assert_eq!(pending[0].txHash, WITHDRAWAL_TX_HASH);
    assert_eq!(pending[0].to, ALICE);
    assert_eq!(pending[0].amount, 500);
    assert_eq!(pending[1].to, BOB);
    assert_eq!(pending[1].amount, 300);

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
    let output = env.finalize_batch(2)?;
    assert_eq!(
        ZoneOutboxAbi::finalizeWithdrawalBatchCall::abi_decode_returns(&output.bytes)?,
        Withdrawal::queue_hash(&expected)
    );
    assert_ne!(expected[0].senderTag, expected[1].senderTag);
    assert!(env.pending_withdrawals().is_empty());
    Ok(())
}

#[test]
fn finalize_validates_count_caller_and_encrypted_senders() -> eyre::Result<()> {
    let mut env = spec().apply()?;
    let output = env.finalize_batch(0)?;
    assert_eq!(
        ZoneOutboxAbi::finalizeWithdrawalBatchCall::abi_decode_returns(&output.bytes)?,
        B256::ZERO
    );

    env.request_withdrawal(ALICE, withdrawal(100, ALICE, 0))?;
    assert_revert(
        env.finalize_batch(0),
        ZoneOutboxError::invalid_withdrawal_count(U256::ZERO, U256::ONE),
    );
    let finalize = |encrypted_senders| {
        ZoneOutboxAbi::finalizeWithdrawalBatchCall {
            count: U256::ONE,
            blockNumber: 0,
            encryptedSenders: encrypted_senders,
        }
        .abi_encode()
    };
    assert_revert(
        env.call(SEQUENCER, ZONE_OUTBOX_ADDRESS, finalize(vec![Bytes::new()])),
        ZoneOutboxError::only_sequencer(),
    );
    assert_revert(
        env.call(Address::ZERO, ZONE_OUTBOX_ADDRESS, finalize(Vec::new())),
        ZoneOutboxError::invalid_encrypted_sender_count(U256::ZERO, U256::ONE),
    );
    assert_revert(
        env.call(
            Address::ZERO,
            ZONE_OUTBOX_ADDRESS,
            finalize(vec![Bytes::from(vec![1])]),
        ),
        ZoneOutboxError::invalid_encrypted_sender_length(U256::ONE, U256::ZERO),
    );
    Ok(())
}

#[test]
fn fee_rate_and_gas_limit_validation_match_reference() -> eyre::Result<()> {
    let mut env = spec().apply()?;
    assert_revert(
        env.call(
            ALICE,
            ZONE_OUTBOX_ADDRESS,
            ZoneOutboxAbi::setTempoGasRateCall { _tempoGasRate: 1 }.abi_encode(),
        ),
        ZoneOutboxError::only_sequencer(),
    );
    set_gas_rate(&mut env, 3)?;

    let output = env.call(
        ALICE,
        ZONE_OUTBOX_ADDRESS,
        ZoneOutboxAbi::calculateWithdrawalFeeCall { gasLimit: 7 }.abi_encode(),
    )?;
    assert_eq!(
        ZoneOutboxAbi::calculateWithdrawalFeeCall::abi_decode_returns(&output.bytes)?,
        u128::from(WITHDRAWAL_BASE_GAS + 7) * 3
    );

    assert_revert(
        env.call(
            ALICE,
            ZONE_OUTBOX_ADDRESS,
            ZoneOutboxAbi::calculateWithdrawalFeeCall {
                gasLimit: MAX_WITHDRAWAL_GAS_LIMIT + 1,
            }
            .abi_encode(),
        ),
        ZoneOutboxError::gas_limit_too_high(),
    );
    assert_revert(
        set_gas_rate(&mut env, TEST_MAX_TEMPO_GAS_RATE + 1),
        ZoneOutboxError::gas_fee_rate_too_high(),
    );
    env.write_portal(ANCHOR, |portal| portal.max_tempo_gas_rate.write(5));
    assert_revert(
        set_gas_rate(&mut env, 6),
        ZoneOutboxError::gas_fee_rate_too_high(),
    );
    set_gas_rate(&mut env, 5)?;
    env.write_portal(ANCHOR, |portal| portal.max_tempo_gas_rate.write(0));
    assert_revert(
        set_gas_rate(&mut env, 1),
        ZoneOutboxError::gas_fee_rate_too_high(),
    );
    set_gas_rate(&mut env, 0)?;
    Ok(())
}

#[test]
fn request_rejects_invalid_parameters_without_mutating_state() -> eyre::Result<()> {
    let mut env = spec().apply()?;
    let base = |data: Bytes, reveal_to: Bytes| ZoneOutboxAbi::requestWithdrawalCall {
        data,
        revealTo: reveal_to,
        ..withdrawal(1, BOB, 0)
    };

    for (call, error) in [
        (
            withdrawal(0, BOB, 0),
            ZoneOutboxError::zero_amount_withdrawal(),
        ),
        (
            ZoneOutboxAbi::requestWithdrawalCall {
                zoneFallbackRecipient: Address::ZERO,
                ..withdrawal(1, BOB, 0)
            },
            ZoneOutboxError::invalid_fallback_recipient(),
        ),
        (
            base(vec![0; MAX_CALLBACK_DATA_SIZE + 1].into(), Bytes::new()),
            ZoneOutboxError::callback_data_too_large(),
        ),
        (
            base(Bytes::new(), vec![2; 32].into()),
            ZoneOutboxError::invalid_reveal_to(),
        ),
        (
            base(Bytes::new(), vec![4; 33].into()),
            ZoneOutboxError::invalid_reveal_to(),
        ),
    ] {
        assert_revert(env.request_withdrawal(ALICE, call), error);
    }
    assert!(env.pending_withdrawals().is_empty());
    assert_eq!(last_fallback_nonce(&mut env)?, 0);

    env.request_withdrawal(
        ALICE,
        base(vec![0; MAX_CALLBACK_DATA_SIZE].into(), Bytes::new()),
    )?;
    env.request_withdrawal(
        ALICE,
        base(
            Bytes::new(),
            alloy_primitives::bytes!(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            ),
        ),
    )?;
    Ok(())
}

#[test]
fn request_charges_fee_to_effective_fee_payer_and_rejects_insufficient_funds() -> eyre::Result<()> {
    let mut env = spec().apply()?;
    set_gas_rate(&mut env, 2)?;
    let sender_before = env.balance(PATH_USD_ADDRESS, ALICE);
    let fee_payer_before = env.balance(PATH_USD_ADDRESS, FEE_PAYER);
    let fee = u128::from(WITHDRAWAL_BASE_GAS) * 2;

    env.request_withdrawal(ALICE, withdrawal(100, BOB, 0))?;
    assert_eq!(
        env.balance(PATH_USD_ADDRESS, ALICE),
        sender_before - U256::from(100 + fee)
    );

    {
        let _tx = tx_context::set_current_transaction(WITHDRAWAL_TX_HASH, FEE_PAYER);
        env.call(
            ALICE,
            ZONE_OUTBOX_ADDRESS,
            withdrawal(100, BOB, 0).abi_encode(),
        )?;
    }
    assert_eq!(
        env.balance(PATH_USD_ADDRESS, ALICE),
        sender_before - U256::from(200 + fee)
    );
    assert_eq!(
        env.balance(PATH_USD_ADDRESS, FEE_PAYER),
        fee_payer_before - U256::from(fee)
    );

    let result = env.request_withdrawal(ALICE, withdrawal(u128::MAX, BOB, 0));
    assert!(result.expect("precompile result").is_revert());
    Ok(())
}

#[test]
fn indices_last_batch_and_timestamp_advance_across_batches() -> eyre::Result<()> {
    let mut env = spec().apply()?;
    env.ctx.block.timestamp = U256::from(123);
    env.request_withdrawal(ALICE, withdrawal(1, BOB, 0))?;
    env.finalize_batch(1)?;
    env.request_withdrawal(ALICE, withdrawal(2, BOB, 0))?;
    let second_hash = ZoneOutboxAbi::finalizeWithdrawalBatchCall::abi_decode_returns(
        &env.finalize_batch(1)?.bytes,
    )?;

    let next = env.call(
        Address::ZERO,
        ZONE_OUTBOX_ADDRESS,
        ZoneOutboxAbi::nextWithdrawalIndexCall {}.abi_encode(),
    )?;
    assert_eq!(
        ZoneOutboxAbi::nextWithdrawalIndexCall::abi_decode_returns(&next.bytes)?,
        2
    );
    let batch = env.call(
        Address::ZERO,
        ZONE_OUTBOX_ADDRESS,
        ZoneOutboxAbi::lastBatchCall {}.abi_encode(),
    )?;
    let batch = ZoneOutboxAbi::lastBatchCall::abi_decode_returns(&batch.bytes)?;
    assert_eq!(batch.withdrawalBatchIndex, 2);
    assert_eq!(batch.withdrawalQueueHash, second_hash);
    let timestamp = env.call(
        Address::ZERO,
        ZONE_OUTBOX_ADDRESS,
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
    let mut env = spec().apply()?;
    set_max_withdrawals(&mut env, 0)?;
    for _ in 0..3 {
        env.request_withdrawal(ALICE, withdrawal(1, BOB, 0))?;
    }

    set_max_withdrawals(&mut env, 1)?;
    env.request_withdrawal(ALICE, withdrawal(1, BOB, 0))?;
    assert_revert(
        env.request_withdrawal(ALICE, withdrawal(1, BOB, 0)),
        ZoneOutboxError::too_many_withdrawals_this_block(),
    );
    env.ctx.block.number = U256::ONE;
    env.request_withdrawal(ALICE, withdrawal(1, BOB, 0))?;
    assert_revert(
        env.request_withdrawal(ALICE, withdrawal(1, BOB, 0)),
        ZoneOutboxError::too_many_withdrawals_this_block(),
    );
    set_max_withdrawals(&mut env, 2)?;
    env.request_withdrawal(ALICE, withdrawal(1, BOB, 0))?;
    Ok(())
}

#[test]
fn static_mutation_halts_without_changing_state() -> eyre::Result<()> {
    let mut env = spec().apply()?;
    let output = env.static_call(
        ALICE,
        ZONE_OUTBOX_ADDRESS,
        withdrawal(1, BOB, 0).abi_encode(),
    )?;
    assert_eq!(
        output.status,
        PrecompileStatus::Halt(PrecompileHalt::Other(
            "state change during static call".into()
        ))
    );
    assert!(output.bytes.is_empty());
    assert!(
        env.l1.storage_requests().is_empty(),
        "static mutation must reach dispatch without portal reads"
    );
    assert!(env.pending_withdrawals().is_empty());
    Ok(())
}

#[test]
fn fallback_recipient_nonce_is_private_and_consumed_once_by_inbox() -> eyre::Result<()> {
    let mut env = spec().apply()?;
    env.request_withdrawal(ALICE, withdrawal(1, BOB, 0))?;
    let nonce = env.pending_withdrawals()[0].fallbackNonce;
    assert_eq!(nonce, 1);

    let calldata = ZoneOutboxAbi::consumeFallbackRecipientCall {
        fallbackNonce: nonce,
    }
    .abi_encode();
    assert_revert(
        env.call(ALICE, ZONE_OUTBOX_ADDRESS, &calldata),
        ZoneOutboxError::only_zone_inbox(),
    );
    assert_revert(
        env.call(
            ZONE_INBOX_ADDRESS,
            ZONE_OUTBOX_ADDRESS,
            ZoneOutboxAbi::consumeFallbackRecipientCall {
                fallbackNonce: nonce + 1,
            }
            .abi_encode(),
        ),
        ZoneOutboxError::invalid_fallback_recipient(),
    );
    let output = env.static_call(ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS, &calldata)?;
    assert_eq!(
        output.status,
        PrecompileStatus::Halt(PrecompileHalt::Other(
            "state change during static call".into()
        ))
    );
    assert!(output.bytes.is_empty());

    // The failed static call must not consume the mapping entry.
    let output = env.call(ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS, &calldata)?;
    assert_eq!(
        ZoneOutboxAbi::consumeFallbackRecipientCall::abi_decode_returns(&output.bytes)?,
        ALICE
    );
    assert_revert(
        env.call(ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS, calldata),
        ZoneOutboxError::invalid_fallback_recipient(),
    );
    Ok(())
}
