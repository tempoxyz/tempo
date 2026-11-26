//! Native version of `SettlementFixture.settle` (`contrib/bench/txgen/zones/PortalFixture.sol`)
//! with its portal calls, deployed with `anchorOffset = 1`.

use super::{
    super::NativeFrame,
    charge, overflow, remaining,
    zone_portal::{Batch, Portal, withdrawal_link},
};
use crate::{
    error::{Result, TempoPrecompileError},
    storage::{StorageCtx, StorageKey},
    zone_factory::portal::ZONE_PORTAL_PROXY_RUNTIME,
};
use alloy::{
    primitives::{Address, B256, Bytes, U256, b256, keccak256},
    sol,
    sol_types::{SolCall, SolValue},
};
use std::sync::LazyLock;
use tempo_contracts::zones::{
    BlockTransition, DepositQueueTransition, TokenEnablementTransition, Withdrawal,
};

/// `settle(address,address,address,bool)`.
pub(super) const SETTLE_SELECTOR: [u8; 4] = settleCall::SELECTOR;

/// Length of the fixture's runtime.
const FIXTURE_RUNTIME_LEN: usize = 3799;
/// keccak256 of the fixture's runtime with `anchorOffset = 1` embedded.
const FIXTURE_RUNTIME_HASH: B256 =
    b256!("0x7f975d7af9dc11f5a20c5af85a8014ff9287c56bb71ab8b81861788f72980343");
/// The fixture's `anchorOffset` immutable.
const ANCHOR_OFFSET: u64 = 1;

/// Opcode gas of a settle frame up to its `processWithdrawals` call, getter and `submitBatch`
/// calls included, without a withdrawal.
const SETTLE_GAS: u64 = 23_946;
/// Extra opcode gas up to and including the `processWithdrawals` call with a withdrawal: the
/// withdrawal root, `submitBatch`'s queue append and the call itself.
const SETTLE_WITHDRAW_GAS: u64 = 4_418;
/// Extra opcode gas of `submitBatch` before the token cursor is initialized.
const CURSOR_UNINITIALIZED_GAS: u64 = 546;
/// Opcode gas of the portal implementation's `processWithdrawals`.
const PROCESS_WITHDRAWALS_GAS: u64 = 9_717;
/// Fixture opcode gas after a successful `processWithdrawals` call, relative to a settle without
/// a withdrawal.
const WITHDRAW_TAIL_GAS: u64 = 95;
/// Fixture opcode gas after a failed T15 `processWithdrawals` call: the pre-T15 fallback call,
/// which the T15 portal rejects, and the revert.
const WITHDRAW_FAILED_TAIL_GAS: u64 = 4_005;
/// The portal proxy's gas before its `DELEGATECALL` of the T15 `processWithdrawals` calldata
/// (17 words): copying it into memory, the warm call and the stack setup.
const PROXY_PRE_GAS: u64 = 226;
/// The portal proxy's gas after a `DELEGATECALL` returning empty data, up to `RETURN`.
const PROXY_RETURN_GAS: u64 = 33;
/// The portal proxy's gas after a `DELEGATECALL` reverting with empty data, up to `REVERT`.
const PROXY_REVERT_GAS: u64 = 32;

/// keccak256 of the portal proxy runtime.
static PROXY_RUNTIME_HASH: LazyLock<B256> = LazyLock::new(|| keccak256(ZONE_PORTAL_PROXY_RUNTIME));

sol! {
    function settle(address portal, address token, address recipient, bool withdraw) external;
}

/// Whether `code` is the settlement fixture's runtime with `anchorOffset = 1`.
pub(super) fn is_fixture(code: &[u8]) -> bool {
    code.len() == FIXTURE_RUNTIME_LEN && keccak256(code) == FIXTURE_RUNTIME_HASH
}

/// `settle(portal, token, recipient, withdraw)` in the fixture at `frame.address`.
pub(super) fn settle(frame: &NativeFrame<'_>) -> Result<Bytes> {
    let call = settleCall::abi_decode_validate(frame.input)
        .map_err(|_| TempoPrecompileError::RawRevert(Bytes::new()))?;
    let fixture = frame.address;
    charge(SETTLE_GAS)?;

    let withdrawal = call.withdraw.then(|| Withdrawal {
        token: call.token,
        senderTag: B256::ZERO,
        to: call.recipient,
        amount: 1,
        memo: B256::ZERO,
        gasLimit: 0,
        fallbackNonce: 1,
        callbackData: Bytes::new(),
        encryptedSender: Bytes::new(),
        senderOrg: 0,
    });
    // The fixture hashes the pre-T15 withdrawal; org 0 hashes the same as the T15 one.
    let withdrawal_queue_hash = withdrawal.as_ref().map_or(B256::ZERO, |withdrawal| {
        withdrawal_link(withdrawal, B256::ZERO)
    });

    // The first getter call touches the proxy, whose DELEGATECALL touches the implementation.
    let proxy_code_hash = StorageCtx.with_account_info(call.portal, |info| Ok(info.code_hash))?;
    if proxy_code_hash != *PROXY_RUNTIME_HASH {
        return Err(TempoPrecompileError::Fatal(
            "native settle supports only portal proxies".into(),
        ));
    }
    let portal = Portal::enter(call.portal)?;

    let height = portal
        .zone_height()?
        .checked_add(U256::ONE)
        .ok_or_else(overflow)?;
    let blocks = BlockTransition {
        prevBlockHash: portal.block_hash()?,
        nextBlockHash: keccak256((portal.address(), height).abi_encode_params()),
    };
    let processed_slot = portal.address().mapping_slot(U256::ZERO);
    let deposits = DepositQueueTransition {
        prevProcessedHash: StorageCtx.sload(fixture, processed_slot)?.into(),
        nextProcessedHash: portal.current_deposit_queue_hash()?,
        prevDepositNumber: portal.last_processed_deposit_number()?,
        nextDepositNumber: portal.deposit_count()?,
    };
    // Solidity's `uint64(...)` of `block.number - anchorOffset` truncates.
    let anchor = StorageCtx
        .block_number()
        .checked_sub(ANCHOR_OFFSET)
        .ok_or_else(overflow)?;
    // TIP-1096 portal: `lastProcessedEnabledTokenCount()` answers, so the fixture takes the
    // submitBatch overload with the token transition.
    let tokens = TokenEnablementTransition {
        prevProcessedTokenCount: portal.last_processed_enabled_token_count()?,
        nextProcessedTokenCount: 1,
    };
    if withdrawal.is_some() {
        charge(SETTLE_WITHDRAW_GAS)?;
    }
    if !portal.token_cursor_initialized()? {
        charge(CURSOR_UNINITIALIZED_GAS)?;
    }
    let next_processed_hash = deposits.nextProcessedHash;
    portal.submit_batch(
        fixture,
        &Batch {
            tempo_block_number: anchor,
            recent_tempo_block_number: 0,
            blocks,
            deposits,
            tokens,
            withdrawal_queue_hash,
            next_zone_height: height,
        },
    )?;
    StorageCtx.sstore(fixture, processed_slot, next_processed_hash.into())?;

    let Some(withdrawal) = withdrawal else {
        return Ok(Bytes::new());
    };
    if !process_withdrawal(&portal, fixture, &withdrawal)? {
        // The pre-T15 fallback call reverts on the T15 portal, and so does settle.
        charge(WITHDRAW_FAILED_TAIL_GAS)?;
        return Err(TempoPrecompileError::RawRevert(Bytes::new()));
    }
    charge(WITHDRAW_TAIL_GAS)?;
    Ok(Bytes::new())
}

/// `try portal.processWithdrawals(...)` with the T15 ABI, made with all the gas left: whether it
/// succeeded.
///
/// The call forwards all but a 64th of the gas left, and the proxy all but a 64th of that to the
/// implementation, which runs out of gas when the bytecode would spend more. Then its state is
/// discarded with the reverting settle frame and it costs all the gas it was given.
fn process_withdrawal(portal: &Portal, fixture: Address, withdrawal: &Withdrawal) -> Result<bool> {
    let forwarded = all_but_one_64th(remaining());
    let implementation_gas = all_but_one_64th(forwarded.saturating_sub(PROXY_PRE_GAS));
    let before = StorageCtx.gas_used();
    let result = charge(PROCESS_WITHDRAWALS_GAS)
        .and_then(|()| portal.process_withdrawal(fixture, withdrawal));
    let spent = StorageCtx.gas_used() - before;
    match result {
        Ok(()) if spent <= implementation_gas => {
            charge(PROXY_PRE_GAS + PROXY_RETURN_GAS)?;
            Ok(true)
        }
        Ok(()) | Err(TempoPrecompileError::OutOfGas) => {
            if spent > implementation_gas {
                StorageCtx.reimburse_gas(spent - implementation_gas)?;
            } else {
                charge(implementation_gas - spent)?;
            }
            charge(PROXY_PRE_GAS + PROXY_REVERT_GAS)?;
            Ok(false)
        }
        Err(error @ (TempoPrecompileError::Fatal(_) | TempoPrecompileError::Database(_))) => {
            Err(error)
        }
        Err(_) => {
            charge(PROXY_PRE_GAS + PROXY_REVERT_GAS)?;
            Ok(false)
        }
    }
}

/// EIP-150: the gas a call forwards out of `gas`.
fn all_but_one_64th(gas: u64) -> u64 {
    gas - gas / 64
}
