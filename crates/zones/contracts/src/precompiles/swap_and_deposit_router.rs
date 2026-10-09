//! `SwapAndDepositRouter` — deployed on Tempo L1.

use crate::DepositPayload;
use alloc::vec::Vec;
use alloy_primitives::{Address, U256};
use alloy_sol_types::SolValue;

crate::sol! {
    #[derive(Debug)]
    contract SwapAndDepositRouter {
        function onWithdrawalReceived(
            uint32 sourceZoneId,
            address sourcePortal,
            bytes32 senderTag,
            address tokenIn,
            uint128 amount,
            bytes calldata data
        ) external returns (bytes4);
    }
}

/// Callback payload for `SwapAndDepositRouter.onWithdrawalReceived`.
///
/// This payload tells the router to optionally swap the withdrawn token on L1
/// and then call `ZonePortal.deposit(...)` with an ECIES-encrypted
/// `(recipient, memo)` payload.
#[derive(Debug, Clone)]
pub struct SwapAndDepositRouterCallback {
    /// Token that should be deposited after the optional L1 swap.
    pub token_out: Address,
    /// Target zone portal that receives the downstream deposit.
    pub target_portal: Address,
    /// Portal encryption key index used to build [`Self::encrypted`].
    pub key_index: U256,
    /// ECIES-encrypted `(recipient, memo)` payload for `deposit`.
    pub encrypted: DepositPayload,
    /// Tempo refund recipient if the downstream deposit later bounces.
    pub tempo_refund_recipient: Address,
    /// Minimum acceptable output from the optional swap.
    ///
    /// Ignored when `tokenIn == token_out` and the router can deposit directly.
    pub min_amount_out: u128,
}

impl SwapAndDepositRouterCallback {
    /// ABI-encode the router callback data expected by the Solidity router.
    pub fn abi_encode(&self) -> Vec<u8> {
        (
            self.token_out,
            self.target_portal,
            self.key_index,
            self.encrypted.clone(),
            self.tempo_refund_recipient,
            self.min_amount_out,
        )
            .abi_encode_params()
    }
}
