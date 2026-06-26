pub use ITIP20ChannelReserve::{
    ITIP20ChannelReserveErrors as TIP20ChannelReserveError,
    ITIP20ChannelReserveEvents as TIP20ChannelReserveEvent,
};
use alloy_primitives::{Address, address};
use alloy_sol_types::{SolCall, SolType};

/// Native TIP-1034 channel reserve precompile address.
pub const TIP20_CHANNEL_RESERVE_ADDRESS: Address =
    address!("0x4D50500000000000000000000000000000000000");

crate::sol! {
    /// TIP-20 channel reserve ABI.
    ///
    /// The reserve locks payer deposits, verifies EIP-712 cumulative vouchers, pays the payee
    /// incrementally, and lets the payer withdraw the remaining balance after a close grace period.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    #[allow(clippy::too_many_arguments)]
    interface ITIP20ChannelReserve {
        /// Immutable channel identity supplied to all descriptor-based methods.
        struct ChannelDescriptor {
            /// Account that funded the channel and receives refunds.
            address payer;
            /// Account that receives settled voucher payments.
            address payee;
            /// Optional relayer allowed to submit `settle` for the payee.
            address operator;
            /// TIP-20 token address held by the channel.
            address token;
            /// User-supplied salt to distinguish otherwise identical channels.
            bytes32 salt;
            /// Optional signer for vouchers. Zero means `payer` signs.
            address authorizedSigner;
            /// Transaction-derived hash assigned when the channel was opened.
            bytes32 expiringNonceHash;
        }

        /// Mutable channel state packed into one native storage slot.
        struct ChannelState {
            /// Cumulative amount already paid to the payee.
            uint96 settled;
            /// Total deposit currently locked by the channel.
            uint96 deposit;
            /// Payer close-request timestamp, or zero when no close is pending.
            uint32 closeRequestedAt;
        }

        /// Full descriptor plus current state.
        struct Channel {
            /// Channel identity fields.
            ChannelDescriptor descriptor;
            /// Mutable channel accounting state.
            ChannelState state;
        }

        /// Delay between payer `requestClose` and `withdraw`.
        function CLOSE_GRACE_PERIOD() external view returns (uint64);
        /// EIP-712 type hash for `Voucher(bytes32 channelId,uint96 cumulativeAmount)`.
        function VOUCHER_TYPEHASH() external view returns (bytes32);

        /// Opens a channel and pulls `deposit` TIP-20 units from `msg.sender`.
        function open(
            address payee,
            address operator,
            address token,
            uint96 deposit,
            bytes32 salt,
            address authorizedSigner
        )
            external
            returns (bytes32 channelId);

        /// Pays the unsettled delta up to `cumulativeAmount` using a valid voucher.
        function settle(
            ChannelDescriptor calldata descriptor,
            uint96 cumulativeAmount,
            bytes calldata signature
        )
            external;

        /// Adds deposit to a channel and cancels any pending close request.
        function topUp(
            ChannelDescriptor calldata descriptor,
            uint96 additionalDeposit
        )
            external;

        /// Closes the channel from the payee/operator side and refunds uncaptured deposit.
        function close(
            ChannelDescriptor calldata descriptor,
            uint96 cumulativeAmount,
            uint96 captureAmount,
            bytes calldata signature
        )
            external;

        /// Starts the payer withdrawal timer.
        function requestClose(ChannelDescriptor calldata descriptor) external;

        /// Withdraws the payer refund after the close grace period has elapsed.
        function withdraw(ChannelDescriptor calldata descriptor) external;

        /// Returns the descriptor and state for a channel.
        function getChannel(ChannelDescriptor calldata descriptor)
            external
            view
            returns (Channel memory);

        /// Returns the state for `channelId`, or the zero state when absent.
        function getChannelState(bytes32 channelId) external view returns (ChannelState memory);

        /// Returns states for `channelIds` in order.
        function getChannelStatesBatch(bytes32[] calldata channelIds)
            external
            view
            returns (ChannelState[] memory);

        /// Computes the canonical channel id for a descriptor.
        function computeChannelId(
            address payer,
            address payee,
            address operator,
            address token,
            bytes32 salt,
            address authorizedSigner,
            bytes32 expiringNonceHash
        )
            external
            view
            returns (bytes32);

        /// Computes the EIP-712 digest signed by the payer or authorized signer.
        function getVoucherDigest(bytes32 channelId, uint96 cumulativeAmount)
            external
            view
            returns (bytes32);

        /// Returns the EIP-712 domain separator for the current chain.
        function domainSeparator() external view returns (bytes32);

        /// Returns the number of reusable channel storage credits owned by `payer`.
        function storageCredits(address payer) external view returns (uint64 credits);

        /// Emitted after a channel is opened and funded.
        event ChannelOpened(
            bytes32 indexed channelId,
            address indexed payer,
            address indexed payee,
            address operator,
            address token,
            address authorizedSigner,
            bytes32 salt,
            bytes32 expiringNonceHash,
            uint96 deposit
        );

        /// Emitted after voucher settlement pays a delta to the payee.
        event Settled(
            bytes32 indexed channelId,
            address indexed payer,
            address indexed payee,
            uint96 cumulativeAmount,
            uint96 deltaPaid,
            uint96 newSettled
        );

        /// Emitted after channel deposit changes or a close request is cancelled by top-up.
        event TopUp(
            bytes32 indexed channelId,
            address indexed payer,
            address indexed payee,
            uint96 additionalDeposit,
            uint96 newDeposit
        );

        /// Emitted when the payer starts the close grace timer.
        event CloseRequested(
            bytes32 indexed channelId,
            address indexed payer,
            address indexed payee,
            uint256 closeGraceEnd
        );

        /// Emitted when a channel is deleted by payee close or payer withdraw.
        event ChannelClosed(
            bytes32 indexed channelId,
            address indexed payer,
            address indexed payee,
            uint96 settledToPayee,
            uint96 refundedToPayer
        );

        /// Emitted when top-up clears a pending close request.
        event CloseRequestCancelled(
            bytes32 indexed channelId,
            address indexed payer,
            address indexed payee
        );

        /// Channel id already exists in persistent state or earlier in this transaction.
        error ChannelAlreadyExists();
        /// Descriptor resolves to an empty channel slot.
        error ChannelNotFound();
        /// Caller must be the descriptor payer.
        error NotPayer();
        /// Caller must be the descriptor payee or nonzero operator.
        error NotPayeeOrOperator();
        /// Payee is zero or a TIP-20-prefix address.
        error InvalidPayee();
        /// Initial deposit cannot be zero.
        error ZeroDeposit();
        /// Handler did not seed the transaction-scoped open context hash.
        error ExpiringNonceHashNotSet();
        /// Voucher signature did not recover to the expected signer.
        error InvalidSignature();
        /// Voucher or capture amount exceeds the channel deposit.
        error AmountExceedsDeposit();
        /// Settlement amount must be greater than the current settled amount.
        error AmountNotIncreasing();
        /// Close capture is below settled amount or above voucher amount.
        error CaptureAmountInvalid();
        /// Payer withdraw was attempted before the close grace period elapsed.
        error CloseNotReady();
        /// Top-up would overflow the packed deposit.
        error DepositOverflow();
    }
}

/// TIP-1045 Maximum calldata length (in bytes) for payment-eligible calls with dynamic params.
pub const MAX_PAYMENT_CALLDATA_LEN: usize = 2048;

impl ITIP20ChannelReserve::ITIP20ChannelReserveCalls {
    /// Returns `true` if `input` matches one of the recognized [TIP-20 channel reserve payment]
    /// selectors: `open`, `topUp`, `settle`, `close`, `requestClose`, `withdraw`.
    ///
    /// # NOTES
    /// - Only validates calldata; caller must check that `to == TIP20_CHANNEL_RESERVE_ADDRESS`.
    /// - Static-only calls require exact ABI-encoded length.
    /// - Dynamic calls require valid ABI decoding and calldata length <= [`MAX_PAYMENT_CALLDATA_LEN`].
    /// - Dynamic calls also require valid `signature` encoding.
    ///
    /// [TIP-20 channel reserve payment]: <https://docs.tempo.xyz/protocol/tip20/overview#get-predictable-payment-fees>
    pub fn is_payment_with_valid_signature(
        input: &[u8],
        validate_signature: impl Fn(&[u8]) -> bool,
    ) -> bool {
        fn is_static_call<C: SolCall>(input: &[u8]) -> bool {
            input.first_chunk::<4>() == Some(&C::SELECTOR)
                && <C::Parameters<'_> as SolType>::ENCODED_SIZE
                    .is_some_and(|canonical_size| input.len() == 4 + canonical_size)
        }

        fn decode_dynamic_call<C: SolCall>(input: &[u8]) -> Option<C> {
            if input.first_chunk::<4>() != Some(&C::SELECTOR)
                || input.len() > MAX_PAYMENT_CALLDATA_LEN
            {
                return None;
            }

            C::abi_decode_validate(input).ok()
        }

        is_static_call::<ITIP20ChannelReserve::openCall>(input)
            || is_static_call::<ITIP20ChannelReserve::topUpCall>(input)
            || decode_dynamic_call::<ITIP20ChannelReserve::closeCall>(input)
                .is_some_and(|call| validate_signature(call.signature.as_ref()))
            || decode_dynamic_call::<ITIP20ChannelReserve::settleCall>(input)
                .is_some_and(|call| validate_signature(call.signature.as_ref()))
            || is_static_call::<ITIP20ChannelReserve::requestCloseCall>(input)
            || is_static_call::<ITIP20ChannelReserve::withdrawCall>(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};
    use alloy_primitives::{B256, aliases::U96};

    impl ITIP20ChannelReserve::ITIP20ChannelReserveCalls {
        /// Test-only helper that accepts any decoded signature.
        /// Avoids depending on `tempo-primitives`, which performs real signature validation.
        fn is_payment(input: &[u8]) -> bool {
            Self::is_payment_with_valid_signature(input, |_| true)
        }
    }

    fn descriptor() -> ITIP20ChannelReserve::ChannelDescriptor {
        ITIP20ChannelReserve::ChannelDescriptor {
            payer: Address::random(),
            payee: Address::random(),
            operator: Address::random(),
            token: Address::random(),
            salt: B256::random(),
            authorizedSigner: Address::random(),
            expiringNonceHash: B256::random(),
        }
    }

    #[rustfmt::skip]
    fn payment_calldatas() -> [Vec<u8>; 6] {
        let descriptor = descriptor();
        [
            ITIP20ChannelReserve::openCall { payee: Address::random(), operator: Address::random(), token: Address::random(), deposit: U96::from(1), salt: B256::random(), authorizedSigner: Address::random() }.abi_encode(),
            ITIP20ChannelReserve::topUpCall { descriptor: descriptor.clone(), additionalDeposit: U96::ONE }.abi_encode(),
            ITIP20ChannelReserve::settleCall { descriptor: descriptor.clone(), cumulativeAmount: U96::ONE, signature: vec![1, 2, 3].into() }.abi_encode(),
            ITIP20ChannelReserve::closeCall { descriptor: descriptor.clone(), cumulativeAmount: U96::ONE, captureAmount: U96::ONE, signature: vec![1, 2, 3].into() }.abi_encode(),
            ITIP20ChannelReserve::requestCloseCall { descriptor: descriptor.clone() }.abi_encode(),
            ITIP20ChannelReserve::withdrawCall { descriptor }.abi_encode(),
        ]
    }

    #[test]
    fn test_is_payment() {
        for calldata in payment_calldatas() {
            assert!(ITIP20ChannelReserve::ITIP20ChannelReserveCalls::is_payment(
                &calldata
            ));
        }

        let mut unknown = payment_calldatas()[0].clone();
        unknown[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert!(!ITIP20ChannelReserve::ITIP20ChannelReserveCalls::is_payment(&unknown));
    }

    #[test]
    fn test_is_payment_rejects_malformed_dynamic_calldata() {
        let mut calldata = ITIP20ChannelReserve::settleCall {
            descriptor: descriptor(),
            cumulativeAmount: U96::from(1),
            signature: vec![1, 2, 3].into(),
        }
        .abi_encode();
        // Corrupt the dynamic `signature` offset word.
        calldata[4 + 8 * 32 + 31] = 0;
        assert!(!ITIP20ChannelReserve::ITIP20ChannelReserveCalls::is_payment(&calldata));

        let mut oversized = ITIP20ChannelReserve::settleCall {
            descriptor: descriptor(),
            cumulativeAmount: U96::from(1),
            signature: vec![0; 2048].into(),
        }
        .abi_encode();
        assert!(oversized.len() > 2048);
        assert!(!ITIP20ChannelReserve::ITIP20ChannelReserveCalls::is_payment(&oversized));

        oversized.truncate(4);
        assert!(!ITIP20ChannelReserve::ITIP20ChannelReserveCalls::is_payment(&oversized));
    }
}
