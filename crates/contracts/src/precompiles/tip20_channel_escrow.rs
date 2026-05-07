pub use ITIP20ChannelEscrow::{
    ITIP20ChannelEscrowErrors as TIP20ChannelEscrowError,
    ITIP20ChannelEscrowEvents as TIP20ChannelEscrowEvent,
};
use alloy_primitives::{Address, address};

pub const TIP20_CHANNEL_ESCROW_ADDRESS: Address =
    address!("0x4D50500000000000000000000000000000000000");

crate::sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    #[allow(clippy::too_many_arguments)]
    interface ITIP20ChannelEscrow {
        struct ChannelDescriptor {
            address payer;
            address payee;
            address operator;
            address token;
            bytes32 salt;
            address authorizedSigner;
            bytes32 expiringNonceHash;
        }

        struct ChannelState {
            uint96 settled;
            uint96 deposit;
            uint32 closeRequestedAt;
        }

        struct Channel {
            ChannelDescriptor descriptor;
            ChannelState state;
        }

        function CLOSE_GRACE_PERIOD() external view returns (uint64);
        function VOUCHER_TYPEHASH() external view returns (bytes32);

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

        function settle(
            ChannelDescriptor calldata descriptor,
            uint96 cumulativeAmount,
            bytes calldata signature
        )
            external;

        function topUp(
            ChannelDescriptor calldata descriptor,
            uint96 additionalDeposit
        )
            external;

        function close(
            ChannelDescriptor calldata descriptor,
            uint96 cumulativeAmount,
            uint96 captureAmount,
            bytes calldata signature
        )
            external;

        function requestClose(ChannelDescriptor calldata descriptor) external;

        function withdraw(ChannelDescriptor calldata descriptor) external;

        function getChannel(ChannelDescriptor calldata descriptor)
            external
            view
            returns (Channel memory);

        function getChannelState(bytes32 channelId) external view returns (ChannelState memory);

        function getChannelStatesBatch(bytes32[] calldata channelIds)
            external
            view
            returns (ChannelState[] memory);

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

        function getVoucherDigest(bytes32 channelId, uint96 cumulativeAmount)
            external
            view
            returns (bytes32);

        function domainSeparator() external view returns (bytes32);

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

        event Settled(
            bytes32 indexed channelId,
            address indexed payer,
            address indexed payee,
            uint96 cumulativeAmount,
            uint96 deltaPaid,
            uint96 newSettled
        );

        event TopUp(
            bytes32 indexed channelId,
            address indexed payer,
            address indexed payee,
            uint96 additionalDeposit,
            uint96 newDeposit
        );

        event CloseRequested(
            bytes32 indexed channelId,
            address indexed payer,
            address indexed payee,
            uint256 closeGraceEnd
        );

        event ChannelClosed(
            bytes32 indexed channelId,
            address indexed payer,
            address indexed payee,
            uint96 settledToPayee,
            uint96 refundedToPayer
        );

        event CloseRequestCancelled(
            bytes32 indexed channelId,
            address indexed payer,
            address indexed payee
        );

        error ChannelAlreadyExists();
        error ChannelNotFound();
        error NotPayer();
        error NotPayee();
        error NotPayeeOrOperator();
        error InvalidPayee();
        error InvalidToken();
        error ZeroDeposit();
        error ExpiringNonceHashNotSet();
        error InvalidSignature();
        error AmountExceedsDeposit();
        error AmountNotIncreasing();
        error CaptureAmountInvalid();
        error CloseNotReady();
        error DepositOverflow();
        error TransferFailed();
    }
}

impl ITIP20ChannelEscrow::ITIP20ChannelEscrowCalls {
    /// Returns `true` if `input` matches one of the recognized [TIP-20 channel escrow payment]
    /// selectors: `open`, `topUp`, `settle`, `close`
    ///
    /// # NOTES
    /// - Only validates calldata; caller must check the that `to == TIP20_CHANNEL_ESCROW_ADDRESS`.
    /// - Static-only calls require exact ABI-encoded length.
    /// - Dynamic calls require ABI decoding and total calldata length <= 2048 bytes.
    ///
    /// [TIP-20 channel escrow payment]: <https://docs.tempo.xyz/protocol/tip20/overview#get-predictable-payment-fees>
    pub fn is_payment(input: &[u8]) -> bool {
        fn is_call<C: SolCall>(input: &[u8]) -> bool {
            if input.first_chunk::<4>() != Some(&C::SELECTOR) {
                return false;
            }

            if let Some(canonical_size) = <C::Parameters<'_> as SolType>::ENCODED_SIZE {
                input.len() == 4 + canonical_size
            } else {
                input.len() <= 2048 && C::abi_decode_validate(input).is_ok()
            }
        }

        is_call::<ITIP20ChannelEscrow::openCall>(input)
            || is_call::<ITIP20ChannelEscrow::topUpCall>(input)
            || is_call::<ITIP20ChannelEscrow::closeCall>(input)
            || is_call::<ITIP20ChannelEscrow::settleCall>(input)
    }
}

impl TIP20ChannelEscrowError {
    pub const fn channel_already_exists() -> Self {
        Self::ChannelAlreadyExists(ITIP20ChannelEscrow::ChannelAlreadyExists {})
    }

    pub const fn channel_not_found() -> Self {
        Self::ChannelNotFound(ITIP20ChannelEscrow::ChannelNotFound {})
    }

    pub const fn not_payer() -> Self {
        Self::NotPayer(ITIP20ChannelEscrow::NotPayer {})
    }

    pub const fn not_payee() -> Self {
        Self::NotPayee(ITIP20ChannelEscrow::NotPayee {})
    }

    pub const fn not_payee_or_operator() -> Self {
        Self::NotPayeeOrOperator(ITIP20ChannelEscrow::NotPayeeOrOperator {})
    }

    pub const fn invalid_payee() -> Self {
        Self::InvalidPayee(ITIP20ChannelEscrow::InvalidPayee {})
    }

    pub const fn invalid_token() -> Self {
        Self::InvalidToken(ITIP20ChannelEscrow::InvalidToken {})
    }

    pub const fn zero_deposit() -> Self {
        Self::ZeroDeposit(ITIP20ChannelEscrow::ZeroDeposit {})
    }

    pub const fn expiring_nonce_hash_not_set() -> Self {
        Self::ExpiringNonceHashNotSet(ITIP20ChannelEscrow::ExpiringNonceHashNotSet {})
    }

    pub const fn invalid_signature() -> Self {
        Self::InvalidSignature(ITIP20ChannelEscrow::InvalidSignature {})
    }

    pub const fn amount_exceeds_deposit() -> Self {
        Self::AmountExceedsDeposit(ITIP20ChannelEscrow::AmountExceedsDeposit {})
    }

    pub const fn amount_not_increasing() -> Self {
        Self::AmountNotIncreasing(ITIP20ChannelEscrow::AmountNotIncreasing {})
    }

    pub const fn capture_amount_invalid() -> Self {
        Self::CaptureAmountInvalid(ITIP20ChannelEscrow::CaptureAmountInvalid {})
    }

    pub const fn close_not_ready() -> Self {
        Self::CloseNotReady(ITIP20ChannelEscrow::CloseNotReady {})
    }

    pub const fn deposit_overflow() -> Self {
        Self::DepositOverflow(ITIP20ChannelEscrow::DepositOverflow {})
    }

    pub const fn transfer_failed() -> Self {
        Self::TransferFailed(ITIP20ChannelEscrow::TransferFailed {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};
    use alloy_primitives::{B256, aliases::U96};

    fn descriptor() -> ITIP20ChannelEscrow::ChannelDescriptor {
        ITIP20ChannelEscrow::ChannelDescriptor {
            payer: Address::random(),
            payee: Address::random(),
            token: Address::random(),
            salt: B256::random(),
            authorizedSigner: Address::random(),
        }
    }

    #[rustfmt::skip]
    fn payment_calldatas() -> [Vec<u8>; 4] {
        let descriptor = descriptor();
        [
            ITIP20ChannelEscrow::openCall { payee: Address::random(), token: Address::random(), deposit: U96::from(1), salt: B256::random(), authorizedSigner: Address::random() }.abi_encode(),
            ITIP20ChannelEscrow::topUpCall { descriptor: descriptor.clone(), additionalDeposit: U96::from(1) }.abi_encode(),
            ITIP20ChannelEscrow::settleCall { descriptor: descriptor.clone(), cumulativeAmount: U96::from(1), signature: vec![1, 2, 3].into() }.abi_encode(),
            ITIP20ChannelEscrow::closeCall { descriptor, cumulativeAmount: U96::from(1), captureAmount: U96::from(1), signature: vec![1, 2, 3].into() }.abi_encode(),
        ]
    }

    #[test]
    fn test_is_payment() {
        for calldata in payment_calldatas() {
            assert!(ITIP20ChannelEscrow::ITIP20ChannelEscrowCalls::is_payment(
                &calldata
            ));
        }

        assert!(!ITIP20ChannelEscrow::ITIP20ChannelEscrowCalls::is_payment(
            &ITIP20ChannelEscrow::requestCloseCall {
                descriptor: descriptor()
            }
            .abi_encode(),
        ));

        let mut unknown = payment_calldatas()[0].clone();
        unknown[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert!(!ITIP20ChannelEscrow::ITIP20ChannelEscrowCalls::is_payment(
            &unknown
        ));
    }

    #[test]
    fn test_is_payment_rejects_malformed_dynamic_calldata() {
        let mut calldata = ITIP20ChannelEscrow::settleCall {
            descriptor: descriptor(),
            cumulativeAmount: U96::from(1),
            signature: vec![1, 2, 3].into(),
        }
        .abi_encode();
        // Corrupt the dynamic `signature` offset word.
        calldata[4 + 6 * 32 + 31] = 0;
        assert!(!ITIP20ChannelEscrow::ITIP20ChannelEscrowCalls::is_payment(
            &calldata
        ));

        let mut oversized = ITIP20ChannelEscrow::settleCall {
            descriptor: descriptor(),
            cumulativeAmount: U96::from(1),
            signature: vec![0; 2048].into(),
        }
        .abi_encode();
        assert!(oversized.len() > 2048);
        assert!(!ITIP20ChannelEscrow::ITIP20ChannelEscrowCalls::is_payment(
            &oversized
        ));

        oversized.truncate(4);
        assert!(!ITIP20ChannelEscrow::ITIP20ChannelEscrowCalls::is_payment(
            &oversized
        ));
    }
}
