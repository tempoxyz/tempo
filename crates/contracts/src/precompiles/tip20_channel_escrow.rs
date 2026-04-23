pub use ITIP20ChannelEscrow::{
    ITIP20ChannelEscrowErrors as TIP20ChannelEscrowError,
    ITIP20ChannelEscrowEvents as TIP20ChannelEscrowEvent,
};
use alloy_primitives::{Address, address};
use alloy_sol_types::{SolCall, SolInterface, SolType};

pub const TIP20_CHANNEL_ESCROW_ADDRESS: Address =
    address!("0x4D50500000000000000000000000000000000000");

const SECP256K1_SIGNATURE_LENGTH: usize = 65;
const P256_SIGNATURE_TYPE: u8 = 0x01;
const P256_SIGNATURE_LENGTH: usize = 130;
const WEBAUTHN_SIGNATURE_TYPE: u8 = 0x02;
const MIN_WEBAUTHN_SIGNATURE_LENGTH: usize = 129;
const MAX_WEBAUTHN_SIGNATURE_LENGTH: usize = 2049;

crate::sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    #[allow(clippy::too_many_arguments)]
    interface ITIP20ChannelEscrow {
        struct ChannelDescriptor {
            address payer;
            address payee;
            address token;
            bytes32 salt;
            address authorizedSigner;
        }

        struct ChannelState {
            uint96 settled;
            uint96 deposit;
            uint32 expiresAt;
            uint32 closeData;
        }

        struct Channel {
            ChannelDescriptor descriptor;
            ChannelState state;
        }

        function CLOSE_GRACE_PERIOD() external view returns (uint64);
        function VOUCHER_TYPEHASH() external view returns (bytes32);

        function open(
            address payee,
            address token,
            uint96 deposit,
            bytes32 salt,
            address authorizedSigner,
            uint32 expiresAt
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
            uint96 additionalDeposit,
            uint32 newExpiresAt
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
            address token,
            bytes32 salt,
            address authorizedSigner
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
            address token,
            address authorizedSigner,
            bytes32 salt,
            uint96 deposit,
            uint32 expiresAt
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
            uint96 newDeposit,
            uint32 newExpiresAt
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

        event ChannelExpired(bytes32 indexed channelId, address indexed payer, address indexed payee);

        error ChannelAlreadyExists();
        error ChannelNotFound();
        error ChannelFinalized();
        error NotPayer();
        error NotPayee();
        error InvalidPayee();
        error InvalidToken();
        error ZeroDeposit();
        error InvalidExpiry();
        error ChannelExpiredError();
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
    /// Returns `true` if `input` matches a channel escrow payment-lane selector and its calldata
    /// is well-formed. `settle` and `close` also require a valid primitive signature encoding.
    pub fn is_payment(input: &[u8]) -> bool {
        fn is_static_call<C: SolCall>(input: &[u8]) -> bool {
            input.first_chunk::<4>() == Some(&C::SELECTOR)
                && input.len()
                    == 4 + <C::Parameters<'_> as SolType>::ENCODED_SIZE.unwrap_or_default()
        }

        if is_static_call::<ITIP20ChannelEscrow::openCall>(input)
            || is_static_call::<ITIP20ChannelEscrow::topUpCall>(input)
            || is_static_call::<ITIP20ChannelEscrow::requestCloseCall>(input)
            || is_static_call::<ITIP20ChannelEscrow::withdrawCall>(input)
        {
            return true;
        }

        match Self::abi_decode(input) {
            Ok(Self::settle(call)) => is_valid_primitive_signature_encoding(&call.signature),
            Ok(Self::close(call)) => is_valid_primitive_signature_encoding(&call.signature),
            _ => false,
        }
    }
}

fn is_valid_primitive_signature_encoding(signature: &[u8]) -> bool {
    match signature.len() {
        SECP256K1_SIGNATURE_LENGTH => true,
        P256_SIGNATURE_LENGTH => signature.first() == Some(&P256_SIGNATURE_TYPE),
        MIN_WEBAUTHN_SIGNATURE_LENGTH..=MAX_WEBAUTHN_SIGNATURE_LENGTH => {
            signature.first() == Some(&WEBAUTHN_SIGNATURE_TYPE)
        }
        _ => false,
    }
}

impl TIP20ChannelEscrowError {
    pub const fn channel_already_exists() -> Self {
        Self::ChannelAlreadyExists(ITIP20ChannelEscrow::ChannelAlreadyExists {})
    }

    pub const fn channel_not_found() -> Self {
        Self::ChannelNotFound(ITIP20ChannelEscrow::ChannelNotFound {})
    }

    pub const fn channel_finalized() -> Self {
        Self::ChannelFinalized(ITIP20ChannelEscrow::ChannelFinalized {})
    }

    pub const fn not_payer() -> Self {
        Self::NotPayer(ITIP20ChannelEscrow::NotPayer {})
    }

    pub const fn not_payee() -> Self {
        Self::NotPayee(ITIP20ChannelEscrow::NotPayee {})
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

    pub const fn invalid_expiry() -> Self {
        Self::InvalidExpiry(ITIP20ChannelEscrow::InvalidExpiry {})
    }

    pub const fn channel_expired() -> Self {
        Self::ChannelExpiredError(ITIP20ChannelEscrow::ChannelExpiredError {})
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
