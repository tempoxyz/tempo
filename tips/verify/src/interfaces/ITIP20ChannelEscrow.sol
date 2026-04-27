// SPDX-License-Identifier: MIT
pragma solidity >=0.8.20 <0.9.0;

/// @title ITIP20ChannelEscrow
/// @notice Reference interface for the TIP-1034 channel model.
interface ITIP20ChannelEscrow {

    struct ChannelDescriptor {
        address payer;
        address payee;
        address token;
        bytes32 salt;
        address authorizedSigner;
    }

    struct ChannelState {
        bool finalized;
        uint32 closeRequestedAt;
        uint32 expiresAt;
        uint96 deposit;
        uint96 settled;
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

    function getVoucherDigest(
        bytes32 channelId,
        uint96 cumulativeAmount
    )
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
        bytes32 indexed channelId, address indexed payer, address indexed payee
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
