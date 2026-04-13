// SPDX-License-Identifier: MIT
pragma solidity >=0.8.20 <0.9.0;

/// @title ITempoStreamChannel
/// @notice Reference interface for the TIP-1034 channel model.
interface ITempoStreamChannel {

    struct Channel {
        bool finalized;
        uint64 closeRequestedAt;
        address payer;
        address payee;
        uint64 expiresAt;
        address token;
        address authorizedSigner;
        uint128 deposit;
        uint128 settled;
    }

    function CLOSE_GRACE_PERIOD() external view returns (uint64);
    function VOUCHER_TYPEHASH() external view returns (bytes32);

    function open(
        address payee,
        address token,
        uint128 deposit,
        bytes32 salt,
        address authorizedSigner,
        uint64 expiresAt
    )
        external
        returns (bytes32 channelId);

    function settle(bytes32 channelId, uint128 cumulativeAmount, bytes calldata signature) external;

    function topUp(bytes32 channelId, uint256 additionalDeposit, uint64 newExpiresAt) external;

    function close(
        bytes32 channelId,
        uint128 cumulativeAmount,
        uint128 captureAmount,
        bytes calldata signature
    )
        external;

    function requestClose(bytes32 channelId) external;

    function withdraw(bytes32 channelId) external;

    function getChannel(bytes32 channelId) external view returns (Channel memory);

    function getChannelsBatch(bytes32[] calldata channelIds)
        external
        view
        returns (Channel[] memory);

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
        uint128 cumulativeAmount
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
        uint128 deposit,
        uint64 expiresAt
    );

    event Settled(
        bytes32 indexed channelId,
        address indexed payer,
        address indexed payee,
        uint128 cumulativeAmount,
        uint128 deltaPaid,
        uint128 newSettled
    );

    event TopUp(
        bytes32 indexed channelId,
        address indexed payer,
        address indexed payee,
        uint128 additionalDeposit,
        uint128 newDeposit,
        uint64 newExpiresAt
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
        uint128 settledToPayee,
        uint128 refundedToPayer
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
