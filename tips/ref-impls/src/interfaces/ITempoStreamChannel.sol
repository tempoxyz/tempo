// SPDX-License-Identifier: MIT
pragma solidity >=0.8.20 <0.9.0;

/// @title ITempoStreamChannel
/// @notice Interface for the TempoStreamChannel escrow contract.
/// @dev Unidirectional payment channel for streaming payments using EIP-712 signed vouchers.
///      Spec: https://paymentauth.tempo.xyz/draft-tempo-stream-00
interface ITempoStreamChannel {

    struct Channel {
        address payer;
        address payee;
        address token;
        address authorizedSigner;
        uint128 deposit;
        uint128 settled;
        uint64 closeRequestedAt;
        bool finalized;
    }

    function CLOSE_GRACE_PERIOD() external view returns (uint64);
    function VOUCHER_TYPEHASH() external view returns (bytes32);

    function open(
        address payee,
        address token,
        uint128 deposit,
        bytes32 salt,
        address authorizedSigner
    )
        external
        returns (bytes32 channelId);

    function settle(bytes32 channelId, uint128 cumulativeAmount, bytes calldata signature) external;

    function topUp(bytes32 channelId, uint256 additionalDeposit) external;

    function close(bytes32 channelId, uint128 cumulativeAmount, bytes calldata signature) external;

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
        uint256 deposit
    );

    event Settled(
        bytes32 indexed channelId,
        address indexed payer,
        address indexed payee,
        uint256 cumulativeAmount,
        uint256 deltaPaid,
        uint256 newSettled
    );

    event CloseRequested(
        bytes32 indexed channelId,
        address indexed payer,
        address indexed payee,
        uint256 closeGraceEnd
    );

    event TopUp(
        bytes32 indexed channelId,
        address indexed payer,
        address indexed payee,
        uint256 additionalDeposit,
        uint256 newDeposit
    );

    event ChannelClosed(
        bytes32 indexed channelId,
        address indexed payer,
        address indexed payee,
        uint256 settledToPayee,
        uint256 refundedToPayer
    );

    event CloseRequestCancelled(
        bytes32 indexed channelId, address indexed payer, address indexed payee
    );

    event ChannelExpired(bytes32 indexed channelId, address indexed payer, address indexed payee);

    error ChannelAlreadyExists();
    error ChannelNotFound();
    error ChannelFinalized();
    error InvalidSignature();
    error AmountExceedsDeposit();
    error AmountNotIncreasing();
    error NotPayer();
    error NotPayee();
    error TransferFailed();
    error CloseNotReady();
    error InvalidPayee();
    error DepositOverflow();

}
