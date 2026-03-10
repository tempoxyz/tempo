// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ITIP20 } from "./interfaces/ITIP20.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";
import { EIP712 } from "solady/utils/EIP712.sol";

/**
 * @title TempoStreamChannel
 * @notice Unidirectional payment channel escrow for streaming payments.
 * @dev Users deposit TIP-20 tokens, sign cumulative vouchers, and servers
 *      can settle or close at any time. Channels have no expiry - they are
 *      closed either cooperatively by the server or after a grace period
 *      following a user's close request.
 */
contract TempoStreamChannel is EIP712 {

    // --- Types ---

    struct Channel {
        address payer; // User who deposited funds
        address payee; // Server authorized to withdraw
        address token; // TIP-20 token address
        address authorizedSigner; // Address authorized to sign vouchers (0 = payer)
        uint128 deposit; // Total amount deposited
        uint128 settled; // Cumulative amount already withdrawn
        uint64 closeRequestedAt; // Timestamp when close was requested (0 if not)
        bool finalized; // Prevents double-withdraw
    }

    // --- Constants ---

    bytes32 public constant VOUCHER_TYPEHASH =
        keccak256("Voucher(bytes32 channelId,uint128 cumulativeAmount)");

    uint64 public constant CLOSE_GRACE_PERIOD = 15 minutes;

    // --- State ---

    mapping(bytes32 => Channel) public channels;

    // --- Events ---

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

    // --- Errors ---

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

    // --- EIP-712 Domain ---

    function _domainNameAndVersion()
        internal
        pure
        override
        returns (string memory name, string memory version)
    {
        name = "Tempo Stream Channel";
        version = "1";
    }

    // --- External Functions ---

    /**
     * @notice Open a new payment channel with escrowed funds.
     * @param payee Address authorized to withdraw (server)
     * @param token TIP-20 token address
     * @param deposit Amount to deposit
     * @param salt Random salt for channel ID generation
     * @param authorizedSigner Address authorized to sign vouchers (0 = use msg.sender)
     * @return channelId The unique channel identifier
     */
    function open(
        address payee,
        address token,
        uint128 deposit,
        bytes32 salt,
        address authorizedSigner
    )
        external
        returns (bytes32 channelId)
    {
        if (payee == address(0)) {
            revert InvalidPayee();
        }

        channelId = computeChannelId(msg.sender, payee, token, salt, authorizedSigner);

        if (channels[channelId].payer != address(0)) {
            revert ChannelAlreadyExists();
        }

        channels[channelId] = Channel({
            payer: msg.sender,
            payee: payee,
            token: token,
            authorizedSigner: authorizedSigner,
            deposit: deposit,
            settled: 0,
            closeRequestedAt: 0,
            finalized: false
        });

        bool success = ITIP20(token).transferFrom(msg.sender, address(this), deposit);
        if (!success) {
            revert TransferFailed();
        }

        emit ChannelOpened(channelId, msg.sender, payee, token, authorizedSigner, salt, deposit);
    }

    /**
     * @notice Settle funds using a signed voucher.
     * @param channelId The channel to settle
     * @param cumulativeAmount Total amount authorized by the voucher
     * @param signature EIP-712 signature from the payer/authorizedSigner
     */
    function settle(
        bytes32 channelId,
        uint128 cumulativeAmount,
        bytes calldata signature
    )
        external
    {
        Channel storage channel = channels[channelId];

        if (channel.payer == address(0)) {
            revert ChannelNotFound();
        }
        if (msg.sender != channel.payee) {
            revert NotPayee();
        }
        if (channel.finalized) {
            revert ChannelFinalized();
        }
        if (cumulativeAmount > channel.deposit) {
            revert AmountExceedsDeposit();
        }
        if (cumulativeAmount <= channel.settled) {
            revert AmountNotIncreasing();
        }

        bytes32 structHash = keccak256(abi.encode(VOUCHER_TYPEHASH, channelId, cumulativeAmount));
        bytes32 digest = _hashTypedData(structHash);
        address signer = ECDSA.recoverCalldata(digest, signature);

        address expectedSigner =
            channel.authorizedSigner != address(0) ? channel.authorizedSigner : channel.payer;

        if (signer != expectedSigner) {
            revert InvalidSignature();
        }

        uint128 delta = cumulativeAmount - channel.settled;
        channel.settled = cumulativeAmount;

        bool success = ITIP20(channel.token).transfer(channel.payee, delta);
        if (!success) {
            revert TransferFailed();
        }

        emit Settled(
            channelId, channel.payer, channel.payee, cumulativeAmount, delta, channel.settled
        );
    }

    /**
     * @notice Add more funds to a channel.
     * @param channelId The channel to top up
     * @param additionalDeposit Amount to add
     */
    function topUp(bytes32 channelId, uint256 additionalDeposit) external {
        Channel storage channel = channels[channelId];

        if (channel.payer == address(0)) {
            revert ChannelNotFound();
        }
        if (msg.sender != channel.payer) {
            revert NotPayer();
        }
        if (channel.finalized) {
            revert ChannelFinalized();
        }

        if (additionalDeposit > 0) {
            if (additionalDeposit > type(uint128).max - channel.deposit) {
                revert DepositOverflow();
            }
            channel.deposit += uint128(additionalDeposit);

            bool success =
                ITIP20(channel.token).transferFrom(msg.sender, address(this), additionalDeposit);
            if (!success) {
                revert TransferFailed();
            }
        }

        if (channel.closeRequestedAt != 0) {
            channel.closeRequestedAt = 0;
            emit CloseRequestCancelled(channelId, channel.payer, channel.payee);
        }

        emit TopUp(channelId, channel.payer, channel.payee, additionalDeposit, channel.deposit);
    }

    /**
     * @notice Request early channel closure.
     * @dev Starts a grace period after which the payer can withdraw.
     * @param channelId The channel to close
     */
    function requestClose(bytes32 channelId) external {
        Channel storage channel = channels[channelId];

        if (channel.payer == address(0)) {
            revert ChannelNotFound();
        }
        if (msg.sender != channel.payer) {
            revert NotPayer();
        }
        if (channel.finalized) {
            revert ChannelFinalized();
        }

        // Only set if not already requested
        if (channel.closeRequestedAt == 0) {
            channel.closeRequestedAt = uint64(block.timestamp);
            emit CloseRequested(
                channelId, channel.payer, channel.payee, block.timestamp + CLOSE_GRACE_PERIOD
            );
        }
    }

    /**
     * @notice Close a channel immediately (server only).
     * @dev Settles any outstanding voucher and refunds remainder to payer.
     * @param channelId The channel to close
     * @param cumulativeAmount Final cumulative amount (0 if no payments)
     * @param signature EIP-712 signature (empty if cumulativeAmount == 0 or same as settled)
     */
    function close(bytes32 channelId, uint128 cumulativeAmount, bytes calldata signature) external {
        Channel storage channel = channels[channelId];

        if (channel.payer == address(0)) {
            revert ChannelNotFound();
        }
        if (msg.sender != channel.payee) {
            revert NotPayee();
        }
        if (channel.finalized) {
            revert ChannelFinalized();
        }

        uint128 settledAmount = channel.settled;
        uint128 delta = 0;

        // If cumulativeAmount > settled, validate the voucher
        if (cumulativeAmount > settledAmount) {
            if (cumulativeAmount > channel.deposit) {
                revert AmountExceedsDeposit();
            }

            bytes32 structHash =
                keccak256(abi.encode(VOUCHER_TYPEHASH, channelId, cumulativeAmount));
            bytes32 digest = _hashTypedData(structHash);
            address signer = ECDSA.recoverCalldata(digest, signature);

            address expectedSigner =
                channel.authorizedSigner != address(0) ? channel.authorizedSigner : channel.payer;

            if (signer != expectedSigner) {
                revert InvalidSignature();
            }

            delta = cumulativeAmount - settledAmount;
            settledAmount = cumulativeAmount;
            channel.settled = cumulativeAmount;
        }

        // Effects before interactions
        uint128 refund = channel.deposit - settledAmount;
        channel.finalized = true;

        // Interactions
        if (delta > 0) {
            bool success = ITIP20(channel.token).transfer(channel.payee, delta);
            if (!success) {
                revert TransferFailed();
            }
        }

        if (refund > 0) {
            bool success = ITIP20(channel.token).transfer(channel.payer, refund);
            if (!success) {
                revert TransferFailed();
            }
        }

        emit ChannelClosed(channelId, channel.payer, channel.payee, settledAmount, refund);
    }

    /**
     * @notice Withdraw remaining funds after close grace period.
     * @param channelId The channel to withdraw from
     */
    function withdraw(bytes32 channelId) external {
        Channel storage channel = channels[channelId];

        if (channel.payer == address(0)) {
            revert ChannelNotFound();
        }
        if (msg.sender != channel.payer) {
            revert NotPayer();
        }
        if (channel.finalized) {
            revert ChannelFinalized();
        }

        // Check if eligible to withdraw
        bool closeGracePassed = channel.closeRequestedAt != 0
            && block.timestamp >= channel.closeRequestedAt + CLOSE_GRACE_PERIOD;

        if (!closeGracePassed) {
            revert CloseNotReady();
        }

        uint128 refund = channel.deposit - channel.settled;
        channel.finalized = true;

        if (refund > 0) {
            bool success = ITIP20(channel.token).transfer(channel.payer, refund);
            if (!success) {
                revert TransferFailed();
            }
        }

        emit ChannelExpired(channelId, channel.payer, channel.payee);
        emit ChannelClosed(channelId, channel.payer, channel.payee, channel.settled, refund);
    }

    // --- View Functions ---

    /**
     * @notice Get channel state.
     */
    function getChannel(bytes32 channelId) external view returns (Channel memory) {
        return channels[channelId];
    }

    /**
     * @notice Compute the channel ID for given parameters.
     * @param payer Address that deposited funds
     * @param payee Address authorized to withdraw
     * @param token TIP-20 token address
     * @param salt Random salt
     * @param authorizedSigner Address authorized to sign vouchers
     */
    function computeChannelId(
        address payer,
        address payee,
        address token,
        bytes32 salt,
        address authorizedSigner
    )
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(payer, payee, token, salt, authorizedSigner, address(this), block.chainid)
        );
    }

    /**
     * @notice Get the EIP-712 domain separator.
     */
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparator();
    }

    /**
     * @notice Compute the digest for a voucher (for off-chain signing).
     */
    function getVoucherDigest(
        bytes32 channelId,
        uint128 cumulativeAmount
    )
        external
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(abi.encode(VOUCHER_TYPEHASH, channelId, cumulativeAmount));
        return _hashTypedData(structHash);
    }

    /**
     * @notice Read multiple channel states in a single call.
     * @param channelIds Array of channel IDs to query
     * @return channelStates Array of Channel structs
     */
    function getChannelsBatch(bytes32[] calldata channelIds)
        external
        view
        returns (Channel[] memory channelStates)
    {
        uint256 length = channelIds.length;
        channelStates = new Channel[](length);

        for (uint256 i = 0; i < length; ++i) {
            channelStates[i] = channels[channelIds[i]];
        }
    }

}
