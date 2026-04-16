// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ISignatureVerifier } from "./interfaces/ISignatureVerifier.sol";
import { ITIP20 } from "./interfaces/ITIP20.sol";
import { ITIP20ChannelEscrow } from "./interfaces/ITIP20ChannelEscrow.sol";

/// @title TIP20ChannelEscrow
/// @notice Reference contract for the TIP-1034 channel model.
contract TIP20ChannelEscrow is ITIP20ChannelEscrow {

    address public constant TIP20_CHANNEL_ESCROW = 0x4d50500000000000000000000000000000000000;
    address public constant SIGNATURE_VERIFIER_PRECOMPILE =
        0x5165300000000000000000000000000000000000;

    bytes32 public constant VOUCHER_TYPEHASH =
        keccak256("Voucher(bytes32 channelId,uint128 cumulativeAmount)");

    uint64 public constant CLOSE_GRACE_PERIOD = 15 minutes;

    bytes32 internal constant _EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 internal constant _NAME_HASH = keccak256("TIP20 Channel Escrow");
    bytes32 internal constant _VERSION_HASH = keccak256("1");

    mapping(bytes32 => Channel) public channels;

    function open(
        address payee,
        address token,
        uint128 deposit,
        bytes32 salt,
        address authorizedSigner,
        uint64 expiresAt
    )
        external
        returns (bytes32 channelId)
    {
        if (payee == address(0)) revert InvalidPayee();
        if (token == address(0)) revert InvalidToken();
        if (deposit == 0) revert ZeroDeposit();
        if (expiresAt <= block.timestamp) revert InvalidExpiry();

        channelId = computeChannelId(msg.sender, payee, token, salt, authorizedSigner);
        if (channels[channelId].payer != address(0)) revert ChannelAlreadyExists();

        channels[channelId] = Channel({
            finalized: false,
            closeRequestedAt: 0,
            payer: msg.sender,
            payee: payee,
            expiresAt: expiresAt,
            token: token,
            authorizedSigner: authorizedSigner,
            deposit: deposit,
            settled: 0
        });

        bool success = ITIP20(token).transferFrom(msg.sender, address(this), deposit);
        if (!success) revert TransferFailed();

        emit ChannelOpened(
            channelId, msg.sender, payee, token, authorizedSigner, salt, deposit, expiresAt
        );
    }

    function settle(
        bytes32 channelId,
        uint128 cumulativeAmount,
        bytes calldata signature
    )
        external
    {
        Channel storage channel = channels[channelId];

        if (channel.payer == address(0)) revert ChannelNotFound();
        if (msg.sender != channel.payee) revert NotPayee();
        if (channel.finalized) revert ChannelFinalized();
        if (_isExpired(channel)) revert ChannelExpiredError();
        if (cumulativeAmount > channel.deposit) revert AmountExceedsDeposit();
        if (cumulativeAmount <= channel.settled) revert AmountNotIncreasing();

        _validateVoucher(channel, channelId, cumulativeAmount, signature);

        uint128 delta = cumulativeAmount - channel.settled;
        channel.settled = cumulativeAmount;

        bool success = ITIP20(channel.token).transfer(channel.payee, delta);
        if (!success) revert TransferFailed();

        emit Settled(
            channelId, channel.payer, channel.payee, cumulativeAmount, delta, channel.settled
        );
    }

    function topUp(bytes32 channelId, uint256 additionalDeposit, uint64 newExpiresAt) external {
        Channel storage channel = channels[channelId];

        if (channel.payer == address(0)) revert ChannelNotFound();
        if (msg.sender != channel.payer) revert NotPayer();
        if (channel.finalized) revert ChannelFinalized();

        if (additionalDeposit > type(uint128).max - channel.deposit) revert DepositOverflow();
        if (newExpiresAt != 0) {
            if (newExpiresAt <= block.timestamp) revert InvalidExpiry();
            if (newExpiresAt <= channel.expiresAt) revert InvalidExpiry();
        }

        if (additionalDeposit > 0) {
            channel.deposit += uint128(additionalDeposit);

            bool success =
                ITIP20(channel.token).transferFrom(msg.sender, address(this), additionalDeposit);
            if (!success) revert TransferFailed();
        }

        if (newExpiresAt != 0) {
            channel.expiresAt = newExpiresAt;
        }

        if (channel.closeRequestedAt != 0) {
            channel.closeRequestedAt = 0;
            emit CloseRequestCancelled(channelId, channel.payer, channel.payee);
        }

        emit TopUp(
            channelId,
            channel.payer,
            channel.payee,
            uint128(additionalDeposit),
            channel.deposit,
            channel.expiresAt
        );
    }

    function requestClose(bytes32 channelId) external {
        Channel storage channel = channels[channelId];

        if (channel.payer == address(0)) revert ChannelNotFound();
        if (msg.sender != channel.payer) revert NotPayer();
        if (channel.finalized) revert ChannelFinalized();

        if (channel.closeRequestedAt == 0) {
            channel.closeRequestedAt = uint64(block.timestamp);
            emit CloseRequested(
                channelId,
                channel.payer,
                channel.payee,
                uint256(block.timestamp) + CLOSE_GRACE_PERIOD
            );
        }
    }

    function close(
        bytes32 channelId,
        uint128 cumulativeAmount,
        uint128 captureAmount,
        bytes calldata signature
    )
        external
    {
        Channel storage channel = channels[channelId];

        if (channel.payer == address(0)) revert ChannelNotFound();
        if (msg.sender != channel.payee) revert NotPayee();
        if (channel.finalized) revert ChannelFinalized();

        uint128 previousSettled = channel.settled;
        if (captureAmount < previousSettled || captureAmount > cumulativeAmount) {
            revert CaptureAmountInvalid();
        }
        if (captureAmount > channel.deposit) revert AmountExceedsDeposit();

        if (captureAmount > previousSettled) {
            if (_isExpired(channel)) revert ChannelExpiredError();
            _validateVoucher(channel, channelId, cumulativeAmount, signature);
        }

        uint128 delta = captureAmount - previousSettled;
        uint128 refund = channel.deposit - captureAmount;

        channel.settled = captureAmount;
        channel.finalized = true;

        if (delta > 0) {
            bool payeeTransferSucceeded = ITIP20(channel.token).transfer(channel.payee, delta);
            if (!payeeTransferSucceeded) revert TransferFailed();
        }

        if (refund > 0) {
            bool payerTransferSucceeded = ITIP20(channel.token).transfer(channel.payer, refund);
            if (!payerTransferSucceeded) revert TransferFailed();
        }

        emit ChannelClosed(channelId, channel.payer, channel.payee, captureAmount, refund);
    }

    function withdraw(bytes32 channelId) external {
        Channel storage channel = channels[channelId];

        if (channel.payer == address(0)) revert ChannelNotFound();
        if (msg.sender != channel.payer) revert NotPayer();
        if (channel.finalized) revert ChannelFinalized();

        bool closeGracePassed = channel.closeRequestedAt != 0
            && block.timestamp >= uint256(channel.closeRequestedAt) + CLOSE_GRACE_PERIOD;

        if (!closeGracePassed && !_isExpired(channel)) revert CloseNotReady();

        uint128 refund = channel.deposit - channel.settled;
        channel.finalized = true;

        if (refund > 0) {
            bool success = ITIP20(channel.token).transfer(channel.payer, refund);
            if (!success) revert TransferFailed();
        }

        emit ChannelExpired(channelId, channel.payer, channel.payee);
        emit ChannelClosed(channelId, channel.payer, channel.payee, channel.settled, refund);
    }

    function getChannel(bytes32 channelId) external view returns (Channel memory) {
        return channels[channelId];
    }

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
            abi.encode(
                payer, payee, token, salt, authorizedSigner, TIP20_CHANNEL_ESCROW, block.chainid
            )
        );
    }

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

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparator();
    }

    function _isExpired(Channel storage channel) internal view returns (bool) {
        return block.timestamp >= channel.expiresAt;
    }

    function _validateVoucher(
        Channel storage channel,
        bytes32 channelId,
        uint128 cumulativeAmount,
        bytes calldata signature
    )
        internal
        view
    {
        bytes32 structHash = keccak256(abi.encode(VOUCHER_TYPEHASH, channelId, cumulativeAmount));
        bytes32 digest = _hashTypedData(structHash);
        address expectedSigner =
            channel.authorizedSigner != address(0) ? channel.authorizedSigner : channel.payer;

        bool isValid;
        try ISignatureVerifier(SIGNATURE_VERIFIER_PRECOMPILE)
            .verify(expectedSigner, digest, signature) returns (
            bool valid
        ) {
            isValid = valid;
        } catch {
            revert InvalidSignature();
        }

        if (!isValid) revert InvalidSignature();
    }

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH,
                _NAME_HASH,
                _VERSION_HASH,
                block.chainid,
                TIP20_CHANNEL_ESCROW
            )
        );
    }

    function _hashTypedData(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
    }

}
