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
        keccak256("Voucher(bytes32 channelId,uint96 cumulativeAmount)");

    uint64 public constant CLOSE_GRACE_PERIOD = 15 minutes;

    uint256 internal constant _DEPOSIT_OFFSET = 96;
    uint256 internal constant _EXPIRES_AT_OFFSET = 192;
    uint256 internal constant _CLOSE_DATA_OFFSET = 224;
    uint32 internal constant _FINALIZED_CLOSE_DATA = 1;

    bytes32 internal constant _EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 internal constant _NAME_HASH = keccak256("TIP20 Channel Escrow");
    bytes32 internal constant _VERSION_HASH = keccak256("1");

    mapping(bytes32 => uint256) internal channelStates;

    function open(
        address payee,
        address token,
        uint96 deposit,
        bytes32 salt,
        address authorizedSigner,
        uint32 expiresAt
    )
        external
        returns (bytes32 channelId)
    {
        if (payee == address(0)) revert InvalidPayee();
        if (token == address(0)) revert InvalidToken();
        if (deposit == 0) revert ZeroDeposit();
        if (expiresAt <= block.timestamp) revert InvalidExpiry();

        channelId = computeChannelId(msg.sender, payee, token, salt, authorizedSigner);
        if (channelStates[channelId] != 0) revert ChannelAlreadyExists();

        channelStates[channelId] = _encodeChannelState(
            ChannelState({
                settled: 0,
                deposit: deposit,
                expiresAt: expiresAt,
                closeData: 0
            })
        );

        // The reference contract keeps ERC-20-style allowance flow for local verification.
        // The enshrined precompile should use TIP-20 `systemTransferFrom` semantics instead.
        bool success = ITIP20(token).transferFrom(msg.sender, address(this), deposit);
        if (!success) revert TransferFailed();

        emit ChannelOpened(
            channelId, msg.sender, payee, token, authorizedSigner, salt, deposit, expiresAt
        );
    }

    function settle(
        ChannelDescriptor calldata descriptor,
        uint96 cumulativeAmount,
        bytes calldata signature
    )
        external
    {
        bytes32 channelId = _channelId(descriptor);
        ChannelState memory channel = _loadChannelState(channelId);

        if (msg.sender != descriptor.payee) revert NotPayee();
        if (_isFinalized(channel.closeData)) revert ChannelFinalized();
        if (_isExpired(channel.expiresAt)) revert ChannelExpiredError();
        if (cumulativeAmount > channel.deposit) revert AmountExceedsDeposit();
        if (cumulativeAmount <= channel.settled) revert AmountNotIncreasing();

        _validateVoucher(descriptor, channelId, cumulativeAmount, signature);

        uint96 delta = cumulativeAmount - channel.settled;
        channel.settled = cumulativeAmount;
        channelStates[channelId] = _encodeChannelState(channel);

        bool success = ITIP20(descriptor.token).transfer(descriptor.payee, delta);
        if (!success) revert TransferFailed();

        emit Settled(
            channelId, descriptor.payer, descriptor.payee, cumulativeAmount, delta, channel.settled
        );
    }

    function topUp(
        ChannelDescriptor calldata descriptor,
        uint96 additionalDeposit,
        uint32 newExpiresAt
    )
        external
    {
        bytes32 channelId = _channelId(descriptor);
        ChannelState memory channel = _loadChannelState(channelId);

        if (msg.sender != descriptor.payer) revert NotPayer();
        if (_isFinalized(channel.closeData)) revert ChannelFinalized();

        if (additionalDeposit > type(uint96).max - channel.deposit) revert DepositOverflow();
        if (newExpiresAt != 0) {
            if (newExpiresAt <= block.timestamp) revert InvalidExpiry();
            if (newExpiresAt <= channel.expiresAt) revert InvalidExpiry();
        }

        if (additionalDeposit > 0) {
            channel.deposit += additionalDeposit;

            // The reference contract keeps ERC-20-style allowance flow for local verification.
            // The enshrined precompile should use TIP-20 `systemTransferFrom` semantics instead.
            bool success =
                ITIP20(descriptor.token).transferFrom(msg.sender, address(this), additionalDeposit);
            if (!success) revert TransferFailed();
        }

        if (newExpiresAt != 0) {
            channel.expiresAt = newExpiresAt;
        }

        if (_closeRequestedAt(channel.closeData) != 0) {
            channel.closeData = 0;
            emit CloseRequestCancelled(channelId, descriptor.payer, descriptor.payee);
        }

        channelStates[channelId] = _encodeChannelState(channel);

        emit TopUp(
            channelId,
            descriptor.payer,
            descriptor.payee,
            additionalDeposit,
            channel.deposit,
            channel.expiresAt
        );
    }

    function requestClose(ChannelDescriptor calldata descriptor) external {
        bytes32 channelId = _channelId(descriptor);
        ChannelState memory channel = _loadChannelState(channelId);

        if (msg.sender != descriptor.payer) revert NotPayer();
        if (_isFinalized(channel.closeData)) revert ChannelFinalized();

        if (_closeRequestedAt(channel.closeData) == 0) {
            channel.closeData = uint32(block.timestamp);
            channelStates[channelId] = _encodeChannelState(channel);
            emit CloseRequested(
                channelId,
                descriptor.payer,
                descriptor.payee,
                uint256(block.timestamp) + CLOSE_GRACE_PERIOD
            );
        }
    }

    function close(
        ChannelDescriptor calldata descriptor,
        uint96 cumulativeAmount,
        uint96 captureAmount,
        bytes calldata signature
    )
        external
    {
        bytes32 channelId = _channelId(descriptor);
        ChannelState memory channel = _loadChannelState(channelId);

        if (msg.sender != descriptor.payee) revert NotPayee();
        if (_isFinalized(channel.closeData)) revert ChannelFinalized();

        uint96 previousSettled = channel.settled;
        if (captureAmount < previousSettled || captureAmount > cumulativeAmount) {
            revert CaptureAmountInvalid();
        }
        if (captureAmount > channel.deposit) revert AmountExceedsDeposit();

        if (captureAmount > previousSettled) {
            if (_isExpired(channel.expiresAt)) revert ChannelExpiredError();
            _validateVoucher(descriptor, channelId, cumulativeAmount, signature);
        }

        uint96 delta = captureAmount - previousSettled;
        uint96 refund = channel.deposit - captureAmount;

        channel.settled = captureAmount;
        channel.closeData = _FINALIZED_CLOSE_DATA;
        channelStates[channelId] = _encodeChannelState(channel);

        if (delta > 0) {
            bool payeeTransferSucceeded = ITIP20(descriptor.token).transfer(descriptor.payee, delta);
            if (!payeeTransferSucceeded) revert TransferFailed();
        }

        if (refund > 0) {
            bool payerTransferSucceeded =
                ITIP20(descriptor.token).transfer(descriptor.payer, refund);
            if (!payerTransferSucceeded) revert TransferFailed();
        }

        emit ChannelClosed(channelId, descriptor.payer, descriptor.payee, captureAmount, refund);
    }

    function withdraw(ChannelDescriptor calldata descriptor) external {
        bytes32 channelId = _channelId(descriptor);
        ChannelState memory channel = _loadChannelState(channelId);

        if (msg.sender != descriptor.payer) revert NotPayer();
        if (_isFinalized(channel.closeData)) revert ChannelFinalized();

        uint32 closeRequestedAt = _closeRequestedAt(channel.closeData);
        bool closeGracePassed = closeRequestedAt != 0
            && block.timestamp >= uint256(closeRequestedAt) + CLOSE_GRACE_PERIOD;

        if (!closeGracePassed && !_isExpired(channel.expiresAt)) revert CloseNotReady();

        uint96 refund = channel.deposit - channel.settled;
        channel.closeData = _FINALIZED_CLOSE_DATA;
        channelStates[channelId] = _encodeChannelState(channel);

        if (refund > 0) {
            bool success = ITIP20(descriptor.token).transfer(descriptor.payer, refund);
            if (!success) revert TransferFailed();
        }

        emit ChannelExpired(channelId, descriptor.payer, descriptor.payee);
        emit ChannelClosed(channelId, descriptor.payer, descriptor.payee, channel.settled, refund);
    }

    function getChannel(ChannelDescriptor calldata descriptor)
        external
        view
        returns (Channel memory channel)
    {
        channel.descriptor = ChannelDescriptor({
            payer: descriptor.payer,
            payee: descriptor.payee,
            token: descriptor.token,
            salt: descriptor.salt,
            authorizedSigner: descriptor.authorizedSigner
        });
        channel.state = _decodeChannelState(channelStates[_channelId(descriptor)]);
    }

    function getChannelState(bytes32 channelId) external view returns (ChannelState memory) {
        return _decodeChannelState(channelStates[channelId]);
    }

    function getChannelStatesBatch(bytes32[] calldata channelIds)
        external
        view
        returns (ChannelState[] memory states)
    {
        uint256 length = channelIds.length;
        states = new ChannelState[](length);

        for (uint256 i = 0; i < length; ++i) {
            states[i] = _decodeChannelState(channelStates[channelIds[i]]);
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
        uint96 cumulativeAmount
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

    function _channelId(ChannelDescriptor calldata descriptor) internal view returns (bytes32) {
        return computeChannelId(
            descriptor.payer,
            descriptor.payee,
            descriptor.token,
            descriptor.salt,
            descriptor.authorizedSigner
        );
    }

    function _loadChannelState(bytes32 channelId) internal view returns (ChannelState memory) {
        uint256 packedState = channelStates[channelId];
        if (packedState == 0) revert ChannelNotFound();
        return _decodeChannelState(packedState);
    }

    function _decodeChannelState(uint256 packedState)
        internal
        pure
        returns (ChannelState memory state)
    {
        if (packedState == 0) {
            return state;
        }

        state.settled = uint96(packedState);
        state.deposit = uint96(packedState >> _DEPOSIT_OFFSET);
        state.expiresAt = uint32(packedState >> _EXPIRES_AT_OFFSET);
        state.closeData = uint32(packedState >> _CLOSE_DATA_OFFSET);
    }

    function _encodeChannelState(ChannelState memory state)
        internal
        pure
        returns (uint256 packedState)
    {
        packedState = uint256(state.settled);
        packedState |= uint256(state.deposit) << _DEPOSIT_OFFSET;
        packedState |= uint256(state.expiresAt) << _EXPIRES_AT_OFFSET;
        packedState |= uint256(state.closeData) << _CLOSE_DATA_OFFSET;
    }

    function _isFinalized(uint32 closeData) internal pure returns (bool) {
        return closeData == _FINALIZED_CLOSE_DATA;
    }

    function _closeRequestedAt(uint32 closeData) internal pure returns (uint32) {
        return closeData >= 2 ? closeData : 0;
    }

    function _isExpired(uint32 expiresAt) internal view returns (bool) {
        return block.timestamp >= expiresAt;
    }

    function _validateVoucher(
        ChannelDescriptor calldata descriptor,
        bytes32 channelId,
        uint96 cumulativeAmount,
        bytes calldata signature
    )
        internal
        view
    {
        bytes32 structHash = keccak256(abi.encode(VOUCHER_TYPEHASH, channelId, cumulativeAmount));
        bytes32 digest = _hashTypedData(structHash);
        address expectedSigner = descriptor.authorizedSigner != address(0)
            ? descriptor.authorizedSigner
            : descriptor.payer;

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
