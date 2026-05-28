// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ITempoStreamChannel} from "tempo-std/interfaces/ITempoStreamChannel.sol";
import {ITIP20} from "tempo-std/interfaces/ITIP20.sol";

/// @title LegacyTempoStreamChannel
/// @notice Legacy stream channel contract from the PaymentAuth session draft Appendix B.
contract LegacyTempoStreamChannel is ITempoStreamChannel {
    uint64 public constant CLOSE_GRACE_PERIOD = 15 minutes;
    bytes32 public constant VOUCHER_TYPEHASH = keccak256("Voucher(bytes32 channelId,uint128 cumulativeAmount)");
    bytes32 public constant CLOSE_REQUEST_TYPEHASH = keccak256("CloseRequest(bytes32 channelId,uint64 requestedAt)");

    bytes32 internal constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal constant _NAME_HASH = keccak256("TempoStreamChannel");
    bytes32 internal constant _VERSION_HASH = keccak256("1");

    mapping(bytes32 => Channel) public channels;

    function open(address payee, address token, uint128 deposit, bytes32 salt, address authorizedSigner)
        external
        returns (bytes32 channelId)
    {
        channelId = computeChannelId(msg.sender, payee, token, salt, authorizedSigner);
        if (channels[channelId].payer != address(0)) revert ChannelAlreadyExists();

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

        if (!ITIP20(token).transferFrom(msg.sender, address(this), deposit)) {
            revert TransferFailed();
        }
        emit ChannelOpened(channelId, msg.sender, payee, token, authorizedSigner, salt, deposit);
    }

    function settle(bytes32 channelId, uint128 cumulativeAmount, bytes calldata signature) external {
        Channel storage channel = _activeChannel(channelId);
        if (msg.sender != channel.payee) revert NotPayee();
        _settle(channelId, channel, cumulativeAmount, signature);
    }

    function topUp(bytes32 channelId, uint256 additionalDeposit) external {
        Channel storage channel = _activeChannel(channelId);
        if (msg.sender != channel.payer) revert NotPayer();

        channel.deposit += uint128(additionalDeposit);
        if (!ITIP20(channel.token).transferFrom(msg.sender, address(this), additionalDeposit)) {
            revert TransferFailed();
        }
        if (channel.closeRequestedAt != 0) {
            channel.closeRequestedAt = 0;
            emit CloseRequestCancelled(channelId, channel.payer, channel.payee);
        }
        emit TopUp(channelId, channel.payer, channel.payee, additionalDeposit, channel.deposit);
    }

    function close(bytes32 channelId, uint128 cumulativeAmount, bytes calldata signature) external {
        Channel storage channel = _activeChannel(channelId);
        if (msg.sender != channel.payee) revert NotPayee();
        _settle(channelId, channel, cumulativeAmount, signature);
        _finalize(channelId, channel);
    }

    function requestClose(bytes32 channelId) external {
        Channel storage channel = _activeChannel(channelId);
        if (msg.sender != channel.payer) revert NotPayer();
        if (channel.closeRequestedAt == 0) {
            channel.closeRequestedAt = uint64(block.timestamp);
            emit CloseRequested(channelId, channel.payer, channel.payee, block.timestamp + CLOSE_GRACE_PERIOD);
        }
    }

    function withdraw(bytes32 channelId) external {
        Channel storage channel = _activeChannel(channelId);
        if (msg.sender != channel.payer) revert NotPayer();
        if (channel.closeRequestedAt == 0 || block.timestamp < uint256(channel.closeRequestedAt) + CLOSE_GRACE_PERIOD) {
            revert CloseNotReady();
        }
        _finalize(channelId, channel);
    }

    function getChannel(bytes32 channelId) external view returns (Channel memory) {
        return channels[channelId];
    }

    function getChannelsBatch(bytes32[] calldata channelIds) external view returns (Channel[] memory channelStates) {
        channelStates = new Channel[](channelIds.length);
        for (uint256 i; i < channelIds.length; ++i) {
            channelStates[i] = channels[channelIds[i]];
        }
    }

    function computeChannelId(address payer, address payee, address token, bytes32 salt, address authorizedSigner)
        public
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(payer, payee, token, salt, authorizedSigner, address(this), block.chainid));
    }

    function getVoucherDigest(bytes32 channelId, uint128 cumulativeAmount) external view returns (bytes32) {
        return _hashTypedData(keccak256(abi.encode(VOUCHER_TYPEHASH, channelId, cumulativeAmount)));
    }

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparator();
    }

    function _settle(bytes32 channelId, Channel storage channel, uint128 cumulativeAmount, bytes calldata signature)
        internal
    {
        if (cumulativeAmount > channel.deposit) revert AmountExceedsDeposit();
        if (cumulativeAmount <= channel.settled) revert AmountNotIncreasing();
        _validateVoucher(channel, channelId, cumulativeAmount, signature);

        uint128 delta = cumulativeAmount - channel.settled;
        channel.settled = cumulativeAmount;
        if (!ITIP20(channel.token).transfer(channel.payee, delta)) revert TransferFailed();
        emit Settled(channelId, channel.payer, channel.payee, cumulativeAmount, delta, channel.settled);
    }

    function _finalize(bytes32 channelId, Channel storage channel) internal {
        uint128 refund = channel.deposit - channel.settled;
        channel.finalized = true;
        if (refund > 0 && !ITIP20(channel.token).transfer(channel.payer, refund)) {
            revert TransferFailed();
        }
        emit ChannelClosed(channelId, channel.payer, channel.payee, channel.settled, refund);
    }

    function _validateVoucher(
        Channel storage channel,
        bytes32 channelId,
        uint128 cumulativeAmount,
        bytes calldata signature
    ) internal view {
        bytes32 digest = _hashTypedData(keccak256(abi.encode(VOUCHER_TYPEHASH, channelId, cumulativeAmount)));
        address expectedSigner = channel.authorizedSigner != address(0) ? channel.authorizedSigner : channel.payer;
        (bytes32 r, bytes32 s, uint8 v) = _splitSignature(signature);
        address signer = ecrecover(digest, v, r, s);
        if (signer != expectedSigner) revert InvalidSignature();
    }

    function _activeChannel(bytes32 channelId) internal view returns (Channel storage channel) {
        channel = channels[channelId];
        if (channel.payer == address(0)) revert ChannelNotFound();
        if (channel.finalized) revert ChannelFinalized();
    }

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(_EIP712_DOMAIN_TYPEHASH, _NAME_HASH, _VERSION_HASH, block.chainid, address(this)));
    }

    function _hashTypedData(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
    }

    function _splitSignature(bytes calldata signature) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        if (signature.length != 65) revert InvalidSignature();
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v < 27) v += 27;
    }
}
