// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {
    IWithdrawalReceiver,
    IZoneFactory,
    IZoneMessenger,
    ZoneInfo
} from "../interfaces/IZone.sol";
import { ITIP20 } from "tempo-std/interfaces/ITIP20.sol";

/// @title ZoneMessenger
/// @notice Shared withdrawal callback sender for all zones created by one ZoneFactory.
contract ZoneMessenger is IZoneMessenger {

    IZoneFactory public immutable zoneFactory;

    uint256 internal _relayReentrancyStatus;

    error UnauthorizedPortal();
    error TransferFailed();
    error CallbackRejected();
    error ReentrantRelay();

    constructor(address _zoneFactory) {
        zoneFactory = IZoneFactory(_zoneFactory);
    }

    modifier nonReentrantRelay() {
        if (_relayReentrancyStatus != 0) revert ReentrantRelay();
        _relayReentrancyStatus = 1;
        _;
        _relayReentrancyStatus = 0;
    }

    function relayMessage(
        uint32 zoneId,
        address token,
        bytes32 senderTag,
        address target,
        uint128 amount,
        uint64 gasLimit,
        bytes calldata data
    )
        external
        nonReentrantRelay
    {
        ZoneInfo memory zone = zoneFactory.zones(zoneId);
        if (zone.portal != msg.sender) revert UnauthorizedPortal();

        if (!ITIP20(token).transfer(target, amount)) {
            revert TransferFailed();
        }

        bytes4 selector = IWithdrawalReceiver(target).onWithdrawalReceived{ gas: gasLimit }(
            zoneId, msg.sender, senderTag, token, amount, data
        );

        if (selector != IWithdrawalReceiver.onWithdrawalReceived.selector) {
            revert CallbackRejected();
        }
    }

}
