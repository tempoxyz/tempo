// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { IWithdrawalReceiver } from "../../src/runtime/interfaces/IZone.sol";

// Withdrawal callback response word that `ZoneMessenger` accepts.
bytes32 constant ACCEPTED_CALLBACK_WORD =
    bytes32(IWithdrawalReceiver.onWithdrawalReceived.selector);

// Accepted selector with dirty low-order padding, which the ABI decoder must reject.
bytes32 constant DIRTY_PADDED_CALLBACK_WORD =
    ACCEPTED_CALLBACK_WORD | (bytes32(type(uint256).max) >> 32);

/// @notice Callback receiver that reverts with `size` bytes of revert data.
/// @dev The blob costs only this frame's memory expansion, charged against the forwarded gas. A
///      caller that propagates the revert copies the whole blob at quadratic cost — the
///      amplification this models.
contract MockRevertingReceiver is IWithdrawalReceiver {

    uint256 internal immutable _size;

    constructor(uint256 size) {
        _size = size;
    }

    function onWithdrawalReceived(
        uint32,
        address,
        bytes32,
        address,
        uint128,
        bytes calldata
    )
        external
        view
        returns (bytes4)
    {
        uint256 size = _size;
        assembly {
            revert(0, size)
        }
    }

}

/// @notice Callback receiver that returns `word` followed by padding out to `size` bytes.
/// @dev Pins an exact response shape: `size` under 32 is a short return, over 32 an overlong one.
///      The second word is deliberately dirty, so an overlong response proves trailing junk is
///      ignored rather than merely tolerated when zeroed.
contract MockRawReturnReceiver is IWithdrawalReceiver {

    bytes32 internal immutable _word;
    uint256 internal immutable _size;

    constructor(bytes32 word, uint256 size) {
        _word = word;
        _size = size;
    }

    function onWithdrawalReceived(
        uint32,
        address,
        bytes32,
        address,
        uint128,
        bytes calldata
    )
        external
        view
        returns (bytes4)
    {
        bytes32 word = _word;
        uint256 size = _size;
        assembly {
            mstore(0, word)
            mstore(32, not(0))
            return(0, size)
        }
    }

}
