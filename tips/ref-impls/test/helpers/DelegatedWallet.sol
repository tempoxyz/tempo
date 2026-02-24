// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

/// @title DelegatedWallet - Minimal wallet implementation for EIP-7702 delegation testing
/// @notice Used as a delegation target to verify that accounts with delegated code
///         behave correctly across all transaction types and precompile interactions
/// @dev Intentionally minimal: only needs to exist as valid code at the delegated address.
///      When an EOA delegates to this contract via EIP-7702, calls to the EOA will execute
///      this code. The `execute` function allows forwarding arbitrary calls.
contract DelegatedWallet {

    /// @notice Execute a single call from this wallet
    /// @param to Target address
    /// @param value ETH value to send
    /// @param data Calldata to forward
    /// @return result The return data from the call
    function execute(
        address to,
        uint256 value,
        bytes calldata data
    )
        external
        payable
        returns (bytes memory result)
    {
        bool success;
        (success, result) = to.call{ value: value }(data);
        if (!success) {
            assembly {
                revert(add(result, 0x20), mload(result))
            }
        }
    }

    /// @notice Execute a batch of calls from this wallet
    /// @param targets Target addresses
    /// @param values ETH values to send
    /// @param datas Calldatas to forward
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas
    )
        external
        payable
    {
        for (uint256 i = 0; i < targets.length; i++) {
            (bool success, bytes memory result) = targets[i].call{ value: values[i] }(datas[i]);
            if (!success) {
                assembly {
                    revert(add(result, 0x20), mload(result))
                }
            }
        }
    }

    /// @notice Allow receiving ETH
    receive() external payable { }

}
