// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

/// @title TIP-1022 virtual address registry interface
/// @notice Registers master addresses and resolves virtual TIP-20 recipients to their masters
interface IAddressRegistry {

    /// @notice Emitted when a new virtual master is registered.
    event MasterRegistered(bytes4 indexed masterId, address indexed masterAddress);

    /// @notice The derived `masterId` is already registered.
    error MasterIdCollision(address master);

    /// @notice The caller is not a valid virtual-address master.
    error InvalidMasterAddress();

    /// @notice The registration hash does not satisfy the required 32-bit proof of work.
    error ProofOfWorkFailed();

    /// @notice The target address matches the virtual format but its master has not been registered.
    error VirtualAddressUnregistered();

    /// @notice Registers `msg.sender` as a virtual-address master.
    function registerVirtualMaster(bytes32 salt) external returns (bytes4 masterId);

    /// @notice Returns the registered master for `masterId`, or `address(0)` if it is unregistered.
    function getMaster(bytes4 masterId) external view returns (address);

    /// @notice Resolves `to` under TIP-1022 rules.
    function resolveRecipient(address to) external view returns (address effectiveRecipient);

    /// @notice Resolves a virtual address to its registered master.
    function resolveVirtualAddress(address virtualAddr) external view returns (address master);

    /// @notice Returns `true` when `addr` matches the TIP-1022 virtual address layout.
    function isVirtualAddress(address addr) external pure returns (bool);

    /// @notice Decodes a virtual address into its components.
    function decodeVirtualAddress(address addr)
        external
        pure
        returns (bool isVirtual, bytes4 masterId, bytes6 userTag);

}
