// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title TempoKey - The "Smart Lease" Protocol
/// @notice A Pay-As-You-Go access control system for Real Estate & IoT.
/// @dev Connects a token balance to a time-based decay function. Money = Time.
contract TempoKey {

    struct Key {
        uint256 balance;        // Remaining rent prepaid
        uint256 ratePerSecond;  // Cost of the lease (e.g., 0.0001 ETH/sec)
        uint256 lastUpdate;     // Last time we calculated usage
        bool isActive;
    }

    mapping(address => Key) public keys;

    event AccessGranted(address indexed tenant, uint256 rate);
    event AccessRevoked(address indexed tenant);
    event TopUp(address indexed tenant, uint256 amount);

    /// @notice Start a lease.
    /// @param _ratePerSecond The price of rent (set by contract or dynamic).
    function startLease(uint256 _ratePerSecond) external payable {
        require(msg.value > 0, "No deposit provided");
        
        keys[msg.sender] = Key({
            balance: msg.value,
            ratePerSecond: _ratePerSecond,
            lastUpdate: block.timestamp,
            isActive: true
        });

        emit AccessGranted(msg.sender, _ratePerSecond);
    }

    /// @notice Add funds to extend the stay.
    function topUp() external payable {
        _burn(msg.sender); // Settle previous debt first
        require(keys[msg.sender].isActive, "No active lease");
        keys[msg.sender].balance += msg.value;
        emit TopUp(msg.sender, msg.value);
    }

    /// @notice The "IoT Lock" calls this to see if the door should open.
    /// @dev View function: Does not cost gas to check.
    function hasAccess(address _tenant) public view returns (bool) {
        Key memory k = keys[_tenant];
        if (!k.isActive) return false;
        
        uint256 timeElapsed = block.timestamp - k.lastUpdate;
        uint256 cost = timeElapsed * k.ratePerSecond;

        return k.balance >= cost;
    }

    /// @notice Internal helper to update balance ("Burn" the rent money).
    function _burn(address _tenant) internal {
        Key storage k = keys[_tenant];
        if (!k.isActive) return;

        uint256 timeElapsed = block.timestamp - k.lastUpdate;
        uint256 cost = timeElapsed * k.ratePerSecond;

        if (cost >= k.balance) {
            k.balance = 0;
            k.isActive = false; // EVICTION
            emit AccessRevoked(_tenant);
        } else {
            k.balance -= cost;
            k.lastUpdate = block.timestamp;
        }
    }
}
