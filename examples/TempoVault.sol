// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title TempoVault - The "Dead Man's Switch" Protocol
/// @notice A trustless asset recovery system.
/// @dev Funds are locked until the owner fails to "ping" for a set duration (e.g., 30 days).
contract TempoVault {
    struct Vault {
        uint256 balance;
        address beneficiary;    // Who gets the money if I disappear?
        uint256 lastHeartbeat;  // The last time I said "I am alive"
        uint256 timeThreshold;  // How long to wait (e.g., 30 days)
    }

    mapping(address => Vault) public vaults;

    event Heartbeat(address indexed owner, uint256 timestamp);
    event VaultClaimed(address indexed owner, address indexed beneficiary, uint256 amount);

    /// @notice Create a vault. You must ping it before _timeThreshold passes.
    function createVault(address _beneficiary, uint256 _timeThreshold) external payable {
        vaults[msg.sender] = Vault({
            balance: msg.value,
            beneficiary: _beneficiary,
            lastHeartbeat: block.timestamp,
            timeThreshold: _timeThreshold
        });
        emit Heartbeat(msg.sender, block.timestamp);
    }

    /// @notice "I am alive." Resets the countdown.
    function ping() external {
        Vault storage v = vaults[msg.sender];
        require(v.balance > 0, "No vault exists");
        v.lastHeartbeat = block.timestamp;
        emit Heartbeat(msg.sender, block.timestamp);
    }

    /// @notice The Beneficiary calls this if the Owner has been silent too long.
    function claim(address _owner) external {
        Vault storage v = vaults[_owner];
        require(msg.sender == v.beneficiary, "Not the beneficiary");
        require(block.timestamp > v.lastHeartbeat + v.timeThreshold, "Owner is still active");
        
        uint256 amount = v.balance;
        v.balance = 0;

        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "Transfer failed");

        emit VaultClaimed(_owner, msg.sender, amount);
    }
}
