// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title TempoTab - The "Invisible Payment" Protocol
/// @notice Allows users to authorize merchants to "pull" funds up to a periodic limit.
/// @dev Implements "Auth/Capture" logic with auto-resetting limits (e.g., Daily/Weekly allowances).
contract TempoTab {

    struct Tab {
        uint256 limit;          // Max amount per period (e.g., 50 USD)
        uint256 period;         // Reset period in seconds (e.g., 86400 for daily)
        uint256 currentUsage;   // Amount spent in current period
        uint256 lastReset;      // Timestamp of last reset
        bool active;
    }

    // Mapping: User Address => Merchant Address => Tab Details
    mapping(address => mapping(address => Tab)) public tabs;

    event TabOpened(address indexed user, address indexed merchant, uint256 limit, uint256 period);
    event TabCharged(address indexed user, address indexed merchant, uint256 amount);
    event TabClosed(address indexed user, address indexed merchant);

    /// @notice User opens a tab for a specific merchant.
    /// @param _merchant The shop/app allowed to pull funds.
    /// @param _limit The max amount they can take per period.
    /// @param _period How often the limit resets (in seconds).
    function openTab(address _merchant, uint256 _limit, uint256 _period) external payable {
        require(msg.value >= _limit, "Initial deposit must cover the limit");
        
        tabs[msg.sender][_merchant] = Tab({
            limit: _limit,
            period: _period,
            currentUsage: 0,
            lastReset: block.timestamp,
            active: true
        });

        emit TabOpened(msg.sender, _merchant, _limit, _period);
    }

    /// @notice Merchant calls this to "pull" payment instantly. No user signature needed.
    function chargeTab(address _user, uint256 _amount) external {
        Tab storage t = tabs[_user][msg.sender];
        
        require(t.active, "Tab is not active");
        
        // Auto-Reset logic if period has passed
        if (block.timestamp >= t.lastReset + t.period) {
            t.currentUsage = 0;
            t.lastReset = block.timestamp;
        }

        require(t.currentUsage + _amount <= t.limit, "Daily limit exceeded");
        
        // Update state BEFORE transfer (Reentrancy protection)
        t.currentUsage += _amount;

        // Execute the "Pull"
        (bool sent, ) = msg.sender.call{value: _amount}("");
        require(sent, "Transfer failed");

        emit TabCharged(_user, msg.sender, _amount);
    }
}
