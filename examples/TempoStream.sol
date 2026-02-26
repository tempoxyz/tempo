// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title TempoStream
/// @notice A real-time payment streaming protocol for the Tempo blockchain.
/// @dev Allows users to open salary/subscription streams that settle by the second.
///      Optimized for Tempo's high-throughput payment lanes.
contract TempoStream {
    
    // --- Events ---
    event StreamCreated(uint256 indexed streamId, address indexed sender, address indexed recipient, uint256 flowRate);
    event Withdraw(uint256 indexed streamId, address indexed recipient, uint256 amount);
    event StreamCancelled(uint256 indexed streamId, address indexed sender, address indexed recipient, uint256 recipientBalance, uint256 senderRefund);

    // --- Structs ---
    struct Stream {
        address sender;
        address recipient;
        uint256 deposit;        // Total funds locked
        uint256 flowRate;       // Wei per second
        uint256 startTime;      // Timestamp when stream started
        uint256 withdrawn;      // How much has been claimed so far
        bool active;
    }

    // --- State ---
    mapping(uint256 => Stream) public streams;
    uint256 public nextStreamId;

    // --- Core Logic ---

    /// @notice Opens a new continuous payment stream.
    /// @param _recipient Who gets the money.
    /// @param _flowRate How much to pay per second (in wei).
    function createStream(address _recipient, uint256 _flowRate) external payable {
        require(msg.value > 0, "Deposit required");
        require(_flowRate > 0, "Flow rate must be positive");
        require(_recipient != address(0), "Invalid recipient");

        uint256 streamId = nextStreamId;
        
        streams[streamId] = Stream({
            sender: msg.sender,
            recipient: _recipient,
            deposit: msg.value,
            flowRate: _flowRate,
            startTime: block.timestamp,
            withdrawn: 0,
            active: true
        });

        nextStreamId++;
        emit StreamCreated(streamId, msg.sender, _recipient, _flowRate);
    }

    /// @notice Calculates how much money the recipient has earned *right now*.
    /// @param _streamId The ID of the stream to check.
    function balanceOf(uint256 _streamId) public view returns (uint256 claimable) {
        Stream memory s = streams[_streamId];
        if (!s.active) return 0;

        uint256 duration = block.timestamp - s.startTime;
        uint256 totalEarned = duration * s.flowRate;

        // Cap at the total deposit (cannot earn more than locked)
        if (totalEarned > s.deposit) {
            totalEarned = s.deposit;
        }

        return totalEarned - s.withdrawn;
    }

    /// @notice The Recipient calls this to pull their earned cash.
    function withdraw(uint256 _streamId) external {
        Stream storage s = streams[_streamId];
        require(msg.sender == s.recipient, "Only recipient can withdraw");
        require(s.active, "Stream is inactive");

        uint256 amount = balanceOf(_streamId);
        require(amount > 0, "No funds available yet");

        s.withdrawn += amount;
        
        (bool sent, ) = s.recipient.call{value: amount}("");
        require(sent, "Transfer failed");

        emit Withdraw(_streamId, s.recipient, amount);
    }

    /// @notice The Sender can cancel the stream and get back unspent money.
    function cancelStream(uint256 _streamId) external {
        Stream storage s = streams[_streamId];
        require(msg.sender == s.sender, "Only sender can cancel");
        require(s.active, "Stream already inactive");

        uint256 recipientShare = balanceOf(_streamId);
        uint256 senderRefund = s.deposit - s.withdrawn - recipientShare;

        s.active = false;

        // Pay the recipient what they earned so far
        if (recipientShare > 0) {
            (bool sentRecipient, ) = s.recipient.call{value: recipientShare}("");
            require(sentRecipient, "Recipient transfer failed");
        }

        // Refund the rest to the sender
        if (senderRefund > 0) {
            (bool sentSender, ) = s.sender.call{value: senderRefund}("");
            require(sentSender, "Sender refund failed");
        }

        emit StreamCancelled(_streamId, s.sender, s.recipient, recipientShare, senderRefund);
    }
}
