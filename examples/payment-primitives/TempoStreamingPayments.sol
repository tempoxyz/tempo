// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/**
 * @title TempoStreamingPayments
 * @notice Continuous TIP-20 payment streams for Tempo Network (Sablier-style)
 * @dev Supports creating, withdrawing from, and canceling payment streams
 */
contract TempoStreamingPayments {
    // Events
    event StreamCreated(
        uint256 indexed streamId,
        address indexed token,
        address indexed sender,
        address recipient,
        uint256 deposit,
        uint256 startTime,
        uint256 stopTime,
        string memo
    );
    event WithdrawFromStream(
        uint256 indexed streamId,
        address indexed recipient,
        uint256 amount
    );
    event StreamCanceled(
        uint256 indexed streamId,
        address indexed sender,
        address indexed recipient,
        uint256 senderBalance,
        uint256 recipientBalance
    );
    event StreamTopUp(
        uint256 indexed streamId,
        address indexed sender,
        uint256 amount
    );
    event StreamExtended(
        uint256 indexed streamId,
        uint256 newStopTime
    );
    
    // Structs
    struct Stream {
        uint256 id;
        address token;
        address sender;
        address recipient;
        uint256 deposit;
        uint256 ratePerSecond;
        uint256 remainingBalance;
        uint256 startTime;
        uint256 stopTime;
        uint256 lastWithdrawTime;
        uint256 withdrawn;
        bool active;
        string memo;
    }
    
    // State variables
    uint256 public streamCounter;
    address public owner;
    
    // Mappings
    mapping(uint256 => Stream) public streams;
    mapping(address => uint256[]) public senderStreams;
    mapping(address => uint256[]) public recipientStreams;
    
    // Modifiers
    modifier streamExists(uint256 streamId) {
        require(streams[streamId].deposit > 0, "Stream does not exist");
        _;
    }
    
    modifier onlySenderOrRecipient(uint256 streamId) {
        require(
            msg.sender == streams[streamId].sender || 
            msg.sender == streams[streamId].recipient,
            "Not sender or recipient"
        );
        _;
    }
    
    constructor() {
        owner = msg.sender;
    }
    
    /**
     * @notice Create a new TIP-20 payment stream
     * @param token The TIP-20 token address
     * @param recipient The recipient of the stream
     * @param deposit The amount to deposit
     * @param startTime When the stream starts (0 for now)
     * @param stopTime When the stream ends
     * @param memo A memo for the stream (Tempo-style)
     * @return streamId The ID of the created stream
     */
    function createStream(
        address token,
        address recipient,
        uint256 deposit,
        uint256 startTime,
        uint256 stopTime,
        string calldata memo
    ) external returns (uint256 streamId) {
        require(token != address(0), "Invalid token");
        require(recipient != address(0), "Invalid recipient");
        require(recipient != msg.sender, "Cannot stream to self");
        require(deposit > 0, "Deposit required");
        
        if (startTime == 0) {
            startTime = block.timestamp;
        }
        require(startTime >= block.timestamp, "Start time in past");
        require(stopTime > startTime, "Stop time must be after start");
        
        uint256 duration = stopTime - startTime;
        require(deposit >= duration, "Deposit too small for duration");
        
        uint256 ratePerSecond = deposit / duration;
        require(ratePerSecond > 0, "Rate must be > 0");
        
        // Adjust deposit to be divisible by duration for clean math
        uint256 actualDeposit = ratePerSecond * duration;
        
        // Transfer tokens to this contract
        require(IERC20(token).transferFrom(msg.sender, address(this), actualDeposit), "Transfer failed");
        
        streamId = ++streamCounter;
        
        streams[streamId] = Stream({
            id: streamId,
            token: token,
            sender: msg.sender,
            recipient: recipient,
            deposit: actualDeposit,
            ratePerSecond: ratePerSecond,
            remainingBalance: actualDeposit,
            startTime: startTime,
            stopTime: stopTime,
            lastWithdrawTime: startTime,
            withdrawn: 0,
            active: true,
            memo: memo
        });
        
        senderStreams[msg.sender].push(streamId);
        recipientStreams[recipient].push(streamId);
        
        emit StreamCreated(
            streamId,
            token,
            msg.sender,
            recipient,
            actualDeposit,
            startTime,
            stopTime,
            memo
        );
        
        return streamId;
    }
    
    /**
     * @notice Create multiple streams at once (batch operation)
     */
    function createBatchStreams(
        address token,
        address[] calldata recipients,
        uint256[] calldata amounts,
        uint256[] calldata durations,
        string calldata memo
    ) external returns (uint256[] memory streamIds) {
        require(recipients.length == amounts.length, "Arrays mismatch");
        require(recipients.length == durations.length, "Arrays mismatch");
        require(recipients.length > 0 && recipients.length <= 20, "Invalid count");
        
        uint256 totalRequired = 0;
        for (uint256 i = 0; i < amounts.length; i++) {
            totalRequired += amounts[i];
        }
        
        require(IERC20(token).transferFrom(msg.sender, address(this), totalRequired), "Transfer failed");
        
        streamIds = new uint256[](recipients.length);
        
        for (uint256 i = 0; i < recipients.length; i++) {
            require(recipients[i] != address(0), "Invalid recipient");
            require(recipients[i] != msg.sender, "Cannot stream to self");
            require(amounts[i] > 0, "Amount required");
            require(durations[i] > 0, "Duration required");
            
            uint256 startTime = block.timestamp;
            uint256 stopTime = startTime + durations[i];
            uint256 ratePerSecond = amounts[i] / durations[i];
            require(ratePerSecond > 0, "Rate must be > 0");
            
            uint256 actualDeposit = ratePerSecond * durations[i];
            
            uint256 streamId = ++streamCounter;
            
            streams[streamId] = Stream({
                id: streamId,
                token: token,
                sender: msg.sender,
                recipient: recipients[i],
                deposit: actualDeposit,
                ratePerSecond: ratePerSecond,
                remainingBalance: actualDeposit,
                startTime: startTime,
                stopTime: stopTime,
                lastWithdrawTime: startTime,
                withdrawn: 0,
                active: true,
                memo: memo
            });
            
            senderStreams[msg.sender].push(streamId);
            recipientStreams[recipients[i]].push(streamId);
            
            streamIds[i] = streamId;
            
            emit StreamCreated(
                streamId,
                token,
                msg.sender,
                recipients[i],
                actualDeposit,
                startTime,
                stopTime,
                memo
            );
        }
        
        return streamIds;
    }
    
    /**
     * @notice Calculate how much has been streamed to the recipient
     */
    function balanceOf(uint256 streamId) public view streamExists(streamId) returns (uint256) {
        Stream storage stream = streams[streamId];
        
        if (!stream.active) {
            return 0;
        }
        
        if (block.timestamp <= stream.startTime) {
            return 0;
        }
        
        uint256 endTime = block.timestamp > stream.stopTime 
            ? stream.stopTime 
            : block.timestamp;
            
        uint256 elapsed = endTime - stream.lastWithdrawTime;
        uint256 streamed = elapsed * stream.ratePerSecond;
        
        return streamed > stream.remainingBalance 
            ? stream.remainingBalance 
            : streamed;
    }
    
    /**
     * @notice Withdraw from a stream (recipient only)
     */
    function withdrawFromStream(
        uint256 streamId,
        uint256 amount
    ) external streamExists(streamId) {
        Stream storage stream = streams[streamId];
        require(msg.sender == stream.recipient, "Not recipient");
        require(stream.active, "Stream not active");
        
        uint256 available = balanceOf(streamId);
        require(available > 0, "Nothing to withdraw");
        
        if (amount == 0 || amount > available) {
            amount = available;
        }
        
        stream.remainingBalance -= amount;
        stream.withdrawn += amount;
        stream.lastWithdrawTime = block.timestamp > stream.stopTime 
            ? stream.stopTime 
            : block.timestamp;
        
        require(IERC20(stream.token).transfer(stream.recipient, amount), "Transfer failed");
        
        emit WithdrawFromStream(streamId, stream.recipient, amount);
        
        // Deactivate if fully withdrawn
        if (stream.remainingBalance == 0) {
            stream.active = false;
        }
    }
    
    /**
     * @notice Cancel a stream and refund remaining balance
     */
    function cancelStream(uint256 streamId) 
        external 
        streamExists(streamId) 
        onlySenderOrRecipient(streamId) 
    {
        Stream storage stream = streams[streamId];
        require(stream.active, "Stream not active");
        
        uint256 recipientBalance = balanceOf(streamId);
        uint256 senderBalance = stream.remainingBalance - recipientBalance;
        
        stream.active = false;
        stream.remainingBalance = 0;
        
        // Pay recipient what they've earned
        if (recipientBalance > 0) {
            require(IERC20(stream.token).transfer(stream.recipient, recipientBalance), "Transfer failed");
        }
        
        // Refund sender the rest
        if (senderBalance > 0) {
            require(IERC20(stream.token).transfer(stream.sender, senderBalance), "Transfer failed");
        }
        
        emit StreamCanceled(
            streamId,
            stream.sender,
            stream.recipient,
            senderBalance,
            recipientBalance
        );
    }
    
    /**
     * @notice Top up an existing stream with more funds
     */
    function topUpStream(uint256 streamId, uint256 amount) 
        external 
        streamExists(streamId) 
    {
        Stream storage stream = streams[streamId];
        require(stream.active, "Stream not active");
        require(msg.sender == stream.sender, "Not sender");
        require(amount > 0, "Amount must be > 0");
        
        require(IERC20(stream.token).transferFrom(msg.sender, address(this), amount), "Transfer failed");
        
        stream.remainingBalance += amount;
        stream.deposit += amount;
        
        // Extend stop time proportionally
        uint256 additionalTime = amount / stream.ratePerSecond;
        stream.stopTime += additionalTime;
        
        emit StreamTopUp(streamId, msg.sender, amount);
        emit StreamExtended(streamId, stream.stopTime);
    }
    
    /**
     * @notice Get stream details
     */
    function getStream(uint256 streamId) external view returns (
        address token,
        address sender,
        address recipient,
        uint256 deposit,
        uint256 ratePerSecond,
        uint256 remainingBalance,
        uint256 startTime,
        uint256 stopTime,
        uint256 withdrawn,
        bool active
    ) {
        Stream storage stream = streams[streamId];
        return (
            stream.token,
            stream.sender,
            stream.recipient,
            stream.deposit,
            stream.ratePerSecond,
            stream.remainingBalance,
            stream.startTime,
            stream.stopTime,
            stream.withdrawn,
            stream.active
        );
    }
    
    /**
     * @notice Get all streams where user is sender
     */
    function getSenderStreams(address user) external view returns (uint256[] memory) {
        return senderStreams[user];
    }
    
    /**
     * @notice Get all streams where user is recipient
     */
    function getRecipientStreams(address user) external view returns (uint256[] memory) {
        return recipientStreams[user];
    }
    
    /**
     * @notice Get stream status info
     */
    function getStreamStatus(uint256 streamId) external view returns (
        bool isActive,
        uint256 percentComplete,
        uint256 withdrawable,
        uint256 totalStreamed
    ) {
        Stream storage stream = streams[streamId];
        
        if (stream.deposit == 0) {
            return (false, 0, 0, 0);
        }
        
        uint256 elapsed = 0;
        if (block.timestamp > stream.startTime) {
            uint256 endTime = block.timestamp > stream.stopTime 
                ? stream.stopTime 
                : block.timestamp;
            elapsed = endTime - stream.startTime;
        }
        
        uint256 duration = stream.stopTime - stream.startTime;
        percentComplete = (elapsed * 100) / duration;
        
        uint256 totalStreamed_ = elapsed * stream.ratePerSecond;
        if (totalStreamed_ > stream.deposit) {
            totalStreamed_ = stream.deposit;
        }
        
        return (
            stream.active,
            percentComplete,
            balanceOf(streamId),
            totalStreamed_
        );
    }
}
