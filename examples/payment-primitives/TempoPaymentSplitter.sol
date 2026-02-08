// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

/**
 * @title TempoPaymentSplitter
 * @notice A contract for splitting TIP-20 payments to multiple recipients
 * @dev Optimized for Tempo Network with batch distribution and memo support
 */
contract TempoPaymentSplitter {
    // Events
    event PayeeAdded(address indexed payee, uint256 shares);
    event PayeeRemoved(address indexed payee);
    event PayeeSharesUpdated(address indexed payee, uint256 oldShares, uint256 newShares);
    event PaymentReceived(address indexed token, address indexed from, uint256 amount, string memo);
    event PaymentDistributed(address indexed token, address indexed payee, uint256 amount, string memo);
    event BatchDistribution(address indexed token, uint256 totalAmount, uint256 payeeCount, string memo);
    event SplitCreated(uint256 indexed splitId, address creator, uint256 totalShares);
    
    // Structs
    struct Payee {
        address wallet;
        uint256 shares;
        uint256 totalReceived;
        bool active;
    }
    
    struct Split {
        uint256 id;
        address creator;
        uint256 totalShares;
        uint256 totalDistributed;
        uint256 createdAt;
        bool active;
        address[] payeeAddresses;
    }
    
    // State variables
    address public owner;
    uint256 public splitCounter;
    
    // Mappings
    mapping(uint256 => Split) public splits;
    mapping(uint256 => mapping(address => Payee)) public splitPayees;
    mapping(address => uint256[]) public userSplits;
    
    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    modifier splitExists(uint256 splitId) {
        require(splits[splitId].createdAt > 0, "Split does not exist");
        _;
    }
    
    modifier splitActive(uint256 splitId) {
        require(splits[splitId].active, "Split is not active");
        _;
    }
    
    constructor() {
        owner = msg.sender;
    }
    
    /**
     * @notice Create a new payment split configuration
     */
    function createSplit(
        address[] calldata payees,
        uint256[] calldata shares
    ) external returns (uint256 splitId) {
        require(payees.length > 0, "At least one payee required");
        require(payees.length == shares.length, "Arrays length mismatch");
        require(payees.length <= 50, "Too many payees");
        
        splitId = ++splitCounter;
        
        Split storage newSplit = splits[splitId];
        newSplit.id = splitId;
        newSplit.creator = msg.sender;
        newSplit.createdAt = block.timestamp;
        newSplit.active = true;
        
        uint256 totalShares = 0;
        for (uint256 i = 0; i < payees.length; i++) {
            require(payees[i] != address(0), "Invalid payee address");
            require(shares[i] > 0, "Shares must be > 0");
            require(!splitPayees[splitId][payees[i]].active, "Duplicate payee");
            
            splitPayees[splitId][payees[i]] = Payee({
                wallet: payees[i],
                shares: shares[i],
                totalReceived: 0,
                active: true
            });
            
            newSplit.payeeAddresses.push(payees[i]);
            totalShares += shares[i];
            
            emit PayeeAdded(payees[i], shares[i]);
        }
        
        newSplit.totalShares = totalShares;
        userSplits[msg.sender].push(splitId);
        
        emit SplitCreated(splitId, msg.sender, totalShares);
        return splitId;
    }
    
    /**
     * @notice Add a new payee to an existing split
     */
    function addPayee(
        uint256 splitId,
        address payee,
        uint256 shares
    ) external splitExists(splitId) splitActive(splitId) {
        require(msg.sender == splits[splitId].creator, "Not split creator");
        require(payee != address(0), "Invalid payee");
        require(shares > 0, "Shares must be > 0");
        require(!splitPayees[splitId][payee].active, "Payee exists");
        
        splitPayees[splitId][payee] = Payee({
            wallet: payee,
            shares: shares,
            totalReceived: 0,
            active: true
        });
        
        splits[splitId].payeeAddresses.push(payee);
        splits[splitId].totalShares += shares;
        
        emit PayeeAdded(payee, shares);
    }
    
    /**
     * @notice Remove a payee from a split
     */
    function removePayee(
        uint256 splitId,
        address payee
    ) external splitExists(splitId) splitActive(splitId) {
        require(msg.sender == splits[splitId].creator, "Not split creator");
        require(splitPayees[splitId][payee].active, "Payee not active");
        
        uint256 payeeShares = splitPayees[splitId][payee].shares;
        splitPayees[splitId][payee].active = false;
        splits[splitId].totalShares -= payeeShares;
        
        emit PayeeRemoved(payee);
    }
    
    /**
     * @notice Update shares for a payee
     */
    function updatePayeeShares(
        uint256 splitId,
        address payee,
        uint256 newShares
    ) external splitExists(splitId) splitActive(splitId) {
        require(msg.sender == splits[splitId].creator, "Not split creator");
        require(splitPayees[splitId][payee].active, "Payee not active");
        require(newShares > 0, "Shares must be > 0");
        
        uint256 oldShares = splitPayees[splitId][payee].shares;
        splits[splitId].totalShares = splits[splitId].totalShares - oldShares + newShares;
        splitPayees[splitId][payee].shares = newShares;
        
        emit PayeeSharesUpdated(payee, oldShares, newShares);
    }
    
    /**
     * @notice Distribute TIP-20 token payment to all active payees in a split
     * @param token The TIP-20 token address
     * @param splitId The split to distribute to
     * @param amount The total amount to distribute
     * @param memo A memo/note for the distribution (Tempo-style)
     */
    function distribute(
        address token,
        uint256 splitId,
        uint256 amount,
        string calldata memo
    ) external splitExists(splitId) splitActive(splitId) {
        require(amount > 0, "Amount must be > 0");
        
        Split storage split = splits[splitId];
        require(split.totalShares > 0, "No active payees");
        
        // Transfer tokens to this contract first
        require(IERC20(token).transferFrom(msg.sender, address(this), amount), "Transfer failed");
        
        emit PaymentReceived(token, msg.sender, amount, memo);
        
        uint256 distributed = 0;
        uint256 activePayeeCount = 0;
        
        for (uint256 i = 0; i < split.payeeAddresses.length; i++) {
            address payeeAddr = split.payeeAddresses[i];
            Payee storage payee = splitPayees[splitId][payeeAddr];
            
            if (payee.active) {
                uint256 payment = (amount * payee.shares) / split.totalShares;
                
                // Handle dust by giving it to last active payee
                if (i == split.payeeAddresses.length - 1) {
                    payment = amount - distributed;
                }
                
                if (payment > 0) {
                    require(IERC20(token).transfer(payee.wallet, payment), "Transfer failed");
                    payee.totalReceived += payment;
                    distributed += payment;
                    activePayeeCount++;
                    
                    emit PaymentDistributed(token, payeeAddr, payment, memo);
                }
            }
        }
        
        split.totalDistributed += distributed;
        
        emit BatchDistribution(token, amount, activePayeeCount, memo);
    }
    
    /**
     * @notice Direct single-payee TIP-20 payment with memo (Tempo optimized)
     */
    function sendWithMemo(
        address token,
        address recipient,
        uint256 amount,
        string calldata memo
    ) external {
        require(amount > 0, "Amount must be > 0");
        require(recipient != address(0), "Invalid recipient");
        
        require(IERC20(token).transferFrom(msg.sender, recipient, amount), "Transfer failed");
        
        emit PaymentDistributed(token, recipient, amount, memo);
    }
    
    /**
     * @notice Batch TIP-20 payment to multiple recipients (Tempo batch transaction style)
     */
    function batchPayment(
        address token,
        address[] calldata recipients,
        uint256[] calldata amounts,
        string calldata memo
    ) external {
        require(recipients.length == amounts.length, "Arrays length mismatch");
        require(recipients.length > 0, "Empty recipients");
        require(recipients.length <= 100, "Too many recipients");
        
        uint256 totalRequired = 0;
        for (uint256 i = 0; i < amounts.length; i++) {
            totalRequired += amounts[i];
        }
        
        require(IERC20(token).transferFrom(msg.sender, address(this), totalRequired), "Transfer failed");
        
        emit PaymentReceived(token, msg.sender, totalRequired, memo);
        
        for (uint256 i = 0; i < recipients.length; i++) {
            require(recipients[i] != address(0), "Invalid recipient");
            if (amounts[i] > 0) {
                require(IERC20(token).transfer(recipients[i], amounts[i]), "Transfer failed");
                emit PaymentDistributed(token, recipients[i], amounts[i], memo);
            }
        }
        
        emit BatchDistribution(token, totalRequired, recipients.length, memo);
    }
    
    /**
     * @notice Deactivate a split
     */
    function deactivateSplit(uint256 splitId) external splitExists(splitId) {
        require(msg.sender == splits[splitId].creator, "Not split creator");
        splits[splitId].active = false;
    }
    
    /**
     * @notice Get split details
     */
    function getSplit(uint256 splitId) external view returns (
        address creator,
        uint256 totalShares,
        uint256 totalDistributed,
        uint256 payeeCount,
        bool active
    ) {
        Split storage split = splits[splitId];
        return (
            split.creator,
            split.totalShares,
            split.totalDistributed,
            split.payeeAddresses.length,
            split.active
        );
    }
    
    /**
     * @notice Get payee details in a split
     */
    function getPayeeInfo(
        uint256 splitId,
        address payee
    ) external view returns (
        uint256 shares,
        uint256 totalReceived,
        bool active
    ) {
        Payee storage p = splitPayees[splitId][payee];
        return (p.shares, p.totalReceived, p.active);
    }
    
    /**
     * @notice Get all splits created by a user
     */
    function getUserSplits(address user) external view returns (uint256[] memory) {
        return userSplits[user];
    }
}
