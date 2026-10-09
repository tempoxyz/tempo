// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { IZoneToken } from "../../src/runtime/interfaces/IZone.sol";

/// @title MockZoneToken
/// @notice Mock TIP-20 for zone testing with mint/burn for system operations
/// @dev In production, this would be the actual TIP-20 at the same address as L1
contract MockZoneToken is IZoneToken {

    string public name;
    string public symbol;
    string public currency;
    uint8 public constant decimals = 6;
    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    /// @notice Transfer policy ID (1 = always-allow, matches TIP-20 default)
    uint64 public transferPolicyId = 1;

    /// @notice Addresses authorized to mint (ZoneInbox)
    mapping(address => bool) public minters;

    /// @notice Addresses authorized to burn (ZoneOutbox)
    mapping(address => bool) public burners;

    address public admin;

    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);

    error Unauthorized();
    error InsufficientBalance();
    error InsufficientAllowance();

    constructor(string memory _name, string memory _symbol) {
        name = _name;
        symbol = _symbol;
        currency = "USD";
        admin = msg.sender;
    }

    function initialize(
        address _admin,
        string calldata _name,
        string calldata _symbol,
        string calldata _currency,
        address,
        address
    )
        external
    {
        admin = _admin;
        name = _name;
        symbol = _symbol;
        currency = _currency;
    }

    function grantRole(bytes32 role, address account) external {
        require(msg.sender == admin, "only admin");
        require(role == ISSUER_ROLE, "unsupported role");
        minters[account] = true;
    }

    function setMinter(address minter, bool authorized) external {
        require(msg.sender == admin, "only admin");
        minters[minter] = authorized;
    }

    function setBurner(address burner, bool authorized) external {
        require(msg.sender == admin, "only admin");
        burners[burner] = authorized;
    }

    function mint(address to, uint256 amount) external {
        if (!minters[msg.sender]) revert Unauthorized();
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function burn(uint256 amount) external {
        if (balanceOf[msg.sender] < amount) revert InsufficientBalance();
        totalSupply -= amount;
        balanceOf[msg.sender] -= amount;
        emit Transfer(msg.sender, address(0), amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        if (balanceOf[msg.sender] < amount) revert InsufficientBalance();
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        if (balanceOf[from] < amount) revert InsufficientBalance();
        if (allowance[from][msg.sender] < amount) revert InsufficientAllowance();

        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }

}
