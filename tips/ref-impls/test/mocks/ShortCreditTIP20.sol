// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ShortCreditTIP20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    bool public shortCreditEnabled;

    function setShortCreditEnabled(bool enabled) external {
        shortCreditEnabled = enabled;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "INSUFFICIENT_BALANCE");

        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "INSUFFICIENT_BALANCE");
        require(allowance[from][msg.sender] >= amount, "INSUFFICIENT_ALLOWANCE");

        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;

        uint256 credited = shortCreditEnabled && amount > 0 ? amount - 1 : amount;
        balanceOf[to] += credited;

        return true;
    }
}
