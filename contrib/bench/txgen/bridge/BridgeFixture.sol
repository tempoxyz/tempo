// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

interface ITIP20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @notice Local execution benchmark only: a minimal bridge. Operators pay bridged
/// funds out with `withdrawV2`, and users bridge funds in with `depositWithId`.
/// Restricted to chain 1337; never hold real funds.
contract BridgeFixture {
    mapping(address => bool) public operators;

    event BridgedWithdrawal(address token, address recipient, uint256 amount);
    event BridgedDeposit(address user, address token, uint256 amount, bytes32 commitmentId);

    constructor() {
        require(block.chainid == 1337, "benchmark chain only");
        operators[msg.sender] = true;
    }

    function setOperator(address operator) external {
        require(operators[msg.sender], "not operator");
        operators[operator] = true;
    }

    function withdrawV2(address token, address recipient, uint256 amount) external {
        require(operators[msg.sender], "not operator");
        require(ITIP20(token).transfer(recipient, amount), "transfer failed");
        emit BridgedWithdrawal(token, recipient, amount);
    }

    function depositWithId(address token, uint256 amount, bytes32 commitmentId) external {
        require(ITIP20(token).transferFrom(msg.sender, address(this), amount), "transfer failed");
        emit BridgedDeposit(msg.sender, token, amount, commitmentId);
    }
}
