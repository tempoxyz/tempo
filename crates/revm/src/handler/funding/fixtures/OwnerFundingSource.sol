// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

interface Token {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

// Compile deployed bytecode with solc 0.8.30, optimizer runs=200, evmVersion=cancun.
contract OwnerFundingSource {
    address constant FUNDER = 0xFfFfFFfFfFffffFFFffFfFFfFFFfFffFffff1120;
    struct Quote { address assetIn; uint256 rate; uint256 maxAmountIn; uint256 amountOut; bytes executionData; }
    struct Request {
        address assetIn;
        uint256 rate;
        uint256 cap;
        uint256 debit;
        uint256 deliver;
        uint256 expectedCost;
        uint256 mode;
    }
    uint256 public calls;

    function quote(address, address, uint256 amountOut, uint256 maxCost, bytes calldata data, bytes calldata configData, bool ownerAuthorized)
        external returns (Quote memory)
    {
        require(ownerAuthorized && configData.length == 0, "context");
        Request memory r = abi.decode(data, (Request));
        require(r.expectedCost == 0 || r.expectedCost == maxCost, "cost");
        if (r.mode == 8) assembly { return(0, 1) }
        if (r.mode == 9) calls++;
        uint256 cap = r.cap;
        if (r.rate != 0 && r.mode != 7) {
            uint256 capacity = maxCost * 1e18 / r.rate;
            if (cap > capacity) cap = capacity;
        }
        return Quote(r.assetIn, r.rate, cap, r.mode == 10 ? amountOut + 1 : (r.deliver < amountOut ? r.deliver : amountOut), r.mode == 11 ? bytes("") : data);
    }

    function fund(address account, address assetOut, uint256 amountOut, bytes calldata data) external {
        require(msg.sender == FUNDER && tx.origin == account, "context");
        Request memory r = abi.decode(data, (Request));
        calls++;
        if (r.mode == 1) revert("source failure");
        if (r.debit != 0) Token(r.assetIn).transferFrom(account, address(this), r.debit);
        uint256 deliver = r.deliver;
        if (deliver > amountOut && r.mode != 3) deliver = amountOut;
        if (deliver != 0 && r.mode != 2) Token(assetOut).transfer(account, deliver);
    }

    function application() external pure { revert("application failure"); }
    function steal(address token, address account) external {
        Token(token).transferFrom(account, address(this), 1);
    }
}
