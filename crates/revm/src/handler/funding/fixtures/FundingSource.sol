// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

interface Token {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract FundingSource {
    struct Plan { address assetIn; uint256 rate; uint256 maxAmountIn; bytes data; }
    address constant FUNDER = address(type(uint160).max - 0xeedf);
    address constant ACCOUNT = address(0x2000);
    uint256 public calls;
    address public account;
    address public asset;
    uint256 public amount;
    bytes32 public payloadHash;
    event Funded(address sender, address account, uint256 amount);
    error SourceFailure(uint256 mode);

    // Intentionally non-view: mode 1 proves that the caller actually uses STATICCALL.
    function prepare(address assetOut, uint256 maxCost, bytes calldata data, bytes calldata policyData, bool ownerAuthorized)
        external returns (Plan memory)
    {
        require(msg.sender == FUNDER && tx.origin == ACCOUNT);
        require(ownerAuthorized && policyData.length == 0);
        uint256 mode = abi.decode(data, (uint256));
        if (mode == 1) calls++;
        if (mode == 2) revert SourceFailure(mode);
        if (mode == 3) assembly { return(0, 1) }
        return Plan(assetOut, 1e18, maxCost, abi.encode(mode, bytes32("prepared")));
    }

    function fund(address account_, address assetOut, uint256 amountOut, bytes calldata data) external {
        require(msg.sender == FUNDER && tx.origin == ACCOUNT);
        (uint256 mode, bytes32 marker) = abi.decode(data, (uint256, bytes32));
        require(marker == bytes32("prepared"));
        calls++;
        account = account_;
        asset = assetOut;
        amount = amountOut;
        payloadHash = keccak256(data);
        emit Funded(msg.sender, account_, amountOut);
        if (mode >= 10) {
            require(Token(assetOut).transferFrom(account_, address(this), 20));
            if (mode == 12) {
                (bool ok,) = address(this).call(abi.encodeCall(this.nestedInput, (account_, assetOut)));
                require(!ok);
            }
            if (mode == 13) require(Token(assetOut).transfer(account_, 20));
            require(Token(assetOut).transferFrom(account_, address(this), mode == 11 || mode == 13 ? 11 : 10));
        }
        if (mode == 8) amount = 0;
        if (mode == 4) revert SourceFailure(mode);
        if (mode == 5) { while (true) {} }
        if (mode == 6) {
            (bool ok,) = address(this).call(abi.encodeCall(this.nestedFailure, ()));
            require(!ok);
        }
        if (mode == 7) {
            (bool ok, bytes memory reason) = FUNDER.call("");
            require(ok && reason.length == 0);
            require(calls == 1);
        }
    }

    function nestedInput(address owner, address token) external {
        require(Token(token).transferFrom(owner, address(this), 5));
        revert SourceFailure(12);
    }

    function application() external {
        require(msg.sender == ACCOUNT && tx.origin == ACCOUNT);
        require(calls == 1 && account == ACCOUNT && amount == 50);
        revert SourceFailure(9);
    }

    function nestedFailure() external { calls = 999; revert SourceFailure(6); }
}
