// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

contract FundingSource {
    struct Quote { address assetIn; uint256 rate; uint256 maxAmountIn; uint256 amountOut; bytes data; }
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
    function quote(address account_, address assetOut, uint256 amountOut, uint256 maxCost, bytes calldata data, bytes calldata policyData, bool ownerAuthorized)
        external returns (Quote memory)
    {
        require(account_ == ACCOUNT);
        require(ownerAuthorized && policyData.length == 0);
        uint256 mode = abi.decode(data, (uint256));
        if (mode == 1) calls++;
        if (mode == 2) revert SourceFailure(mode);
        if (mode == 3) assembly { return(0, 1) }
        return Quote(assetOut, 1e18, maxCost, amountOut, abi.encode(mode, bytes32("prepared")));
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

    function application() external {
        require(msg.sender == ACCOUNT && tx.origin == ACCOUNT);
        require(calls == 1 && account == ACCOUNT && amount == 50);
        revert SourceFailure(9);
    }

    function nestedFailure() external { calls = 999; revert SourceFailure(6); }
}
