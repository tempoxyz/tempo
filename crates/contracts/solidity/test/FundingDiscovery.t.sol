// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {IFundingDiscovery} from "../src/IFundingDiscovery.sol";

interface IDiscoverySource {
    struct Candidate {
        bytes requestData;
        uint256 availableAmount;
    }

    function discover(
        address account,
        address assetOut,
        uint256 amountOut,
        uint256 maxCost,
        bytes calldata policyData
    ) external view returns (Candidate[] memory);
}

contract Source {
    address immutable account;
    address immutable token;
    uint256 immutable amount;
    uint256 immutable budget;
    bytes private candidates;
    error SourceFailure();

    constructor(
        address account_,
        address token_,
        uint256 amount_,
        uint256 budget_,
        IDiscoverySource.Candidate[] memory candidates_
    ) {
        account = account_;
        token = token_;
        amount = amount_;
        budget = budget_;
        candidates = abi.encode(candidates_);
    }

    function verify(bytes calldata requestData, bytes calldata policyData)
        external
        pure
        returns (bool)
    {
        return requestData.length > 0 && keccak256(policyData) == keccak256(hex"1122");
    }

    function discover(
        address account_,
        address token_,
        uint256 amount_,
        uint256 budget_,
        bytes calldata data
    ) external view returns (IDiscoverySource.Candidate[] memory) {
        require(msg.sender == address(0x1120000000000000000000000000000000000003));
        require(tx.origin == account);
        if (keccak256(data) == keccak256(hex"ff")) revert SourceFailure();
        require(account_ == account && token_ == token && amount_ == amount && budget_ == budget);
        require(keccak256(data) == keccak256(hex"1122"));
        return abi.decode(candidates, (IDiscoverySource.Candidate[]));
    }
}

contract DiscoveryCaller {
    fallback() external {
        (bool success, bytes memory result) =
            address(0x1120000000000000000000000000000000000003).staticcall(msg.data);
        assembly {
            switch success
            case 0 { revert(add(result, 32), mload(result)) }
            default { return(add(result, 32), mload(result)) }
        }
    }
}

contract RecursiveSource {
    bytes private rules;

    function setRules(bytes calldata value) external {
        rules = value;
    }

    function discover(address account, address token, uint256, uint256, bytes calldata)
        external
        view
        returns (IDiscoverySource.Candidate[] memory)
    {
        IFundingDiscovery(address(0x1120000000000000000000000000000000000003))
            .discover(1, account, token, 50, rules);
        return new IDiscoverySource.Candidate[](0);
    }
}
