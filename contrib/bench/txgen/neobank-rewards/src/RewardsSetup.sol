// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

/// @dev Minimal access-control surface read by Merkl's Distributor and pull wrapper.
contract BenchmarkAccessControlManager {
    address public immutable governor;

    constructor(address governor_) {
        require(governor_ != address(0), "zero governor");
        governor = governor_;
    }

    function isGovernor(address account) external view returns (bool) {
        return account == governor;
    }

    function isGovernorOrGuardian(address account) external view returns (bool) {
        return account == governor;
    }
}

/// @dev Minimal DistributionCreator surface read once by PullTokenWrapperAllowImmutable's constructor.
contract BenchmarkDistributionCreator {
    address public immutable accessControlManager;
    address public immutable distributor;
    address public immutable feeRecipient;

    constructor(address accessControlManager_, address distributor_, address feeRecipient_) {
        require(accessControlManager_ != address(0), "zero access manager");
        require(distributor_ != address(0), "zero distributor");
        require(feeRecipient_ != address(0), "zero fee recipient");
        accessControlManager = accessControlManager_;
        distributor = distributor_;
        feeRecipient = feeRecipient_;
    }
}
