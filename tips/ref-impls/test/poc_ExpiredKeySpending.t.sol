// SPDX-License-Identifier: MIT
pragma solidity >=0.8.28 <0.9.0;

import "forge-std/Test.sol";
import "src/AccountKeychain.sol";

contract AccountKeychainHarness is AccountKeychain {
    function setTransactionKey(address keyId) external {
        _setTransactionKey(keyId);
    }

    function verifyAndUpdateSpending(address account, address keyId, address token, uint256 amount)
        external
    {
        _verifyAndUpdateSpending(account, keyId, token, amount);
    }
}

contract ExpiredKeySpendingTest is Test {
    AccountKeychainHarness keychain;

    function setUp() public {
        keychain = new AccountKeychainHarness();
    }

    /// @notice Regression test: expired keys must NOT be able to spend
    function test_expired_key_cannot_spend() public {
        address keyId = address(0xBEEF);
        address token = address(0xCAFE);

        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](1);
        limits[0] = IAccountKeychain.TokenLimit({token: token, amount: 100});

        // authorize key with short expiry
        keychain.authorizeKey(
            keyId,
            IAccountKeychain.SignatureType.Secp256k1,
            uint64(block.timestamp + 1),
            true,
            limits
        );

        // move time past expiry
        vm.warp(block.timestamp + 2);

        // Protocol-level spending check should fail for expired keys
        vm.expectRevert(IAccountKeychain.KeyExpired.selector);
        keychain.verifyAndUpdateSpending(address(this), keyId, token, 10);
    }
}
