// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { console2 } from "forge-std/console2.sol";

/// Optional evidence helper, with no auto-discovered tests or claimed executions.
/// The collector must join markers to the SAME test attempt's final outcome.
/// Checks the condition before emitting, with the test identity and actual fork.
/// Identifiers are deliberately restricted so the output is valid JSON.
library SpecEvidence {

    function assertEvidence(
        bool condition,
        string memory requirement,
        string memory caseName,
        string memory testName,
        string memory fork
    )
        internal
        pure
    {
        require(condition, "spec evidence assertion failed");
        _checkIdentifier(requirement);
        _checkIdentifier(caseName);
        _checkIdentifier(testName);
        _checkIdentifier(fork);
        console2.log(
            string.concat(
                'TIP_EVIDENCE {"requirement":"',
                requirement,
                '","case":"',
                caseName,
                '","test":"',
                testName,
                '","fork":"',
                fork,
                '"}'
            )
        );
    }

    function _checkIdentifier(string memory value) private pure {
        bytes memory chars = bytes(value);
        require(chars.length != 0, "empty evidence identifier");
        for (uint256 i = 0; i < chars.length; ++i) {
            bytes1 c = chars[i];
            require(
                (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a)
                    || c == 0x2d || c == 0x5f || c == 0x3a || c == 0x2e,
                "invalid evidence identifier"
            );
        }
    }

}
