crate::sol! {
    /// TIP-1120 source quoting and synchronous funding hooks.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IFundingSource {
        struct Candidate {
            bytes requestData;
            uint256 availableAmount;
        }

        /// Whether a configured path supports the token, independent of balances and liquidity.
        /// @param policyData Source-specific rules or owner-selected configuration; malformed data reverts.
        function supportsToken(address token, bytes calldata policyData) external view returns (bool);

        /// Discovers independent funding candidates in configuration order without granting authority.
        function discover(
            address account,
            address assetOut,
            uint256 amountOut,
            uint256 maxCost,
            bytes calldata policyData
        ) external view returns (Candidate[] memory candidates);

        struct Quote {
            address assetIn;
            /// Output base units per input base unit, scaled by 1e18 and rounded up.
            uint256 rate;
            uint256 maxAmountIn;
            uint256 amountOut;
            bytes requestData;
        }

        /// Estimates additional output without reserving liquidity or granting input authority.
        /// @param account Input owner and output recipient to simulate.
        /// @param amountOut Output ceiling; uint256.max requests maximum availability.
        /// @param maxCost Remaining aggregate cost budget in output base units.
        /// @param ownerAuthorized Select owner rules with empty policyData; this flag grants no authority.
        /// @dev Public read-only estimate; grants no input authority.
        function quote(
            address account,
            address assetOut,
            uint256 amountOut,
            uint256 maxCost,
            bytes calldata requestData,
            bytes calldata policyData,
            bool ownerAuthorized
        ) external view returns (Quote memory result);

        /// Delivers up to amountOut to the authenticated account within its quoted input cap.
        /// @param requestData Unmodified execution payload returned by quote.
        /// @dev Only TIP20Funder may call, within the quoted native input permission.
        function fund(address account, address assetOut, uint256 amountOut, bytes calldata requestData) external;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{U256, address, bytes, hex};
    use alloy_sol_types::{SolCall, SolValue};

    #[test]
    fn funding_quote_abi_vector() {
        let call = IFundingSource::quoteCall {
            account: address!("0000000000000000000000000000000000000003"),
            amountOut: U256::from(50),
            assetOut: address!("0000000000000000000000000000000000000001"),
            maxCost: U256::from(100),
            requestData: bytes!("1234"),
            policyData: bytes!("ab"),
            ownerAuthorized: true,
        };
        let encoded = hex!(
            "0000000000000000000000000000000000000000000000000000000000000003"
            "0000000000000000000000000000000000000000000000000000000000000001"
            "0000000000000000000000000000000000000000000000000000000000000032"
            "0000000000000000000000000000000000000000000000000000000000000064"
            "00000000000000000000000000000000000000000000000000000000000000e0"
            "0000000000000000000000000000000000000000000000000000000000000120"
            "0000000000000000000000000000000000000000000000000000000000000001"
            "0000000000000000000000000000000000000000000000000000000000000002"
            "1234000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000001"
            "ab00000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            IFundingSource::quoteCall::SIGNATURE,
            "quote(address,address,uint256,uint256,bytes,bytes,bool)"
        );
        assert_eq!(call.abi_encode()[4..], encoded);
        let encoded = call.abi_encode();
        assert_eq!(
            IFundingSource::quoteCall::abi_decode_validate(&encoded).unwrap(),
            call
        );
    }

    #[test]
    fn funding_execution_abi_vector() {
        let call = IFundingSource::fundCall {
            account: address!("0000000000000000000000000000000000000001"),
            assetOut: address!("0000000000000000000000000000000000000002"),
            amountOut: U256::from(50),
            requestData: bytes!("1234"),
        };
        let encoded = hex!(
            "0f9cd729"
            "0000000000000000000000000000000000000000000000000000000000000001"
            "0000000000000000000000000000000000000000000000000000000000000002"
            "0000000000000000000000000000000000000000000000000000000000000032"
            "0000000000000000000000000000000000000000000000000000000000000080"
            "0000000000000000000000000000000000000000000000000000000000000002"
            "1234000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(call.abi_encode(), encoded);
        assert_eq!(
            IFundingSource::fundCall::abi_decode_validate(&encoded).unwrap(),
            call
        );
    }

    #[test]
    fn funding_quote_return_abi_vector() {
        let plan = IFundingSource::Quote {
            assetIn: address!("0000000000000000000000000000000000000002"),
            rate: U256::from(1_000_000_000_000_000_000u64),
            maxAmountIn: U256::from(30),
            amountOut: U256::from(29),
            requestData: bytes!("1234"),
        };
        let encoded = hex!(
            "0000000000000000000000000000000000000000000000000000000000000020"
            "0000000000000000000000000000000000000000000000000000000000000002"
            "0000000000000000000000000000000000000000000000000de0b6b3a7640000"
            "000000000000000000000000000000000000000000000000000000000000001e"
            "000000000000000000000000000000000000000000000000000000000000001d"
            "00000000000000000000000000000000000000000000000000000000000000a0"
            "0000000000000000000000000000000000000000000000000000000000000002"
            "1234000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(plan.abi_encode(), encoded);
        assert_eq!(
            IFundingSource::Quote::abi_decode_validate(&encoded).unwrap(),
            plan
        );
        assert_eq!(
            IFundingSource::quoteCall::abi_decode_returns_validate(&encoded).unwrap(),
            plan
        );
    }
    #[test]
    fn discovery_returns_ordered_reusable_requests() {
        let candidates = alloc::vec![
            IFundingSource::Candidate {
                requestData: bytes!("1234"),
                availableAmount: U256::from(30)
            },
            IFundingSource::Candidate {
                requestData: bytes!("abcd"),
                availableAmount: U256::from(40)
            },
        ];
        assert_eq!(
            IFundingSource::discoverCall::SIGNATURE,
            "discover(address,address,uint256,uint256,bytes)"
        );
        let encoded = IFundingSource::discoverCall::abi_encode_returns(&candidates);
        assert_eq!(
            IFundingSource::discoverCall::abi_decode_returns_validate(&encoded).unwrap(),
            candidates
        );
    }
}
