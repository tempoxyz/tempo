pub use ITIP20Funder::{
    ITIP20FunderErrors as TIP20FunderError, ITIP20FunderEvents as TIP20FunderEvent,
};

crate::sol! {
    /// TIP-1120 synchronous funding of required TIP-20 balances.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface ITIP20Funder {
        struct Source {
            address target;
            bytes data;
        }

        error InvalidFundingContext();
        error InvalidAsset(address asset);
        error TokenNotAllowed(address token);
        error FundingNotAuthorized(address source);
        error InvalidSourceOrder();
        error InvalidFundingQuote(address source);
        error InputLimitExceeded(address source, uint256 limit, uint256 attempted);
        error UnexpectedFundingAmount(address source, uint256 maximum, uint256 received);
        error InsufficientFunding(uint256 required, uint256 available);
        error FundingReentrancy();

        /// Records a verified positive contribution and its actual input consumption.
        /// @param requestHash Hash of the original source call data signed by the sender.
        event SourceFunded(
            address indexed account,
            address indexed assetOut,
            address indexed source,
            bytes32 requestHash,
            address assetIn,
            uint256 amountIn,
            uint256 amountOut
        );

        event FundsRequired(
            address indexed account,
            address indexed key,
            address indexed asset,
            uint256 requiredAmount,
            uint256 fundedAmount
        );

        /// Makes the authenticated account's balance at least amount.
        /// @return fundedAmount Newly delivered units, excluding the existing balance.
        function requireFunds(address asset, uint256 amount, Source[] calldata sources)
            external returns (uint256 fundedAmount);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloy_primitives::{Address, B256, U256, address, b256, bytes, hex};
    use alloy_sol_types::{SolCall, SolError, SolEvent};

    #[test]
    fn funding_call_abi_vector() {
        let call = ITIP20Funder::requireFundsCall {
            asset: address!("0000000000000000000000000000000000000001"),
            amount: U256::from(50),
            sources: vec![ITIP20Funder::Source {
                target: address!("0000000000000000000000000000000000000002"),
                data: bytes!("1234"),
            }],
        };
        let encoded = hex!(
            "1e35b1a8"
            "0000000000000000000000000000000000000000000000000000000000000001"
            "0000000000000000000000000000000000000000000000000000000000000032"
            "0000000000000000000000000000000000000000000000000000000000000060"
            "0000000000000000000000000000000000000000000000000000000000000001"
            "0000000000000000000000000000000000000000000000000000000000000020"
            "0000000000000000000000000000000000000000000000000000000000000002"
            "0000000000000000000000000000000000000000000000000000000000000040"
            "0000000000000000000000000000000000000000000000000000000000000002"
            "1234000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(call.abi_encode(), encoded);
        assert_eq!(
            ITIP20Funder::requireFundsCall::abi_decode_validate(&encoded).unwrap(),
            call
        );
        assert!(ITIP20Funder::requireFundsCall::abi_decode_validate(&encoded[..100]).is_err());
        assert_eq!(
            ITIP20Funder::requireFundsCall::abi_decode_returns_validate(&hex!(
                "000000000000000000000000000000000000000000000000000000000000001e"
            ))
            .unwrap(),
            U256::from(30)
        );
    }

    #[test]
    fn funding_error_abi_vector() {
        let error = ITIP20Funder::InputLimitExceeded {
            source: address!("0000000000000000000000000000000000000003"),
            limit: U256::from(30),
            attempted: U256::from(31),
        };
        let encoded = hex!(
            "83ad1dc5"
            "0000000000000000000000000000000000000000000000000000000000000003"
            "000000000000000000000000000000000000000000000000000000000000001e"
            "000000000000000000000000000000000000000000000000000000000000001f"
        );
        assert_eq!(error.abi_encode(), encoded);
        assert_eq!(
            ITIP20Funder::InputLimitExceeded::abi_decode_validate(&encoded).unwrap(),
            error
        );
    }

    #[test]
    fn funding_event_topics_and_data() {
        let account = address!("0000000000000000000000000000000000000001");
        let asset = address!("0000000000000000000000000000000000000002");
        let source = address!("0000000000000000000000000000000000000003");
        let log = ITIP20Funder::SourceFunded {
            account,
            assetOut: asset,
            source,
            requestHash: B256::ZERO,
            assetIn: asset,
            amountIn: U256::from(30),
            amountOut: U256::from(50),
        }
        .encode_log_data();
        assert_eq!(
            log.topics(),
            &[
                b256!("c706d8a6f4fb8d0bd385fcd4c23831c55e0c4abda215fc6d4374cafafa69827e"),
                account.into_word(),
                asset.into_word(),
                source.into_word(),
            ]
        );
        assert_eq!(
            log.data.as_ref(),
            hex!(
                "0000000000000000000000000000000000000000000000000000000000000000"
                "0000000000000000000000000000000000000000000000000000000000000002"
                "000000000000000000000000000000000000000000000000000000000000001e"
                "0000000000000000000000000000000000000000000000000000000000000032"
            )
        );

        let log = ITIP20Funder::FundsRequired {
            account,
            key: Address::ZERO,
            asset,
            requiredAmount: U256::from(50),
            fundedAmount: U256::from(30),
        }
        .encode_log_data();
        assert_eq!(
            log.topics(),
            &[
                b256!("1dd13101cd768c07e2e333321f8a44501dbecfca0540a01625fe7264214313e7"),
                account.into_word(),
                B256::ZERO,
                asset.into_word(),
            ]
        );
        assert_eq!(
            log.data.as_ref(),
            hex!(
                "0000000000000000000000000000000000000000000000000000000000000032"
                "000000000000000000000000000000000000000000000000000000000000001e"
            )
        );
    }
}
