pub use ITIP20Funder::{
    ITIP20FunderErrors as TIP20FunderError, ITIP20FunderEvents as TIP20FunderEvent,
};

crate::sol! {
    /// TIP-1120 transaction funding events and errors; no callable funding entry point.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface ITIP20Funder {
        struct Source {
            address target;
            bytes data;
        }

        error InvalidFundingContext();
        error InvalidAsset(address asset);
        error FundingNotAuthorized(address source);
        error InvalidSourceOrder();
        error InvalidFundingPlan(address source);
        error InputLimitExceeded(address source, uint256 limit, uint256 attempted);
        error UnexpectedFundingAmount(address source, uint256 maximum, uint256 received);
        error InsufficientFunding(uint256 required, uint256 available);

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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256, U256, address, b256, hex};
    use alloy_sol_types::{SolError, SolEvent};

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
