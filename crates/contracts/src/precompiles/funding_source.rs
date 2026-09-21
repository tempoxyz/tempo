crate::sol! {
    /// TIP-1120 source preparation and synchronous funding hooks.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IFundingSource {
        struct Plan {
            address assetIn;
            /// Output base units per input base unit, scaled by 1e18 and rounded up.
            uint256 rate;
            uint256 maxAmountIn;
            bytes data;
        }

        /// Validates source arguments against policy rules before granting input authority.
        /// @param maxCost Remaining aggregate cost budget in output base units.
        /// @param ownerAuthorized Native owner authentication; policyData is empty in this mode.
        /// @dev Only TIP20Funder may call, using STATICCALL.
        function prepare(
            address assetOut,
            uint256 maxCost,
            bytes calldata data,
            bytes calldata policyData,
            bool ownerAuthorized
        ) external view returns (Plan memory plan);

        /// Delivers up to amountOut to the authenticated account within its prepared input cap.
        /// @param data Unmodified execution payload returned by prepare.
        /// @dev Only TIP20Funder may call, within the prepared native input permission.
        function fund(address account, address assetOut, uint256 amountOut, bytes calldata data) external;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{U256, address, bytes, hex};
    use alloy_sol_types::{SolCall, SolValue};

    #[test]
    fn funding_prepare_abi_vector() {
        let call = IFundingSource::prepareCall {
            assetOut: address!("0000000000000000000000000000000000000001"),
            maxCost: U256::from(100),
            data: bytes!("1234"),
            policyData: bytes!("ab"),
            ownerAuthorized: true,
        };
        let encoded = hex!(
            "d645c5d8"
            "0000000000000000000000000000000000000000000000000000000000000001"
            "0000000000000000000000000000000000000000000000000000000000000064"
            "00000000000000000000000000000000000000000000000000000000000000a0"
            "00000000000000000000000000000000000000000000000000000000000000e0"
            "0000000000000000000000000000000000000000000000000000000000000001"
            "0000000000000000000000000000000000000000000000000000000000000002"
            "1234000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000001"
            "ab00000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(call.abi_encode(), encoded);
        assert_eq!(
            IFundingSource::prepareCall::abi_decode_validate(&encoded).unwrap(),
            call
        );
    }

    #[test]
    fn funding_execution_abi_vector() {
        let call = IFundingSource::fundCall {
            account: address!("0000000000000000000000000000000000000001"),
            assetOut: address!("0000000000000000000000000000000000000002"),
            amountOut: U256::from(50),
            data: bytes!("1234"),
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
    fn funding_plan_abi_vector() {
        let plan = IFundingSource::Plan {
            assetIn: address!("0000000000000000000000000000000000000002"),
            rate: U256::from(1_000_000_000_000_000_000u64),
            maxAmountIn: U256::from(30),
            data: bytes!("1234"),
        };
        let encoded = hex!(
            "0000000000000000000000000000000000000000000000000000000000000020"
            "0000000000000000000000000000000000000000000000000000000000000002"
            "0000000000000000000000000000000000000000000000000de0b6b3a7640000"
            "000000000000000000000000000000000000000000000000000000000000001e"
            "0000000000000000000000000000000000000000000000000000000000000080"
            "0000000000000000000000000000000000000000000000000000000000000002"
            "1234000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(plan.abi_encode(), encoded);
        assert_eq!(
            IFundingSource::Plan::abi_decode_validate(&encoded).unwrap(),
            plan
        );
        assert_eq!(
            IFundingSource::prepareCall::abi_decode_returns_validate(&encoded).unwrap(),
            plan
        );
    }
}
