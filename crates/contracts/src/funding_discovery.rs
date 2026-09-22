//! Read-only Solidity helper bindings; discovery is not a native precompile operation.

crate::sol!(
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    IFundingDiscovery,
    "abi/IFundingDiscovery.json"
);

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloy_primitives::{Address, Bytes, U256};
    use alloy_sol_types::{SolCall, SolValue};
    #[test]
    fn discovery_preserves_target_and_independent_estimates() {
        let result = IFundingDiscovery::Discovery {
            token: Address::repeat_byte(1),
            amount: U256::from(50),
            slippageBps: 100,
            sources: vec![
                IFundingDiscovery::SourceCandidate {
                    target: Address::repeat_byte(2),
                    data: Bytes::from_static(&[1]),
                    availableAmount: U256::from(30),
                },
                IFundingDiscovery::SourceCandidate {
                    target: Address::repeat_byte(2),
                    data: Bytes::from_static(&[2]),
                    availableAmount: U256::from(40),
                },
            ],
        };
        assert_eq!(
            IFundingDiscovery::discoverCall::SIGNATURE,
            "discover(uint64,address,address,uint256)"
        );
        assert_eq!(
            IFundingDiscovery::discoverCall::abi_decode_returns_validate(&result.abi_encode())
                .unwrap(),
            result
        );
    }
}
