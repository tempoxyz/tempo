pub use IFundingPolicy::{
    IFundingPolicyErrors as FundingPolicyError, IFundingPolicyEvents as FundingPolicyEvent,
};

crate::sol! {
    /// TIP-1120 shared funding policy interface; registry execution is activated separately.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
interface IFundingPolicy {
    struct Source {
        address target;
        bytes data;
    }

    struct Route {
        address token;
        Source[] sources;
    }

    struct Policy {
        address[] admins;
        uint16 slippageBps;
        Route[] routes;
    }

    struct Candidate {
        address target;
        bytes data;
        uint256 availableAmount;
    }

    struct Discovery {
        address token;
        uint256 amount;
        uint16 slippageBps;
        Candidate[] sources;
    }

    error TokenNotAllowed(address token);
    error PolicyNotFound();
    error Unauthorized();
    error InvalidPolicy();

    function policyIdCounter() external view returns (uint64);
    function policyExists(uint64 policyId) external view returns (bool);
    function createPolicy(Policy calldata policy) external returns (uint64 policyId);
    function getPolicy(uint64 policyId) external view returns (Policy memory policy);
    function modifyPolicy(uint64 policyId, uint16 slippageBps, Route[] calldata routes) external;
    function setAdmins(uint64 policyId, address[] calldata admins) external;

    /// Constructs independently estimated requests without selecting a policy or granting authority.
    function discover(uint64 policyId, address account, address token, uint256 amount)
        external view returns (Discovery memory);

    event PolicyCreated(uint64 indexed policyId, address indexed updater);
    /// @dev policyHash is keccak256(abi.encode(policy)) after the rule update.
    event PolicyUpdated(uint64 indexed policyId, address indexed updater, bytes32 policyHash);
    event PolicyAdminsUpdated(uint64 indexed policyId, address indexed updater, address[] admins);
}
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloy_primitives::{Address, Bytes, U256};
    use alloy_sol_types::{SolCall, SolValue};

    #[test]
    fn policy_encoding_binds_routes_tokens_and_source_rules() {
        let route = IFundingPolicy::Route {
            token: Address::repeat_byte(2),
            sources: vec![IFundingPolicy::Source {
                target: Address::repeat_byte(4),
                data: Bytes::from_static(&[0xaa]),
            }],
        };
        let policy = IFundingPolicy::Policy {
            admins: vec![Address::repeat_byte(1)],
            slippageBps: 100,
            routes: vec![
                route,
                IFundingPolicy::Route {
                    token: Address::repeat_byte(5),
                    sources: vec![IFundingPolicy::Source {
                        target: Address::repeat_byte(4),
                        data: Bytes::from_static(&[0xbb]),
                    }],
                },
            ],
        };
        let encoded = policy.abi_encode_params();
        assert_eq!(&encoded[..32], &U256::from(96).to_be_bytes::<32>());
        assert_eq!(&encoded[32..64], &U256::from(100).to_be_bytes::<32>());
        assert_eq!(&encoded[64..96], &U256::from(160).to_be_bytes::<32>());
        assert_eq!(&encoded[160..192], &U256::from(2).to_be_bytes::<32>());
        let call = IFundingPolicy::createPolicyCall {
            policy: policy.clone(),
        };
        assert_eq!(
            IFundingPolicy::createPolicyCall::SIGNATURE,
            "createPolicy((address[],uint16,(address,(address,bytes)[])[]))"
        );
        assert_eq!(
            IFundingPolicy::createPolicyCall::abi_decode_validate(&call.abi_encode()).unwrap(),
            call
        );
        for change in 0..4 {
            let mut changed = policy.clone();
            match change {
                0 => changed.routes.reverse(),
                1 => changed.routes[0].token = Address::repeat_byte(3),
                2 => changed.routes[0].sources[0].data = Bytes::new(),
                _ => changed.routes.clear(),
            }
            assert_ne!(encoded, changed.abi_encode_params());
            assert_eq!(
                IFundingPolicy::Policy::abi_decode_params_validate(&changed.abi_encode_params())
                    .unwrap(),
                changed
            );
        }
    }

    #[test]
    fn modify_policy_replaces_routes_without_admins() {
        let call = IFundingPolicy::modifyPolicyCall {
            policyId: 7,
            slippageBps: 100,
            routes: vec![],
        };
        assert_eq!(
            IFundingPolicy::modifyPolicyCall::SIGNATURE,
            "modifyPolicy(uint64,uint16,(address,(address,bytes)[])[])"
        );
        assert_eq!(
            IFundingPolicy::modifyPolicyCall::abi_decode_validate(&call.abi_encode()).unwrap(),
            call
        );
    }
    #[test]
    fn discovery_preserves_target_and_independent_estimates() {
        let result = IFundingPolicy::Discovery {
            token: Address::repeat_byte(1),
            amount: U256::from(50),
            slippageBps: 100,
            sources: vec![
                IFundingPolicy::Candidate {
                    target: Address::repeat_byte(2),
                    data: Bytes::from_static(&[1]),
                    availableAmount: U256::from(30),
                },
                IFundingPolicy::Candidate {
                    target: Address::repeat_byte(2),
                    data: Bytes::from_static(&[2]),
                    availableAmount: U256::from(40),
                },
            ],
        };
        assert_eq!(
            IFundingPolicy::discoverCall::SIGNATURE,
            "discover(uint64,address,address,uint256)"
        );
        assert_eq!(
            IFundingPolicy::discoverCall::abi_decode_returns_validate(&result.abi_encode())
                .unwrap(),
            result
        );
    }
}
