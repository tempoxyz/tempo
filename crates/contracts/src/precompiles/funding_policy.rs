pub use IFundingPolicy::{
    IFundingPolicyErrors as FundingPolicyError, IFundingPolicyEvents as FundingPolicyEvent,
};

crate::sol! {
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

    struct Rules {
        uint16 maxSlippageBps;
        Route[] routes;
    }

    struct Policy {
        address[] admins;
        bytes32 rulesHash;
    }

    error PolicyNotFound();
    error Unauthorized();
    error InvalidPolicy();
    error InvalidPolicyData();
    error TokenNotAllowed(address token);

    function policyIdCounter() external view returns (uint64);
    function policyExists(uint64 policyId) external view returns (bool);
    function createPolicy(address[] calldata admins, Rules calldata rules) external returns (uint64 policyId);
    function getPolicy(uint64 policyId) external view returns (Policy memory policy);
    function setRules(uint64 policyId, Rules calldata rules) external;
    function setAdmins(uint64 policyId, address[] calldata admins) external;

    event PolicyCreated(uint64 indexed policyId, address indexed updater, bytes32 rulesHash, Rules rules);
    event PolicyRulesUpdated(uint64 indexed policyId, address indexed updater, bytes32 rulesHash, Rules rules);
    event PolicyAdminsUpdated(uint64 indexed policyId, address indexed updater, address[] admins);
}
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloy_primitives::{Address, Bytes};
    use alloy_sol_types::{SolCall, SolValue};

    #[test]
    fn rules_encoding_binds_routes_and_source_order() {
        let rules = IFundingPolicy::Rules {
            maxSlippageBps: 100,
            routes: vec![IFundingPolicy::Route {
                token: Address::repeat_byte(2),
                sources: vec![
                    IFundingPolicy::Source {
                        target: Address::repeat_byte(3),
                        data: Bytes::from_static(&[1]),
                    },
                    IFundingPolicy::Source {
                        target: Address::repeat_byte(3),
                        data: Bytes::from_static(&[2]),
                    },
                ],
            }],
        };
        let encoded = rules.abi_encode();
        assert_eq!(
            IFundingPolicy::Rules::abi_decode_validate(&encoded).unwrap(),
            rules
        );
        let mutations: &[fn(&mut IFundingPolicy::Rules)] = &[
            |r| r.maxSlippageBps = 0,
            |r| r.routes[0].token = Address::repeat_byte(4),
            |r| r.routes[0].sources.reverse(),
            |r| r.routes[0].sources[0].data = Bytes::new(),
        ];
        for mutate in mutations {
            let mut changed = rules.clone();
            mutate(&mut changed);
            assert_ne!(encoded, changed.abi_encode());
        }
        let call = IFundingPolicy::createPolicyCall {
            admins: vec![Address::repeat_byte(1)],
            rules,
        };
        assert_eq!(
            IFundingPolicy::createPolicyCall::SIGNATURE,
            "createPolicy(address[],(uint16,(address,(address,bytes)[])[]))"
        );
        assert_eq!(
            IFundingPolicy::createPolicyCall::abi_decode_validate(&call.abi_encode()).unwrap(),
            call
        );
        assert_eq!(
            IFundingPolicy::setRulesCall::SIGNATURE,
            "setRules(uint64,(uint16,(address,(address,bytes)[])[]))"
        );
    }
}
