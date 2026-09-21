pub use IFundingPolicyRegistry::{
    IFundingPolicyRegistryErrors as FundingPolicyRegistryError,
    IFundingPolicyRegistryEvents as FundingPolicyRegistryEvent,
};

crate::sol! {
    /// TIP-1120 shared funding policy interface; registry execution is activated separately.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
interface IFundingPolicyRegistry {
    struct Source {
        address target;
        bytes data;
    }

    struct Policy {
        address[] admins;
        address[] tokens;
        uint16 slippageBps;
        Source[] sources;
    }

    error PolicyNotFound();
    error Unauthorized();
    error InvalidPolicy();

    function policyIdCounter() external view returns (uint64);
    function policyExists(uint64 policyId) external view returns (bool);
    function createPolicy(Policy calldata policy) external returns (uint64 policyId);
    function getPolicy(uint64 policyId) external view returns (Policy memory policy);
    function modifyPolicy(uint64 policyId, address[] calldata tokens, uint16 slippageBps, Source[] calldata sources) external;
    function setAdmins(uint64 policyId, address[] calldata admins) external;

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
    fn policy_encoding_includes_allowed_tokens() {
        let policy = IFundingPolicyRegistry::Policy {
            admins: vec![Address::repeat_byte(1)],
            tokens: vec![Address::repeat_byte(2), Address::repeat_byte(3)],
            slippageBps: 100,
            sources: vec![IFundingPolicyRegistry::Source {
                target: Address::repeat_byte(4),
                data: Bytes::from_static(&[0xaa]),
            }],
        };
        let encoded = policy.abi_encode_params();
        // Four tuple heads: admins offset, tokens offset, slippage, sources offset.
        assert_eq!(&encoded[..32], &U256::from(128).to_be_bytes::<32>());
        assert_eq!(&encoded[32..64], &U256::from(192).to_be_bytes::<32>());
        assert_eq!(&encoded[192..224], &U256::from(2).to_be_bytes::<32>());
        assert_eq!(
            &encoded[224..256],
            Address::repeat_byte(2).into_word().as_slice()
        );
        assert_eq!(
            &encoded[256..288],
            Address::repeat_byte(3).into_word().as_slice()
        );
        let call = IFundingPolicyRegistry::createPolicyCall {
            policy: policy.clone(),
        };
        assert_eq!(
            IFundingPolicyRegistry::createPolicyCall::abi_decode_validate(&call.abi_encode())
                .unwrap(),
            call
        );
        let mut changed = policy.clone();
        changed.tokens.reverse();
        assert_ne!(policy.abi_encode_params(), changed.abi_encode_params());
        changed.tokens.clear();
        assert_eq!(
            IFundingPolicyRegistry::Policy::abi_decode_params_validate(
                &changed.abi_encode_params()
            )
            .unwrap(),
            changed
        );
    }

    #[test]
    fn modify_policy_carries_tokens_and_rules_without_admins() {
        let call = IFundingPolicyRegistry::modifyPolicyCall {
            policyId: 7,
            tokens: vec![Address::repeat_byte(2)],
            slippageBps: 100,
            sources: vec![],
        };
        assert_eq!(
            IFundingPolicyRegistry::modifyPolicyCall::SIGNATURE,
            "modifyPolicy(uint64,address[],uint16,(address,bytes)[])"
        );
        assert_eq!(
            IFundingPolicyRegistry::modifyPolicyCall::abi_decode_validate(&call.abi_encode())
                .unwrap(),
            call
        );
    }
}
