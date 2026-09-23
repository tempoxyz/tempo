pub use IFundingPolicy::{
    IFundingPolicyErrors as FundingPolicyError, IFundingPolicyEvents as FundingPolicyEvent,
};

crate::sol!(
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    IFundingPolicy,
    "abi/IFundingPolicy.json"
);

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
