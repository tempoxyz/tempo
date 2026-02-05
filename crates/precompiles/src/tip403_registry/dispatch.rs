#[cfg(test)]
mod tests {
    use crate::{
        Precompile,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage},
        tip403_registry::{TIP403Registry, abi::ITIP403Registry},
    };
    use alloy::{primitives::Address, sol_types::{SolCall, SolValue}};
    use tempo_chainspec::hardfork::TempoHardfork;

    #[test]
    fn test_is_authorized_precompile() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Test policy 1 (always allow)
            let call = ITIP403Registry::isAuthorizedCall { policy_id: 1, user };
            let calldata = call.abi_encode();
            let result = registry.call(&calldata, Address::ZERO);

            assert!(result.is_ok());
            let output = result.unwrap();
            let decoded: bool =
                ITIP403Registry::isAuthorizedCall::abi_decode_returns(&output.bytes).unwrap();
            assert!(decoded);

            Ok(())
        })
    }

    #[test]
    fn test_create_policy_precompile() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            let call = ITIP403Registry::createPolicyCall {
                admin,
                policy_type: ITIP403Registry::PolicyType::WHITELIST,
            };
            let calldata = call.abi_encode();
            let result = registry.call(&calldata, admin);

            assert!(result.is_ok());
            let output = result.unwrap();
            let decoded: u64 =
                ITIP403Registry::createPolicyCall::abi_decode_returns(&output.bytes).unwrap();
            assert_eq!(decoded, 2); // First created policy ID

            Ok(())
        })
    }

    #[test]
    fn test_policy_id_counter_initialization() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let sender = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Get initial counter
            let counter_call = ITIP403Registry::policyIdCounterCall {};
            let calldata = counter_call.abi_encode();
            let result = registry.call(&calldata, sender).unwrap();
            let counter = u64::abi_decode(&result.bytes).unwrap();
            assert_eq!(counter, 2); // Counter starts at 2 (policies 0 and 1 are reserved)

            Ok(())
        })
    }

    #[test]
    fn test_special_policy_ids() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Test policy 0 (always deny)
            let is_auth_call = ITIP403Registry::isAuthorizedCall { policy_id: 0, user };
            let calldata = is_auth_call.abi_encode();
            let result = registry.call(&calldata, Address::ZERO).unwrap();
            let is_authorized = bool::abi_decode(&result.bytes).unwrap();
            assert!(!is_authorized);

            // Test policy 1 (always allow)
            let is_auth_call = ITIP403Registry::isAuthorizedCall { policy_id: 1, user };
            let calldata = is_auth_call.abi_encode();
            let result = registry.call(&calldata, Address::ZERO).unwrap();
            let is_authorized = bool::abi_decode(&result.bytes).unwrap();
            assert!(is_authorized);

            Ok(())
        })
    }

    #[test]
    fn test_invalid_selector() -> eyre::Result<()> {
        let sender = Address::random();

        // T1: invalid selector returns reverted output
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut registry = TIP403Registry::new();

            let invalid_data = vec![0x12, 0x34, 0x56, 0x78];
            let result = registry.call(&invalid_data, sender)?;
            assert!(result.reverted);

            // T1: insufficient data also returns reverted output
            let short_data = vec![0x12, 0x34];
            let result = registry.call(&short_data, sender)?;
            assert!(result.reverted);

            Ok(())
        })?;

        // Pre-T1 (T0): insufficient data returns error
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T0);
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            let short_data = vec![0x12, 0x34];
            let result = registry.call(&short_data, sender);
            assert!(result.is_err());

            Ok(())
        })
    }

    #[test]
    fn test_selector_coverage() -> eyre::Result<()> {
        use ITIP403Registry::Calls;

        // Use T2 to test all selectors including TIP-1015 compound policy functions
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            let unsupported = check_selector_coverage(
                &mut registry,
                Calls::SELECTORS,
                "ITIP403Registry",
                Calls::name_by_selector,
            );

            assert_full_coverage([unsupported]);

            Ok(())
        })
    }
}
