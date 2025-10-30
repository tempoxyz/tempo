//! Interface and dispatcher tests for the #[contract] macro.
//!
//! Tests the macro expansion for contracts with and without interfaces.

// Re-export `tempo_precompiles::storage` as a local module so `crate::storage` works
mod storage {
    pub(super) use tempo_precompiles::storage::*;
}

use alloy::{
    primitives::{Address, U256},
    sol,
    sol_types::{SolCall, SolValue},
};
use storage::{ContractStorage, hashmap::HashMapStorageProvider};
use tempo_precompiles_macros::contract;

// Test interface for E2E dispatcher tests
sol! {
    interface ITestToken {
        // Metadata (no params)
        function name() external view returns (string);
        function symbol() external view returns (string);
        function decimals() external pure returns (uint8);

        // View (with params)
        function balanceOf(address account) external view returns (uint256);
        function allowance(address owner, address spender) external view returns (uint256);

        // Mutate (returns bool)
        function transfer(address to, uint256 amount) external returns (bool);
        function approve(address spender, uint256 amount) external returns (bool);

        // Mutate void
        function mint(address to, uint256 amount) external;
        function burn(uint256 amount) external;

        // Errors
        error InsufficientBalance(uint256 requested, uint256 available);
        error InsufficientAllowance();
        error InvalidRecipient();
    }
}

// Second test interface for multi-interface testing
sol! {
    interface IMetadata {
        // Additional metadata functions
        function version() external view returns (uint256);
        function owner() external view returns (address);
    }
}

// Create type alias for the generated error enum
pub use ITestToken::ITestTokenErrors as TestTokenError;

// Re-export helper functions so macro-generated code can find them via `crate::`
pub use tempo_precompiles::{
    METADATA_GAS, MUTATE_FUNC_GAS, Precompile, VIEW_FUNC_GAS, error, metadata, mutate, mutate_void,
    view,
};

// Helper to generate addresses
fn test_address(byte: u8) -> Address {
    let mut bytes = [0u8; 20];
    bytes[19] = byte;
    Address::from(bytes)
}

// E2E Test contract with dispatcher
#[contract(ITestToken)]
pub struct TestToken {
    pub name: String,
    pub symbol: String,
    #[slot(10)]
    #[map = "balanceOf"]
    pub balances: storage::Mapping<Address, U256>,
    #[slot(11)]
    #[map = "allowance"]
    pub allowances: storage::Mapping<Address, storage::Mapping<Address, U256>>,
}

impl<S: storage::PrecompileStorageProvider> TestTokenCall for TestToken<'_, S> {
    // name(), symbol(), balanceOf(), allowance() auto-generated with default impls

    fn decimals(&mut self) -> tempo_precompiles::error::Result<u8> {
        Ok(18)
    }

    fn transfer(
        &mut self,
        s: Address,
        to: Address,
        amount: U256,
    ) -> tempo_precompiles::error::Result<bool> {
        let balance = self._get_balances(s)?;
        if amount > balance {
            return Err(tempo_precompiles::error::TempoPrecompileError::Fatal(
                format!(
                    "InsufficientBalance: requested {}, available {}",
                    amount, balance
                ),
            ));
        }
        self._set_balances(s, balance - amount)?;
        let to_balance = self._get_balances(to)?;
        self._set_balances(to, to_balance + amount)?;
        Ok(true)
    }

    fn approve(
        &mut self,
        s: Address,
        spender: Address,
        amount: U256,
    ) -> tempo_precompiles::error::Result<bool> {
        self._set_allowances(s, spender, amount)?;
        Ok(true)
    }

    fn mint(
        &mut self,
        _s: Address,
        to: Address,
        amount: U256,
    ) -> tempo_precompiles::error::Result<()> {
        let balance = self._get_balances(to)?;
        self._set_balances(to, balance + amount)?;
        Ok(())
    }

    fn burn(&mut self, s: Address, amount: U256) -> tempo_precompiles::error::Result<()> {
        let balance = self._get_balances(s)?;
        if amount > balance {
            return Err(tempo_precompiles::error::TempoPrecompileError::Fatal(
                format!(
                    "InsufficientBalance: requested {}, available {}",
                    amount, balance
                ),
            ));
        }
        self._set_balances(s, balance - amount)?;
        Ok(())
    }
}

#[test]
fn test_contract_without_interface() {
    // Test that macro works without interface (only generates storage)
    #[contract]
    pub struct SimpleStorage {
        pub value: U256,
        pub name: String,
        #[slot(5)]
        pub counter: u64,
    }

    let mut storage = HashMapStorageProvider::new(1);
    let addr = test_address(1);
    let mut simple = SimpleStorage::_new(addr, &mut storage);

    // Storage accessors should work
    simple._set_value(U256::from(42)).unwrap();
    simple._set_name("Test".to_string()).unwrap();
    simple._set_counter(100).unwrap();

    assert_eq!(simple._get_value().unwrap(), U256::from(42));
    assert_eq!(simple._get_name().unwrap(), "Test");
    assert_eq!(simple._get_counter().unwrap(), 100);

    // Verify ContractStorage trait is implemented
    assert_eq!(simple.address(), addr);
}

#[test]
fn test_contract_with_map_attribute() {
    // Test that map attribute works for field renaming
    #[contract]
    pub struct TokenStorage {
        pub name: String,
        pub symbol: String,
        #[slot(10)]
        #[map = "balanceOf"]
        pub balances: storage::Mapping<Address, U256>,
        #[slot(11)]
        #[map = "allowance"]
        pub allowances: storage::Mapping<Address, storage::Mapping<Address, U256>>,
    }

    let mut storage = HashMapStorageProvider::new(1);
    let addr = test_address(1);
    let mut token = TokenStorage::_new(addr, &mut storage);

    // Test single-level mapping
    let account1 = test_address(2);
    let account2 = test_address(3);

    token._set_balances(account1, U256::from(1000)).unwrap();
    token._set_balances(account2, U256::from(500)).unwrap();

    assert_eq!(token._get_balances(account1).unwrap(), U256::from(1000));
    assert_eq!(token._get_balances(account2).unwrap(), U256::from(500));

    // Test nested mapping
    let owner = test_address(4);
    let spender = test_address(5);

    token
        ._set_allowances(owner, spender, U256::from(200))
        .unwrap();
    assert_eq!(
        token._get_allowances(owner, spender).unwrap(),
        U256::from(200)
    );
}

#[test]
fn test_multiple_storage_types() {
    // Test contract with various storage types
    #[contract]
    pub struct MultiType {
        pub string_val: String,
        pub u256_val: U256,
        pub u64_val: u64,
        pub bool_val: bool,
        pub address_val: Address,
        #[slot(10)]
        pub mapping_val: storage::Mapping<Address, U256>,
    }

    let mut storage = HashMapStorageProvider::new(1);
    let addr = test_address(1);
    let mut multi = MultiType::_new(addr, &mut storage);

    // Set all types
    multi._set_string_val("Hello".to_string()).unwrap();
    multi._set_u256_val(U256::from(12345)).unwrap();
    multi._set_u64_val(999).unwrap();
    multi._set_bool_val(true).unwrap();
    multi._set_address_val(test_address(99)).unwrap();

    let key = test_address(10);
    multi._set_mapping_val(key, U256::from(777)).unwrap();

    // Verify all types
    assert_eq!(multi._get_string_val().unwrap(), "Hello");
    assert_eq!(multi._get_u256_val().unwrap(), U256::from(12345));
    assert_eq!(multi._get_u64_val().unwrap(), 999);
    assert!(multi._get_bool_val().unwrap());
    assert_eq!(multi._get_address_val().unwrap(), test_address(99));
    assert_eq!(multi._get_mapping_val(key).unwrap(), U256::from(777));
}

#[test]
fn test_slots_module_with_map_attribute() {
    #[contract]
    pub struct TokenStorage {
        pub name: String, // Auto: slot 0
        #[slot(5)]
        pub symbol: String, // Explicit: slot 5
        #[slot(10)]
        #[map = "balanceOf"]
        pub balances: storage::Mapping<Address, U256>, // Explicit: slot 10
    }

    // Verify the slots module constants
    assert_eq!(slots::NAME, U256::from(0));
    assert_eq!(slots::SYMBOL, U256::from(5));
    assert_eq!(slots::BALANCES, U256::from(10));
}

#[test]
fn test_nested_mapping_storage() {
    #[contract]
    pub struct NestedStorage {
        #[slot(20)]
        pub nested: storage::Mapping<Address, storage::Mapping<Address, U256>>,
    }

    let mut storage = HashMapStorageProvider::new(1);
    let addr = test_address(1);
    let mut nested = NestedStorage::_new(addr, &mut storage);

    let key1 = test_address(2);
    let key2 = test_address(3);

    // Test nested mapping operations
    nested._set_nested(key1, key2, U256::from(888)).unwrap();
    assert_eq!(nested._get_nested(key1, key2).unwrap(), U256::from(888));

    // Test multiple nested entries
    let key3 = test_address(4);
    nested._set_nested(key1, key3, U256::from(999)).unwrap();
    assert_eq!(nested._get_nested(key1, key3).unwrap(), U256::from(999));

    // Original value should be unchanged
    assert_eq!(nested._get_nested(key1, key2).unwrap(), U256::from(888));
}

#[test]
fn test_contract_with_generic_storage_provider() {
    #[contract]
    pub struct GenericContract {
        pub value: U256,
    }

    // Test with HashMapStorageProvider
    let mut hash_storage = HashMapStorageProvider::new(1);
    let addr = test_address(1);
    let mut contract1 = GenericContract::_new(addr, &mut hash_storage);

    contract1._set_value(U256::from(42)).unwrap();
    assert_eq!(contract1._get_value().unwrap(), U256::from(42));

    // The contract should work with any PrecompileStorageProvider implementation
    // This demonstrates the generic nature of the generated code
}

#[test]
fn test_constructor_and_contract_storage_trait() {
    #[contract]
    pub struct TestContract {
        pub data: U256,
    }

    let mut storage = HashMapStorageProvider::new(1);
    let addr = test_address(42);

    // Test constructor
    let mut contract = TestContract::_new(addr, &mut storage);

    // Test ContractStorage trait implementation
    assert_eq!(contract.address(), addr);

    // The storage() method should return a mutable reference to the storage provider
    let _storage_ref: &mut HashMapStorageProvider = contract.storage();
}

// ============================================================================
// E2E Dispatcher Tests
// ============================================================================

#[test]
fn test_dispatcher_metadata_functions() {
    let mut storage = HashMapStorageProvider::new(1);
    let addr = test_address(1);
    let mut token = TestToken::_new(addr, &mut storage);
    let sender = test_address(2);

    // Setup
    token._set_name("Test Token".to_string()).unwrap();
    token._set_symbol("TEST".to_string()).unwrap();

    // Test name() - metadata function
    let calldata = ITestToken::nameCall {}.abi_encode();
    let result = token.call(&calldata, sender).unwrap();
    assert_eq!(result.gas_used, METADATA_GAS);
    let name = String::abi_decode(&result.bytes).unwrap();
    assert_eq!(name, "Test Token");

    // Test symbol() - metadata function
    let calldata = ITestToken::symbolCall {}.abi_encode();
    let result = token.call(&calldata, sender).unwrap();
    assert_eq!(result.gas_used, METADATA_GAS);
    let symbol = String::abi_decode(&result.bytes).unwrap();
    assert_eq!(symbol, "TEST");

    // Test decimals() - metadata function (custom impl)
    let calldata = ITestToken::decimalsCall {}.abi_encode();
    let result = token.call(&calldata, sender).unwrap();
    assert_eq!(result.gas_used, METADATA_GAS);
    let decimals =
        <ITestToken::decimalsCall as SolCall>::abi_decode_returns(&result.bytes).unwrap();
    assert_eq!(decimals, 18);
}

#[test]
fn test_dispatcher_view_functions() {
    let mut storage = HashMapStorageProvider::new(1);
    let addr = test_address(1);
    let mut token = TestToken::_new(addr, &mut storage);
    let account = test_address(2);
    let spender = test_address(3);
    let sender = test_address(4);

    // Setup balances and allowances
    token._set_balances(account, U256::from(1000)).unwrap();
    token
        ._set_allowances(account, spender, U256::from(500))
        .unwrap();

    // Test balanceOf() - view function
    let calldata = ITestToken::balanceOfCall { account }.abi_encode();
    let result = token.call(&calldata, sender).unwrap();
    assert_eq!(result.gas_used, VIEW_FUNC_GAS);
    let balance = U256::abi_decode(&result.bytes).unwrap();
    assert_eq!(balance, U256::from(1000));

    // Test allowance() - view function
    let calldata = ITestToken::allowanceCall {
        owner: account,
        spender,
    }
    .abi_encode();
    let result = token.call(&calldata, sender).unwrap();
    assert_eq!(result.gas_used, VIEW_FUNC_GAS);
    let allowance = U256::abi_decode(&result.bytes).unwrap();
    assert_eq!(allowance, U256::from(500));
}

#[test]
fn test_dispatcher_mutate_functions() {
    let mut storage = HashMapStorageProvider::new(1);
    let addr = test_address(1);
    let mut token = TestToken::_new(addr, &mut storage);
    let sender = test_address(2);
    let recipient = test_address(3);
    let spender = test_address(4);

    // Setup initial balance
    token._set_balances(sender, U256::from(1000)).unwrap();

    // Test transfer() - mutate function returning bool
    let calldata = ITestToken::transferCall {
        to: recipient,
        amount: U256::from(100),
    }
    .abi_encode();
    let result = token.call(&calldata, sender).unwrap();
    assert_eq!(result.gas_used, MUTATE_FUNC_GAS);
    assert!(!result.reverted);
    let success = bool::abi_decode(&result.bytes).unwrap();
    assert!(success);

    // Verify state changes
    assert_eq!(token._get_balances(sender).unwrap(), U256::from(900));
    assert_eq!(token._get_balances(recipient).unwrap(), U256::from(100));

    // Test approve() - mutate function returning bool
    let calldata = ITestToken::approveCall {
        spender,
        amount: U256::from(200),
    }
    .abi_encode();
    let result = token.call(&calldata, sender).unwrap();
    assert_eq!(result.gas_used, MUTATE_FUNC_GAS);
    assert!(!result.reverted);
    let success = bool::abi_decode(&result.bytes).unwrap();
    assert!(success);
    assert_eq!(
        token._get_allowances(sender, spender).unwrap(),
        U256::from(200)
    );
}

#[test]
fn test_dispatcher_mutate_void_functions() {
    let mut storage = HashMapStorageProvider::new(1);
    let addr = test_address(1);
    let mut token = TestToken::_new(addr, &mut storage);
    let sender = test_address(2);
    let recipient = test_address(3);

    // Test mint() - mutate_void function
    let calldata = ITestToken::mintCall {
        to: recipient,
        amount: U256::from(500),
    }
    .abi_encode();
    let result = token.call(&calldata, sender).unwrap();
    assert_eq!(result.gas_used, MUTATE_FUNC_GAS);
    assert!(!result.reverted);
    assert!(result.bytes.is_empty()); // void return
    assert_eq!(token._get_balances(recipient).unwrap(), U256::from(500));

    // Setup for burn
    token._set_balances(sender, U256::from(300)).unwrap();

    // Test burn() - mutate_void function
    let calldata = ITestToken::burnCall {
        amount: U256::from(100),
    }
    .abi_encode();
    let result = token.call(&calldata, sender).unwrap();
    assert_eq!(result.gas_used, MUTATE_FUNC_GAS);
    assert!(!result.reverted);
    assert!(result.bytes.is_empty());
    assert_eq!(token._get_balances(sender).unwrap(), U256::from(200));
}

#[test]
fn test_dispatcher_error_handling() {
    let mut storage = HashMapStorageProvider::new(1);
    let addr = test_address(1);
    let mut token = TestToken::_new(addr, &mut storage);
    let sender = test_address(2);
    let recipient = test_address(3);

    // Test insufficient balance error
    token._set_balances(sender, U256::from(50)).unwrap();
    let calldata = ITestToken::transferCall {
        to: recipient,
        amount: U256::from(100),
    }
    .abi_encode();
    let result = token.call(&calldata, sender);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, ::revm::precompile::PrecompileError::Fatal(_)));

    // Test invalid selector
    let invalid_calldata = vec![0x12, 0x34, 0x56, 0x78];
    let result = token.call(&invalid_calldata, sender);
    assert!(result.is_err());

    // Test insufficient calldata (< 4 bytes)
    let short_calldata = vec![0x12, 0x34];
    let result = token.call(&short_calldata, sender);
    assert!(result.is_err());
}

#[test]
fn test_dispatcher_selector_routing() {
    // Verify each selector routes to correct function
    let mut storage = HashMapStorageProvider::new(1);
    let addr = test_address(1);
    let mut token = TestToken::_new(addr, &mut storage);
    let sender = test_address(2);

    token._set_name("Test".to_string()).unwrap();

    // Verify selector routing works
    let name_selector = ITestToken::nameCall::SELECTOR;
    let mut calldata = name_selector.to_vec();
    let result = token.call(&calldata, sender).unwrap();
    let name = String::abi_decode(&result.bytes).unwrap();
    assert_eq!(name, "Test");

    // Test multiple selectors to ensure routing is correct
    token._set_symbol("TST".to_string()).unwrap();
    let symbol_selector = ITestToken::symbolCall::SELECTOR;
    calldata = symbol_selector.to_vec();
    let result = token.call(&calldata, sender).unwrap();
    let symbol = String::abi_decode(&result.bytes).unwrap();
    assert_eq!(symbol, "TST");

    // Test view function selector
    let account = test_address(5);
    token._set_balances(account, U256::from(999)).unwrap();
    let balance_calldata = ITestToken::balanceOfCall { account }.abi_encode();
    let result = token.call(&balance_calldata, sender).unwrap();
    let balance = U256::abi_decode(&result.bytes).unwrap();
    assert_eq!(balance, U256::from(999));
}

#[test]
fn test_dispatcher_all_function_types_together() {
    // Comprehensive test exercising all function types in sequence
    let mut storage = HashMapStorageProvider::new(1);
    let addr = test_address(1);
    let mut token = TestToken::_new(addr, &mut storage);
    let alice = test_address(2);
    let bob = test_address(3);

    // Setup metadata
    token._set_name("Full Test".to_string()).unwrap();
    token._set_symbol("FULL".to_string()).unwrap();

    // 1. Check metadata
    let calldata = ITestToken::nameCall {}.abi_encode();
    let result = token.call(&calldata, alice).unwrap();
    assert_eq!(String::abi_decode(&result.bytes).unwrap(), "Full Test");

    // 2. Mint (mutate void)
    let calldata = ITestToken::mintCall {
        to: alice,
        amount: U256::from(1000),
    }
    .abi_encode();
    token.call(&calldata, alice).unwrap();

    // 3. Check balance (view)
    let calldata = ITestToken::balanceOfCall { account: alice }.abi_encode();
    let result = token.call(&calldata, alice).unwrap();
    assert_eq!(U256::abi_decode(&result.bytes).unwrap(), U256::from(1000));

    // 4. Approve (mutate returning bool)
    let calldata = ITestToken::approveCall {
        spender: bob,
        amount: U256::from(500),
    }
    .abi_encode();
    let result = token.call(&calldata, alice).unwrap();
    assert!(bool::abi_decode(&result.bytes).unwrap());

    // 5. Check allowance (view)
    let calldata = ITestToken::allowanceCall {
        owner: alice,
        spender: bob,
    }
    .abi_encode();
    let result = token.call(&calldata, alice).unwrap();
    assert_eq!(U256::abi_decode(&result.bytes).unwrap(), U256::from(500));

    // 6. Transfer (mutate returning bool)
    let calldata = ITestToken::transferCall {
        to: bob,
        amount: U256::from(300),
    }
    .abi_encode();
    let result = token.call(&calldata, alice).unwrap();
    assert!(bool::abi_decode(&result.bytes).unwrap());

    // 7. Verify final balances (view)
    let calldata = ITestToken::balanceOfCall { account: alice }.abi_encode();
    let result = token.call(&calldata, alice).unwrap();
    assert_eq!(U256::abi_decode(&result.bytes).unwrap(), U256::from(700));

    let calldata = ITestToken::balanceOfCall { account: bob }.abi_encode();
    let result = token.call(&calldata, alice).unwrap();
    assert_eq!(U256::abi_decode(&result.bytes).unwrap(), U256::from(300));

    // 8. Burn (mutate void)
    let calldata = ITestToken::burnCall {
        amount: U256::from(100),
    }
    .abi_encode();
    token.call(&calldata, alice).unwrap();

    // 9. Final balance check
    let calldata = ITestToken::balanceOfCall { account: alice }.abi_encode();
    let result = token.call(&calldata, alice).unwrap();
    assert_eq!(U256::abi_decode(&result.bytes).unwrap(), U256::from(600));
}

// ============================================================================
// Multi-Interface Tests
// ============================================================================

#[test]
fn test_multi_interface_contract() {
    // Test contract with multiple interfaces
    #[contract(ITestToken, IMetadata)]
    pub struct MultiInterfaceToken {
        pub name: String,
        pub symbol: String,
        #[slot(10)]
        #[map = "balanceOf"]
        pub balances: storage::Mapping<Address, U256>,
        #[slot(11)]
        #[map = "allowance"]
        pub allowances: storage::Mapping<Address, storage::Mapping<Address, U256>>,
        pub version: U256,
        pub owner: Address,
    }

    impl<S: storage::PrecompileStorageProvider> MultiInterfaceTokenCall for MultiInterfaceToken<'_, S> {
        // ITestToken methods (some auto-generated: name, symbol, balanceOf, allowance)
        fn decimals(&mut self) -> tempo_precompiles::error::Result<u8> {
            Ok(18)
        }

        fn transfer(
            &mut self,
            s: Address,
            to: Address,
            amount: U256,
        ) -> tempo_precompiles::error::Result<bool> {
            let balance = self._get_balances(s)?;
            if amount > balance {
                return Err(tempo_precompiles::error::TempoPrecompileError::Fatal(
                    "InsufficientBalance".to_string(),
                ));
            }
            self._set_balances(s, balance - amount)?;
            let to_balance = self._get_balances(to)?;
            self._set_balances(to, to_balance + amount)?;
            Ok(true)
        }

        fn approve(
            &mut self,
            s: Address,
            spender: Address,
            amount: U256,
        ) -> tempo_precompiles::error::Result<bool> {
            self._set_allowances(s, spender, amount)?;
            Ok(true)
        }

        fn mint(
            &mut self,
            _s: Address,
            to: Address,
            amount: U256,
        ) -> tempo_precompiles::error::Result<()> {
            let balance = self._get_balances(to)?;
            self._set_balances(to, balance + amount)?;
            Ok(())
        }

        fn burn(&mut self, s: Address, amount: U256) -> tempo_precompiles::error::Result<()> {
            let balance = self._get_balances(s)?;
            if amount > balance {
                return Err(tempo_precompiles::error::TempoPrecompileError::Fatal(
                    "InsufficientBalance".to_string(),
                ));
            }
            self._set_balances(s, balance - amount)?;
            Ok(())
        }

        // IMetadata methods (auto-generated: version, owner)
    }

    let mut storage = HashMapStorageProvider::new(1);
    let addr = test_address(1);
    let mut token = MultiInterfaceToken::_new(addr, &mut storage);
    let sender = test_address(2);

    // Test ITestToken interface methods
    token._set_name("Multi Token".to_string()).unwrap();
    token._set_symbol("MULTI".to_string()).unwrap();

    let calldata = ITestToken::nameCall {}.abi_encode();
    let result = token.call(&calldata, sender).unwrap();
    assert_eq!(String::abi_decode(&result.bytes).unwrap(), "Multi Token");

    let calldata = ITestToken::symbolCall {}.abi_encode();
    let result = token.call(&calldata, sender).unwrap();
    assert_eq!(String::abi_decode(&result.bytes).unwrap(), "MULTI");

    // Test IMetadata interface methods
    token._set_version(U256::from(1)).unwrap();
    token._set_owner(test_address(99)).unwrap();

    let calldata = IMetadata::versionCall {}.abi_encode();
    let result = token.call(&calldata, sender).unwrap();
    assert_eq!(U256::abi_decode(&result.bytes).unwrap(), U256::from(1));

    let calldata = IMetadata::ownerCall {}.abi_encode();
    let result = token.call(&calldata, sender).unwrap();
    assert_eq!(
        Address::abi_decode(&result.bytes).unwrap(),
        test_address(99)
    );

    // Test that both interfaces work together in the same dispatcher
    // Mint some tokens (ITestToken interface)
    let calldata = ITestToken::mintCall {
        to: sender,
        amount: U256::from(500),
    }
    .abi_encode();
    token.call(&calldata, sender).unwrap();

    // Check balance (ITestToken interface)
    let calldata = ITestToken::balanceOfCall { account: sender }.abi_encode();
    let result = token.call(&calldata, sender).unwrap();
    assert_eq!(U256::abi_decode(&result.bytes).unwrap(), U256::from(500));

    // Verify version still accessible (IMetadata interface)
    let calldata = IMetadata::versionCall {}.abi_encode();
    let result = token.call(&calldata, sender).unwrap();
    assert_eq!(U256::abi_decode(&result.bytes).unwrap(), U256::from(1));
}

#[test]
fn test_error_constructors() {
    sol! {
        interface IErrorTest {
            function dummy() external;
            error SimpleError();
            error ParameterizedError(uint256 code, address addr);
        }
    }

    use IErrorTest::IErrorTestErrors as ErrorTestError;

    #[contract(IErrorTest)]
    pub struct ErrorTestContract {
        pub dummy: U256,
    }

    impl<S: storage::PrecompileStorageProvider> ErrorTestContractCall for ErrorTestContract<'_, S> {
        fn dummy(&mut self, _s: Address) -> error::Result<()> {
            Ok(())
        }
    }

    // Test parameterless error constructor
    let error = ErrorTestError::simple_error();
    assert!(matches!(
        error,
        ErrorTestError::SimpleError(IErrorTest::SimpleError {})
    ));

    // Test parameterized error constructor
    let code = U256::from(42);
    let addr = test_address(5);
    let error = ErrorTestError::parameterized_error(code, addr);

    match error {
        ErrorTestError::ParameterizedError(e) => {
            assert_eq!(e.code, code);
            assert_eq!(e.addr, addr);
        }
        _ => panic!("Expected ParameterizedError"),
    }

    // If this compiles, it proves the constructor is const
    const _ERROR: ErrorTestError = ErrorTestError::simple_error();
}
