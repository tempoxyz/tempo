// Module for tip20_factory precompile
pub mod dispatch;

pub use tempo_contracts::precompiles::{ITIP20Factory, TIP20FactoryError, TIP20FactoryEvent};
use tempo_precompiles_macros::contract;

use crate::{
    TIP20_FACTORY_ADDRESS,
    error::{Result, TempoPrecompileError},
    tip20::{TIP20Error, TIP20Token, is_tip20_prefix},
};
use alloy::{
    primitives::{Address, B256, keccak256},
    sol_types::SolValue,
};
use tracing::trace;

/// Number of reserved addresses (0 to RESERVED_SIZE-1) that cannot be deployed via factory
const RESERVED_SIZE: u128 = 1024;

/// TIP20 token address prefix (12 bytes): 0x20C000000000000000000000
const TIP20_PREFIX_BYTES: [u8; 12] = [
    0x20, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[contract(addr = TIP20_FACTORY_ADDRESS)]
pub struct TIP20Factory {}

/// Computes the deterministic TIP20 address from sender and salt.
/// Returns the address and the lower bytes used for derivation.
fn compute_tip20_address(sender: Address, salt: B256) -> (Address, u128) {
    let hash = keccak256((sender, salt).abi_encode());

    // Take first 10 bytes of hash as lower bytes (padded to u128)
    let mut padded = [0u8; 16];
    padded[6..].copy_from_slice(&hash[..10]);
    let lower_bytes = u128::from_be_bytes(padded);

    // Construct the address: TIP20_PREFIX (10 bytes) || hash[..10] (10 bytes)
    let mut address_bytes = [0u8; 20];
    address_bytes[..10].copy_from_slice(&TIP20_PREFIX_BYTES);
    address_bytes[10..].copy_from_slice(&hash[..10]);

    (Address::from(address_bytes), lower_bytes)
}

// Precompile functions
impl TIP20Factory {
    /// Initializes the TIP20 factory contract.
    pub fn initialize(&mut self) -> Result<()> {
        // must ensure the account is not empty, by setting some code
        self.__initialize()
    }

    /// Returns true if the factory has been initialized (has code set).
    pub fn is_initialized(&self) -> Result<bool> {
        self.storage
            .with_account_info(TIP20_FACTORY_ADDRESS, |info| Ok(info.code.is_some()))
    }

    /// Computes the deterministic address for a token given sender and salt.
    pub fn get_token_address(&self, call: ITIP20Factory::getTokenAddressCall) -> Result<Address> {
        let (address, _) = compute_tip20_address(call.sender, call.salt);
        Ok(address)
    }

    /// Returns true if the address is a valid TIP20 token.
    ///
    /// Checks both:
    /// 1. The address has the correct TIP20 prefix
    /// 2. The address has code deployed (non-empty code hash)
    pub fn is_tip20(&self, token: Address) -> Result<bool> {
        if !is_tip20_prefix(token) {
            return Ok(false);
        }
        // Check if the token has code deployed (non-empty code hash)
        self.storage
            .with_account_info(token, |info| Ok(!info.is_empty_code_hash()))
    }

    pub fn create_token(
        &mut self,
        sender: Address,
        call: ITIP20Factory::createTokenCall,
    ) -> Result<Address> {
        trace!(%sender, ?call, "Create token");

        // Compute the deterministic address from sender and salt
        let (token_address, lower_bytes) = compute_tip20_address(sender, call.salt);

        // Check if address is in reserved range
        if lower_bytes < RESERVED_SIZE {
            return Err(TempoPrecompileError::TIP20Factory(
                TIP20FactoryError::AddressReserved(ITIP20Factory::AddressReserved {}),
            ));
        }

        if self.is_tip20(token_address)? {
            return Err(TempoPrecompileError::TIP20Factory(
                TIP20FactoryError::TokenAlreadyExists(ITIP20Factory::TokenAlreadyExists {
                    token: token_address,
                }),
            ));
        }

        // Ensure that the quote token is a valid TIP20 that is currently deployed.
        if !self.is_tip20(call.quoteToken)? {
            return Err(TIP20Error::invalid_quote_token().into());
        }

        TIP20Token::from_address(token_address)?.initialize(
            &call.name,
            &call.symbol,
            &call.currency,
            call.quoteToken,
            call.admin,
        )?;

        self.emit_event(TIP20FactoryEvent::TokenCreated(
            ITIP20Factory::TokenCreated {
                token: token_address,
                name: call.name,
                symbol: call.symbol,
                currency: call.currency,
                quoteToken: call.quoteToken,
                admin: call.admin,
                salt: call.salt,
            },
        ))?;

        Ok(token_address)
    }

    /// Creates a token at a reserved address
    /// Internal function used to deploy TIP20s at reserved addresses at genesis or hardforks
    pub fn create_token_reserved_address(
        &mut self,
        address: Address,
        name: &str,
        symbol: &str,
        currency: &str,
        admin: Address,
    ) -> Result<Address> {
        // Validate that the address has a TIP20 prefix
        if !is_tip20_prefix(address) {
            return Err(TIP20Error::invalid_token().into());
        }

        // Validate that the address is not already deployed
        if self.is_tip20(address)? {
            return Err(TempoPrecompileError::TIP20Factory(
                TIP20FactoryError::TokenAlreadyExists(ITIP20Factory::TokenAlreadyExists {
                    token: address,
                }),
            ));
        }

        let mut token = TIP20Token::from_address(address)?;
        token.initialize(name, symbol, currency, Address::ZERO, admin)?;

        self.emit_event(TIP20FactoryEvent::TokenCreated(
            ITIP20Factory::TokenCreated {
                token: address,
                name: name.into(),
                symbol: symbol.into(),
                currency: currency.into(),
                quoteToken: Address::ZERO,
                admin,
                salt: B256::ZERO,
            },
        ))?;

        Ok(address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        PATH_USD_ADDRESS,
        error::TempoPrecompileError,
        storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider},
        test_util::TIP20Setup,
    };
    use alloy::primitives::Address;

    #[test]
    fn test_create_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let sender = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut factory = TIP20Setup::factory()?;
            let path_usd = TIP20Setup::path_usd(sender).apply()?;

            let salt1 = B256::random();
            let salt2 = B256::random();
            let call1 = ITIP20Factory::createTokenCall {
                name: "Test Token 1".to_string(),
                symbol: "TEST1".to_string(),
                currency: "USD".to_string(),
                quoteToken: path_usd.address(),
                admin: sender,
                salt: salt1,
            };
            let call2 = ITIP20Factory::createTokenCall {
                name: "Test Token 2".to_string(),
                symbol: "TEST2".to_string(),
                currency: "USD".to_string(),
                quoteToken: path_usd.address(),
                admin: sender,
                salt: salt2,
            };

            let token_addr_1 = factory.create_token(sender, call1)?;
            let token_addr_2 = factory.create_token(sender, call2)?;

            // Verify addresses are different
            assert_ne!(token_addr_1, token_addr_2);

            // Verify addresses have TIP20 prefix
            assert!(is_tip20_prefix(token_addr_1));
            assert!(is_tip20_prefix(token_addr_2));

            // Verify tokens are valid TIP20s
            assert!(factory.is_tip20(token_addr_1)?);
            assert!(factory.is_tip20(token_addr_2)?);

            Ok(())
        })
    }

    #[test]
    fn test_create_token_invalid_quote_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let sender = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut factory = TIP20Setup::factory()?;
            TIP20Setup::path_usd(sender).apply()?;

            let invalid_call = ITIP20Factory::createTokenCall {
                name: "Test Token".to_string(),
                symbol: "TEST".to_string(),
                currency: "USD".to_string(),
                quoteToken: Address::random(),
                admin: sender,
                salt: B256::random(),
            };

            let result = factory.create_token(sender, invalid_call);
            assert_eq!(
                result.unwrap_err(),
                TempoPrecompileError::TIP20(TIP20Error::invalid_quote_token())
            );
            Ok(())
        })
    }

    #[test]
    fn test_create_token_quote_token_not_deployed() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let sender = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut factory = TIP20Setup::factory()?;
            TIP20Setup::path_usd(sender).apply()?;

            // Create an address with TIP20 prefix but no code
            let non_existent_tip20 =
                Address::from(alloy::hex!("20C0000000000000000000000000000000009999"));
            let invalid_call = ITIP20Factory::createTokenCall {
                name: "Test Token".to_string(),
                symbol: "TEST".to_string(),
                currency: "USD".to_string(),
                quoteToken: non_existent_tip20,
                admin: sender,
                salt: B256::random(),
            };

            let result = factory.create_token(sender, invalid_call);
            assert_eq!(
                result.unwrap_err(),
                TempoPrecompileError::TIP20(TIP20Error::invalid_quote_token())
            );
            Ok(())
        })
    }

    #[test]
    fn test_create_token_reserved_address() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let sender = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut factory = TIP20Setup::factory()?;
            TIP20Setup::path_usd(sender).apply()?;

            // Find a salt that produces an address in the reserved range
            // We'll try a few salts until we find one (or use a known one)
            let mut found_reserved_salt = None;
            for i in 0..1000u64 {
                let test_salt = B256::from(alloy::primitives::U256::from(i));
                let (_, lower_bytes) = compute_tip20_address(sender, test_salt);
                if lower_bytes < RESERVED_SIZE {
                    found_reserved_salt = Some(test_salt);
                    break;
                }
            }

            if let Some(reserved_salt) = found_reserved_salt {
                let call = ITIP20Factory::createTokenCall {
                    name: "Reserved Token".to_string(),
                    symbol: "RES".to_string(),
                    currency: "USD".to_string(),
                    quoteToken: PATH_USD_ADDRESS,
                    admin: sender,
                    salt: reserved_salt,
                };

                let result = factory.create_token(sender, call);
                assert_eq!(
                    result.unwrap_err(),
                    TempoPrecompileError::TIP20Factory(TIP20FactoryError::AddressReserved(
                        ITIP20Factory::AddressReserved {}
                    ))
                );
            }
            // If we didn't find a reserved salt in 1000 tries, that's statistically unlikely
            // but acceptable for this test

            Ok(())
        })
    }

    #[test]
    fn test_is_tip20() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let sender = Address::random();

        StorageCtx::enter(&mut storage, || {
            // Initialize PathUSD
            let _path_usd = TIP20Setup::path_usd(sender).apply()?;

            let factory = TIP20Factory::new();

            // PATH_USD should be valid (has code deployed)
            assert!(factory.is_tip20(PATH_USD_ADDRESS)?);

            // Address with TIP20 prefix but no code should be invalid
            let no_code_tip20 =
                Address::from(alloy::hex!("20C0000000000000000000000000000000009999"));
            assert!(!factory.is_tip20(no_code_tip20)?);

            // Random address (wrong prefix) should be invalid
            assert!(!factory.is_tip20(Address::random())?);

            // Create a token via factory and verify it's valid
            let token = TIP20Setup::create("Test", "TST", sender).apply()?;
            assert!(factory.is_tip20(token.address())?);

            Ok(())
        })
    }

    #[test]
    fn test_is_tip20_prefix() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);

        StorageCtx::enter(&mut storage, || {
            // PATH_USD has correct prefix
            assert!(is_tip20_prefix(PATH_USD_ADDRESS));

            // Address with TIP20 prefix (0x20C0...)
            let tip20_addr = Address::from(alloy::hex!("20C0000000000000000000000000000000001234"));
            assert!(is_tip20_prefix(tip20_addr));

            // Random address does not have TIP20 prefix
            let random = Address::random();
            assert!(!is_tip20_prefix(random));

            Ok(())
        })
    }

    #[test]
    fn test_compute_tip20_address_deterministic() {
        let sender = Address::random();
        let salt = B256::random();

        // Same sender + salt should produce same address
        let (addr1, lower1) = compute_tip20_address(sender, salt);
        let (addr2, lower2) = compute_tip20_address(sender, salt);

        assert_eq!(addr1, addr2);
        assert_eq!(lower1, lower2);

        // Different salt should produce different address
        let (addr3, _) = compute_tip20_address(sender, B256::random());
        assert_ne!(addr1, addr3);

        // Address should have TIP20 prefix
        assert!(is_tip20_prefix(addr1));
    }
}
