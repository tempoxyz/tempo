// Module for tip20_factory precompile
pub mod abi;
mod dispatch;

pub use abi::{ITIP20Factory, ITIP20Factory::Interface};

use tempo_precompiles_macros::contract;

use crate::{
    PATH_USD_ADDRESS, TIP20_FACTORY_ADDRESS,
    error::Result,
    storage::ContractStorage,
    tip20::{ITIP20::traits::*, TIP20Error, TIP20Token, USD_CURRENCY, is_tip20_prefix},
};
use alloy::{
    primitives::{Address, B256, keccak256},
    sol_types::SolValue,
};
use tracing::trace;

/// Number of reserved addresses (0 to RESERVED_SIZE-1) that cannot be deployed via factory
const RESERVED_SIZE: u64 = 1024;

/// TIP20 token address prefix (12 bytes): 0x20C000000000000000000000
const TIP20_PREFIX_BYTES: [u8; 12] = [
    0x20, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[contract(addr = TIP20_FACTORY_ADDRESS, abi = ITIP20Factory, dispatch)]
pub struct TIP20Factory {}

/// Computes the deterministic TIP20 address from sender and salt.
/// Returns the address and the lower bytes used for derivation.
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn compute_tip20_address(sender: Address, salt: B256) -> (Address, u64) {
    let hash = keccak256((sender, salt).abi_encode());

    // Take first 8 bytes of hash as lower bytes
    let mut padded = [0u8; 8];
    padded.copy_from_slice(&hash[..8]);
    let lower_bytes = u64::from_be_bytes(padded);

    // Construct the address: TIP20_PREFIX (12 bytes) || hash[..8] (8 bytes)
    let mut address_bytes = [0u8; 20];
    address_bytes[..12].copy_from_slice(&TIP20_PREFIX_BYTES);
    address_bytes[12..].copy_from_slice(&hash[..8]);

    (Address::from(address_bytes), lower_bytes)
}

// Precompile functions
impl TIP20Factory {
    /// Initializes the TIP20 factory contract.
    pub fn initialize(&mut self) -> Result<()> {
        // must ensure the account is not empty, by setting some code
        self.__initialize()
    }
}

impl ITIP20Factory::Interface for TIP20Factory {
    /// Returns true if the address is a valid TIP20 token.
    ///
    /// Checks both:
    /// 1. The address has the correct TIP20 prefix
    /// 2. The address has been initialized (code deployed)
    fn is_tip20(&self, token: Address) -> Result<bool> {
        if !is_tip20_prefix(token) {
            return Ok(false);
        }
        // Check if the token has code deployed (non-empty code hash)
        TIP20Token::from_address_unchecked(token).is_initialized()
    }

    /// Computes the deterministic address for a token given sender and salt.
    /// Reverts if the computed address would be in the reserved range.
    fn get_token_address(&self, sender: Address, salt: B256) -> Result<Address> {
        let (address, lower_bytes) = compute_tip20_address(sender, salt);

        // Check if address would be in reserved range
        if lower_bytes < RESERVED_SIZE {
            return Err(TIP20FactoryError::address_reserved().into());
        }

        Ok(address)
    }

    /// Creates a new TIP20 token at a deterministic address.
    fn create_token(
        &mut self,
        msg_sender: Address,
        name: String,
        symbol: String,
        currency: String,
        quote_token: Address,
        admin: Address,
        salt: B256,
    ) -> Result<Address> {
        trace!(%msg_sender, %name, %symbol, %currency, %quote_token, %admin, %salt, "Create token");

        // Compute the deterministic address from sender and salt
        let (token_address, lower_bytes) = compute_tip20_address(msg_sender, salt);

        if self.is_tip20(token_address)? {
            return Err(TIP20FactoryError::token_already_exists(token_address).into());
        }

        // Ensure that the quote token is a valid TIP20 that is currently deployed.
        if !self.is_tip20(quote_token)? {
            return Err(TIP20Error::invalid_quote_token().into());
        }

        // If token is USD, its quote token must also be USD
        if currency == USD_CURRENCY
            && TIP20Token::from_address(quote_token)?.currency()? != USD_CURRENCY
        {
            return Err(TIP20Error::invalid_quote_token().into());
        }

        // Check if address is in reserved range
        if lower_bytes < RESERVED_SIZE {
            return Err(TIP20FactoryError::address_reserved().into());
        }

        TIP20Token::from_address(token_address)?.initialize(
            msg_sender,
            &name,
            &symbol,
            &currency,
            quote_token,
            admin,
        )?;

        self.emit_event(TIP20FactoryEvent::token_created(
            token_address,
            name,
            symbol,
            currency,
            quote_token,
            admin,
            salt,
        ))?;

        Ok(token_address)
    }
}

impl TIP20Factory {
    /// Creates a new TIP20 token at a reserved address.
    /// Internal function used to deploy TIP20s at reserved addresses at genesis or hardforks.
    pub fn create_token_reserved_address(
        &mut self,
        address: Address,
        name: &str,
        symbol: &str,
        currency: &str,
        quote_token: Address,
        admin: Address,
    ) -> Result<Address> {
        // Validate that the address has a TIP20 prefix
        if !is_tip20_prefix(address) {
            return Err(TIP20Error::invalid_token().into());
        }

        // Validate that the address is not already deployed
        if self.is_tip20(address)? {
            return Err(TIP20FactoryError::token_already_exists(address).into());
        }

        // quote_token must be address(0) or a valid TIP20
        if !quote_token.is_zero() {
            // pathUSD must set address(0) as the quote token
            // or the tip20 must be a valid deployed token
            if address == PATH_USD_ADDRESS || !self.is_tip20(quote_token)? {
                return Err(TIP20Error::invalid_quote_token().into());
            }
            // If token is USD, its quote token must also be USD
            if currency == USD_CURRENCY
                && TIP20Token::from_address(quote_token)?.currency()? != USD_CURRENCY
            {
                return Err(TIP20Error::invalid_quote_token().into());
            }
        }

        // Validate that the address is within the reserved range
        // Reserved addresses have their last 8 bytes represent a value < RESERVED_SIZE
        let mut padded = [0u8; 8];
        padded.copy_from_slice(&address.as_slice()[12..]);
        let lower_bytes = u64::from_be_bytes(padded);
        if lower_bytes >= RESERVED_SIZE {
            return Err(TIP20FactoryError::address_not_reserved().into());
        }

        let mut token = TIP20Token::from_address(address)?;
        token.initialize(admin, name, symbol, currency, quote_token, admin)?;

        self.emit_event(TIP20FactoryEvent::token_created(
            address,
            name.into(),
            symbol.into(),
            currency.into(),
            quote_token,
            admin,
            B256::ZERO,
        ))?;

        Ok(address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        PATH_USD_ADDRESS,
        storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider},
        test_util::TIP20Setup,
    };
    use alloy::primitives::{Address, address};

    #[test]
    fn test_is_initialized() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);

        StorageCtx::enter(&mut storage, || {
            let mut factory = TIP20Factory::new();

            // Factory should not be initialized before initialize() call
            assert!(!factory.is_initialized()?);

            // After initialize(), factory should be initialized
            factory.initialize()?;
            assert!(factory.is_initialized()?);

            // Creating a new handle should still see initialized state
            let factory2 = TIP20Factory::new();
            assert!(factory2.is_initialized()?);

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
    fn test_is_tip20() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let sender = Address::random();

        StorageCtx::enter(&mut storage, || {
            // Initialize pathUSD
            let _path_usd = TIP20Setup::path_usd(sender).apply()?;

            let factory = TIP20Factory::new();

            // PATH_USD should be valid (has code deployed)
            assert!(factory.is_tip20(PATH_USD_ADDRESS)?);

            // Address with TIP20 prefix but no code should be invalid
            let no_code_tip20 = address!("20C0000000000000000000000000000000000002");
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
    fn test_get_token_address() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);

        StorageCtx::enter(&mut storage, || {
            let factory = TIP20Factory::new();
            let sender = Address::random();
            let salt = B256::random();

            // get_token_address should return same address as compute_tip20_address
            let address = factory.get_token_address(sender, salt)?;
            let (expected, _) = compute_tip20_address(sender, salt);
            assert_eq!(address, expected);

            // Calling with same params should be deterministic
            assert_eq!(factory.get_token_address(sender, salt)?, address);

            Ok(())
        })
    }

    #[test]
    fn test_compute_tip20_address_deterministic() {
        let sender1 = Address::random();
        let sender2 = Address::random();
        let salt1 = B256::random();
        let salt2 = B256::random();

        let (addr0, lower0) = compute_tip20_address(sender1, salt1);
        let (addr1, lower1) = compute_tip20_address(sender1, salt1);
        assert_eq!(addr0, addr1);
        assert_eq!(lower0, lower1);

        // Same salt with different senders should produce different addresses
        let (addr2, lower2) = compute_tip20_address(sender1, salt1);
        let (addr3, lower3) = compute_tip20_address(sender2, salt1);
        assert_ne!(addr2, addr3);
        assert_ne!(lower2, lower3);

        // Same sender with different salts should produce different addresses
        let (addr4, lower4) = compute_tip20_address(sender1, salt1);
        let (addr5, lower5) = compute_tip20_address(sender1, salt2);
        assert_ne!(addr4, addr5);
        assert_ne!(lower4, lower5);

        // All addresses should have TIP20 prefix
        assert!(is_tip20_prefix(addr1));
        assert!(is_tip20_prefix(addr2));
        assert!(is_tip20_prefix(addr3));
        assert!(is_tip20_prefix(addr4));
        assert!(is_tip20_prefix(addr5));
    }

    #[test]
    fn test_create_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let sender = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut factory = TIP20Setup::factory()?;
            let path_usd = TIP20Setup::path_usd(sender).apply()?;
            factory.clear_emitted_events();

            let salt1 = B256::random();
            let salt2 = B256::random();

            let token_addr_1 = factory.create_token(
                sender,
                "Test Token 1".to_string(),
                "TEST1".to_string(),
                "USD".to_string(),
                path_usd.address(),
                sender,
                salt1,
            )?;
            let token_addr_2 = factory.create_token(
                sender,
                "Test Token 2".to_string(),
                "TEST2".to_string(),
                "USD".to_string(),
                path_usd.address(),
                sender,
                salt2,
            )?;

            // Verify addresses are different
            assert_ne!(token_addr_1, token_addr_2);

            // Verify addresses have TIP20 prefix
            assert!(is_tip20_prefix(token_addr_1));
            assert!(is_tip20_prefix(token_addr_2));

            // Verify tokens are valid TIP20s
            assert!(factory.is_tip20(token_addr_1)?);
            assert!(factory.is_tip20(token_addr_2)?);

            // Verify event emission
            factory.assert_emitted_events(vec![
                TIP20FactoryEvent::token_created(
                    token_addr_1,
                    "Test Token 1".into(),
                    "TEST1".into(),
                    "USD".into(),
                    path_usd.address(),
                    sender,
                    salt1,
                ),
                TIP20FactoryEvent::token_created(
                    token_addr_2,
                    "Test Token 2".into(),
                    "TEST2".into(),
                    "USD".into(),
                    path_usd.address(),
                    sender,
                    salt2,
                ),
            ]);

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

            let result = factory.create_token(
                sender,
                "Test Token".to_string(),
                "TEST".to_string(),
                "USD".to_string(),
                Address::random(),
                sender,
                B256::random(),
            );
            assert_eq!(
                result.unwrap_err(),
                TIP20Error::invalid_quote_token().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_create_token_usd_with_non_usd_quote() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let sender = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut factory = TIP20Setup::factory()?;
            let _path_usd = TIP20Setup::path_usd(sender).apply()?;
            let eur_token = TIP20Setup::create("EUR Token", "EUR", sender)
                .currency("EUR")
                .apply()?;

            let result = factory.create_token(
                sender,
                "USD Token".to_string(),
                "USDT".to_string(),
                "USD".to_string(),
                eur_token.address(),
                sender,
                B256::random(),
            );
            assert_eq!(
                result.unwrap_err(),
                TIP20Error::invalid_quote_token().into()
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

            let result = factory.create_token(
                sender,
                "Test Token".to_string(),
                "TEST".to_string(),
                "USD".to_string(),
                non_existent_tip20,
                sender,
                B256::random(),
            );
            assert_eq!(
                result.unwrap_err(),
                TIP20Error::invalid_quote_token().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_create_token_already_deployed() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let sender = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut factory = TIP20Setup::factory()?;
            TIP20Setup::path_usd(sender).apply()?;

            let salt = B256::random();

            let token = factory.create_token(
                sender,
                "Test Token".to_string(),
                "TEST".to_string(),
                "USD".to_string(),
                PATH_USD_ADDRESS,
                sender,
                salt,
            )?;
            let result = factory.create_token(
                sender,
                "Test Token".to_string(),
                "TEST".to_string(),
                "USD".to_string(),
                PATH_USD_ADDRESS,
                sender,
                salt,
            );
            assert_eq!(
                result.unwrap_err(),
                TIP20FactoryError::token_already_exists(token).into()
            );

            Ok(())
        })
    }

    #[test]
    fn test_create_token_reserved_address_rejects_invalid_prefix() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut factory = TIP20Factory::new();
            factory.initialize()?;

            let result = factory.create_token_reserved_address(
                Address::random(), // No TIP20 prefix
                "Test",
                "TST",
                "USD",
                Address::ZERO,
                admin,
            );

            assert_eq!(result.unwrap_err(), TIP20Error::invalid_token().into());

            Ok(())
        })
    }

    #[test]
    fn test_create_token_reserved_address_rejects_already_deployed() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut factory = TIP20Factory::new();
            factory.initialize()?;

            factory.create_token_reserved_address(
                PATH_USD_ADDRESS,
                "pathUSD",
                "pathUSD",
                "USD",
                Address::ZERO,
                admin,
            )?;

            let result = factory.create_token_reserved_address(
                PATH_USD_ADDRESS,
                "pathUSD",
                "pathUSD",
                "USD",
                Address::ZERO,
                admin,
            );

            assert_eq!(
                result.unwrap_err(),
                TIP20FactoryError::token_already_exists(PATH_USD_ADDRESS).into()
            );

            Ok(())
        })
    }

    #[test]
    fn test_create_token_reserved_address_rejects_non_usd_quote_for_usd_token() -> eyre::Result<()>
    {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let eur_token = TIP20Setup::create("EUR Token", "EUR", admin)
                .currency("EUR")
                .apply()?;

            let mut factory = TIP20Factory::new();

            let result = factory.create_token_reserved_address(
                address!("20C0000000000000000000000000000000000001"), // reserved address
                "Test USD",
                "TUSD",
                "USD",
                eur_token.address(),
                admin,
            );

            assert_eq!(
                result.unwrap_err(),
                TIP20Error::invalid_quote_token().into()
            );

            Ok(())
        })
    }

    #[test]
    fn test_create_token_reserved_address_rejects_non_reserved_address() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let _path_usd = TIP20Setup::path_usd(admin).apply()?;
            let mut factory = TIP20Factory::new();

            // 0x9999 = 39321 > 1024 (RESERVED_SIZE)
            let non_reserved = address!("20C0000000000000000000000000000000009999");

            let result = factory.create_token_reserved_address(
                non_reserved,
                "Test",
                "TST",
                "USD",
                PATH_USD_ADDRESS,
                admin,
            );

            assert_eq!(
                result.unwrap_err(),
                TIP20FactoryError::address_not_reserved().into()
            );

            Ok(())
        })
    }

    #[test]
    fn test_create_token_reserved_address_requires_zero_addr_as_first_quote() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut factory = TIP20Factory::new();
            factory.initialize()?;

            // Try to create PATH_USD with a non-deployed TIP20 as quote_token
            let result = factory.create_token_reserved_address(
                PATH_USD_ADDRESS,
                "pathUSD",
                "pathUSD",
                "USD",
                address!("20C0000000000000000000000000000000000001"),
                admin,
            );
            assert_eq!(
                result.unwrap_err(),
                TIP20Error::invalid_quote_token().into()
            );

            // Only possible to deploy PATH_USD (the first token) without a quote token
            factory.create_token_reserved_address(
                PATH_USD_ADDRESS,
                "pathUSD",
                "pathUSD",
                "USD",
                Address::ZERO,
                admin,
            )?;

            Ok(())
        })
    }

    #[test]
    fn test_path_usd_requires_zero_quote_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut factory = TIP20Factory::new();
            factory.initialize()?;

            let other_usd = factory.create_token_reserved_address(
                address!("20C0000000000000000000000000000000000001"),
                "testUSD",
                "testUSD",
                "USD",
                Address::ZERO,
                admin,
            )?;

            let result = factory.create_token_reserved_address(
                PATH_USD_ADDRESS,
                "pathUSD",
                "pathUSD",
                "USD",
                other_usd,
                admin,
            );
            assert_eq!(
                result.unwrap_err(),
                TIP20Error::invalid_quote_token().into()
            );

            factory.create_token_reserved_address(
                PATH_USD_ADDRESS,
                "pathUSD",
                "pathUSD",
                "USD",
                Address::ZERO,
                admin,
            )?;

            assert!(TIP20Token::from_address(PATH_USD_ADDRESS)?.is_initialized()?);

            Ok(())
        })
    }

    #[test]
    fn test_compute_tip20_address_returns_non_default() {
        let sender = Address::random();
        let salt = B256::random();

        let (address, lower_bytes) = compute_tip20_address(sender, salt);

        // Address should NOT be default
        assert_ne!(address, Address::ZERO);

        // Address should have TIP20 prefix
        assert!(is_tip20_prefix(address));

        // Same inputs should produce same outputs (deterministic)
        let (address2, lower_bytes2) = compute_tip20_address(sender, salt);
        assert_eq!(address, address2);
        assert_eq!(lower_bytes, lower_bytes2);

        // Different sender should produce different outputs
        let (address3, _) = compute_tip20_address(Address::random(), salt);
        assert_ne!(address, address3);

        // Different salt should produce different outputs
        let (address4, _) = compute_tip20_address(sender, B256::random());
        assert_ne!(address, address4);
    }

    #[test]
    fn test_get_token_address_returns_correct_address() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let sender = Address::random();

        StorageCtx::enter(&mut storage, || {
            let factory = TIP20Factory::new();

            // Use a salt that produces non-reserved address
            let salt = B256::repeat_byte(0xFF);

            let address = factory.get_token_address(sender, salt)?;

            // Address should NOT be default
            assert_ne!(address, Address::ZERO);

            // Should have TIP20 prefix
            assert!(is_tip20_prefix(address));

            // Should be deterministic
            let address2 = factory.get_token_address(sender, salt)?;
            assert_eq!(address, address2);

            Ok(())
        })
    }

    #[test]
    fn test_is_tip20_returns_correct_boolean() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let factory = TIP20Factory::new();

            // Non-TIP20 address should return false
            let non_tip20 = Address::random();
            assert!(
                !factory.is_tip20(non_tip20)?,
                "Non-TIP20 address should return false"
            );

            // PATH_USD before deployment should return false (no code)
            assert!(
                !factory.is_tip20(PATH_USD_ADDRESS)?,
                "Undeployed TIP20 should return false"
            );

            // Deploy pathUSD
            TIP20Setup::path_usd(admin).apply()?;

            // Now PATH_USD should return true
            assert!(
                factory.is_tip20(PATH_USD_ADDRESS)?,
                "Deployed TIP20 should return true"
            );

            Ok(())
        })
    }

    #[test]
    fn test_get_token_address_reserved_boundary() {
        let sender = Address::ZERO;
        let salt = B256::repeat_byte(0xAB);
        let (_, lower_bytes) = compute_tip20_address(sender, salt);
        assert!(
            lower_bytes >= RESERVED_SIZE,
            "compute_tip20_address should produce non-reserved addresses for typical salts"
        );
    }
}
