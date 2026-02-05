//! Test utilities for precompile dispatch testing

#[cfg(any(test, feature = "test-utils"))]
use crate::error::TempoPrecompileError;
use crate::{
    PATH_USD_ADDRESS, Precompile, Result,
    storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider},
    tip20::{self, ITIP20, TIP20Token},
    tip20_factory::{ITIP20Factory::traits::*, TIP20Factory},
};
use alloy::{
    primitives::{Address, B256, U256},
    sol_types::SolError,
};
use revm::precompile::PrecompileError;
#[cfg(any(test, feature = "test-utils"))]
use tempo_contracts::precompiles::TIP20Error;
use tempo_contracts::precompiles::{TIP20_FACTORY_ADDRESS, UnknownFunctionSelector};

/// Checks that all selectors in an interface have dispatch handlers.
///
/// Calls each selector with dummy parameters and checks for "Unknown function selector" errors.
/// Returns unsupported selectors as `(selector_bytes, function_name)` tuples.
pub fn check_selector_coverage<P: Precompile>(
    precompile: &mut P,
    selectors: &[[u8; 4]],
    interface_name: &str,
    name_lookup: impl Fn([u8; 4]) -> Option<&'static str>,
) -> Vec<([u8; 4], &'static str)> {
    let mut unsupported_selectors = Vec::new();

    for selector in selectors.iter() {
        let mut calldata = selector.to_vec();
        // Add some dummy data for functions that require parameters
        calldata.extend_from_slice(&[0u8; 32]);

        let result = precompile.call(&calldata, Address::ZERO);

        // Check if we got "Unknown function selector" error (old format)
        let is_unsupported_old = matches!(&result,
            Err(PrecompileError::Other(msg)) if msg.contains("Unknown function selector")
        );

        // Check if we got "Unknown function selector" error (new format - ABI-encoded)
        let is_unsupported_new = if let Ok(output) = &result {
            output.reverted && UnknownFunctionSelector::abi_decode(&output.bytes).is_ok()
        } else {
            false
        };

        if (is_unsupported_old || is_unsupported_new)
            && let Some(name) = name_lookup(*selector)
        {
            unsupported_selectors.push((*selector, name));
        }
    }

    // Print unsupported selectors for visibility
    if !unsupported_selectors.is_empty() {
        eprintln!("Unsupported {interface_name} selectors:");
        for (selector, name) in &unsupported_selectors {
            eprintln!("  - {name} ({selector:?})");
        }
    }

    unsupported_selectors
}

/// Asserts that multiple selector coverage checks all pass (no unsupported selectors).
///
/// Takes an iterator of unsupported selector results and panics if any are found.
pub fn assert_full_coverage(results: impl IntoIterator<Item = Vec<([u8; 4], &'static str)>>) {
    let all_unsupported: Vec<_> = results
        .into_iter()
        .flat_map(|r| r.into_iter())
        .map(|(_, name)| name)
        .collect();

    assert!(
        all_unsupported.is_empty(),
        "Found {} unsupported selectors: {:?}",
        all_unsupported.len(),
        all_unsupported
    );
}

/// Helper to create a test storage provider with a random address
pub fn setup_storage() -> (HashMapStorageProvider, Address) {
    (HashMapStorageProvider::new(1), Address::random())
}

/// Setup mode - determines how the token is obtained.
#[derive(Default, Clone)]
#[cfg(any(test, feature = "test-utils"))]
enum Action {
    #[default]
    /// Ensure pathUSD (token 0) is deployed and configure it.
    PathUSD,

    /// Create and configure a new token using the TIP20Factory.
    CreateToken {
        name: &'static str,
        symbol: &'static str,
        currency: String,
    },
    /// Configure an existing token at the given address
    ConfigureToken { address: Address },
}

/// Helper for TIP20 token setup in tests.
///
/// Supports creating new tokens, configuring pathUSD, or modifying existing tokens.
/// Uses a chainable API for role grants, minting, approvals, and rewards.
///
/// # Examples
///
/// ```ignore
/// // Initialize and configure pathUSD
/// TIP20Setup::path_usd(admin)
///     .with_issuer(admin)
///     .apply()?;
///
/// // Create a new token
/// let token = TIP20Setup::new("MyToken", "MTK", admin)
///     .with_mint(user, amount)
///     .apply()?;
///
/// // Configure an existing token
/// TIP20Setup::from_address(token_address, admin)
///     .with_mint(user, amount)
///     .apply()?;
/// ```
#[derive(Default)]
#[cfg(any(test, feature = "test-utils"))]
pub struct TIP20Setup {
    action: Action,
    quote_token: Option<Address>,
    admin: Option<Address>,
    salt: Option<B256>,
    roles: Vec<(Address, B256)>,
    mints: Vec<(Address, U256)>,
    approvals: Vec<(Address, Address, U256)>,
    reward_opt_ins: Vec<Address>,
    distribute_rewards: Vec<U256>,
    clear_events: bool,
}

#[cfg(any(test, feature = "test-utils"))]
impl TIP20Setup {
    /// Configure pathUSD (token 0).
    pub fn path_usd(admin: Address) -> Self {
        Self {
            action: Action::PathUSD,
            admin: Some(admin),
            ..Default::default()
        }
    }

    /// Create a new token via factory. Ensures that `pathUSD` and `TIP20Factory` are initialized.
    ///
    /// Defaults to `currency: "USD"`, `quote_token: pathUSD`
    pub fn create(name: &'static str, symbol: &'static str, admin: Address) -> Self {
        Self {
            action: Action::CreateToken {
                name,
                symbol,
                currency: "USD".into(),
            },
            admin: Some(admin),
            ..Default::default()
        }
    }

    /// Configure an existing token at the given address.
    pub fn config(address: Address) -> Self {
        Self {
            action: Action::ConfigureToken { address },
            ..Default::default()
        }
    }

    /// Clear the emitted events of the token after setup.
    ///
    /// SAFETY: it is the caller's responsibility to ensure the test uses `HashMapStorageProvider`.
    pub fn clear_events(mut self) -> Self {
        self.clear_events = true;
        self
    }

    /// Set the token currency (default: "USD"). Only applies to new tokens.
    pub fn currency(mut self, currency: impl Into<String>) -> Self {
        if let Action::CreateToken {
            currency: ref mut c,
            ..
        } = self.action
        {
            *c = currency.into();
        }
        self
    }

    /// Set a custom quote token (default: pathUSD).
    pub fn quote_token(mut self, token: Address) -> Self {
        self.quote_token = Some(token);
        self
    }

    /// Set a custom salt for token address derivation (default: random).
    pub fn with_salt(mut self, salt: B256) -> Self {
        self.salt = Some(salt);
        self
    }

    /// Set the admin address explicitly. Required for `config()` when using `with_mint()`.
    pub fn with_admin(mut self, admin: Address) -> Self {
        self.admin = Some(admin);
        self
    }

    /// Grant ISSUER_ROLE to an account.
    pub fn with_issuer(self, account: Address) -> Self {
        self.with_role(account, *tip20::ISSUER_ROLE)
    }

    /// Grant an arbitrary role to an account.
    pub fn with_role(mut self, account: Address, role: B256) -> Self {
        self.roles.push((account, role));
        self
    }

    /// Mint tokens to an address after creation.
    ///
    /// Note: Requires ISSUER_ROLE on admin (use `with_issuer(admin)`).
    pub fn with_mint(mut self, to: Address, amount: U256) -> Self {
        self.mints.push((to, amount));
        self
    }

    /// Set an approval from owner to spender.
    pub fn with_approval(mut self, owner: Address, spender: Address, amount: U256) -> Self {
        self.approvals.push((owner, spender, amount));
        self
    }

    /// Opt a user into rewards (sets reward recipient to themselves).
    pub fn with_reward_opt_in(mut self, user: Address) -> Self {
        self.reward_opt_ins.push(user);
        self
    }

    /// Distribute rewards (requires tokens minted to admin first).
    pub fn with_reward(mut self, amount: U256) -> Self {
        self.distribute_rewards.push(amount);
        self
    }

    /// Initialize pathUSD if needed and return it.
    fn path_usd_inner(&self) -> Result<TIP20Token> {
        if is_initialized(PATH_USD_ADDRESS) {
            return TIP20Token::from_address(PATH_USD_ADDRESS);
        }

        let admin = self
            .admin
            .expect("pathUSD is uninitialized and requires an admin");

        Self::factory()?.create_token_reserved_address(
            PATH_USD_ADDRESS,
            "pathUSD",
            "pathUSD",
            "USD",
            Address::ZERO,
            admin,
        )?;

        TIP20Token::from_address(PATH_USD_ADDRESS)
    }

    /// Initialize the TIP20 factory if needed.
    pub fn factory() -> Result<TIP20Factory> {
        let mut factory = TIP20Factory::new();
        if !is_initialized(TIP20_FACTORY_ADDRESS) {
            factory.initialize()?;
        }
        Ok(factory)
    }

    /// Apply the configuration, returning just the TIP20Token.
    pub fn apply(self) -> Result<TIP20Token> {
        let mut token = match self.action.clone() {
            Action::PathUSD => self.path_usd_inner()?,
            Action::CreateToken {
                name,
                symbol,
                currency,
            } => {
                let mut factory = Self::factory()?;
                self.path_usd_inner()?;

                let admin = self.admin.expect("initializing a token requires an admin");
                let quote = self.quote_token.unwrap_or(PATH_USD_ADDRESS);
                let salt = self.salt.unwrap_or_else(B256::random);
                let token_address = factory.create_token(
                    admin,
                    name.to_string(),
                    symbol.to_string(),
                    currency,
                    quote,
                    admin,
                    salt,
                )?;
                TIP20Token::from_address(token_address)?
            }
            Action::ConfigureToken { address } => {
                assert!(
                    is_initialized(address),
                    "token not initialized, use `fn create` instead"
                );
                TIP20Token::from_address(address)?
            }
        };

        // Apply roles
        for (account, role) in self.roles {
            token.grant_role_internal(account, role)?;
        }

        // Apply mints
        for (to, amount) in self.mints {
            let admin = self.admin.unwrap_or_else(|| {
                get_tip20_admin(token.address()).expect("unable to get token admin")
            });
            token.mint(admin, ITIP20::mintCall { to, amount })?;
        }

        // Apply approvals
        for (owner, spender, amount) in self.approvals {
            token.approve(owner, ITIP20::approveCall { spender, amount })?;
        }

        // Apply reward opt-ins
        for user in self.reward_opt_ins {
            token.set_reward_recipient(user, ITIP20::setRewardRecipientCall { recipient: user })?;
        }

        // Distribute rewards
        for amount in self.distribute_rewards {
            let admin = self.admin.unwrap_or_else(|| {
                get_tip20_admin(token.address()).expect("unable to get token admin")
            });
            token.distribute_reward(admin, ITIP20::distributeRewardCall { amount })?;
        }

        if self.clear_events {
            token.clear_emitted_events();
        }

        Ok(token)
    }

    /// Apply the configuration, and expect it to fail with the given error.
    pub fn expect_err(self, expected: TempoPrecompileError) {
        let result = self.apply();
        assert!(result.is_err_and(|err| err == expected));
    }

    /// Apply the configuration, and expect it to fail with the given TIP20 error.
    pub fn expect_tip20_err(self, expected: TIP20Error) {
        let result = self.apply();
        assert!(result.is_err_and(|err| err == TempoPrecompileError::TIP20(expected)));
    }
}

/// Checks if a contract at the given address has bytecode deployed.
#[cfg(any(test, feature = "test-utils"))]
fn is_initialized(address: Address) -> bool {
    crate::storage::StorageCtx.has_bytecode(address)
}

#[cfg(any(test, feature = "test-utils"))]
fn get_tip20_admin(token: Address) -> Option<Address> {
    use alloy::{primitives::Log, sol_types::SolEvent};
    use tempo_contracts::precompiles::ITIP20Factory;

    let events = StorageCtx.get_events(TIP20_FACTORY_ADDRESS);
    for log_data in events {
        let log = Log::new_unchecked(
            TIP20_FACTORY_ADDRESS,
            log_data.topics().to_vec(),
            log_data.data.clone(),
        );
        if let Ok(event) = ITIP20Factory::TokenCreated::decode_log(&log)
            && event.token == token
        {
            return Some(event.admin);
        }
    }

    None
}

/// Test helper function for constructing EVM words from hex string literals.
///
/// Takes an array of hex strings (with or without "0x" prefix), concatenates
/// them left-to-right, left-pads with zeros to 32 bytes, and returns a U256.
///
/// # Example
/// ```ignore
/// let word = gen_word_from(&[
///     "0x2a",                                        // 1 byte
///     "0x1111111111111111111111111111111111111111",  // 20 bytes
///     "0x01",                                        // 1 byte
/// ]);
/// // Produces: [10 zeros] [0x2a] [20 bytes of 0x11] [0x01]
/// ```
pub fn gen_word_from(values: &[&str]) -> U256 {
    let mut bytes = Vec::new();

    for value in values {
        let hex_str = value.strip_prefix("0x").unwrap_or(value);

        // Parse hex string to bytes
        assert!(
            hex_str.len() % 2 == 0,
            "Hex string '{value}' has odd length"
        );

        for i in (0..hex_str.len()).step_by(2) {
            let byte_str = &hex_str[i..i + 2];
            let byte = u8::from_str_radix(byte_str, 16)
                .unwrap_or_else(|e| panic!("Invalid hex in '{value}': {e}"));
            bytes.push(byte);
        }
    }

    assert!(
        bytes.len() <= 32,
        "Total bytes ({}) exceed 32-byte slot limit",
        bytes.len()
    );

    // Left-pad with zeros to 32 bytes
    let mut slot_bytes = [0u8; 32];
    let start_idx = 32 - bytes.len();
    slot_bytes[start_idx..].copy_from_slice(&bytes);

    U256::from_be_bytes(slot_bytes)
}
