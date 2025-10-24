pub mod roles;

pub use tempo_contracts::precompiles::{
    IRolesAuth, ITIP20, RolesAuthError, RolesAuthEvent, TIP20Error, TIP20Event,
};
use tempo_precompiles_macros::contract;

use crate::{
    LINKING_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
    storage::PrecompileStorageProvider,
    tip20::roles::{DEFAULT_ADMIN_ROLE, RolesAuthContract},
    tip20_factory::TIP20Factory,
    tip403_registry::{ITIP403Registry, TIP403Registry},
    tip4217_registry::{ITIP4217Registry, TIP4217Registry},
};
use alloy::{
    consensus::crypto::secp256k1 as eth_secp256k1,
    hex,
    primitives::{
        Address, B256, Bytes, FixedBytes, IntoLogData, Signature as EthSignature, U256, keccak256,
    },
    sol_types::{SolCall, SolStruct},
};
use revm::state::Bytecode;
use std::sync::LazyLock;
use tracing::trace;

/// TIP20 token address prefix (12 bytes for token ID encoding)
const TIP20_TOKEN_PREFIX: [u8; 12] = hex!("20C000000000000000000000");

/// TIP20 payment address prefix (14 bytes for payment classification)
/// Same as TIP20_TOKEN_PREFIX but extended to 14 bytes for payment classification
pub const TIP20_PAYMENT_PREFIX: [u8; 14] = hex!("20C0000000000000000000000000");

pub fn is_tip20(token: &Address) -> bool {
    token.as_slice().starts_with(&TIP20_TOKEN_PREFIX)
}

/// Converts a token ID to its corresponding contract address
/// Uses the pattern: TIP20_TOKEN_PREFIX ++ token_id
pub fn token_id_to_address(token_id: u64) -> Address {
    let mut address_bytes = [0u8; 20];
    address_bytes[..12].copy_from_slice(&TIP20_TOKEN_PREFIX);
    address_bytes[12..20].copy_from_slice(&token_id.to_be_bytes());
    Address::from(address_bytes)
}

pub fn address_to_token_id_unchecked(address: &Address) -> u64 {
    u64::from_be_bytes(address.as_slice()[12..20].try_into().unwrap())
}

#[contract(ITIP20, TIP20Error)]
pub struct TIP20Token {
    // Variables
    name: String,
    symbol: String,
    #[slot(3)]
    total_supply: U256,
    #[slot(4)]
    currency: String,
    #[slot(5)]
    #[map = "DOMAIN_SEPARATOR"]
    domain_separator: B256,
    #[slot(6)]
    transfer_policy_id: u64,
    #[slot(7)]
    supply_cap: U256,
    #[slot(8)]
    paused: bool,

    #[slot(9)]
    quote_token: Address,
    #[slot(16)]
    next_quote_token: Address,

    // Mappings
    #[slot(10)]
    #[map = "balanceOf"]
    balances: Mapping<Address, U256>,
    #[slot(11)]
    #[map = "allowance"]
    allowances: Mapping<Address, Mapping<Address, U256>>,
    #[slot(12)]
    nonces: Mapping<Address, U256>,
    #[slot(13)]
    salts: Mapping<Address, Mapping<FixedBytes<4>, bool>>,
}

// TODO(rusowsky): impl on `RolesAuthContract` as custom slots
const ROLES_BASE_SLOT: U256 = alloy::primitives::uint!(14_U256);
const ROLE_ADMIN_BASE_SLOT: U256 = alloy::primitives::uint!(15_U256);

pub static PAUSE_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"PAUSE_ROLE"));
pub static UNPAUSE_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"UNPAUSE_ROLE"));
pub static ISSUER_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"ISSUER_ROLE"));
pub static BURN_BLOCKED_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"BURN_BLOCKED_ROLE"));

impl<'a, S: PrecompileStorageProvider> TIP20TokenCall for TIP20Token<'a, S> {
    // Metadata functions with auto-generated getters:
    // name(), symbol(), totalsupply(), currency(), supplyCap(), paused(), transferPolicyId(), quoteToken(), nextQuoteToken(), nonces()

    fn decimals(&mut self) -> u8 {
        TIP4217Registry::default().get_currency_decimals(
            ITIP4217Registry::getCurrencyDecimalsCall {
                currency: self._get_currency(),
            },
        )
    }

    // View functions with auto-generated getters:
    // balanceOf(), allowance()

    // Admin functions
    fn change_transfer_policy_id(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::changeTransferPolicyIdCall,
    ) -> Result<(), TIP20Error> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;
        self._set_transfer_policy_id(call.newPolicyId);

        self.storage
            .emit_event(
                self.address,
                TIP20Event::TransferPolicyUpdate(ITIP20::TransferPolicyUpdate {
                    updater: *msg_sender,
                    newPolicyId: call.newPolicyId,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");
        Ok(())
    }

    fn set_supply_cap(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::setSupplyCapCall,
    ) -> Result<(), TIP20Error> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;
        if call.newSupplyCap < self._get_total_supply() {
            return Err(TIP20Error::supply_cap_exceeded());
        }
        self._set_supply_cap(call.newSupplyCap);

        self.storage
            .emit_event(
                self.address,
                TIP20Event::SupplyCapUpdate(ITIP20::SupplyCapUpdate {
                    updater: *msg_sender,
                    newSupplyCap: call.newSupplyCap,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");
        Ok(())
    }

    fn pause(&mut self, msg_sender: &Address, _call: ITIP20::pauseCall) -> Result<(), TIP20Error> {
        self.check_role(msg_sender, *PAUSE_ROLE)?;
        self._set_paused(true);

        self.storage
            .emit_event(
                self.address,
                TIP20Event::PauseStateUpdate(ITIP20::PauseStateUpdate {
                    updater: *msg_sender,
                    isPaused: true,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");
        Ok(())
    }

    fn unpause(
        &mut self,
        msg_sender: &Address,
        _call: ITIP20::unpauseCall,
    ) -> Result<(), TIP20Error> {
        self.check_role(msg_sender, *UNPAUSE_ROLE)?;
        self._set_paused(false);

        self.storage
            .emit_event(
                self.address,
                TIP20Event::PauseStateUpdate(ITIP20::PauseStateUpdate {
                    updater: *msg_sender,
                    isPaused: false,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");
        Ok(())
    }

    fn update_quote_token(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::updateQuoteTokenCall,
    ) -> Result<(), TIP20Error> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;

        // Verify the new quote token is a valid TIP20 token that has been deployed
        if !is_tip20(&call.newQuoteToken) {
            return Err(TIP20Error::invalid_quote_token());
        }

        let new_token_id = address_to_token_id_unchecked(&call.newQuoteToken);
        let factory_token_id_counter = TIP20Factory::new(self.storage)
            .token_id_counter()
            .to::<u64>();

        // Ensure the quote token has been deployed (token_id < counter)
        if new_token_id >= factory_token_id_counter {
            return Err(TIP20Error::invalid_quote_token());
        }

        self._set_next_quote_token(call.newQuoteToken);

        self.storage
            .emit_event(
                self.address,
                TIP20Event::UpdateQuoteToken(ITIP20::UpdateQuoteToken {
                    updater: *msg_sender,
                    newQuoteToken: call.newQuoteToken,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");
        Ok(())
    }

    fn finalize_quote_token_update(
        &mut self,
        msg_sender: &Address,
        _call: ITIP20::finalizeQuoteTokenUpdateCall,
    ) -> Result<(), TIP20Error> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;

        let next_quote_token = self._get_next_quote_token();

        // Check that this does not create a loop
        // Loop through quote tokens until we reach the root (LinkingUSD)
        let mut current = next_quote_token;
        while current != LINKING_USD_ADDRESS {
            if current == self.address {
                return Err(TIP20Error::invalid_quote_token());
            }

            let token_id = address_to_token_id_unchecked(&current);
            current = TIP20Token::new(token_id, self.storage)._get_quote_token();
        }

        // Update the quote token
        self._set_quote_token(next_quote_token);

        self.storage
            .emit_event(
                self.address,
                TIP20Event::QuoteTokenUpdateFinalized(ITIP20::QuoteTokenUpdateFinalized {
                    updater: *msg_sender,
                    newQuoteToken: next_quote_token,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");
        Ok(())
    }

    // Token operations
    /// Mints new tokens to specified address
    fn mint(&mut self, msg_sender: &Address, call: ITIP20::mintCall) -> Result<(), TIP20Error> {
        self._mint(msg_sender, call.to, call.amount)
    }

    /// Mints new tokens to specified address with memo attached
    fn mint_with_memo(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::mintWithMemoCall,
    ) -> Result<(), TIP20Error> {
        self._mint(msg_sender, call.to, call.amount)?;

        self.storage
            .emit_event(
                self.address,
                TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
                    from: *msg_sender,
                    to: call.to,
                    amount: call.amount,
                    memo: call.memo,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");

        Ok(())
    }

    /// Burns tokens from sender's balance and reduces total supply
    fn burn(&mut self, msg_sender: &Address, call: ITIP20::burnCall) -> Result<(), TIP20Error> {
        self._burn(msg_sender, call.amount)
    }

    /// Burns tokens from sender's balance with memo attached
    fn burn_with_memo(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::burnWithMemoCall,
    ) -> Result<(), TIP20Error> {
        self._burn(msg_sender, call.amount)?;

        self.storage
            .emit_event(
                self.address,
                TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
                    from: *msg_sender,
                    to: Address::ZERO,
                    amount: call.amount,
                    memo: call.memo,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");

        Ok(())
    }

    /// Burns tokens from blocked addresses that cannot transfer
    fn burn_blocked(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::burnBlockedCall,
    ) -> Result<(), TIP20Error> {
        self.check_role(msg_sender, *BURN_BLOCKED_ROLE)?;

        // Check if the address is blocked from transferring
        let transfer_policy_id = self._get_transfer_policy_id();
        let mut registry = TIP403Registry::new(self.storage);
        if registry.is_authorized(ITIP403Registry::isAuthorizedCall {
            policyId: transfer_policy_id,
            user: call.from,
        }) {
            // Only allow burning from addresses that are blocked from transferring
            return Err(TIP20Error::policy_forbids());
        }

        self._transfer(&call.from, &Address::ZERO, call.amount)?;

        let total_supply = self._get_total_supply();
        let new_supply = total_supply
            .checked_sub(call.amount)
            .ok_or(TIP20Error::insufficient_balance())?;
        self._set_total_supply(new_supply);

        self.storage
            .emit_event(
                self.address,
                TIP20Event::BurnBlocked(ITIP20::BurnBlocked {
                    from: call.from,
                    amount: call.amount,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");

        Ok(())
    }

    // Standard token functions
    fn approve(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::approveCall,
    ) -> Result<bool, TIP20Error> {
        self._set_allowances(*msg_sender, call.spender, call.amount);

        self.storage
            .emit_event(
                self.address,
                TIP20Event::Approval(ITIP20::Approval {
                    owner: *msg_sender,
                    spender: call.spender,
                    amount: call.amount,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");

        Ok(true)
    }

    fn transfer(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::transferCall,
    ) -> Result<bool, TIP20Error> {
        trace!(%msg_sender, ?call, "transferring TIP20");
        self.check_not_paused()?;
        self.check_not_token_address(&call.to)?;
        self.ensure_transfer_authorized(msg_sender, &call.to)?;
        self._transfer(msg_sender, &call.to, call.amount)?;
        Ok(true)
    }

    fn transfer_from(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::transferFromCall,
    ) -> Result<bool, TIP20Error> {
        self._transfer_from(msg_sender, call.from, call.to, call.amount)
    }

    /// Transfer from `from` to `to` address with memo attached
    fn transfer_from_with_memo(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::transferFromWithMemoCall,
    ) -> Result<bool, TIP20Error> {
        self._transfer_from(msg_sender, call.from, call.to, call.amount)?;

        self.storage
            .emit_event(
                self.address,
                TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
                    from: *msg_sender,
                    to: call.to,
                    amount: call.amount,
                    memo: call.memo,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");

        Ok(true)
    }

    fn permit(
        &mut self,
        _msg_sender: &Address,
        call: ITIP20::permitCall,
    ) -> Result<(), TIP20Error> {
        if U256::from(call.deadline) < self.storage.timestamp() {
            return Err(TIP20Error::expired());
        }

        // Get current nonce (increment after successful verification)
        let nonce = self._get_nonces(call.owner);

        // Recover address from signature
        let recovered_addr = {
            let digest = self.compute_permit_digest(
                call.owner,
                call.spender,
                call.value,
                nonce,
                U256::from(call.deadline),
            );

            let v_norm = if call.v >= 27 { call.v - 27 } else { call.v };
            if v_norm > 1 {
                return Err(TIP20Error::invalid_signature());
            }

            eth_secp256k1::recover_signer(
                &EthSignature::from_scalars_and_parity(call.r, call.s, v_norm == 1),
                digest,
            )
            .map_err(|_| TIP20Error::invalid_signature())?
        };

        // Verify recovered address matches owner
        if recovered_addr != call.owner {
            return Err(TIP20Error::invalid_signature());
        }

        // Increment nonce after successful verification
        self._set_nonces(call.owner, nonce + U256::ONE);

        self._set_allowances(call.owner, call.spender, call.value);

        self.storage
            .emit_event(
                self.address,
                TIP20Event::Approval(ITIP20::Approval {
                    owner: call.owner,
                    spender: call.spender,
                    amount: call.value,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");

        Ok(())
    }

    // TIP20 extension functions
    fn transfer_with_memo(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::transferWithMemoCall,
    ) -> Result<(), TIP20Error> {
        self.check_not_paused()?;
        self.check_not_token_address(&call.to)?;
        self.ensure_transfer_authorized(msg_sender, &call.to)?;

        self._transfer(msg_sender, &call.to, call.amount)?;

        self.storage
            .emit_event(
                self.address,
                TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
                    from: *msg_sender,
                    to: call.to,
                    amount: call.amount,
                    memo: call.memo,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");

        Ok(())
    }
}

// Internal and RolesAuth methods
impl<'a, S: PrecompileStorageProvider> TIP20Token<'a, S> {
    // Internal helper methods
    fn _mint(&mut self, msg_sender: &Address, to: Address, amount: U256) -> Result<(), TIP20Error> {
        self.check_role(msg_sender, *ISSUER_ROLE)?;
        let total_supply = self._get_total_supply();

        let new_supply = total_supply
            .checked_add(amount)
            .ok_or(TIP20Error::supply_cap_exceeded())?;

        let supply_cap = self._get_supply_cap();
        if new_supply > supply_cap {
            return Err(TIP20Error::supply_cap_exceeded());
        }

        self._set_total_supply(new_supply);

        let to_balance = self._get_balances(to);
        let new_to_balance: alloy::primitives::Uint<256, 4> = to_balance
            .checked_add(amount)
            .ok_or(TIP20Error::supply_cap_exceeded())?;
        self._set_balances(to, new_to_balance);

        self.storage
            .emit_event(
                self.address,
                TIP20Event::Transfer(ITIP20::Transfer {
                    from: Address::ZERO,
                    to,
                    amount,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");

        self.storage
            .emit_event(
                self.address,
                TIP20Event::Mint(ITIP20::Mint { to, amount }).into_log_data(),
            )
            .expect("TODO: handle error");

        Ok(())
    }

    fn _burn(&mut self, msg_sender: &Address, amount: U256) -> Result<(), TIP20Error> {
        self.check_role(msg_sender, *ISSUER_ROLE)?;

        self._transfer(msg_sender, &Address::ZERO, amount)?;

        let total_supply = self._get_total_supply();
        let new_supply = total_supply
            .checked_sub(amount)
            .ok_or(TIP20Error::insufficient_balance())?;
        self._set_total_supply(new_supply);

        self.storage
            .emit_event(
                self.address,
                TIP20Event::Burn(ITIP20::Burn {
                    from: *msg_sender,
                    amount,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");

        Ok(())
    }

    fn _transfer_from(
        &mut self,
        msg_sender: &Address,
        from: Address,
        to: Address,
        amount: U256,
    ) -> Result<bool, TIP20Error> {
        self.check_not_paused()?;
        self.check_not_token_address(&to)?;
        self.ensure_transfer_authorized(&from, &to)?;

        let allowed = self._get_allowances(from, *msg_sender);
        if amount > allowed {
            return Err(TIP20Error::insufficient_allowance());
        }

        if allowed != U256::MAX {
            let new_allowance = allowed
                .checked_sub(amount)
                .ok_or(TIP20Error::insufficient_allowance())?;
            self._set_allowances(from, *msg_sender, new_allowance);
        }

        self._transfer(&from, &to, amount)?;

        Ok(true)
    }

    /// Transfer from `from` to `to` address without approval requirement
    /// This function is not exposed via the public interface and should only be invoked by precompiles
    pub fn system_transfer_from(
        &mut self,
        from: Address,
        to: Address,
        amount: U256,
    ) -> Result<bool, TIP20Error> {
        self.check_not_paused()?;
        self.check_not_token_address(&to)?;
        self.ensure_transfer_authorized(&from, &to)?;

        self._transfer(&from, &to, amount)?;

        Ok(true)
    }
}

// Utility functions and internal helpers
impl<'a, S: PrecompileStorageProvider> TIP20Token<'a, S> {
    pub fn new(token_id: u64, storage: &'a mut S) -> Self {
        Self::_new(token_id_to_address(token_id), storage)
    }

    /// Only called internally from the factory, which won't try to re-initialize a token.
    pub fn initialize(
        &mut self,
        name: &str,
        symbol: &str,
        currency: &str,
        quote_token: Address,
        admin: &Address,
    ) -> Result<(), TIP20Error> {
        trace!(%name, address=%self.address, "Initializing token");

        // must ensure the account is not empty, by setting some code
        self.storage
            .set_code(
                self.address,
                Bytecode::new_legacy(Bytes::from_static(&[0xef])),
            )
            .expect("TODO: handle error");

        self._set_name(name.to_string());
        self._set_symbol(symbol.to_string());
        self._set_currency(currency.to_string());
        self._set_quote_token(quote_token);
        // Initialize nextQuoteToken to the same value as quoteToken
        self._set_next_quote_token(quote_token);

        // Validate currency via TIP4217 registry
        if self.decimals() == 0 {
            return Err(TIP20Error::invalid_currency());
        }

        // Set default values
        self._set_supply_cap(U256::MAX);
        self._set_transfer_policy_id(1); // Default "always-allow" policy

        // Initialize roles system and grant admin role
        let mut roles = self.get_roles_contract();
        roles.initialize();
        roles.grant_default_admin(admin);

        // Calculate DOMAIN_SEPARATOR
        let mut domain_data = Vec::new();
        domain_data.extend_from_slice(
            keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)").as_slice(),
        );
        domain_data.extend_from_slice(keccak256(name.as_bytes()).as_slice());
        domain_data.extend_from_slice(keccak256(b"1").as_slice());
        domain_data.extend_from_slice(&U256::from(self.storage.chain_id()).to_be_bytes::<32>());
        domain_data.extend_from_slice(self.address.as_slice());
        let domain_separator = keccak256(&domain_data);
        self._set_domain_separator(B256::from(domain_separator));

        Ok(())
    }

    // Helper to get a RolesAuthContract instance
    pub fn get_roles_contract(&mut self) -> RolesAuthContract<'_, S> {
        RolesAuthContract::new(
            self.storage,
            self.address,
            ROLES_BASE_SLOT,
            ROLE_ADMIN_BASE_SLOT,
        )
    }

    pub fn check_role(&mut self, account: &Address, role: B256) -> Result<(), TIP20Error> {
        let mut roles = self.get_roles_contract();
        roles
            .check_role(account, role)
            .map_err(|_| TIP20Error::policy_forbids())
    }

    pub fn has_role(&mut self, account: &Address, role: B256) -> bool {
        let mut roles = self.get_roles_contract();
        roles.has_role_internal(account, role)
    }

    fn check_not_paused(&mut self) -> Result<(), TIP20Error> {
        if self._get_paused() {
            return Err(TIP20Error::contract_paused());
        }
        Ok(())
    }

    fn check_not_token_address(&self, to: &Address) -> Result<(), TIP20Error> {
        // Don't allow sending to other precompiled tokens
        if is_tip20(to) {
            return Err(TIP20Error::invalid_recipient());
        }
        Ok(())
    }

    /// Checks if the transfer is authorized.
    pub fn is_transfer_authorized(&mut self, from: &Address, to: &Address) -> bool {
        let transfer_policy_id = self._get_transfer_policy_id();
        let mut registry = TIP403Registry::new(self.storage);

        // Check if 'from' address is authorized
        let from_authorized = registry.is_authorized(ITIP403Registry::isAuthorizedCall {
            policyId: transfer_policy_id,
            user: *from,
        });

        // Check if 'to' address is authorized
        let to_authorized = registry.is_authorized(ITIP403Registry::isAuthorizedCall {
            policyId: transfer_policy_id,
            user: *to,
        });

        from_authorized && to_authorized
    }

    /// Ensures the transfer is authorized.
    pub fn ensure_transfer_authorized(
        &mut self,
        from: &Address,
        to: &Address,
    ) -> Result<(), TIP20Error> {
        if !self.is_transfer_authorized(from, to) {
            return Err(TIP20Error::policy_forbids());
        }

        Ok(())
    }

    fn _transfer(&mut self, from: &Address, to: &Address, amount: U256) -> Result<(), TIP20Error> {
        let from_balance = self._get_balances(*from);

        if amount > from_balance {
            return Err(TIP20Error::insufficient_balance());
        }

        let new_from_balance = from_balance
            .checked_sub(amount)
            .ok_or(TIP20Error::insufficient_balance())?;

        self._set_balances(*from, new_from_balance);

        if *to != Address::ZERO {
            let to_balance = self._get_balances(*to);
            let new_to_balance = to_balance
                .checked_add(amount)
                .ok_or(TIP20Error::supply_cap_exceeded())?;
            self._set_balances(*to, new_to_balance);
        }

        self.storage
            .emit_event(
                self.address,
                TIP20Event::Transfer(ITIP20::Transfer {
                    from: *from,
                    to: *to,
                    amount,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");

        Ok(())
    }

    /// Transfers fee tokens from user to fee manager before transaction execution
    pub fn transfer_fee_pre_tx(&mut self, from: &Address, amount: U256) -> Result<(), TIP20Error> {
        let from_balance = self._get_balances(*from);
        if amount > from_balance {
            return Err(TIP20Error::insufficient_balance());
        }

        let new_from_balance = from_balance
            .checked_sub(amount)
            .ok_or(TIP20Error::insufficient_balance())?;

        self._set_balances(*from, new_from_balance);

        let to_balance = self._get_balances(TIP_FEE_MANAGER_ADDRESS);
        let new_to_balance = to_balance
            .checked_add(amount)
            .ok_or(TIP20Error::supply_cap_exceeded())?;
        self._set_balances(TIP_FEE_MANAGER_ADDRESS, new_to_balance);

        Ok(())
    }

    /// Refunds unused fee tokens to user and emits transfer event for gas amount used
    pub fn transfer_fee_post_tx(
        &mut self,
        to: &Address,
        refund: U256,
        actual_used: U256,
    ) -> Result<(), TIP20Error> {
        let from_balance = self._get_balances(TIP_FEE_MANAGER_ADDRESS);
        if refund > from_balance {
            return Err(TIP20Error::insufficient_balance());
        }

        let new_from_balance = from_balance
            .checked_sub(refund)
            .ok_or(TIP20Error::insufficient_balance())?;

        self._set_balances(TIP_FEE_MANAGER_ADDRESS, new_from_balance);

        let to_balance = self._get_balances(*to);
        let new_to_balance = to_balance
            .checked_add(refund)
            .ok_or(TIP20Error::supply_cap_exceeded())?;
        self._set_balances(*to, new_to_balance);

        self.storage
            .emit_event(
                self.address,
                TIP20Event::Transfer(ITIP20::Transfer {
                    from: *to,
                    to: TIP_FEE_MANAGER_ADDRESS,
                    amount: actual_used,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");

        Ok(())
    }

    fn compute_permit_digest(
        &mut self,
        owner: Address,
        spender: Address,
        value: U256,
        nonce: U256,
        deadline: U256,
    ) -> B256 {
        // Build EIP-712 struct hash for Permit
        let struct_hash = ITIP20::Permit {
            owner,
            spender,
            value,
            nonce,
            deadline,
        }
        .eip712_hash_struct();

        // EIP-191 digest: 0x19 0x01 || domainSeparator || structHash
        let mut digest_data = [0u8; 66];
        digest_data[0] = 0x19;
        digest_data[1] = 0x01;
        digest_data[2..34].copy_from_slice(self._get_domain_separator().as_slice());
        digest_data[34..66].copy_from_slice(struct_hash.as_slice());
        keccak256(digest_data)
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{Address, FixedBytes, U256, keccak256};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;

    use super::*;
    use crate::{
        DEFAULT_FEE_TOKEN, LINKING_USD_ADDRESS,
        storage::{
            ContractStorage, StorageType, hashmap::HashMapStorageProvider, slots::mapping_slot,
        },
        tip20_factory::ITIP20Factory,
    };

    /// Initialize a factory and create a single token
    fn setup_factory_with_token(
        storage: &mut HashMapStorageProvider,
        admin: &Address,
        name: &str,
        symbol: &str,
    ) -> u64 {
        let mut factory = TIP20Factory::new(storage);
        factory.initialize().unwrap();

        factory
            .create_token(
                admin,
                ITIP20Factory::createTokenCall {
                    name: name.to_string(),
                    symbol: symbol.to_string(),
                    currency: "USD".to_string(),
                    quoteToken: LINKING_USD_ADDRESS,
                    admin: *admin,
                },
            )
            .unwrap()
            .to::<u64>()
    }

    /// Create a token via an already-initialized factory
    fn create_token_via_factory(
        factory: &mut TIP20Factory<'_, HashMapStorageProvider>,
        admin: &Address,
        name: &str,
        symbol: &str,
        quote_token: Address,
    ) -> u64 {
        factory
            .create_token(
                admin,
                ITIP20Factory::createTokenCall {
                    name: name.to_string(),
                    symbol: symbol.to_string(),
                    currency: "USD".to_string(),
                    quoteToken: quote_token,
                    admin: *admin,
                },
            )
            .unwrap()
            .to::<u64>()
    }

    /// Setup factory and create a token with a separate quote token (both linking to LINKING_USD)
    fn setup_token_with_custom_quote_token(
        storage: &mut HashMapStorageProvider,
        admin: &Address,
    ) -> (u64, u64) {
        let mut factory = TIP20Factory::new(storage);
        factory.initialize().unwrap();

        let token_id =
            create_token_via_factory(&mut factory, admin, "Test", "TST", LINKING_USD_ADDRESS);
        let quote_token_id =
            create_token_via_factory(&mut factory, admin, "Quote", "QUOTE", LINKING_USD_ADDRESS);

        (token_id, quote_token_id)
    }

    #[test]
    fn test_permit_sets_allowance_and_increments_nonce() {
        // Setup token
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::from([0u8; 20]);
        let token_id = 1u64;
        let mut token = TIP20Token::new(token_id, &mut storage);
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        // Owner keypair
        let signer = PrivateKeySigner::random();
        let owner = signer.address();

        // Permit params
        let spender = Address::from([2u8; 20]);
        let value = U256::from(12345u64);

        #[expect(clippy::disallowed_methods)]
        let deadline_u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        let deadline = U256::from(deadline_u64);

        // Build EIP-712 struct hash
        let nonce_slot = mapping_slot(owner, super::slots::NONCES);
        let nonce = token
            .storage
            .sload(token.address(), nonce_slot)
            .expect("Could not get nonce");

        let struct_hash = ITIP20::Permit {
            owner,
            spender,
            value,
            nonce,
            deadline,
        }
        .eip712_hash_struct();

        // Build digest per EIP-191
        let domain = token._get_domain_separator();
        let mut digest_data = [0u8; 66];
        digest_data[0] = 0x19;
        digest_data[1] = 0x01;
        digest_data[2..34].copy_from_slice(domain.as_slice());
        digest_data[34..66].copy_from_slice(struct_hash.as_slice());
        let digest = keccak256(digest_data);

        // Sign prehash digest
        let signature = signer.sign_hash_sync(&digest).unwrap();
        let r = signature.r();
        let s = signature.s();
        let v: u8 = if signature.v() { 28 } else { 27 };

        // Call permit
        token
            .permit(
                &admin,
                ITIP20::permitCall {
                    owner,
                    spender,
                    value,
                    deadline,
                    v,
                    r: r.into(),
                    s: s.into(),
                },
            )
            .unwrap();

        // Effects: allowance set and nonce incremented
        assert_eq!(token._get_allowances(owner, spender), value);
        let nonce_after = token
            .storage
            .sload(token.address(), nonce_slot)
            .expect("Could not get nonce");
        assert_eq!(nonce_after, U256::ONE);
    }

    #[test]
    fn test_permit_rejects_invalid_signature() {
        // Setup token
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::from([0u8; 20]);
        let token_id = 2u64;
        let mut token = TIP20Token::new(token_id, &mut storage);
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        // Owner keypair
        let signer = PrivateKeySigner::random();
        let owner = signer.address();

        // Params
        let spender = Address::from([3u8; 20]);
        let value = U256::from(777u64);

        #[expect(clippy::disallowed_methods)]
        let deadline_u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        let deadline = U256::from(deadline_u64);

        // Build digest
        let nonce_slot = mapping_slot(owner, super::slots::NONCES);
        let nonce = token
            .storage
            .sload(token.address(), nonce_slot)
            .expect("Could not get nonce");

        let struct_hash = ITIP20::Permit {
            owner,
            spender,
            value,
            nonce,
            deadline,
        }
        .eip712_hash_struct();

        let domain = token._get_domain_separator();
        let mut digest_data = [0u8; 66];
        digest_data[0] = 0x19;
        digest_data[1] = 0x01;
        digest_data[2..34].copy_from_slice(domain.as_slice());
        digest_data[34..66].copy_from_slice(struct_hash.as_slice());
        let digest = keccak256(digest_data);

        // Sign then tamper with value (invalidates signature)
        let signature = signer.sign_hash_sync(&digest).unwrap();
        let r = signature.r();
        let s = signature.s();
        let v: u8 = if signature.v() { 28 } else { 27 };

        let bad_value = value + U256::from(1u64);
        let result = token.permit(
            &admin,
            ITIP20::permitCall {
                owner,
                spender,
                value: bad_value,
                deadline,
                v,
                r: r.into(),
                s: s.into(),
            },
        );
        assert!(matches!(result, Err(TIP20Error::InvalidSignature(_))));
    }

    #[test]
    fn test_mint_increases_balance_and_supply() {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::from([0u8; 20]);
        let addr = Address::from([1u8; 20]);
        let amount = U256::from(100);
        let token_id = 1;
        {
            let mut token = TIP20Token::new(token_id, &mut storage);
            // Initialize with admin
            token
                .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
                .unwrap();

            // Grant issuer role to admin
            let mut roles = token.get_roles_contract();
            roles.grant_role_internal(&admin, *ISSUER_ROLE);

            token
                .mint(&admin, ITIP20::mintCall { to: addr, amount })
                .unwrap();

            assert_eq!(token._get_balances(addr), amount);
            assert_eq!(token._get_total_supply(), amount);
        }
        assert_eq!(storage.events[&token_id_to_address(token_id)].len(), 2);
        assert_eq!(
            storage.events[&token_id_to_address(token_id)][0],
            TIP20Event::Transfer(ITIP20::Transfer {
                from: Address::ZERO,
                to: addr,
                amount
            })
            .into_log_data()
        );
        assert_eq!(
            storage.events[&token_id_to_address(token_id)][1],
            TIP20Event::Mint(ITIP20::Mint { to: addr, amount }).into_log_data()
        );
    }

    #[test]
    fn test_transfer_moves_balance() {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::from([0u8; 20]);
        let from = Address::from([1u8; 20]);
        let to = Address::from([2u8; 20]);
        let amount = U256::from(100);
        let token_id = 1;
        {
            let mut token = TIP20Token::new(token_id, &mut storage);
            token
                .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
                .unwrap();
            let mut roles = token.get_roles_contract();
            roles.grant_role_internal(&admin, *ISSUER_ROLE);

            token
                .mint(&admin, ITIP20::mintCall { to: from, amount })
                .unwrap();
            token
                .transfer(&from, ITIP20::transferCall { to, amount })
                .unwrap();

            assert_eq!(token._get_balances(from), U256::ZERO);
            assert_eq!(token._get_balances(to), amount);
            assert_eq!(token._get_total_supply(), amount); // Supply unchanged
        }
        assert_eq!(storage.events[&token_id_to_address(token_id)].len(), 3);
        assert_eq!(
            storage.events[&token_id_to_address(token_id)][0],
            TIP20Event::Transfer(ITIP20::Transfer {
                from: Address::ZERO,
                to: from,
                amount
            })
            .into_log_data()
        );
        assert_eq!(
            storage.events[&token_id_to_address(token_id)][1],
            TIP20Event::Mint(ITIP20::Mint { to: from, amount }).into_log_data()
        );
        assert_eq!(
            storage.events[&token_id_to_address(token_id)][2],
            TIP20Event::Transfer(ITIP20::Transfer { from, to, amount }).into_log_data()
        );
    }

    #[test]
    fn test_transfer_insufficient_balance_fails() {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::from([0u8; 20]);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();
        let from = Address::from([1u8; 20]);
        let to = Address::from([2u8; 20]);
        let amount = U256::from(100);

        let result = token.transfer(&from, ITIP20::transferCall { to, amount });
        assert!(matches!(result, Err(TIP20Error::InsufficientBalance(_))));
    }

    #[test]
    fn test_mint_with_memo() {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let token_id = 1;
        let mut token = TIP20Token::new(token_id, &mut storage);
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE);

        let to = Address::random();
        let amount = U256::random();
        let memo = FixedBytes::random();

        token
            .mint_with_memo(&admin, ITIP20::mintWithMemoCall { to, amount, memo })
            .unwrap();

        let events = &storage.events[&token_id_to_address(token_id)];

        assert_eq!(
            events[0],
            TIP20Event::Transfer(ITIP20::Transfer {
                from: Address::ZERO,
                to,
                amount
            })
            .into_log_data()
        );

        assert_eq!(
            events[1],
            TIP20Event::Mint(ITIP20::Mint { to, amount }).into_log_data()
        );

        assert_eq!(
            events[2],
            TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
                from: admin,
                to,
                amount,
                memo
            })
            .into_log_data()
        );
    }

    #[test]
    fn test_burn_with_memo() {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let token_id = 1;
        let mut token = TIP20Token::new(token_id, &mut storage);
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE);

        let amount = U256::random();
        let memo = FixedBytes::random();

        token
            .mint(&admin, ITIP20::mintCall { to: admin, amount })
            .unwrap();

        token
            .burn_with_memo(&admin, ITIP20::burnWithMemoCall { amount, memo })
            .unwrap();

        let events = &storage.events[&token_id_to_address(token_id)];

        assert_eq!(
            events[2],
            TIP20Event::Transfer(ITIP20::Transfer {
                from: admin,
                to: Address::ZERO,
                amount
            })
            .into_log_data()
        );

        assert_eq!(
            events[3],
            TIP20Event::Burn(ITIP20::Burn {
                from: admin,
                amount
            })
            .into_log_data()
        );

        assert_eq!(
            events[4],
            TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
                from: admin,
                to: Address::ZERO,
                amount,
                memo
            })
            .into_log_data()
        );
    }

    #[test]
    fn test_transfer_from_with_memo() {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let token_id = 1;
        let mut token = TIP20Token::new(token_id, &mut storage);
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE);

        let owner = Address::random();
        let spender = Address::random();
        let to = Address::random();
        let amount = U256::random();
        let memo = FixedBytes::random();

        token
            .mint(&admin, ITIP20::mintCall { to: owner, amount })
            .unwrap();

        token
            .approve(&owner, ITIP20::approveCall { spender, amount })
            .unwrap();

        let result = token
            .transfer_from_with_memo(
                &spender,
                ITIP20::transferFromWithMemoCall {
                    from: owner,
                    to,
                    amount,
                    memo,
                },
            )
            .unwrap();

        assert!(result);

        let events = &storage.events[&token_id_to_address(token_id)];

        assert_eq!(
            events[3],
            TIP20Event::Transfer(ITIP20::Transfer {
                from: owner,
                to,
                amount
            })
            .into_log_data()
        );

        assert_eq!(
            events[4],
            TIP20Event::TransferWithMemo(ITIP20::TransferWithMemo {
                from: spender,
                to,
                amount,
                memo
            })
            .into_log_data()
        );
    }

    #[test]
    fn test_transfer_fee_pre_tx() {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let token_id = 1;
        let mut token = TIP20Token::new(token_id, &mut storage);
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE);

        let amount = U256::from(100);
        token
            .mint(&admin, ITIP20::mintCall { to: user, amount })
            .unwrap();

        let fee_amount = U256::from(50);
        token
            .transfer_fee_pre_tx(&user, fee_amount)
            .expect("transfer failed");

        assert_eq!(token._get_balances(user), U256::from(50));
        assert_eq!(token._get_balances(TIP_FEE_MANAGER_ADDRESS), fee_amount);
    }

    #[test]
    fn test_transfer_fee_pre_tx_insufficient_balance() {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let token_id = 1;
        let mut token = TIP20Token::new(token_id, &mut storage);
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        let fee_amount = U256::from(50);
        let result = token.transfer_fee_pre_tx(&user, fee_amount);
        assert_eq!(result, Err(TIP20Error::insufficient_balance()));
    }

    #[test]
    fn test_transfer_fee_post_tx() {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let token_id = 1;
        let mut token = TIP20Token::new(token_id, &mut storage);
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        let initial_fee = U256::from(100);
        token._set_balances(TIP_FEE_MANAGER_ADDRESS, initial_fee);

        let refund_amount = U256::from(30);
        let gas_used = U256::from(10);
        token
            .transfer_fee_post_tx(&user, refund_amount, gas_used)
            .expect("transfer failed");

        assert_eq!(token._get_balances(user), refund_amount);
        assert_eq!(token._get_balances(TIP_FEE_MANAGER_ADDRESS), U256::from(70));

        let events = &storage.events[&token_id_to_address(token_id)];
        assert_eq!(
            events.last().unwrap(),
            &TIP20Event::Transfer(ITIP20::Transfer {
                from: user,
                to: TIP_FEE_MANAGER_ADDRESS,
                amount: gas_used
            })
            .into_log_data()
        );
    }

    #[test]
    fn test_transfer_from_insufficient_allowance() {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let from = Address::random();
        let spender = Address::random();
        let to = Address::random();
        let amount = U256::from(100);
        let token_id = 1;
        let mut token = TIP20Token::new(token_id, &mut storage);
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE);

        token
            .mint(&admin, ITIP20::mintCall { to: from, amount })
            .unwrap();

        let result = token.transfer_from(&spender, ITIP20::transferFromCall { from, to, amount });
        assert!(matches!(result, Err(TIP20Error::InsufficientAllowance(_))));
    }

    #[test]
    fn test_system_transfer_from() {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let from = Address::random();
        let to = Address::random();
        let amount = U256::from(100);
        let token_id = 1;
        let mut token = TIP20Token::new(token_id, &mut storage);
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE);

        token
            .mint(&admin, ITIP20::mintCall { to: from, amount })
            .unwrap();

        let result = token.system_transfer_from(from, to, amount);
        assert!(result.is_ok());

        assert_eq!(
            storage.events[&token_id_to_address(token_id)].last(),
            Some(&TIP20Event::Transfer(ITIP20::Transfer { from, to, amount }).into_log_data())
        );
    }

    #[test]
    fn test_initialize_sets_next_quote_token() {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        let token_id = setup_factory_with_token(&mut storage, &admin, "Test", "TST");
        let mut token = TIP20Token::new(token_id, &mut storage);

        // Verify both quoteToken and nextQuoteToken are set to the same value
        assert_eq!(token._get_quote_token(), LINKING_USD_ADDRESS);
        assert_eq!(token._get_next_quote_token(), LINKING_USD_ADDRESS);
    }

    #[test]
    fn test_update_quote_token() {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        let (token_id, quote_token_id) = setup_token_with_custom_quote_token(&mut storage, &admin);
        let quote_token_address = token_id_to_address(quote_token_id);

        let mut token = TIP20Token::new(token_id, &mut storage);

        // Set next quote token
        token
            .update_quote_token(
                &admin,
                ITIP20::updateQuoteTokenCall {
                    newQuoteToken: quote_token_address,
                },
            )
            .unwrap();

        // Verify next quote token was set
        assert_eq!(token._get_next_quote_token(), quote_token_address);

        // Verify event was emitted
        let events = &storage.events[&token_id_to_address(token_id)];
        assert_eq!(
            events.last().unwrap(),
            &TIP20Event::UpdateQuoteToken(ITIP20::UpdateQuoteToken {
                updater: admin,
                newQuoteToken: quote_token_address,
            })
            .into_log_data()
        );
    }

    #[test]
    fn test_update_quote_token_requires_admin() {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let non_admin = Address::random();
        let token_id = 1;
        let mut token = TIP20Token::new(token_id, &mut storage);
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        let quote_token_address = token_id_to_address(2);

        // Try to set next quote token as non-admin
        let result = token.update_quote_token(
            &non_admin,
            ITIP20::updateQuoteTokenCall {
                newQuoteToken: quote_token_address,
            },
        );

        assert!(matches!(result, Err(TIP20Error::PolicyForbids(_))));
    }

    #[test]
    fn test_update_quote_token_rejects_non_tip20() {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        let token_id = setup_factory_with_token(&mut storage, &admin, "Test", "TST");
        let mut token = TIP20Token::new(token_id, &mut storage);

        // Try to set a non-TIP20 address (random address that doesn't match TIP20 pattern)
        let non_tip20_address = Address::random();
        let result = token.update_quote_token(
            &admin,
            ITIP20::updateQuoteTokenCall {
                newQuoteToken: non_tip20_address,
            },
        );

        assert!(matches!(result, Err(TIP20Error::InvalidQuoteToken(_))));
    }

    #[test]
    fn test_update_quote_token_rejects_undeployed_token() {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        let token_id = setup_factory_with_token(&mut storage, &admin, "Test", "TST");
        let mut token = TIP20Token::new(token_id, &mut storage);

        // Try to set a TIP20 address that hasn't been deployed yet (token_id = 999)
        // This has the correct TIP20 address pattern but hasn't been created
        let undeployed_token_address = token_id_to_address(999);
        let result = token.update_quote_token(
            &admin,
            ITIP20::updateQuoteTokenCall {
                newQuoteToken: undeployed_token_address,
            },
        );

        assert!(matches!(result, Err(TIP20Error::InvalidQuoteToken(_))));
    }

    #[test]
    fn test_finalize_quote_token_update() {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        let (token_id, quote_token_id) = setup_token_with_custom_quote_token(&mut storage, &admin);
        let quote_token_address = token_id_to_address(quote_token_id);

        let mut token = TIP20Token::new(token_id, &mut storage);

        // Set next quote token
        token
            .update_quote_token(
                &admin,
                ITIP20::updateQuoteTokenCall {
                    newQuoteToken: quote_token_address,
                },
            )
            .unwrap();

        // Complete the update
        token
            .finalize_quote_token_update(&admin, ITIP20::finalizeQuoteTokenUpdateCall {})
            .unwrap();

        // Verify quote token was updated
        assert_eq!(token._get_quote_token(), quote_token_address);

        // Verify event was emitted
        let events = &storage.events[&token_id_to_address(token_id)];
        assert_eq!(
            events.last().unwrap(),
            &TIP20Event::QuoteTokenUpdateFinalized(ITIP20::QuoteTokenUpdateFinalized {
                updater: admin,
                newQuoteToken: quote_token_address,
            })
            .into_log_data()
        );
    }

    #[test]
    fn test_finalize_quote_token_update_detects_loop() {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        let mut factory = TIP20Factory::new(&mut storage);
        factory.initialize().unwrap();

        // Create token_b first (links to LINKING_USD)
        let token_b_id =
            create_token_via_factory(&mut factory, &admin, "Token B", "TKB", LINKING_USD_ADDRESS);
        let token_b_address = token_id_to_address(token_b_id);

        // Create token_a (links to token_b)
        let token_a_id =
            create_token_via_factory(&mut factory, &admin, "Token A", "TKA", token_b_address);
        let token_a_address = token_id_to_address(token_a_id);

        // Now try to set token_a as the next quote token for token_b (would create A -> B -> A loop)
        let mut token_b = TIP20Token::new(token_b_id, &mut storage);
        token_b
            .update_quote_token(
                &admin,
                ITIP20::updateQuoteTokenCall {
                    newQuoteToken: token_a_address,
                },
            )
            .unwrap();

        // Try to complete the update - should fail due to loop detection
        let result =
            token_b.finalize_quote_token_update(&admin, ITIP20::finalizeQuoteTokenUpdateCall {});

        assert!(matches!(result, Err(TIP20Error::InvalidQuoteToken(_))));
    }

    #[test]
    fn test_finalize_quote_token_update_requires_admin() {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let non_admin = Address::random();

        let (token_id, quote_token_id) = setup_token_with_custom_quote_token(&mut storage, &admin);
        let quote_token_address = token_id_to_address(quote_token_id);

        let mut token = TIP20Token::new(token_id, &mut storage);

        // Set next quote token as admin
        token
            .update_quote_token(
                &admin,
                ITIP20::updateQuoteTokenCall {
                    newQuoteToken: quote_token_address,
                },
            )
            .unwrap();

        // Try to complete update as non-admin
        let result =
            token.finalize_quote_token_update(&non_admin, ITIP20::finalizeQuoteTokenUpdateCall {});

        assert!(matches!(result, Err(TIP20Error::PolicyForbids(_))));
    }

    #[test]
    fn test_tip20_token_prefix() {
        assert_eq!(
            TIP20_TOKEN_PREFIX,
            [
                0x20, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );
        assert_eq!(&DEFAULT_FEE_TOKEN.as_slice()[..12], &TIP20_TOKEN_PREFIX);
    }

    #[test]
    fn test_tip20_payment_prefix() {
        assert_eq!(
            TIP20_PAYMENT_PREFIX,
            [
                0x20, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );
        // Payment prefix should start with token prefix
        assert_eq!(&TIP20_PAYMENT_PREFIX[..12], &TIP20_TOKEN_PREFIX);
        assert_eq!(&DEFAULT_FEE_TOKEN.as_slice()[..14], &TIP20_PAYMENT_PREFIX);
    }

    /// Test round-trip storage operations using StorageType for various primitives
    #[test]
    fn test_storage_type_round_trips() {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let token_id = 2;
        let mut token = TIP20Token::new(token_id, &mut storage);
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        // Test U256
        let test_supply = U256::from(1_000_000u64);
        token
            .storage
            .sstore(token.address(), slots::TOTAL_SUPPLY, test_supply.to_u256())
            .unwrap();
        let loaded_supply = token
            .storage
            .sload(token.address(), slots::TOTAL_SUPPLY)
            .unwrap();
        assert_eq!(U256::from_u256(loaded_supply).unwrap(), test_supply);

        // Test bool (paused state)
        let test_paused = true;
        token
            .storage
            .sstore(token.address(), slots::PAUSED, test_paused.to_u256())
            .unwrap();
        let loaded_paused = token.storage.sload(token.address(), slots::PAUSED).unwrap();
        assert_eq!(bool::from_u256(loaded_paused).unwrap(), test_paused);

        // Test u64 (transfer_policy_id)
        let test_policy = 42u64;
        token
            .storage
            .sstore(
                token.address(),
                slots::TRANSFER_POLICY_ID,
                test_policy.to_u256(),
            )
            .unwrap();
        let loaded_policy = token
            .storage
            .sload(token.address(), slots::TRANSFER_POLICY_ID)
            .unwrap();
        assert_eq!(u64::from_u256(loaded_policy).unwrap(), test_policy);
    }
}

#[cfg(test)]
mod dispatcher_tests {
    use super::*;
    use crate::{
        LINKING_USD_ADDRESS, METADATA_GAS, MUTATE_FUNC_GAS, Precompile, VIEW_FUNC_GAS,
        expect_precompile_revert, storage::hashmap::HashMapStorageProvider, tip20::TIP20Token,
    };
    use alloy::{
        primitives::{Bytes, U256, keccak256},
        sol_types::SolValue,
    };
    use revm::precompile::PrecompileError;

    #[test]
    fn test_function_selector_dispatch() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        let sender = Address::from([1u8; 20]);

        // Test invalid selector
        let result = token.call(&Bytes::from([0x12, 0x34, 0x56, 0x78]), &sender);
        assert!(matches!(result, Err(PrecompileError::Other(_))));

        // Test insufficient calldata
        let result = token.call(&Bytes::from([0x12, 0x34]), &sender);
        assert!(matches!(result, Err(PrecompileError::Other(_))));
    }
    #[test]
    fn test_balance_of_calldata_handling() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        let admin = Address::from([0u8; 20]);
        let sender = Address::from([1u8; 20]);
        let account = Address::from([2u8; 20]);

        // Initialize token with admin
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        // Grant ISSUER_ROLE to admin
        use alloy::primitives::keccak256;
        let issuer_role = keccak256(b"ISSUER_ROLE");
        token
            .get_roles_contract()
            .grant_role(
                &admin,
                IRolesAuth::grantRoleCall {
                    role: issuer_role,
                    account: admin,
                },
            )
            .unwrap();

        // Mint to set the balance first
        let test_balance = U256::from(1000);
        token
            .mint(
                &admin,
                ITIP20::mintCall {
                    to: account,
                    amount: test_balance,
                },
            )
            .unwrap();

        // Valid balanceOf call
        let balance_of_call = ITIP20::balanceOfCall { account };
        let calldata = balance_of_call.abi_encode();

        let result = token.call(&Bytes::from(calldata), &sender).unwrap();
        assert_eq!(result.gas_used, VIEW_FUNC_GAS);

        // Verify we get the correct balance
        let decoded = U256::abi_decode(&result.bytes).unwrap();
        assert_eq!(decoded, test_balance);
    }

    #[test]
    fn test_mint_updates_storage() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        let admin = Address::from([0u8; 20]);
        let sender = Address::from([1u8; 20]);
        let recipient = Address::from([2u8; 20]);
        let mint_amount = U256::from(500);

        // Initialize token with admin
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        // Grant ISSUER_ROLE to sender
        use alloy::primitives::keccak256;
        let issuer_role = keccak256(b"ISSUER_ROLE");
        token
            .get_roles_contract()
            .grant_role(
                &admin,
                IRolesAuth::grantRoleCall {
                    role: issuer_role,
                    account: sender,
                },
            )
            .unwrap();

        // Check initial balance is zero
        let initial_balance = token.balance_of(ITIP20::balanceOfCall { account: recipient });
        assert_eq!(initial_balance, U256::ZERO);

        // Create mint call
        let mint_call = ITIP20::mintCall {
            to: recipient,
            amount: mint_amount,
        };
        let calldata = mint_call.abi_encode();

        // Execute mint
        let result = token.call(&Bytes::from(calldata), &sender).unwrap();
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);

        // Verify balance was updated in storage
        let final_balance = token.balance_of(ITIP20::balanceOfCall { account: recipient });
        assert_eq!(final_balance, mint_amount);
    }

    #[test]
    fn test_transfer_updates_balances() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        let admin = Address::from([0u8; 20]);
        let sender = Address::from([1u8; 20]);
        let recipient = Address::from([2u8; 20]);
        let transfer_amount = U256::from(300);
        let initial_sender_balance = U256::from(1000);

        // Initialize token with admin
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        // Grant ISSUER_ROLE to admin
        use alloy::primitives::keccak256;
        let issuer_role = keccak256(b"ISSUER_ROLE");
        token
            .get_roles_contract()
            .grant_role(
                &admin,
                IRolesAuth::grantRoleCall {
                    role: issuer_role,
                    account: admin,
                },
            )
            .unwrap();

        // Set up initial balance for sender by minting
        token
            .mint(
                &admin,
                ITIP20::mintCall {
                    to: sender,
                    amount: initial_sender_balance,
                },
            )
            .unwrap();

        // Check initial balances
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: sender }),
            initial_sender_balance
        );
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: recipient }),
            U256::ZERO
        );

        // Create transfer call
        let transfer_call = ITIP20::transferCall {
            to: recipient,
            amount: transfer_amount,
        };
        let calldata = transfer_call.abi_encode();

        // Execute transfer
        let result = token.call(&Bytes::from(calldata), &sender).unwrap();
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);

        // Decode the return value (should be true)
        let success = bool::abi_decode(&result.bytes).unwrap();
        assert!(success);

        // Verify balances were updated correctly
        let final_sender_balance = token.balance_of(ITIP20::balanceOfCall { account: sender });
        let final_recipient_balance =
            token.balance_of(ITIP20::balanceOfCall { account: recipient });

        assert_eq!(
            final_sender_balance,
            initial_sender_balance - transfer_amount
        );
        assert_eq!(final_recipient_balance, transfer_amount);
    }

    #[test]
    fn test_approve_and_transfer_from() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        let admin = Address::random();
        let owner = Address::random();
        let spender = Address::random();
        let recipient = Address::random();
        let approve_amount = U256::from(500);
        let transfer_amount = U256::from(300);
        let initial_owner_balance = U256::from(1000);

        // Initialize token with admin
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        // Grant ISSUER_ROLE to admin
        let issuer_role = keccak256(b"ISSUER_ROLE");
        token
            .get_roles_contract()
            .grant_role(
                &admin,
                IRolesAuth::grantRoleCall {
                    role: issuer_role,
                    account: admin,
                },
            )
            .unwrap();

        // Mint initial balance to owner
        token
            .mint(
                &admin,
                ITIP20::mintCall {
                    to: owner,
                    amount: initial_owner_balance,
                },
            )
            .unwrap();

        // Owner approves spender
        let approve_call = ITIP20::approveCall {
            spender,
            amount: approve_amount,
        };
        let calldata = approve_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &owner).unwrap();
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);
        let success = bool::abi_decode(&result.bytes).unwrap();
        assert!(success);

        // Check allowance
        let allowance = token.allowance(ITIP20::allowanceCall { owner, spender });
        assert_eq!(allowance, approve_amount);

        // Spender transfers from owner to recipient
        let transfer_from_call = ITIP20::transferFromCall {
            from: owner,
            to: recipient,
            amount: transfer_amount,
        };
        let calldata = transfer_from_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &spender).unwrap();
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);
        let success = bool::abi_decode(&result.bytes).unwrap();
        assert!(success);

        // Verify balances
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: owner }),
            initial_owner_balance - transfer_amount
        );
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: recipient }),
            transfer_amount
        );

        // Verify allowance was reduced
        let remaining_allowance = token.allowance(ITIP20::allowanceCall { owner, spender });
        assert_eq!(remaining_allowance, approve_amount - transfer_amount);
    }

    #[test]
    fn test_pause_and_unpause() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        let admin = Address::from([0u8; 20]);
        let pauser = Address::from([1u8; 20]);
        let unpauser = Address::from([2u8; 20]);

        // Initialize token with admin
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        // Grant PAUSE_ROLE to pauser and UNPAUSE_ROLE to unpauser
        use alloy::primitives::keccak256;
        let pause_role = keccak256(b"PAUSE_ROLE");
        let unpause_role = keccak256(b"UNPAUSE_ROLE");

        token
            .get_roles_contract()
            .grant_role(
                &admin,
                IRolesAuth::grantRoleCall {
                    role: pause_role,
                    account: pauser,
                },
            )
            .unwrap();

        token
            .get_roles_contract()
            .grant_role(
                &admin,
                IRolesAuth::grantRoleCall {
                    role: unpause_role,
                    account: unpauser,
                },
            )
            .unwrap();

        // Verify initial state (not paused)
        assert!(!token.paused());

        // Pause the token
        let pause_call = ITIP20::pauseCall {};
        let calldata = pause_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &pauser).unwrap();
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);

        // Verify token is paused
        assert!(token.paused());

        // Unpause the token
        let unpause_call = ITIP20::unpauseCall {};
        let calldata = unpause_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &unpauser).unwrap();
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);

        // Verify token is unpaused
        assert!(!token.paused());
    }

    #[test]
    fn test_burn_functionality() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        let admin = Address::from([0u8; 20]);
        let burner = Address::from([1u8; 20]);
        let initial_balance = U256::from(1000);
        let burn_amount = U256::from(300);

        // Initialize token with admin
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        // Grant ISSUER_ROLE to admin and burner
        use alloy::primitives::keccak256;
        let issuer_role = keccak256(b"ISSUER_ROLE");

        token
            .get_roles_contract()
            .grant_role(
                &admin,
                IRolesAuth::grantRoleCall {
                    role: issuer_role,
                    account: admin,
                },
            )
            .unwrap();

        token
            .get_roles_contract()
            .grant_role(
                &admin,
                IRolesAuth::grantRoleCall {
                    role: issuer_role,
                    account: burner,
                },
            )
            .unwrap();

        // Mint initial balance to burner
        token
            .mint(
                &admin,
                ITIP20::mintCall {
                    to: burner,
                    amount: initial_balance,
                },
            )
            .unwrap();

        // Check initial state
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: burner }),
            initial_balance
        );
        assert_eq!(token.total_supply(), initial_balance);

        // Burn tokens
        let burn_call = ITIP20::burnCall {
            amount: burn_amount,
        };
        let calldata = burn_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &burner).unwrap();
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);

        // Verify balances and total supply after burn
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: burner }),
            initial_balance - burn_amount
        );
        assert_eq!(token.total_supply(), initial_balance - burn_amount);
    }

    #[test]
    fn test_metadata_functions() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        let admin = Address::from([0u8; 20]);
        let caller = Address::from([1u8; 20]);

        // Initialize token
        token
            .initialize("Test Token", "TEST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        // Test name()
        let name_call = ITIP20::nameCall {};
        let calldata = name_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &caller).unwrap();
        assert_eq!(result.gas_used, METADATA_GAS);
        let name = String::abi_decode(&result.bytes).unwrap();
        assert_eq!(name, "Test Token");

        // Test symbol()
        let symbol_call = ITIP20::symbolCall {};
        let calldata = symbol_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &caller).unwrap();
        assert_eq!(result.gas_used, METADATA_GAS);
        let symbol = String::abi_decode(&result.bytes).unwrap();
        assert_eq!(symbol, "TEST");

        // Test decimals()
        let decimals_call = ITIP20::decimalsCall {};
        let calldata = decimals_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &caller).unwrap();
        assert_eq!(result.gas_used, METADATA_GAS);
        let decimals = ITIP20::decimalsCall::abi_decode_returns(&result.bytes).unwrap();
        assert_eq!(decimals, 6);

        // Test currency()
        let currency_call = ITIP20::currencyCall {};
        let calldata = currency_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &caller).unwrap();
        assert_eq!(result.gas_used, METADATA_GAS);
        let currency = String::abi_decode(&result.bytes).unwrap();
        assert_eq!(currency, "USD");

        // Test totalSupply()
        let total_supply_call = ITIP20::totalSupplyCall {};
        let calldata = total_supply_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &caller).unwrap();
        assert_eq!(result.gas_used, METADATA_GAS);
        let total_supply = U256::abi_decode(&result.bytes).unwrap();
        assert_eq!(total_supply, U256::ZERO);
    }

    #[test]
    fn test_supply_cap_enforcement() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        let admin = Address::from([0u8; 20]);
        let recipient = Address::from([1u8; 20]);
        let supply_cap = U256::from(1000);
        let mint_amount = U256::from(1001);

        // Initialize token with admin
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        // Grant ISSUER_ROLE to admin
        use alloy::primitives::keccak256;
        let issuer_role = keccak256(b"ISSUER_ROLE");
        token
            .get_roles_contract()
            .grant_role(
                &admin,
                IRolesAuth::grantRoleCall {
                    role: issuer_role,
                    account: admin,
                },
            )
            .unwrap();

        // Set supply cap
        let set_cap_call = ITIP20::setSupplyCapCall {
            newSupplyCap: supply_cap,
        };
        let calldata = set_cap_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &admin).unwrap();
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);

        // Try to mint more than supply cap
        let mint_call = ITIP20::mintCall {
            to: recipient,
            amount: mint_amount,
        };
        let calldata = mint_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &admin);

        // Should fail due to supply cap
        expect_precompile_revert(&result, TIP20Error::supply_cap_exceeded());
    }

    // TODO(rusowsky): support multiple interfaces with a single dispatcher
    #[test]
    fn test_role_based_access_control() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        let admin = Address::from([0u8; 20]);
        let user1 = Address::from([1u8; 20]);
        let user2 = Address::from([2u8; 20]);
        let unauthorized = Address::from([3u8; 20]);

        // Initialize token with admin
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        // Grant a role to user1
        use alloy::primitives::keccak256;
        let issuer_role = keccak256(b"ISSUER_ROLE");

        let grant_call = IRolesAuth::grantRoleCall {
            role: issuer_role,
            account: user1,
        };
        let calldata = grant_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &admin).unwrap();
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);

        // Check that user1 has the role
        let has_role_call = IRolesAuth::hasRoleCall {
            role: issuer_role,
            account: user1,
        };
        let calldata = has_role_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &admin).unwrap();
        assert_eq!(result.gas_used, VIEW_FUNC_GAS);
        let has_role = bool::abi_decode(&result.bytes).unwrap();
        assert!(has_role);

        // Check that user2 doesn't have the role
        let has_role_call = IRolesAuth::hasRoleCall {
            role: issuer_role,
            account: user2,
        };
        let calldata = has_role_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &admin).unwrap();
        let has_role = bool::abi_decode(&result.bytes).unwrap();
        assert!(!has_role);

        // Test unauthorized mint (should fail)
        let mint_call = ITIP20::mintCall {
            to: user2,
            amount: U256::from(100),
        };
        let calldata = mint_call.abi_encode();
        let result = token.call(&Bytes::from(calldata.clone()), &unauthorized);
        expect_precompile_revert(&result, TIP20Error::policy_forbids());

        // Test authorized mint (should succeed)
        let result = token.call(&Bytes::from(calldata), &user1).unwrap();
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);
    }

    #[test]
    fn test_transfer_with_memo() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        let admin = Address::from([0u8; 20]);
        let sender = Address::from([1u8; 20]);
        let recipient = Address::from([2u8; 20]);
        let transfer_amount = U256::from(100);
        let initial_balance = U256::from(500);

        // Initialize and setup
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        use alloy::primitives::keccak256;
        let issuer_role = keccak256(b"ISSUER_ROLE");
        token
            .get_roles_contract()
            .grant_role(
                &admin,
                IRolesAuth::grantRoleCall {
                    role: issuer_role,
                    account: admin,
                },
            )
            .unwrap();

        // Mint initial balance
        token
            .mint(
                &admin,
                ITIP20::mintCall {
                    to: sender,
                    amount: initial_balance,
                },
            )
            .unwrap();

        // Transfer with memo
        let memo = alloy::primitives::B256::from([1u8; 32]);
        let transfer_call = ITIP20::transferWithMemoCall {
            to: recipient,
            amount: transfer_amount,
            memo,
        };
        let calldata = transfer_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &sender).unwrap();
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);

        // Verify balances
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: sender }),
            initial_balance - transfer_amount
        );
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: recipient }),
            transfer_amount
        );
    }

    #[test]
    fn test_nonces_and_salts() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        let admin = Address::from([0u8; 20]);
        let user = Address::from([1u8; 20]);

        // Initialize token
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        // Test nonces (should start at 0)
        let nonces_call = ITIP20::noncesCall { owner: user };
        let calldata = nonces_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &admin).unwrap();
        assert_eq!(result.gas_used, VIEW_FUNC_GAS);
        let nonce = U256::abi_decode(&result.bytes).unwrap();
        assert_eq!(nonce, U256::ZERO);

        // Test salts (should be false for unused salt)
        let salt = alloy::primitives::FixedBytes::<4>::from([1u8, 2u8, 3u8, 4u8]);
        let salts_call = ITIP20::saltsCall { owner: user, salt };
        let calldata = salts_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &admin).unwrap();
        assert_eq!(result.gas_used, VIEW_FUNC_GAS);
        let is_used = bool::abi_decode(&result.bytes).unwrap();
        assert!(!is_used);
    }

    #[test]
    fn test_change_transfer_policy_id() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        let admin = Address::from([0u8; 20]);
        let non_admin = Address::from([1u8; 20]);
        let new_policy_id = 42u64;

        // Initialize token
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        // Admin can change transfer policy ID
        let change_policy_call = ITIP20::changeTransferPolicyIdCall {
            newPolicyId: new_policy_id,
        };
        let calldata = change_policy_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &admin).unwrap();
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);

        // Verify policy ID was changed
        assert_eq!(token.transfer_policy_id(), new_policy_id);

        // Non-admin cannot change transfer policy ID
        let change_policy_call = ITIP20::changeTransferPolicyIdCall { newPolicyId: 100 };
        let calldata = change_policy_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &non_admin);
        expect_precompile_revert(&result, TIP20Error::policy_forbids());
    }
}
