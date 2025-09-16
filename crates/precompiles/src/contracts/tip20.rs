use std::sync::LazyLock;

use crate::{
    TIP_FEE_MANAGER_ADDRESS,
    contracts::{
        ITIP20, ITIP403Registry, ITIP4217Registry, StorageProvider, TIP403Registry,
        TIP4217Registry, address_is_token_address,
        roles::{DEFAULT_ADMIN_ROLE, RolesAuthContract},
        storage::slots::{double_mapping_slot, mapping_slot},
        token_id_to_address,
        types::{TIP20Error, TIP20Event},
    },
};
use alloy::primitives::{Address, B256, IntoLogData, Signature as EthSignature, U256, keccak256};
use alloy_consensus::crypto::secp256k1 as eth_secp256k1;
use alloy_primitives::Bytes;
use reth_evm::revm::state::Bytecode;
use tracing::trace;

pub mod slots {
    use alloy::primitives::{U256, uint};

    // Variables
    pub const NAME: U256 = uint!(0_U256);
    pub const SYMBOL: U256 = uint!(1_U256);
    pub const TOTAL_SUPPLY: U256 = uint!(3_U256);
    pub const CURRENCY: U256 = uint!(4_U256);
    pub const DOMAIN_SEPARATOR: U256 = uint!(5_U256);
    pub const TRANSFER_POLICY_ID: U256 = uint!(6_U256);
    pub const SUPPLY_CAP: U256 = uint!(7_U256);
    pub const PAUSED: U256 = uint!(8_U256);
    // Mappings
    pub const BALANCES: U256 = uint!(10_U256);
    pub const ALLOWANCES: U256 = uint!(11_U256);
    pub const NONCES: U256 = uint!(12_U256);
    pub const SALTS: U256 = uint!(13_U256);
    pub const ROLES_BASE_SLOT: U256 = uint!(14_U256); // via RolesAuthContract
    pub const ROLE_ADMIN_BASE_SLOT: U256 = uint!(15_U256); // via RolesAuthContract
}

#[derive(Debug)]
pub struct TIP20Token<'a, S: StorageProvider> {
    pub token_address: Address,
    pub storage: &'a mut S,
}

pub static PAUSE_ROLE: LazyLock<B256> = LazyLock::new(|| B256::from(keccak256(b"PAUSE_ROLE")));
pub static UNPAUSE_ROLE: LazyLock<B256> = LazyLock::new(|| B256::from(keccak256(b"UNPAUSE_ROLE")));
pub static ISSUER_ROLE: LazyLock<B256> = LazyLock::new(|| B256::from(keccak256(b"ISSUER_ROLE")));
pub static BURN_BLOCKED_ROLE: LazyLock<B256> =
    LazyLock::new(|| B256::from(keccak256(b"BURN_BLOCKED_ROLE")));

pub static PERMIT_TYPEHASH: LazyLock<B256> = LazyLock::new(|| {
    keccak256(b"Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)")
});

impl<'a, S: StorageProvider> TIP20Token<'a, S> {
    pub fn name(&mut self) -> String {
        self.read_string(slots::NAME)
    }

    pub fn symbol(&mut self) -> String {
        self.read_string(slots::SYMBOL)
    }

    pub fn decimals(&mut self) -> u8 {
        TIP4217Registry::default().get_currency_decimals(
            ITIP4217Registry::getCurrencyDecimalsCall {
                currency: self.currency(),
            },
        )
    }

    pub fn currency(&mut self) -> String {
        self.read_string(slots::CURRENCY)
    }

    pub fn total_supply(&mut self) -> U256 {
        self.storage
            .sload(self.token_address, slots::TOTAL_SUPPLY)
            .expect("TODO: handle error")
    }

    pub fn supply_cap(&mut self) -> U256 {
        self.storage
            .sload(self.token_address, slots::SUPPLY_CAP)
            .expect("TODO: handle error")
    }

    pub fn paused(&mut self) -> bool {
        self.storage
            .sload(self.token_address, slots::PAUSED)
            .expect("TODO: handle error")
            != U256::ZERO
    }

    pub fn transfer_policy_id(&mut self) -> u64 {
        self.storage
            .sload(self.token_address, slots::TRANSFER_POLICY_ID)
            .expect("TODO: handle error")
            .to::<u64>()
    }

    pub fn domain_separator(&mut self) -> B256 {
        B256::from(
            self.storage
                .sload(self.token_address, slots::DOMAIN_SEPARATOR)
                .expect("TODO: handle error"),
        )
    }

    // View functions
    pub fn balance_of(&mut self, call: ITIP20::balanceOfCall) -> U256 {
        self.get_balance(&call.account)
    }

    pub fn allowance(&mut self, call: ITIP20::allowanceCall) -> U256 {
        self.get_allowance(&call.owner, &call.spender)
    }

    pub fn nonces(&mut self, call: ITIP20::noncesCall) -> U256 {
        let slot = mapping_slot(call.owner, slots::NONCES);
        self.storage
            .sload(self.token_address, slot)
            .expect("TODO: handle error")
    }

    pub fn salts(&mut self, call: ITIP20::saltsCall) -> bool {
        let slot = double_mapping_slot(call.owner, call.salt, slots::SALTS);
        self.storage
            .sload(self.token_address, slot)
            .expect("TODO: handle error")
            != U256::ZERO
    }

    // Admin functions
    pub fn change_transfer_policy_id(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::changeTransferPolicyIdCall,
    ) -> Result<(), TIP20Error> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;
        self.storage
            .sstore(
                self.token_address,
                slots::TRANSFER_POLICY_ID,
                U256::from(call.newPolicyId),
            )
            .expect("TODO: handle error");

        self.storage
            .emit_event(
                self.token_address,
                TIP20Event::TransferPolicyUpdate(ITIP20::TransferPolicyUpdate {
                    updater: *msg_sender,
                    newPolicyId: call.newPolicyId,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");
        Ok(())
    }

    pub fn set_supply_cap(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::setSupplyCapCall,
    ) -> Result<(), TIP20Error> {
        self.check_role(msg_sender, DEFAULT_ADMIN_ROLE)?;
        if call.newSupplyCap < self.total_supply() {
            return Err(TIP20Error::supply_cap_exceeded());
        }
        self.storage
            .sstore(self.token_address, slots::SUPPLY_CAP, call.newSupplyCap)
            .expect("TODO: handle error");

        self.storage
            .emit_event(
                self.token_address,
                TIP20Event::SupplyCapUpdate(ITIP20::SupplyCapUpdate {
                    updater: *msg_sender,
                    newSupplyCap: call.newSupplyCap,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");
        Ok(())
    }

    pub fn pause(
        &mut self,
        msg_sender: &Address,
        _call: ITIP20::pauseCall,
    ) -> Result<(), TIP20Error> {
        self.check_role(msg_sender, *PAUSE_ROLE)?;
        self.storage
            .sstore(self.token_address, slots::PAUSED, U256::ONE)
            .expect("TODO: handle error");

        self.storage
            .emit_event(
                self.token_address,
                TIP20Event::PauseStateUpdate(ITIP20::PauseStateUpdate {
                    updater: *msg_sender,
                    isPaused: true,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");
        Ok(())
    }

    pub fn unpause(
        &mut self,
        msg_sender: &Address,
        _call: ITIP20::unpauseCall,
    ) -> Result<(), TIP20Error> {
        self.check_role(msg_sender, *UNPAUSE_ROLE)?;
        self.storage
            .sstore(self.token_address, slots::PAUSED, U256::ZERO)
            .expect("TODO: handle error");

        self.storage
            .emit_event(
                self.token_address,
                TIP20Event::PauseStateUpdate(ITIP20::PauseStateUpdate {
                    updater: *msg_sender,
                    isPaused: false,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");
        Ok(())
    }

    // Token operations
    /// Mints new tokens to specified address
    pub fn mint(&mut self, msg_sender: &Address, call: ITIP20::mintCall) -> Result<(), TIP20Error> {
        self._mint(msg_sender, call.to, call.amount)
    }

    /// Mints new tokens to specified address with memo attached
    pub fn mint_with_memo(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::mintWithMemoCall,
    ) -> Result<(), TIP20Error> {
        self._mint(msg_sender, call.to, call.amount)?;

        self.storage
            .emit_event(
                self.token_address,
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

    /// Internal helper to mint new tokens and update balances
    fn _mint(&mut self, msg_sender: &Address, to: Address, amount: U256) -> Result<(), TIP20Error> {
        self.check_role(msg_sender, *ISSUER_ROLE)?;
        let total_supply = self.total_supply();

        let new_supply = total_supply
            .checked_add(amount)
            .ok_or(TIP20Error::supply_cap_exceeded())?;

        let supply_cap = self.supply_cap();
        if new_supply > supply_cap {
            return Err(TIP20Error::supply_cap_exceeded());
        }

        self.set_total_supply(new_supply);

        let to_balance = self.get_balance(&to);
        let new_to_balance: alloy::primitives::Uint<256, 4> = to_balance
            .checked_add(amount)
            .ok_or(TIP20Error::supply_cap_exceeded())?;
        self.set_balance(&to, new_to_balance);

        self.storage
            .emit_event(
                self.token_address,
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
                self.token_address,
                TIP20Event::Mint(ITIP20::Mint { to, amount }).into_log_data(),
            )
            .expect("TODO: handle error");

        Ok(())
    }

    /// Burns tokens from sender's balance and reduces total supply
    pub fn burn(&mut self, msg_sender: &Address, call: ITIP20::burnCall) -> Result<(), TIP20Error> {
        self._burn(msg_sender, call.amount)
    }

    /// Burns tokens from sender's balance with memo attached
    pub fn burn_with_memo(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::burnWithMemoCall,
    ) -> Result<(), TIP20Error> {
        self._burn(msg_sender, call.amount)?;

        self.storage
            .emit_event(
                self.token_address,
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
    pub fn burn_blocked(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::burnBlockedCall,
    ) -> Result<(), TIP20Error> {
        self.check_role(msg_sender, *BURN_BLOCKED_ROLE)?;

        // Check if the address is blocked from transferring
        let transfer_policy_id = self.transfer_policy_id();
        let mut registry = TIP403Registry::new(self.storage);
        if registry.is_authorized(ITIP403Registry::isAuthorizedCall {
            policyId: transfer_policy_id,
            user: call.from,
        }) {
            // Only allow burning from addresses that are blocked from transferring
            return Err(TIP20Error::policy_forbids());
        }

        self._transfer(&call.from, &Address::ZERO, call.amount)?;

        let total_supply = self.total_supply();
        let new_supply = total_supply
            .checked_sub(call.amount)
            .ok_or(TIP20Error::insufficient_balance())?;
        self.set_total_supply(new_supply);

        self.storage
            .emit_event(
                self.token_address,
                TIP20Event::BurnBlocked(ITIP20::BurnBlocked {
                    from: call.from,
                    amount: call.amount,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");

        Ok(())
    }

    fn _burn(&mut self, msg_sender: &Address, amount: U256) -> Result<(), TIP20Error> {
        self.check_role(msg_sender, *ISSUER_ROLE)?;

        self._transfer(msg_sender, &Address::ZERO, amount)?;

        let total_supply = self.total_supply();
        let new_supply = total_supply
            .checked_sub(amount)
            .ok_or(TIP20Error::insufficient_balance())?;
        self.set_total_supply(new_supply);

        self.storage
            .emit_event(
                self.token_address,
                TIP20Event::Burn(ITIP20::Burn {
                    from: *msg_sender,
                    amount,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");

        Ok(())
    }

    // Standard token functions
    pub fn approve(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::approveCall,
    ) -> Result<bool, TIP20Error> {
        self.set_allowance(msg_sender, &call.spender, call.amount);

        self.storage
            .emit_event(
                self.token_address,
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

    pub fn transfer(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::transferCall,
    ) -> Result<bool, TIP20Error> {
        trace!(%msg_sender, ?call, "transferring TIP20");
        self.check_not_paused()?;
        self.check_not_token_address(&call.to)?;
        self.check_transfer_authorized(msg_sender, &call.to)?;
        self._transfer(msg_sender, &call.to, call.amount)?;
        Ok(true)
    }

    pub fn transfer_from(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::transferFromCall,
    ) -> Result<bool, TIP20Error> {
        self._transfer_from(msg_sender, call.from, call.to, call.amount)
    }

    /// Transfer from `from` to `to` address with memo attached
    pub fn transfer_from_with_memo(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::transferFromWithMemoCall,
    ) -> Result<bool, TIP20Error> {
        self._transfer_from(msg_sender, call.from, call.to, call.amount)?;

        self.storage
            .emit_event(
                self.token_address,
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

    fn _transfer_from(
        &mut self,
        msg_sender: &Address,
        from: Address,
        to: Address,
        amount: U256,
    ) -> Result<bool, TIP20Error> {
        self.check_not_paused()?;
        self.check_not_token_address(&to)?;
        self.check_transfer_authorized(&from, &to)?;

        // Check and update allowance
        // Skip allowance check if the caller is the fee manager
        if *msg_sender != TIP_FEE_MANAGER_ADDRESS {
            let allowed = self.get_allowance(&from, msg_sender);
            if amount > allowed {
                return Err(TIP20Error::insufficient_allowance());
            }

            if allowed != U256::MAX {
                let new_allowance = allowed
                    .checked_sub(amount)
                    .ok_or(TIP20Error::insufficient_allowance())?;
                self.set_allowance(&from, msg_sender, new_allowance);
            }
        }

        self._transfer(&from, &to, amount)?;

        Ok(true)
    }

    pub fn permit(
        &mut self,
        _msg_sender: &Address,
        call: ITIP20::permitCall,
    ) -> Result<(), TIP20Error> {
        if U256::from(call.deadline)
            < U256::from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            )
        {
            return Err(TIP20Error::expired());
        }

        // Get current nonce (increment after successful verification)
        let nonce_slot = mapping_slot(call.owner, slots::NONCES);
        let nonce = self
            .storage
            .sload(self.token_address, nonce_slot)
            .expect("TODO: handle error");

        // Recover address from signature
        let recovered_addr = {
            let digest = self.compute_permit_digest(
                &call.owner,
                &call.spender,
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
        self.storage
            .sstore(self.token_address, nonce_slot, nonce + U256::ONE)
            .expect("TODO: handle error");

        self.set_allowance(&call.owner, &call.spender, call.value);

        self.storage
            .emit_event(
                self.token_address,
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
    pub fn transfer_with_memo(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::transferWithMemoCall,
    ) -> Result<(), TIP20Error> {
        self.check_not_paused()?;
        self.check_not_token_address(&call.to)?;
        self.check_transfer_authorized(msg_sender, &call.to)?;

        self._transfer(msg_sender, &call.to, call.amount)?;

        self.storage
            .emit_event(
                self.token_address,
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

// Utility functions
impl<'a, S: StorageProvider> TIP20Token<'a, S> {
    pub fn new(token_id: u64, storage: &'a mut S) -> Self {
        let token_address = token_id_to_address(token_id);

        Self {
            token_address,
            storage,
        }
    }

    /// Only called internally from the factory, which won't try to re-initialize a token.
    pub fn initialize(
        &mut self,
        name: &str,
        symbol: &str,
        currency: &str,
        admin: &Address,
    ) -> Result<(), TIP20Error> {
        trace!(%name, address=%self.token_address, "Initializing token");

        // must ensure the account is not empty, by setting some code
        self.storage
            .set_code(
                self.token_address,
                Bytecode::new_legacy(Bytes::from_static(&[0xef])),
            )
            .expect("TODO: handle error");

        self.write_string(slots::NAME, name.to_string())?;
        self.write_string(slots::SYMBOL, symbol.to_string())?;
        self.write_string(slots::CURRENCY, currency.to_string())?;

        // Validate currency via TIP4217 registry
        if self.decimals() == 0 {
            return Err(TIP20Error::invalid_currency());
        }

        // Set default values
        self.storage
            .sstore(self.token_address, slots::SUPPLY_CAP, U256::MAX)
            .expect("TODO: handle error");
        self.storage
            .sstore(self.token_address, slots::TRANSFER_POLICY_ID, U256::ONE)
            .expect("TODO: handle error"); // Default "always-allow" policy

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
        domain_data.extend_from_slice(self.token_address.as_slice());
        let domain_separator = keccak256(&domain_data);
        self.storage
            .sstore(
                self.token_address,
                slots::DOMAIN_SEPARATOR,
                U256::from_be_bytes(domain_separator.0),
            )
            .expect("TODO: handle error");

        Ok(())
    }

    // Helper to get a RolesAuthContract instance
    pub fn get_roles_contract(&mut self) -> RolesAuthContract<'_, S> {
        RolesAuthContract::new(
            self.storage,
            self.token_address,
            slots::ROLES_BASE_SLOT,
            slots::ROLE_ADMIN_BASE_SLOT,
        )
    }

    fn get_balance(&mut self, account: &Address) -> U256 {
        let slot = mapping_slot(account, slots::BALANCES);
        self.storage
            .sload(self.token_address, slot)
            .expect("TODO: handle error")
    }

    fn set_balance(&mut self, account: &Address, amount: U256) {
        let slot = mapping_slot(account, slots::BALANCES);
        self.storage
            .sstore(self.token_address, slot, amount)
            .expect("TODO: handle error");
    }

    fn get_allowance(&mut self, owner: &Address, spender: &Address) -> U256 {
        let slot = double_mapping_slot(owner, spender, slots::ALLOWANCES);
        self.storage
            .sload(self.token_address, slot)
            .expect("TODO: handle error")
    }

    fn set_allowance(&mut self, owner: &Address, spender: &Address, amount: U256) {
        let slot = double_mapping_slot(owner, spender, slots::ALLOWANCES);
        self.storage
            .sstore(self.token_address, slot, amount)
            .expect("TODO: handle error");
    }

    fn set_total_supply(&mut self, amount: U256) {
        self.storage
            .sstore(self.token_address, slots::TOTAL_SUPPLY, amount)
            .expect("TODO: handle error");
    }

    fn check_role(&mut self, account: &Address, role: B256) -> Result<(), TIP20Error> {
        let mut roles = self.get_roles_contract();
        roles
            .check_role(account, role)
            .map_err(|_| TIP20Error::policy_forbids())
    }

    fn check_not_paused(&mut self) -> Result<(), TIP20Error> {
        if self.paused() {
            return Err(TIP20Error::contract_paused());
        }
        Ok(())
    }

    fn check_not_token_address(&self, to: &Address) -> Result<(), TIP20Error> {
        // Don't allow sending to other precompiled tokens
        if address_is_token_address(to) {
            return Err(TIP20Error::invalid_recipient());
        }
        Ok(())
    }

    fn check_transfer_authorized(
        &mut self,
        from: &Address,
        to: &Address,
    ) -> Result<(), TIP20Error> {
        let transfer_policy_id = self.transfer_policy_id();
        let mut registry = TIP403Registry::new(self.storage);

        // Check if 'from' address is authorized
        let from_authorized = registry.is_authorized(ITIP403Registry::isAuthorizedCall {
            policyId: transfer_policy_id,
            user: *from,
        });

        // Check if 'to' address is authorized
        let to_authorized_call = ITIP403Registry::isAuthorizedCall {
            policyId: transfer_policy_id,
            user: *to,
        };
        let to_authorized = registry.is_authorized(to_authorized_call);

        if !from_authorized || !to_authorized {
            return Err(TIP20Error::policy_forbids());
        }

        Ok(())
    }

    fn _transfer(&mut self, from: &Address, to: &Address, amount: U256) -> Result<(), TIP20Error> {
        let from_balance = self.get_balance(from);
        if amount > from_balance {
            return Err(TIP20Error::insufficient_balance());
        }

        let new_from_balance = from_balance
            .checked_sub(amount)
            .ok_or(TIP20Error::insufficient_balance())?;

        self.set_balance(from, new_from_balance);

        if *to != Address::ZERO {
            let to_balance = self.get_balance(to);
            let new_to_balance = to_balance
                .checked_add(amount)
                .ok_or(TIP20Error::supply_cap_exceeded())?;
            self.set_balance(to, new_to_balance);
        }

        self.storage
            .emit_event(
                self.token_address,
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

    fn read_string(&mut self, slot: U256) -> String {
        let value = self
            .storage
            .sload(self.token_address, slot)
            .expect("TODO: handle error");
        let bytes = value.to_be_bytes::<32>();
        let len = bytes[31] as usize / 2; // Last byte stores length * 2 for short strings
        if len > 31 {
            panic!("String too long, we shouldn't have stored this in the first place.");
        } else {
            String::from_utf8_lossy(&bytes[..len]).to_string()
        }
    }

    /// Write string to storage (simplified - assumes string fits in one slot)
    fn write_string(&mut self, slot: U256, value: String) -> Result<(), TIP20Error> {
        let bytes = value.as_bytes();
        if bytes.len() > 31 {
            return Err(TIP20Error::string_too_long());
        }
        let mut storage_bytes = [0u8; 32];
        storage_bytes[..bytes.len()].copy_from_slice(bytes);
        storage_bytes[31] = (bytes.len() * 2) as u8; // Store length * 2 in last byte

        self.storage
            .sstore(self.token_address, slot, U256::from_be_bytes(storage_bytes))
            .expect("TODO: handle error");
        Ok(())
    }

    fn compute_permit_digest(
        &mut self,
        owner: &Address,
        spender: &Address,
        value: U256,
        nonce: U256,
        deadline: U256,
    ) -> B256 {
        // Build EIP-712 struct hash for Permit
        let struct_hash = {
            // 32 (typehash) + 20 (owner) + 20 (spender) + 32 (value) + 32 (nonce) + 32 (deadline) = 168
            let mut struct_data = [0u8; 168];
            // typehash
            struct_data[0..32].copy_from_slice(PERMIT_TYPEHASH.as_slice());
            // owner (20 bytes)
            struct_data[32..52].copy_from_slice(owner.as_slice());
            // spender (20 bytes)
            struct_data[52..72].copy_from_slice(spender.as_slice());
            // value (32 bytes)
            struct_data[72..104].copy_from_slice(&value.to_be_bytes::<32>());
            // nonce (32 bytes)
            struct_data[104..136].copy_from_slice(&nonce.to_be_bytes::<32>());
            // deadline (32 bytes)
            struct_data[136..168].copy_from_slice(&deadline.to_be_bytes::<32>());
            keccak256(struct_data)
        };

        // EIP-191 digest: 0x19 0x01 || domainSeparator || structHash
        let mut digest_data = [0u8; 66];
        digest_data[0] = 0x19;
        digest_data[1] = 0x01;
        digest_data[2..34].copy_from_slice(self.domain_separator().as_slice());
        digest_data[34..66].copy_from_slice(struct_hash.as_slice());
        keccak256(digest_data)
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{Address, U256, keccak256};
    use alloy_primitives::FixedBytes;
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;

    use super::*;
    use crate::contracts::storage::hashmap::HashMapStorageProvider;

    #[test]
    fn test_permit_sets_allowance_and_increments_nonce() {
        // Setup token
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::from([0u8; 20]);
        let token_id = 1u64;
        let mut token = TIP20Token::new(token_id, &mut storage);
        token.initialize("Test", "TST", "USD", &admin).unwrap();

        // Owner keypair
        let signer = PrivateKeySigner::random();
        let owner = signer.address();

        // Permit params
        let spender = Address::from([2u8; 20]);
        let value = U256::from(12345u64);
        let deadline_u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        let deadline = U256::from(deadline_u64);

        // Build EIP-712 struct hash
        let nonce_slot =
            crate::contracts::storage::slots::mapping_slot(owner, super::slots::NONCES);
        let nonce = token
            .storage
            .sload(token.token_address, nonce_slot)
            .expect("Could not get nonce");

        let mut struct_data = [0u8; 168];
        struct_data[0..32].copy_from_slice(super::PERMIT_TYPEHASH.as_slice());
        struct_data[32..52].copy_from_slice(owner.as_slice());
        struct_data[52..72].copy_from_slice(spender.as_slice());
        struct_data[72..104].copy_from_slice(&value.to_be_bytes::<32>());
        struct_data[104..136].copy_from_slice(&nonce.to_be_bytes::<32>());
        struct_data[136..168].copy_from_slice(&deadline.to_be_bytes::<32>());
        let struct_hash = keccak256(struct_data);

        // Build digest per EIP-191
        let domain = token.domain_separator();
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
        assert_eq!(token.get_allowance(&owner, &spender), value);
        let nonce_after = token
            .storage
            .sload(token.token_address, nonce_slot)
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
        token.initialize("Test", "TST", "USD", &admin).unwrap();

        // Owner keypair
        let signer = PrivateKeySigner::random();
        let owner = signer.address();

        // Params
        let spender = Address::from([3u8; 20]);
        let value = U256::from(777u64);
        let deadline_u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        let deadline = U256::from(deadline_u64);

        // Build digest
        let nonce_slot =
            crate::contracts::storage::slots::mapping_slot(owner, super::slots::NONCES);
        let nonce = token
            .storage
            .sload(token.token_address, nonce_slot)
            .expect("Could not get nonce");

        let mut struct_data = [0u8; 168];
        struct_data[0..32].copy_from_slice(super::PERMIT_TYPEHASH.as_slice());
        struct_data[32..52].copy_from_slice(owner.as_slice());
        struct_data[52..72].copy_from_slice(spender.as_slice());
        struct_data[72..104].copy_from_slice(&value.to_be_bytes::<32>());
        struct_data[104..136].copy_from_slice(&nonce.to_be_bytes::<32>());
        struct_data[136..168].copy_from_slice(&deadline.to_be_bytes::<32>());
        let struct_hash = keccak256(struct_data);

        let domain = token.domain_separator();
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
            token.initialize("Test", "TST", "USD", &admin).unwrap();

            // Grant issuer role to admin
            let mut roles = token.get_roles_contract();
            roles.grant_role_internal(&admin, *ISSUER_ROLE);

            token
                .mint(&admin, ITIP20::mintCall { to: addr, amount })
                .unwrap();

            assert_eq!(token.get_balance(&addr), amount);
            assert_eq!(token.total_supply(), amount);
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
            token.initialize("Test", "TST", "USD", &admin).unwrap();
            let mut roles = token.get_roles_contract();
            roles.grant_role_internal(&admin, *ISSUER_ROLE);

            token
                .mint(&admin, ITIP20::mintCall { to: from, amount })
                .unwrap();
            token
                .transfer(&from, ITIP20::transferCall { to, amount })
                .unwrap();

            assert_eq!(token.get_balance(&from), U256::ZERO);
            assert_eq!(token.get_balance(&to), amount);
            assert_eq!(token.total_supply(), amount); // Supply unchanged
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
        token.initialize("Test", "TST", "USD", &admin).unwrap();
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
        token.initialize("Test", "TST", "USD", &admin).unwrap();

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
        token.initialize("Test", "TST", "USD", &admin).unwrap();

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
        token.initialize("Test", "TST", "USD", &admin).unwrap();

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
}
