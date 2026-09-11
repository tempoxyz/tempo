//! Journaled TIP-1086 counters. Immutable policy lives only in transaction transient storage.
use super::*;
use tempo_primitives::transaction::SignedKeyAuthorization;

fn context_slot(field: u8, token: Address) -> U256 {
    let mut preimage = [0u8; 53];
    preimage[..32].copy_from_slice(keccak256(b"tempo.carried-key.context.v1").as_slice());
    preimage[32] = field;
    preimage[33..].copy_from_slice(token.as_slice());
    keccak256(preimage).into()
}

/// Namespaced counter slots; policy fields never occupy persistent storage.
pub fn counter_slot(window: bool, account: Address, id: B256, token: Address) -> U256 {
    let domain = if window {
        b"tempo.carried-key.window.v1".as_slice()
    } else {
        b"tempo.carried-key.spent.v1".as_slice()
    };
    let mut preimage = [0u8; 128];
    preimage[..32].copy_from_slice(keccak256(domain).as_slice());
    preimage[44..64].copy_from_slice(account.as_slice());
    preimage[64..96].copy_from_slice(id.as_slice());
    preimage[108..].copy_from_slice(token.as_slice());
    keccak256(preimage).into()
}

impl AccountKeychain {
    pub(super) fn carried_read(&self, field: u8, token: Address) -> Result<U256> {
        self.storage
            .tload(ACCOUNT_KEYCHAIN_ADDRESS, context_slot(field, token))
    }

    fn carried_write(&mut self, field: u8, token: Address, value: U256) -> Result<()> {
        self.storage
            .tstore(ACCOUNT_KEYCHAIN_ADDRESS, context_slot(field, token), value)
    }

    /// Whether the installed certificate names this exact debit owner and transaction key.
    pub fn is_carried(&self, account: Address, key_id: Address) -> Result<bool> {
        if !self.storage.spec().is_t12() {
            return Ok(false);
        }
        Ok(
            self.carried_read(0, Address::ZERO)? == U256::from_be_slice(account.as_slice())
                && !account.is_zero()
                && self.carried_read(1, Address::ZERO)? == U256::from_be_slice(key_id.as_slice()),
        )
    }

    /// Checks stateful authority and installs immutable limits without registering the key.
    /// Cryptography and native configuration validation must already have succeeded.
    pub fn install_carried(
        &mut self,
        account: Address,
        auth: &SignedKeyAuthorization,
        issuer: Address,
    ) -> Result<()> {
        let carried = auth
            .carried
            .as_ref()
            .ok_or_else(AccountKeychainError::unauthorized_caller)?;
        if !self.storage.spec().is_t12() || auth.account != Some(account) {
            return Err(AccountKeychainError::unauthorized_caller().into());
        }
        if auth.tree.is_none() {
            let key = self.keys[account][auth.key_id].read()?;
            if key != AuthorizedKey::default() {
                return Err(AccountKeychainError::key_already_exists().into());
            }
            self.ensure_key_authorization_witness_not_burned(
                account,
                auth.witness.unwrap_or_default(),
            )?;
        }
        // V2 revocation is authenticated by membership/allocator/epoch under the root.
        // Legacy key and witness tombstones are a separate authorization namespace.
        if issuer != account {
            if auth.tree.is_some() {
                return Err(AccountKeychainError::unauthorized_caller().into());
            }
            let key = self.validate_keychain_authorization(
                account,
                issuer,
                self.storage.timestamp().saturating_to(),
                auth.signature.signature_type().map(Into::into),
            )?;
            if !key.is_admin || auth.signature.signature_type().is_none() {
                return Err(AccountKeychainError::unauthorized_caller().into());
            }
        }
        self.carried_write(0, Address::ZERO, U256::from_be_slice(account.as_slice()))?;
        self.carried_write(
            1,
            Address::ZERO,
            U256::from_be_slice(auth.key_id.as_slice()),
        )?;
        self.carried_write(2, Address::ZERO, auth.signature_hash().into())?;
        self.carried_write(3, Address::ZERO, U256::from(carried.valid_after))?;
        self.carried_write(
            4,
            Address::ZERO,
            U256::from(u8::from(auth.limits.is_some())),
        )?;
        if let Some(limits) = &auth.limits {
            for limit in limits {
                self.carried_write(5, limit.token, limit.limit)?;
                // period + 1 distinguishes an absent token from a zero cap or lifetime limit.
                self.carried_write(6, limit.token, U256::from(limit.period) + U256::from(1))?;
            }
        }
        if auth.tree.is_some() {
            self.install_tree(account, auth)?;
        }
        Ok(())
    }

    /// Return the effective counter and cap at the transaction timestamp.
    fn carried_counter(
        &mut self,
        account: Address,
        token: Address,
    ) -> Result<(B256, U256, U256, u64, u64)> {
        let id: B256 = self.carried_read(2, Address::ZERO)?.into();
        let period = self.carried_read(6, token)?;
        if period.is_zero() {
            return Err(AccountKeychainError::spending_limit_exceeded().into());
        }
        let period = (period - U256::from(1)).to::<u64>();
        let cap = self.carried_read(5, token)?;
        let mut spent = self.storage.sload(
            ACCOUNT_KEYCHAIN_ADDRESS,
            counter_slot(false, account, id, token),
        )?;
        self.storage.deduct_gas(54)?;
        let index = if period == 0 {
            0
        } else {
            let anchor = self.carried_read(3, Address::ZERO)?.to::<u64>();
            let now = self.storage.timestamp().saturating_to::<u64>();
            let index = now
                .checked_sub(anchor)
                .and_then(|elapsed| elapsed.checked_div(period))
                .ok_or_else(AccountKeychainError::unauthorized_caller)?;
            let stored = self.storage.sload(
                ACCOUNT_KEYCHAIN_ADDRESS,
                counter_slot(true, account, id, token),
            )?;
            self.storage.deduct_gas(54)?;
            if stored != U256::from(index) {
                spent = U256::ZERO;
            }
            index
        };
        Ok((id, cap, spent, period, index))
    }

    /// Debit a carried budget. Fee reservation uses `emit = false`; settlement emits actual fees.
    pub fn debit_carried(
        &mut self,
        account: Address,
        key_id: Address,
        token: Address,
        amount: U256,
        emit: bool,
    ) -> Result<()> {
        if amount.is_zero() || self.carried_read(4, Address::ZERO)?.is_zero() {
            return Ok(());
        }
        if let Some(tree) = super::tree::load(account)? {
            return self.debit_tree(account, token, amount, emit, tree);
        }
        let (id, cap, spent, period, index) = self.carried_counter(account, token)?;
        let remaining = cap
            .checked_sub(spent)
            .ok_or_else(AccountKeychainError::spending_limit_exceeded)?;
        let remaining = remaining
            .checked_sub(amount)
            .ok_or_else(AccountKeychainError::spending_limit_exceeded)?;
        self.storage.sstore(
            ACCOUNT_KEYCHAIN_ADDRESS,
            counter_slot(false, account, id, token),
            spent + amount,
        )?;
        if period != 0 {
            let slot = counter_slot(true, account, id, token);
            if self.storage.sload(ACCOUNT_KEYCHAIN_ADDRESS, slot)? != U256::from(index) {
                self.storage
                    .sstore(ACCOUNT_KEYCHAIN_ADDRESS, slot, U256::from(index))?;
            }
        }
        if emit {
            self.emit_event(AccountKeychainEvent::carried_access_key_spend(
                account, id, token, key_id, amount, remaining, index,
            ))?;
        }
        Ok(())
    }

    /// Refund only previously reserved fees, preserving the same signed window and budget.
    pub fn refund_carried(&mut self, account: Address, token: Address, amount: U256) -> Result<()> {
        if amount.is_zero() || self.carried_read(4, Address::ZERO)?.is_zero() {
            return Ok(());
        }
        if let Some(mut tree) = super::tree::load(account)? {
            let i = tree
                .tokens
                .binary_search_by_key(&token, |t| t.token)
                .map_err(|_| AccountKeychainError::spending_limit_exceeded())?;
            tree.leaf.usage[i].spent = tree.leaf.usage[i]
                .spent
                .checked_sub(amount)
                .ok_or_else(AccountKeychainError::spending_limit_exceeded)?;
            return super::tree::save(account, &mut tree);
        }
        let (id, _, spent, _, _) = self.carried_counter(account, token)?;
        let remaining = spent
            .checked_sub(amount)
            .ok_or_else(AccountKeychainError::spending_limit_exceeded)?;
        self.storage.sstore(
            ACCOUNT_KEYCHAIN_ADDRESS,
            counter_slot(false, account, id, token),
            remaining,
        )
    }

    /// Emits actual account-paid fees after refunds, including failed user execution.
    pub fn emit_carried_fee(
        &mut self,
        account: Address,
        token: Address,
        amount: U256,
    ) -> Result<()> {
        let key = self.transaction_key.t_read()?;
        if amount.is_zero()
            || !self.is_carried(account, key)?
            || self.carried_read(4, Address::ZERO)?.is_zero()
        {
            return Ok(());
        }
        if let Some(tree) = super::tree::load(account)? {
            return super::tree::emit(account, &tree);
        }
        let (id, cap, spent, _, index) = self.carried_counter(account, token)?;
        let remaining = cap
            .checked_sub(spent)
            .ok_or_else(AccountKeychainError::spending_limit_exceeded)?;
        self.emit_event(AccountKeychainEvent::carried_access_key_spend(
            account, id, token, key, amount, remaining, index,
        ))
    }

    /// Raw counter getter; this does not authenticate a grant or compute remaining allowance.
    pub fn get_carried_spending(
        &self,
        call: IAccountKeychain::getCarriedSpendingCall,
    ) -> Result<IAccountKeychain::getCarriedSpendingReturn> {
        Ok(IAccountKeychain::getCarriedSpendingReturn {
            spent: self.storage.sload(
                ACCOUNT_KEYCHAIN_ADDRESS,
                counter_slot(false, call.account, call.authorizationId, call.token),
            )?,
            windowIndex: self
                .storage
                .sload(
                    ACCOUNT_KEYCHAIN_ADDRESS,
                    counter_slot(true, call.account, call.authorizationId, call.token),
                )?
                .to(),
        })
    }

    /// Permanently revoke an unused key ID without requiring a registration write first.
    pub fn revoke_carried_key(&mut self, account: Address, key_id: Address) -> Result<()> {
        self.ensure_admin_caller(account)?;
        if key_id.is_zero() || key_id == account {
            return Err(AccountKeychainError::invalid_key_id().into());
        }
        let key = self.keys[account][key_id].read()?;
        if key.is_revoked {
            return Ok(());
        }
        if key != AuthorizedKey::default() {
            return Err(AccountKeychainError::key_already_exists().into());
        }
        self.keys[account][key_id].write(AuthorizedKey {
            is_revoked: true,
            ..Default::default()
        })?;
        self.emit_event(AccountKeychainEvent::key_revoked(account, key_id))
    }
}
